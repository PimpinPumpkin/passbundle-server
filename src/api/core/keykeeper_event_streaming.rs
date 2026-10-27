// Keykeeper: the places an organization's events are sent (event streaming),
// under /api/keykeeper. An organization's owners and admins manage its own
// destinations, except MSP technicians, as for script access: a technician
// mustn't be able to send a client's activity somewhere the client and the
// MSP can't see. An MSP's admins manage the MSP's own destinations, which get
// every client's events and the MSP's activity log. Anyone else gets "not
// found".
//
// Secrets (a webhook's URL, its signing secret, a header's value, Sentinel's
// client secret) are written here and never read back: the signing secret is
// shown once, when it's made. Every change is in the organization's event log
// or the MSP's activity log, and goes to the other destinations like any
// event. See DESIGN.md, "Sending events to security tools".

use std::time::{Duration, Instant};

use chrono::Utc;
use rocket::{Route, http::Status, serde::json::Json};
use serde_json::{Value, json};

use crate::{
    api::{EmptyResult, JsonResult, PasswordOrOtpData},
    auth::Headers,
    db::{
        DbConn,
        models::{
            DestinationAdded, Event, EventDelivery, EventDestination, EventKind, EventSecrets, EventSettings,
            EventType, MAX_DESTINATIONS, MAX_SCOPES_PER_PERSON, Membership, MembershipStatus, MembershipType, Msp,
            MspClient, MspId, MspMembership, MspRole, Organization, OrganizationId, destination_target,
            save_with_extras,
        },
    },
    keykeeper_streaming::{
        self, TEST_LIMIT, TESTS_RUNNING, Target, TestTurn,
        format::{self, MessageFormat},
        guard::{self, Policy},
        secrets,
    },
    util::format_date,
};

use super::keykeeper_msp::{Audit, clean_name, staff_role};

pub fn routes() -> Vec<Route> {
    routes![
        list_org,
        create_org,
        update_org,
        delete_org,
        test_org,
        new_secret_org,
        list_msp,
        create_msp,
        update_msp,
        delete_msp,
        test_msp,
        new_secret_msp,
    ]
}

/// Whose destinations: an organization's, or an MSP's.
#[derive(Clone)]
enum Scope {
    Org(OrganizationId),
    Msp(MspId),
}

impl Scope {
    fn owns(&self, destination: &EventDestination) -> bool {
        match self {
            Self::Org(id) => destination.org_uuid.as_ref() == Some(id),
            Self::Msp(id) => destination.msp_uuid.as_ref() == Some(id),
        }
    }

    async fn destinations(&self, conn: &DbConn) -> Vec<EventDestination> {
        match self {
            Self::Org(id) => EventDestination::find_by_org(id, conn).await,
            Self::Msp(id) => EventDestination::find_by_msp(id, conn).await,
        }
    }

    /// What an event sent straight to a destination says it's from.
    async fn event_scope(&self, conn: &DbConn) -> Value {
        match self {
            Self::Org(id) => {
                let name = Organization::find_by_uuid(id, conn).await.map(|o| o.name);
                json!({ "organization": { "id": id, "name": name } })
            }
            Self::Msp(id) => {
                let name = Msp::find_by_uuid(id, conn).await.map(|m| m.name);
                json!({ "msp": { "id": id, "name": name } })
            }
        }
    }
}

/// An organization's owners and admins, except technicians of its MSP.
async fn require_org_manager(org_id: &OrganizationId, headers: &Headers, conn: &DbConn) -> Result<Scope, crate::Error> {
    let allowed = match Membership::find_by_user_and_org(&headers.user.uuid, org_id, conn).await {
        Some(m)
            if m.status == MembershipStatus::Confirmed as i32
                && (m.atype == MembershipType::Owner as i32 || m.atype == MembershipType::Admin as i32) =>
        {
            if MspMembership::find_by_membership(&m.uuid, conn).await.is_none() {
                true
            } else {
                match MspClient::find_by_org(org_id, conn).await {
                    Some(client) => {
                        matches!(staff_role(&client.msp_uuid, &headers.user.uuid, conn).await, Ok(MspRole::Admin))
                    }
                    None => false,
                }
            }
        }
        _ => false,
    };
    if !allowed {
        // The same answer whether the organization exists or not.
        err_code!("Organization not found", Status::NotFound.code)
    }
    Ok(Scope::Org(org_id.clone()))
}

/// An MSP's admins. Technicians get "not found" too: the console doesn't
/// show them this, and the web app signs out on a refusal.
async fn require_msp_admin(msp_id: &MspId, headers: &Headers, conn: &DbConn) -> Result<Scope, crate::Error> {
    match staff_role(msp_id, &headers.user.uuid, conn).await? {
        MspRole::Admin => Ok(Scope::Msp(msp_id.clone())),
        MspRole::Technician => err_code!("Not found", Status::NotFound.code),
    }
}

async fn find_in(scope: &Scope, id: &str, conn: &DbConn) -> Result<EventDestination, crate::Error> {
    match EventDestination::find(id, conn).await {
        Some(d) if scope.owns(&d) => Ok(d),
        _ => err_code!("Destination not found", Status::NotFound.code),
    }
}

/// How a destination is doing, in one word. Slow (it takes events, but
/// slowly, so it's sent to less often) is never failing, and only failing
/// turns a destination off.
fn status(d: &EventDestination) -> &'static str {
    match (d.enabled, d.paused_reason.is_some(), d.failures > 0) {
        (true, _, false) if d.slow_count > 0 => "slow",
        (true, _, false) => "on",
        (true, _, true) => "failing",
        (false, true, _) => "paused",
        (false, false, _) => "off",
    }
}

async fn view(d: &EventDestination, conn: &DbConn) -> Value {
    let settings = d.settings();
    let mut out = json!({
        "id": d.uuid,
        "name": d.name,
        "kind": d.kind,
        "enabled": d.enabled,
        "target": d.shown_target,
        "status": status(d),
        "pausedReason": d.paused_reason,
        "failures": d.failures,
        "failingSince": d.failing_since.as_ref().map(format_date),
        "lastSuccessAt": d.last_success_at.as_ref().map(format_date),
        "lastError": d.last_error,
        "lastErrorAt": d.last_error_at.as_ref().map(format_date),
        "queued": EventDelivery::count(&d.uuid, conn).await,
        "retryAt": d.retry_at.as_ref().map(format_date),
        "dropped": d.dropped,
        "createdAt": format_date(&d.created_at),
        "updatedAt": format_date(&d.updated_at),
    });
    // What's set, without the secrets.
    let has_secret = |f: fn(&EventSecrets) -> bool| f(&opened(d));
    match d.kind() {
        Some(EventKind::Webhook) => {
            out["webhook"] = json!({
                "headerName": settings.header_name,
                "caCertificate": settings.ca_certificate,
            });
        }
        Some(EventKind::Syslog) => {
            out["syslog"] = json!({
                "host": settings.host,
                "port": settings.port,
                "format": settings.format,
                "caCertificate": settings.ca_certificate,
            });
        }
        Some(EventKind::Sentinel) => {
            out["sentinel"] = json!({
                "tenantId": settings.tenant_id,
                "clientId": settings.client_id,
                "endpoint": settings.endpoint,
                "ruleId": settings.rule_id,
                "stream": settings.stream,
                "hasClientSecret": has_secret(|s| s.client_secret.is_some()),
            });
        }
        None => {}
    }
    out
}

async fn list(scope: &Scope, conn: &DbConn) -> Value {
    let mut data = Vec::new();
    for d in scope.destinations(conn).await {
        data.push(view(&d, conn).await);
    }
    json!({
        "data": data,
        "maxDestinations": MAX_DESTINATIONS,
        "privateNetworks": Policy::current().any(),
    })
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct WebhookData {
    url: Option<String>,
    /// "" removes the header.
    header_name: Option<String>,
    header_value: Option<String>,
    /// "" removes it.
    ca_certificate: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SyslogData {
    host: Option<String>,
    port: Option<u16>,
    format: Option<String>,
    ca_certificate: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SentinelData {
    tenant_id: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    endpoint: Option<String>,
    rule_id: Option<String>,
    stream: Option<String>,
    ca_certificate: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct DestinationData {
    name: Option<String>,
    kind: Option<String>,
    enabled: Option<bool>,
    webhook: Option<WebhookData>,
    syslog: Option<SyslogData>,
    sentinel: Option<SentinelData>,
    /// The caller's master password or a one-time code: adding or changing a
    /// destination needs it (DESIGN.md, "Confirming sensitive changes").
    #[serde(flatten)]
    verification: PasswordOrOtpData,
}

const MAX_CA: usize = 16 * 1024;

/// A certificate authority to trust instead of the system's: one to five
/// PEM certificates.
fn checked_ca(pem: &str) -> Result<String, String> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let pem = pem.trim();
    if pem.len() > MAX_CA {
        return Err("A certificate authority is at most 16 KB of PEM".into());
    }
    let mut roots = rustls::RootCertStore::empty();
    let mut count = 0;
    for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        let cert = cert.map_err(|_| "That isn't a PEM certificate".to_owned())?;
        roots.add(cert).map_err(|_| "That isn't a certificate".to_owned())?;
        count += 1;
    }
    if count == 0 || count > 5 {
        return Err("Paste one to five PEM certificates (-----BEGIN CERTIFICATE-----)".into());
    }
    Ok(format!("{pem}\n"))
}

/// Applies "" (remove), text (set), or nothing (keep) to an optional setting.
fn change(
    current: &mut Option<String>,
    new: Option<&String>,
    check: impl Fn(&str) -> Result<String, String>,
) -> Result<(), String> {
    if let Some(new) = new {
        *current = if new.trim().is_empty() {
            None
        } else {
            Some(check(new)?)
        };
    }
    Ok(())
}

/// Headers a webhook may add. The ones the server sets, and ones that change
/// how HTTP works, aren't allowed.
fn checked_header_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    let reserved = [
        "host",
        "content-length",
        "content-type",
        "content-encoding",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "user-agent",
        "cookie",
        "expect",
        format::HEADER_ID,
        format::HEADER_TIMESTAMP,
        format::HEADER_SIGNATURE,
    ];
    let lower = name.to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 64
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        || reserved.contains(&lower.as_str())
        || lower.starts_with("proxy-")
    {
        return Err(format!("{name} can't be the webhook's header. Use one like Authorization or X-Api-Key."));
    }
    Ok(name.to_owned())
}

fn checked_header_value(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 2048 || !value.chars().all(|c| c == ' ' || c.is_ascii_graphic()) {
        return Err("A header's value is 1 to 2048 printable characters".into());
    }
    Ok(value.to_owned())
}

fn is_guid(text: &str) -> bool {
    uuid::Uuid::parse_str(text).is_ok() && text.len() == 36
}

/// What saving a destination's settings did.
struct Applied {
    /// What the console shows of where events go.
    shown: String,
    /// It now sends somewhere else (another URL, collector, rule, or
    /// certificate authority), so the old place gets a last notice.
    moved: bool,
    /// A new signing secret, shown once.
    new_signing_secret: Option<String>,
}

/// The settings and secrets a request asks for, applied to what's there.
/// A secret stays with exactly what it was entered for: a webhook's header
/// value with its URL, certificate authority, and header name, and a new
/// signing secret for a new host; Sentinel's client secret with its tenant,
/// app, and endpoint. Changing any of those asks for it again, so nobody
/// can point someone else's secret at themselves.
fn apply(
    kind: EventKind,
    data: &DestinationData,
    settings: &mut EventSettings,
    secrets: &mut EventSecrets,
    creating: bool,
) -> Result<Applied, String> {
    let policy = Policy::current();
    match kind {
        EventKind::Webhook => {
            let w = data.webhook.as_ref().ok_or("Missing the webhook's settings")?;
            let (old_url, old_ca, old_header) =
                (secrets.url.clone(), settings.ca_certificate.clone(), settings.header_name.clone());
            if let Some(url) = &w.url {
                secrets.url = Some(guard::checked_url(url, &policy)?.to_string());
            }
            let url = secrets.url.clone().ok_or("Enter the webhook's URL")?;
            let parsed = url::Url::parse(&url).map_err(|_| "Bad URL".to_owned())?;
            change(&mut settings.header_name, w.header_name.as_ref(), checked_header_name)?;
            change(&mut settings.ca_certificate, w.ca_certificate.as_ref(), checked_ca)?;
            let url_changed = old_url.as_deref() != Some(url.as_str());
            let ca_changed = old_ca != settings.ca_certificate;
            if ca_changed && !creating && w.url.is_none() {
                // Who trusts another authority could read what's sent: only
                // someone who knows the URL (which can carry a token) may.
                return Err("Enter the webhook's URL again when you change its certificate authority".into());
            }
            if url_changed || ca_changed || old_header != settings.header_name {
                secrets.header_value = None;
            }
            match (&settings.header_name, &w.header_value) {
                (None, _) => secrets.header_value = None,
                (Some(_), Some(v)) => secrets.header_value = Some(checked_header_value(v)?),
                (Some(_), None) if secrets.header_value.is_none() => {
                    return Err(if creating {
                        "Enter the header's value".into()
                    } else {
                        "Enter the header's value again: it's kept only for the URL, certificate authority, and header it was entered for".into()
                    });
                }
                (Some(_), None) => {}
            }
            let origin = |u: &url::Url| (u.host_str().map(str::to_owned), u.port_or_known_default());
            let old_origin = old_url.as_deref().and_then(|u| url::Url::parse(u).ok()).map(|u| origin(&u));
            let new_signing_secret =
                if creating || secrets.signing_secret.is_none() || old_origin != Some(origin(&parsed)) {
                    let secret = format::new_signing_secret();
                    secrets.signing_secret = Some(secret.clone());
                    Some(secret)
                } else {
                    None
                };
            Ok(Applied {
                shown: guard::shown_url(&parsed),
                moved: !creating && (url_changed || ca_changed),
                new_signing_secret,
            })
        }
        EventKind::Syslog => {
            let s = data.syslog.as_ref().ok_or("Missing the syslog settings")?;
            let before = (settings.host.clone(), settings.port, settings.ca_certificate.clone());
            if let Some(port) = s.port {
                if port == 0 {
                    return Err("Enter the collector's port (often 6514)".into());
                }
                settings.port = Some(port);
            }
            let port = *settings.port.get_or_insert(6514);
            if let Some(host) = &s.host {
                settings.host = Some(host.clone());
            }
            let host =
                guard::checked_host(settings.host.as_deref().ok_or("Enter the collector's host")?, port, &policy)?;
            settings.host = Some(host.clone());
            if let Some(format) = &s.format {
                settings.format =
                    Some(MessageFormat::from_str(format).ok_or("The format is json or cef")?.as_str().to_owned());
            }
            change(&mut settings.ca_certificate, s.ca_certificate.as_ref(), checked_ca)?;
            settings.format.get_or_insert_with(|| "json".into());
            let moved = !creating && before != (settings.host.clone(), settings.port, settings.ca_certificate.clone());
            Ok(Applied {
                shown: if host.contains(':') {
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                },
                moved,
                new_signing_secret: None,
            })
        }
        EventKind::Sentinel => {
            let s = data.sentinel.as_ref().ok_or("Missing the Sentinel settings")?;
            if s.ca_certificate.as_deref().is_some_and(|c| !c.trim().is_empty()) {
                return Err("Sentinel uses the system's certificate authorities; it doesn't take one of its own".into());
            }
            settings.ca_certificate = None;
            let before = (
                settings.tenant_id.clone(),
                settings.client_id.clone(),
                settings.endpoint.clone(),
                settings.rule_id.clone(),
                settings.stream.clone(),
            );
            change(&mut settings.tenant_id, s.tenant_id.as_ref(), |t| {
                let t = t.trim().to_ascii_lowercase();
                if is_guid(&t) || guard::checked_host(&t, 443, &policy).is_ok_and(|h| h.contains('.')) {
                    Ok(t)
                } else {
                    Err("The tenant is a directory (tenant) ID or a domain like contoso.onmicrosoft.com".into())
                }
            })?;
            change(&mut settings.client_id, s.client_id.as_ref(), |c| {
                let c = c.trim().to_ascii_lowercase();
                if is_guid(&c) {
                    Ok(c)
                } else {
                    Err("The client is the app registration's application (client) ID".into())
                }
            })?;
            change(&mut settings.endpoint, s.endpoint.as_ref(), |e| guard::checked_sentinel_endpoint(e, &policy))?;
            change(&mut settings.rule_id, s.rule_id.as_ref(), |r| {
                let r = r.trim().to_ascii_lowercase();
                match r.strip_prefix("dcr-") {
                    Some(hex) if hex.len() == 32 && hex.chars().all(|c| c.is_ascii_hexdigit()) => Ok(r),
                    _ => Err("The rule is the data collection rule's immutable ID, dcr- and 32 characters".into()),
                }
            })?;
            change(&mut settings.stream, s.stream.as_ref(), |st| {
                let st = st.trim();
                match st.strip_prefix("Custom-") {
                    Some(name)
                        if !name.is_empty()
                            && name.len() <= 100
                            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') =>
                    {
                        Ok(st.to_owned())
                    }
                    _ => Err("The stream is the rule's custom stream, like Custom-PassBundleEvents".into()),
                }
            })?;
            let now = (
                settings.tenant_id.clone(),
                settings.client_id.clone(),
                settings.endpoint.clone(),
                settings.rule_id.clone(),
                settings.stream.clone(),
            );
            let identity_changed = (&now.0, &now.1, &now.2) != (&before.0, &before.1, &before.2);
            if let Some(secret) = &s.client_secret {
                secrets.client_secret =
                    Some(checked_header_value(secret.trim()).map_err(|_| "Enter the app's client secret".to_owned())?);
            } else if identity_changed && secrets.client_secret.is_some() {
                // The app's secret goes only where it was entered for.
                return Err("Enter the client secret again when the tenant, the app, or the endpoint changes".into());
            }
            let complete = settings.tenant_id.is_some()
                && settings.client_id.is_some()
                && secrets.client_secret.is_some()
                && settings.endpoint.is_some()
                && settings.rule_id.is_some()
                && settings.stream.is_some();
            if !complete {
                return Err("Sentinel needs the tenant, the app's client ID and secret, the endpoint, the rule's ID, and the stream".into());
            }
            let host = url::Url::parse(settings.endpoint.as_deref().unwrap_or_default())
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
                .unwrap_or_default();
            Ok(Applied {
                shown: format!("Sentinel: {host} ({})", settings.stream.as_deref().unwrap_or_default()),
                moved: !creating && now != before,
                new_signing_secret: None,
            })
        }
    }
}

fn seal_secrets(d: &EventDestination, secrets: &EventSecrets) -> Result<String, crate::Error> {
    let text = zeroize::Zeroizing::new(serde_json::to_string(secrets).map_res_err()?);
    match secrets::seal(&d.binding(), &text) {
        Ok(s) => Ok(s),
        Err(e) => err!(e),
    }
}

trait MapResErr<T> {
    fn map_res_err(self) -> Result<T, crate::Error>;
}

impl<T> MapResErr<T> for Result<T, serde_json::Error> {
    fn map_res_err(self) -> Result<T, crate::Error> {
        self.map_err(|e| crate::Error::new("Couldn't save the destination", e.to_string()))
    }
}

/// Records a change in the organization's event log or the MSP's activity
/// log. What destinations get says which destination it was (its id, name,
/// kind, and what the console shows of where it sends, never a secret), what
/// changed, and whether it's on now.
async fn record(
    scope: &Scope,
    what: &'static str,
    changes: &[&str],
    d: &EventDestination,
    headers: &Headers,
    conn: &DbConn,
) -> EmptyResult {
    let on = d.enabled && what != "removed";
    let detail = match what {
        "added" if on => "Added, and on.".to_owned(),
        "added" => "Added, and off.".to_owned(),
        "removed" => "Removed: events stop going there.".to_owned(),
        _ if changes.is_empty() => format!(
            "Saved without changes. It's {}.",
            if on {
                "on"
            } else {
                "off"
            }
        ),
        _ => format!(
            "Changed: {}. It's {}.",
            changes.join(", "),
            if on {
                "on"
            } else {
                "off"
            }
        ),
    };
    match scope {
        Scope::Org(org_id) => {
            let code = match what {
                "added" => EventType::KeykeeperEventStreamAdded,
                "removed" => EventType::KeykeeperEventStreamRemoved,
                _ => EventType::KeykeeperEventStreamChanged,
            };
            let mut event = Event::new(code as i32, None);
            event.org_uuid = Some(org_id.clone());
            event.act_user_uuid = Some(headers.user.uuid.clone());
            event.device_type = Some(headers.device.atype);
            event.ip_address = Some(headers.ip.ip.to_string());
            let mut target = destination_target(d);
            target["enabled"] = json!(on);
            save_with_extras(&event, json!({ "target": target, "changes": changes, "detail": detail }), conn).await;
            Ok(())
        }
        Scope::Msp(msp_id) => {
            let event = match what {
                "added" => "event_stream_added",
                "removed" => "event_stream_removed",
                _ => "event_stream_changed",
            };
            Audit::by(event, headers)
                .detail(format!("{} (id {}, {}: {}): {detail}", d.name, d.uuid, d.kind, d.shown_target))
                .record(msp_id, conn)
                .await
        }
    }
}

async fn create(scope: Scope, data: DestinationData, headers: &Headers, conn: &DbConn) -> JsonResult {
    data.verification.confirm_change(&headers.user, conn).await?;
    let name = clean_name(data.name.as_deref().unwrap_or_default())?;
    let Some(kind) = data.kind.as_deref().and_then(EventKind::from_str) else {
        err!("The kind is webhook, syslog, or sentinel")
    };
    let (org, msp) = match &scope {
        Scope::Org(id) => (Some(id.clone()), None),
        Scope::Msp(id) => (None, Some(id.clone())),
    };
    let mut d = EventDestination::new(org, msp, name, kind, headers.user.uuid.clone());
    let mut settings = EventSettings::default();
    let mut secrets = EventSecrets::default();
    let applied = match apply(kind, &data, &mut settings, &mut secrets, true) {
        Ok(a) => a,
        Err(e) => err!(e),
    };
    d.shown_target = applied.shown;
    d.settings = serde_json::to_string(&settings).map_res_err()?;
    d.secrets = seal_secrets(&d, &secrets)?;
    d.enabled = data.enabled.unwrap_or(true);
    match d.insert_capped(MAX_DESTINATIONS, conn).await? {
        DestinationAdded::Yes => {}
        DestinationAdded::ScopeFull => {
            err!(format!("Events can go to at most {MAX_DESTINATIONS} places. Remove one first."))
        }
        DestinationAdded::PersonFull => err!(format!(
            "You've set up places events go for {MAX_SCOPES_PER_PERSON} organizations and MSPs, the most one person can. Ask another admin to add this one, or remove one of yours."
        )),
    }
    // It's added either way, so its signing secret must be shown either way.
    if let Err(e) = record(&scope, "added", &[], &d, headers, conn).await {
        warn!("Couldn't record a new event destination in the log: {e:?}");
    }
    let mut out = view(&d, conn).await;
    if let Some(secret) = applied.new_signing_secret {
        // Shown this once.
        out["signingSecret"] = json!(secret);
    }
    Ok(Json(out))
}

/// A destination's secrets, or none when they can't be read anymore (they're
/// entered again).
fn opened(d: &EventDestination) -> EventSecrets {
    secrets::open(&d.binding(), &d.secrets)
        .ok()
        .and_then(|s| serde_json::from_str::<EventSecrets>(s.as_str()).ok())
        .unwrap_or_default()
}

async fn update(scope: Scope, id: &str, data: DestinationData, headers: &Headers, conn: &DbConn) -> JsonResult {
    let mut d = find_in(&scope, id, conn).await?;
    data.verification.confirm_change(&headers.user, conn).await?;
    let Some(kind) = d.kind() else {
        err!("Unknown kind of destination")
    };
    if data.kind.as_deref().is_some_and(|k| k != d.kind) {
        err!("A destination's kind can't change. Add a new one instead.")
    }
    let mut changes: Vec<&str> = Vec::new();
    if let Some(name) = &data.name {
        let name = clean_name(name)?;
        if name != d.name {
            changes.push("name");
        }
        d.name = name;
    }
    let touches_settings = data.webhook.is_some() || data.syslog.is_some() || data.sentinel.is_some();
    let new_signing_secret = if touches_settings {
        let before = Target::open(&d).ok();
        let mut settings = d.settings();
        let old_secrets = opened(&d);
        let mut secrets = old_secrets.clone();
        let applied = match apply(kind, &data, &mut settings, &mut secrets, false) {
            Ok(a) => a,
            Err(e) => err!(e),
        };
        if applied.moved {
            changes.push("where it sends");
            if let Some(old) = before {
                // Pointed somewhere else: the old place hears so first.
                let notice = farewell_event(&scope, "pointed elsewhere", headers, conn).await;
                keykeeper_streaming::farewell(old, notice, &d.scope_key());
            }
        } else if serde_json::to_string(&settings).map_res_err()? != d.settings || secrets != old_secrets {
            changes.push("settings");
        }
        if applied.new_signing_secret.is_some() {
            changes.push("new signing secret");
        }
        d.shown_target = applied.shown;
        d.settings = serde_json::to_string(&settings).map_res_err()?;
        d.secrets = seal_secrets(&d, &secrets)?;
        keykeeper_streaming::forget_token(&d.uuid);
        applied.new_signing_secret
    } else {
        None
    };
    d.updated_at = Utc::now().naive_utc();
    d.save_settings(conn).await?;
    match data.enabled {
        Some(true) if !d.enabled => {
            // Turned on again: a fresh start, and what waited goes now.
            EventDestination::set_enabled(&d.uuid, true, conn).await?;
            EventDelivery::due_now(&d.uuid, conn).await;
            crate::db::models::WAKE.notify_one();
            changes.push("turned on");
        }
        Some(false) if d.enabled || d.paused_reason.is_some() => {
            // Turned off on purpose: it's told so, and what waited is forgotten.
            let notice = farewell_event(&scope, "turned off", headers, conn).await;
            EventDestination::set_enabled(&d.uuid, false, conn).await?;
            EventDelivery::forget_all(&d.uuid, conn).await;
            if d.enabled
                && let Ok(target) = Target::open(&d)
            {
                keykeeper_streaming::farewell(target, notice, &d.scope_key());
            }
            changes.push("turned off");
        }
        _ => {}
    }
    let d = find_in(&scope, &d.uuid, conn).await?;
    record(&scope, "changed", &changes, &d, headers, conn).await?;
    let mut out = view(&d, conn).await;
    if let Some(secret) = new_signing_secret {
        // A new host, or the old secret couldn't be read: a new one, shown once.
        out["signingSecret"] = json!(secret);
    }
    Ok(Json(out))
}

/// The last event a destination gets when it's turned off, removed, or
/// pointed elsewhere, so its SIEM sees that, even if nothing else reaches it
/// again.
async fn farewell_event(scope: &Scope, what: &str, headers: &Headers, conn: &DbConn) -> (String, String) {
    let code = match (scope, what) {
        (Scope::Org(_), "removed") => EventType::KeykeeperEventStreamRemoved as i32,
        (Scope::Org(_), _) => EventType::KeykeeperEventStreamChanged as i32,
        (Scope::Msp(_), "removed") => 9172,
        (Scope::Msp(_), _) => 9171,
    };
    let detail = format!("This destination was {what}: events stop coming here.");
    keykeeper_streaming::direct_event(
        code,
        &scope.event_scope(conn).await,
        &headers.user,
        &headers.ip.ip.to_string(),
        Some(&detail),
    )
}

async fn delete(scope: Scope, id: &str, headers: &Headers, conn: &DbConn) -> EmptyResult {
    let d = find_in(&scope, id, conn).await?;
    let notice = farewell_event(&scope, "removed", headers, conn).await;
    let target = Target::open(&d).ok();
    d.delete(conn).await?;
    keykeeper_streaming::forget_token(&d.uuid);
    if d.enabled
        && let Some(target) = target
    {
        keykeeper_streaming::farewell(target, notice, &d.scope_key());
    }
    record(&scope, "removed", &[], &d, headers, conn).await
}

/// A new signing secret for a webhook, shown once. The old one stops working.
async fn new_secret(
    scope: Scope,
    id: &str,
    verification: &PasswordOrOtpData,
    headers: &Headers,
    conn: &DbConn,
) -> JsonResult {
    let mut d = find_in(&scope, id, conn).await?;
    verification.confirm_change(&headers.user, conn).await?;
    if d.kind() != Some(EventKind::Webhook) {
        err!("Only webhooks have a signing secret")
    }
    let Ok(text) = secrets::open(&d.binding(), &d.secrets) else {
        err!("This server can't read the webhook's settings anymore. Enter its URL again first.")
    };
    let mut s: EventSecrets = serde_json::from_str(text.as_str()).map_res_err()?;
    let secret = format::new_signing_secret();
    s.signing_secret = Some(secret.clone());
    d.secrets = seal_secrets(&d, &s)?;
    d.updated_at = Utc::now().naive_utc();
    d.save_settings(conn).await?;
    record(&scope, "changed", &["new signing secret"], &d, headers, conn).await?;
    let mut out = view(&d, conn).await;
    out["signingSecret"] = json!(secret);
    Ok(Json(out))
}

/// How long a test may take to send.
const TEST_TIME: Duration = Duration::from_secs(15);
/// Anything that goes wrong before a connection and its TLS handshake are
/// complete is answered this long after the test started, whatever it was
/// (a name that doesn't resolve, a refused address, a closed port, a
/// timeout), so a test can't be used to time which hosts and ports exist
/// inside a network. Longer than any of those can take within TEST_TIME.
const TEST_ANSWER_TIME: Duration = Duration::from_secs(16);

/// Sends a sample event now and says what happened: one test at a time per
/// organization or MSP and per person, a few a minute per person, four at
/// once on the server. The database connection is given back before
/// anything goes out, so slow receivers can't tie up the server's
/// connections.
async fn test(scope: Scope, id: &str, headers: &Headers, conn: DbConn) -> JsonResult {
    let d = find_in(&scope, id, &conn).await?;
    let Some(_here) = TestTurn::take(&d.scope_key()) else {
        err_code!("A test is already running here. Try again when it's done.", Status::TooManyRequests.code)
    };
    let Some(_mine) = TestTurn::take(&format!("person:{}", headers.user.uuid)) else {
        err_code!("You have a test running. Try again when it's done.", Status::TooManyRequests.code)
    };
    if TEST_LIMIT.check_key(headers.user.uuid.as_ref()).is_err() {
        err_code!("Wait a few seconds before testing again", Status::TooManyRequests.code)
    }
    let target = match Target::open(&d) {
        Ok(t) => t,
        Err(f) => err!(f.message),
    };
    let (event_id, payload) = keykeeper_streaming::direct_event(
        keykeeper_streaming::TEST_EVENT_TYPE,
        &scope.event_scope(&conn).await,
        &headers.user,
        &headers.ip.ip.to_string(),
        None,
    );
    drop(conn);
    let Ok(_running) = TESTS_RUNNING.try_acquire() else {
        err_code!("Other tests are running. Try again in a moment.", Status::TooManyRequests.code)
    };
    let started = Instant::now();
    match keykeeper_streaming::send(&target, &[(event_id.clone(), payload)], started + TEST_TIME).await {
        (1, None) => Ok(Json(json!({ "sent": true, "eventId": event_id }))),
        // Delivered, though slowly.
        (1, Some(f)) => Ok(Json(json!({ "sent": true, "eventId": event_id, "warning": f.message }))),
        (_, Some(f)) => {
            if f.before_tls {
                tokio::time::sleep_until((started + TEST_ANSWER_TIME).into()).await;
            }
            err!(f.message)
        }
        _ => err!("Nothing was sent"),
    }
}

fn checked_id(id: &str) -> Result<String, crate::Error> {
    let Ok(id) = uuid::Uuid::parse_str(id) else {
        err_code!("Destination not found", Status::NotFound.code)
    };
    Ok(id.hyphenated().to_string())
}

// Organizations

#[get("/keykeeper/organizations/<org_id>/event-streaming")]
async fn list_org(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    let scope = require_org_manager(&org_id, &headers, &conn).await?;
    Ok(Json(list(&scope, &conn).await))
}

#[post("/keykeeper/organizations/<org_id>/event-streaming", data = "<data>")]
async fn create_org(org_id: OrganizationId, data: Json<DestinationData>, headers: Headers, conn: DbConn) -> JsonResult {
    let scope = require_org_manager(&org_id, &headers, &conn).await?;
    create(scope, data.into_inner(), &headers, &conn).await
}

#[put("/keykeeper/organizations/<org_id>/event-streaming/<id>", data = "<data>")]
async fn update_org(
    org_id: OrganizationId,
    id: &str,
    data: Json<DestinationData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let scope = require_org_manager(&org_id, &headers, &conn).await?;
    update(scope, &checked_id(id)?, data.into_inner(), &headers, &conn).await
}

#[delete("/keykeeper/organizations/<org_id>/event-streaming/<id>")]
async fn delete_org(org_id: OrganizationId, id: &str, headers: Headers, conn: DbConn) -> EmptyResult {
    let scope = require_org_manager(&org_id, &headers, &conn).await?;
    delete(scope, &checked_id(id)?, &headers, &conn).await
}

#[post("/keykeeper/organizations/<org_id>/event-streaming/<id>/test")]
async fn test_org(org_id: OrganizationId, id: &str, headers: Headers, conn: DbConn) -> JsonResult {
    let scope = require_org_manager(&org_id, &headers, &conn).await?;
    test(scope, &checked_id(id)?, &headers, conn).await
}

#[post("/keykeeper/organizations/<org_id>/event-streaming/<id>/secret", data = "<data>")]
async fn new_secret_org(
    org_id: OrganizationId,
    id: &str,
    data: Option<Json<PasswordOrOtpData>>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let scope = require_org_manager(&org_id, &headers, &conn).await?;
    new_secret(scope, &checked_id(id)?, &data.map(Json::into_inner).unwrap_or_default(), &headers, &conn).await
}

// MSPs

#[get("/keykeeper/msp/<msp_id>/event-streaming")]
async fn list_msp(msp_id: MspId, headers: Headers, conn: DbConn) -> JsonResult {
    let scope = require_msp_admin(&msp_id, &headers, &conn).await?;
    Ok(Json(list(&scope, &conn).await))
}

#[post("/keykeeper/msp/<msp_id>/event-streaming", data = "<data>")]
async fn create_msp(msp_id: MspId, data: Json<DestinationData>, headers: Headers, conn: DbConn) -> JsonResult {
    let scope = require_msp_admin(&msp_id, &headers, &conn).await?;
    create(scope, data.into_inner(), &headers, &conn).await
}

#[put("/keykeeper/msp/<msp_id>/event-streaming/<id>", data = "<data>")]
async fn update_msp(
    msp_id: MspId,
    id: &str,
    data: Json<DestinationData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let scope = require_msp_admin(&msp_id, &headers, &conn).await?;
    update(scope, &checked_id(id)?, data.into_inner(), &headers, &conn).await
}

#[delete("/keykeeper/msp/<msp_id>/event-streaming/<id>")]
async fn delete_msp(msp_id: MspId, id: &str, headers: Headers, conn: DbConn) -> EmptyResult {
    let scope = require_msp_admin(&msp_id, &headers, &conn).await?;
    delete(scope, &checked_id(id)?, &headers, &conn).await
}

#[post("/keykeeper/msp/<msp_id>/event-streaming/<id>/test")]
async fn test_msp(msp_id: MspId, id: &str, headers: Headers, conn: DbConn) -> JsonResult {
    let scope = require_msp_admin(&msp_id, &headers, &conn).await?;
    test(scope, &checked_id(id)?, &headers, conn).await
}

#[post("/keykeeper/msp/<msp_id>/event-streaming/<id>/secret", data = "<data>")]
async fn new_secret_msp(
    msp_id: MspId,
    id: &str,
    data: Option<Json<PasswordOrOtpData>>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let scope = require_msp_admin(&msp_id, &headers, &conn).await?;
    new_secret(scope, &checked_id(id)?, &data.map(Json::into_inner).unwrap_or_default(), &headers, &conn).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_headers_can_carry_a_token_but_not_change_http() {
        assert_eq!(checked_header_name("Authorization").unwrap(), "Authorization");
        assert!(checked_header_name("X-Api-Key").is_ok());
        assert!(checked_header_name("DD-API-KEY").is_ok());
        for bad in [
            "Host",
            "content-length",
            "Transfer-Encoding",
            "webhook-signature",
            "Proxy-Authorization",
            "",
            "Bad Header",
            "a:b",
        ] {
            assert!(checked_header_name(bad).is_err(), "{bad}");
        }
        assert!(checked_header_value("Bearer abc.def").is_ok());
        assert!(checked_header_value("line\nbreak").is_err());
        assert!(checked_header_value("").is_err());
    }

    #[test]
    fn certificate_authorities_are_pem_certificates() {
        assert!(checked_ca("not a certificate").is_err());
        assert!(checked_ca("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----").is_err());
    }

    #[test]
    fn statuses_say_how_a_destination_is_doing() {
        let mut d = EventDestination::new(None, None, "x".into(), EventKind::Webhook, "u".to_owned().into());
        assert_eq!(status(&d), "on");
        d.slow_count = 1;
        assert_eq!(status(&d), "slow");
        d.failures = 2;
        assert_eq!(status(&d), "failing");
        d.enabled = false;
        assert_eq!(status(&d), "off");
        d.paused_reason = Some("why".into());
        assert_eq!(status(&d), "paused");
    }
}

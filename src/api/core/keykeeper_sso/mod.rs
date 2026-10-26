// Keykeeper: sign in with Microsoft Entra ID, per organization. Each of an
// MSP's clients (or any organization) connects its own Entra tenant on its
// Settings page: the tenant id, an app registration's client id and secret,
// an identifier people type, and optionally email domains it proves with DNS,
// so typing an email finds it. Single sign-on proves who someone is; their
// master password still unlocks their vault, so nothing about keys changes.
//
// The flow is OpenID Connect's authorization code flow with PKCE, a state,
// and a nonce, against the tenant's own `/v2.0` endpoints: this server is the
// OpenID client (it holds the app's secret, redeems the code, and checks the
// ID token in token.rs), and the web vault is this server's client, with its
// own state and PKCE challenge, exactly as upstream's apps expect:
//
// 1. The web vault's /sso page asks /identity/sso/prevalidate for the
//    identifier, then opens /identity/connect/authorize (authorize below).
// 2. This server sends the browser to Microsoft with its own state, nonce,
//    and PKCE challenge, and a cookie tying the answer to this browser.
// 3. Microsoft sends the browser back to /identity/connect/oidc-signin
//    (callback below), the one redirect URI each app registration has. This
//    server redeems the code at once, checks the ID token, and hands the web
//    vault a one-time code of its own.
// 4. The web vault redeems that code at /identity/connect/token with its PKCE
//    verifier (redeem_code below), and link.rs decides which account it is.
//
// See DESIGN.md, "Sign in with Microsoft Entra ID", in the meta repo, for the
// threat model and what's out of scope (trusted-device unlock, creating
// accounts, other directories).

pub mod dns;
mod entra;
pub mod link;
pub mod token;

use std::net::IpAddr;

use chrono::Utc;
use rocket::{
    Route,
    http::{Cookie, CookieJar, SameSite},
    response::Redirect,
    serde::json::Json,
};
use serde_json::{Value, json};

use self::{
    link::{Candidate, Decision, Facts},
    token::{Expected, Identity},
};
use super::{keykeeper_msp::Audit, keykeeper_script_access::is_token_admin};
use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult, JsonResult},
    auth::Headers,
    crypto::ct_eq,
    db::{
        DbConn,
        models::{
            CONSUMER_TENANT, Device, Event, EventType, Membership, MembershipId, MembershipStatus, MembershipType,
            MspClient, MspMembership, MspStaff, OrgPolicy, OrgPolicyType, Organization, OrganizationId, SsoAuthRow,
            SsoConfig, SsoDomain, SsoLink, SsoLinkTicket, User, UserId, email_domain, normalize_domain, normalize_guid,
            normalize_identifier, pkce_challenge, sso_hash, sso_random, txt_value,
        },
    },
    mail,
    util::format_date,
};

pub fn routes() -> Vec<Route> {
    routes![
        get_sso,
        put_sso,
        add_domain,
        verify_domain,
        remove_domain,
        unlink,
        rotate_api_keys,
        link_ticket,
        unlink_self
    ]
}

/// What this server asks Entra for: an ID token with the person's object id
/// and tenant (`profile`), and their email as a suggestion (`email`).
pub const SCOPES: &str = "openid profile email";

/// The redirect URI each organization's app registration has in Entra.
pub fn callback_uri() -> String {
    format!("{}/identity/connect/oidc-signin", CONFIG.domain())
}

/// Where the web vault and the browser extension want the answer: the web
/// vault's SSO connector page. Nothing else is accepted.
fn connector_uri() -> String {
    format!("{}/sso-connector.html", CONFIG.domain())
}

/// The most email domains one organization may add.
const MAX_DOMAINS: usize = 20;

/// The client secret at rest.
///
/// Keykeeper: until the event-streaming change (server PR #36) lands its
/// sealed-secrets module, the secret is kept as it was typed, behind these two
/// functions, which are the only place it's read or written. When #36 merges,
/// they call that module (bound to the organization), and nothing else
/// changes. This branch must not merge before then. See DESIGN.md, "Sign in
/// with Microsoft Entra ID", "The client secret".
mod secret {
    use crate::db::models::OrganizationId;

    const PLAIN: &str = "unsealed.";

    pub fn seal(_org: &OrganizationId, secret: &str) -> Result<String, String> {
        Ok(format!("{PLAIN}{secret}"))
    }

    pub fn open(_org: &OrganizationId, stored: &str) -> Result<String, String> {
        stored
            .strip_prefix(PLAIN)
            .map(str::to_owned)
            .ok_or_else(|| "This server can't read the app's client secret. Enter it again.".to_owned())
    }
}

/// Owners and admins of the organization, and an MSP's admins in its clients
/// (never other MSP staff), as for provisioning. Anyone else gets "not
/// found": upstream's web vault signs out on 403.
async fn require_admin(org_id: &OrganizationId, headers: &Headers, conn: &DbConn) -> EmptyResult {
    if !is_token_admin(org_id, &headers.user.uuid, conn).await {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    }
    Ok(())
}

/// An organization event about single sign-on, with or without a person.
#[expect(clippy::too_many_arguments)]
async fn log_sso_event(
    event_type: EventType,
    org_id: &OrganizationId,
    member: Option<&MembershipId>,
    act_user: Option<&UserId>,
    detail: Option<String>,
    device_type: Option<i32>,
    ip: &IpAddr,
    conn: &DbConn,
) {
    if !CONFIG.org_events_enabled() {
        return;
    }
    let mut event = Event::new(event_type as i32, None);
    event.org_uuid = Some(org_id.clone());
    event.org_user_uuid = member.cloned();
    event.user_uuid = act_user.cloned();
    event.act_user_uuid = act_user.cloned();
    event.device_type = device_type;
    event.ip_address = Some(ip.to_string());
    event.keykeeper_detail = detail.map(|d| d.chars().take(300).collect());
    event.save(conn).await.unwrap_or(());
}

/// For an MSP's client, its activity log; nothing for other organizations.
async fn record_for_msp(
    org_id: &OrganizationId,
    event: &'static str,
    detail: Option<String>,
    headers: &Headers,
    conn: &DbConn,
) -> EmptyResult {
    let Some(client) = MspClient::find_by_org(org_id, conn).await else {
        return Ok(());
    };
    let name = Organization::find_by_uuid(org_id, conn).await.map(|o| o.name).unwrap_or_default();
    let mut audit = Audit::by(event, headers).org(org_id, &name);
    if let Some(detail) = detail {
        audit = audit.detail(detail);
    }
    audit.record(&client.msp_uuid, conn).await
}

/// Ends these people's sessions on every device (their refresh tokens stop
/// working), when the single sign-on that may have started them changes.
async fn end_sessions(users: &[UserId], conn: &DbConn) -> EmptyResult {
    let mut seen = std::collections::HashSet::new();
    for user in users {
        if seen.insert(user.clone()) {
            Device::rotate_refresh_tokens_by_user(user, conn).await?;
        }
    }
    Ok(())
}

async fn policy_on(org_id: &OrganizationId, policy: OrgPolicyType, conn: &DbConn) -> bool {
    OrgPolicy::find_by_org_and_type(org_id, policy, conn).await.is_some_and(|p| p.enabled)
}

// ---------------------------------------------------------------------------
// The settings page.

async fn view(org_id: &OrganizationId, conn: &DbConn) -> Value {
    let config = SsoConfig::find(org_id, conn).await;
    let mut domains = Vec::new();
    for d in SsoDomain::find_by_org(org_id, conn).await {
        let elsewhere = d.verified_at.is_none()
            && SsoDomain::find_verified(&d.domain, conn).await.is_some_and(|v| &v.org_uuid != org_id);
        domains.push(json!({
            "id": d.uuid,
            "domain": d.domain,
            "txtName": d.domain,
            "txtValue": txt_value(&d.txt_token),
            "verifiedAt": d.verified_at.as_ref().map(format_date),
            "lastCheckedAt": d.last_checked_at.as_ref().map(format_date),
            "verifiedElsewhere": elsewhere,
        }));
    }
    let mut links = Vec::new();
    for l in SsoLink::find_by_org(org_id, conn).await {
        let member = Membership::find_by_user_and_org(&l.user_uuid, org_id, conn).await;
        let email = User::find_by_uuid(&l.user_uuid, conn).await.map_or(l.email.clone(), |u| u.email);
        links.push(json!({
            "userId": l.user_uuid,
            "memberId": member.map(|m| m.uuid),
            "email": email,
            "linkedAt": format_date(&l.created_at),
            "lastUsedAt": l.last_used_at.as_ref().map(format_date),
        }));
    }
    json!({
        "enabled": config.as_ref().is_some_and(|c| c.enabled),
        "identifier": config.as_ref().map(|c| c.identifier.clone()),
        "tenantId": config.as_ref().map(|c| c.tenant_id.clone()),
        "clientId": config.as_ref().map(|c| c.client_id.clone()),
        "secretSavedAt": config.as_ref().and_then(|c| c.secret_set_at.as_ref().map(format_date)),
        "updatedBy": config.as_ref().map(|c| c.updated_by.clone()),
        "updatedAt": config.as_ref().map(|c| format_date(&c.updated_at)),
        "callbackUrl": callback_uri(),
        "signInUrl": config.as_ref().map(|c| format!("{}/#/sso?identifier={}", CONFIG.domain(), c.identifier)),
        "requireSso": policy_on(org_id, OrgPolicyType::RequireSso, conn).await,
        "singleOrg": policy_on(org_id, OrgPolicyType::SingleOrg, conn).await,
        "domains": domains,
        "links": links,
    })
}

#[get("/keykeeper/organizations/<org_id>/sso")]
async fn get_sso(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&org_id, &headers, &conn).await?;
    Ok(Json(view(&org_id, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SsoSettings {
    enabled: bool,
    identifier: String,
    tenant_id: String,
    client_id: String,
    /// A new secret, or nothing to keep the saved one.
    client_secret: Option<String>,
}

/// Saves the organization's single sign-on settings. Turning it on checks
/// that Microsoft knows the tenant. The secret is never sent back.
#[put("/keykeeper/organizations/<org_id>/sso", data = "<data>")]
async fn put_sso(org_id: OrganizationId, data: Json<SsoSettings>, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&org_id, &headers, &conn).await?;
    let data = data.into_inner();
    let Some(identifier) = normalize_identifier(&data.identifier) else {
        err!("The SSO identifier is 3 to 40 lowercase letters, digits, and hyphens, such as acme-dental.")
    };
    let Some(tenant_id) = normalize_guid(&data.tenant_id) else {
        err!(
            "The tenant ID is the Directory (tenant) ID on the app's Overview page in Entra, a GUID such as 72f988bf-86f1-41af-91ab-2d7cd011db47."
        )
    };
    if tenant_id == CONSUMER_TENANT {
        err!("That's the tenant for personal Microsoft accounts. Use your organization's own tenant ID.")
    }
    let Some(client_id) = normalize_guid(&data.client_id) else {
        err!("The client ID is the Application (client) ID on the app's Overview page in Entra, a GUID.")
    };
    let new_secret = data.client_secret.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if new_secret.is_some_and(|s| s.len() > 512 || s.chars().any(char::is_control)) {
        err!(
            "That doesn't look like a client secret. Copy its Value (not its Secret ID) from Certificates & secrets in Entra."
        )
    }
    if let Some(other) = SsoConfig::find_by_identifier(&identifier, &conn).await
        && other.org_uuid != org_id
    {
        err!("Another organization uses that SSO identifier. Choose another.")
    }

    let old = SsoConfig::find(&org_id, &conn).await;
    let mut config = old.clone().unwrap_or_else(|| SsoConfig::new(org_id.clone(), &headers.user.email));
    let was_enabled = old.as_ref().is_some_and(|c| c.enabled);
    if was_enabled && !data.enabled && policy_on(&org_id, OrgPolicyType::RequireSso, &conn).await {
        err!("Turn off the Require single sign-on policy first, so members can still sign in.")
    }
    if data.enabled && new_secret.is_none() && config.client_secret.is_none() {
        err!("Paste the app's client secret to turn on single sign-on.")
    }

    let mut changed = Vec::new();
    if old.as_ref().is_none_or(|c| c.identifier != identifier) {
        changed.push("identifier");
    }
    if old.as_ref().is_none_or(|c| c.tenant_id != tenant_id) {
        changed.push("tenant");
    }
    if old.as_ref().is_none_or(|c| c.client_id != client_id) {
        changed.push("app");
    }
    if new_secret.is_some() {
        changed.push("client secret");
    }

    if data.enabled {
        // Microsoft must know the tenant before anyone is sent there.
        entra::forget(&tenant_id);
        if let Err(e) = entra::provider(&tenant_id).await {
            err!(format!("Microsoft didn't recognize the tenant {tenant_id}: {e}. Check the tenant ID."))
        }
    }

    // Sessions that single sign-on started end when what vouched for them
    // goes: the old tenant's people lose their links, and turning it off
    // ends every linked person's sessions.
    let mut ended = Vec::new();
    if old.as_ref().is_some_and(|c| c.tenant_id != tenant_id) {
        // Links name the old tenant's people, who can't sign in here anymore.
        for l in SsoLink::find_by_org(&org_id, &conn).await {
            if l.tenant_id != tenant_id {
                SsoLink::delete(&org_id, &l.user_uuid, &conn).await?;
                ended.push(l.user_uuid);
            }
        }
    }
    if was_enabled && !data.enabled {
        ended.extend(SsoLink::find_by_org(&org_id, &conn).await.into_iter().map(|l| l.user_uuid));
    }
    end_sessions(&ended, &conn).await?;

    config.enabled = data.enabled;
    config.identifier = identifier;
    config.tenant_id = tenant_id;
    config.client_id = client_id;
    if let Some(s) = new_secret {
        config.client_secret = Some(match secret::seal(&org_id, s) {
            Ok(sealed) => sealed,
            Err(e) => err!(e),
        });
        config.secret_set_at = Some(Utc::now().naive_utc());
    }
    config.updated_by = headers.user.email.clone();
    config.save(&conn).await?;

    let (dt, ip) = (Some(headers.device.atype), headers.ip.ip);
    if data.enabled != was_enabled {
        let (event, audit) = if data.enabled {
            (EventType::OrganizationEnabledSso, "sso_turned_on")
        } else {
            (EventType::OrganizationDisabledSso, "sso_turned_off")
        };
        log_sso_event(event, &org_id, None, Some(&headers.user.uuid), None, dt, &ip, &conn).await;
        record_for_msp(&org_id, audit, None, &headers, &conn).await?;
    }
    if !changed.is_empty() {
        let detail = changed.join(", ");
        log_sso_event(
            EventType::KeykeeperSsoSettingsChanged,
            &org_id,
            None,
            Some(&headers.user.uuid),
            Some(detail.clone()),
            dt,
            &ip,
            &conn,
        )
        .await;
        record_for_msp(&org_id, "sso_settings_changed", Some(detail), &headers, &conn).await?;
    }
    Ok(Json(view(&org_id, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DomainData {
    domain: String,
}

#[post("/keykeeper/organizations/<org_id>/sso/domains", data = "<data>")]
async fn add_domain(org_id: OrganizationId, data: Json<DomainData>, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&org_id, &headers, &conn).await?;
    let raw = data.into_inner().domain;
    let raw = raw.trim();
    let raw = raw.rsplit_once('@').map_or(raw, |(_, d)| d);
    let Some(domain) = normalize_domain(raw) else {
        err!("Enter a domain such as acmedental.com.")
    };
    let existing = SsoDomain::find_by_org(&org_id, &conn).await;
    if existing.iter().any(|d| d.domain == domain) {
        err!(format!("{domain} is already on the list."))
    }
    if existing.len() >= MAX_DOMAINS {
        err!(format!("An organization can verify up to {MAX_DOMAINS} domains."))
    }
    if SsoDomain::find_verified(&domain, &conn).await.is_some() {
        err!(format!("Another organization verified {domain}. A domain belongs to one organization."))
    }
    SsoDomain::new(org_id.clone(), domain.clone(), &headers.user.email).insert(&conn).await?;
    log_sso_event(
        EventType::OrganizationDomainAdded,
        &org_id,
        None,
        Some(&headers.user.uuid),
        Some(domain.clone()),
        Some(headers.device.atype),
        &headers.ip.ip,
        &conn,
    )
    .await;
    record_for_msp(&org_id, "sso_domain_added", Some(domain), &headers, &conn).await?;
    Ok(Json(view(&org_id, &conn).await))
}

/// Looks for the domain's TXT record now. Found: the domain is verified,
/// unless another organization verified it first.
#[post("/keykeeper/organizations/<org_id>/sso/domains/<domain_id>/verify")]
async fn verify_domain(org_id: OrganizationId, domain_id: &str, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&org_id, &headers, &conn).await?;
    let Some(d) = SsoDomain::find(domain_id, &org_id, &conn).await else {
        err_code!("Domain not found", rocket::http::Status::NotFound.code)
    };
    if d.verified_at.is_some() {
        return Ok(Json(view(&org_id, &conn).await));
    }
    if SsoDomain::find_verified(&d.domain, &conn).await.is_some() {
        err!(format!("Another organization verified {} first. A domain belongs to one organization.", d.domain))
    }
    let records = match dns::txt_records(&d.domain).await {
        Ok(r) => r,
        Err(e) => {
            d.mark_checked(&conn).await?;
            err!(format!("Couldn't check {}: {e}. Try again in a few minutes.", d.domain))
        }
    };
    let (dt, ip) = (Some(headers.device.atype), headers.ip.ip);
    let found = dns::has_record(&records, &txt_value(&d.txt_token));
    if found {
        if !d.mark_verified(&conn).await {
            err!(format!("Another organization verified {} first. A domain belongs to one organization.", d.domain))
        }
        log_sso_event(
            EventType::OrganizationDomainVerified,
            &org_id,
            None,
            Some(&headers.user.uuid),
            Some(d.domain.clone()),
            dt,
            &ip,
            &conn,
        )
        .await;
        record_for_msp(&org_id, "sso_domain_verified", Some(d.domain.clone()), &headers, &conn).await?;
    } else {
        d.mark_checked(&conn).await?;
        log_sso_event(
            EventType::OrganizationDomainNotVerified,
            &org_id,
            None,
            Some(&headers.user.uuid),
            Some(d.domain.clone()),
            dt,
            &ip,
            &conn,
        )
        .await;
    }
    let mut answer = view(&org_id, &conn).await;
    answer["check"] = json!({ "domain": d.domain, "found": found });
    Ok(Json(answer))
}

#[delete("/keykeeper/organizations/<org_id>/sso/domains/<domain_id>")]
async fn remove_domain(org_id: OrganizationId, domain_id: &str, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&org_id, &headers, &conn).await?;
    let Some(d) = SsoDomain::find(domain_id, &org_id, &conn).await else {
        err_code!("Domain not found", rocket::http::Status::NotFound.code)
    };
    d.delete(&conn).await?;
    log_sso_event(
        EventType::OrganizationDomainRemoved,
        &org_id,
        None,
        Some(&headers.user.uuid),
        Some(d.domain.clone()),
        Some(headers.device.atype),
        &headers.ip.ip,
        &conn,
    )
    .await;
    record_for_msp(&org_id, "sso_domain_removed", Some(d.domain), &headers, &conn).await?;
    Ok(Json(view(&org_id, &conn).await))
}

/// Unlinks an account: the next time its person signs in with the
/// organization's single sign-on, they're linked again under the rules (say,
/// to a new Entra account after theirs was recreated).
#[delete("/keykeeper/organizations/<org_id>/sso/links/<user_id>")]
async fn unlink(org_id: OrganizationId, user_id: UserId, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&org_id, &headers, &conn).await?;
    let Some(link) = SsoLink::find_by_user(&org_id, &user_id, &conn).await else {
        err_code!("Link not found", rocket::http::Status::NotFound.code)
    };
    SsoLink::delete(&org_id, &user_id, &conn).await?;
    // Sessions it started end; they sign in again (and link again) from scratch.
    end_sessions(std::slice::from_ref(&user_id), &conn).await?;
    let member = Membership::find_by_user_and_org(&user_id, &org_id, &conn).await.map(|m| m.uuid);
    log_sso_event(
        EventType::OrganizationUserUnlinkedSso,
        &org_id,
        member.as_ref(),
        Some(&headers.user.uuid),
        Some(link.email.clone()),
        Some(headers.device.atype),
        &headers.ip.ip,
        &conn,
    )
    .await;
    if let Some(client) = MspClient::find_by_org(&org_id, &conn).await {
        let name = Organization::find_by_uuid(&org_id, &conn).await.map(|o| o.name).unwrap_or_default();
        Audit::by("sso_unlinked", &headers)
            .org(&org_id, &name)
            .target(&link.email)
            .record(&client.msp_uuid, &conn)
            .await?;
    }
    Ok(Json(view(&org_id, &conn).await))
}

/// With "Require single sign-on" on, replaces the API keys of the members it
/// covers: an API key signs in without single sign-on (the CLI's
/// client_credentials, as upstream allows), so an admin can make the old
/// keys stop working. Members get a new key from their account settings,
/// after signing in with single sign-on.
#[post("/keykeeper/organizations/<org_id>/sso/rotate-api-keys")]
async fn rotate_api_keys(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&org_id, &headers, &conn).await?;
    if !policy_on(&org_id, OrgPolicyType::RequireSso, &conn).await {
        err!("Turn on the Require single sign-on policy first.")
    }
    let mut replaced = 0;
    for m in Membership::find_by_org(&org_id, &conn).await {
        if m.status < MembershipStatus::Accepted as i32 || exempt_from_requirement(&m.user_uuid, &m, &conn).await {
            continue;
        }
        if let Some(mut user) = User::find_by_uuid(&m.user_uuid, &conn).await
            && user.api_key.is_some()
        {
            user.api_key = Some(crate::crypto::generate_api_key());
            user.save(&conn).await?;
            replaced += 1;
        }
    }
    let detail = format!("{replaced} members' API keys replaced");
    log_sso_event(
        EventType::KeykeeperSsoSettingsChanged,
        &org_id,
        None,
        Some(&headers.user.uuid),
        Some(detail.clone()),
        Some(headers.device.atype),
        &headers.ip.ip,
        &conn,
    )
    .await;
    record_for_msp(&org_id, "sso_api_keys_replaced", Some(replaced.to_string()), &headers, &conn).await?;
    let mut answer = view(&org_id, &conn).await;
    answer["apiKeysReplaced"] = json!(replaced);
    Ok(Json(answer))
}

/// Upstream's Link SSO, step one: a signed-in session asks for a ticket that
/// names its account, and passes it to /identity/connect/authorize as
/// `user_identifier`. Five minutes, once.
#[get("/accounts/sso/user-identifier")]
async fn link_ticket(headers: Headers, conn: DbConn) -> JsonResult {
    crate::ratelimit::check_limit_prelogin(&headers.ip.ip)?;
    let (ticket, row) = SsoLinkTicket::generate(headers.user.uuid.clone());
    row.insert(&conn).await?;
    Ok(Json(json!(ticket)))
}

/// Upstream's Unlink SSO: someone unlinks their own account from an
/// organization's single sign-on. Its sessions end.
#[delete("/accounts/sso/<org_id>")]
async fn unlink_self(org_id: OrganizationId, headers: Headers, conn: DbConn) -> EmptyResult {
    let Some(link) = SsoLink::find_by_user(&org_id, &headers.user.uuid, &conn).await else {
        err_code!("Link not found", rocket::http::Status::NotFound.code)
    };
    SsoLink::delete(&org_id, &headers.user.uuid, &conn).await?;
    let member = Membership::find_by_user_and_org(&headers.user.uuid, &org_id, &conn).await.map(|m| m.uuid);
    log_sso_event(
        EventType::OrganizationUserUnlinkedSso,
        &org_id,
        member.as_ref(),
        Some(&headers.user.uuid),
        Some(link.email),
        Some(headers.device.atype),
        &headers.ip.ip,
        &conn,
    )
    .await;
    User::update_uuid_revision(&headers.user.uuid, &conn).await;
    // Other devices' sessions end; this one signs in again too.
    end_sessions(std::slice::from_ref(&headers.user.uuid), &conn).await
}

/// For the apps: the organization's SSO identifier, when its single sign-on
/// is on, and whether this account is linked to it. Upstream's apps offer
/// Link SSO, or Unlink SSO, from these.
pub async fn profile_fields(org_id: &OrganizationId, user_id: &UserId, conn: &DbConn) -> (Option<String>, bool) {
    match SsoConfig::find(org_id, conn).await.filter(SsoConfig::ready) {
        Some(config) => (Some(config.identifier), SsoLink::find_by_user(org_id, user_id, conn).await.is_some()),
        None => (None, false),
    }
}

// ---------------------------------------------------------------------------
// What the rest of the server asks.

/// The organizations that let someone find them by email: the one that
/// verified the email's domain, if its single sign-on is on. Answers
/// upstream's /organizations/domain/sso/verified, which the web vault's /sso
/// page asks before anything is typed.
pub async fn verified_for_email(email: &str, conn: &DbConn) -> Value {
    let mut data = Vec::new();
    if let Some(domain) = email_domain(email)
        && let Some(d) = SsoDomain::find_verified(&domain, conn).await
        && let Some(config) = SsoConfig::find(&d.org_uuid, conn).await.filter(SsoConfig::ready)
    {
        // Only the identifier, which is all the web vault uses: anyone can ask,
        // so the answer doesn't name the organization.
        data.push(json!({ "organizationIdentifier": config.identifier }));
    }
    json!({ "object": "list", "data": data, "continuationToken": null })
}

/// The organization an SSO identifier names, for upstream's first sign-in
/// (setting a master password, enrolling in account recovery).
pub async fn org_for_identifier(identifier: &str, conn: &DbConn) -> Option<Organization> {
    let config = SsoConfig::find_by_identifier(identifier, conn).await?;
    Organization::find_by_uuid(&config.org_uuid, conn).await
}

/// Whether someone is on an MSP's staff, or in any organization through an
/// MSP. Their account reaches every client they work in, so no client's
/// single sign-on signs them in. Fails closed: a database error counts as
/// staff (MspStaff::is_staff_anywhere).
async fn msp_person(user_id: &UserId, memberships: &[Membership], conn: &DbConn) -> bool {
    if MspStaff::is_staff_anywhere(user_id, conn).await {
        return true;
    }
    for m in memberships {
        if MspMembership::find_by_membership(&m.uuid, conn).await.is_some() {
            return true;
        }
    }
    false
}

/// Whether "Require single sign-on" leaves this membership alone: an owner,
/// a membership that came through an MSP, or staff of the MSP that manages
/// this organization. Decided per organization, so joining some other MSP's
/// staff (or making one) never gets anyone out of it.
async fn exempt_from_requirement(user_id: &UserId, member: &Membership, conn: &DbConn) -> bool {
    if member.atype == MembershipType::Owner as i32 {
        return true;
    }
    if MspMembership::find_by_membership(&member.uuid, conn).await.is_some() {
        return true;
    }
    match MspClient::find_by_org(&member.org_uuid, conn).await {
        Some(client) => MspStaff::find(&client.msp_uuid, user_id, conn).await.is_some(),
        None => false,
    }
}

/// The organizations that require this person to sign in with their single
/// sign-on, with each one's SSO identifier: "Require single sign-on" is on,
/// its single sign-on is on, and they've joined it (accepted or confirmed)
/// and aren't exempt there.
pub async fn required_orgs(user_id: &UserId, conn: &DbConn) -> Vec<(OrganizationId, String)> {
    let mut required = Vec::new();
    for m in Membership::find_by_user(user_id, conn).await {
        if m.status < MembershipStatus::Accepted as i32 {
            continue;
        }
        if !policy_on(&m.org_uuid, OrgPolicyType::RequireSso, conn).await {
            continue;
        }
        if exempt_from_requirement(user_id, &m, conn).await {
            continue;
        }
        if let Some(config) = SsoConfig::find(&m.org_uuid, conn).await.filter(SsoConfig::ready) {
            required.push((m.org_uuid, config.identifier));
        }
    }
    required
}

/// The SSO identifier of an organization that requires this person to sign
/// in with its single sign-on, if one does (`required_orgs`). The password
/// login answers with it, and the apps take the person to that sign-in.
pub async fn required_identifier(user_id: &UserId, conn: &DbConn) -> Option<String> {
    required_orgs(user_id, conn).await.into_iter().next().map(|(_, identifier)| identifier)
}

/// Whether a session single sign-on started may go on: the account is still
/// linked in an organization whose single sign-on is on. Checked at every
/// refresh.
pub async fn sso_session_live(user_id: &UserId, conn: &DbConn) -> bool {
    for link in SsoLink::find_all_by_user(user_id, conn).await {
        if SsoConfig::find(&link.org_uuid, conn).await.is_some_and(|c| c.ready() && c.tenant_id == link.tenant_id) {
            return true;
        }
    }
    false
}

/// The checks for "Require single sign-on" and what it depends on, run
/// wherever a policy changes (upstream's put_policy and MSP defaults).
pub async fn check_policy(org_id: &OrganizationId, policy: OrgPolicyType, enabled: bool, conn: &DbConn) -> EmptyResult {
    match policy {
        OrgPolicyType::RequireSso if enabled => {
            if !SsoConfig::find(org_id, conn).await.is_some_and(|c| c.ready()) {
                err!("Turn on single sign-on (Settings, Single sign-on) before requiring it.")
            }
            if !policy_on(org_id, OrgPolicyType::SingleOrg, conn).await {
                err!("Turn on the Single organization policy before requiring single sign-on.")
            }
        }
        OrgPolicyType::SingleOrg if !enabled && policy_on(org_id, OrgPolicyType::RequireSso, conn).await => {
            err!("Turn off Require single sign-on before turning off Single organization.")
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Signing in (called from api/identity.rs).

/// Before leaving for Microsoft, the web vault checks the identifier.
pub async fn prevalidate(identifier: Option<&str>, ip: &IpAddr, conn: &DbConn) -> JsonResult {
    crate::ratelimit::check_limit_prelogin(ip)?;
    match identifier {
        Some(id) if SsoConfig::find_by_identifier(id, conn).await.is_some_and(|c| c.ready()) => {
            // The apps pass this back to authorize, which doesn't need it.
            Ok(Json(json!({ "token": "" })))
        }
        _ => err!("No organization uses that SSO identifier, or its single sign-on is turned off."),
    }
}

/// What the app sent to /identity/connect/authorize.
pub struct Authorize {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub domain_hint: Option<String>,
    /// Upstream's Link SSO: a signed-in session's link ticket
    /// (`/api/accounts/sso/user-identifier`).
    pub user_identifier: Option<String>,
}

const BINDING_COOKIE: &str = "PB_SSO_BINDING";

fn binding_cookie_path() -> String {
    format!("{}/identity/connect/", CONFIG.domain_path())
}

/// A PKCE challenge as the apps make it: base64url of a SHA-256.
fn looks_like_challenge(challenge: &str) -> bool {
    challenge.len() == 43 && challenge.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Starts a sign-in: checks what the app sent, remembers it, and sends the
/// browser to the organization's tenant.
pub async fn authorize(a: Authorize, cookies: &CookieJar<'_>, ip: &IpAddr, conn: &DbConn) -> ApiResult<Redirect> {
    // Each start keeps a row for ten minutes, so starts are limited per
    // address, with the allowance pre-login gets.
    crate::ratelimit::check_limit_prelogin(ip)?;
    SsoAuthRow::purge_expired(conn).await;
    if a.client_id != "web" && a.client_id != "browser" {
        err!("Single sign-on works from the web vault and the browser extension.")
    }
    if a.redirect_uri != connector_uri() {
        err!("Unsupported redirect URI")
    }
    if a.code_challenge_method != "S256" || !looks_like_challenge(&a.code_challenge) {
        err!("Unsupported code challenge")
    }
    if a.state.is_empty() || a.state.len() > 1024 {
        err!("Unsupported state")
    }
    // The web vault puts the identifier in domain_hint and at the end of its state.
    let identifier = a
        .domain_hint
        .clone()
        .filter(|h| !h.is_empty())
        .or_else(|| a.state.rsplit_once("_identifier=").map(|(_, id)| id.to_owned()))
        .unwrap_or_default();
    let Some(config) = SsoConfig::find_by_identifier(&identifier, conn).await.filter(SsoConfig::ready) else {
        err!("No organization uses that SSO identifier, or its single sign-on is turned off.")
    };
    // Linking from a signed-in session: the ticket names the account, once.
    let link_user_uuid = match a.user_identifier.as_deref().filter(|t| !t.is_empty()) {
        Some(ticket) => match SsoLinkTicket::take(ticket, conn).await {
            Some(user) if a.client_id == "web" => Some(user),
            _ => err!("This request to link single sign-on expired. Choose Link SSO again."),
        },
        None => None,
    };
    let provider = match entra::provider(&config.tenant_id).await {
        Ok(p) => p,
        Err(e) => err!(format!("Microsoft sign-in isn't available for this organization right now: {e}.")),
    };

    let (state, nonce, verifier, binding) = (sso_random(), sso_random(), sso_random(), sso_random());
    SsoAuthRow {
        state_hash: sso_hash(&state),
        org_uuid: config.org_uuid.clone(),
        client_id: a.client_id,
        redirect_uri: a.redirect_uri,
        client_state: a.state,
        client_challenge: a.code_challenge,
        nonce: nonce.clone(),
        code_verifier: verifier.clone(),
        binding_hash: sso_hash(&binding),
        code_hash: None,
        link_user_uuid,
        identity: None,
        error: None,
        created_at: Utc::now().naive_utc(),
        returned_at: None,
    }
    .insert(conn)
    .await?;

    let Ok(url) = url::Url::parse_with_params(
        &provider.authorization_endpoint,
        &[
            ("client_id", config.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", &callback_uri()),
            ("response_mode", "query"),
            ("scope", SCOPES),
            ("state", &state),
            ("nonce", &nonce),
            ("code_challenge", &pkce_challenge(&verifier)),
            ("code_challenge_method", "S256"),
        ],
    ) else {
        err!("The tenant's sign-in address isn't a URL")
    };

    cookies.add(
        Cookie::build((BINDING_COOKIE, binding))
            .path(binding_cookie_path())
            .max_age(time::Duration::minutes(crate::db::models::SSO_AUTH_MINUTES))
            // Lax: Microsoft's answer is a top-level navigation from another site.
            .same_site(SameSite::Lax)
            .http_only(true)
            // From the server's own address, never a request header.
            .secure(CONFIG.domain().starts_with("https://"))
            .build(),
    );
    Ok(Redirect::temporary(String::from(url)))
}

/// Redeems Microsoft's code and checks the ID token it returns.
async fn exchange(row: &SsoAuthRow, code: &str, conn: &DbConn) -> Result<Identity, String> {
    // The settings are read again: they may have changed since the sign-in started.
    let Some(config) = SsoConfig::find(&row.org_uuid, conn).await.filter(SsoConfig::ready) else {
        return Err("Single sign-on was turned off for this organization.".to_owned());
    };
    let client_secret = secret::open(&row.org_uuid, config.client_secret.as_deref().unwrap_or_default())?;
    let provider = entra::provider(&config.tenant_id).await?;
    let id_token = entra::redeem(
        &provider,
        &entra::Redeem {
            client_id: &config.client_id,
            client_secret: &client_secret,
            code,
            code_verifier: &row.code_verifier,
            redirect_uri: &callback_uri(),
        },
    )
    .await?;
    let expected = Expected {
        issuer: &provider.issuer,
        tenant_id: &config.tenant_id,
        client_id: &config.client_id,
        nonce: &row.nonce,
        now: Utc::now().timestamp(),
    };
    let keys = entra::keys(&config.tenant_id, &provider, false).await?;
    let checked = match token::validate(&id_token, &keys, &expected) {
        // Microsoft rolled its keys: fetch them again, once.
        Err(token::Refusal::UnknownKey) => {
            let keys = entra::keys(&config.tenant_id, &provider, true).await?;
            token::validate(&id_token, &keys, &expected)
        }
        other => other,
    };
    checked.map_err(|r| r.detail().to_owned())
}

/// Microsoft's answer (/identity/connect/oidc-signin): taken once, from the
/// browser that started the sign-in. Whatever it comes to, the app gets a
/// one-time code of this server's own, and learns the outcome when it
/// redeems it, so the person sees what went wrong.
pub async fn callback(
    state: &str,
    code: Option<&str>,
    error: Option<(&str, Option<&str>)>,
    cookies: &CookieJar<'_>,
    ip: &IpAddr,
    conn: &DbConn,
) -> ApiResult<Redirect> {
    const START_AGAIN: &str = "This sign-in expired or was already used. Go back to PassBundle and sign in again.";
    let Some(row) = SsoAuthRow::find_waiting(state, conn).await else {
        err!(START_AGAIN)
    };
    // Taken now, whatever happens next: a state never works twice.
    if !row.take(conn).await {
        err!(START_AGAIN)
    }
    let binding = cookies.get(BINDING_COOKIE).map(|c| c.value().to_owned());
    cookies.remove(Cookie::build(BINDING_COOKIE).path(binding_cookie_path()).build());
    if !binding.is_some_and(|b| ct_eq(sso_hash(&b), &row.binding_hash)) {
        log_sso_event(
            EventType::KeykeeperSsoRefused,
            &row.org_uuid,
            None,
            None,
            Some("Microsoft's answer reached a browser that didn't start the sign-in".to_owned()),
            None,
            ip,
            conn,
        )
        .await;
        err!("This sign-in was started in another browser. Sign in again from this one.")
    }

    // Who it is, or what the person is told and a few words for the event log.
    let outcome: Result<Identity, (String, String)> = match (error, code) {
        (Some((error, description)), _) => {
            let description: String = description.unwrap_or("").chars().take(300).collect();
            let detail = format!("Microsoft refused: {error} {description}").trim().to_owned();
            Err((format!("Microsoft didn't sign you in ({error}). {description}").trim().to_owned(), detail))
        }
        (None, Some(code)) => exchange(&row, code, conn).await.map_err(|detail| {
            (
                format!(
                    "Microsoft's sign-in for this organization didn't check out ({detail}). Ask your administrator to check its single sign-on settings."
                ),
                detail,
            )
        }),
        (None, None) => Err(("Microsoft's answer had no code.".to_owned(), "Microsoft's answer had no code".to_owned())),
    };
    let our_code = sso_random();
    match outcome {
        // Linking from a signed-in session finishes here: the app is already
        // signed in, and goes back to where it was.
        Ok(identity) if row.link_user_uuid.is_some() => {
            link_session(&row, &identity, ip, conn).await?;
            row.delete(conn).await?;
        }
        Ok(identity) => {
            let identity = serde_json::to_string(&identity)?;
            row.finish(&our_code, Some(identity), None, conn).await?;
        }
        Err((message, detail)) if row.link_user_uuid.is_some() => {
            log_sso_event(EventType::KeykeeperSsoRefused, &row.org_uuid, None, None, Some(detail), None, ip, conn)
                .await;
            row.delete(conn).await?;
            err!(message)
        }
        Err((message, detail)) => {
            log_sso_event(EventType::KeykeeperSsoRefused, &row.org_uuid, None, None, Some(detail), None, ip, conn)
                .await;
            row.finish(&our_code, None, Some(message), conn).await?;
        }
    }
    let Ok(mut url) = url::Url::parse(&row.redirect_uri) else {
        err!("Unsupported redirect URI")
    };
    url.query_pairs_mut().append_pair("code", &our_code).append_pair("state", &row.client_state);
    Ok(Redirect::temporary(String::from(url)))
}

/// Links the signed-in session's account to the Microsoft account that just
/// signed in (upstream's Link SSO), under the rules in link.rs, then tells
/// the account by email and logs it.
async fn link_session(row: &SsoAuthRow, identity: &Identity, ip: &IpAddr, conn: &DbConn) -> EmptyResult {
    let (Some(user_id), Some(org)) =
        (row.link_user_uuid.as_ref(), Organization::find_by_uuid(&row.org_uuid, conn).await)
    else {
        err!("This request to link single sign-on expired. Choose Link SSO again.")
    };
    let Some(user) = User::find_by_uuid(user_id, conn).await else {
        err!("This account no longer exists.")
    };
    let account = candidate(user, &org.uuid, identity, conn).await;
    let facts = link::SessionFacts {
        microsoft_account_linked_to: SsoLink::find(&org.uuid, &identity.tenant_id, &identity.object_id, conn)
            .await
            .map(|l| l.user_uuid),
        account,
    };
    let member = facts.account.membership.as_ref().map(|(id, _)| id.clone());
    match link::decide_session(&facts) {
        Decision::SignIn(_) => Ok(()),
        Decision::Link(user_id) => {
            let Some(user) = User::find_by_uuid(&user_id, conn).await else {
                err!("This account no longer exists.")
            };
            make_link(&org, identity, &user, member.as_ref(), None, ip, conn).await
        }
        Decision::Refuse(refusal) => {
            log_sso_event(
                EventType::KeykeeperSsoRefused,
                &org.uuid,
                member.as_ref(),
                Some(user_id),
                Some(refusal.detail()),
                None,
                ip,
                conn,
            )
            .await;
            err!(refusal.message(&org.name))
        }
    }
}

/// Makes a link and says so: the organization's event log (the person's
/// first single sign-on), and an email to the account, so a link nobody
/// expected is seen.
async fn make_link(
    org: &Organization,
    identity: &Identity,
    user: &User,
    member: Option<&MembershipId>,
    device_type: Option<i32>,
    ip: &IpAddr,
    conn: &DbConn,
) -> EmptyResult {
    let link = SsoLink::new(
        org.uuid.clone(),
        identity.tenant_id.clone(),
        identity.object_id.clone(),
        user.uuid.clone(),
        identity.email.clone().unwrap_or_else(|| user.email.clone()),
    );
    if !link.insert(conn).await {
        err!("This account or Microsoft account was just linked to another. Ask your administrator.")
    }
    // The apps learn of the link (Link SSO becomes Unlink SSO) at their next sync.
    User::update_uuid_revision(&user.uuid, conn).await;
    log_sso_event(
        EventType::OrganizationUserFirstSsoLogin,
        &org.uuid,
        member,
        Some(&user.uuid),
        identity.email.clone(),
        device_type,
        ip,
        conn,
    )
    .await;
    if CONFIG.mail_enabled()
        && let Err(e) = mail::send_sso_linked(&user.email, &org.name, identity.email.as_deref()).await
    {
        error!("Error sending the single sign-on link email: {e:#?}");
    }
    Ok(())
}

/// What the decision needs to know about one account.
async fn candidate(user: User, org_id: &OrganizationId, identity: &Identity, conn: &DbConn) -> Candidate {
    let memberships = Membership::find_any_state_by_user(&user.uuid, conn).await;
    let here = memberships.iter().find(|m| &m.org_uuid == org_id).map(|m| (m.uuid.clone(), m.status));
    let other_orgs = memberships.iter().filter(|m| &m.org_uuid != org_id).count();
    let msp_staff = msp_person(&user.uuid, &memberships, conn).await;
    let domain_verified = match email_domain(&user.email) {
        Some(domain) => SsoDomain::is_verified_for(org_id, &domain, conn).await,
        None => false,
    };
    let linked_elsewhere = SsoLink::find_by_user(org_id, &user.uuid, conn)
        .await
        .is_some_and(|l| l.tenant_id != identity.tenant_id || l.object_id != identity.object_id);
    Candidate {
        user_id: user.uuid.clone(),
        email: user.email.clone(),
        enabled: user.enabled,
        msp_staff,
        has_keys: user.private_key.is_some(),
        membership: here,
        other_orgs,
        domain_verified,
        linked_elsewhere,
    }
}

async fn load_facts(org_id: &OrganizationId, identity: &Identity, conn: &DbConn) -> Facts {
    let linked = match SsoLink::find(org_id, &identity.tenant_id, &identity.object_id, conn).await {
        Some(l) => match User::find_by_uuid(&l.user_uuid, conn).await {
            Some(user) => Some(candidate(user, org_id, identity, conn).await),
            None => None,
        },
        None => None,
    };
    let email_domain_verified = match identity.email.as_deref().and_then(email_domain) {
        Some(domain) => SsoDomain::is_verified_for(org_id, &domain, conn).await,
        None => false,
    };
    let by_email = match (&linked, identity.email.as_deref()) {
        (None, Some(email)) => match User::find_by_mail(email, conn).await {
            Some(user) => Some(candidate(user, org_id, identity, conn).await),
            None => None,
        },
        _ => None,
    };
    Facts {
        linked,
        email: identity.email.clone(),
        email_edov: identity.email_edov,
        guest: identity.guest,
        email_domain_verified,
        by_email,
    }
}

/// A sign-in the app redeemed: who it is, and whether to link them.
pub struct SsoLogin {
    row: SsoAuthRow,
    identity: Identity,
    org_id: OrganizationId,
    new_link: bool,
    member: Option<MembershipId>,
}

/// The app redeems the code this server gave it (grant type
/// authorization_code at /identity/connect/token): from the same client, to
/// the same redirect URI, with the PKCE verifier for the challenge it started
/// with. Then link.rs decides which account it is. The code works again only
/// for the two-step login that may follow; `finish_login` ends it.
pub async fn redeem_code(
    code: &str,
    verifier: &str,
    client_id: Option<&str>,
    redirect_uri: Option<&str>,
    ip: &IpAddr,
    conn: &DbConn,
) -> ApiResult<(SsoLogin, User)> {
    let Some(row) = SsoAuthRow::find_by_code(code, conn).await else {
        err!("This sign-in expired or was already used. Sign in again.")
    };
    if client_id != Some(row.client_id.as_str())
        || redirect_uri != Some(row.redirect_uri.as_str())
        || !ct_eq(pkce_challenge(verifier), &row.client_challenge)
    {
        row.delete(conn).await?;
        err!("This sign-in didn't come from the app that started it. Sign in again.")
    }
    if let Some(message) = row.error.clone() {
        row.delete(conn).await?;
        err!(message)
    }
    let Some(identity) = row.identity.as_deref().and_then(|i| serde_json::from_str::<Identity>(i).ok()) else {
        row.delete(conn).await?;
        err!("This sign-in didn't finish. Sign in again.")
    };
    let config = SsoConfig::find(&row.org_uuid, conn).await.filter(SsoConfig::ready);
    let (Some(config), Some(org)) = (config, Organization::find_by_uuid(&row.org_uuid, conn).await) else {
        row.delete(conn).await?;
        err!("Single sign-on is turned off for this organization.")
    };
    if config.tenant_id != identity.tenant_id {
        row.delete(conn).await?;
        err!("This organization's single sign-on changed during the sign-in. Sign in again.")
    }

    let facts = load_facts(&org.uuid, &identity, conn).await;
    let (user_id, new_link) = match link::decide(&facts) {
        Decision::SignIn(user_id) => (user_id, false),
        Decision::Link(user_id) => (user_id, true),
        Decision::Refuse(refusal) => {
            let who = facts.linked.as_ref().or(facts.by_email.as_ref());
            let member = who.and_then(|c| c.membership.as_ref().map(|(id, _)| id.clone()));
            let user = who.map(|c| c.user_id.clone());
            log_sso_event(
                EventType::KeykeeperSsoRefused,
                &org.uuid,
                member.as_ref(),
                user.as_ref(),
                Some(refusal.detail()),
                None,
                ip,
                conn,
            )
            .await;
            row.delete(conn).await?;
            err!(refusal.message(&org.name))
        }
    };
    let Some(user) = User::find_by_uuid(&user_id, conn).await else {
        row.delete(conn).await?;
        err!("This account no longer exists.")
    };
    let member = Membership::find_by_user_and_org(&user.uuid, &org.uuid, conn).await.map(|m| m.uuid);
    // Another organization that requires its own single sign-on of this
    // person isn't satisfied by this one's.
    let required = required_orgs(&user.uuid, conn).await;
    if !required.is_empty() && !required.iter().any(|(id, _)| id == &org.uuid) {
        let (other, _) = &required[0];
        let other = Organization::find_by_uuid(other, conn).await.map(|o| o.name).unwrap_or_default();
        log_sso_event(
            EventType::KeykeeperSsoRefused,
            &org.uuid,
            member.as_ref(),
            Some(&user.uuid),
            Some(format!("{} must sign in with {other}'s single sign-on", user.email)),
            None,
            ip,
            conn,
        )
        .await;
        row.delete(conn).await?;
        err!(format!("{other} requires you to sign in with its own single sign-on. Use that instead."))
    }
    Ok((
        SsoLogin {
            row,
            identity,
            org_id: org.uuid,
            new_link,
            member,
        },
        user,
    ))
}

/// The sign-in passed two-step login: link the person if they're new here,
/// log it, and end the sign-in so its code never works again.
pub async fn finish_login(login: &SsoLogin, user: &User, device_type: i32, ip: &IpAddr, conn: &DbConn) -> EmptyResult {
    let SsoLogin {
        row,
        identity,
        org_id,
        new_link,
        member,
    } = login;
    row.delete(conn).await?;
    if *new_link {
        let Some(org) = Organization::find_by_uuid(org_id, conn).await else {
            err!("Organization not found")
        };
        make_link(&org, identity, user, member.as_ref(), Some(device_type), ip, conn).await?;
    } else if let Some(link) = SsoLink::find(org_id, &identity.tenant_id, &identity.object_id, conn).await {
        link.touch(conn).await?;
    }
    log_sso_event(
        EventType::KeykeeperSsoSignedIn,
        org_id,
        member.as_ref(),
        Some(&user.uuid),
        None,
        Some(device_type),
        ip,
        conn,
    )
    .await;
    Ok(())
}

/// For the server's request log: the identity routes' query strings carry
/// codes and states, so they're never logged.
pub fn redacts(path: &str) -> bool {
    path.starts_with("/identity/connect/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_are_s256_shaped() {
        assert!(looks_like_challenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        for bad in ["", "short", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c=", &"a".repeat(44)] {
            assert!(!looks_like_challenge(bad), "{bad}");
        }
    }

    #[test]
    fn the_secret_shim_round_trips_and_refuses_anything_else() {
        let org = OrganizationId::from("org".to_owned());
        let sealed = secret::seal(&org, "s3cr3t~value").unwrap();
        assert_eq!(secret::open(&org, &sealed).unwrap(), "s3cr3t~value");
        assert!(secret::open(&org, "s3cr3t~value").is_err());
    }
}

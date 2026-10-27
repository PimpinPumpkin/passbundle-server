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
// Linking an account that already has keys takes a session that proved the
// master password, and that session's confirmation ("Linking an account"
// below). With "Require single sign-on" on, a member who isn't linked yet
// gets a linking session from their password and two-step login, which can
// do that and nothing else (password_requirement).
//
// See DESIGN.md, "Sign in with Microsoft Entra ID", in the meta repo, for the
// threat model and what's out of scope (trusted-device unlock, creating
// accounts, other directories).

pub mod dns;
mod entra;
pub mod link;
pub mod secret;
pub mod token;

use std::net::IpAddr;

use chrono::Utc;
use rocket::{
    Request, Route,
    http::{Cookie, CookieJar, SameSite, Status},
    request::{FromRequest, Outcome},
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
    api::{ApiResult, EmptyResult, JsonResult, PasswordOrOtpData},
    auth::{ClientIp, Headers},
    crypto::ct_eq,
    db::{
        DbConn,
        models::{
            CONSUMER_TENANT, Device, Event, EventType, Membership, MembershipId, MembershipStatus, MembershipType,
            MspClient, MspMembership, MspStaff, OrgPolicy, OrgPolicyType, Organization, OrganizationId, SsoAuthRow,
            SsoConfig, SsoDomain, SsoLink, SsoLinkSession, SsoLinkTicket, User, UserId, email_domain, normalize_domain,
            normalize_guid, normalize_identifier, pkce_challenge, save_with_extras, sso_hash, sso_random, txt_value,
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
        link_pending,
        link_confirm,
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

/// Owners and admins of the organization, and an MSP's admins in its clients
/// (never other MSP staff), as for provisioning. Anyone else gets "not
/// found": upstream's web vault signs out on 403.
async fn require_admin(org_id: &OrganizationId, headers: &Headers, conn: &DbConn) -> EmptyResult {
    if !is_token_admin(org_id, &headers.user.uuid, conn).await {
        err_code!("Organization not found", Status::NotFound.code)
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

/// A refusal for the organization's event log: who, if anyone, a few words
/// of this server's own about why (never text a browser brought), and a
/// fixed reason code that security tools get, so refusals for different
/// reasons are never merged into one event (keykeeper_event_streaming).
async fn log_refusal(
    org_id: &OrganizationId,
    member: Option<&MembershipId>,
    user: Option<&UserId>,
    reason: &'static str,
    detail: String,
    ip: &IpAddr,
    conn: &DbConn,
) {
    let mut event = Event::new(EventType::KeykeeperSsoRefused as i32, None);
    event.org_uuid = Some(org_id.clone());
    event.org_user_uuid = member.cloned();
    event.user_uuid = user.cloned();
    event.act_user_uuid = user.cloned();
    event.ip_address = Some(ip.to_string());
    event.keykeeper_detail = Some(detail.chars().take(300).collect());
    save_with_extras(&event, json!({ "reason": reason }), conn).await;
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
    let found_links = SsoLink::find_by_org(org_id, conn).await;
    // Who the policy covers (or would) and isn't linked yet: with it on,
    // their next password sign-in asks them to link first.
    let mut unlinked = Vec::new();
    for m in Membership::find_by_org(org_id, conn).await {
        if m.status < MembershipStatus::Accepted as i32
            || found_links.iter().any(|l| l.user_uuid == m.user_uuid)
            || exempt_from_requirement(&m.user_uuid, &m, conn).await
        {
            continue;
        }
        if let Some(user) = User::find_by_uuid(&m.user_uuid, conn).await {
            unlinked.push(json!({ "memberId": m.uuid, "userId": user.uuid, "email": user.email, "name": user.name }));
        }
    }
    let mut links = Vec::new();
    for l in found_links {
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
        // False when the server's keys changed since it was saved, so sign-ins
        // fail until an admin enters it again (secret.rs).
        "secretReadable": config.as_ref().and_then(|c| c.client_secret.as_deref()).map(|s| secret::open(org_id, s).is_ok()),
        "updatedBy": config.as_ref().map(|c| c.updated_by.clone()),
        "updatedAt": config.as_ref().map(|c| format_date(&c.updated_at)),
        "callbackUrl": callback_uri(),
        "signInUrl": config.as_ref().map(|c| format!("{}/#/sso?identifier={}", CONFIG.domain(), c.identifier)),
        "requireSso": policy_on(org_id, OrgPolicyType::RequireSso, conn).await,
        "singleOrg": policy_on(org_id, OrgPolicyType::SingleOrg, conn).await,
        "domains": domains,
        "links": links,
        "unlinked": unlinked,
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
    let required = policy_on(&org_id, OrgPolicyType::RequireSso, &conn).await;
    if was_enabled && !data.enabled && required {
        err!("Turn off the Require single sign-on policy first, so members can still sign in.")
    }
    // A new tenant unlinks everyone (their links name the old tenant's
    // people), which the policy would turn into everyone linking again at
    // once: so not while it's on.
    if required && old.as_ref().is_some_and(|c| c.tenant_id != tenant_id) {
        err!(
            "Turn off the Require single sign-on policy before changing the tenant: a new tenant unlinks everyone, and each member links again at their next sign-in."
        )
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
        err_code!("Domain not found", Status::NotFound.code)
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
        err_code!("Domain not found", Status::NotFound.code)
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
        err_code!("Link not found", Status::NotFound.code)
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

// ---------------------------------------------------------------------------
// Linking an account (upstream's Link SSO), in four steps:
//
// 1. A session asks for a ticket (`link_ticket`): a signed-in session with
//    its master password or a one-time code, or a linking session, which a
//    password sign-in gets when single sign-on is required of someone who
//    isn't linked yet. The answer sets a cookie the ticket only works with.
// 2. The web vault starts a sign-in with the ticket as `user_identifier`
//    (`authorize`), from the same browser; Microsoft is asked to let the
//    person pick their account.
// 3. Microsoft's answer (`callback`) is held as a pending link, and the
//    browser goes back to the web vault with a one-time code.
// 4. The web vault shows which Microsoft account it is, and the session that
//    asked confirms it (`link_confirm`). Only then is the link made.

/// Who's asking to link: a signed-in session (a login token, never an API
/// key's), or a linking session. A linking session's token isn't a login
/// token, so no other request takes it.
pub enum LinkCaller {
    Session(Box<Headers>),
    Linking(SsoLinkSession, IpAddr),
}

impl LinkCaller {
    fn user_id(&self) -> &UserId {
        match self {
            Self::Session(h) => &h.user.uuid,
            Self::Linking(s, _) => &s.user_uuid,
        }
    }

    /// Which session this is, as tickets and pending links remember it.
    fn session_ref(&self) -> String {
        match self {
            Self::Session(h) => format!("device:{}", h.device.uuid),
            Self::Linking(s, _) => format!("link:{}", s.session_hash),
        }
    }

    fn ip(&self) -> &IpAddr {
        match self {
            Self::Session(h) => &h.ip.ip,
            Self::Linking(_, ip) => ip,
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for LinkCaller {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(token) = request.headers().get_one("Authorization").and_then(|a| a.strip_prefix("Bearer ")) else {
            return Outcome::Error((Status::Unauthorized, "No access token provided"));
        };
        if let Ok(claims) = crate::auth::decode_login(token) {
            // An API key's token (the CLI's client_credentials) proves no
            // master password, so it can't link anything.
            if !claims.scope.iter().any(|s| s == "offline_access") {
                return Outcome::Error((Status::Unauthorized, "An API key can't link single sign-on"));
            }
            return request.guard::<Headers>().await.map(|h| Self::Session(Box::new(h)));
        }
        let Outcome::Success(conn) = request.guard::<DbConn>().await else {
            return Outcome::Error((Status::ServiceUnavailable, "Error getting DB"));
        };
        let Outcome::Success(ip) = request.guard::<ClientIp>().await else {
            return Outcome::Error((Status::BadRequest, "Error getting Client IP"));
        };
        match SsoLinkSession::find(token, &conn).await {
            Some(session) => Outcome::Success(Self::Linking(session, ip.ip)),
            None => Outcome::Error((Status::Unauthorized, "This linking session expired. Sign in again.")),
        }
    }
}

const LINK_COOKIE: &str = "PB_SSO_LINK";

/// Step one: a ticket that names the account and the session, and a cookie it
/// works only with. A signed-in session proves its master password or a
/// one-time code first; a linking session already did, with its password and
/// two-step login, and its ticket works only for its organization. Five
/// minutes, once.
#[post("/accounts/sso/user-identifier", data = "<data>")]
async fn link_ticket(
    data: Json<PasswordOrOtpData>,
    caller: LinkCaller,
    cookies: &CookieJar<'_>,
    conn: DbConn,
) -> JsonResult {
    crate::ratelimit::check_limit_prelogin(caller.ip())?;
    let org = match &caller {
        LinkCaller::Session(h) => {
            data.validate(&h.user, true, &conn).await?;
            None
        }
        LinkCaller::Linking(s, _) => Some(s.org_uuid.clone()),
    };
    let (ticket, binding, row) = SsoLinkTicket::generate(caller.user_id().clone(), org, caller.session_ref());
    row.insert(&conn).await?;
    cookies.add(
        Cookie::build((LINK_COOKIE, binding))
            .path(binding_cookie_path())
            .max_age(time::Duration::minutes(crate::db::models::SSO_LINK_TICKET_MINUTES))
            // Only from this site: the web vault starts the sign-in itself.
            .same_site(SameSite::Strict)
            .http_only(true)
            .secure(CONFIG.domain().starts_with("https://"))
            .build(),
    );
    Ok(Json(json!(ticket)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingLinkData {
    code: String,
}

/// A pending link, if it's this caller's: the same account and session.
fn pending_for<'a>(row: &'a SsoAuthRow, caller: &LinkCaller) -> Option<&'a SsoAuthRow> {
    let same_user = row.link_user_uuid.as_ref() == Some(caller.user_id());
    let same_session = row.link_session.as_deref().is_some_and(|s| ct_eq(s, caller.session_ref()));
    (same_user && same_session).then_some(row)
}

const LINK_EXPIRED: &str = "This request to link single sign-on expired, or was started somewhere else. Start again.";

/// Step four, first half: what the web vault shows before the person confirms:
/// which Microsoft account would be linked, to which PassBundle account, in
/// which organization, or why it didn't work.
#[post("/accounts/sso/link/pending", data = "<data>")]
async fn link_pending(data: Json<PendingLinkData>, caller: LinkCaller, conn: DbConn) -> JsonResult {
    crate::ratelimit::check_limit_prelogin(caller.ip())?;
    let row = SsoAuthRow::find_by_code(&data.code, &conn).await;
    let Some(row) = row.as_ref().and_then(|r| pending_for(r, &caller)) else {
        err!(LINK_EXPIRED)
    };
    let org = Organization::find_by_uuid(&row.org_uuid, &conn).await;
    let identifier = SsoConfig::find(&row.org_uuid, &conn).await.map(|c| c.identifier);
    let account = User::find_by_uuid(caller.user_id(), &conn).await.map(|u| u.email);
    let identity = row.identity.as_deref().and_then(|i| serde_json::from_str::<Identity>(i).ok());
    Ok(Json(json!({
        "organizationName": org.map(|o| o.name),
        "identifier": identifier,
        "accountEmail": account,
        "microsoftName": identity.as_ref().and_then(|i| i.name.clone()),
        "microsoftEmail": identity.as_ref().and_then(|i| i.email.clone()),
        "error": row.error,
    })))
}

/// Step four: the session that asked confirms the link, once. A linking
/// session ends here; the person then signs in with single sign-on.
#[post("/accounts/sso/link/confirm", data = "<data>")]
async fn link_confirm(data: Json<PendingLinkData>, caller: LinkCaller, conn: DbConn) -> JsonResult {
    crate::ratelimit::check_limit_prelogin(caller.ip())?;
    // Only the session that asked can take it, so another one can't use up
    // its code either.
    let Some(found) = SsoAuthRow::find_by_code(&data.code, &conn).await else {
        err!(LINK_EXPIRED)
    };
    if pending_for(&found, &caller).is_none() {
        err!(LINK_EXPIRED)
    }
    let Some(row) = SsoAuthRow::take_by_code(&data.code, &conn).await else {
        err!(LINK_EXPIRED)
    };
    if let Some(message) = row.error.clone() {
        err!(message)
    }
    let Some(identity) = row.identity.as_deref().and_then(|i| serde_json::from_str::<Identity>(i).ok()) else {
        err!(LINK_EXPIRED)
    };
    let Some(config) = SsoConfig::find(&row.org_uuid, &conn).await.filter(SsoConfig::ready) else {
        err!("Single sign-on is turned off for this organization.")
    };
    if config.tenant_id != identity.tenant_id {
        err!("This organization's single sign-on changed while you were linking. Start again.")
    }
    link_session(&row, &identity, caller.ip(), &conn).await?;
    if let LinkCaller::Linking(session, _) = &caller {
        session.delete(&conn).await?;
    }
    Ok(Json(json!({ "identifier": config.identifier })))
}

/// Upstream's Unlink SSO: someone unlinks their own account from an
/// organization's single sign-on. Its sessions end.
#[delete("/accounts/sso/<org_id>")]
async fn unlink_self(org_id: OrganizationId, headers: Headers, conn: DbConn) -> EmptyResult {
    let Some(link) = SsoLink::find_by_user(&org_id, &headers.user.uuid, &conn).await else {
        err_code!("Link not found", Status::NotFound.code)
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

/// What a password sign-in comes to for someone an organization requires to
/// sign in with its single sign-on.
pub enum PasswordRequirement {
    /// Linked to it: they sign in with single sign-on (its identifier).
    UseSso(String),
    /// Not linked yet: once their password and two-step login check out,
    /// a linking session for that organization, and nothing else
    /// (`start_linking`). Without this, the policy would lock them out: a
    /// password sends them to single sign-on, which needs a link, which
    /// needs a session.
    LinkFirst(OrganizationId, String),
}

/// Whether, and how, an organization's requirement applies to a password
/// sign-in that checked out (`required_orgs`).
pub async fn password_requirement(user_id: &UserId, conn: &DbConn) -> Option<PasswordRequirement> {
    let required = required_orgs(user_id, conn).await;
    for (org, identifier) in &required {
        if SsoLink::find_by_user(org, user_id, conn).await.is_none() {
            return Some(PasswordRequirement::LinkFirst(org.clone(), identifier.clone()));
        }
    }
    required.into_iter().next().map(|(_, identifier)| PasswordRequirement::UseSso(identifier))
}

/// A linking session for someone whose password and two-step login just
/// checked out: its token, which only the link endpoints take.
pub async fn start_linking(user_id: &UserId, org_id: &OrganizationId, conn: &DbConn) -> ApiResult<String> {
    let (token, row) = SsoLinkSession::generate(user_id.clone(), org_id.clone());
    row.insert(conn).await?;
    Ok(token)
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
    /// Upstream's Link SSO: a session's link ticket
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
    // Linking: the ticket names the account and the session, once, and only
    // from the browser it was issued to (its cookie).
    let link = match a.user_identifier.as_deref().filter(|t| !t.is_empty()) {
        Some(ticket) => {
            let binding = cookies.get(LINK_COOKIE).map(|c| c.value().to_owned());
            cookies.remove(Cookie::build(LINK_COOKIE).path(binding_cookie_path()).build());
            match SsoLinkTicket::take(ticket, binding.as_deref(), conn).await {
                Some(used)
                    if a.client_id == "web" && used.org_uuid.as_ref().is_none_or(|org| org == &config.org_uuid) =>
                {
                    Some(used)
                }
                _ => err!(
                    "This request to link single sign-on expired, or was started in another browser. Start again from this one."
                ),
            }
        }
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
        link_user_uuid: link.as_ref().map(|l| l.user_uuid.clone()),
        link_session: link.as_ref().map(|l| l.session_ref.clone()),
        identity: None,
        error: None,
        created_at: Utc::now().naive_utc(),
        returned_at: None,
    }
    .insert(conn)
    .await?;

    let Ok(mut url) = url::Url::parse_with_params(
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
    if link.is_some() {
        // Linking: the person picks the Microsoft account, rather than the
        // browser using whichever one is signed in.
        url.query_pairs_mut().append_pair("prompt", "select_account");
    }

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
        log_refusal(
            &row.org_uuid,
            None,
            None,
            "another_browser",
            "Microsoft's answer reached a browser that didn't start the sign-in".to_owned(),
            ip,
            conn,
        )
        .await;
        err!("This sign-in was started in another browser. Sign in again from this one.")
    }

    // Who it is, or what the person is told, a reason code, and a few words
    // of this server's own for the event log. Anything the browser brought
    // (Microsoft's error and its description) can be made up by whoever
    // started the sign-in, so the log keeps only an error code that fits
    // OAuth's grammar, and never the description.
    let outcome: Result<Identity, (String, &'static str, String)> = match (error, code) {
        (Some((error, description)), _) => {
            let error = oauth_error_code(error);
            let description = description.and_then(oauth_error_description).unwrap_or_default();
            Err((
                format!("Microsoft didn't sign you in ({error}). {description}").trim().to_owned(),
                "microsoft_refused",
                format!("Microsoft refused, as the browser reported it: {error}"),
            ))
        }
        (None, Some(code)) => exchange(&row, code, conn).await.map_err(|detail| {
            (
                format!(
                    "Microsoft's sign-in for this organization didn't check out ({detail}). Ask your administrator to check its single sign-on settings."
                ),
                "token_check_failed",
                detail,
            )
        }),
        (None, None) => Err((
            "Microsoft's answer had no code.".to_owned(),
            "no_code",
            "Microsoft's answer had no code".to_owned(),
        )),
    };
    let our_code = sso_random();
    let (identity, error) = match outcome {
        Ok(identity) => (Some(serde_json::to_string(&identity)?), None),
        Err((message, reason, detail)) => {
            log_refusal(&row.org_uuid, None, row.link_user_uuid.as_ref(), reason, detail, ip, conn).await;
            (None, Some(message))
        }
    };
    row.finish(&our_code, identity, error, conn).await?;
    // Linking: the link waits for the session that asked to confirm it, on
    // the web vault's linking page.
    if row.link_user_uuid.is_some() {
        return Ok(Redirect::temporary(format!("{}/#/sso-link?code={our_code}", CONFIG.domain())));
    }
    let Ok(mut url) = url::Url::parse(&row.redirect_uri) else {
        err!("Unsupported redirect URI")
    };
    url.query_pairs_mut().append_pair("code", &our_code).append_pair("state", &row.client_state);
    Ok(Redirect::temporary(String::from(url)))
}

/// Microsoft's `error`, if it fits OAuth's grammar for one (RFC 6749, 5.2:
/// printable ASCII without quotes or backslashes) and is short; otherwise a
/// fixed word, since the browser brought it.
fn oauth_error_code(error: &str) -> &str {
    let fits = !error.is_empty()
        && error.len() <= 64
        && error.bytes().all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E));
    if fits {
        error
    } else {
        "unrecognized_error"
    }
}

/// Microsoft's `error_description`, for the person only, if it fits the same
/// grammar and isn't long.
fn oauth_error_description(description: &str) -> Option<String> {
    let fits =
        description.len() <= 500 && description.bytes().all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E));
    fits.then(|| description.to_owned())
}

/// Links the account whose session asked to the Microsoft account that
/// signed in (upstream's Link SSO), once that session confirmed it, under the
/// rules in link.rs, then tells the account by email and logs it.
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
            log_refusal(&org.uuid, member.as_ref(), Some(user_id), refusal.code(), refusal.detail(), ip, conn).await;
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
    // A link's code is only ever confirmed by the session that asked
    // (link_confirm), never redeemed as a sign-in.
    if row.link_user_uuid.is_some() {
        err!("This sign-in expired or was already used. Sign in again.")
    }
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
            log_refusal(&org.uuid, member.as_ref(), user.as_ref(), refusal.code(), refusal.detail(), ip, conn).await;
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
        // This organization's log doesn't name the other one; only the
        // person is told which.
        log_refusal(
            &org.uuid,
            member.as_ref(),
            Some(&user.uuid),
            "another_org_requires_its_own",
            format!("{} must sign in with the single sign-on of another organization that requires it", user.email),
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
    fn microsofts_error_is_kept_only_when_it_fits_oauths_grammar() {
        assert_eq!(oauth_error_code("access_denied"), "access_denied");
        assert_eq!(oauth_error_code("consent_required"), "consent_required");
        for made_up in ["", "say \"hello\"", "back\\slash", "line\nbreak", "caf\u{e9}", &"a".repeat(65)] {
            assert_eq!(oauth_error_code(made_up), "unrecognized_error", "{made_up}");
        }
        assert_eq!(
            oauth_error_description("AADSTS50105: The signed in user is not assigned to a role.").as_deref(),
            Some("AADSTS50105: The signed in user is not assigned to a role.")
        );
        for made_up in ["tab\there", "<script>\"x\"</script>", &"a".repeat(501)] {
            assert_eq!(oauth_error_description(made_up), None, "{made_up}");
        }
    }
}

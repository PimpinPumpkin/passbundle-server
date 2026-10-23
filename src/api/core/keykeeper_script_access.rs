// Keykeeper: script access (docs/script-access.md in the meta repo). Admin
// endpoints for an organization's owners and admins, and for its MSP's admins
// (never other MSP staff); refreshing a copy for anyone who can edit the item;
// and script endpoints authenticated by nothing but a token's auth secret.
// The server stores copies it can't read: the token key that encrypts them is
// derived from a seed only the admin's browser and the script ever have.

use std::{net::IpAddr, num::NonZeroU32, sync::LazyLock};

use chrono::{DateTime, NaiveDateTime, TimeDelta, Utc};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use ring::digest;
use rocket::{
    Request, Route,
    http::{ContentType, Status},
    request::{FromRequest, Outcome},
    serde::json::Json,
};
use serde_json::{Value, json};

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult},
    auth::{ClientIp, Headers},
    crypto::ct_eq,
    db::{
        DbConn,
        models::{
            Cipher, CipherId, Membership, MembershipStatus, MembershipType, MspClient, MspMembership, MspRole,
            Organization, OrganizationId, ScriptGrant, ScriptRead, ScriptToken, User, parse_networks,
            valid_encrypted_secret,
        },
    },
    util::format_date,
};

use super::keykeeper_msp::{Audit, staff_role};

pub fn routes() -> Vec<Route> {
    routes![
        list_tokens,
        create_token,
        revoke_token,
        set_grant,
        remove_grant,
        token_reads,
        stale_grants,
        script_items,
        script_item,
        script_module
    ]
}

/// The longest a token may last.
const MAX_LIFETIME_DAYS: i64 = 366;
/// Grants per token.
const MAX_GRANTS: usize = 100;
/// A copy's size, encrypted.
const MAX_COPY: usize = 64 * 1024;
/// A sealed spec's size, encrypted.
const MAX_SPEC: usize = 8 * 1024;
const MAX_NAME: usize = 100;

/// Reads per token per minute.
static SCRIPT_READS: LazyLock<RateLimiter<String, DashMapStateStore<String>, DefaultClock>> =
    LazyLock::new(|| RateLimiter::keyed(Quota::per_minute(NonZeroU32::new(60).expect("Non-zero script read limit"))));

/// An encrypted value as upstream writes it (`2.<iv>|<data>|<mac>`), at most `max` long.
fn valid_enc_string(value: &str, max: usize) -> bool {
    let Some(parts) = value.strip_prefix("2.") else {
        return false;
    };
    let parts: Vec<&str> = parts.split('|').collect();
    value.len() <= max && parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && BASE64.decode(p.as_bytes()).is_ok())
}

/// Whether a copy's revision is the item's revision. Apps hold revisions as
/// JavaScript dates, to the millisecond; the server writes microseconds.
fn same_revision(revision: &str, updated_at: &NaiveDateTime) -> bool {
    DateTime::parse_from_rfc3339(revision)
        .is_ok_and(|r| r.timestamp_millis() == updated_at.and_utc().timestamp_millis())
}

/// The base64 SHA-256 of an auth secret, as a token stores it.
fn auth_hash(secret: &[u8]) -> String {
    BASE64.encode(digest::digest(&digest::SHA256, secret).as_ref())
}

/// The caller may make and manage tokens for the organization: a confirmed
/// owner or admin, and, when that place comes from an MSP, an admin of the MSP.
/// Errors never use 403, which upstream's web vault answers by signing out.
async fn require_token_admin(org_id: &OrganizationId, headers: &Headers, conn: &DbConn) -> EmptyResult {
    if !is_token_admin(org_id, &headers.user.uuid, conn).await {
        err_code!("Organization not found", Status::NotFound.code)
    }
    Ok(())
}

pub(super) async fn is_token_admin(
    org_id: &OrganizationId,
    user_id: &crate::db::models::UserId,
    conn: &DbConn,
) -> bool {
    let Some(member) = Membership::find_by_user_and_org(user_id, org_id, conn).await.filter(|m| {
        m.status == MembershipStatus::Confirmed as i32
            && (m.atype == MembershipType::Owner as i32 || m.atype == MembershipType::Admin as i32)
    }) else {
        return false;
    };
    if MspMembership::find_by_membership(&member.uuid, conn).await.is_none() {
        return true;
    }
    match MspClient::find_by_org(org_id, conn).await {
        Some(client) => matches!(staff_role(&client.msp_uuid, user_id, conn).await, Ok(MspRole::Admin)),
        None => false,
    }
}

/// Records an event in the MSP's activity log when the organization is an MSP's client.
async fn record_for_msp(
    org_id: &OrganizationId,
    event: &'static str,
    actor: Option<&User>,
    ip: Option<String>,
    detail: String,
    conn: &DbConn,
) -> EmptyResult {
    let Some(client) = MspClient::find_by_org(org_id, conn).await else {
        return Ok(());
    };
    let name = Organization::find_by_uuid(org_id, conn).await.map(|o| o.name).unwrap_or_default();
    Audit {
        event,
        actor,
        ip,
        org: Some((org_id, &name)),
        target_email: None,
        detail: Some(detail),
    }
    .record(&client.msp_uuid, conn)
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantData {
    item_id: CipherId,
    copy: String,
    revision: String,
    sealed_spec: String,
}

/// A grant's item: in the organization, not in the trash, visible to the
/// caller, and at the revision the copy was made from.
async fn granted_item(
    org_id: &OrganizationId,
    grant: &GrantData,
    headers: &Headers,
    conn: &DbConn,
) -> Result<Cipher, crate::error::Error> {
    let cipher = match Cipher::find_by_uuid(&grant.item_id, conn).await {
        Some(c) if c.organization_uuid.as_ref() == Some(org_id) && c.deleted_at.is_none() => c,
        _ => err!("Item not found"),
    };
    if !cipher.is_accessible_to_user(&headers.user.uuid, conn).await {
        err!("Item not found")
    }
    if !valid_enc_string(&grant.copy, MAX_COPY) || !valid_enc_string(&grant.sealed_spec, MAX_SPEC) {
        err!("A grant's copy or spec isn't encrypted the way PassBundle encrypts")
    }
    if !same_revision(&grant.revision, &cipher.updated_at) {
        err!("An item changed since you opened it. Reload and try again.")
    }
    Ok(cipher)
}

async fn token_view(token: &ScriptToken, conn: &DbConn) -> Value {
    let mut grants = Vec::new();
    for grant in ScriptGrant::find_for_token(&token.uuid, conn).await {
        let current = Cipher::find_by_uuid(&grant.cipher_uuid, conn).await;
        grants.push(json!({
            "itemId": grant.cipher_uuid,
            "revision": grant.revision,
            "sealedSpec": grant.sealed_spec,
            "itemDeleted": current.as_ref().is_none_or(|c| c.deleted_at.is_some()),
            "upToDate": current.as_ref().is_some_and(|c| same_revision(&grant.revision, &c.updated_at)),
        }));
    }
    let networks: Vec<String> = serde_json::from_str(&token.networks).unwrap_or_default();
    let created_by = User::find_by_uuid(&token.created_by, conn).await.map(|u| u.email);
    json!({
        "id": token.uuid,
        "organizationId": token.org_uuid,
        "name": token.name,
        "createdBy": created_by,
        "createdAt": format_date(&token.created_at),
        "expiresAt": format_date(&token.expires_at),
        "revokedAt": token.revoked_at.as_ref().map(format_date),
        "networks": networks,
        "sealedKey": token.sealed_key,
        "lastUsedAt": token.last_used_at.as_ref().map(format_date),
        "lastUsedIp": token.last_used_ip,
        "grants": grants,
    })
}

#[get("/keykeeper/organizations/<org_id>/script-tokens")]
async fn list_tokens(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    require_token_admin(&org_id, &headers, &conn).await?;
    let mut data = Vec::new();
    for token in ScriptToken::find_by_org(&org_id, &conn).await {
        data.push(token_view(&token, &conn).await);
    }
    Ok(Json(json!({ "data": data })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewTokenData {
    id: String,
    name: String,
    expires_at: String,
    #[serde(default)]
    networks: Vec<String>,
    auth_hash: String,
    sealed_key: String,
    grants: Vec<GrantData>,
}

/// When a token expires: in the future, and at most a year away.
fn checked_expiry(text: &str, now: NaiveDateTime) -> Result<NaiveDateTime, String> {
    let expires = DateTime::parse_from_rfc3339(text).map_err(|_| "That isn't a date and time".to_owned())?.naive_utc();
    if expires <= now + TimeDelta::hours(1) {
        return Err("A token must last at least an hour".into());
    }
    if expires > now + TimeDelta::days(MAX_LIFETIME_DAYS) {
        return Err("A token lasts at most a year".into());
    }
    Ok(expires)
}

#[post("/keykeeper/organizations/<org_id>/script-tokens", data = "<data>")]
async fn create_token(org_id: OrganizationId, data: Json<NewTokenData>, headers: Headers, conn: DbConn) -> JsonResult {
    require_token_admin(&org_id, &headers, &conn).await?;
    let data = data.into_inner();
    let now = Utc::now().naive_utc();

    let Ok(id) = uuid::Uuid::parse_str(&data.id).map(|id| id.hyphenated().to_string()) else {
        err!("A token's id is a UUID")
    };
    if ScriptToken::find(&id, &conn).await.is_some() {
        err!("A token with that id exists")
    }
    let name = data.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME || name.chars().any(char::is_control) {
        err!(format!("Name the token in {MAX_NAME} characters or fewer"))
    }
    let expires_at = match checked_expiry(&data.expires_at, now) {
        Ok(e) => e,
        Err(e) => err!(e),
    };
    let networks = match parse_networks(&data.networks) {
        Ok(n) => n.iter().map(ToString::to_string).collect::<Vec<_>>(),
        Err(e) => err!(e),
    };
    if !BASE64.decode(data.auth_hash.as_bytes()).is_ok_and(|h| h.len() == 32) {
        err!("A token's auth hash is a base64 SHA-256")
    }
    if !valid_encrypted_secret(&data.sealed_key) {
        err!("A token's key must be sealed with the organization's key")
    }
    if data.grants.is_empty() || data.grants.len() > MAX_GRANTS {
        err!(format!("Grant between 1 and {MAX_GRANTS} items"))
    }
    let mut grants = Vec::new();
    for grant in &data.grants {
        granted_item(&org_id, grant, &headers, &conn).await?;
        if grants.iter().any(|g: &ScriptGrant| g.cipher_uuid == grant.item_id) {
            err!("An item is granted twice")
        }
        grants.push(ScriptGrant {
            token_uuid: id.clone(),
            cipher_uuid: grant.item_id.clone(),
            copy: grant.copy.clone(),
            revision: grant.revision.clone(),
            sealed_spec: grant.sealed_spec.clone(),
        });
    }

    let token = ScriptToken {
        uuid: id,
        org_uuid: org_id.clone(),
        name: name.to_owned(),
        created_by: headers.user.uuid.clone(),
        created_at: now,
        expires_at,
        revoked_at: None,
        auth_hash: data.auth_hash,
        networks: serde_json::to_string(&networks).unwrap_or_else(|_| "[]".into()),
        sealed_key: data.sealed_key,
        last_used_at: None,
        last_used_ip: None,
    };
    token.insert(&conn).await?;
    for grant in &grants {
        grant.save(&conn).await?;
    }
    let detail = format!(
        "{}: {} item{}",
        token.name,
        grants.len(),
        if grants.len() == 1 {
            ""
        } else {
            "s"
        }
    );
    record_for_msp(
        &org_id,
        "script_token_created",
        Some(&headers.user),
        Some(headers.ip.ip.to_string()),
        detail,
        &conn,
    )
    .await?;
    Ok(Json(token_view(&token, &conn).await))
}

async fn org_token(org_id: &OrganizationId, token_id: &str, conn: &DbConn) -> Result<ScriptToken, crate::error::Error> {
    match ScriptToken::find(token_id, conn).await {
        Some(t) if &t.org_uuid == org_id => Ok(t),
        _ => err_code!("Token not found", Status::NotFound.code),
    }
}

#[delete("/keykeeper/organizations/<org_id>/script-tokens/<token_id>")]
async fn revoke_token(org_id: OrganizationId, token_id: &str, headers: Headers, conn: DbConn) -> JsonResult {
    require_token_admin(&org_id, &headers, &conn).await?;
    let mut token = org_token(&org_id, token_id, &conn).await?;
    if token.revoked_at.is_none() {
        token.revoke(&conn).await?;
        record_for_msp(
            &org_id,
            "script_token_revoked",
            Some(&headers.user),
            Some(headers.ip.ip.to_string()),
            token.name.clone(),
            &conn,
        )
        .await?;
    }
    Ok(Json(token_view(&token, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CopyData {
    copy: String,
    revision: String,
    sealed_spec: String,
}

/// Adds a grant (token admins), or refreshes an existing one's copy (anyone
/// who can edit the item, for the item's current revision).
#[put("/keykeeper/organizations/<org_id>/script-tokens/<token_id>/grants/<item_id>", data = "<data>")]
async fn set_grant(
    org_id: OrganizationId,
    token_id: &str,
    item_id: CipherId,
    data: Json<CopyData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let data = data.into_inner();
    let token = org_token(&org_id, token_id, &conn).await?;
    if !token.is_live(Utc::now().naive_utc()) {
        err!("That token was revoked or expired")
    }
    let existing = ScriptGrant::find(&token.uuid, &item_id, &conn).await;
    let admin = is_token_admin(&org_id, &headers.user.uuid, &conn).await;
    let grant = GrantData {
        item_id: item_id.clone(),
        copy: data.copy,
        revision: data.revision,
        sealed_spec: data.sealed_spec,
    };
    if admin {
        if existing.is_none() && ScriptGrant::find_for_token(&token.uuid, &conn).await.len() >= MAX_GRANTS {
            err!(format!("A token has at most {MAX_GRANTS} items"))
        }
    } else {
        // Someone else may only refresh an existing grant, on an item of this
        // organization they can edit; otherwise it's as if there were no token.
        let editable = match Cipher::find_by_uuid(&item_id, &conn).await {
            Some(c) if existing.is_some() && c.organization_uuid.as_ref() == Some(&org_id) => {
                c.is_write_accessible_to_user(&headers.user.uuid, &conn).await
            }
            _ => false,
        };
        if !editable {
            err_code!("Token not found", Status::NotFound.code)
        }
    }
    granted_item(&org_id, &grant, &headers, &conn).await?;
    ScriptGrant {
        token_uuid: token.uuid.clone(),
        cipher_uuid: item_id,
        copy: grant.copy,
        revision: grant.revision,
        sealed_spec: grant.sealed_spec,
    }
    .save(&conn)
    .await?;
    Ok(Json(token_view(&token, &conn).await))
}

#[delete("/keykeeper/organizations/<org_id>/script-tokens/<token_id>/grants/<item_id>")]
async fn remove_grant(
    org_id: OrganizationId,
    token_id: &str,
    item_id: CipherId,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    require_token_admin(&org_id, &headers, &conn).await?;
    let token = org_token(&org_id, token_id, &conn).await?;
    ScriptGrant::delete(&token.uuid, &item_id, &conn).await?;
    Ok(Json(token_view(&token, &conn).await))
}

#[get("/keykeeper/organizations/<org_id>/script-tokens/<token_id>/reads")]
async fn token_reads(org_id: OrganizationId, token_id: &str, headers: Headers, conn: DbConn) -> JsonResult {
    require_token_admin(&org_id, &headers, &conn).await?;
    let token = org_token(&org_id, token_id, &conn).await?;
    let reads: Vec<Value> = ScriptRead::recent(&token.uuid, 200, &conn)
        .await
        .iter()
        .map(|r| {
            json!({
                "itemId": r.cipher_uuid,
                "at": format_date(&r.read_at),
                "ip": r.ip,
                "allowed": r.allowed,
                "reason": r.reason,
            })
        })
        .collect();
    Ok(Json(json!({ "data": reads })))
}

/// Grants whose copy is behind its item, on items the caller can edit, in
/// tokens that still work, with what an app needs to refresh them: the
/// sealed token key, the sealed spec, and the item's current revision.
#[get("/keykeeper/script-grants/stale")]
async fn stale_grants(headers: Headers, conn: DbConn) -> JsonResult {
    let now = Utc::now().naive_utc();
    let mut data = Vec::new();
    for member in Membership::find_confirmed_by_user(&headers.user.uuid, &conn).await {
        for token in ScriptToken::find_by_org(&member.org_uuid, &conn).await {
            if !token.is_live(now) {
                continue;
            }
            for grant in ScriptGrant::find_for_token(&token.uuid, &conn).await {
                let Some(cipher) = Cipher::find_by_uuid(&grant.cipher_uuid, &conn).await else {
                    continue;
                };
                let revision = format_date(&cipher.updated_at);
                if cipher.deleted_at.is_some()
                    || same_revision(&grant.revision, &cipher.updated_at)
                    || !cipher.is_write_accessible_to_user(&headers.user.uuid, &conn).await
                {
                    continue;
                }
                data.push(json!({
                    "organizationId": token.org_uuid,
                    "tokenId": token.uuid,
                    "itemId": grant.cipher_uuid,
                    "revision": revision,
                    "sealedKey": token.sealed_key,
                    "sealedSpec": grant.sealed_spec,
                }));
            }
        }
    }
    Ok(Json(json!({ "data": data })))
}

/// A script, authenticated by `Authorization: PassBundleScript <token id>.<auth
/// secret>` and nothing else: the token exists, the secret matches, it's
/// neither revoked nor expired, the address is in its networks, and it's
/// within its reads per minute. Refusals for a known token are logged.
pub struct ScriptCaller {
    token: ScriptToken,
    ip: IpAddr,
}

/// The token id and auth secret in a script's Authorization header.
fn parse_authorization(value: &str) -> Option<(String, Vec<u8>)> {
    let (id, secret) = value.strip_prefix("PassBundleScript ")?.trim().split_once('.')?;
    let id = uuid::Uuid::parse_str(id).ok()?.hyphenated().to_string();
    let secret = BASE64URL_NOPAD.decode(secret.as_bytes()).ok().filter(|s| s.len() == 32)?;
    Some((id, secret))
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ScriptCaller {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let ip = match ClientIp::from_request(request).await {
            Outcome::Success(client) => client.ip,
            _ => return Outcome::Error((Status::BadRequest, "No client address")),
        };
        let Outcome::Success(conn) = DbConn::from_request(request).await else {
            return Outcome::Error((Status::ServiceUnavailable, "No database"));
        };
        let refused = Outcome::Error((Status::Unauthorized, "That token doesn't work"));
        let Some((id, secret)) = request.headers().get_one("Authorization").and_then(parse_authorization) else {
            return refused;
        };
        let Some(token) = ScriptToken::find(&id, &conn).await else {
            return refused;
        };
        let reason = if !ct_eq(auth_hash(&secret), &token.auth_hash) {
            Some("wrong secret")
        } else if token.revoked_at.is_some() {
            Some("revoked")
        } else if !token.is_live(Utc::now().naive_utc()) {
            Some("expired")
        } else if !token.allows(&ip) {
            Some("outside its networks")
        } else if SCRIPT_READS.check_key(&token.uuid).is_err() {
            Some("too many reads")
        } else {
            None
        };
        if let Some(reason) = reason {
            // The log is best effort: a refusal stands either way.
            if let Err(e) = ScriptRead::record(&token.uuid, None, &ip, false, reason, &conn).await {
                warn!("Couldn't log a refused script read: {e:?}");
            }
            return if reason == "too many reads" {
                Outcome::Error((Status::TooManyRequests, "Too many reads; try again in a minute"))
            } else {
                refused
            };
        }
        Outcome::Success(ScriptCaller {
            token,
            ip,
        })
    }
}

/// Marks the token used, and tells the MSP the first time it's used from an address.
async fn mark_used(caller: &ScriptCaller, conn: &DbConn) -> EmptyResult {
    let ip = caller.ip.to_string();
    if !ScriptRead::seen_from(&caller.token.uuid, &ip, conn).await {
        record_for_msp(
            &caller.token.org_uuid,
            "script_token_new_address",
            None,
            Some(ip.clone()),
            caller.token.name.clone(),
            conn,
        )
        .await?;
    }
    let mut token = caller.token.clone();
    token.last_used_at = Some(Utc::now().naive_utc());
    token.last_used_ip = Some(ip);
    token.save(conn).await
}

fn copy_json(grant: &ScriptGrant, cipher: &Cipher) -> Value {
    json!({
        "itemId": grant.cipher_uuid,
        "copy": grant.copy,
        "upToDate": same_revision(&grant.revision, &cipher.updated_at),
    })
}

/// Every copy the token has, for a script that asks by name.
#[get("/keykeeper/script/items")]
async fn script_items(caller: ScriptCaller, conn: DbConn) -> JsonResult {
    mark_used(&caller, &conn).await?;
    let mut data = Vec::new();
    for grant in ScriptGrant::find_for_token(&caller.token.uuid, &conn).await {
        let Some(cipher) = Cipher::find_by_uuid(&grant.cipher_uuid, &conn).await.filter(|c| c.deleted_at.is_none())
        else {
            continue;
        };
        ScriptRead::record(&caller.token.uuid, Some(&grant.cipher_uuid), &caller.ip, true, "read", &conn).await?;
        data.push(copy_json(&grant, &cipher));
    }
    Ok(Json(json!({ "data": data })))
}

#[get("/keykeeper/script/items/<item_id>")]
async fn script_item(item_id: CipherId, caller: ScriptCaller, conn: DbConn) -> JsonResult {
    let grant = ScriptGrant::find(&caller.token.uuid, &item_id, &conn).await;
    let cipher = Cipher::find_by_uuid(&item_id, &conn).await.filter(|c| c.deleted_at.is_none());
    let (Some(grant), Some(cipher)) = (grant, cipher) else {
        ScriptRead::record(&caller.token.uuid, Some(&item_id), &caller.ip, false, "not granted", &conn).await?;
        err_code!("Item not found", Status::NotFound.code)
    };
    mark_used(&caller, &conn).await?;
    ScriptRead::record(&caller.token.uuid, Some(&item_id), &caller.ip, true, "read", &conn).await?;
    Ok(Json(copy_json(&grant, &cipher)))
}

/// The PowerShell module scripts use, with this server's address filled in.
#[get("/keykeeper/script/PassBundle.psm1")]
fn script_module() -> (ContentType, String) {
    let module = include_str!("../../static/scripts/PassBundle.psm1");
    (ContentType::Plain, module.replace("{{SERVER}}", &CONFIG.domain().replace('\'', "")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_vectors_authorization_header() {
        // docs/vectors/script-access-v1.json in the meta repo.
        let (id, secret) = parse_authorization(
            "PassBundleScript 5b0f3c1a-7e2d-4a9b-8c6d-1f2e3a4b5c6d.x5JMlrHWMMx4vpDRzp0kDKZlkLs_rEbg20FwpFqleC8",
        )
        .unwrap();
        assert_eq!(id, "5b0f3c1a-7e2d-4a9b-8c6d-1f2e3a4b5c6d");
        assert_eq!(auth_hash(&secret), "gjAVeo8WlaVyb7i9c+u32QFR4TyEhU8afI62fU5VFp8=");
    }

    #[test]
    fn refuses_other_authorization_headers() {
        for header in [
            "Bearer x5JMlrHWMMx4vpDRzp0kDKZlkLs_rEbg20FwpFqleC8",
            "PassBundleScript not-a-uuid.x5JMlrHWMMx4vpDRzp0kDKZlkLs_rEbg20FwpFqleC8",
            "PassBundleScript 5b0f3c1a-7e2d-4a9b-8c6d-1f2e3a4b5c6d",
            "PassBundleScript 5b0f3c1a-7e2d-4a9b-8c6d-1f2e3a4b5c6d.c2hvcnQ",
        ] {
            assert!(parse_authorization(header).is_none(), "{header}");
        }
    }

    #[test]
    fn a_token_lasts_an_hour_to_a_year() {
        let now = DateTime::parse_from_rfc3339("2026-10-20T00:00:00Z").unwrap().naive_utc();
        assert!(checked_expiry("2027-01-18T00:00:00Z", now).is_ok());
        assert!(checked_expiry("2026-10-20T00:30:00Z", now).is_err());
        assert!(checked_expiry("2026-10-19T00:00:00Z", now).is_err());
        assert!(checked_expiry("2027-10-22T00:00:00Z", now).is_err());
        assert!(checked_expiry("next week", now).is_err());
    }

    #[test]
    fn a_revision_to_the_millisecond_is_the_same_revision() {
        let updated = DateTime::parse_from_rfc3339("2026-10-20T18:00:00.123456Z").unwrap().naive_utc();
        assert!(same_revision("2026-10-20T18:00:00.123Z", &updated));
        assert!(same_revision("2026-10-20T18:00:00.123456Z", &updated));
        assert!(!same_revision("2026-10-20T18:00:00.124Z", &updated));
        assert!(!same_revision("yesterday", &updated));
    }

    #[test]
    fn copies_and_specs_are_encrypted_strings() {
        assert!(valid_enc_string("2.UFFSU1RVVldYWVpbXF1eXw==|bmFtZQ==|bWFj", MAX_COPY));
        assert!(!valid_enc_string("plain text", MAX_COPY));
        assert!(!valid_enc_string("2.only|two", MAX_COPY));
        assert!(!valid_enc_string(&format!("2.{}|YQ==|YQ==", "A".repeat(MAX_SPEC)), MAX_SPEC));
    }
}

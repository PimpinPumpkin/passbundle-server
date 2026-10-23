// Keykeeper: an organization's Provisioning page (DESIGN.md, "Provisioning
// from Entra ID", in the meta repo). Its owners and admins, and for an MSP's
// client its MSP's admins (never other MSP staff, as for script tokens), make,
// replace, and revoke the token the directory uses at /scim/v2/<organization>,
// see when it was last used, and let in people the directory invited.
//
// The token is made here, by the server, from 32 random bytes; the answer that
// makes it is the only place it ever appears. The server keeps its SHA-256.
//
// Letting someone in is an owner's or admin's browser sealing their
// invitation, exactly as when it invites them from the Members page: the
// directory's requests reach only the server, so nothing in them can vouch
// for an address to the apps that give out the organization's key. See
// "Joins a hacked server can't forge".

use rocket::{Route, serde::json::Json};
use serde_json::{Value, json};

use super::{
    keykeeper_enrollment::checked_seal, keykeeper_msp::Audit, keykeeper_script_access::is_token_admin, log_event,
};
use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult},
    auth::Headers,
    db::{
        DbConn,
        models::{
            EventType, JoinSeal, MembershipStatus, MembershipType, MspClient, MspMembership, Organization,
            OrganizationId, ScimGroup, ScimPerson, ScimToken, SealKind,
        },
    },
    util::format_date,
};

pub fn routes() -> Vec<Route> {
    routes![get_provisioning, make_token, revoke_token, let_in]
}

/// The most invitations one request seals.
const MAX_SEALS: usize = 500;

/// Owners and admins of the organization, and an MSP's admins in its clients.
/// Anyone else gets "not found": upstream's web vault signs out on 403.
async fn require_admin(org_id: &OrganizationId, headers: &Headers, conn: &DbConn) -> EmptyResult {
    if !is_token_admin(org_id, &headers.user.uuid, conn).await {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    }
    Ok(())
}

/// The organization's SCIM URL, the one to paste into Entra as the Tenant URL.
pub fn scim_url(org_id: &OrganizationId) -> String {
    format!("{}/scim/v2/{org_id}", CONFIG.domain())
}

/// A word for someone provisioning leaves alone.
async fn role_of(person: &ScimPerson, conn: &DbConn) -> &'static str {
    if MspMembership::find_by_membership(&person.member.uuid, conn).await.is_some() {
        return "IT provider's staff";
    }
    match person.member.atype {
        t if t == MembershipType::Owner as i32 => "Owner",
        t if t == MembershipType::Admin as i32 => "Admin",
        _ if crate::db::models::keykeeper_roles::find(&person.member.uuid, conn).await.is_some() => "Custom role",
        _ if person.member.access_all => "Sees every item",
        _ => "Manager",
    }
}

async fn view(org_id: &OrganizationId, conn: &DbConn) -> Value {
    let token = ScimToken::find(org_id, conn).await;
    let people = ScimPerson::load_org(org_id, conn).await;
    let mut linked = 0;
    let mut provisioned = 0;
    let mut waiting = Vec::new();
    let mut turned_off = Vec::new();
    for person in &people {
        let Some(scim) = &person.scim else {
            continue;
        };
        linked += 1;
        if scim.provisioned {
            provisioned += 1;
        }
        let status = person.member.status;
        // Invited by the directory, not let in by anyone yet.
        if scim.provisioned
            && !person.protected
            && (status == MembershipStatus::Invited as i32 || status == MembershipStatus::Accepted as i32)
            && JoinSeal::find(org_id, &person.user.email, SealKind::Invite, conn).await.is_none()
        {
            waiting.push(json!({
                "memberId": person.member.uuid,
                "email": person.user.email,
                "userName": scim.user_name,
                "joined": status == MembershipStatus::Accepted as i32,
            }));
        }
        // The directory turned off someone it can't change, who still has access.
        if let Some(at) = &scim.refused_off_at
            && person.protected
            && status > MembershipStatus::Revoked as i32
        {
            turned_off.push(json!({
                "memberId": person.member.uuid,
                "email": person.user.email,
                "role": role_of(person, conn).await,
                "at": format_date(at),
            }));
        }
    }
    json!({
        "scimUrl": scim_url(org_id),
        "token": token.map(|t| json!({
            "createdAt": format_date(&t.created_at),
            "createdBy": t.created_by,
            "lastUsedAt": t.last_used_at.as_ref().map(format_date),
            "lastUsedIp": t.last_used_ip,
        })),
        "people": linked,
        "provisioned": provisioned,
        "groups": ScimGroup::count_by_org(org_id, conn).await,
        "groupsEnabled": CONFIG.org_groups_enabled(),
        "mailEnabled": CONFIG.mail_enabled(),
        "waiting": waiting,
        "turnedOff": turned_off,
    })
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

#[get("/keykeeper/organizations/<org_id>/provisioning")]
async fn get_provisioning(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&org_id, &headers, &conn).await?;
    Ok(Json(view(&org_id, &conn).await))
}

/// Makes the organization's token, or replaces it: the old one stops working
/// at once. The answer carries the token; nothing else ever will.
#[post("/keykeeper/organizations/<org_id>/provisioning/token")]
async fn make_token(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&org_id, &headers, &conn).await?;
    let replaced = ScimToken::find(&org_id, &conn).await.is_some();
    let (token, row) = ScimToken::generate(org_id.clone(), &headers.user.email);
    row.replace(&conn).await?;
    let event = if replaced {
        "provisioning_token_replaced"
    } else {
        "provisioning_token_created"
    };
    record_for_msp(&org_id, event, None, &headers, &conn).await?;
    log_event(
        EventType::OrganizationUpdated,
        &org_id,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;
    let mut answer = view(&org_id, &conn).await;
    answer["newToken"] = json!(token);
    Ok(Json(answer))
}

/// Revokes the organization's token: provisioning stops until there's a new one.
#[delete("/keykeeper/organizations/<org_id>/provisioning/token")]
async fn revoke_token(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&org_id, &headers, &conn).await?;
    if ScimToken::find(&org_id, &conn).await.is_some() {
        ScimToken::delete(&org_id, &conn).await?;
        record_for_msp(&org_id, "provisioning_token_revoked", None, &headers, &conn).await?;
        log_event(
            EventType::OrganizationUpdated,
            &org_id,
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await;
    }
    Ok(Json(view(&org_id, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteSeal {
    email: String,
    seal: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LetInData {
    seals: Vec<InviteSeal>,
}

/// Lets in people the directory invited: an owner's or admin's browser seals
/// their invitations, as it does for the Members page's invitations, after
/// its person chose them from the waiting list. Only for people provisioning
/// invited who are still waiting; everything is checked before anything is
/// saved.
#[put("/keykeeper/organizations/<org_id>/provisioning/seals", data = "<data>")]
async fn let_in(org_id: OrganizationId, data: Json<LetInData>, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&org_id, &headers, &conn).await?;
    let data = data.into_inner();
    if data.seals.is_empty() || data.seals.len() > MAX_SEALS {
        err!(format!("Let in between 1 and {MAX_SEALS} people at a time"))
    }
    let people = ScimPerson::load_org(&org_id, &conn).await;
    for s in &data.seals {
        checked_seal(Some(&s.seal))?;
        let waiting = people.iter().any(|p| {
            p.user.email.eq_ignore_ascii_case(s.email.trim())
                && !p.protected
                && p.scim.as_ref().is_some_and(|scim| scim.provisioned)
                && (p.member.status == MembershipStatus::Invited as i32
                    || p.member.status == MembershipStatus::Accepted as i32)
        });
        if !waiting {
            err!(format!("{} isn't waiting to be let in from your directory", s.email.trim()))
        }
    }
    for s in &data.seals {
        JoinSeal::set(&org_id, s.email.trim(), SealKind::Invite, Some(&s.seal), &conn).await?;
    }
    let count = data.seals.len();
    let detail = if count == 1 {
        "1 person".to_owned()
    } else {
        format!("{count} people")
    };
    record_for_msp(&org_id, "provisioning_let_in", Some(detail), &headers, &conn).await?;
    Ok(Json(view(&org_id, &conn).await))
}

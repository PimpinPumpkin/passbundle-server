// Keykeeper: how people join an organization (see the model in
// db/models/keykeeper_joining.rs): whether a member who accepts an invitation
// is confirmed automatically, and how long invitations last. An organization's
// owners and admins set its own; an MSP's admins set a default for its clients.
//
// Confirming needs the organization's key, which the server never holds, so
// "automatically" means an owner's or admin's unlocked web vault or extension
// does it in the background. They find who's waiting with GET
// /keykeeper/organizations/pending. See DESIGN.md, "Joining".

use rocket::{Route, serde::json::Json};
use serde_json::{Value, json};

use crate::{
    api::{EmptyResult, JsonResult},
    auth::Headers,
    db::{
        DbConn,
        models::{
            INVITE_HOURS, Joining, JoiningSource, Membership, MembershipStatus, MembershipType, Msp, MspClient, MspId,
            MspJoining, OrgJoining, Organization, OrganizationId, User, confirms_automatically, effective_joining,
            msp_default,
        },
    },
};

use super::keykeeper_msp::{Audit, require_admin, staff_member};

pub fn routes() -> Vec<Route> {
    routes![get_org_joining, set_org_joining, reset_org_joining, get_msp_joining, set_msp_joining, pending_for_caller]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoiningData {
    auto_confirm: bool,
    invite_hours: i32,
}

impl JoiningData {
    fn checked(&self) -> Result<Joining, crate::error::Error> {
        if !INVITE_HOURS.contains(&self.invite_hours) {
            err!("Invitations last between 1 hour and 30 days")
        }
        Ok(Joining {
            auto_confirm: self.auto_confirm,
            invite_hours: self.invite_hours,
        })
    }
}

fn joining_json(joining: Joining) -> Value {
    json!({ "autoConfirm": joining.auto_confirm, "inviteHours": joining.invite_hours })
}

/// The caller's membership, if they're a confirmed owner or admin.
async fn owner_or_admin(org_id: &OrganizationId, headers: &Headers, conn: &DbConn) -> Option<Membership> {
    Membership::find_by_user_and_org(&headers.user.uuid, org_id, conn).await.filter(|m| {
        m.status == MembershipStatus::Confirmed as i32
            && (m.atype == MembershipType::Owner as i32 || m.atype == MembershipType::Admin as i32)
    })
}

/// Only an organization's owners and admins see or change how people join it.
async fn require_owner_or_admin(org_id: &OrganizationId, headers: &Headers, conn: &DbConn) -> EmptyResult {
    if owner_or_admin(org_id, headers, conn).await.is_none() {
        // The same answer whether the organization exists or not.
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    }
    Ok(())
}

async fn org_view(org_id: &OrganizationId, conn: &DbConn) -> Value {
    let (joining, source) = effective_joining(org_id, conn).await;
    let mut view = joining_json(joining);
    view["source"] = json!(match source {
        JoiningSource::Own => "own",
        JoiningSource::Msp => "msp",
        JoiningSource::Server => "server",
    });
    // For an MSP's client, the MSP and its default, whether the client
    // follows it or has its own: the admin console offers to go back to it.
    let msp = match MspClient::find_by_org(org_id, conn).await {
        Some(client) => Msp::find_by_uuid(&client.msp_uuid, conn).await,
        None => None,
    };
    if let Some(msp) = msp {
        view["mspName"] = json!(msp.name);
        view["default"] = joining_json(msp_default(&msp.uuid, conn).await);
    } else {
        view["default"] = joining_json(Joining::server_default());
    }
    view
}

/// For an MSP's client, its activity log; nothing for other organizations.
async fn record_for_msp(
    org_id: &OrganizationId,
    event: &'static str,
    detail: String,
    headers: &Headers,
    conn: &DbConn,
) -> EmptyResult {
    let Some(client) = MspClient::find_by_org(org_id, conn).await else {
        return Ok(());
    };
    let name = Organization::find_by_uuid(org_id, conn).await.map(|o| o.name).unwrap_or_default();
    Audit::by(event, headers).org(org_id, &name).detail(detail).record(&client.msp_uuid, conn).await
}

fn describe(joining: Joining) -> String {
    format!(
        "{}; invitations last {}",
        if joining.auto_confirm {
            "confirmed automatically"
        } else {
            "approved by an admin"
        },
        crate::mail::lifetime_words(i64::from(joining.invite_hours))
    )
}

#[get("/keykeeper/organizations/<org_id>/joining")]
async fn get_org_joining(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    require_owner_or_admin(&org_id, &headers, &conn).await?;
    Ok(Json(org_view(&org_id, &conn).await))
}

/// Sets the organization's own setting, which its MSP's default won't change.
#[put("/keykeeper/organizations/<org_id>/joining", data = "<data>")]
async fn set_org_joining(
    org_id: OrganizationId,
    data: Json<JoiningData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    require_owner_or_admin(&org_id, &headers, &conn).await?;
    let joining = data.into_inner().checked()?;
    OrgJoining::new(org_id.clone(), joining).save(&conn).await?;
    record_for_msp(&org_id, "client_joining_set", describe(joining), &headers, &conn).await?;
    Ok(Json(org_view(&org_id, &conn).await))
}

/// Puts the organization back on its MSP's default, or the server's.
#[delete("/keykeeper/organizations/<org_id>/joining")]
async fn reset_org_joining(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    require_owner_or_admin(&org_id, &headers, &conn).await?;
    OrgJoining::delete(&org_id, &conn).await?;
    record_for_msp(&org_id, "client_joining_default", String::new(), &headers, &conn).await?;
    Ok(Json(org_view(&org_id, &conn).await))
}

/// The MSP's default, and which clients follow it. Any of its staff can see it.
#[get("/keykeeper/msp/<msp_id>/joining")]
async fn get_msp_joining(msp_id: MspId, headers: Headers, conn: DbConn) -> JsonResult {
    let caller = staff_member(&msp_id, &headers.user.uuid, &conn).await?;
    // A technician limited to some clients sees only those.
    let reach = caller.reach(&conn).await;
    let mut own = Vec::new();
    for client in MspClient::find_by_msp(&msp_id, &conn).await {
        if reach.as_ref().is_some_and(|r| !r.contains(&client.org_uuid)) {
            continue;
        }
        if let Some(setting) = OrgJoining::find(&client.org_uuid, &conn).await {
            let name = Organization::find_by_uuid(&client.org_uuid, &conn).await.map(|o| o.name).unwrap_or_default();
            own.push(json!({
                "organizationId": client.org_uuid,
                "name": name,
                "autoConfirm": setting.auto_confirm,
                "inviteHours": setting.invite_hours,
            }));
        }
    }
    Ok(Json(json!({ "default": joining_json(msp_default(&msp_id, &conn).await), "ownSettings": own })))
}

/// Sets the MSP's default. Clients with their own setting keep it.
#[put("/keykeeper/msp/<msp_id>/joining", data = "<data>")]
async fn set_msp_joining(msp_id: MspId, data: Json<JoiningData>, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let joining = data.into_inner().checked()?;
    MspJoining::new(msp_id.clone(), joining).save(&conn).await?;
    Audit::by("joining_default_set", &headers).detail(describe(joining)).record(&msp_id, &conn).await?;
    get_msp_joining(msp_id, headers, conn).await
}

/// Everyone waiting for an organization's key in organizations where the
/// caller can confirm them, with whether each organization confirms
/// automatically. Upstream's rules: owners confirm anyone, admins only
/// regular members.
#[get("/keykeeper/organizations/pending")]
async fn pending_for_caller(headers: Headers, conn: DbConn) -> JsonResult {
    let mut pending = Vec::new();
    for caller in Membership::find_confirmed_by_user(&headers.user.uuid, &conn).await {
        let is_owner = caller.atype == MembershipType::Owner as i32;
        if !is_owner && caller.atype != MembershipType::Admin as i32 {
            continue;
        }
        let (joining, _) = effective_joining(&caller.org_uuid, &conn).await;
        for member in Membership::find_by_org(&caller.org_uuid, &conn).await {
            if member.status != MembershipStatus::Accepted as i32
                || (!is_owner && member.atype != MembershipType::User as i32)
            {
                continue;
            }
            let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
                continue;
            };
            let Some(public_key) = user.public_key.clone() else {
                continue;
            };
            pending.push(json!({
                "organizationId": caller.org_uuid,
                "memberId": member.uuid,
                "email": user.email,
                "publicKey": public_key,
                "autoConfirm": confirms_automatically(joining.auto_confirm, &member, &conn).await,
            }));
        }
    }
    Ok(Json(json!({ "data": pending })))
}

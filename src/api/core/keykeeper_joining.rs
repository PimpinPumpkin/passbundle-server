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
            EnrollmentDomains, INVITE_HOURS, JoinSeal, Joining, JoiningSeal, JoiningSource, Membership,
            MembershipStatus, MembershipType, Msp, MspClient, MspEnrollmentJoin, MspId, MspJoining, MspMembership,
            OrgJoining, OrgPolicy, OrgSetup, Organization, OrganizationId, SealKind, User, confirms_automatically,
            effective_joining, msp_default,
        },
    },
};

use super::keykeeper_msp::{Audit, require_admin, staff_member};

pub fn routes() -> Vec<Route> {
    routes![
        get_org_joining,
        set_org_joining,
        reset_org_joining,
        get_msp_joining,
        set_msp_joining,
        pending_for_caller,
        two_step_needed
    ]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoiningData {
    auto_confirm: bool,
    invite_hours: i32,
    /// For an organization's own setting: the seal over it and the
    /// organization's email domains, from the app that saved it.
    seal: Option<String>,
    /// For an MSP's default: a seal per client that follows it.
    #[serde(default)]
    seals: std::collections::HashMap<OrganizationId, String>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SealData {
    seal: Option<String>,
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
    // What the seal covers with the setting, and the seal, so an app saving a
    // change can check what it's resealing.
    view["domains"] = json!(EnrollmentDomains::for_org(org_id, conn).await);
    view["seal"] = json!(JoiningSeal::find(org_id, conn).await);
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
    let data = data.into_inner();
    let seal = super::keykeeper_enrollment::checked_seal(data.seal.as_ref())?;
    let joining = data.checked()?;
    OrgJoining::new(org_id.clone(), joining).save(&conn).await?;
    JoiningSeal::set(&org_id, seal, &conn).await?;
    record_for_msp(&org_id, "client_joining_set", describe(joining), &headers, &conn).await?;
    Ok(Json(org_view(&org_id, &conn).await))
}

/// Puts the organization back on its MSP's default, or the server's.
#[delete("/keykeeper/organizations/<org_id>/joining", data = "<data>")]
async fn reset_org_joining(
    org_id: OrganizationId,
    data: Option<Json<SealData>>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    require_owner_or_admin(&org_id, &headers, &conn).await?;
    let data = data.map(Json::into_inner).unwrap_or_default();
    let seal = super::keykeeper_enrollment::checked_seal(data.seal.as_ref())?;
    OrgJoining::delete(&org_id, &conn).await?;
    JoiningSeal::set(&org_id, seal, &conn).await?;
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
    // The clients that follow the default, with what an MSP admin's app
    // reseals for each when the default changes.
    let mut following = Vec::new();
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
        } else {
            following.push(json!({
                "organizationId": client.org_uuid,
                "domains": EnrollmentDomains::for_org(&client.org_uuid, &conn).await,
                "seal": JoiningSeal::find(&client.org_uuid, &conn).await,
            }));
        }
    }
    Ok(Json(json!({
        "default": joining_json(msp_default(&msp_id, &conn).await),
        "ownSettings": own,
        "following": following,
    })))
}

/// Sets the MSP's default. Clients with their own setting keep it.
#[put("/keykeeper/msp/<msp_id>/joining", data = "<data>")]
async fn set_msp_joining(msp_id: MspId, data: Json<JoiningData>, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let data = data.into_inner();
    let joining = data.checked()?;
    for seal in data.seals.values() {
        super::keykeeper_enrollment::checked_seal(Some(seal))?;
    }
    // Keykeeper: a client following the default where the caller has no place
    // of their own (it may have revoked them) keeps how people join it now,
    // as its own setting, with its seal (keykeeper_offboarding.rs).
    let before = msp_default(&msp_id, &conn).await;
    for client in MspClient::find_by_msp(&msp_id, &conn).await {
        if OrgJoining::find(&client.org_uuid, &conn).await.is_none()
            && !super::keykeeper_offboarding::has_client_place(&client.org_uuid, &headers.user.uuid, true, &conn).await
        {
            OrgJoining::new(client.org_uuid.clone(), before).save(&conn).await?;
        }
    }
    MspJoining::new(msp_id.clone(), joining).save(&conn).await?;
    // Every client that follows the default gets the seal the app made for
    // it, or none: then its joins need approval until an admin seals it.
    for client in MspClient::find_by_msp(&msp_id, &conn).await {
        if OrgJoining::find(&client.org_uuid, &conn).await.is_none() {
            JoiningSeal::set(&client.org_uuid, data.seals.get(&client.org_uuid).map(String::as_str), &conn).await?;
        }
    }
    Audit::by("joining_default_set", &headers).detail(describe(joining)).record(&msp_id, &conn).await?;
    get_msp_joining(msp_id, headers, conn).await
}

/// What an app needs to decide on its own whether to let someone waiting in,
/// without trusting the server: the organization's joining setting with its
/// seal, and whatever vouches for the person (an invitation's seal, an MSP
/// staff seal, or an install command join's proof with the command's
/// encrypted join secret). The server can't make any of these. See DESIGN.md,
/// "Joins a hacked server can't forge".
pub(super) async fn vouching(
    org_id: &OrganizationId,
    member: &Membership,
    email: &str,
    from_msp: bool,
    conn: &DbConn,
) -> Value {
    let (joining, _) = effective_joining(org_id, conn).await;
    let proof = MspEnrollmentJoin::proof_for(&member.uuid, conn).await;
    let secret = match &proof {
        None => None,
        Some(_) => match MspClient::find_by_org(org_id, conn).await {
            Some(client) => client.enrollment_secret,
            None => OrgSetup::find_by_org(org_id, conn).await.and_then(|s| s.enrollment_secret),
        },
    };
    json!({
        "joining": {
            "autoConfirm": joining.auto_confirm,
            "domains": EnrollmentDomains::for_org(org_id, conn).await,
            "seal": JoiningSeal::find(org_id, conn).await,
        },
        "inviteSeal": JoinSeal::find(org_id, email, SealKind::Invite, conn).await,
        "staffSeal": if from_msp { JoinSeal::find(org_id, email, SealKind::Staff, conn).await } else { None },
        "joinProof": proof,
        "enrollmentSecret": secret,
    })
}

/// Adds the fields of `more` to `entry`.
pub(super) fn extend(entry: &mut Value, more: Value) {
    if let (Some(entry), Value::Object(more)) = (entry.as_object_mut(), more) {
        entry.extend(more);
    }
}

/// Everyone waiting for an organization's key in organizations where the
/// caller can confirm them, with whether each organization confirms
/// automatically, and whether they first have to turn on two-step login
/// (confirming them fails until they do). Upstream's rules: owners confirm
/// anyone, admins only regular members.
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
            let from_msp = MspMembership::find_by_membership(&member.uuid, &conn).await.is_some();
            let mut entry = json!({
                "organizationId": caller.org_uuid,
                "memberId": member.uuid,
                "userId": user.uuid,
                "email": user.email,
                "publicKey": public_key,
                "fromMsp": from_msp,
                "autoConfirm": confirms_automatically(joining.auto_confirm, &member, &conn).await,
                "needsTwoStep": OrgPolicy::waits_for_two_step(&member, &conn).await,
            });
            extend(&mut entry, vouching(&caller.org_uuid, &member, &user.email, from_msp, &conn).await);
            pending.push(entry);
        }
    }
    Ok(Json(json!({ "data": pending })))
}

/// The caller's organizations that can't confirm them until they turn on
/// two-step login, so their apps can say so.
#[get("/keykeeper/organizations/two-step-needed")]
async fn two_step_needed(headers: Headers, conn: DbConn) -> JsonResult {
    let mut waiting = Vec::new();
    for member in Membership::find_accepted_and_confirmed_by_user(&headers.user.uuid, &conn).await {
        if member.status != MembershipStatus::Accepted as i32 || !OrgPolicy::waits_for_two_step(&member, &conn).await {
            continue;
        }
        if let Some(org) = Organization::find_by_uuid(&member.org_uuid, &conn).await {
            waiting.push(json!({ "organizationId": org.uuid, "name": org.name }));
        }
    }
    Ok(Json(json!({ "data": waiting })))
}

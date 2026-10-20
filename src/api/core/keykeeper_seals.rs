// Keykeeper: where owners' and admins' apps leave what lets other apps confirm
// joins on their own without trusting the server: staff seals in an MSP's
// clients, joining seals, and install commands' encrypted join secrets. Most
// come with the change they vouch for (an invitation, a joining setting,
// email domains, a new token); these routes are for what can only be made
// after the server answers, such as a new organization's, whose id the app
// needs first. The server can't read or make any of these, so it only checks
// who may leave them and that each looks like one. See DESIGN.md, "Joins a
// hacked server can't forge".

use rocket::{Route, serde::json::Json};
use serde_json::json;

use super::keykeeper_enrollment::{checked_seal, checked_secret};
use super::keykeeper_msp::require_admin;
use crate::{
    api::JsonResult,
    auth::Headers,
    db::{
        DbConn,
        models::{
            JoinSeal, JoiningSeal, Membership, MembershipType, MspClient, MspId, MspInvite, MspStaff, OrgSetup,
            Organization, OrganizationId, SealKind, User,
        },
    },
};

pub fn routes() -> Vec<Route> {
    routes![set_msp_seals, set_org_seals, get_org_private_key]
}

/// The organization's private key, encrypted with its organization key, for
/// its owners and admins. Their browser derives the organization's public
/// key from it for the install command's fingerprint, rather than trusting
/// the public key the server reports. They hold the organization key already,
/// so this tells them nothing new. Anyone else gets "not found": the web
/// vault signs out on 403.
#[get("/keykeeper/organizations/<org_id>/private-key")]
async fn get_org_private_key(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    let caller = Membership::find_confirmed_by_user_and_org(&headers.user.uuid, &org_id, &conn).await;
    if !caller.is_some_and(|c| c.atype == MembershipType::Owner as i32 || c.atype == MembershipType::Admin as i32) {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    }
    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    };
    Ok(Json(json!({ "encryptedPrivateKey": org.private_key })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StaffSeal {
    organization_id: OrganizationId,
    email: String,
    seal: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgSeal {
    organization_id: OrganizationId,
    seal: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgSecret {
    organization_id: OrganizationId,
    secret: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MspSealsData {
    #[serde(default)]
    staff: Vec<StaffSeal>,
    #[serde(default)]
    joining: Vec<OrgSeal>,
    #[serde(default)]
    secrets: Vec<OrgSecret>,
}

/// An MSP admin's app seals staff members' places in its clients, clients'
/// joining settings, and their install commands' join secrets. MSP admins
/// only, for the MSP's own clients, and staff seals only for its staff or
/// people it invited.
#[put("/keykeeper/msp/<msp_id>/seals", data = "<data>")]
async fn set_msp_seals(msp_id: MspId, data: Json<MspSealsData>, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let data = data.into_inner();
    let clients: Vec<OrganizationId> =
        MspClient::find_by_msp(&msp_id, &conn).await.into_iter().map(|c| c.org_uuid).collect();
    let mut staff_emails: Vec<String> = Vec::new();
    for staff in MspStaff::find_by_msp(&msp_id, &conn).await {
        if let Some(user) = User::find_by_uuid(&staff.user_uuid, &conn).await {
            staff_emails.push(user.email.to_lowercase());
        }
    }
    for invite in MspInvite::find_by_msp(&msp_id, &conn).await {
        staff_emails.push(invite.email.to_lowercase());
    }
    let ours = |org: &OrganizationId| -> Result<(), crate::error::Error> {
        if !clients.contains(org) {
            err_code!("Client not found", rocket::http::Status::NotFound.code)
        }
        Ok(())
    };
    // Everything is checked before anything is saved.
    for s in &data.staff {
        ours(&s.organization_id)?;
        checked_seal(Some(&s.seal))?;
        if !staff_emails.contains(&s.email.to_lowercase()) {
            err!("That person isn't on your staff or invited to it")
        }
    }
    for s in &data.joining {
        ours(&s.organization_id)?;
        checked_seal(Some(&s.seal))?;
    }
    for s in &data.secrets {
        ours(&s.organization_id)?;
        checked_secret(Some(&s.secret))?;
    }
    for s in &data.staff {
        JoinSeal::set(&s.organization_id, &s.email, SealKind::Staff, Some(&s.seal), &conn).await?;
    }
    for s in &data.joining {
        JoiningSeal::set(&s.organization_id, Some(&s.seal), &conn).await?;
    }
    for s in data.secrets {
        if let Some(mut client) = MspClient::find_by_org(&s.organization_id, &conn).await {
            client.set_enrollment_secret(Some(s.secret), &conn).await?;
        }
    }
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgSealsData {
    joining: Option<String>,
    secret: Option<String>,
}

/// An owner's or admin's app seals a company's own organization's joining
/// setting and its install command's join secret, such as right after making
/// the organization. An MSP's client's are its MSP admins' to seal.
#[put("/keykeeper/organizations/<org_id>/seals", data = "<data>")]
async fn set_org_seals(org_id: OrganizationId, data: Json<OrgSealsData>, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(caller) = Membership::find_confirmed_by_user_and_org(&headers.user.uuid, &org_id, &conn).await else {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    };
    if caller.atype != MembershipType::Owner as i32 && caller.atype != MembershipType::Admin as i32 {
        err_code!("Only owners and admins can seal how people join", rocket::http::Status::Forbidden.code)
    }
    if MspClient::find_by_org(&org_id, &conn).await.is_some() {
        err_code!(
            "This organization's IT provider seals how people join it, in their MSP console",
            rocket::http::Status::Forbidden.code
        )
    }
    let data = data.into_inner();
    let seal = checked_seal(data.joining.as_ref())?;
    let secret = checked_secret(data.secret.as_ref())?;
    if seal.is_some() {
        JoiningSeal::set(&org_id, seal, &conn).await?;
    }
    if let Some(secret) = secret {
        let Some(mut setup) = OrgSetup::find_by_org(&org_id, &conn).await else {
            err!("This organization has no install command yet")
        };
        setup.set_enrollment_secret(Some(secret), &conn).await?;
    }
    Ok(Json(json!({})))
}

// Keykeeper: assisted password change in an organization (DESIGN.md,
// "Assisted password change", "Organizations", in the meta repo). The browser
// extension changes a login's password on its site, saving the new one to the
// item first. For an organization's items:
//
// - The organization's setting allows it, on by default. Its owners, admins,
//   and its MSP's admins turn it off or on again on its Settings page (not
//   technicians, as for two-step login for admins), and an MSP can make it a
//   default policy for its clients ("Turn off assisted password change",
//   keykeeper_msp_policies), following, own settings, Use default, and
//   required for every client included. Members learn it with the
//   organization in sync (`keykeeperPasswordChange`).
// - The extension tells the organization's event log when a change saved a
//   new password to one of its items (1192), and when someone put an item's
//   earlier password back after one (1193). The save itself is upstream's
//   "Edited item" (1101), as any edit; these say how it was made. The server
//   takes them only for an item of an organization that allows it, which the
//   sender can edit and see the password of: the same check the server makes
//   for changing an item's folders, so nobody can write them for an item
//   they couldn't change that way.

use std::net::IpAddr;

use rocket::{Route, http::Status, serde::json::Json};
use serde_json::Value;

use super::{
    keykeeper_msp::Audit,
    keykeeper_msp_policies::{PASSWORD_CHANGE_OFF, is_locked, refuse_if_required},
    keykeeper_script_access::is_token_admin,
    log_event,
};
use crate::{
    api::{ApiResult, JsonResult},
    auth::Headers,
    db::{
        DbConn,
        models::{
            Cipher, EventType, Membership, Msp, MspClient, OrgPasswordChange, Organization, OrganizationId, User,
            UserId,
        },
    },
};

pub fn routes() -> Vec<Route> {
    routes![get_org_setting, put_org_setting]
}

/// Whether the organization allows assisted password change on its items. When
/// its setting can't be read, it doesn't: a change it may have turned off
/// never starts, and no event about one is taken.
pub async fn allowed(org_id: &OrganizationId, conn: &DbConn) -> bool {
    OrgPasswordChange::allowed(org_id, conn)
        .await
        .inspect_err(|e| error!("Taken as off, as the assisted password change setting couldn't be read: {e}"))
        .unwrap_or(false)
}

/// Sets whether the organization allows it, if that's a change: an event in
/// its log, and every member's account changes so their apps sync it (an app
/// syncs at unlock only when the account changed). Used by its Settings page
/// and an MSP's default policies. Answers whether it changed.
pub async fn set_org_allowed(
    org_id: &OrganizationId,
    allowed: bool,
    actor: &UserId,
    device_type: i32,
    ip: &IpAddr,
    conn: &DbConn,
) -> ApiResult<bool> {
    if OrgPasswordChange::allowed(org_id, conn).await? == allowed {
        return Ok(false);
    }
    OrgPasswordChange::set(org_id, allowed, conn).await?;
    for member in Membership::find_by_org(org_id, conn).await {
        User::update_uuid_revision(&member.user_uuid, conn).await;
    }
    let event = if allowed {
        EventType::KeykeeperPasswordChangeOn
    } else {
        EventType::KeykeeperPasswordChangeOff
    };
    log_event(event, org_id, org_id, actor, device_type, ip, conn).await;
    Ok(true)
}

/// Upstream's type number for a login, the only kind of item it changes.
const LOGIN: i32 = 1;

/// Whether an app's event about an assisted password change (1192 or 1193) is
/// taken for this item from this person: an organization's login (personal
/// items have no organization log to go in), in an organization that allows
/// it, which they can edit and see the password of.
pub async fn takes_cipher_event(cipher: &Cipher, user_id: &UserId, conn: &DbConn) -> Option<OrganizationId> {
    let org_id = cipher.organization_uuid.clone()?;
    if cipher.atype != LOGIN || cipher.deleted_at.is_some() {
        return None;
    }
    if !cipher.is_in_editable_collection_by_user(user_id, conn).await || !allowed(&org_id, conn).await {
        return None;
    }
    Some(org_id)
}

async fn org_view(org_id: &OrganizationId, conn: &DbConn) -> ApiResult<Value> {
    let msp = match MspClient::find_by_org(org_id, conn).await {
        Some(client) => {
            Msp::find_by_uuid(&client.msp_uuid, conn).await.map(|m| json!({ "id": m.uuid, "name": m.name }))
        }
        None => None,
    };
    Ok(json!({
        "allowed": OrgPasswordChange::allowed(org_id, conn).await?,
        "msp": msp,
        // The MSP requires its setting for every client, so it can't be
        // changed here (DESIGN.md, "Required for every client").
        "requiredByMsp": is_locked(org_id, PASSWORD_CHANGE_OFF, conn).await,
    }))
}

/// The organization's setting, for its owners and admins (and its MSP's
/// admins, not technicians), as its Settings page shows it. Anyone else gets
/// "not found": upstream's web vault signs out on 403.
#[get("/keykeeper/organizations/<org_id>/password-change")]
async fn get_org_setting(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    if !is_token_admin(&org_id, &headers.user.uuid, &conn).await {
        err_code!("Organization not found", Status::NotFound.code)
    }
    Ok(Json(org_view(&org_id, &conn).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgSettingData {
    allowed: bool,
}

/// Allows assisted password change on the organization's items, or turns it
/// off. Not while its MSP requires its setting for every client. For an MSP's
/// client, the change is its own setting from then on, and goes in the MSP's
/// activity log. It needs no master password: it lets no one in, and gives
/// nobody more than their folders let them do by hand ("Confirming sensitive
/// changes").
#[put("/keykeeper/organizations/<org_id>/password-change", data = "<data>")]
async fn put_org_setting(
    org_id: OrganizationId,
    headers: Headers,
    data: Json<OrgSettingData>,
    conn: DbConn,
) -> JsonResult {
    if !is_token_admin(&org_id, &headers.user.uuid, &conn).await {
        err_code!("Organization not found", Status::NotFound.code)
    }
    let allowed = data.into_inner().allowed;
    // The MSP's default is "Turn off assisted password change": on means off here.
    refuse_if_required(&org_id, PASSWORD_CHANGE_OFF, !allowed, &conn).await?;
    let changed =
        set_org_allowed(&org_id, allowed, &headers.user.uuid, headers.device.atype, &headers.ip.ip, &conn).await?;
    if changed && let Some(client) = MspClient::find_by_org(&org_id, &conn).await {
        let name = Organization::find_by_uuid(&org_id, &conn).await.map(|o| o.name).unwrap_or_default();
        Audit::by("client_password_change_set", &headers)
            .org(&org_id, &name)
            .detail(if allowed {
                "on"
            } else {
                "off"
            })
            .record(&client.msp_uuid, &conn)
            .await?;
    }
    Ok(Json(org_view(&org_id, &conn).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbPool;

    #[rocket::async_test]
    async fn it_is_allowed_until_turned_off_and_each_change_counts_once() {
        let conn = DbPool::for_test().await;
        let org = Organization::new("Acme Dental".to_owned(), "billing@example.test", None, None);
        org.save(&conn).await.unwrap();
        assert!(OrgPasswordChange::allowed(&org.uuid, &conn).await.unwrap());
        assert!(allowed(&org.uuid, &conn).await);

        let actor = UserId::from("someone".to_owned());
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(set_org_allowed(&org.uuid, false, &actor, 0, &ip, &conn).await.unwrap());
        assert!(!allowed(&org.uuid, &conn).await);
        // The same again changes nothing.
        assert!(!set_org_allowed(&org.uuid, false, &actor, 0, &ip, &conn).await.unwrap());
        assert!(set_org_allowed(&org.uuid, true, &actor, 0, &ip, &conn).await.unwrap());
        assert!(allowed(&org.uuid, &conn).await);
    }

    #[rocket::async_test]
    async fn the_setting_goes_with_its_organization() {
        let conn = DbPool::for_test().await;
        let org = Organization::new("Acme Dental".to_owned(), "billing@example.test", None, None);
        org.save(&conn).await.unwrap();
        let org_id = org.uuid.clone();
        OrgPasswordChange::set(&org_id, false, &conn).await.unwrap();
        org.delete(&conn).await.unwrap();
        // Its row went with it: a new organization with the same id would start allowed again.
        assert!(OrgPasswordChange::allowed(&org_id, &conn).await.unwrap());
    }
}

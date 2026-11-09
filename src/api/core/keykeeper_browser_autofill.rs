// Keykeeper: the browsers' own card and address autofill, as an organization
// sets it for its people (DESIGN.md, "Addresses and cards", "IT control of the
// browsers' own autofill", in the meta repo):
//
// - Leave as is (the default), off, or off with an offer to bring saved cards
//   and addresses into PassBundle. Its owners, admins, and its MSP's admins
//   set it on its Settings page (not technicians, as for assisted password
//   change), and an MSP can make it a default policy for its clients ("Turn
//   off the browsers' card and address autofill", keykeeper_msp_policies),
//   following, own settings, Use default, and required for every client
//   included.
// - Members learn it with the organization in sync
//   (`keykeeperBrowserAutofill`): the extension turns the browser's switches
//   off in work profiles. The install command carries it too
//   (keykeeper_enrollment), so the install scripts write the browsers'
//   policies while it's off.
//
// It needs no master password: it changes a browser feature, not who gets in
// or what they can see ("Confirming sensitive changes").

use std::net::IpAddr;

use rocket::{Route, http::Status, serde::json::Json};
use serde_json::Value;

use super::{
    keykeeper_msp::Audit,
    keykeeper_msp_policies::{BROWSER_AUTOFILL_OFF, is_locked, refuse_if_required},
    keykeeper_script_access::is_token_admin,
    log_event,
};
use crate::{
    api::{ApiResult, JsonResult},
    auth::Headers,
    db::{
        DbConn,
        models::{
            BrowserAutofillMode, EventType, Membership, Msp, MspClient, OrgBrowserAutofill, Organization,
            OrganizationId, User, UserId,
        },
    },
};

pub fn routes() -> Vec<Route> {
    routes![get_org_setting, put_org_setting]
}

/// The organization's setting. When it can't be read, the browsers are left
/// as they are: a setting that can't be read never turns anything off, and
/// nothing a person saved is touched by mistake.
pub async fn mode(org_id: &OrganizationId, conn: &DbConn) -> BrowserAutofillMode {
    OrgBrowserAutofill::mode(org_id, conn)
        .await
        .inspect_err(|e| error!("Taken as left as is, as the browser autofill setting couldn't be read: {e}"))
        .unwrap_or(BrowserAutofillMode::Unchanged)
}

/// Sets the organization's setting, if that's a change: an event in its log,
/// and every member's account changes so their apps sync it (an app syncs at
/// unlock only when the account changed). Used by its Settings page and an
/// MSP's default policies. Answers whether it changed.
pub async fn set_org_mode(
    org_id: &OrganizationId,
    mode: BrowserAutofillMode,
    actor: &UserId,
    device_type: i32,
    ip: &IpAddr,
    conn: &DbConn,
) -> ApiResult<bool> {
    if OrgBrowserAutofill::mode(org_id, conn).await? == mode {
        return Ok(false);
    }
    OrgBrowserAutofill::set(org_id, mode, conn).await?;
    for member in Membership::find_by_org(org_id, conn).await {
        User::update_uuid_revision(&member.user_uuid, conn).await;
    }
    let event = match mode {
        BrowserAutofillMode::Unchanged => EventType::KeykeeperBrowserAutofillUnchanged,
        BrowserAutofillMode::Off => EventType::KeykeeperBrowserAutofillOff,
        BrowserAutofillMode::OffAndImport => EventType::KeykeeperBrowserAutofillOffAndImport,
    };
    log_event(event, org_id, org_id, actor, device_type, ip, conn).await;
    Ok(true)
}

async fn org_view(org_id: &OrganizationId, conn: &DbConn) -> ApiResult<Value> {
    let msp = match MspClient::find_by_org(org_id, conn).await {
        Some(client) => {
            Msp::find_by_uuid(&client.msp_uuid, conn).await.map(|m| json!({ "id": m.uuid, "name": m.name }))
        }
        None => None,
    };
    Ok(json!({
        "mode": OrgBrowserAutofill::mode(org_id, conn).await?.as_str(),
        "msp": msp,
        // The MSP requires its setting for every client, so it can't be
        // changed here (DESIGN.md, "Required for every client").
        "requiredByMsp": is_locked(org_id, BROWSER_AUTOFILL_OFF, conn).await,
    }))
}

/// The organization's setting, for its owners and admins (and its MSP's
/// admins, not technicians), as its Settings page shows it. Anyone else gets
/// "not found": upstream's web vault signs out on 403.
#[get("/keykeeper/organizations/<org_id>/browser-autofill")]
async fn get_org_setting(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    if !is_token_admin(&org_id, &headers.user.uuid, &conn).await {
        err_code!("Organization not found", Status::NotFound.code)
    }
    Ok(Json(org_view(&org_id, &conn).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgSettingData {
    mode: String,
}

/// Leaves the browsers' card and address autofill as they are, turns them
/// off, or turns them off and offers each person to bring theirs in. Not
/// while its MSP requires its setting for every client. For an MSP's client,
/// the change is its own setting from then on, and goes in the MSP's activity
/// log.
#[put("/keykeeper/organizations/<org_id>/browser-autofill", data = "<data>")]
async fn put_org_setting(
    org_id: OrganizationId,
    headers: Headers,
    data: Json<OrgSettingData>,
    conn: DbConn,
) -> JsonResult {
    if !is_token_admin(&org_id, &headers.user.uuid, &conn).await {
        err_code!("Organization not found", Status::NotFound.code)
    }
    let Some(mode) = BrowserAutofillMode::parse(&data.into_inner().mode) else {
        err!("Choose unchanged, off, or offAndImport")
    };
    // The MSP's default is "Turn off the browsers' card and address
    // autofill": on means off here.
    refuse_if_required(&org_id, BROWSER_AUTOFILL_OFF, mode.is_off(), &conn).await?;
    let changed = set_org_mode(&org_id, mode, &headers.user.uuid, headers.device.atype, &headers.ip.ip, &conn).await?;
    if changed && let Some(client) = MspClient::find_by_org(&org_id, &conn).await {
        let name = Organization::find_by_uuid(&org_id, &conn).await.map(|o| o.name).unwrap_or_default();
        Audit::by("client_browser_autofill_set", &headers)
            .org(&org_id, &name)
            .detail(mode.as_str())
            .record(&client.msp_uuid, &conn)
            .await?;
    }
    Ok(Json(org_view(&org_id, &conn).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbPool;

    #[test]
    fn its_three_values_have_one_name_each() {
        for mode in [BrowserAutofillMode::Unchanged, BrowserAutofillMode::Off, BrowserAutofillMode::OffAndImport] {
            assert_eq!(BrowserAutofillMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(BrowserAutofillMode::parse("Off"), None);
        assert_eq!(BrowserAutofillMode::parse(""), None);
        assert!(!BrowserAutofillMode::Unchanged.is_off());
        assert!(BrowserAutofillMode::Off.is_off());
        assert!(BrowserAutofillMode::OffAndImport.is_off());
    }

    #[rocket::async_test]
    async fn it_leaves_them_as_they_are_until_changed_and_each_change_counts_once() {
        let conn = DbPool::for_test().await;
        let org = Organization::new("Acme Dental".to_owned(), "billing@example.test", None, None);
        org.save(&conn).await.unwrap();
        assert_eq!(mode(&org.uuid, &conn).await, BrowserAutofillMode::Unchanged);

        let actor = UserId::from("someone".to_owned());
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(set_org_mode(&org.uuid, BrowserAutofillMode::Off, &actor, 0, &ip, &conn).await.unwrap());
        assert_eq!(mode(&org.uuid, &conn).await, BrowserAutofillMode::Off);
        // The same again changes nothing.
        assert!(!set_org_mode(&org.uuid, BrowserAutofillMode::Off, &actor, 0, &ip, &conn).await.unwrap());
        assert!(set_org_mode(&org.uuid, BrowserAutofillMode::OffAndImport, &actor, 0, &ip, &conn).await.unwrap());
        assert_eq!(mode(&org.uuid, &conn).await, BrowserAutofillMode::OffAndImport);
        assert!(set_org_mode(&org.uuid, BrowserAutofillMode::Unchanged, &actor, 0, &ip, &conn).await.unwrap());
        assert_eq!(mode(&org.uuid, &conn).await, BrowserAutofillMode::Unchanged);
    }

    #[rocket::async_test]
    async fn the_setting_goes_with_its_organization() {
        let conn = DbPool::for_test().await;
        let org = Organization::new("Acme Dental".to_owned(), "billing@example.test", None, None);
        org.save(&conn).await.unwrap();
        let org_id = org.uuid.clone();
        OrgBrowserAutofill::set(&org_id, BrowserAutofillMode::Off, &conn).await.unwrap();
        org.delete(&conn).await.unwrap();
        // Its row went with it: a new organization with the same id would leave them as they are.
        assert_eq!(OrgBrowserAutofill::mode(&org_id, &conn).await.unwrap(), BrowserAutofillMode::Unchanged);
    }
}

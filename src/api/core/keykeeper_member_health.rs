// Keykeeper: an organization's owners and admins see how healthy their
// people's own passwords are, without seeing them. Each member's apps count
// the logins in the member's Personal items and send four numbers (how many,
// weak, reused, exposed); the admin console's Reports lists them per member.
// Never which items. See DESIGN.md, "Members' own passwords".
//
// Only where the organization has "Members' own passwords" on (its own
// setting: on with the Business preset and an MSP's default policies, off for
// one made the upstream way). A member's apps ask first which of their
// organizations see the numbers (`seen-by`), and send them only while one
// does; the server keeps a report only then, and deletes the numbers once no
// organization sees them (the last one turns it off, or the member leaves it,
// is removed, or is revoked there; MemberHealth::forget_unless_seen).
//
// An MSP's staff see the same numbers for the clients they manage, in the MSP
// console (`msp_member_health`): only clients they reach where they're a
// confirmed owner or admin, as the client's own owners and admins are, and
// never the numbers of the MSP's own people in a client.

use std::{collections::HashMap, net::IpAddr};

use rocket::{Route, http::Status, serde::json::Json};
use serde_json::{Value, json};

use super::{keykeeper_msp::Audit, keykeeper_script_access::is_token_admin, log_event};
use crate::{
    api::{ApiResult, JsonResult},
    auth::Headers,
    db::{
        DbConn,
        models::{
            EventType, MemberHealth, Membership, MembershipStatus, MembershipType, Msp, MspClient, MspId,
            OrgMemberHealth, Organization, OrganizationId, OwnCounts, UserId, msp_memberships_among,
        },
    },
    util::format_date,
};

pub fn routes() -> Vec<Route> {
    routes![put_own_health, own_health_seen_by, member_health, msp_member_health, get_setting, put_setting]
}

/// The report as an app sends it: whole numbers, `exposed` left out (or
/// null) when it wasn't checked. Anything else is refused in plain words.
fn own_counts(data: &Value) -> Result<OwnCounts, &'static str> {
    const WHOLE: &str = "Send logins, weak, and reused as whole numbers, and exposed only when it was checked";
    let whole = |key: &str| -> Result<Option<i32>, &'static str> {
        match data.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(n) => n.as_i64().and_then(|n| i32::try_from(n).ok()).map(Some).ok_or(WHOLE),
        }
    };
    if !data.is_object() {
        return Err(WHOLE);
    }
    let counts = OwnCounts {
        logins: whole("logins")?.ok_or(WHOLE)?,
        weak: whole("weak")?.ok_or(WHOLE)?,
        reused: whole("reused")?.ok_or(WHOLE)?,
        exposed: whole("exposed")?,
    };
    counts.check()?;
    Ok(counts)
}

fn numbers(row: &MemberHealth) -> Value {
    json!({
        "logins": row.logins,
        "weak": row.weak,
        "reused": row.reused,
        "exposed": row.exposed,
        "exposedCheckedAt": row.exposed_checked_at.as_ref().map(format_date),
        "reportedAt": format_date(&row.reported_at),
    })
}

/// The organizations that see someone's numbers, by id and name.
async fn seen_by_json(user: &UserId, conn: &DbConn) -> ApiResult<Vec<Value>> {
    let mut seen = Vec::new();
    for org_id in MemberHealth::seen_by(user, conn).await? {
        if let Some(org) = Organization::find_by_uuid(&org_id, conn).await {
            seen.push(json!({ "id": org.uuid, "name": org.name }));
        }
    }
    seen.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(seen)
}

/// A member's apps report how many of their own logins are weak, reused,
/// and exposed. Only the numbers are kept, and only while an organization
/// the person has joined sees them: otherwise the report is ignored (200,
/// `kept: false`), and anything kept from before is deleted. Ignored rather
/// than refused: a report can cross a switch turning off, which isn't
/// something the person can fix, and the apps ask `seen-by` first anyway.
#[put("/keykeeper/own-health", data = "<data>")]
async fn put_own_health(data: Json<Value>, headers: Headers, conn: DbConn) -> JsonResult {
    let counts = match own_counts(&data) {
        Ok(counts) => counts,
        Err(why) => err!(why),
    };
    let seen_by = seen_by_json(&headers.user.uuid, &conn).await?;
    if seen_by.is_empty() {
        MemberHealth::delete_for_user(&headers.user.uuid, &conn).await?;
        return Ok(Json(json!({ "object": "keykeeperOwnHealth", "kept": false, "seenBy": [] })));
    }
    let saved = MemberHealth::report(&headers.user.uuid, counts, &conn).await?;
    let mut view = numbers(&saved);
    view["object"] = json!("keykeeperOwnHealth");
    view["kept"] = json!(true);
    view["seenBy"] = json!(seen_by);
    Ok(Json(view))
}

/// For the person: the organizations whose owners and admins see how many of
/// their own passwords are weak, reused, or exposed, by name, for their apps
/// to decide whether to send the numbers and to tell them who sees them.
/// Empty when none does.
#[get("/keykeeper/own-health/seen-by")]
async fn own_health_seen_by(headers: Headers, conn: DbConn) -> JsonResult {
    let data = seen_by_json(&headers.user.uuid, &conn).await?;
    Ok(Json(json!({ "object": "list", "data": data, "continuationToken": null })))
}

/// Whether someone is a confirmed owner or admin of the organization.
async fn owner_or_admin(org_id: &OrganizationId, user: &UserId, conn: &DbConn) -> bool {
    Membership::find_by_user_and_org(user, org_id, conn).await.is_some_and(|m| {
        m.status == MembershipStatus::Confirmed as i32
            && (m.atype == MembershipType::Owner as i32 || m.atype == MembershipType::Admin as i32)
    })
}

/// Each confirmed member's numbers, by membership id, or none reported yet,
/// as the organization's owners and admins see them. An MSP's people in a
/// client are left out: a client never sees its MSP's people's numbers, and
/// the MSP console doesn't count them as the client's.
async fn member_rows(org_id: &OrganizationId, conn: &DbConn) -> ApiResult<Vec<Value>> {
    let confirmed = Membership::find_confirmed_by_org(org_id, conn).await;
    let from_msp = msp_memberships_among(confirmed.iter().map(|m| m.uuid.clone()).collect(), conn).await?;
    let members: Vec<Membership> = confirmed.into_iter().filter(|m| !from_msp.contains(&m.uuid)).collect();
    let reported: HashMap<_, _> =
        MemberHealth::find_by_users(members.iter().map(|m| m.user_uuid.clone()).collect(), conn)
            .await?
            .into_iter()
            .map(|row| (row.user_uuid.clone(), row))
            .collect();
    Ok(members
        .iter()
        .map(|m| {
            let mut row = reported.get(&m.user_uuid).map_or_else(
                || {
                    json!({
                        "logins": null, "weak": null, "reused": null, "exposed": null,
                        "exposedCheckedAt": null, "reportedAt": null,
                    })
                },
                numbers,
            );
            row["memberId"] = json!(m.uuid);
            row
        })
        .collect())
}

/// For an organization's owners and admins: each confirmed member's numbers,
/// by membership id, or none reported yet. An MSP's people in a client are
/// left out. Anyone else gets "not found", whether the organization exists
/// or not: upstream's web vault signs out on 403. With "Members' own
/// passwords" off, it answers as if there were nobody to list (`on: false`),
/// never a member's numbers, which another organization may still see: the
/// page can then say the setting is off and where to turn it on, which a 404
/// couldn't tell apart from someone who isn't an owner or admin.
#[get("/keykeeper/organizations/<org_id>/member-health")]
async fn member_health(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    if !owner_or_admin(&org_id, &headers.user.uuid, &conn).await {
        err_code!("Organization not found", Status::NotFound.code)
    }
    if !OrgMemberHealth::enabled(&org_id, &conn).await? {
        return Ok(Json(json!({ "object": "list", "data": [], "on": false, "continuationToken": null })));
    }
    let data = member_rows(&org_id, &conn).await?;
    Ok(Json(json!({ "object": "list", "data": data, "on": true, "continuationToken": null })))
}

/// The clients of an MSP whose members' numbers one of its staff sees in the
/// MSP console: those they reach (a technician limited to chosen clients
/// reaches only those) where they're a confirmed owner or admin, as the
/// client's own owners and admins are. So a technician with a custom role
/// there, one waiting to be confirmed, and one the client revoked or removed
/// see nothing of it. Anyone who isn't the MSP's staff gets "not found", as
/// for the rest of the MSP's API, whether the MSP exists or not.
async fn msp_clients_seen(msp_id: &MspId, user: &UserId, conn: &DbConn) -> ApiResult<Vec<OrganizationId>> {
    let staff = super::keykeeper_msp::staff_member(msp_id, user, conn).await?;
    let reach = staff.reach(conn).await;
    let mut seen = Vec::new();
    for client in MspClient::find_by_msp(msp_id, conn).await {
        if reach.as_ref().is_some_and(|r| !r.contains(&client.org_uuid)) {
            continue;
        }
        if owner_or_admin(&client.org_uuid, user, conn).await {
            seen.push(client.org_uuid);
        }
    }
    Ok(seen)
}

/// One client in the MSP console: whether it has "Members' own passwords"
/// on, and, only then, each of its own confirmed members' numbers. With it
/// off, nobody's: another organization may still see someone's numbers, and
/// this one doesn't.
async fn msp_client_view(org_id: &OrganizationId, conn: &DbConn) -> ApiResult<Value> {
    let on = OrgMemberHealth::enabled(org_id, conn).await?;
    let members = if on {
        member_rows(org_id, conn).await?
    } else {
        Vec::new()
    };
    Ok(json!({ "organizationId": org_id, "on": on, "members": members }))
}

/// For an MSP's console: each client the caller manages (`msp_clients_seen`),
/// with its members' numbers as its own owners and admins see them, by
/// membership id; the console names them from the client's member list and
/// adds them up for the clients list. Never which items, and never the
/// numbers of the MSP's own people in a client.
#[get("/keykeeper/msp/<msp_id>/member-health")]
async fn msp_member_health(msp_id: MspId, headers: Headers, conn: DbConn) -> JsonResult {
    let mut data = Vec::new();
    for org_id in msp_clients_seen(&msp_id, &headers.user.uuid, &conn).await? {
        data.push(msp_client_view(&org_id, &conn).await?);
    }
    Ok(Json(json!({ "object": "list", "data": data, "continuationToken": null })))
}

/// Turns an organization's "Members' own passwords" on or off, if that's a
/// change, with an event in its log. Off, it deletes the numbers of its
/// members that no other organization sees. Used by the Settings page, the
/// Business preset, and an MSP's default policies.
pub async fn set_org_member_health(
    org_id: &OrganizationId,
    enabled: bool,
    actor: &UserId,
    device_type: i32,
    ip: &IpAddr,
    conn: &DbConn,
) -> ApiResult<bool> {
    if OrgMemberHealth::enabled(org_id, conn).await? == enabled {
        return Ok(false);
    }
    OrgMemberHealth::set(org_id, enabled, conn).await?;
    if !enabled {
        for member in Membership::find_by_org(org_id, conn).await {
            MemberHealth::forget_unless_seen(&member.user_uuid, conn).await?;
        }
    }
    let event = if enabled {
        EventType::KeykeeperMemberHealthOn
    } else {
        EventType::KeykeeperMemberHealthOff
    };
    log_event(event, org_id, org_id, actor, device_type, ip, conn).await;
    Ok(true)
}

async fn setting_view(org_id: &OrganizationId, conn: &DbConn) -> ApiResult<Value> {
    let msp = match MspClient::find_by_org(org_id, conn).await {
        Some(client) => {
            Msp::find_by_uuid(&client.msp_uuid, conn).await.map(|m| json!({ "id": m.uuid, "name": m.name }))
        }
        None => None,
    };
    Ok(json!({
        "enabled": OrgMemberHealth::enabled(org_id, conn).await?,
        "msp": msp,
        // The MSP requires it for every client, so it can't be changed here
        // (DESIGN.md, "Required for every client").
        "requiredByMsp": super::keykeeper_msp_policies::is_locked(
            org_id,
            super::keykeeper_msp_policies::MEMBER_HEALTH,
            conn,
        )
        .await,
    }))
}

/// The organization's "Members' own passwords", for its owners and admins
/// (and its MSP's admins, not technicians), as its Settings page shows it.
/// Anyone else gets "not found": upstream's web vault signs out on 403.
#[get("/keykeeper/organizations/<org_id>/member-health-setting")]
async fn get_setting(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    if !is_token_admin(&org_id, &headers.user.uuid, &conn).await {
        err_code!("Organization not found", Status::NotFound.code)
    }
    Ok(Json(setting_view(&org_id, &conn).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingData {
    enabled: bool,
}

/// Turns "Members' own passwords" on or off. For an MSP's client, the change
/// is its own setting from then on, and goes in the MSP's activity log.
#[put("/keykeeper/organizations/<org_id>/member-health-setting", data = "<data>")]
async fn put_setting(org_id: OrganizationId, headers: Headers, data: Json<SettingData>, conn: DbConn) -> JsonResult {
    if !is_token_admin(&org_id, &headers.user.uuid, &conn).await {
        err_code!("Organization not found", Status::NotFound.code)
    }
    let enabled = data.into_inner().enabled;
    // Not while the organization's MSP requires it for every client.
    super::keykeeper_msp_policies::refuse_if_required(
        &org_id,
        super::keykeeper_msp_policies::MEMBER_HEALTH,
        enabled,
        &conn,
    )
    .await?;
    let changed =
        set_org_member_health(&org_id, enabled, &headers.user.uuid, headers.device.atype, &headers.ip.ip, &conn)
            .await?;
    if changed && let Some(client) = MspClient::find_by_org(&org_id, &conn).await {
        let name = Organization::find_by_uuid(&org_id, &conn).await.map(|o| o.name).unwrap_or_default();
        Audit::by("client_member_health_set", &headers)
            .org(&org_id, &name)
            .detail(if enabled {
                "on"
            } else {
                "off"
            })
            .record(&client.msp_uuid, &conn)
            .await?;
    }
    Ok(Json(setting_view(&org_id, &conn).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use crate::db::{
        DbPool,
        models::{MspMembership, MspRole, MspStaff, TechnicianAccess, User},
    };

    #[test]
    fn a_report_is_whole_numbers_only() {
        let ok = own_counts(&json!({ "logins": 40, "weak": 3, "reused": 4, "exposed": 1 })).unwrap();
        assert_eq!((ok.logins, ok.weak, ok.reused, ok.exposed), (40, 3, 4, Some(1)));
        let unchecked = own_counts(&json!({ "logins": 2, "weak": 0, "reused": 2 })).unwrap();
        assert_eq!(unchecked.exposed, None);
        assert_eq!(own_counts(&json!({ "logins": 2, "weak": 0, "reused": 2, "exposed": null })).unwrap(), unchecked);
        for refused in [
            json!({ "logins": 2, "weak": 0 }),
            json!({ "logins": "2", "weak": 0, "reused": 0 }),
            json!({ "logins": 2.5, "weak": 0, "reused": 0 }),
            json!({ "logins": 2, "weak": 3, "reused": 0 }),
            json!({ "logins": 5_000_000_000_i64, "weak": 0, "reused": 0 }),
            json!({ "logins": 2, "weak": 0, "reused": 0, "exposed": "1" }),
            json!([2, 0, 0]),
        ] {
            assert!(own_counts(&refused).is_err(), "{refused}");
        }
    }

    async fn person(name: &str, conn: &DbConn) -> User {
        let mut user = User::new(&format!("{name}@example.test"), None);
        user.save(conn).await.unwrap();
        user
    }

    async fn join(
        user: &User,
        org: &Organization,
        atype: MembershipType,
        status: MembershipStatus,
        conn: &DbConn,
    ) -> Membership {
        let mut member = Membership::new(user.uuid.clone(), org.uuid.clone(), None);
        member.atype = atype as i32;
        member.status = status as i32;
        member.save(conn).await.unwrap();
        member
    }

    fn counts(logins: i32, weak: i32, reused: i32, exposed: Option<i32>) -> OwnCounts {
        OwnCounts {
            logins,
            weak,
            reused,
            exposed,
        }
    }

    #[rocket::async_test]
    async fn a_report_without_exposed_keeps_the_last_breach_check() {
        let conn = DbPool::for_test().await;
        let ana = person("ana", &conn).await;
        let checked = MemberHealth::report(&ana.uuid, counts(10, 2, 3, Some(1)), &conn).await.unwrap();
        assert_eq!(checked.exposed, Some(1));
        let checked_at = checked.exposed_checked_at.expect("when it was checked");

        let later = MemberHealth::report(&ana.uuid, counts(11, 1, 2, None), &conn).await.unwrap();
        assert_eq!((later.logins, later.weak, later.reused), (11, 1, 2));
        assert_eq!((later.exposed, later.exposed_checked_at), (Some(1), Some(checked_at)));

        let again = MemberHealth::report(&ana.uuid, counts(11, 1, 2, Some(0)), &conn).await.unwrap();
        assert_eq!(again.exposed, Some(0));
        let rows = MemberHealth::find_by_users(vec![ana.uuid.clone()], &conn).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].exposed, Some(0));
    }

    #[rocket::async_test]
    async fn an_msps_people_are_told_apart_from_the_clients_own() {
        let conn = DbPool::for_test().await;
        let org = Organization::new("Contoso".to_owned(), "billing@example.test", None, None);
        org.save(&conn).await.unwrap();
        let own =
            join(&person("own", &conn).await, &org, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        let tech =
            join(&person("tech", &conn).await, &org, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        let msp = Msp::new("Northwind IT".to_owned());
        msp.insert(&conn).await.unwrap();
        MspMembership::new(tech.uuid.clone(), msp.uuid.clone()).insert(&conn).await.unwrap();

        let from_msp = msp_memberships_among(vec![own.uuid.clone(), tech.uuid.clone()], &conn).await.unwrap();
        assert!(from_msp.contains(&tech.uuid));
        assert!(!from_msp.contains(&own.uuid));
    }

    async fn organization(name: &str, conn: &DbConn) -> Organization {
        let org = Organization::new(name.to_owned(), "billing@example.test", None, None);
        org.save(conn).await.unwrap();
        org
    }

    async fn turn(org: &Organization, on: bool, actor: &User, conn: &DbConn) -> bool {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        set_org_member_health(&org.uuid, on, &actor.uuid, 0, &ip, conn).await.unwrap()
    }

    async fn kept(user: &User, conn: &DbConn) -> bool {
        !MemberHealth::find_by_users(vec![user.uuid.clone()], conn).await.unwrap().is_empty()
    }

    #[rocket::async_test]
    async fn only_organizations_with_it_on_see_a_members_numbers_and_never_through_an_msp() {
        let conn = DbPool::for_test().await;
        let owner = person("owner", &conn).await;
        let ana = person("ana", &conn).await;
        let family = organization("Family", &conn).await;
        let contoso = organization("Contoso", &conn).await;
        join(&ana, &family, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        join(&ana, &contoso, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;

        // Made the upstream way: off, so nobody sees them.
        assert!(!OrgMemberHealth::enabled(&contoso.uuid, &conn).await.unwrap());
        assert!(MemberHealth::seen_by(&ana.uuid, &conn).await.unwrap().is_empty());
        assert!(turn(&contoso, true, &owner, &conn).await);
        // Saving what's already there isn't a change.
        assert!(!turn(&contoso, true, &owner, &conn).await);
        assert_eq!(MemberHealth::seen_by(&ana.uuid, &conn).await.unwrap(), vec![contoso.uuid.clone()]);

        // Invited, accepted, or revoked: not yet, or no longer, a member it sees.
        let ben = person("ben", &conn).await;
        for status in [MembershipStatus::Invited, MembershipStatus::Accepted, MembershipStatus::Revoked] {
            let mut member = join(&ben, &contoso, MembershipType::User, status, &conn).await;
            assert!(MemberHealth::seen_by(&ben.uuid, &conn).await.unwrap().is_empty());
            member.status = MembershipStatus::Confirmed as i32;
            member.save(&conn).await.unwrap();
            assert_eq!(MemberHealth::seen_by(&ben.uuid, &conn).await.unwrap(), vec![contoso.uuid.clone()]);
            member.delete(&conn).await.unwrap();
        }

        // An MSP's person in a client: the client never sees their numbers.
        let tech = person("tech", &conn).await;
        let through_msp = join(&tech, &contoso, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        let msp = Msp::new("Northwind IT".to_owned());
        msp.insert(&conn).await.unwrap();
        MspMembership::new(through_msp.uuid.clone(), msp.uuid.clone()).insert(&conn).await.unwrap();
        assert!(MemberHealth::seen_by(&tech.uuid, &conn).await.unwrap().is_empty());
    }

    #[rocket::async_test]
    async fn the_numbers_go_when_the_last_organization_that_sees_them_turns_it_off() {
        let conn = DbPool::for_test().await;
        let owner = person("owner", &conn).await;
        let ana = person("ana", &conn).await;
        let contoso = organization("Contoso", &conn).await;
        let fabrikam = organization("Fabrikam", &conn).await;
        for org in [&contoso, &fabrikam] {
            join(&ana, org, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
            turn(org, true, &owner, &conn).await;
        }
        MemberHealth::report(&ana.uuid, counts(4, 1, 2, None), &conn).await.unwrap();

        // Fabrikam still sees them.
        turn(&contoso, false, &owner, &conn).await;
        assert!(kept(&ana, &conn).await);
        turn(&fabrikam, false, &owner, &conn).await;
        assert!(!kept(&ana, &conn).await);
    }

    #[rocket::async_test]
    async fn the_numbers_go_when_the_member_leaves_or_is_revoked_from_the_last_one() {
        let conn = DbPool::for_test().await;
        let owner = person("owner", &conn).await;
        let ana = person("ana", &conn).await;
        let contoso = organization("Contoso", &conn).await;
        let fabrikam = organization("Fabrikam", &conn).await;
        turn(&contoso, true, &owner, &conn).await;
        turn(&fabrikam, true, &owner, &conn).await;
        let in_contoso = join(&ana, &contoso, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        let mut in_fabrikam = join(&ana, &fabrikam, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        MemberHealth::report(&ana.uuid, counts(4, 1, 2, None), &conn).await.unwrap();

        // Leaving one, or being removed, while another sees them keeps them.
        in_contoso.delete(&conn).await.unwrap();
        assert!(kept(&ana, &conn).await);
        // Revoked from the last one: gone.
        assert!(in_fabrikam.revoke());
        in_fabrikam.save(&conn).await.unwrap();
        assert!(!kept(&ana, &conn).await);

        // And deleting the last organization she's in deletes them too.
        let ben = person("ben", &conn).await;
        join(&ben, &contoso, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        MemberHealth::report(&ben.uuid, counts(2, 0, 0, None), &conn).await.unwrap();
        assert!(kept(&ben, &conn).await);
        contoso.delete(&conn).await.unwrap();
        assert!(!kept(&ben, &conn).await);
    }

    /// A client of the MSP, as keykeeper_offboarding's tests make one:
    /// MspClient::new seals an install token with the server's keys, which
    /// tests don't load.
    async fn msp_client(name: &str, msp: &Msp, conn: &DbConn) -> Organization {
        let org = organization(name, conn).await;
        MspClient {
            org_uuid: org.uuid.clone(),
            msp_uuid: msp.uuid.clone(),
            created_at: chrono::Utc::now().naive_utc(),
            preset: None,
            enrollment_token: None,
            enrollment_token_created_at: None,
            everyone_collection: None,
            templates_collection: None,
            enrollment_secret: None,
            enrollment_token_hash: None,
            client_seal: None,
            joined_with_code: false,
        }
        .insert(conn)
        .await
        .unwrap();
        org
    }

    /// Someone on an MSP's staff, reaching every client.
    async fn staff(name: &str, msp: &Msp, role: MspRole, conn: &DbConn) -> User {
        let user = person(name, conn).await;
        MspStaff::new(msp.uuid.clone(), user.uuid.clone(), role).insert(conn).await.unwrap();
        user
    }

    /// A membership the MSP made, as its people get in its clients.
    async fn through(
        msp: &Msp,
        user: &User,
        org: &Organization,
        atype: MembershipType,
        status: MembershipStatus,
        conn: &DbConn,
    ) -> Membership {
        let member = join(user, org, atype, status, conn).await;
        MspMembership::new(member.uuid.clone(), msp.uuid.clone()).insert(conn).await.unwrap();
        member
    }

    /// The clients whose members' numbers someone sees in the MSP console,
    /// or why not.
    async fn seen_in_console(msp: &Msp, user: &User, conn: &DbConn) -> Result<HashSet<OrganizationId>, String> {
        msp_clients_seen(&msp.uuid, &user.uuid, conn)
            .await
            .map(|orgs| orgs.into_iter().collect())
            .map_err(|e| e.message().to_owned())
    }

    fn set(orgs: &[&Organization]) -> Result<HashSet<OrganizationId>, String> {
        Ok(orgs.iter().map(|o| o.uuid.clone()).collect())
    }

    #[rocket::async_test]
    async fn only_the_msps_staff_who_manage_a_client_see_its_members_numbers_in_the_console() {
        let conn = DbPool::for_test().await;
        let northwind = Msp::new("Northwind IT".to_owned());
        northwind.insert(&conn).await.unwrap();
        let litware = Msp::new("Litware IT".to_owned());
        litware.insert(&conn).await.unwrap();
        let contoso = msp_client("Contoso", &northwind, &conn).await;
        let fabrikam = msp_client("Fabrikam", &northwind, &conn).await;
        let elsewhere = msp_client("Woodgrove", &litware, &conn).await;

        // An MSP admin, an owner of each client: both.
        let admin = staff("admin", &northwind, MspRole::Admin, &conn).await;
        for org in [&contoso, &fabrikam] {
            through(&northwind, &admin, org, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        }
        assert_eq!(seen_in_console(&northwind, &admin, &conn).await, set(&[&contoso, &fabrikam]));

        // A technician assigned only to Fabrikam: not Contoso, even as an
        // admin there that Contoso made itself.
        let tech = staff("tech", &northwind, MspRole::Technician, &conn).await;
        let mut record = MspStaff::find(&northwind.uuid, &tech.uuid, &conn).await.unwrap();
        let only_fabrikam = TechnicianAccess {
            all_clients: false,
            clients: vec![fabrikam.uuid.clone()],
            ..TechnicianAccess::default()
        };
        record.set_access(&only_fabrikam, &conn).await.unwrap();
        through(&northwind, &tech, &fabrikam, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        join(&tech, &contoso, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        assert_eq!(seen_in_console(&northwind, &tech, &conn).await, set(&[&fabrikam]));

        // Staff whose place in Contoso isn't an owner's or admin's, confirmed:
        // waiting for the key, a custom role, or revoked by the client.
        for (name, atype, status) in [
            ("waiting", MembershipType::Admin, MembershipStatus::Accepted),
            ("custom", MembershipType::User, MembershipStatus::Confirmed),
            ("revoked", MembershipType::Admin, MembershipStatus::Revoked),
        ] {
            let who = staff(name, &northwind, MspRole::Technician, &conn).await;
            through(&northwind, &who, &contoso, atype, status, &conn).await;
            assert_eq!(seen_in_console(&northwind, &who, &conn).await, set(&[]), "{name}");
        }
        // Nor a client they were never added to.
        let new_tech = staff("new", &northwind, MspRole::Technician, &conn).await;
        assert_eq!(seen_in_console(&northwind, &new_tech, &conn).await, set(&[]));

        // Another MSP's staff, even an owner of Contoso; Contoso's own admin;
        // and an MSP that doesn't exist: "not found", as the MSP's API answers.
        let other = staff("other", &litware, MspRole::Admin, &conn).await;
        join(&other, &contoso, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        through(&litware, &other, &elsewhere, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        assert_eq!(seen_in_console(&northwind, &other, &conn).await, Err("MSP not found".to_owned()));
        assert_eq!(seen_in_console(&litware, &other, &conn).await, set(&[&elsewhere]));
        let own_admin = person("own-admin", &conn).await;
        join(&own_admin, &contoso, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        assert_eq!(seen_in_console(&northwind, &own_admin, &conn).await, Err("MSP not found".to_owned()));
        let nowhere = Msp::new("Nowhere".to_owned());
        assert_eq!(seen_in_console(&nowhere, &admin, &conn).await, Err("MSP not found".to_owned()));
    }

    #[rocket::async_test]
    async fn the_console_shows_a_clients_own_members_numbers_only_while_it_has_it_on() {
        let conn = DbPool::for_test().await;
        let northwind = Msp::new("Northwind IT".to_owned());
        northwind.insert(&conn).await.unwrap();
        let contoso = msp_client("Contoso", &northwind, &conn).await;
        let admin = staff("admin", &northwind, MspRole::Admin, &conn).await;
        through(&northwind, &admin, &contoso, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        let tech = staff("tech", &northwind, MspRole::Technician, &conn).await;
        through(&northwind, &tech, &contoso, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        let ana = person("ana", &conn).await;
        let anas = join(&ana, &contoso, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        let ben = person("ben", &conn).await;
        let bens = join(&ben, &contoso, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        let invited = person("invited", &conn).await;
        join(&invited, &contoso, MembershipType::User, MembershipStatus::Invited, &conn).await;

        // Off (a client added without the defaults): it says so, and lists nobody.
        let off = msp_client_view(&contoso.uuid, &conn).await.unwrap();
        assert_eq!(off, json!({ "organizationId": contoso.uuid, "on": false, "members": [] }));

        turn(&contoso, true, &admin, &conn).await;
        MemberHealth::report(&ana.uuid, counts(4, 1, 2, Some(1)), &conn).await.unwrap();
        // The MSP's own people have numbers too, which the console never counts as the client's.
        for who in [&admin, &tech] {
            MemberHealth::report(&who.uuid, counts(9, 9, 9, Some(9)), &conn).await.unwrap();
        }
        let on = msp_client_view(&contoso.uuid, &conn).await.unwrap();
        assert_eq!(on["on"], true);
        let rows = on["members"].as_array().unwrap();
        let ids: HashSet<&str> = rows.iter().map(|r| r["memberId"].as_str().unwrap()).collect();
        assert_eq!(ids, HashSet::from([anas.uuid.as_str(), bens.uuid.as_str()]));
        let anas_row = rows.iter().find(|r| r["memberId"] == json!(anas.uuid)).unwrap();
        assert_eq!(
            (&anas_row["logins"], &anas_row["weak"], &anas_row["reused"], &anas_row["exposed"]),
            (&json!(4), &json!(1), &json!(2), &json!(1))
        );
        let bens_row = rows.iter().find(|r| r["memberId"] == json!(bens.uuid)).unwrap();
        assert!(bens_row["reportedAt"].is_null() && bens_row["logins"].is_null(), "{bens_row}");
        // Numbers and when, by membership id: nothing that names an item or a person.
        for row in rows {
            let mut keys: Vec<&str> = row.as_object().unwrap().keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                ["exposed", "exposedCheckedAt", "logins", "memberId", "reportedAt", "reused", "weak"],
                "{row}"
            );
        }

        // Off again: nobody's numbers, though Ana's stay for another
        // organization that still sees them.
        let fabrikam = organization("Fabrikam", &conn).await;
        join(&ana, &fabrikam, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        turn(&fabrikam, true, &ana, &conn).await;
        turn(&contoso, false, &admin, &conn).await;
        assert!(kept(&ana, &conn).await);
        let off = msp_client_view(&contoso.uuid, &conn).await.unwrap();
        assert_eq!(off, json!({ "organizationId": contoso.uuid, "on": false, "members": [] }));
    }
}

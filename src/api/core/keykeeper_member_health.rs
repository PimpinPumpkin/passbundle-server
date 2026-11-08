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
            EventType, MemberHealth, Membership, MembershipStatus, MembershipType, Msp, MspClient, OrgMemberHealth,
            Organization, OrganizationId, OwnCounts, UserId, msp_memberships_among,
        },
    },
    util::format_date,
};

pub fn routes() -> Vec<Route> {
    routes![put_own_health, own_health_seen_by, member_health, get_setting, put_setting]
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

/// Whether the caller is a confirmed owner or admin.
async fn owner_or_admin(org_id: &OrganizationId, headers: &Headers, conn: &DbConn) -> bool {
    Membership::find_by_user_and_org(&headers.user.uuid, org_id, conn).await.is_some_and(|m| {
        m.status == MembershipStatus::Confirmed as i32
            && (m.atype == MembershipType::Owner as i32 || m.atype == MembershipType::Admin as i32)
    })
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
    if !owner_or_admin(&org_id, &headers, &conn).await {
        err_code!("Organization not found", Status::NotFound.code)
    }
    if !OrgMemberHealth::enabled(&org_id, &conn).await? {
        return Ok(Json(json!({ "object": "list", "data": [], "on": false, "continuationToken": null })));
    }
    let confirmed = Membership::find_confirmed_by_org(&org_id, &conn).await;
    let from_msp = msp_memberships_among(confirmed.iter().map(|m| m.uuid.clone()).collect(), &conn).await?;
    let members: Vec<Membership> = confirmed.into_iter().filter(|m| !from_msp.contains(&m.uuid)).collect();
    let reported: HashMap<_, _> =
        MemberHealth::find_by_users(members.iter().map(|m| m.user_uuid.clone()).collect(), &conn)
            .await?
            .into_iter()
            .map(|row| (row.user_uuid.clone(), row))
            .collect();
    let data: Vec<Value> = members
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
        .collect();
    Ok(Json(json!({ "object": "list", "data": data, "on": true, "continuationToken": null })))
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
    use crate::db::{
        DbPool,
        models::{MspMembership, User},
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
}

// Keykeeper: an organization's owners and admins see how healthy their
// people's own passwords are, without seeing them. Each member's apps count
// the logins in the member's Personal items and send four numbers (how many,
// weak, reused, exposed); the admin console's Reports lists them per member.
// Never which items. See DESIGN.md, "Members' own passwords".

use std::collections::HashMap;

use rocket::{Route, serde::json::Json};
use serde_json::{Value, json};

use crate::{
    api::JsonResult,
    auth::Headers,
    db::{
        DbConn,
        models::{
            MemberHealth, Membership, MembershipStatus, MembershipType, OrganizationId, OwnCounts,
            msp_memberships_among,
        },
    },
    util::format_date,
};

pub fn routes() -> Vec<Route> {
    routes![put_own_health, member_health]
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

/// A member's apps report how many of their own logins are weak, reused,
/// and exposed. Only the numbers are kept.
#[put("/keykeeper/own-health", data = "<data>")]
async fn put_own_health(data: Json<Value>, headers: Headers, conn: DbConn) -> JsonResult {
    let counts = match own_counts(&data) {
        Ok(counts) => counts,
        Err(why) => err!(why),
    };
    let saved = MemberHealth::report(&headers.user.uuid, counts, &conn).await?;
    let mut view = numbers(&saved);
    view["object"] = json!("keykeeperOwnHealth");
    Ok(Json(view))
}

/// The caller's membership, if they're a confirmed owner or admin.
async fn owner_or_admin(org_id: &OrganizationId, headers: &Headers, conn: &DbConn) -> bool {
    Membership::find_by_user_and_org(&headers.user.uuid, org_id, conn).await.is_some_and(|m| {
        m.status == MembershipStatus::Confirmed as i32
            && (m.atype == MembershipType::Owner as i32 || m.atype == MembershipType::Admin as i32)
    })
}

/// For an organization's owners and admins: each confirmed member's numbers,
/// by membership id, or none reported yet. An MSP's people in a client are
/// left out. Anyone else gets "not found", whether the organization exists
/// or not: upstream's web vault signs out on 403.
#[get("/keykeeper/organizations/<org_id>/member-health")]
async fn member_health(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    if !owner_or_admin(&org_id, &headers, &conn).await {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
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
    Ok(Json(json!({ "object": "list", "data": data, "continuationToken": null })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        DbPool,
        models::{MspMembership, Organization, User},
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
        let msp = crate::db::models::Msp::new("Northwind IT".to_owned());
        msp.insert(&conn).await.unwrap();
        MspMembership::new(tech.uuid.clone(), msp.uuid.clone()).insert(&conn).await.unwrap();

        let from_msp = msp_memberships_among(vec![own.uuid.clone(), tech.uuid.clone()], &conn).await.unwrap();
        assert!(from_msp.contains(&tech.uuid));
        assert!(!from_msp.contains(&own.uuid));
    }
}

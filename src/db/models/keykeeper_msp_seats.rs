// Keykeeper: seats by client. The server bills nothing itself; it records,
// once a day, how many seats each of an MSP's clients has, so the MSP can
// bill each client for its own. A seat is a member of the client who has
// joined (accepted or confirmed), isn't revoked, and isn't one of the MSP's
// staff. Each row copies the client's name, and nothing refers to the
// organization, so a month stays readable after a client leaves, is renamed,
// or is deleted. See DESIGN.md, "Seats by client", in the meta repo.

use std::collections::HashSet;

use diesel::prelude::*;

use crate::{
    api::{ApiResult, EmptyResult},
    db::{
        DbConn,
        keykeeper_schema::{msp_client_seats, msp_clients, msp_staff, msps},
        schema::{organizations, users_organizations},
    },
    error::MapResult,
};

use super::{MembershipId, MembershipStatus, MspId, MspRole, OrganizationId, UserId};

/// One client's seats on one day (UTC, `YYYY-MM-DD`), with its name then.
#[derive(Clone, Debug, PartialEq, Eq, Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_client_seats)]
#[diesel(primary_key(msp_uuid, org_uuid, day))]
pub struct ClientSeats {
    pub msp_uuid: MspId,
    pub org_uuid: OrganizationId,
    pub day: String,
    pub seats: i32,
    pub org_name: String,
}

impl ClientSeats {
    /// Records a day's readings, each replacing that client's earlier reading
    /// of the same day, so a day keeps its last reading. A client that left
    /// since an earlier reading that day keeps that one.
    pub async fn record(rows: Vec<Self>, conn: &DbConn) -> EmptyResult {
        if rows.is_empty() {
            return Ok(());
        }
        conn.run(move |conn| {
            conn.transaction(|conn| {
                for row in &rows {
                    diesel::delete(
                        msp_client_seats::table
                            .filter(msp_client_seats::msp_uuid.eq(&row.msp_uuid))
                            .filter(msp_client_seats::org_uuid.eq(&row.org_uuid))
                            .filter(msp_client_seats::day.eq(&row.day)),
                    )
                    .execute(conn)?;
                    diesel::insert_into(msp_client_seats::table).values(row).execute(conn)?;
                }
                Ok::<(), diesel::result::Error>(())
            })
            .map_res("Error recording clients' seats")
        })
        .await
    }

    /// An MSP's readings from `from` up to, not including, `until` (both days).
    pub async fn find_between(msp_uuid: &MspId, from: &str, until: &str, conn: &DbConn) -> ApiResult<Vec<Self>> {
        let (from, until) = (from.to_owned(), until.to_owned());
        conn.run(move |conn| {
            msp_client_seats::table
                .filter(msp_client_seats::msp_uuid.eq(msp_uuid))
                .filter(msp_client_seats::day.ge(from))
                .filter(msp_client_seats::day.lt(until))
                .order((msp_client_seats::day.asc(), msp_client_seats::org_uuid.asc()))
                .load::<Self>(conn)
                .map_res("Error loading clients' seats")
        })
        .await
    }

    /// The days the server recorded an MSP's clients.
    pub async fn days(msp_uuid: &MspId, conn: &DbConn) -> ApiResult<Vec<String>> {
        conn.run(move |conn| {
            msp_client_seats::table
                .filter(msp_client_seats::msp_uuid.eq(msp_uuid))
                .select(msp_client_seats::day)
                .distinct()
                .load::<String>(conn)
                .map_res("Error loading the days clients' seats were recorded")
        })
        .await
    }
}

/// Every MSP, for the daily reading.
pub async fn all_msps(conn: &DbConn) -> ApiResult<Vec<MspId>> {
    conn.run(move |conn| msps::table.select(msps::uuid).load::<MspId>(conn).map_res("Error loading MSPs")).await
}

/// An MSP's clients now, with their names, by name.
pub async fn clients_now(msp_uuid: &MspId, conn: &DbConn) -> ApiResult<Vec<(OrganizationId, String)>> {
    conn.run(move |conn| {
        let ids = msp_clients::table
            .filter(msp_clients::msp_uuid.eq(msp_uuid))
            .select(msp_clients::org_uuid)
            .load::<OrganizationId>(conn)
            .map_res("Error loading an MSP's clients")?;
        organizations::table
            .filter(organizations::uuid.eq_any(ids))
            .select((organizations::uuid, organizations::name))
            .order(organizations::name.asc())
            .load::<(OrganizationId, String)>(conn)
            .map_res("Error loading an MSP's clients")
    })
    .await
}

/// The people on an MSP's staff now: its admins and technicians.
pub async fn staff_users(msp_uuid: &MspId, conn: &DbConn) -> ApiResult<HashSet<UserId>> {
    let roles = [MspRole::Admin as i32, MspRole::Technician as i32];
    conn.run(move |conn| {
        msp_staff::table
            .filter(msp_staff::msp_uuid.eq(msp_uuid))
            .filter(msp_staff::role.eq_any(roles))
            .select(msp_staff::user_uuid)
            .load::<UserId>(conn)
            .map(|ids| ids.into_iter().collect())
            .map_res("Error loading an MSP's staff")
    })
    .await
}

/// A client's members who have joined: accepted or confirmed. Invited
/// memberships haven't, and revoked ones keep a negative status
/// (`Membership::revoke`), so neither is here.
pub async fn joined_members(org_uuid: &OrganizationId, conn: &DbConn) -> ApiResult<Vec<(MembershipId, UserId)>> {
    let joined = [MembershipStatus::Accepted as i32, MembershipStatus::Confirmed as i32];
    conn.run(move |conn| {
        users_organizations::table
            .filter(users_organizations::org_uuid.eq(org_uuid))
            .filter(users_organizations::status.eq_any(joined))
            .select((users_organizations::uuid, users_organizations::user_uuid))
            .load::<(MembershipId, UserId)>(conn)
            .map_res("Error loading a client's members")
    })
    .await
}

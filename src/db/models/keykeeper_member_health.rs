// Keykeeper: how healthy each person's own passwords are, in numbers only. A
// member's apps count the logins in their Personal items (how many, how many
// weak, reused, and exposed) and send just those numbers; the owners and
// admins of their organizations that have "Members' own passwords" on see
// them, never which items. Counts aren't vault contents, so they're kept as
// they are, and only while such an organization sees them. See DESIGN.md,
// "Members' own passwords".

use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;

use std::collections::HashSet;

use crate::{
    api::{ApiResult, EmptyResult},
    db::{
        DbConn,
        keykeeper_schema::{keykeeper_member_health, msp_memberships, org_member_health},
    },
    error::MapResult,
};

use super::{Membership, MembershipId, OrganizationId, UserId};

/// The most logins a report may count: more than any vault holds.
pub const MAX_LOGINS: i32 = 100_000;

/// What a member's app reports about their own logins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnCounts {
    pub logins: i32,
    pub weak: i32,
    pub reused: i32,
    /// Only when every login was checked against known breaches.
    pub exposed: Option<i32>,
}

impl OwnCounts {
    /// Whole numbers, `logins` at most `MAX_LOGINS` and the others at most
    /// `logins`; otherwise why not, in plain words.
    pub fn check(&self) -> Result<(), &'static str> {
        if !(0..=MAX_LOGINS).contains(&self.logins) {
            return Err("The number of logins must be a whole number from 0 to 100,000");
        }
        let within = |n: i32| (0..=self.logins).contains(&n);
        if !within(self.weak) || !within(self.reused) || !self.exposed.is_none_or(within) {
            return Err("Weak, reused, and exposed are whole numbers no larger than the number of logins");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Identifiable, Queryable, Insertable)]
#[diesel(table_name = keykeeper_member_health)]
#[diesel(primary_key(user_uuid))]
pub struct MemberHealth {
    pub user_uuid: UserId,
    pub logins: i32,
    pub weak: i32,
    pub reused: i32,
    pub exposed: Option<i32>,
    pub exposed_checked_at: Option<NaiveDateTime>,
    pub reported_at: NaiveDateTime,
}

impl MemberHealth {
    /// The numbers last reported for these people, by account; anyone who
    /// hasn't reported is left out.
    pub async fn find_by_users(users: Vec<UserId>, conn: &DbConn) -> Result<Vec<Self>, crate::error::Error> {
        conn.run(move |conn| {
            keykeeper_member_health::table
                .filter(keykeeper_member_health::user_uuid.eq_any(users))
                .load::<Self>(conn)
                .map_res("Error reading members' numbers")
        })
        .await
    }

    /// Replaces someone's numbers with a new report, already checked. A
    /// report without `exposed` keeps the last exposed count and when it was
    /// checked, so an app that doesn't check breaches doesn't erase what one
    /// that does found. It writes before it reads, so two of the person's
    /// apps reporting at once never wait on each other's read (SQLite), and
    /// the second of two first reports updates the row the first made.
    pub async fn report(user: &UserId, counts: OwnCounts, conn: &DbConn) -> Result<Self, crate::error::Error> {
        let user = user.clone();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            let save = |conn: &mut crate::db::DbConnInner| {
                conn.transaction(|conn| {
                    let mine = || keykeeper_member_health::table.filter(keykeeper_member_health::user_uuid.eq(&user));
                    let updated = match counts.exposed {
                        Some(exposed) => diesel::update(mine())
                            .set((
                                keykeeper_member_health::logins.eq(counts.logins),
                                keykeeper_member_health::weak.eq(counts.weak),
                                keykeeper_member_health::reused.eq(counts.reused),
                                keykeeper_member_health::exposed.eq(Some(exposed)),
                                keykeeper_member_health::exposed_checked_at.eq(Some(now)),
                                keykeeper_member_health::reported_at.eq(now),
                            ))
                            .execute(conn)?,
                        // The last breach check stays as it was.
                        None => diesel::update(mine())
                            .set((
                                keykeeper_member_health::logins.eq(counts.logins),
                                keykeeper_member_health::weak.eq(counts.weak),
                                keykeeper_member_health::reused.eq(counts.reused),
                                keykeeper_member_health::reported_at.eq(now),
                            ))
                            .execute(conn)?,
                    };
                    if updated == 0 {
                        let row = Self {
                            user_uuid: user.clone(),
                            logins: counts.logins,
                            weak: counts.weak,
                            reused: counts.reused,
                            exposed: counts.exposed,
                            exposed_checked_at: counts.exposed.map(|_| now),
                            reported_at: now,
                        };
                        diesel::insert_into(keykeeper_member_health::table).values(&row).execute(conn)?;
                    }
                    mine().first::<Self>(conn)
                })
            };
            match save(conn) {
                // Another of the person's apps made the row first: update it.
                Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _)) => {
                    save(conn)
                }
                other => other,
            }
            .map_res("Error saving your numbers")
        })
        .await
    }

    /// The organizations whose owners and admins see this person's numbers:
    /// those they're a confirmed member of, not through an MSP (a client sees
    /// nothing about its MSP's people), that have "Members' own passwords"
    /// on. Their apps send the numbers only while there's one, and the server
    /// keeps them only then.
    pub async fn seen_by(user: &UserId, conn: &DbConn) -> ApiResult<Vec<OrganizationId>> {
        let confirmed = Membership::find_confirmed_by_user(user, conn).await;
        let from_msp = msp_memberships_among(confirmed.iter().map(|m| m.uuid.clone()).collect(), conn).await?;
        let orgs = confirmed.into_iter().filter(|m| !from_msp.contains(&m.uuid)).map(|m| m.org_uuid).collect();
        OrgMemberHealth::enabled_among(orgs, conn).await
    }

    /// Deletes someone's numbers.
    pub async fn delete_for_user(user: &UserId, conn: &DbConn) -> EmptyResult {
        let user = user.clone();
        conn.run(move |conn| {
            diesel::delete(keykeeper_member_health::table.filter(keykeeper_member_health::user_uuid.eq(user)))
                .execute(conn)
                .map(|_| ())
                .map_res("Error deleting your numbers")
        })
        .await
    }

    /// Deletes someone's numbers once no organization sees them: when the
    /// last one that has it on turns it off, or they leave it, are removed,
    /// or are revoked there. True when they were deleted, or there were none.
    pub async fn forget_unless_seen(user: &UserId, conn: &DbConn) -> ApiResult<bool> {
        if !Self::seen_by(user, conn).await?.is_empty() {
            return Ok(false);
        }
        Self::delete_for_user(user, conn).await?;
        Ok(true)
    }
}

/// An organization's "Members' own passwords": whether its owners and admins
/// see how many of its members' own passwords are weak, reused, or exposed.
/// Without a row they don't, so an organization made the upstream way (a
/// family or a group) has it off; the Business preset and an MSP's default
/// policies turn it on.
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = org_member_health)]
#[diesel(primary_key(org_uuid))]
pub struct OrgMemberHealth {
    pub org_uuid: OrganizationId,
    pub enabled: bool,
}

impl OrgMemberHealth {
    /// Whether the organization has it on. Without a row, it doesn't.
    pub async fn enabled(org_uuid: &OrganizationId, conn: &DbConn) -> ApiResult<bool> {
        Ok(!Self::enabled_among(vec![org_uuid.clone()], conn).await?.is_empty())
    }

    /// Which of these organizations have it on.
    pub async fn enabled_among(orgs: Vec<OrganizationId>, conn: &DbConn) -> ApiResult<Vec<OrganizationId>> {
        if orgs.is_empty() {
            return Ok(Vec::new());
        }
        conn.run(move |conn| {
            org_member_health::table
                .filter(org_member_health::org_uuid.eq_any(orgs))
                .filter(org_member_health::enabled.eq(true))
                .select(org_member_health::org_uuid)
                .load::<OrganizationId>(conn)
                .map_res("Error reading organizations' Members' own passwords setting")
        })
        .await
    }

    pub async fn set(org_uuid: &OrganizationId, enabled: bool, conn: &DbConn) -> EmptyResult {
        let row = Self {
            org_uuid: org_uuid.clone(),
            enabled,
        };
        conn.run(move |conn| {
            conn.transaction(|conn| {
                diesel::delete(org_member_health::table.filter(org_member_health::org_uuid.eq(&row.org_uuid)))
                    .execute(conn)?;
                diesel::insert_into(org_member_health::table).values(&row).execute(conn)
            })
            .map(|_| ())
            .map_res("Error saving an organization's Members' own passwords setting")
        })
        .await
    }
}

/// Which of these memberships came from an MSP. A database error is an
/// error, not "none": the admin view must never show an MSP's people to a
/// client by mistake.
pub async fn msp_memberships_among(
    members: Vec<MembershipId>,
    conn: &DbConn,
) -> Result<HashSet<MembershipId>, crate::error::Error> {
    conn.run(move |conn| {
        msp_memberships::table
            .filter(msp_memberships::membership_uuid.eq_any(members))
            .select(msp_memberships::membership_uuid)
            .load::<MembershipId>(conn)
            .map(|ids| ids.into_iter().collect())
            .map_res("Error reading MSP memberships")
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(logins: i32, weak: i32, reused: i32, exposed: Option<i32>) -> OwnCounts {
        OwnCounts {
            logins,
            weak,
            reused,
            exposed,
        }
    }

    #[test]
    fn numbers_are_whole_and_never_more_than_the_logins() {
        assert!(counts(0, 0, 0, None).check().is_ok());
        assert!(counts(40, 3, 4, Some(1)).check().is_ok());
        assert!(counts(40, 40, 40, Some(40)).check().is_ok());
        assert!(counts(MAX_LOGINS, 0, 0, None).check().is_ok());
        for refused in [
            counts(-1, 0, 0, None),
            counts(MAX_LOGINS + 1, 0, 0, None),
            counts(3, 4, 0, None),
            counts(3, 0, 4, None),
            counts(3, 0, 0, Some(4)),
            counts(3, -1, 0, None),
            counts(3, 0, -1, None),
            counts(3, 0, 0, Some(-1)),
        ] {
            assert!(refused.check().is_err(), "{refused:?}");
        }
    }
}

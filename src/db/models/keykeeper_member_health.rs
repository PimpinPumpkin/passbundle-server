// Keykeeper: how healthy each person's own passwords are, in numbers only. A
// member's apps count the logins in their Personal items (how many, how many
// weak, reused, and exposed) and send just those numbers; their
// organizations' owners and admins see them, never which items. Counts
// aren't vault contents, so they're kept as they are. See DESIGN.md,
// "Members' own passwords".

use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;

use std::collections::HashSet;

use crate::{
    db::{
        DbConn,
        keykeeper_schema::{keykeeper_member_health, msp_memberships},
    },
    error::MapResult,
};

use super::{MembershipId, UserId};

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
    /// that does found.
    pub async fn report(user: &UserId, counts: OwnCounts, conn: &DbConn) -> Result<Self, crate::error::Error> {
        let user = user.clone();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            conn.transaction(|conn| {
                let before = keykeeper_member_health::table
                    .filter(keykeeper_member_health::user_uuid.eq(&user))
                    .first::<Self>(conn)
                    .optional()?;
                let (exposed, exposed_checked_at) = match counts.exposed {
                    Some(exposed) => (Some(exposed), Some(now)),
                    None => before.as_ref().map_or((None, None), |b| (b.exposed, b.exposed_checked_at)),
                };
                let row = Self {
                    user_uuid: user.clone(),
                    logins: counts.logins,
                    weak: counts.weak,
                    reused: counts.reused,
                    exposed,
                    exposed_checked_at,
                    reported_at: now,
                };
                if before.is_some() {
                    diesel::update(keykeeper_member_health::table.filter(keykeeper_member_health::user_uuid.eq(&user)))
                        .set((
                            keykeeper_member_health::logins.eq(row.logins),
                            keykeeper_member_health::weak.eq(row.weak),
                            keykeeper_member_health::reused.eq(row.reused),
                            keykeeper_member_health::exposed.eq(row.exposed),
                            keykeeper_member_health::exposed_checked_at.eq(row.exposed_checked_at),
                            keykeeper_member_health::reported_at.eq(row.reported_at),
                        ))
                        .execute(conn)?;
                } else {
                    diesel::insert_into(keykeeper_member_health::table).values(&row).execute(conn)?;
                }
                Ok::<_, diesel::result::Error>(row)
            })
            .map_res("Error saving your numbers")
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

// Keykeeper: a family's people limit (DESIGN.md, "Plans and billing", "What
// the server refuses", in the meta repo). A Families plan covers so many
// people (PLAN_FAMILIES_PEOPLE), and the server counts them instead of
// trusting the clients' seat count: everyone invited or joined who isn't
// revoked, the owner included. Revoked people don't count, except someone an
// owner or admin restored whose restore waits for them to accept their role
// (RevokedUntilAccepted, two-step login for admins): their place was given
// back when the restore was asked for, and accepting it later adds nobody.
//
// The count and the write that adds or restores someone are one transaction
// that holds a write lock (SQLite's immediate transaction, or PostgreSQL's
// lock on the organization's row), so invitations sent at once can't both
// take the last place. Whether an organization has a limit, and what it is,
// is the one function's answer (`PlanNow::people_limit`); this only counts
// and writes.

use diesel::prelude::*;

use crate::{
    api::ApiResult,
    db::{DbConn, keykeeper_schema::revoked_until_accepted, schema::users_organizations},
    error::MapResult,
};

use super::{Membership, MembershipStatus, OrganizationId, User};

/// The statuses that hold a place: invited, accepted, and confirmed.
const COUNTED: [i32; 3] =
    [MembershipStatus::Invited as i32, MembershipStatus::Accepted as i32, MembershipStatus::Confirmed as i32];

/// What became of a way in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Within {
    /// Saved: there was room.
    Saved,
    /// Nothing written: the family is full. `has` is how many people it has
    /// now, for the sentence.
    Full {
        has: i64,
    },
}

/// Whether a row of `users_organizations` holds a place: counted, or held
/// until its person accepts their role (`$held`, the memberships held).
macro_rules! holds_a_place {
    ($held:expr) => {
        users_organizations::status.eq_any(COUNTED).or(users_organizations::uuid.eq_any($held))
    };
}

/// The memberships held until their people accept their roles, anywhere: a
/// few rows at most.
macro_rules! held {
    ($conn:ident) => {
        revoked_until_accepted::table.select(revoked_until_accepted::membership_uuid).load::<String>($conn)
    };
}

/// Everyone the limit counts in `$org`, on a connection of either database.
macro_rules! everyone {
    ($conn:ident, $org:expr, $held:expr) => {
        users_organizations::table
            .filter(users_organizations::org_uuid.eq($org))
            .filter(holds_a_place!($held))
            .count()
            .get_result::<i64>($conn)
    };
}

impl Membership {
    /// How many people a family's limit counts in `org` now. A look without
    /// a lock, for a refusal before anything is written; `save_within` is
    /// what holds.
    pub async fn people_counted(org: &OrganizationId, conn: &DbConn) -> ApiResult<i64> {
        let counted: Result<i64, diesel::result::Error> = db_run! { conn:
            sqlite, postgresql {
                held!(conn).and_then(|held| everyone!(conn, org, &held))
            }
        };
        counted.map_res("Error counting a family's people")
    }

    /// `save`, on a way into an organization whose plan covers `limit`
    /// people: the membership is written only if, with it, the people the
    /// limit counts are no more than `limit`. The count and the write are one
    /// transaction that holds a write lock, so two requests at once can't
    /// both get under it.
    pub async fn save_within(&self, limit: i64, conn: &DbConn) -> ApiResult<Within> {
        let counts_after = COUNTED.contains(&self.status);
        // The same count and write for either database.
        macro_rules! count_and_save {
            ($conn:ident) => {{
                let held = held!($conn)?;
                let everyone = everyone!($conn, &self.org_uuid, &held)?;
                let this_one = users_organizations::table
                    .filter(users_organizations::uuid.eq(&self.uuid))
                    .filter(users_organizations::org_uuid.eq(&self.org_uuid))
                    .filter(holds_a_place!(&held))
                    .count()
                    .get_result::<i64>($conn)?;
                let others = everyone - this_one;
                if counts_after && others.saturating_add(1) > limit {
                    Ok(Within::Full {
                        has: everyone,
                    })
                } else {
                    diesel::insert_into(users_organizations::table)
                        .values(self)
                        .on_conflict(users_organizations::uuid)
                        .do_update()
                        .set(self)
                        .execute($conn)?;
                    Ok(Within::Saved)
                }
            }};
        }
        let within: Result<Within, diesel::result::Error> = db_run! { conn:
            sqlite {
                conn.immediate_transaction(|conn| count_and_save!(conn))
            }
            postgresql {
                conn.transaction(|conn| {
                    use crate::db::schema::organizations;
                    organizations::table
                        .filter(organizations::uuid.eq(&self.org_uuid))
                        .select(organizations::uuid)
                        .for_update()
                        .first::<OrganizationId>(conn)?;
                    count_and_save!(conn)
                })
            }
        };
        let within = within.map_res("Error adding a person to a family")?;
        if within == Within::Saved {
            User::update_uuid_revision(&self.user_uuid, conn).await;
        }
        Ok(within)
    }
}

#[cfg(all(test, sqlite))]
mod tests {
    use super::*;
    use crate::db::{
        DbPool,
        models::{MembershipType, Organization, RevokedUntilAccepted},
    };

    async fn person(name: &str, conn: &DbConn) -> User {
        let mut user = User::new(&format!("{name}@example.test"), None);
        user.save(conn).await.unwrap();
        user
    }

    async fn family(conn: &DbConn) -> Organization {
        let org = Organization::new("Rivera family".to_owned(), "owner@example.test", None, None);
        org.save(conn).await.unwrap();
        org
    }

    fn membership(user: &User, org: &Organization, status: MembershipStatus) -> Membership {
        let mut member = Membership::new(user.uuid.clone(), org.uuid.clone(), None);
        member.status = status as i32;
        member
    }

    /// Someone in the family in `status`, written as `save` writes, past any limit.
    async fn already(name: &str, org: &Organization, status: MembershipStatus, conn: &DbConn) -> Membership {
        let member = membership(&person(name, conn).await, org, status);
        member.save(conn).await.unwrap();
        member
    }

    async fn count(org: &Organization, conn: &DbConn) -> i64 {
        Membership::people_counted(&org.uuid, conn).await.unwrap()
    }

    #[rocket::async_test]
    async fn the_owner_and_pending_invitations_count_and_revoked_people_dont() {
        let conn = DbPool::for_test().await;
        let org = family(&conn).await;
        assert_eq!(count(&org, &conn).await, 0);

        let mut owner = already("owner", &org, MembershipStatus::Confirmed, &conn).await;
        owner.atype = MembershipType::Owner as i32;
        owner.save(&conn).await.unwrap();
        assert_eq!(count(&org, &conn).await, 1);

        already("invited", &org, MembershipStatus::Invited, &conn).await;
        already("accepted", &org, MembershipStatus::Accepted, &conn).await;
        already("confirmed", &org, MembershipStatus::Confirmed, &conn).await;
        assert_eq!(count(&org, &conn).await, 4);

        // Revoked from each status: none of them counts.
        for (name, status) in [
            ("was-invited", MembershipStatus::Invited),
            ("was-accepted", MembershipStatus::Accepted),
            ("was-confirmed", MembershipStatus::Confirmed),
        ] {
            let mut member = already(name, &org, status, &conn).await;
            assert!(member.revoke());
            member.save(&conn).await.unwrap();
        }
        assert_eq!(count(&org, &conn).await, 4);

        // Except one whose restore waits for them to accept their role.
        let mut held = already("held", &org, MembershipStatus::Confirmed, &conn).await;
        assert!(held.revoke());
        held.save(&conn).await.unwrap();
        assert_eq!(count(&org, &conn).await, 4);
        RevokedUntilAccepted::hold(&held.uuid, &conn).await.unwrap();
        assert_eq!(count(&org, &conn).await, 5);

        // Another organization's people are its own.
        let other = family(&conn).await;
        already("elsewhere", &other, MembershipStatus::Confirmed, &conn).await;
        assert_eq!(count(&org, &conn).await, 5);
        assert_eq!(count(&other, &conn).await, 1);
    }

    #[rocket::async_test]
    async fn an_invitation_takes_the_last_place_and_the_next_one_is_refused() {
        let conn = DbPool::for_test().await;
        let org = family(&conn).await;
        for n in 1..=5 {
            already(&format!("member{n}"), &org, MembershipStatus::Confirmed, &conn).await;
        }

        let sixth = membership(&person("sixth", &conn).await, &org, MembershipStatus::Invited);
        assert_eq!(sixth.save_within(6, &conn).await.unwrap(), Within::Saved);
        assert_eq!(count(&org, &conn).await, 6);

        let seventh = membership(&person("seventh", &conn).await, &org, MembershipStatus::Invited);
        assert_eq!(
            seventh.save_within(6, &conn).await.unwrap(),
            Within::Full {
                has: 6
            }
        );
        assert!(Membership::find_by_uuid(&seventh.uuid, &conn).await.is_none(), "nothing was written");
        assert_eq!(count(&org, &conn).await, 6);

        // Someone already counted changes status without taking a second place.
        let mut accepted = sixth;
        accepted.status = MembershipStatus::Accepted as i32;
        assert_eq!(accepted.save_within(6, &conn).await.unwrap(), Within::Saved);
        assert_eq!(count(&org, &conn).await, 6);

        // A lower limit than the family has: nobody new, and nobody counted
        // gets further either.
        accepted.status = MembershipStatus::Confirmed as i32;
        assert_eq!(
            accepted.save_within(5, &conn).await.unwrap(),
            Within::Full {
                has: 6
            }
        );
        let stored = Membership::find_by_uuid(&accepted.uuid, &conn).await.unwrap();
        assert_eq!(stored.status, MembershipStatus::Accepted as i32, "left as it was");
    }

    #[rocket::async_test]
    async fn restoring_someone_needs_a_place_and_revoking_frees_one() {
        let conn = DbPool::for_test().await;
        let org = family(&conn).await;
        let mut gone = already("gone", &org, MembershipStatus::Confirmed, &conn).await;
        assert!(gone.revoke());
        gone.save(&conn).await.unwrap();
        for n in 1..=6 {
            already(&format!("member{n}"), &org, MembershipStatus::Confirmed, &conn).await;
        }
        assert_eq!(count(&org, &conn).await, 6);

        // At the limit, restoring is refused and the row stays revoked.
        let mut back = Membership::find_by_uuid(&gone.uuid, &conn).await.unwrap();
        assert!(back.restore());
        assert_eq!(
            back.save_within(6, &conn).await.unwrap(),
            Within::Full {
                has: 6
            }
        );
        assert!(Membership::find_by_uuid(&gone.uuid, &conn).await.unwrap().status < MembershipStatus::Invited as i32);

        // Revoking someone frees their place, and the restore then fits.
        let mut someone = Membership::find_by_org(&org.uuid, &conn)
            .await
            .into_iter()
            .find(|m| m.status == MembershipStatus::Confirmed as i32)
            .unwrap();
        assert!(someone.revoke());
        assert_eq!(someone.save_within(6, &conn).await.unwrap(), Within::Saved, "revoking never needs a place");
        assert_eq!(count(&org, &conn).await, 5);
        assert_eq!(back.save_within(6, &conn).await.unwrap(), Within::Saved);
        assert_eq!(count(&org, &conn).await, 6);
        assert_eq!(
            Membership::find_by_uuid(&gone.uuid, &conn).await.unwrap().status,
            MembershipStatus::Confirmed as i32
        );
    }

    /// Eight invitations at once for the one place left, each on its own
    /// connection to the same database: exactly one is written, the rest are
    /// refused (not failed), and the family ends with six.
    #[rocket::async_test]
    async fn invitations_at_once_for_the_last_place_let_one_in() {
        const AT_ONCE: u32 = 8;
        let pool = std::sync::Arc::new(DbPool::for_test_pool_of(AT_ONCE));
        let conn = pool.get().await.unwrap();
        let org = family(&conn).await;
        for n in 1..=5 {
            already(&format!("member{n}"), &org, MembershipStatus::Confirmed, &conn).await;
        }
        let mut invitations = Vec::new();
        for n in 0..AT_ONCE {
            invitations.push(membership(&person(&format!("invitee{n}"), &conn).await, &org, MembershipStatus::Invited));
        }
        drop(conn);

        let start = std::sync::Arc::new(tokio::sync::Barrier::new(invitations.len()));
        let mut tasks = Vec::new();
        for invitation in invitations {
            let (pool, start) = (std::sync::Arc::clone(&pool), std::sync::Arc::clone(&start));
            tasks.push(tokio::spawn(async move {
                let conn = pool.get().await.unwrap();
                start.wait().await;
                invitation.save_within(6, &conn).await.map_err(|e| e.message().to_owned())
            }));
        }
        let mut saved = 0;
        for task in tasks {
            match task.await.unwrap() {
                Ok(Within::Saved) => saved += 1,
                Ok(Within::Full {
                    has,
                }) => assert_eq!(has, 6),
                Err(e) => panic!("an invitation failed instead of being refused: {e}"),
            }
        }
        assert_eq!(saved, 1);
        let conn = pool.get().await.unwrap();
        assert_eq!(count(&org, &conn).await, 6);
        let invited = Membership::find_by_org(&org.uuid, &conn)
            .await
            .into_iter()
            .filter(|m| m.status == MembershipStatus::Invited as i32)
            .count();
        assert_eq!(invited, 1);
    }
}

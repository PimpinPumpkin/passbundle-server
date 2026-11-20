// Keykeeper: offboarding that holds. An organization remembers whom it
// removed, so an install command they kept only lets them ask to join again
// (an admin approves them), and whom of its MSP's people it removed or
// revoked itself, so the MSP's staff changes never bring them back. A new
// invitation from the organization's own people clears it. See DESIGN.md,
// "Offboarding", in the meta repo.

use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    db::{DbConn, keykeeper_schema::removed_members},
    error::MapResult,
};

use super::{MspId, OrganizationId, UserId};

#[derive(Identifiable, Queryable, Insertable, Clone, Debug)]
#[diesel(table_name = removed_members)]
#[diesel(primary_key(org_uuid, user_uuid))]
pub struct RemovedMember {
    pub org_uuid: OrganizationId,
    pub user_uuid: UserId,
    pub removed_at: NaiveDateTime,
    /// The MSP whose membership the client removed or revoked, if it was one.
    pub msp_uuid: Option<MspId>,
    /// Revoked rather than removed: restoring them clears it.
    pub revoked: bool,
    /// Taken out by removing their MSP as a whole, not removed or revoked by
    /// the organization itself: joining an MSP with a code doesn't keep them
    /// out (DESIGN.md, "Offboarding", "Taken out with the MSP").
    pub with_msp: bool,
}

impl RemovedMember {
    /// Records that the organization removed someone, or for an MSP's person
    /// (`msp`), removed or revoked them, replacing an earlier record.
    pub async fn record(
        org_uuid: &OrganizationId,
        user_uuid: &UserId,
        msp: Option<&MspId>,
        revoked: bool,
        conn: &DbConn,
    ) -> EmptyResult {
        let row = Self {
            org_uuid: org_uuid.clone(),
            user_uuid: user_uuid.clone(),
            removed_at: Utc::now().naive_utc(),
            msp_uuid: msp.cloned(),
            revoked,
            with_msp: false,
        };
        conn.run(move |conn| {
            conn.transaction(|conn| {
                diesel::delete(
                    removed_members::table
                        .filter(removed_members::org_uuid.eq(&row.org_uuid))
                        .filter(removed_members::user_uuid.eq(&row.user_uuid)),
                )
                .execute(conn)?;
                diesel::insert_into(removed_members::table).values(&row).execute(conn)?;
                Ok::<(), diesel::result::Error>(())
            })
            .map_res("Error recording a removal")
        })
        .await
    }

    /// Records that removing their MSP took this person out of the
    /// organization, unless it already has a record of them: a removal or
    /// revocation the organization made itself is never replaced by one that
    /// came with the MSP. It looks before it writes, so the transaction holds
    /// the organization's lock from its start (`crate::db::write_locked`): a
    /// write elsewhere at the same moment makes it wait its turn instead of
    /// failing.
    pub async fn record_with_msp(
        org_uuid: &OrganizationId,
        user_uuid: &UserId,
        msp: &MspId,
        conn: &DbConn,
    ) -> EmptyResult {
        let row = Self {
            org_uuid: org_uuid.clone(),
            user_uuid: user_uuid.clone(),
            removed_at: Utc::now().naive_utc(),
            msp_uuid: Some(msp.clone()),
            revoked: false,
            with_msp: true,
        };
        conn.run(move |conn| {
            crate::db::write_locked(conn, lock_organization(&row.org_uuid), |conn| {
                let known = removed_members::table
                    .filter(removed_members::org_uuid.eq(&row.org_uuid))
                    .filter(removed_members::user_uuid.eq(&row.user_uuid))
                    .count()
                    .get_result::<i64>(conn)?;
                if known == 0 {
                    diesel::insert_into(removed_members::table).values(&row).execute(conn)?;
                }
                Ok::<(), diesel::result::Error>(())
            })
            .map_res("Error recording a removal")
        })
        .await
    }

    /// The record for someone in an organization. An error is an error, so
    /// callers can fail closed.
    pub async fn try_find(
        org_uuid: &OrganizationId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> Result<Option<Self>, crate::error::Error> {
        conn.run(move |conn| {
            removed_members::table
                .filter(removed_members::org_uuid.eq(org_uuid))
                .filter(removed_members::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .optional()
                .map_res("Error reading removals")
        })
        .await
    }

    /// Whether the organization removed this person (or, for its MSP's
    /// people, removed or revoked them) since anyone invited them again. A
    /// database error counts as removed, so the check fails closed.
    pub async fn exists(org_uuid: &OrganizationId, user_uuid: &UserId, conn: &DbConn) -> bool {
        Self::try_find(org_uuid, user_uuid, conn).await.map_or(true, |r| r.is_some())
    }

    /// Forgets the record: the organization's own people invited them again,
    /// approved them, or restored them.
    pub async fn clear(org_uuid: &OrganizationId, user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(
                removed_members::table
                    .filter(removed_members::org_uuid.eq(org_uuid))
                    .filter(removed_members::user_uuid.eq(user_uuid)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error clearing a removal")
        })
        .await
    }

    /// An MSP's people its clients removed or revoked, for its console.
    pub async fn find_by_msp(msp_uuid: &MspId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            removed_members::table
                .filter(removed_members::msp_uuid.eq(msp_uuid))
                .order(removed_members::removed_at.desc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    /// How many people the organization removed or revoked since a time, such
    /// as when its install command's token was made: each may still have the
    /// command.
    pub async fn count_since(org_uuid: &OrganizationId, since: Option<NaiveDateTime>, conn: &DbConn) -> i64 {
        conn.run(move |conn| {
            let mut query = removed_members::table.filter(removed_members::org_uuid.eq(org_uuid)).into_boxed();
            if let Some(since) = since {
                query = query.filter(removed_members::removed_at.ge(since));
            }
            query.count().get_result::<i64>(conn).unwrap_or(0)
        })
        .await
    }
}

/// `record_with_msp`'s lock on PostgreSQL: the organization's row, locked for
/// update, as a move to another MSP locks it (`begin_write`), so two writers
/// of its records go one at a time. On SQLite the transaction holds the write
/// lock already.
fn lock_organization(
    org: &OrganizationId,
) -> impl FnOnce(&mut crate::db::DbConnInner) -> Result<(), diesel::result::Error> + '_ {
    move |conn| {
        #[cfg(not(postgresql))]
        let _ = org;
        match conn {
            #[cfg(postgresql)]
            crate::db::DbConnInner::Postgresql(conn) => {
                use crate::db::schema::organizations;
                organizations::table
                    .filter(organizations::uuid.eq(org))
                    .select(organizations::uuid)
                    .for_update()
                    .first::<OrganizationId>(conn)
                    .optional()
                    .map(drop)
            }
            #[cfg(sqlite)]
            crate::db::DbConnInner::Sqlite(_) => Ok(()),
        }
    }
}

#[cfg(all(test, sqlite))]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::db::{
        DbPool,
        models::{Msp, Organization, User, begin_write, commit_write, rollback_write},
    };

    /// An organization, someone in its MSP's staff, and the MSP.
    async fn client_and_staff(conn: &DbConn) -> (OrganizationId, UserId, MspId) {
        let org = Organization::new("Acme Dental".to_owned(), "billing@example.test", None, None);
        org.save(conn).await.unwrap();
        let mut tech = User::new("tech@example.test", None);
        tech.save(conn).await.unwrap();
        let msp = Msp::new("Acme Dental IT".to_owned());
        msp.insert(conn).await.unwrap();
        (org.uuid, tech.uuid, msp.uuid)
    }

    /// A client removing its MSP records each of the MSP's people as taken
    /// out with it while another write holds the database's write lock (the
    /// seats job runs every second where a tier 1 test removes an MSP, and the
    /// event streaming worker writes while it sends the client's events): it
    /// waits for that write instead of failing with "Error recording a
    /// removal". Inside a transaction the caller holds (a move to another MSP
    /// is one), it's part of that transaction: undone with it, and kept with
    /// it.
    #[rocket::async_test]
    async fn taken_out_with_the_msp_waits_for_a_write_in_progress_and_is_part_of_a_move() {
        let pool = DbPool::for_test_pool_of(2);
        let conn = pool.get().await.unwrap();
        let (org, tech, msp) = client_and_staff(&conn).await;

        let released = pool.hold_write_lock(Duration::from_millis(300)).await;
        let recorded = RemovedMember::record_with_msp(&org, &tech, &msp, &conn).await;
        released.await.unwrap();
        recorded.map_err(|e| e.message().to_owned()).expect("the record waits for the other write, and is written");
        let row = RemovedMember::try_find(&org, &tech, &conn).await.unwrap().expect("the record");
        assert!(row.with_msp);
        assert_eq!(row.msp_uuid, Some(msp.clone()));

        RemovedMember::clear(&org, &tech, &conn).await.unwrap();
        begin_write(&org, &conn).await.unwrap();
        RemovedMember::record_with_msp(&org, &tech, &msp, &conn).await.unwrap();
        rollback_write(&conn).await;
        assert!(RemovedMember::try_find(&org, &tech, &conn).await.unwrap().is_none());
        begin_write(&org, &conn).await.unwrap();
        RemovedMember::record_with_msp(&org, &tech, &msp, &conn).await.unwrap();
        commit_write(&conn).await.unwrap();
        assert!(RemovedMember::try_find(&org, &tech, &conn).await.unwrap().is_some_and(|r| r.with_msp));
    }
}

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

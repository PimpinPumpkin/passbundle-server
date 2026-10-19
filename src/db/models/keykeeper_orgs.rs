// Keykeeper: a company's own organization, set up with a preset rather than
// through an MSP. It keeps what an MSP's client keeps in msp_clients: the
// preset it started with, its install command's enrollment token, and the
// collection people who join with it get. See DESIGN.md, "A company's own IT".

use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    db::{DbConn, keykeeper_schema::org_setups},
    error::MapResult,
};

use super::{CollectionId, MspClient, OrganizationId};

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = org_setups)]
#[diesel(primary_key(org_uuid))]
pub struct OrgSetup {
    pub org_uuid: OrganizationId,
    pub created_at: NaiveDateTime,
    /// The defaults the organization started with, such as "business".
    pub preset: Option<String>,
    /// Lets an account ask to join as a regular member, through the install
    /// command. Never grants the org key.
    pub enrollment_token: Option<String>,
    pub enrollment_token_created_at: Option<NaiveDateTime>,
    /// The collection people who join get, such as "Everyone".
    pub everyone_collection: Option<CollectionId>,
}

impl OrgSetup {
    /// A new setup, with an install command when `token` is set.
    pub fn new(
        org_uuid: OrganizationId,
        preset: Option<String>,
        everyone_collection: Option<CollectionId>,
        token: bool,
    ) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            org_uuid,
            created_at: now,
            preset,
            enrollment_token: token.then(MspClient::new_enrollment_token),
            enrollment_token_created_at: token.then_some(now),
            everyone_collection,
        }
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| org_setups::table.filter(org_setups::org_uuid.eq(org_uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn find_by_enrollment_token(token: &str, conn: &DbConn) -> Option<Self> {
        let token = token.to_owned();
        conn.run(move |conn| org_setups::table.filter(org_setups::enrollment_token.eq(token)).first::<Self>(conn).ok())
            .await
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(org_setups::table).values(self).execute(conn).map_res("Error saving organization setup")
        })
        .await
    }

    /// Replaces the enrollment token, or makes the first one. Install commands
    /// with the old one stop letting new people join.
    pub async fn replace_enrollment_token(&mut self, conn: &DbConn) -> EmptyResult {
        let token = MspClient::new_enrollment_token();
        let now = Utc::now().naive_utc();
        let org = self.org_uuid.clone();
        let saved = token.clone();
        let updated: EmptyResult = conn
            .run(move |conn| {
                diesel::update(org_setups::table.filter(org_setups::org_uuid.eq(org)))
                    .set((org_setups::enrollment_token.eq(saved), org_setups::enrollment_token_created_at.eq(now)))
                    .execute(conn)
                    .map_res("Error replacing the enrollment token")
            })
            .await;
        updated?;
        self.enrollment_token = Some(token);
        self.enrollment_token_created_at = Some(now);
        Ok(())
    }
}

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

use super::{CollectionId, OrganizationId};

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = org_setups)]
#[diesel(primary_key(org_uuid))]
pub struct OrgSetup {
    pub org_uuid: OrganizationId,
    pub created_at: NaiveDateTime,
    /// The defaults the organization started with, such as "business".
    pub preset: Option<String>,
    /// Lets an account ask to join as a regular member, through the install
    /// command. Never grants the org key. Sealed, and found by its hash, as
    /// an MSP client's (MspClient).
    pub enrollment_token: Option<String>,
    pub enrollment_token_created_at: Option<NaiveDateTime>,
    /// The collection people who join get, such as "Everyone".
    pub everyone_collection: Option<CollectionId>,
    /// The install command's join secret, encrypted with the organization's
    /// key by an owner's or admin's browser. See DESIGN.md, "Joins a hacked
    /// server can't forge".
    pub enrollment_secret: Option<String>,
    /// The enrollment token's SHA-256, to find it by.
    pub enrollment_token_hash: Option<String>,
}

impl OrgSetup {
    /// A new setup, with an install command when `token` is set.
    pub fn new(
        org_uuid: OrganizationId,
        preset: Option<String>,
        everyone_collection: Option<CollectionId>,
        token: bool,
    ) -> Result<Self, crate::error::Error> {
        let now = Utc::now().naive_utc();
        let token = if token {
            Some(super::StoredToken::new(&org_uuid)?)
        } else {
            None
        };
        Ok(Self {
            org_uuid,
            created_at: now,
            preset,
            enrollment_token_created_at: token.is_some().then_some(now),
            enrollment_token_hash: token.as_ref().map(|t| t.hash.clone()),
            enrollment_token: token.map(|t| t.sealed),
            everyone_collection,
            enrollment_secret: None,
        })
    }

    /// The enrollment token, for the install command admins see.
    pub fn enrollment_token(&self) -> Option<String> {
        super::open_install_token(&self.org_uuid, self.enrollment_token.as_deref()?)
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| org_setups::table.filter(org_setups::org_uuid.eq(org_uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn find_by_enrollment_token(token: &str, conn: &DbConn) -> Option<Self> {
        let hash = super::token_hash(token);
        conn.run(move |conn| {
            org_setups::table.filter(org_setups::enrollment_token_hash.eq(hash)).first::<Self>(conn).ok()
        })
        .await
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(org_setups::table).values(self).execute(conn).map_res("Error saving organization setup")
        })
        .await
    }

    /// Sets the install command's join secret, encrypted by the browser,
    /// keeping the token.
    pub async fn set_enrollment_secret(&mut self, secret: Option<String>, conn: &DbConn) -> EmptyResult {
        let org = self.org_uuid.clone();
        let saved = secret.clone();
        conn.run(move |conn| {
            diesel::update(org_setups::table.filter(org_setups::org_uuid.eq(org)))
                .set(org_setups::enrollment_secret.eq(saved))
                .execute(conn)
                .map(|_| ())
                .map_res("Error saving the join secret")
        })
        .await?;
        self.enrollment_secret = secret;
        Ok(())
    }

    /// Replaces the enrollment token, or makes the first one, with the new
    /// command's join secret (encrypted, from the browser that made it; none
    /// from an older app). Install commands with the old one stop letting new
    /// people join.
    pub async fn replace_enrollment_token(&mut self, secret: Option<String>, conn: &DbConn) -> EmptyResult {
        let token = super::StoredToken::new(&self.org_uuid)?;
        let now = Utc::now().naive_utc();
        let org = self.org_uuid.clone();
        let (saved, saved_hash) = (token.sealed.clone(), token.hash.clone());
        let saved_secret = secret.clone();
        let updated: EmptyResult = conn
            .run(move |conn| {
                diesel::update(org_setups::table.filter(org_setups::org_uuid.eq(org)))
                    .set((
                        org_setups::enrollment_token.eq(saved),
                        org_setups::enrollment_token_hash.eq(saved_hash),
                        org_setups::enrollment_token_created_at.eq(now),
                        org_setups::enrollment_secret.eq(saved_secret),
                    ))
                    .execute(conn)
                    .map_res("Error replacing the enrollment token")
            })
            .await;
        updated?;
        self.enrollment_token_hash = Some(token.hash);
        self.enrollment_token = Some(token.sealed);
        self.enrollment_token_created_at = Some(now);
        self.enrollment_secret = secret;
        Ok(())
    }
}

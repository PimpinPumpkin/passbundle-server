// Keykeeper: whether an organization lets its people use assisted password
// change on its items: the browser extension changing a login's password on
// its site, saving the new one first (DESIGN.md, "Assisted password change",
// in the meta repo). On by default: an organization without a row allows it.
// Its owners, admins, and its MSP's admins turn it off, and an MSP can turn it
// off for its clients as a default policy (keykeeper_msp_policies).

use diesel::prelude::*;

use crate::{
    api::{ApiResult, EmptyResult},
    db::{DbConn, keykeeper_schema::org_password_change},
    error::MapResult,
};

use super::OrganizationId;

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = org_password_change)]
#[diesel(primary_key(org_uuid))]
pub struct OrgPasswordChange {
    pub org_uuid: OrganizationId,
    pub allowed: bool,
}

impl OrgPasswordChange {
    /// Whether the organization allows it. Without a row it does.
    pub async fn allowed(org_uuid: &OrganizationId, conn: &DbConn) -> ApiResult<bool> {
        let org_uuid = org_uuid.clone();
        conn.run(move |conn| {
            org_password_change::table
                .filter(org_password_change::org_uuid.eq(org_uuid))
                .select(org_password_change::allowed)
                .first::<bool>(conn)
                .optional()
                .map(|allowed| allowed.unwrap_or(true))
                .map_res("Error reading an organization's assisted password change setting")
        })
        .await
    }

    pub async fn set(org_uuid: &OrganizationId, allowed: bool, conn: &DbConn) -> EmptyResult {
        let row = Self {
            org_uuid: org_uuid.clone(),
            allowed,
        };
        conn.run(move |conn| {
            diesel::delete(org_password_change::table.filter(org_password_change::org_uuid.eq(&row.org_uuid)))
                .execute(conn)
                .map_res("Error saving an organization's assisted password change setting")
                .map(|_: usize| ())?;
            diesel::insert_into(org_password_change::table)
                .values(&row)
                .execute(conn)
                .map_res("Error saving an organization's assisted password change setting")
        })
        .await
    }
}

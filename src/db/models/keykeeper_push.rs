// Keykeeper: a phone's UnifiedPush endpoint, one per account and device: the
// address its distributor gave it, and the P-256 public key and auth secret
// that messages to it are encrypted to (RFC 8291), both base64url. Gone with
// the device's row or the account. See DESIGN.md, "Push to phones", in the
// meta repo.

use chrono::NaiveDateTime;
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    db::{DbConn, keykeeper_schema::push_endpoints},
    error::MapResult,
};

use super::{DeviceId, UserId};

#[derive(Clone, Debug, Identifiable, Queryable, Insertable)]
#[diesel(table_name = push_endpoints)]
#[diesel(primary_key(user_uuid, device_uuid))]
pub struct PushEndpoint {
    pub user_uuid: UserId,
    pub device_uuid: DeviceId,
    /// Where messages go: an https URL, checked when it's saved and again
    /// before each message (keykeeper_push::guard).
    pub endpoint: String,
    /// The phone's P-256 public key, uncompressed (65 bytes), base64url.
    pub public_key: String,
    /// The phone's auth secret (16 bytes), base64url.
    pub auth: String,
    pub created_at: NaiveDateTime,
}

impl PushEndpoint {
    /// Keeps this device's endpoint, in place of the one it had.
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        let row = self.clone();
        conn.run(move |conn| {
            conn.transaction(|conn| {
                diesel::delete(
                    push_endpoints::table
                        .filter(push_endpoints::user_uuid.eq(&row.user_uuid))
                        .filter(push_endpoints::device_uuid.eq(&row.device_uuid)),
                )
                .execute(conn)?;
                diesel::insert_into(push_endpoints::table).values(&row).execute(conn)
            })
            .map(|_| ())
            .map_res("Error keeping the device's push endpoint")
        })
        .await
    }

    pub async fn find(user_uuid: &UserId, device_uuid: &DeviceId, conn: &DbConn) -> Option<Self> {
        let (user_uuid, device_uuid) = (user_uuid.clone(), device_uuid.clone());
        conn.run(move |conn| {
            push_endpoints::table
                .filter(push_endpoints::user_uuid.eq(user_uuid))
                .filter(push_endpoints::device_uuid.eq(device_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// Every endpoint of the account's devices.
    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        let user_uuid = user_uuid.clone();
        conn.run(move |conn| {
            push_endpoints::table.filter(push_endpoints::user_uuid.eq(user_uuid)).load::<Self>(conn).unwrap_or_default()
        })
        .await
    }

    /// Removes this device's endpoint, if it has one.
    pub async fn delete(user_uuid: &UserId, device_uuid: &DeviceId, conn: &DbConn) -> EmptyResult {
        let (user_uuid, device_uuid) = (user_uuid.clone(), device_uuid.clone());
        conn.run(move |conn| {
            diesel::delete(
                push_endpoints::table
                    .filter(push_endpoints::user_uuid.eq(user_uuid))
                    .filter(push_endpoints::device_uuid.eq(device_uuid)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error removing the device's push endpoint")
        })
        .await
    }

    /// Removes this endpoint, once its push service said it's gone, unless
    /// the device registered another since: whether it was removed.
    pub async fn delete_if_unchanged(&self, conn: &DbConn) -> bool {
        let row = self.clone();
        conn.run(move |conn| {
            diesel::delete(
                push_endpoints::table
                    .filter(push_endpoints::user_uuid.eq(row.user_uuid))
                    .filter(push_endpoints::device_uuid.eq(row.device_uuid))
                    .filter(push_endpoints::endpoint.eq(row.endpoint)),
            )
            .execute(conn)
            .is_ok_and(|n| n > 0)
        })
        .await
    }

    /// Removes every endpoint of the account's: its sessions all ended.
    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        let user_uuid = user_uuid.clone();
        conn.run(move |conn| {
            diesel::delete(push_endpoints::table.filter(push_endpoints::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map(|_| ())
                .map_res("Error removing the account's push endpoints")
        })
        .await
    }
}

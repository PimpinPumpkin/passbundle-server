// Keykeeper: the new-device check's rows. A sign-in held because the account
// has no two-step login and the device has never been used waits here until
// the person approves it from another device (typing the number the new
// device shows), with a code by email, or it ends. And the token a device
// gets once it's in, so a device identifier alone, which isn't a secret,
// never counts as a device the account knows. See DESIGN.md, "New-device
// check", in the meta repo.

use chrono::NaiveDateTime;
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        keykeeper_schema::{known_device_tokens, new_device_checks},
    },
    error::MapResult,
};

use super::{DeviceId, UserId, sso_hash, sso_random};

/// One sign-in waiting for the new-device check.
#[derive(Clone, Debug, Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = new_device_checks)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct NewDeviceCheck {
    pub uuid: String,
    pub user_uuid: UserId,
    pub device_uuid: DeviceId,
    pub device_type: i32,
    pub device_name: String,
    /// The address the sign-in came from, as the server saw it.
    pub ip: String,
    /// The SHA-256 of the token the new device asks with; replaced each time
    /// the device signs in again while the check waits.
    pub token_hash: String,
    /// The number the new device shows and the approving one must type.
    pub number: i32,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    pub approved_at: Option<NaiveDateTime>,
    /// "device", "email", or "waiting".
    pub approved_how: Option<String>,
    /// The approving device's identifier.
    pub approved_by: Option<String>,
    pub denied_at: Option<NaiveDateTime>,
    /// "number" (a wrong one) or "denied".
    pub denied_why: Option<String>,
    /// When a code by email may be sent, once the person asked for one
    /// because they can't reach their other devices.
    pub email_after: Option<NaiveDateTime>,
    /// The emailed code's SHA-256.
    pub code_hash: Option<String>,
    pub code_sends: i32,
    pub code_tries: i32,
    /// When the new device signed in with it: an approval signs in once.
    pub used_at: Option<NaiveDateTime>,
}

impl NewDeviceCheck {
    /// A new token for the new device: its value, kept only as a hash.
    pub fn new_token(&mut self) -> String {
        let token = sso_random();
        self.token_hash = sso_hash(&token);
        token
    }

    pub fn token_matches(&self, token: &str) -> bool {
        crate::crypto::ct_eq(&self.token_hash, sso_hash(token))
    }

    pub fn is_open(&self, now: NaiveDateTime) -> bool {
        self.expires_at > now && self.denied_at.is_none() && self.used_at.is_none()
    }

    pub fn is_waiting(&self, now: NaiveDateTime) -> bool {
        self.is_open(now) && self.approved_at.is_none()
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        let row = self.clone();
        conn.run(move |conn| {
            diesel::insert_into(new_device_checks::table)
                .values(&row)
                .execute(conn)
                .map_res("Error holding the sign-in for approval")
        })
        .await
    }

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        let row = self.clone();
        conn.run(move |conn| {
            diesel::update(new_device_checks::table.filter(new_device_checks::uuid.eq(&row.uuid)))
                .set(&row)
                .execute(conn)
                .map_res("Error saving the sign-in's approval")
        })
        .await
    }

    /// The check by its id, if it hasn't been cleaned up yet (it may have
    /// ended: see `is_open`).
    pub async fn find(uuid: &str, conn: &DbConn) -> Option<Self> {
        let uuid = uuid.to_owned();
        conn.run(move |conn| new_device_checks::table.filter(new_device_checks::uuid.eq(uuid)).first::<Self>(conn).ok())
            .await
    }

    /// Every check of the account's not cleaned up yet, newest first.
    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        let user_uuid = user_uuid.clone();
        conn.run(move |conn| {
            new_device_checks::table
                .filter(new_device_checks::user_uuid.eq(user_uuid))
                .order(new_device_checks::created_at.desc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    /// Ends every check that's over, everyone's: past its time, plus an hour
    /// so the new device can still hear it was denied or used.
    pub async fn delete_ended(before: NaiveDateTime, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(new_device_checks::table.filter(new_device_checks::expires_at.lt(before)))
                .execute(conn)
                .map(|_| ())
                .map_res("Error cleaning up sign-in approvals")
        })
        .await
    }

    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        let uuid = self.uuid.clone();
        conn.run(move |conn| {
            diesel::delete(new_device_checks::table.filter(new_device_checks::uuid.eq(uuid)))
                .execute(conn)
                .map(|_| ())
                .map_res("Error removing a sign-in approval")
        })
        .await
    }
}

/// The token a device shows to count as one the account knows.
pub struct KnownDeviceToken;

impl KnownDeviceToken {
    /// A new token for this account's device, replacing any it had.
    pub async fn issue(user_uuid: &UserId, device_uuid: &DeviceId, now: NaiveDateTime, conn: &DbConn) -> String {
        let token = sso_random();
        let hash = sso_hash(&token);
        let (user_uuid, device_uuid) = (user_uuid.clone(), device_uuid.clone());
        let saved = conn
            .run(move |conn| {
                conn.transaction(|conn| {
                    diesel::delete(
                        known_device_tokens::table
                            .filter(known_device_tokens::user_uuid.eq(&user_uuid))
                            .filter(known_device_tokens::device_uuid.eq(&device_uuid)),
                    )
                    .execute(conn)?;
                    diesel::insert_into(known_device_tokens::table)
                        .values((
                            known_device_tokens::user_uuid.eq(&user_uuid),
                            known_device_tokens::device_uuid.eq(&device_uuid),
                            known_device_tokens::token_hash.eq(hash),
                            known_device_tokens::created_at.eq(now),
                        ))
                        .execute(conn)
                })
            })
            .await;
        if let Err(e) = saved {
            error!("Error keeping a device's token: {e:#?}");
        }
        token
    }

    /// Whether this is the account's device's current token.
    pub async fn matches(user_uuid: &UserId, device_uuid: &DeviceId, token: &str, conn: &DbConn) -> bool {
        let (user_uuid, device_uuid) = (user_uuid.clone(), device_uuid.clone());
        let kept: Option<String> = conn
            .run(move |conn| {
                known_device_tokens::table
                    .filter(known_device_tokens::user_uuid.eq(user_uuid))
                    .filter(known_device_tokens::device_uuid.eq(device_uuid))
                    .select(known_device_tokens::token_hash)
                    .first::<String>(conn)
                    .ok()
            })
            .await;
        kept.is_some_and(|hash| crate::crypto::ct_eq(hash, sso_hash(token)))
    }
}

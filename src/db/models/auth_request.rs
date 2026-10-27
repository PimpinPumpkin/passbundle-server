use chrono::{NaiveDateTime, TimeDelta, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    api::{ApiResult, EmptyResult},
    crypto::ct_eq,
    db::{DbConn, schema::auth_requests},
    error::MapResult,
    util::format_date,
};
use macros::UuidFromParam;

use super::{DeviceId, OrganizationId, UserId};

/// Keykeeper: how long a sign-in request lasts, from when it's made:
/// listing it, approving or denying it, the requesting device reading the
/// answer, and signing in with it all stop then, as upstream's 15 minutes
/// (DESIGN.md, "Approving a sign-in from another device").
pub const AUTH_REQUEST_LIFETIME: TimeDelta = TimeDelta::minutes(15);

/// Keykeeper: the most sign-in requests one account may have waiting at once.
/// A device's new request replaces its own waiting one, so this is about
/// five devices asking at the same time.
pub const MAX_PENDING_AUTH_REQUESTS: usize = 5;

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Deserialize, Serialize)]
#[diesel(table_name = auth_requests)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct AuthRequest {
    pub uuid: AuthRequestId,
    pub user_uuid: UserId,
    pub organization_uuid: Option<OrganizationId>,

    pub request_device_identifier: DeviceId,
    pub device_type: i32, // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/Enums/DeviceType.cs

    pub request_ip: String,
    pub response_device_id: Option<DeviceId>,

    pub access_code: String,
    pub public_key: String,

    pub enc_key: Option<String>,

    pub master_password_hash: Option<String>,
    pub approved: Option<bool>,
    pub creation_date: NaiveDateTime,
    pub response_date: Option<NaiveDateTime>,

    pub authentication_date: Option<NaiveDateTime>,
}

impl AuthRequest {
    pub fn new(
        user_uuid: UserId,
        request_device_identifier: DeviceId,
        device_type: i32,
        request_ip: String,
        access_code: String,
        public_key: String,
    ) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: AuthRequestId(crate::util::get_uuid()),
            user_uuid,
            organization_uuid: None,

            request_device_identifier,
            device_type,
            request_ip,
            response_device_id: None,
            access_code,
            public_key,
            enc_key: None,
            master_password_hash: None,
            approved: None,
            creation_date: now,
            response_date: None,
            authentication_date: None,
        }
    }

    /// Keykeeper: past its lifetime at `now` (`AUTH_REQUEST_LIFETIME`).
    pub fn is_expired_at(&self, now: NaiveDateTime) -> bool {
        now >= self.creation_date + AUTH_REQUEST_LIFETIME
    }

    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Utc::now().naive_utc())
    }

    pub fn to_json_for_pending_device(&self) -> Value {
        json!({
            "id": self.uuid,
            "creationDate": format_date(&self.creation_date),
        })
    }
}

impl AuthRequest {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            mysql {
                diesel::insert_into(auth_requests::table)
                    .values(self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving auth_request")
            }
            postgresql, sqlite {
                diesel::insert_into(auth_requests::table)
                    .values(self)
                    .on_conflict(auth_requests::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving auth_request")
            }
        }
    }

    pub async fn find_by_uuid(uuid: &AuthRequestId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| auth_requests::table.filter(auth_requests::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn find_by_uuid_and_user(uuid: &AuthRequestId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            auth_requests::table
                .filter(auth_requests::uuid.eq(uuid))
                .filter(auth_requests::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_user_and_requested_device(
        user_uuid: &UserId,
        device_uuid: &DeviceId,
        conn: &DbConn,
    ) -> Option<Self> {
        conn.run(move |conn| {
            auth_requests::table
                .filter(auth_requests::user_uuid.eq(user_uuid))
                .filter(auth_requests::request_device_identifier.eq(device_uuid))
                .filter(auth_requests::approved.is_null())
                // Keykeeper: an expired request isn't waiting any more.
                .filter(auth_requests::creation_date.gt(Utc::now().naive_utc() - AUTH_REQUEST_LIFETIME))
                .order_by(auth_requests::creation_date.desc())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// Keykeeper: the account's requests still waiting for an answer at
    /// `now`, newest first.
    pub async fn find_pending_by_user(user_uuid: &UserId, now: NaiveDateTime, conn: &DbConn) -> Vec<Self> {
        let since = now - AUTH_REQUEST_LIFETIME;
        conn.run(move |conn| {
            auth_requests::table
                .filter(auth_requests::user_uuid.eq(user_uuid))
                .filter(auth_requests::approved.is_null())
                .filter(auth_requests::creation_date.gt(since))
                .order_by(auth_requests::creation_date.desc())
                .load::<Self>(conn)
                .expect("Error loading auth_requests")
        })
        .await
    }

    /// Keykeeper: deletes a device's own requests still waiting for an
    /// answer, when it makes a new one, so each device has one at most.
    pub async fn delete_pending_from_device(user_uuid: &UserId, device_uuid: &DeviceId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(
                auth_requests::table
                    .filter(auth_requests::user_uuid.eq(user_uuid))
                    .filter(auth_requests::request_device_identifier.eq(device_uuid))
                    .filter(auth_requests::approved.is_null()),
            )
            .execute(conn)
            .map_res("Error deleting auth requests")
        })
        .await
    }

    pub async fn find_created_before(dt: &NaiveDateTime, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            auth_requests::table
                .filter(auth_requests::creation_date.lt(dt))
                .load::<Self>(conn)
                .expect("Error loading auth_requests")
        })
        .await
    }

    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(auth_requests::table.filter(auth_requests::uuid.eq(&self.uuid)))
                .execute(conn)
                .map_res("Error deleting auth request")
        })
        .await
    }

    /// Marks the request as used to log in. Returns false when it already was, so it only works once.
    pub async fn set_authentication_date(uuid: &AuthRequestId, conn: &DbConn) -> ApiResult<bool> {
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            diesel::update(auth_requests::table)
                .filter(auth_requests::uuid.eq(uuid))
                .filter(auth_requests::authentication_date.is_null())
                .set(auth_requests::authentication_date.eq(now))
                .execute(conn)
                .map(|updated| updated == 1)
                .map_res("Error updating auth request")
        })
        .await
    }

    pub fn check_access_code(&self, access_code: &str) -> bool {
        ct_eq(&self.access_code, access_code)
    }

    pub async fn purge_expired_auth_requests(conn: &DbConn) {
        // delete auth requests older than 15 minutes which is functionally equivalent to upstream:
        // https://github.com/bitwarden/server/blob/f8ee2270409f7a13125cd414c450740af605a175/src/Sql/dbo/Auth/Stored%20Procedures/AuthRequest_DeleteIfExpired.sql
        // Keykeeper: the same lifetime every other check uses.
        let expiry_time = Utc::now().naive_utc() - AUTH_REQUEST_LIFETIME;
        for auth_request in Self::find_created_before(&expiry_time, conn).await {
            auth_request.delete(conn).await.ok();
        }
    }
}

#[derive(
    Clone,
    Debug,
    AsRef,
    Deref,
    DieselNewType,
    Display,
    From,
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    UuidFromParam,
)]
pub struct AuthRequestId(String);

#[cfg(test)]
mod tests {
    use chrono::NaiveDate;

    use super::*;

    fn made_at(creation_date: NaiveDateTime) -> AuthRequest {
        AuthRequest {
            creation_date,
            ..AuthRequest::new(
                UserId::from("user".to_owned()),
                DeviceId::from("device".to_owned()),
                9,
                "203.0.113.7".to_owned(),
                "code".to_owned(),
                "key".to_owned(),
            )
        }
    }

    #[test]
    fn a_request_lasts_fifteen_minutes_from_when_its_made() {
        let made = NaiveDate::from_ymd_opt(2026, 10, 26).unwrap().and_hms_opt(12, 0, 0).unwrap();
        let request = made_at(made);
        assert!(!request.is_expired_at(made));
        assert!(!request.is_expired_at(made + TimeDelta::minutes(14) + TimeDelta::seconds(59)));
        assert!(request.is_expired_at(made + TimeDelta::minutes(15)));
        assert!(request.is_expired_at(made + TimeDelta::hours(3)));
        // A clock behind the server's when it was made doesn't expire it.
        assert!(!request.is_expired_at(made - TimeDelta::minutes(1)));
    }
}

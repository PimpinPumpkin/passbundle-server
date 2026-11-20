// Keykeeper: a phone registers its UnifiedPush endpoint here, with the keys
// messages to it are encrypted to, and removes it. Only for the device the
// session is for: no device is named in a request. Upstream's push token
// route (`/devices/identifier/<id>/token`) and its relay are separate and
// unchanged. See DESIGN.md, "Push to phones", in the meta repo.

use chrono::Utc;
use data_encoding::BASE64URL_NOPAD;
use rocket::{Route, serde::json::Json};
use serde_json::{Value, json};

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult},
    auth::Headers,
    db::{DbConn, models::PushEndpoint},
    keykeeper_push::{self, guard, webpush},
};

pub fn routes() -> Vec<Route> {
    routes![get_unified_push, put_unified_push, delete_unified_push]
}

/// Whether the server sends push, its VAPID key (the phone registers with
/// its distributor with it), and whether this device has an endpoint.
async fn view(headers: &Headers, conn: &DbConn) -> Value {
    let enabled = CONFIG.unified_push_enabled();
    let registered = PushEndpoint::find(&headers.user.uuid, &headers.device.uuid, conn).await.is_some();
    json!({
        "object": "unifiedPush",
        "enabled": enabled,
        "vapidPublicKey": if enabled { keykeeper_push::vapid_public_key() } else { None },
        "registered": registered,
    })
}

#[get("/keykeeper/push/unified-push")]
async fn get_unified_push(headers: Headers, conn: DbConn) -> JsonResult {
    Ok(Json(view(&headers, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Registration {
    endpoint: String,
    public_key: String,
    auth: String,
}

/// base64url, with or without padding, as distributors' libraries give it.
fn base64url(text: &str) -> Option<Vec<u8>> {
    BASE64URL_NOPAD.decode(text.trim().trim_end_matches('=').as_bytes()).ok()
}

/// Keeps this device's endpoint, in place of any it had.
#[put("/keykeeper/push/unified-push", data = "<data>")]
async fn put_unified_push(data: Json<Registration>, headers: Headers, conn: DbConn) -> JsonResult {
    if !CONFIG.unified_push_enabled() {
        err!("This server doesn't send push notifications.")
    }
    let data = data.into_inner();
    let url = match guard::checked_url(&data.endpoint, &guard::Policy::current()) {
        Ok(url) => url,
        Err(e) => err!(format!("That push endpoint can't be used. {e}")),
    };
    let Some(public_key) = base64url(&data.public_key).filter(|k| webpush::public_key(k).is_ok()) else {
        err!("The push public key isn't an uncompressed P-256 key in base64url.")
    };
    let Some(auth) = base64url(&data.auth).filter(|a| a.len() == webpush::AUTH_LEN) else {
        err!("The push auth secret isn't 16 bytes in base64url.")
    };
    PushEndpoint {
        user_uuid: headers.user.uuid.clone(),
        device_uuid: headers.device.uuid.clone(),
        endpoint: url.to_string(),
        public_key: BASE64URL_NOPAD.encode(&public_key),
        auth: BASE64URL_NOPAD.encode(&auth),
        created_at: Utc::now().naive_utc(),
    }
    .save(&conn)
    .await?;
    Ok(Json(view(&headers, &conn).await))
}

/// Removes this device's endpoint, if it has one.
#[delete("/keykeeper/push/unified-push")]
async fn delete_unified_push(headers: Headers, conn: DbConn) -> EmptyResult {
    PushEndpoint::delete(&headers.user.uuid, &headers.device.uuid, &conn).await
}

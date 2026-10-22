// Keykeeper: settings that follow someone to each of their devices, such as
// the password generator's: an app saves them encrypted with the account's
// key, and the others read them when they sync. The server can't read them.
// See DESIGN.md, "Generator settings".

use rocket::{Route, serde::json::Json};
use serde_json::{Value, json};

use crate::{
    api::{JsonResult, Notify, UpdateType},
    auth::Headers,
    db::{
        DbConn,
        models::{UserSettings, valid_settings},
    },
    util::format_date,
};

pub fn routes() -> Vec<Route> {
    routes![get_settings, put_settings]
}

fn view(settings: Option<&UserSettings>) -> Value {
    json!({
        "object": "keykeeperSettings",
        "data": settings.map(|s| s.data.clone()),
        "revisionDate": settings.map(|s| format_date(&s.revision_date)),
    })
}

/// The caller's settings, or none saved yet.
#[get("/keykeeper/settings")]
async fn get_settings(headers: Headers, conn: DbConn) -> JsonResult {
    Ok(Json(view(UserSettings::find(&headers.user.uuid, &conn).await?.as_ref())))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingsData {
    data: String,
}

/// Saves the caller's settings, and tells their other devices to sync.
#[put("/keykeeper/settings", data = "<data>")]
async fn put_settings(data: Json<SettingsData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    if !valid_settings(&data.data) {
        err!("Settings must be encrypted with your account's key")
    }
    let saved = UserSettings::save(&headers.user.uuid, &data.data, &conn).await?;
    // Their sync reads the settings again even when nothing else changed, so
    // the account's revision stays and nobody downloads the whole vault.
    nt.send_user_update(UpdateType::SyncSettings, &headers.user, headers.device.push_uuid.as_ref(), &conn).await;
    Ok(Json(view(Some(&saved))))
}

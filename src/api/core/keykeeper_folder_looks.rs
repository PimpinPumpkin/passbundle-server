// Keykeeper: a shared folder's icon and color (DESIGN.md, "Folder icons").
// The apps encrypt the choice with the organization's key, as they do the
// folder's name, since "bank" says something about what's inside: the server
// keeps a ciphertext it can't read and only checks its shape. It's a column
// of the folder (`collections.keykeeper_look`), so it goes with the folder in
// sync and in every answer about the folder (Collection::to_json), and goes
// when the folder does. Whoever may rename the folder may change it.

use rocket::{Route, serde::json::Json};

use crate::{
    api::{JsonResult, core::log_event},
    auth::Headers,
    db::{
        DbConn,
        models::{Collection, CollectionId, EventType, OrganizationId, keykeeper_folder_permissions},
    },
};

pub fn routes() -> Vec<Route> {
    routes![put_look]
}

/// The longest look the server keeps. An icon's and a color's names,
/// encrypted, come to under 200 characters.
pub const MAX_LOOK: usize = 1024;

/// What everyone who may not change a folder's icon is told, whether the
/// folder is someone else's, isn't there, or is one they can't rename: 400,
/// never 401 or 403, which sign the web vault out, and the same words for
/// each, so it says nothing about other organizations' folders.
const REFUSED: &str = "Only people who can rename this shared folder can change its icon.";

/// Encrypted with a symmetric key as upstream encrypts a folder's name:
/// `2.<iv>|<data>|<mac>`, each part base64, at most MAX_LOOK long.
pub fn valid_look(look: &str) -> bool {
    let Some(parts) = look.strip_prefix("2.") else {
        return false;
    };
    let parts: Vec<&str> = parts.split('|').collect();
    look.len() <= MAX_LOOK
        && parts.len() == 3
        && parts.iter().all(|p| !p.is_empty() && data_encoding::BASE64.decode(p.as_bytes()).is_ok())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LookData {
    /// The icon and color, encrypted with the organization's key; null (or
    /// left out) for the plain folder.
    look: Option<String>,
}

/// Sets or clears a shared folder's icon and color. Allowed for whoever may
/// rename it with upstream's `PUT /organizations/<org>/collections/<id>`: a
/// confirmed member who manages the folder (owners, admins, managers with
/// access to all items, and anyone whose grid there has manage, through a
/// group or directly; keykeeper_folder_permissions::manages), the same rule
/// that route's guard applies. Answers with the folder as a save does
/// (Collection::to_json_saved), the look in it.
#[put("/keykeeper/organizations/<org_id>/collections/<col_id>/look", data = "<data>")]
async fn put_look(
    org_id: OrganizationId,
    col_id: CollectionId,
    data: Json<LookData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let look = data.into_inner().look.filter(|l| !l.is_empty());
    if look.as_deref().is_some_and(|l| !valid_look(l)) {
        err!("A shared folder's icon must be encrypted with its organization's key.")
    }
    let Some(mut collection) = Collection::find_by_uuid_and_org(&col_id, &org_id, &conn).await else {
        err!(REFUSED)
    };
    // A database error is an error (500), not a refusal.
    if !keykeeper_folder_permissions::manages(&headers.user.uuid, &org_id, &col_id, &conn).await? {
        err!(REFUSED)
    }

    collection.keykeeper_look = look;
    // Saving tells the folder's people's apps to sync again, as a rename does.
    collection.save(&conn).await?;

    log_event(
        EventType::CollectionUpdated,
        &collection.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    Ok(Json(collection.to_json_saved(&headers.user.uuid, &conn).await))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_encrypted_look_is_kept() {
        assert!(valid_look("2.aXY=|Y3Q=|bWFj"));
        for refused in [
            r#"{"icon":"bank","tone":"emerald"}"#,
            "bank emerald",
            "0.aXY=|Y3Q=",
            "2.aXY=|Y3Q=",
            "2.aXY=||bWFj",
            "2.not base64!|Y3Q=|bWFj",
            "2.aXY=|Y3Q=|bWFj|bWFj",
        ] {
            assert!(!valid_look(refused), "{refused}");
        }
        let long = format!("2.aXY=|{}|bWFj", "A".repeat(MAX_LOOK));
        assert!(!valid_look(&long));
    }
}

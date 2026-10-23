// Keykeeper: an item's past versions, for whoever can open the item. The
// server keeps them as it stored them (keykeeper_cipher_versions) and can't
// read them; apps decrypt each like the item, and restore one by saving it as
// a normal edit. See DESIGN.md, "Item history".

use std::collections::{HashMap, HashSet};

use rocket::{Route, http::Status, serde::json::Json};
use serde_json::{Value, json};

use crate::{
    api::JsonResult,
    auth::Headers,
    db::{
        DbConn,
        models::{
            Cipher, CipherId, CipherVersion, Membership, User, UserId,
            keykeeper_roles::{self, Permission},
        },
    },
    util::format_date,
};

use super::{CipherSyncData, CipherSyncType};

pub fn routes() -> Vec<Route> {
    routes![get_history]
}

/// An item's past versions, newest first, each as an item to decrypt, with
/// when it was saved and by whom. Anyone who can't open the item gets 404,
/// the same as for an item that doesn't exist.
#[get("/keykeeper/ciphers/<cipher_id>/history")]
async fn get_history(cipher_id: CipherId, headers: Headers, conn: DbConn) -> JsonResult {
    let cipher = match Cipher::find_by_uuid(&cipher_id, &conn).await {
        Some(cipher) if cipher.is_accessible_to_user(&headers.user.uuid, &conn).await => cipher,
        _ => err_code!("Item not found", Status::NotFound.code),
    };

    let versions = CipherVersion::find_by_cipher(&cipher.uuid, &conn).await?;
    let mut editors = Editors::new(&cipher, &headers.user.uuid, &conn).await;
    let savers = CipherVersion::saved_by(&versions, cipher.user_uuid.as_ref());
    // As an organization's sync sends items: nothing per person, and no
    // attachments, folders, or collections, which aren't part of versions.
    let no_extras = no_sync_data();

    let mut data = Vec::with_capacity(versions.len());
    for (version, saved_by) in versions.iter().zip(savers) {
        let item = version
            .as_cipher(&cipher)
            .to_json(&headers.host, &headers.user.uuid, Some(&no_extras), CipherSyncType::Organization, &conn)
            .await?;
        data.push(json!({
            "object": "keykeeperCipherVersion",
            "id": version.uuid,
            "revisionDate": format_date(&version.revision_date),
            "replacedDate": format_date(&version.replaced_at),
            "savedBy": editors.view(saved_by, &conn).await,
            "cipher": item,
        }));
    }

    // Who saved what the item is now: whoever replaced its newest version.
    let current_saved_by = match versions.first() {
        Some(newest) => newest.replaced_by.as_ref(),
        None => cipher.user_uuid.as_ref(),
    };
    Ok(Json(json!({
        "object": "keykeeperCipherHistory",
        "cipherId": cipher.uuid,
        "revisionDate": format_date(&cipher.updated_at),
        "savedBy": editors.view(current_saved_by, &conn).await,
        "data": data,
    })))
}

fn no_sync_data() -> CipherSyncData {
    CipherSyncData {
        cipher_attachments: HashMap::new(),
        cipher_folders: HashMap::new(),
        cipher_favorites: HashSet::new(),
        cipher_collections: HashMap::new(),
        cipher_archives: HashMap::new(),
        members: HashMap::new(),
        user_collections: HashMap::new(),
        user_collections_groups: HashMap::new(),
        user_group_full_access_for_organizations: HashSet::new(),
    }
}

/// Who saved a version, as the caller may see them: by name and email to
/// themselves and to those who can list the organization's members; to other
/// members only that it was someone else.
struct Editors {
    caller: UserId,
    sees_members: bool,
    users: HashMap<UserId, Option<User>>,
}

impl Editors {
    async fn new(cipher: &Cipher, caller: &UserId, conn: &DbConn) -> Self {
        let sees_members = match &cipher.organization_uuid {
            // Only its owner reads a personal item's versions.
            None => true,
            Some(org) => match Membership::find_confirmed_by_user_and_org(caller, org, conn).await {
                Some(member) if member.has_full_access() => true,
                // The custom roles that list the members (keykeeper_roles).
                Some(member) => keykeeper_roles::find(&member.uuid, conn)
                    .await
                    .is_some_and(|role| role.has(Permission::ManageUsers) || role.has(Permission::ManageResetPassword)),
                None => false,
            },
        };
        Self {
            caller: caller.clone(),
            sees_members,
            users: HashMap::new(),
        }
    }

    /// Null when nobody is recorded (or their account is gone).
    async fn view(&mut self, who: Option<&UserId>, conn: &DbConn) -> Value {
        let Some(who) = who else {
            return Value::Null;
        };
        if !self.sees_members && *who != self.caller {
            return json!({ "id": null, "name": null, "email": null });
        }
        if !self.users.contains_key(who) {
            self.users.insert(who.clone(), User::find_by_uuid(who, conn).await);
        }
        match self.users.get(who) {
            Some(Some(user)) => json!({ "id": user.uuid, "name": user.name, "email": user.email }),
            _ => Value::Null,
        }
    }
}

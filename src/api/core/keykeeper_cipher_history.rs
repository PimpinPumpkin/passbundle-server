// Keykeeper: an item's past versions, for whoever can open the item. The
// server keeps them as it stored them (keykeeper_cipher_versions) and can't
// read them; apps decrypt each like the item, and restore one by saving it as
// a normal edit. Whoever can delete the item can clear its history. See
// DESIGN.md, "Item history".

use std::collections::{HashMap, HashSet};

use rocket::{Route, http::Status, serde::json::Json};
use serde_json::{Value, json};

use crate::{
    api::{EmptyResult, JsonResult, core::log_event},
    auth::Headers,
    db::{
        DbConn,
        models::{
            Cipher, CipherId, CipherVersion, EventType, Membership, MembershipType, User, UserId,
            keykeeper_folder_permissions::{Access, Grid, ways_to_cipher},
            keykeeper_roles::{self, Permission},
        },
    },
    util::format_date,
};

use super::{CipherSyncData, CipherSyncType};

pub fn routes() -> Vec<Route> {
    routes![get_history, clear_history, delete_version]
}

/// The item, and what the caller may do with it: (hide passwords, may clear
/// its history). Anyone who can't open it, or whose shared folders don't let
/// them view its history, gets 404, the same as for an item that doesn't
/// exist (DESIGN.md, "Folders and permissions"). Each needs both of its
/// capabilities in one way to the item, not one from each of two folders:
/// versions' contents need view item history and see passwords together,
/// and clearing needs view item history and delete together.
async fn readable(
    cipher_id: &CipherId,
    headers: &Headers,
    conn: &DbConn,
) -> Result<(Cipher, bool, bool), crate::Error> {
    if let Some(cipher) = Cipher::find_by_uuid(cipher_id, conn).await {
        let ways: Vec<Grid> =
            ways_to_cipher(&cipher, &headers.user.uuid, conn).await?.into_iter().filter(|g| g.view_history).collect();
        if !ways.is_empty() {
            let shows_passwords = ways.iter().any(|g| g.see_passwords);
            let clears = ways.iter().any(|g| g.delete);
            return Ok((cipher, !shows_passwords, clears));
        }
    }
    err_code!("Item not found", Status::NotFound.code)
}

/// An item's past versions, newest first, each as an item to decrypt, with
/// when it was saved and by whom. People who can't see the item's passwords
/// get when and by whom only: no version's encrypted fields.
#[get("/keykeeper/ciphers/<cipher_id>/history")]
async fn get_history(cipher_id: CipherId, headers: Headers, conn: DbConn) -> JsonResult {
    let (cipher, hide_passwords, _) = readable(&cipher_id, &headers, &conn).await?;
    let versions = CipherVersion::find_by_cipher(&cipher.uuid, &conn).await?;
    let mut editors = Editors::new(&cipher, &headers.user.uuid, &conn).await;
    // As an organization's sync sends items: nothing per person, and no
    // attachments, folders, or collections, which aren't part of versions.
    let no_extras = no_sync_data();

    let mut data = Vec::with_capacity(versions.len());
    for version in &versions {
        let item = if hide_passwords {
            Value::Null
        } else {
            version
                .as_cipher(&cipher)
                .to_json(&headers.host, &headers.user.uuid, Some(&no_extras), CipherSyncType::Organization, &conn)
                .await?
        };
        data.push(json!({
            "object": "keykeeperCipherVersion",
            "id": version.uuid,
            "revisionDate": format_date(&version.revision_date),
            "savedBy": editors.view(version.saved_by.as_ref(), &conn).await,
            "replacedDate": format_date(&version.replaced_at),
            "replacedBy": editors.view(version.replaced_by.as_ref(), &conn).await,
            "cipher": item,
        }));
    }

    let saved_by = CipherVersion::saved_by(&cipher.uuid, &conn).await;
    Ok(Json(json!({
        "object": "keykeeperCipherHistory",
        "cipherId": cipher.uuid,
        "revisionDate": format_date(&cipher.updated_at),
        "savedBy": editors.view(saved_by.as_ref(), &conn).await,
        "hidePasswords": hide_passwords,
        "data": data,
    })))
}

/// Clears an item's history, for those who may delete the item and view its
/// history in the same shared folder. Logged in
/// an organization's event log for its items.
#[delete("/keykeeper/ciphers/<cipher_id>/history")]
async fn clear_history(cipher_id: CipherId, headers: Headers, conn: DbConn) -> EmptyResult {
    let (cipher, _, can_delete) = readable(&cipher_id, &headers, &conn).await?;
    if !can_delete {
        // 400, not 403, which signs the web vault out.
        err!("You don't have permission to clear this item's history")
    }
    CipherVersion::delete_all_by_cipher(&cipher.uuid, &conn).await?;
    logged(EventType::KeykeeperCipherHistoryCleared, &cipher, &headers, &conn).await;
    Ok(())
}

/// Deletes one of an item's past versions, for those who may clear its history.
#[delete("/keykeeper/ciphers/<cipher_id>/history/<version_id>")]
async fn delete_version(cipher_id: CipherId, version_id: &str, headers: Headers, conn: DbConn) -> EmptyResult {
    let (cipher, _, can_delete) = readable(&cipher_id, &headers, &conn).await?;
    if !can_delete {
        err!("You don't have permission to delete this item's versions")
    }
    if !CipherVersion::delete_one(&cipher.uuid, version_id, &conn).await? {
        err_code!("Version not found", Status::NotFound.code)
    }
    logged(EventType::KeykeeperCipherVersionDeleted, &cipher, &headers, &conn).await;
    Ok(())
}

async fn logged(event: EventType, cipher: &Cipher, headers: &Headers, conn: &DbConn) {
    info!("{event:?}: item {} by {}", cipher.uuid, headers.user.uuid);
    if let Some(org_id) = &cipher.organization_uuid {
        log_event(event, &cipher.uuid, org_id, &headers.user.uuid, headers.device.atype, &headers.ip.ip, conn).await;
    }
}

fn no_sync_data() -> CipherSyncData {
    CipherSyncData {
        cipher_attachments: HashMap::new(),
        cipher_folders: HashMap::new(),
        cipher_favorites: HashSet::new(),
        cipher_collections: HashMap::new(),
        cipher_archives: HashMap::new(),
        members: HashMap::new(),
        access: Access::default(),
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
                Some(member) => lists_members(&member, conn).await,
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

/// Whether a confirmed member can list the organization's members, as
/// `GET /organizations/<id>/users` decides: a manager or above with access to
/// all items (owners and admins have it), or a custom role that manages
/// members or account recovery (keykeeper_roles).
async fn lists_members(member: &Membership, conn: &DbConn) -> bool {
    if member.atype >= MembershipType::Manager && member.has_full_access() {
        return true;
    }
    keykeeper_roles::find(&member.uuid, conn)
        .await
        .is_some_and(|role| role.has(Permission::ManageUsers) || role.has(Permission::ManageResetPassword))
}

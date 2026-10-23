// Keykeeper: custom roles with real permissions. Upstream's member dialog
// offers a "Custom" role with permissions; Vaultwarden ignores them and treats
// Custom as the old Manager role. Here a custom member is a regular member
// (upstream's User type) plus the permissions in this table, which the admin
// guard honors only for the endpoints listed in ROUTES below.
//
// A custom member acts with an admin's rules but only on regular members: never
// on themselves, admins, owners, or other custom members, and they can't grant
// roles, permissions, or access to all items. See DESIGN.md, "Roles and
// permissions".
//
// Endpoints a custom member's permissions don't cover refuse them with 403, not
// upstream's 401, so a client can tell a missing permission from an expired
// session. The manager guards answer 404 instead, as they do for every
// confirmed member (refuse_on_manager_route).

use std::collections::HashMap;

use diesel::prelude::*;
use rocket::{
    Request,
    http::{Method, Status},
    outcome::Outcome,
    request,
};
use serde_json::Value;

use crate::{
    api::{ApiResult, EmptyResult},
    db::{DbConn, keykeeper_schema::membership_permissions},
    error::MapResult,
};

use super::{
    CollectionId, Membership, MembershipId, MembershipStatus, MembershipType, OrganizationId, UserId,
    keykeeper_folder_permissions::{Access, Grid},
};

/// What a custom role can be allowed to do, by upstream's permission names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    /// Invite, confirm, remove, revoke, restore, and edit regular members.
    ManageUsers,
    /// Recover regular members' accounts.
    ManageResetPassword,
    ManagePolicies,
    AccessEventLogs,
    /// Export the organization's vault.
    AccessImportExport,
}

impl Permission {
    pub const ALL: [Permission; 5] =
        [ManageUsers, ManageResetPassword, ManagePolicies, AccessEventLogs, AccessImportExport];

    /// How the MSP audit log names it.
    pub fn label(self) -> &'static str {
        match self {
            ManageUsers => "manage users",
            ManageResetPassword => "account recovery",
            ManagePolicies => "policies",
            AccessEventLogs => "event logs",
            AccessImportExport => "import and export",
        }
    }

    /// The name upstream's clients use.
    pub fn key(self) -> &'static str {
        match self {
            ManageUsers => "manageUsers",
            ManageResetPassword => "manageResetPassword",
            ManagePolicies => "managePolicies",
            AccessEventLogs => "accessEventLogs",
            AccessImportExport => "accessImportExport",
        }
    }
}

use Permission::{AccessEventLogs, AccessImportExport, ManagePolicies, ManageResetPassword, ManageUsers};

/// Upstream's "Manage all collections" permissions, which custom roles can't have.
const COLLECTION_PERMISSIONS: [&str; 3] = ["createNewCollections", "editAnyCollection", "deleteAnyCollection"];

/// The endpoints a custom role can reach, and the permissions that each
/// accepts (any one of them). Every other admin endpoint needs an owner or
/// admin. Paths are route templates, without the "/api" mount or the query.
const ROUTES: &[(Method, &str, &[Permission])] = &[
    // Members
    (Method::Get, "/organizations/<org_id>/users", &[ManageUsers, ManageResetPassword]),
    (Method::Get, "/organizations/<org_id>/users/<member_id>", &[ManageUsers, ManageResetPassword]),
    (Method::Post, "/organizations/<org_id>/users/invite", &[ManageUsers]),
    (Method::Post, "/organizations/<org_id>/users/reinvite", &[ManageUsers]),
    (Method::Post, "/organizations/<org_id>/users/<member_id>/reinvite", &[ManageUsers]),
    (Method::Post, "/organizations/<org_id>/users/public-keys", &[ManageUsers]),
    (Method::Post, "/organizations/<org_id>/users/confirm", &[ManageUsers]),
    (Method::Post, "/organizations/<org_id>/users/<member_id>/confirm", &[ManageUsers]),
    (Method::Put, "/organizations/<org_id>/users/<member_id>", &[ManageUsers]),
    (Method::Delete, "/organizations/<org_id>/users", &[ManageUsers]),
    (Method::Delete, "/organizations/<org_id>/users/<member_id>", &[ManageUsers]),
    (Method::Put, "/organizations/<org_id>/users/revoke", &[ManageUsers]),
    (Method::Put, "/organizations/<org_id>/users/<member_id>/revoke", &[ManageUsers]),
    (Method::Put, "/organizations/<org_id>/users/restore", &[ManageUsers]),
    (Method::Put, "/organizations/<org_id>/users/<member_id>/restore", &[ManageUsers]),
    (Method::Put, "/organizations/<org_id>/users/<member_id>/restore/vnext", &[ManageUsers]),
    // The Members page loads the collection list for its Collections column.
    (Method::Get, "/organizations/<org_id>/collections", &[ManageUsers, ManageResetPassword]),
    // The invite and edit dialogs and the import page load this one. For a
    // member without access to all items it lists only the collections
    // they're assigned to.
    (Method::Get, "/organizations/<org_id>/collections/details", &[ManageUsers, AccessImportExport]),
    // The Members page loads the group list for its Groups column, and the
    // invite and edit dialogs the groups with their collections. Read only:
    // creating, editing, or deleting groups and changing anyone's groups need
    // an owner or admin. For a member without access to all items, each group
    // lists only the collections they reach.
    (Method::Get, "/organizations/<org_id>/groups", &[ManageUsers, ManageResetPassword]),
    (Method::Get, "/organizations/<org_id>/groups/details", &[ManageUsers]),
    // Account recovery
    (Method::Get, "/organizations/<org_id>/users/<member_id>/reset-password-details", &[ManageResetPassword]),
    (Method::Put, "/organizations/<org_id>/users/<member_id>/recover-account", &[ManageResetPassword]),
    // Policies
    (Method::Get, "/organizations/<org_id>/policies", &[ManagePolicies]),
    (Method::Get, "/organizations/<org_id>/policies/<pol_type>", &[ManagePolicies]),
    (Method::Put, "/organizations/<org_id>/policies/<pol_type>", &[ManagePolicies]),
    // Event logs
    (Method::Get, "/organizations/<org_id>/events", &[AccessEventLogs]),
    (Method::Get, "/organizations/<org_id>/users/<member_id>/events", &[AccessEventLogs]),
    // The event log loads the members' names and emails to say who acted.
    // Read only, and only what the endpoint gives anyone who can call it.
    (Method::Get, "/organizations/<org_id>/users/mini-details", &[AccessEventLogs]),
    // Export
    (Method::Get, "/organizations/<org_id>/export", &[AccessImportExport]),
];

/// The permissions that admit a custom role to this request's route, if any.
pub fn route_permissions(method: Method, path: &str) -> &'static [Permission] {
    ROUTES.iter().find(|(m, p, _)| *m == method && *p == path).map_or(&[], |(_, _, perms)| *perms)
}

/// A custom role's permissions.
#[expect(clippy::struct_excessive_bools, reason = "One flag per upstream permission, as clients send them")]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomPermissions {
    #[serde(default)]
    pub manage_users: bool,
    #[serde(default)]
    pub manage_reset_password: bool,
    #[serde(default)]
    pub manage_policies: bool,
    #[serde(default)]
    pub access_event_logs: bool,
    #[serde(default)]
    pub access_import_export: bool,
}

impl CustomPermissions {
    pub fn has(&self, permission: Permission) -> bool {
        match permission {
            ManageUsers => self.manage_users,
            ManageResetPassword => self.manage_reset_password,
            ManagePolicies => self.manage_policies,
            AccessEventLogs => self.access_event_logs,
            AccessImportExport => self.access_import_export,
        }
    }

    pub fn any(&self) -> bool {
        Permission::ALL.iter().any(|p| self.has(*p))
    }

    /// The custom role an invite or edit asks for: upstream's Custom type ("4")
    /// with at least one of our permissions. Otherwise None, and upstream's own
    /// handling of Custom applies.
    ///
    /// A custom role can't also manage collections. We don't enforce those
    /// permissions for custom roles yet, so the admin console's collection
    /// tools would refuse them, and the web vault signs out on those refusals.
    /// Upstream's Custom with only the collection permissions (a Manager)
    /// still works.
    pub fn from_request(raw_type: &str, permissions: &HashMap<String, Value>) -> ApiResult<Option<Self>> {
        if raw_type != "4" && raw_type != "Custom" {
            return Ok(None);
        }
        let granted = |p: Permission| permissions.get(p.key()) == Some(&Value::Bool(true));
        let role = Self {
            manage_users: granted(ManageUsers),
            manage_reset_password: granted(ManageResetPassword),
            manage_policies: granted(ManagePolicies),
            access_event_logs: granted(AccessEventLogs),
            access_import_export: granted(AccessImportExport),
        };
        if !role.any() {
            return Ok(None);
        }
        if COLLECTION_PERMISSIONS.iter().any(|p| permissions.get(*p) == Some(&Value::Bool(true))) {
            err!(
                "Custom roles can't also manage all collections yet. Give them access to the collections they need, or make them an admin."
            )
        }
        Ok(Some(role))
    }

    /// Upstream's full permissions object, as clients expect it. It never
    /// shows a custom role as managing collections, even with access to all
    /// items (an MSP technician's vault access): the admin console's collection
    /// tools need permissions custom roles don't have, and its refusals would
    /// sign them out. They see and edit those items in their own vault.
    pub fn to_client_json(&self) -> Value {
        json!({
            "accessEventLogs": self.access_event_logs,
            "accessImportExport": self.access_import_export,
            "accessReports": false,
            "createNewCollections": false,
            "editAnyCollection": false,
            "deleteAnyCollection": false,
            "manageGroups": false,
            "managePolicies": self.manage_policies,
            "manageSso": false,
            "manageUsers": self.manage_users,
            "manageResetPassword": self.manage_reset_password,
            "manageScim": false,
        })
    }
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = membership_permissions)]
#[diesel(primary_key(membership_uuid))]
struct MembershipPermissions {
    membership_uuid: MembershipId,
    permissions: String,
}

/// A membership's custom role, if it has one.
pub async fn find(member_id: &MembershipId, conn: &DbConn) -> Option<CustomPermissions> {
    let row = conn
        .run(move |conn| {
            membership_permissions::table
                .filter(membership_permissions::membership_uuid.eq(member_id))
                .first::<MembershipPermissions>(conn)
                .ok()
        })
        .await?;
    serde_json::from_str(&row.permissions).ok()
}

/// Gives a membership a custom role, or takes it away with None.
pub async fn set(member_id: &MembershipId, role: Option<&CustomPermissions>, conn: &DbConn) -> EmptyResult {
    let id = member_id.clone();
    let deleted: EmptyResult = conn
        .run(move |conn| {
            diesel::delete(membership_permissions::table.filter(membership_permissions::membership_uuid.eq(id)))
                .execute(conn)
                .map_res("Error removing a custom role")
        })
        .await;
    deleted?;
    let Some(role) = role else {
        return Ok(());
    };
    let row = MembershipPermissions {
        membership_uuid: member_id.clone(),
        permissions: serde_json::to_string(role).unwrap_or_default(),
    };
    conn.run(move |conn| {
        diesel::insert_into(membership_permissions::table)
            .values(&row)
            .execute(conn)
            .map_res("Error saving a custom role")
    })
    .await
}

/// For the admin guard: the custom role that admits this member to this
/// request, if their permissions cover its route. Owners and admins don't use
/// this; they're admitted as before.
pub async fn admitted(request: &Request<'_>, member: &Membership) -> Option<CustomPermissions> {
    let route = request.route()?;
    let needed = route_permissions(route.method, route.uri.unmounted_origin.path().as_str());
    if needed.is_empty() || member.atype != MembershipType::User as i32 {
        return None;
    }
    let Outcome::Success(conn) = request.guard::<DbConn>().await else {
        return None;
    };
    let role = find(&member.uuid, &conn).await?;
    needed.iter().any(|p| role.has(*p)).then_some(role)
}

/// For the org guards, when they turn a member away: 403 for a custom member,
/// whose session is fine but whose role doesn't cover this endpoint, and
/// upstream's 401 for everyone else.
pub async fn refuse<S>(
    request: &Request<'_>,
    member: &Membership,
    message: &'static str,
) -> request::Outcome<S, &'static str> {
    let custom = member.atype == MembershipType::User as i32
        && match request.guard::<DbConn>().await {
            Outcome::Success(conn) => find(&member.uuid, &conn).await.is_some(),
            _ => false,
        };
    if custom {
        error!(target: "auth", "Forbidden Error: {message}");
        return Outcome::Error((Status::Forbidden, message));
    }
    error!(target: "auth", "Unauthorized Error: {message}");
    Outcome::Error((Status::Unauthorized, message))
}

/// For the manager guards: as refuse, but any confirmed member, custom or
/// not, gets 404, as for something that isn't there. A member's web vault can
/// reach a folder's endpoints (a folder they manage, or one they just stopped
/// managing), and 401 or 403 would sign them out.
pub async fn refuse_on_manager_route<S>(
    request: &Request<'_>,
    member: &Membership,
    message: &'static str,
) -> request::Outcome<S, &'static str> {
    if member.status == MembershipStatus::Confirmed as i32 {
        error!(target: "auth", "Not found: {message}");
        return Outcome::Error((Status::NotFound, message));
    }
    refuse(request, member, message).await
}

/// Refuses a custom member's action on anyone but a regular member: not
/// themselves, admins, owners, or other custom members.
pub async fn ensure_regular_target(
    acting_as: Option<&CustomPermissions>,
    actor: &UserId,
    target: &Membership,
    conn: &DbConn,
) -> EmptyResult {
    if acting_as.is_none() {
        return Ok(());
    }
    if &target.user_uuid == actor {
        err!("You can't change your own membership")
    }
    if target.atype != MembershipType::User as i32 || find(&target.uuid, conn).await.is_some() {
        err!("Your role can only manage regular members")
    }
    Ok(())
}

/// Refuses a custom member's attempt to grant more than a regular member:
/// another role, a custom role, or access to all items.
pub fn ensure_regular_grant(
    acting_as: Option<&CustomPermissions>,
    new_type: i32,
    custom_role: Option<&CustomPermissions>,
    access_all: bool,
) -> EmptyResult {
    if acting_as.is_some() && (new_type != MembershipType::User as i32 || custom_role.is_some() || access_all) {
        err!("Your role can only add regular members, without access to all items")
    }
    Ok(())
}

/// The collections a custom member can give others, and what they can give in
/// each: what they have there themselves, merged over all their ways in
/// (DESIGN.md, "Folders and permissions"), or anything but manage in every
/// collection for a member with access to all items. A custom role never
/// grants more than it has (DESIGN.md, "Roles and permissions"): otherwise a
/// role that manages users could give a second account of its own every item,
/// and "no vault items" for a technician would mean nothing.
pub enum Reach {
    All,
    Only(HashMap<CollectionId, Grid>),
}

impl Reach {
    pub async fn of(actor: &UserId, org_id: &OrganizationId, conn: &DbConn) -> ApiResult<Self> {
        let access = Access::in_org(actor, org_id, conn).await?;
        Ok(if access.has_full(org_id) {
            Self::All
        } else {
            Self::Only(access.folders)
        })
    }

    pub fn contains(&self, collection: &CollectionId) -> bool {
        match self {
            Self::All => true,
            Self::Only(mine) => mine.contains_key(collection),
        }
    }

    /// Refuses giving a collection the actor doesn't reach, any capability
    /// there the actor doesn't have, or the right to manage it. The grant is
    /// checked as it will be saved, so a request with only upstream's fields
    /// is checked as the preset they name.
    pub fn ensure_grant(&self, collection: &CollectionId, grant: &Grid) -> EmptyResult {
        if grant.manage {
            err!("Your role can't give others the right to manage a collection")
        }
        match self {
            Self::All => Ok(()),
            Self::Only(mine) => match mine.get(collection) {
                None => err!("Your role can only give access to collections it can reach"),
                Some(own) if !grant.within(own) => {
                    err!("Your role can't give more access to a collection than it has")
                }
                Some(_) => Ok(()),
            },
        }
    }
}

/// Refuses a technician role that could export a client's vault without
/// access to all items: the export holds every item, so it's the same as
/// access to all items, and the org key decrypts it. A client's own custom
/// roles can't have access to all items yet, so they keep import and the
/// export itself refuses them (get_org_export).
pub fn ensure_export_needs_items(custom_role: Option<&CustomPermissions>, access_all: bool) -> EmptyResult {
    if custom_role.is_some_and(|r| r.access_import_export) && !access_all {
        err!("Import and export gives every item in the organization, so it needs access to all items too")
    }
    Ok(())
}

/// What clients see for a membership: Custom (4) with the role's permissions,
/// or whatever upstream decided.
pub async fn client_type_and_permissions(
    member: &Membership,
    upstream_type: i32,
    upstream_permissions: Value,
    conn: &DbConn,
) -> (i32, Value) {
    match find(&member.uuid, conn).await {
        Some(role) => (4, role.to_client_json()),
        None => (upstream_type, upstream_permissions),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_route_has_a_permission_and_appears_once() {
        for (i, (method, path, perms)) in ROUTES.iter().enumerate() {
            assert!(!perms.is_empty(), "{method} {path} has no permission");
            assert!(!ROUTES[i + 1..].iter().any(|(m, p, _)| m == method && p == path), "{method} {path} appears twice");
        }
    }

    #[test]
    fn unknown_routes_admit_no_custom_role() {
        assert!(route_permissions(Method::Delete, "/organizations/<org_id>").is_empty());
        assert!(route_permissions(Method::Post, "/organizations/<org_id>/api-key").is_empty());
        assert!(route_permissions(Method::Put, "/organizations/<org_id>").is_empty());
        assert_eq!(route_permissions(Method::Put, "/organizations/<org_id>/policies/<pol_type>"), &[ManagePolicies]);
    }

    #[test]
    fn the_members_page_member_dialog_and_import_page_can_load_their_collections() {
        assert_eq!(
            route_permissions(Method::Get, "/organizations/<org_id>/collections"),
            route_permissions(Method::Get, "/organizations/<org_id>/users")
        );
        assert_eq!(
            route_permissions(Method::Get, "/organizations/<org_id>/collections/details"),
            &[ManageUsers, AccessImportExport]
        );
        assert!(route_permissions(Method::Post, "/organizations/<org_id>/collections").is_empty());
        assert!(route_permissions(Method::Get, "/organizations/<org_id>/collections/<col_id>/details").is_empty());
    }

    #[test]
    fn the_members_page_and_member_dialogs_read_groups_and_never_change_them() {
        assert_eq!(
            route_permissions(Method::Get, "/organizations/<org_id>/groups"),
            route_permissions(Method::Get, "/organizations/<org_id>/users")
        );
        assert_eq!(route_permissions(Method::Get, "/organizations/<org_id>/groups/details"), &[ManageUsers]);
        for (method, path) in [
            (Method::Post, "/organizations/<org_id>/groups"),
            (Method::Delete, "/organizations/<org_id>/groups"),
            (Method::Get, "/organizations/<org_id>/groups/<group_id>"),
            (Method::Get, "/organizations/<org_id>/groups/<group_id>/details"),
            (Method::Get, "/organizations/<org_id>/groups/<group_id>/users"),
            (Method::Put, "/organizations/<org_id>/groups/<group_id>"),
            (Method::Delete, "/organizations/<org_id>/groups/<group_id>"),
        ] {
            assert!(route_permissions(method, path).is_empty(), "{method} {path}");
        }
    }

    #[test]
    fn the_event_log_can_name_who_acted() {
        assert_eq!(route_permissions(Method::Get, "/organizations/<org_id>/users/mini-details"), &[AccessEventLogs]);
        assert_eq!(
            route_permissions(Method::Get, "/organizations/<org_id>/events"),
            route_permissions(Method::Get, "/organizations/<org_id>/users/mini-details")
        );
    }

    #[test]
    fn only_custom_type_with_our_permissions_is_a_custom_role() {
        let perms = |pairs: &[(&str, bool)]| -> HashMap<String, Value> {
            pairs.iter().map(|(k, v)| ((*k).to_owned(), Value::Bool(*v))).collect()
        };
        assert_eq!(CustomPermissions::from_request("2", &perms(&[("manageUsers", true)])).ok(), Some(None));
        assert_eq!(CustomPermissions::from_request("4", &perms(&[("editAnyCollection", true)])).ok(), Some(None));
        assert_eq!(CustomPermissions::from_request("4", &perms(&[("manageUsers", false)])).ok(), Some(None));
        let role = CustomPermissions::from_request("4", &perms(&[("manageUsers", true), ("managePolicies", true)]));
        assert_eq!(
            role.ok(),
            Some(Some(CustomPermissions {
                manage_users: true,
                manage_policies: true,
                ..Default::default()
            }))
        );
    }

    #[test]
    fn a_custom_role_cant_also_manage_collections() {
        let perms = |pairs: &[(&str, bool)]| -> HashMap<String, Value> {
            pairs.iter().map(|(k, v)| ((*k).to_owned(), Value::Bool(*v))).collect()
        };
        for collection_permission in COLLECTION_PERMISSIONS {
            let asked = perms(&[("manageUsers", true), (collection_permission, true)]);
            assert!(CustomPermissions::from_request("4", &asked).is_err(), "{collection_permission}");
        }
        // Upstream's Custom with only the collection permissions is still upstream's.
        let all_collections =
            perms(&[("createNewCollections", true), ("editAnyCollection", true), ("deleteAnyCollection", true)]);
        assert_eq!(CustomPermissions::from_request("4", &all_collections).ok(), Some(None));
        // Unchecked boxes are fine.
        let unchecked = perms(&[("manageUsers", true), ("editAnyCollection", false)]);
        assert!(CustomPermissions::from_request("4", &unchecked).is_ok_and(|role| role.is_some()));

        let shown = CustomPermissions {
            manage_users: true,
            ..Default::default()
        }
        .to_client_json();
        for collection_permission in COLLECTION_PERMISSIONS {
            assert_eq!(shown[collection_permission], Value::Bool(false), "{collection_permission}");
        }
    }
}

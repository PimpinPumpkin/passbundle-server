// Keykeeper: custom roles with real permissions. Upstream's member dialog
// offers a "Custom" role with permissions; Vaultwarden ignores them and treats
// Custom as the old Manager role. Here a custom member is a regular member
// (upstream's User type) plus the permissions in this table, which the admin
// and manager guards honor only for the endpoints listed in ROUTES below.
// Access to all items is upstream's own flag on the membership (access_all),
// which owners and admins give.
//
// A custom member acts with an admin's rules but only on regular members: never
// on themselves, admins, owners, or other custom members, and they can't grant
// roles, permissions, or access to all items. What they give others is never
// more than they have (Reach, check_folder_access, check_group_change). See
// DESIGN.md, "Roles and permissions".
//
// Endpoints a custom member's permissions don't cover answer 404, "You can't do
// that here.", never upstream's 401 or 403, on both of which the web vault signs
// out (refuse).

use std::collections::{HashMap, HashSet};

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
    CollectionId, Group, GroupId, GroupUser, Membership, MembershipId, MembershipStatus, MembershipType,
    OrganizationId, UserId,
    keykeeper_folder_permissions::{Access, Grid, Stored},
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
    /// Import into the organization, and export it with access to all items.
    AccessImportExport,
    /// Make shared folders, and rename, delete, and set who reaches the ones
    /// they reach themselves (check_folder_access).
    ManageCollections,
    /// Make, edit, and delete groups, and who's in them (check_group_change).
    ManageGroups,
    /// The organization's reports, over the items they reach.
    AccessReports,
}

impl Permission {
    pub const ALL: [Permission; 8] = [
        ManageUsers,
        ManageResetPassword,
        ManagePolicies,
        AccessEventLogs,
        AccessImportExport,
        ManageCollections,
        ManageGroups,
        AccessReports,
    ];

    /// How the MSP audit log names it.
    pub fn label(self) -> &'static str {
        match self {
            ManageUsers => "manage users",
            ManageResetPassword => "account recovery",
            ManagePolicies => "policies",
            AccessEventLogs => "event logs",
            AccessImportExport => "import and export",
            ManageCollections => "shared folders",
            ManageGroups => "groups",
            AccessReports => "reports",
        }
    }

    /// The name clients use: upstream's, or ours for managing shared folders,
    /// which isn't upstream's "Manage all collections".
    pub fn key(self) -> &'static str {
        match self {
            ManageUsers => "manageUsers",
            ManageResetPassword => "manageResetPassword",
            ManagePolicies => "managePolicies",
            AccessEventLogs => "accessEventLogs",
            AccessImportExport => "accessImportExport",
            ManageCollections => "keykeeperManageCollections",
            ManageGroups => "manageGroups",
            AccessReports => "accessReports",
        }
    }
}

use Permission::{
    AccessEventLogs, AccessImportExport, AccessReports, ManageCollections, ManageGroups, ManagePolicies,
    ManageResetPassword, ManageUsers,
};

/// Where clients ask for, and see, a custom role's access to all items.
pub const ACCESS_ALL_KEY: &str = "keykeeperAccessAllItems";

/// Upstream's "Manage all collections" permissions. All three on upstream's
/// Custom, without our permissions, is upstream's manager of every collection.
/// With ours, only "create new collections" goes, and only beside our own
/// "manage shared folders", which it means anyway; edit any and delete any
/// would reach collections the role doesn't.
const COLLECTION_PERMISSIONS: [&str; 3] = ["createNewCollections", "editAnyCollection", "deleteAnyCollection"];

/// What the web vault shows when a custom member's role doesn't cover a
/// request (refuse).
pub const CANT_DO_THAT_HERE: &str = "You can't do that here.";

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
    // The collection names: the Members page's Collections column and the
    // Groups page's.
    (
        Method::Get,
        "/organizations/<org_id>/collections",
        &[ManageUsers, ManageResetPassword, ManageCollections, ManageGroups],
    ),
    // The collections with who reaches them: the member, folder, and group
    // dialogs, the Collections page, and the import page. For a member without
    // access to all items it lists only the collections they're assigned to.
    (
        Method::Get,
        "/organizations/<org_id>/collections/details",
        &[ManageUsers, AccessImportExport, ManageCollections, ManageGroups],
    ),
    // Shared folders: making them, and renaming, deleting, and setting who
    // reaches the ones they reach (check_folder_access, may_delete_folder).
    (Method::Post, "/organizations/<org_id>/collections", &[ManageCollections]),
    (Method::Post, "/organizations/<org_id>/collections/bulk-access", &[ManageCollections]),
    (Method::Get, "/organizations/<org_id>/collections/<col_id>/details", &[ManageCollections]),
    (Method::Get, "/organizations/<org_id>/collections/<col_id>/users", &[ManageCollections]),
    (Method::Put, "/organizations/<org_id>/collections/<col_id>", &[ManageCollections]),
    (Method::Delete, "/organizations/<org_id>/collections/<col_id>", &[ManageCollections]),
    (Method::Delete, "/organizations/<org_id>/collections", &[ManageCollections]),
    // The group names: the Members page's Groups column, the Collections
    // page, and the folder dialog's choices.
    (
        Method::Get,
        "/organizations/<org_id>/groups",
        &[ManageUsers, ManageResetPassword, ManageCollections, ManageGroups],
    ),
    // The groups with their collections: the member dialogs and the Groups
    // page. For a member without access to all items, each group lists only
    // the collections they reach.
    (Method::Get, "/organizations/<org_id>/groups/details", &[ManageUsers, ManageGroups]),
    // Groups: making, editing, and deleting them, and who's in them
    // (check_group_change, may_delete_group).
    (Method::Post, "/organizations/<org_id>/groups", &[ManageGroups]),
    (Method::Get, "/organizations/<org_id>/groups/<group_id>", &[ManageGroups]),
    (Method::Get, "/organizations/<org_id>/groups/<group_id>/details", &[ManageGroups]),
    (Method::Get, "/organizations/<org_id>/groups/<group_id>/users", &[ManageGroups]),
    (Method::Put, "/organizations/<org_id>/groups/<group_id>", &[ManageGroups]),
    (Method::Delete, "/organizations/<org_id>/groups/<group_id>", &[ManageGroups]),
    (Method::Delete, "/organizations/<org_id>/groups", &[ManageGroups]),
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
    // The members' names and emails: the event log says who acted, and the
    // folder and group dialogs list whom to give access. Read only, and only
    // what the endpoint gives anyone who can call it.
    (Method::Get, "/organizations/<org_id>/users/mini-details", &[AccessEventLogs, ManageCollections, ManageGroups]),
    // The organization's items: the reports, and the Collections page for a
    // member with access to all items. Only the items they reach
    // (get_org_details).
    (Method::Get, "/ciphers/organization-details", &[AccessReports, ManageCollections]),
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
    #[serde(default)]
    pub manage_collections: bool,
    #[serde(default)]
    pub manage_groups: bool,
    #[serde(default)]
    pub access_reports: bool,
}

impl CustomPermissions {
    pub fn has(&self, permission: Permission) -> bool {
        match permission {
            ManageUsers => self.manage_users,
            ManageResetPassword => self.manage_reset_password,
            ManagePolicies => self.manage_policies,
            AccessEventLogs => self.access_event_logs,
            AccessImportExport => self.access_import_export,
            ManageCollections => self.manage_collections,
            ManageGroups => self.manage_groups,
            AccessReports => self.access_reports,
        }
    }

    pub fn any(&self) -> bool {
        Permission::ALL.iter().any(|p| self.has(*p))
    }

    /// The custom role an invite or edit asks for: upstream's Custom type ("4")
    /// with at least one of our permissions, or access to all items. Otherwise
    /// None, and upstream's own handling of Custom applies (with all three
    /// collection permissions, a manager of every collection).
    ///
    /// Our permissions combine with each other freely. Upstream's "edit any
    /// collection" and "delete any collection" don't combine with them: they
    /// reach every collection, which a custom role's limits don't allow. A
    /// custom role manages shared folders with ours (ManageCollections), and
    /// sees every item with access to all items.
    pub fn from_request(raw_type: &str, permissions: &HashMap<String, Value>) -> ApiResult<Option<Self>> {
        if raw_type != "4" && raw_type != "Custom" {
            return Ok(None);
        }
        let granted = |key: &str| permissions.get(key) == Some(&Value::Bool(true));
        let role = Self {
            manage_users: granted(ManageUsers.key()),
            manage_reset_password: granted(ManageResetPassword.key()),
            manage_policies: granted(ManagePolicies.key()),
            access_event_logs: granted(AccessEventLogs.key()),
            access_import_export: granted(AccessImportExport.key()),
            manage_collections: granted(ManageCollections.key()),
            manage_groups: granted(ManageGroups.key()),
            access_reports: granted(AccessReports.key()),
        };
        if !role.any() && !granted(ACCESS_ALL_KEY) {
            return Ok(None);
        }
        // "Create new collections" is what managing shared folders shows as
        // (to_client_json), so a client sending a role back may send it.
        let upstream_collections = COLLECTION_PERMISSIONS
            .iter()
            .any(|p| granted(p) && !(*p == "createNewCollections" && role.manage_collections));
        if upstream_collections {
            err!(
                "Custom roles can't also manage all collections. Give them Manage shared folders, and Access to all items if they need every item."
            )
        }
        Ok(Some(role))
    }

    /// Upstream's full permissions object, as clients expect it, with ours
    /// beside it. Managing shared folders shows as upstream's "create new
    /// collections", which the apps read to offer making one, and never as
    /// editing or deleting any collection: the web vault would then load every
    /// item and offer every collection's tools, which a custom role's limits
    /// refuse. Access to all items is the membership's (access_all).
    pub fn to_client_json(&self, access_all: bool) -> Value {
        let mut shown = json!({
            "accessEventLogs": self.access_event_logs,
            "accessImportExport": self.access_import_export,
            "accessReports": self.access_reports,
            "createNewCollections": self.manage_collections,
            "editAnyCollection": false,
            "deleteAnyCollection": false,
            "manageGroups": self.manage_groups,
            "managePolicies": self.manage_policies,
            "manageSso": false,
            "manageUsers": self.manage_users,
            "manageResetPassword": self.manage_reset_password,
            "manageScim": false,
            "keykeeperManageCollections": self.manage_collections,
        });
        shown[ACCESS_ALL_KEY] = json!(access_all);
        shown
    }
}

/// Whether an invite or edit asks for a custom role with access to all items.
/// Only with a custom role (from_request): owners and admins have it anyway,
/// and upstream's manager of every collection gets it from its permissions.
pub fn access_all_requested(custom_role: Option<&CustomPermissions>, permissions: &HashMap<String, Value>) -> bool {
    custom_role.is_some() && permissions.get(ACCESS_ALL_KEY) == Some(&Value::Bool(true))
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

/// Marks a request a custom member's role doesn't cover, so the API's 404
/// answers "You can't do that here." (api_not_found in api/core/mod.rs).
#[derive(Clone, Copy, Default)]
pub struct RefusedByRole(pub bool);

/// Whether a guard turned this request away from a custom member.
pub fn refused_by_role(request: &Request<'_>) -> bool {
    request.local_cache(RefusedByRole::default).0
}

fn not_here<S>(request: &Request<'_>, message: &'static str) -> request::Outcome<S, &'static str> {
    request.local_cache(|| RefusedByRole(true));
    error!(target: "auth", "Not found (custom role): {message}");
    Outcome::Error((Status::NotFound, CANT_DO_THAT_HERE))
}

/// For the org guards, when they turn a member away: 404, "You can't do that
/// here.", for a custom member, whose session is fine but whose role doesn't
/// cover this endpoint, and upstream's 401 for everyone else. Not 403: the web
/// vault signs out on 403 as well as 401, so a page their role doesn't cover
/// would sign them out (DESIGN.md, "Roles and permissions", B30). 404 is what
/// the MSP's endpoints and the manager guards answer too.
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
        return not_here(request, message);
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
        let custom = member.atype == MembershipType::User as i32
            && match request.guard::<DbConn>().await {
                Outcome::Success(conn) => find(&member.uuid, &conn).await.is_some(),
                _ => false,
            };
        if custom {
            return not_here(request, message);
        }
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

    /// What the actor has in a collection themselves, or None where they
    /// don't reach it: every capability but manage everywhere, with access to
    /// all items.
    pub fn own(&self, collection: &CollectionId) -> Option<Grid> {
        match self {
            Self::All => Some(Grid::EVERY_ITEM),
            Self::Only(mine) => mine.get(collection).copied(),
        }
    }

    /// With a shared folder the actor just made, where they have every
    /// capability but manage: a custom role never manages a folder, not even
    /// one it made (post_organization_collections).
    #[must_use]
    pub fn with_new(self, collection: &CollectionId) -> Self {
        match self {
            Self::All => Self::All,
            Self::Only(mut mine) => {
                mine.insert(collection.clone(), Grid::EVERY_ITEM);
                Self::Only(mine)
            }
        }
    }

    /// Whether a group gives nothing beyond the actor's own access: not every
    /// item, and in each collection it reaches, one the actor reaches, with no
    /// capability the actor doesn't have there, and never manage. Only such a
    /// group can a custom role add people to, take people out of, or delete:
    /// adding someone to any other gives them what the role doesn't have.
    pub fn covers_group(&self, group: &GroupState) -> bool {
        !group.access_all
            && group.grants.iter().all(|(c, g)| !g.manage && self.own(c).is_some_and(|own| g.within(&own)))
    }

    /// Refuses a shared folder the actor doesn't reach: a custom role that
    /// manages shared folders renames, deletes, and sets who reaches only
    /// those (DESIGN.md, "Roles and permissions").
    pub fn ensure_reaches(&self, collection: &CollectionId) -> EmptyResult {
        if !self.contains(collection) {
            err!("Your role can only change shared folders it reaches")
        }
        Ok(())
    }

    /// Refuses deleting a shared folder unless the actor reaches it and can
    /// delete items there: deleting it takes its items from everyone without
    /// access to all items.
    pub fn ensure_may_delete_folder(&self, collection: &CollectionId) -> EmptyResult {
        self.ensure_reaches(collection)?;
        if !self.own(collection).is_some_and(|own| own.delete) {
            err!("Your role can only delete a shared folder where it can delete items")
        }
        Ok(())
    }
}

/// Whether a custom member may change this member's access: a regular member
/// other than themselves, as for everything else they do to people
/// (ensure_regular_target).
async fn is_regular_other(actor: &UserId, member: &Membership, conn: &DbConn) -> bool {
    &member.user_uuid != actor
        && member.atype == MembershipType::User as i32
        && find(&member.uuid, conn).await.is_none()
}

/// Whether giving a group more would raise this member of it past what a
/// custom role may give: anyone but a regular member other than the actor.
/// People who already reach every item with every capability a custom role
/// can give (confirmed owners, admins, and members with access to all items)
/// can't be raised by it, so their being in a group doesn't stop it.
async fn raised_past_role(actor: &UserId, member: &Membership, conn: &DbConn) -> bool {
    !member.has_full_access() && !is_regular_other(actor, member, conn).await
}

/// A shared folder's access as a save asks for it: each member's grant, by
/// membership (without members with access to all items, whose grants upstream
/// skips), and each group's.
#[derive(Default)]
pub struct FolderAccess {
    pub users: Vec<(Membership, Grid)>,
    pub groups: Vec<(GroupId, Grid)>,
}

/// Checks a custom member's change to who reaches a shared folder (making it,
/// editing it, or bulk access) against "Never more than they have" (DESIGN.md,
/// "Roles and permissions"). Owners and admins don't come here.
///
/// - The folder is one they reach (a new one: Reach::with_new).
/// - A regular member other than themselves may be given access, have it
///   changed, or be taken out, and is given only what the actor has there,
///   never manage (Reach::ensure_grant).
/// - Everyone else's grant (their own, a manager's, another custom member's)
///   stays exactly as it was: it may be sent back, not changed or left out.
/// - A group may be given access, or more of it, only within the actor's own,
///   and only when no one in it would be raised past the role (raised_past_role).
///   A group's access may be lowered or taken away.
///
/// A grant sent back exactly as it was isn't one the role gives, so it isn't
/// checked. `stored` is the folder's grants before the save
/// (Stored::of_collection), empty for a new folder.
pub async fn check_folder_access(
    reach: &Reach,
    actor: &UserId,
    org: &OrganizationId,
    collection: &CollectionId,
    stored: &Stored,
    asked: &FolderAccess,
    conn: &DbConn,
) -> EmptyResult {
    reach.ensure_reaches(collection)?;
    let mut asked_users = HashSet::new();
    for (member, grid) in &asked.users {
        asked_users.insert(member.user_uuid.clone());
        if stored.user(&member.user_uuid, collection) == Some(*grid) {
            continue;
        }
        if !is_regular_other(actor, member, conn).await {
            err!("Your role can only change regular members' access to a shared folder, not its own or anyone else's")
        }
        reach.ensure_grant(collection, grid)?;
    }
    for (user, _) in stored.users_of(collection) {
        if asked_users.contains(&user) {
            continue;
        }
        let Some(member) = Membership::find_by_user_and_org(&user, org, conn).await else {
            continue;
        };
        // Upstream drops the grant of someone with access to all items, who
        // reaches the folder anyway.
        if member.access_all {
            continue;
        }
        if !is_regular_other(actor, &member, conn).await {
            err!("Your role can only change regular members' access to a shared folder, not its own or anyone else's")
        }
    }
    for (group, grid) in &asked.groups {
        let had = stored.group(collection, group);
        if had == Some(*grid) {
            continue;
        }
        reach.ensure_grant(collection, grid)?;
        if had.is_none_or(|h| !grid.within(&h)) {
            ensure_group_raisable(actor, group, org, conn).await?;
        }
    }
    Ok(())
}

/// Refuses giving a group more when that would raise someone in it past the
/// role: a manager, another custom member, or the actor themselves.
async fn ensure_group_raisable(actor: &UserId, group: &GroupId, org: &OrganizationId, conn: &DbConn) -> EmptyResult {
    for gu in GroupUser::find_by_group(group, org, conn).await {
        let Some(member) = Membership::find_by_uuid_and_org(&gu.users_organizations_uuid, org, conn).await else {
            continue;
        };
        if raised_past_role(actor, &member, conn).await {
            err!(
                "Your role can't give more access to a group with you, a manager, or another custom role in it. An owner or admin can."
            )
        }
    }
    Ok(())
}

/// A group as it is, or as a save asks for it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupState {
    pub access_all: bool,
    pub grants: HashMap<CollectionId, Grid>,
    pub members: HashSet<MembershipId>,
}

impl GroupState {
    /// The group as stored. A database error reading its grants is an error.
    pub async fn of(group: &Group, conn: &DbConn) -> ApiResult<Self> {
        let grants = Stored::of_group(&group.uuid, &group.organizations_uuid, conn).await?.grants_of(&group.uuid);
        let members = GroupUser::find_by_group(&group.uuid, &group.organizations_uuid, conn)
            .await
            .into_iter()
            .map(|gu| gu.users_organizations_uuid)
            .collect();
        Ok(Self {
            access_all: group.access_all,
            grants,
            members,
        })
    }
}

/// Checks a custom member's new or edited group against "Never more than they
/// have" (DESIGN.md, "Roles and permissions"), and answers the group to save.
/// Owners and admins don't come here.
///
/// - Never access to all items: only owners and admins give that.
/// - In the collections they reach, what was asked: each new or changed grant
///   within their own access, never manage (Reach::ensure_grant). In the
///   others, the group's grants as they were: they don't see them (the group
///   lists show them only the collections they reach), so a save leaves them.
/// - More access (a new collection, or more in one) only when no one in the
///   group would be raised past the role (raised_past_role).
/// - People added or taken out are regular members other than themselves,
///   and only in a group within their reach (Reach::covers_group): adding
///   someone to any other gives them what the role doesn't have.
///
/// `stored` is None for a new group.
pub async fn check_group_change(
    reach: &Reach,
    actor: &UserId,
    org: &OrganizationId,
    stored: Option<&GroupState>,
    asked: GroupState,
    conn: &DbConn,
) -> ApiResult<GroupState> {
    let new_group = GroupState::default();
    let stored = stored.unwrap_or(&new_group);
    if asked.access_all != stored.access_all {
        err!("Only owners and admins give a group access to all items")
    }
    let mut grants: HashMap<CollectionId, Grid> =
        stored.grants.iter().filter(|(c, _)| !reach.contains(c)).map(|(c, g)| (c.clone(), *g)).collect();
    let mut raised = false;
    for (collection, grid) in &asked.grants {
        let had = stored.grants.get(collection).copied();
        if had != Some(*grid) {
            reach.ensure_grant(collection, grid)?;
            raised |= had.is_none_or(|h| !grid.within(&h));
        }
        grants.insert(collection.clone(), *grid);
    }
    let changed: Vec<MembershipId> = asked.members.symmetric_difference(&stored.members).cloned().collect();
    for id in &changed {
        let Some(member) = Membership::find_by_uuid_and_org(id, org, conn).await else {
            err!("Member not found")
        };
        if !is_regular_other(actor, &member, conn).await {
            err!("Your role can only add regular members to a group or take them out, not itself or anyone else")
        }
    }
    let saved = GroupState {
        access_all: stored.access_all,
        grants,
        members: asked.members,
    };
    if !changed.is_empty() && !reach.covers_group(&saved) {
        err!(
            "Your role can only change who's in a group whose shared folders it reaches, with no more access than its own"
        )
    }
    if raised {
        for id in &saved.members {
            if let Some(member) = Membership::find_by_uuid_and_org(id, org, conn).await
                && raised_past_role(actor, &member, conn).await
            {
                err!(
                    "Your role can't give more access to a group with you, a manager, or another custom role in it. An owner or admin can."
                )
            }
        }
    }
    Ok(saved)
}

/// Refuses deleting a group beyond the actor's reach (Reach::covers_group):
/// its people would lose shared folders the role doesn't reach.
pub fn ensure_may_delete_group(reach: &Reach, group: &GroupState) -> EmptyResult {
    if !reach.covers_group(group) {
        err!("Your role can only delete a group whose shared folders it reaches, with no more access than its own")
    }
    Ok(())
}

/// Checks a custom member's change to someone's groups from the member
/// dialogs (`inviting` someone new, or editing them): none at all without
/// managing groups; with it, only groups within their reach, as
/// check_group_change has it for one person. The person is a regular member,
/// which the caller checks (ensure_regular_target).
pub async fn check_member_groups(
    acting_as: &CustomPermissions,
    reach: &Reach,
    org: &OrganizationId,
    inviting: bool,
    current: &HashSet<GroupId>,
    asked: &HashSet<GroupId>,
    conn: &DbConn,
) -> EmptyResult {
    if current == asked {
        return Ok(());
    }
    if !acting_as.manage_groups {
        if inviting {
            err!("Your role can't add people to groups")
        }
        err!("Your role can't change someone's groups")
    }
    for group_id in current.symmetric_difference(asked) {
        let Some(group) = Group::find_by_uuid_and_org(group_id, org, conn).await else {
            err!("Group not found in Organization")
        };
        if !reach.covers_group(&GroupState::of(&group, conn).await?) {
            err!(
                "Your role can only change who's in a group whose shared folders it reaches, with no more access than its own"
            )
        }
    }
    Ok(())
}

/// Whether someone's custom role lets them rename a shared folder, and so
/// change its icon: one that manages shared folders, in a folder it reaches
/// (keykeeper_folder_looks.rs). A database error is an error.
pub async fn renames_folder(
    user: &UserId,
    org: &OrganizationId,
    collection: &CollectionId,
    conn: &DbConn,
) -> ApiResult<bool> {
    let Some(member) = Membership::find_confirmed_by_user_and_org(user, org, conn).await else {
        return Ok(false);
    };
    if member.atype != MembershipType::User as i32
        || !find(&member.uuid, conn).await.is_some_and(|r| r.manage_collections)
    {
        return Ok(false);
    }
    Ok(Reach::of(user, org, conn).await?.contains(collection))
}

/// Refuses a role that could export a client's vault without access to all
/// items: the export holds every item, so it's the same as access to all
/// items, and the org key decrypts it. For an MSP's technician the console
/// refuses it outright; a client's own custom role may have import and export
/// without it, which then covers import, and the export itself refuses them
/// (get_org_export).
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
        Some(role) => (4, role.to_client_json(member.access_all)),
        None => (upstream_type, upstream_permissions),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        DbPool,
        models::{Collection, Organization, User, keykeeper_folder_permissions::save_user},
    };

    fn perms(pairs: &[(&str, bool)]) -> HashMap<String, Value> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), Value::Bool(*v))).collect()
    }

    #[test]
    fn every_route_has_a_permission_and_appears_once() {
        for (i, (method, path, perms)) in ROUTES.iter().enumerate() {
            assert!(!perms.is_empty(), "{method} {path} has no permission");
            assert!(!ROUTES[i + 1..].iter().any(|(m, p, _)| m == method && p == path), "{method} {path} appears twice");
        }
    }

    /// A path that isn't a real route would admit no one, quietly: the page
    /// that needs it would be refused.
    #[test]
    fn every_route_in_the_map_is_one_the_server_has() {
        let routes = crate::api::core_routes();
        for (method, path, _) in ROUTES {
            assert!(
                routes.iter().any(|r| r.method == *method && r.uri.unmounted_origin.path().as_str() == *path),
                "{method} {path} isn't a route"
            );
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
    fn each_page_can_load_the_collections_it_shows() {
        // The Members page's and the Groups page's names.
        let names = route_permissions(Method::Get, "/organizations/<org_id>/collections");
        for p in [ManageUsers, ManageResetPassword, ManageCollections, ManageGroups] {
            assert!(names.contains(&p), "{p:?}");
        }
        // The member, folder, and group dialogs, the Collections page, and the import page.
        assert_eq!(
            route_permissions(Method::Get, "/organizations/<org_id>/collections/details"),
            &[ManageUsers, AccessImportExport, ManageCollections, ManageGroups]
        );
    }

    #[test]
    fn only_managing_shared_folders_changes_them() {
        for (method, path) in [
            (Method::Post, "/organizations/<org_id>/collections"),
            (Method::Post, "/organizations/<org_id>/collections/bulk-access"),
            (Method::Put, "/organizations/<org_id>/collections/<col_id>"),
            (Method::Delete, "/organizations/<org_id>/collections/<col_id>"),
            (Method::Delete, "/organizations/<org_id>/collections"),
            (Method::Get, "/organizations/<org_id>/collections/<col_id>/details"),
            (Method::Get, "/organizations/<org_id>/collections/<col_id>/users"),
        ] {
            assert_eq!(route_permissions(method, path), &[ManageCollections], "{method} {path}");
        }
    }

    #[test]
    fn only_managing_groups_changes_them() {
        assert_eq!(
            route_permissions(Method::Get, "/organizations/<org_id>/groups/details"),
            &[ManageUsers, ManageGroups]
        );
        for (method, path) in [
            (Method::Post, "/organizations/<org_id>/groups"),
            (Method::Delete, "/organizations/<org_id>/groups"),
            (Method::Get, "/organizations/<org_id>/groups/<group_id>"),
            (Method::Get, "/organizations/<org_id>/groups/<group_id>/details"),
            (Method::Get, "/organizations/<org_id>/groups/<group_id>/users"),
            (Method::Put, "/organizations/<org_id>/groups/<group_id>"),
            (Method::Delete, "/organizations/<org_id>/groups/<group_id>"),
        ] {
            assert_eq!(route_permissions(method, path), &[ManageGroups], "{method} {path}");
        }
    }

    #[test]
    fn reports_and_the_collections_page_load_the_items() {
        assert_eq!(
            route_permissions(Method::Get, "/ciphers/organization-details"),
            &[AccessReports, ManageCollections]
        );
        // The export holds every item: import and export only, with access to all items.
        assert_eq!(route_permissions(Method::Get, "/organizations/<org_id>/export"), &[AccessImportExport]);
    }

    #[test]
    fn the_event_log_and_the_dialogs_can_name_people() {
        assert!(route_permissions(Method::Get, "/organizations/<org_id>/events").contains(&AccessEventLogs));
        assert_eq!(
            route_permissions(Method::Get, "/organizations/<org_id>/users/mini-details"),
            &[AccessEventLogs, ManageCollections, ManageGroups]
        );
    }

    #[test]
    fn only_custom_type_with_our_permissions_or_every_item_is_a_custom_role() {
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
        // Every permission, by the name clients send.
        let all: Vec<(&str, bool)> = Permission::ALL.iter().map(|p| (p.key(), true)).collect();
        let role = CustomPermissions::from_request("4", &perms(&all)).unwrap().unwrap();
        assert!(Permission::ALL.iter().all(|p| role.has(*p)));
        // Access to all items alone is a custom role with no permissions.
        let items = perms(&[(ACCESS_ALL_KEY, true)]);
        let role = CustomPermissions::from_request("4", &items).unwrap();
        assert_eq!(role, Some(CustomPermissions::default()));
        assert!(access_all_requested(role.as_ref(), &items));
        assert!(!access_all_requested(None, &items));
    }

    #[test]
    fn a_custom_role_never_also_manages_every_collection() {
        for collection_permission in COLLECTION_PERMISSIONS {
            let asked = perms(&[("manageUsers", true), (collection_permission, true)]);
            assert!(CustomPermissions::from_request("4", &asked).is_err(), "{collection_permission}");
            let asked = perms(&[(ACCESS_ALL_KEY, true), (collection_permission, true)]);
            assert!(CustomPermissions::from_request("4", &asked).is_err(), "{collection_permission}");
        }
        // Managing shared folders shows as creating them, which a client may send back.
        let ours = perms(&[(ManageCollections.key(), true), ("createNewCollections", true)]);
        assert_eq!(
            CustomPermissions::from_request("4", &ours).unwrap(),
            Some(CustomPermissions {
                manage_collections: true,
                ..Default::default()
            })
        );
        for any in ["editAnyCollection", "deleteAnyCollection"] {
            let asked = perms(&[(ManageCollections.key(), true), (any, true)]);
            assert!(CustomPermissions::from_request("4", &asked).is_err(), "{any}");
        }
        // Upstream's Custom with only the collection permissions is still upstream's.
        let all_collections =
            perms(&[("createNewCollections", true), ("editAnyCollection", true), ("deleteAnyCollection", true)]);
        assert_eq!(CustomPermissions::from_request("4", &all_collections).ok(), Some(None));
        // Unchecked boxes are fine.
        let unchecked = perms(&[("manageUsers", true), ("editAnyCollection", false)]);
        assert!(CustomPermissions::from_request("4", &unchecked).is_ok_and(|role| role.is_some()));
    }

    #[test]
    fn clients_see_each_permission_and_never_every_collection() {
        let shown = CustomPermissions {
            manage_users: true,
            ..Default::default()
        }
        .to_client_json(false);
        for collection_permission in COLLECTION_PERMISSIONS {
            assert_eq!(shown[collection_permission], Value::Bool(false), "{collection_permission}");
        }
        assert_eq!(shown[ACCESS_ALL_KEY], Value::Bool(false));

        let every = CustomPermissions {
            manage_users: true,
            manage_reset_password: true,
            manage_policies: true,
            access_event_logs: true,
            access_import_export: true,
            manage_collections: true,
            manage_groups: true,
            access_reports: true,
        };
        let shown = every.to_client_json(true);
        for p in Permission::ALL {
            assert_eq!(shown[p.key()], Value::Bool(true), "{p:?}");
        }
        assert_eq!(shown["createNewCollections"], Value::Bool(true));
        assert_eq!(shown["editAnyCollection"], Value::Bool(false));
        assert_eq!(shown["deleteAnyCollection"], Value::Bool(false));
        assert_eq!(shown[ACCESS_ALL_KEY], Value::Bool(true));
        // What clients see is what a client sending it back asks for.
        let back: HashMap<String, Value> = serde_json::from_value(shown).unwrap();
        assert_eq!(CustomPermissions::from_request("4", &back).unwrap(), Some(every));
    }

    const VIEW: Grid = Grid {
        see_passwords: true,
        print: true,
        view_history: true,
        ..Grid::NONE
    };

    #[test]
    fn a_group_is_within_reach_only_if_every_grant_is() {
        let mine = CollectionId::from("mine".to_owned());
        let other = CollectionId::from("other".to_owned());
        let reach = Reach::Only(HashMap::from([(mine.clone(), VIEW)]));
        let group = |grants: &[(&CollectionId, Grid)], access_all: bool| GroupState {
            access_all,
            grants: grants.iter().map(|(c, g)| ((*c).clone(), *g)).collect(),
            members: HashSet::new(),
        };
        assert!(reach.covers_group(&group(&[], false)));
        assert!(reach.covers_group(&group(&[(&mine, VIEW)], false)));
        assert!(!reach.covers_group(&group(&[], true)), "every item");
        assert!(!reach.covers_group(&group(&[(&other, VIEW)], false)), "a collection it doesn't reach");
        assert!(!reach.covers_group(&group(&[(&mine, Grid::EVERY_ITEM)], false)), "more than its own");
        // With every item, anything but manage and every item.
        assert!(Reach::All.covers_group(&group(&[(&other, Grid::EVERY_ITEM)], false)));
        assert!(!Reach::All.covers_group(&group(&[(&other, Grid::ALL)], false)));
        assert!(!Reach::All.covers_group(&group(&[], true)));
    }

    #[test]
    fn a_folder_is_deleted_only_where_its_items_can_be() {
        let viewed = CollectionId::from("viewed".to_owned());
        let edited = CollectionId::from("edited".to_owned());
        let made = CollectionId::from("made".to_owned());
        let reach =
            Reach::Only(HashMap::from([(viewed.clone(), VIEW), (edited.clone(), Grid::preset(false, false, false))]));
        assert!(reach.ensure_may_delete_folder(&viewed).is_err());
        assert!(reach.ensure_may_delete_folder(&edited).is_ok());
        assert!(reach.ensure_may_delete_folder(&made).is_err());
        assert!(reach.ensure_reaches(&made).is_err());
        // One it makes, it has every capability in but manage.
        let reach = reach.with_new(&made);
        assert_eq!(reach.own(&made), Some(Grid::EVERY_ITEM));
        assert!(reach.ensure_may_delete_folder(&made).is_ok());
        assert!(reach.ensure_grant(&made, &Grid::EVERY_ITEM).is_ok());
        assert!(reach.ensure_grant(&made, &Grid::ALL).is_err());
    }

    async fn member(name: &str, org: &Organization, atype: MembershipType, conn: &DbConn) -> Membership {
        let mut user = User::new(&format!("{name}@example.test"), None);
        user.save(conn).await.unwrap();
        let mut member = Membership::new(user.uuid.clone(), org.uuid.clone(), None);
        member.status = MembershipStatus::Confirmed as i32;
        member.atype = atype as i32;
        member.access_all = atype >= MembershipType::Admin;
        member.save(conn).await.unwrap();
        member
    }

    async fn collection(org: &Organization, conn: &DbConn) -> CollectionId {
        let collection = Collection::new(org.uuid.clone(), "2.aXY=|Y3Q=|bWFj".to_owned(), None);
        collection.save(conn).await.unwrap();
        collection.uuid
    }

    /// The limits on groups, one by one: what a custom role that manages
    /// groups may do to a group, and what it keeps as it was.
    #[rocket::async_test]
    async fn a_custom_role_changes_groups_only_within_what_it_has() {
        let conn = DbPool::for_test().await;
        let org = Organization::new("Contoso".to_owned(), "billing@example.test", None, None);
        org.save(&conn).await.unwrap();
        let poc = member("poc", &org, MembershipType::User, &conn).await;
        set(
            &poc.uuid,
            Some(&CustomPermissions {
                manage_groups: true,
                ..Default::default()
            }),
            &conn,
        )
        .await
        .unwrap();
        let other_custom = member("other", &org, MembershipType::User, &conn).await;
        set(
            &other_custom.uuid,
            Some(&CustomPermissions {
                manage_users: true,
                ..Default::default()
            }),
            &conn,
        )
        .await
        .unwrap();
        let admin = member("admin", &org, MembershipType::Admin, &conn).await;
        let regular = member("regular", &org, MembershipType::User, &conn).await;
        let mine = collection(&org, &conn).await;
        let theirs = collection(&org, &conn).await;
        save_user(&poc.user_uuid, &mine, &VIEW, &conn).await.unwrap();
        let reach = Reach::of(&poc.user_uuid, &org.uuid, &conn).await.unwrap();
        let actor = &poc.user_uuid;
        let state = |grants: &[(&CollectionId, Grid)], members: &[&Membership]| GroupState {
            access_all: false,
            grants: grants.iter().map(|(c, g)| ((*c).clone(), *g)).collect(),
            members: members.iter().map(|m| m.uuid.clone()).collect(),
        };
        let org_id = &org.uuid;
        let check = |stored: Option<GroupState>, asked: GroupState| {
            let reach = &reach;
            let conn = &conn;
            async move { check_group_change(reach, actor, org_id, stored.as_ref(), asked, conn).await }
        };

        // A new group within its reach, with a regular member in it.
        assert!(check(None, state(&[(&mine, VIEW)], &[&regular])).await.is_ok());
        // Never more than it has, a collection it doesn't reach, manage, or every item.
        assert!(check(None, state(&[(&mine, Grid::EVERY_ITEM)], &[])).await.is_err());
        assert!(check(None, state(&[(&theirs, VIEW)], &[])).await.is_err());
        assert!(check(None, state(&[(&mine, Grid::ALL)], &[])).await.is_err());
        let mut every_item = state(&[], &[]);
        every_item.access_all = true;
        assert!(check(None, every_item).await.is_err());
        // Nobody but regular members other than itself goes in or out.
        for someone in [&poc, &other_custom, &admin] {
            assert!(check(None, state(&[], &[someone])).await.is_err(), "{}", someone.uuid);
            assert!(check(Some(state(&[], &[someone])), state(&[], &[])).await.is_err(), "{}", someone.uuid);
        }

        // A group an admin made reaching beyond it: the save keeps what it
        // doesn't see, and nobody goes in or out.
        let beyond = state(&[(&mine, VIEW), (&theirs, VIEW)], &[&regular]);
        let renamed = check(Some(beyond.clone()), state(&[(&mine, VIEW)], &[&regular])).await.unwrap();
        assert_eq!(renamed, beyond);
        let lowered = check(Some(beyond.clone()), state(&[], &[&regular])).await.unwrap();
        assert_eq!(lowered, state(&[(&theirs, VIEW)], &[&regular]));
        assert!(check(Some(beyond.clone()), state(&[(&mine, VIEW)], &[])).await.is_err(), "taking someone out");
        let newcomer = member("newcomer", &org, MembershipType::User, &conn).await;
        assert!(check(Some(beyond.clone()), state(&[(&mine, VIEW)], &[&regular, &newcomer])).await.is_err());

        // More access for a group with an admin in it is fine (it can't raise
        // them); with another custom role or itself in it, it isn't. Less is.
        let with = |m: &Membership| state(&[], &[&regular, m]);
        assert!(check(Some(with(&admin)), state(&[(&mine, VIEW)], &[&regular, &admin])).await.is_ok());
        for someone in [&other_custom, &poc] {
            assert!(check(Some(with(someone)), state(&[(&mine, VIEW)], &[&regular, someone])).await.is_err());
            let had = state(&[(&mine, VIEW)], &[&regular, someone]);
            assert!(check(Some(had), with(someone)).await.is_ok(), "lowered");
        }

        // Deleting needs the group within its reach.
        assert!(ensure_may_delete_group(&reach, &state(&[(&mine, VIEW)], &[&admin])).is_ok());
        assert!(ensure_may_delete_group(&reach, &beyond).is_err());
    }

    /// The limits on a shared folder's access: who a custom role that manages
    /// shared folders may give it to, change, or take out.
    #[rocket::async_test]
    async fn a_custom_role_changes_a_folders_access_only_for_regular_members_within_what_it_has() {
        let conn = DbPool::for_test().await;
        let org = Organization::new("Contoso".to_owned(), "billing@example.test", None, None);
        org.save(&conn).await.unwrap();
        let poc = member("poc", &org, MembershipType::User, &conn).await;
        set(
            &poc.uuid,
            Some(&CustomPermissions {
                manage_collections: true,
                ..Default::default()
            }),
            &conn,
        )
        .await
        .unwrap();
        let other_custom = member("other", &org, MembershipType::User, &conn).await;
        set(
            &other_custom.uuid,
            Some(&CustomPermissions {
                manage_users: true,
                ..Default::default()
            }),
            &conn,
        )
        .await
        .unwrap();
        let regular = member("regular", &org, MembershipType::User, &conn).await;
        let edit = Grid::preset(false, false, false);
        let folder = collection(&org, &conn).await;
        let elsewhere = collection(&org, &conn).await;
        save_user(&poc.user_uuid, &folder, &edit, &conn).await.unwrap();
        save_user(&other_custom.user_uuid, &folder, &VIEW, &conn).await.unwrap();
        let reach = Reach::of(&poc.user_uuid, &org.uuid, &conn).await.unwrap();
        let stored = Stored::of_collection(&folder, &conn).await.unwrap();
        let actor = &poc.user_uuid;
        let org_id = &org.uuid;
        let check = |collection: CollectionId, users: Vec<(&Membership, Grid)>| {
            let reach = &reach;
            let stored = &stored;
            let conn = &conn;
            let users: Vec<(MembershipId, Grid)> = users.into_iter().map(|(m, g)| (m.uuid.clone(), g)).collect();
            async move {
                let mut asked = FolderAccess::default();
                for (id, grid) in users {
                    asked.users.push((Membership::find_by_uuid(&id, conn).await.unwrap(), grid));
                }
                check_folder_access(reach, actor, org_id, &collection, stored, &asked, conn).await
            }
        };
        let kept = || vec![(&poc, edit), (&other_custom, VIEW)];

        // A regular member, with no more than its own, never manage.
        let mut users = kept();
        users.push((&regular, VIEW));
        assert!(check(folder.clone(), users).await.is_ok());
        for too_much in [Grid::EVERY_ITEM, Grid::ALL] {
            let mut users = kept();
            users.push((&regular, too_much));
            assert!(check(folder.clone(), users).await.is_err());
        }
        // Not a folder it doesn't reach.
        assert!(check(elsewhere, vec![(&regular, VIEW)]).await.is_err());
        // Its own grant and another custom role's stay as they were.
        assert!(check(folder.clone(), vec![(&poc, VIEW), (&other_custom, VIEW)]).await.is_err());
        assert!(check(folder.clone(), vec![(&poc, edit), (&other_custom, edit)]).await.is_err());
        assert!(check(folder.clone(), vec![(&poc, edit)]).await.is_err(), "taking another custom role out");
        assert!(check(folder.clone(), vec![(&other_custom, VIEW)]).await.is_err(), "taking itself out");
        // Sent back as they were, nothing is given.
        assert!(check(folder, kept()).await.is_ok());
    }
}

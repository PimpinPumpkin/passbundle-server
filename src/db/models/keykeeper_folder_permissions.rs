// Keykeeper: what each person and group can do in a shared folder (upstream's
// collection), as a grid of capabilities instead of upstream's presets. See
// DESIGN.md, "Folders and permissions".
//
// Upstream's three fields on each grant (read_only, hide_passwords, manage)
// keep the closest preset, so upstream clients show something sensible. Our
// tables keep the other capabilities, with the upstream values they were saved
// with: a row counts only while the grant still has those values, so a grant
// an upstream client changes becomes the preset it showed. Rows go with their
// grant (ON DELETE CASCADE).
//
// The server enforces see items, create, edit, delete, manage, and view item
// history. See passwords, export, print, and share are for the apps: anyone who
// can decrypt an item can take it out with their own tools. The server still
// refuses the part of share it can see, taking an item out of a folder.

use std::collections::{HashMap, HashSet};

use diesel::prelude::*;
use rocket::{Request, http::Method, outcome::Outcome};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult},
    db::{
        DbConn,
        keykeeper_schema::{keykeeper_collections_groups, keykeeper_users_collections},
        schema::ciphers_collections,
    },
    error::MapResult,
};

use super::{
    Cipher, CipherId, CollectionGroup, CollectionId, CollectionUser, Group, GroupId, GroupUser, Membership,
    MembershipStatus, MembershipType, OrganizationId, UserId,
};

/// What someone can do in a shared folder. Having a grant at all is "see
/// items"; everything here needs it.
#[expect(clippy::struct_excessive_bools, reason = "One flag per capability, as the apps send them")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grid {
    pub see_passwords: bool,
    pub create: bool,
    pub edit: bool,
    pub delete: bool,
    pub export: bool,
    pub share: bool,
    pub print: bool,
    pub view_history: bool,
    pub manage: bool,
}

impl Grid {
    /// Everything: owners, admins, members with access to all items, a
    /// folder's managers, and the owner of a personal item.
    pub const ALL: Grid = Grid {
        see_passwords: true,
        create: true,
        edit: true,
        delete: true,
        export: true,
        share: true,
        print: true,
        view_history: true,
        manage: true,
    };

    /// Every item, without managing folders: members with access to all items
    /// who aren't owners, admins, or managers, such as an MSP's technician
    /// with vault items. A custom role never manages every folder (DESIGN.md,
    /// "Roles and permissions").
    pub const EVERY_ITEM: Grid = Grid {
        manage: false,
        ..Self::ALL
    };

    /// Nothing at all, for someone who can't open the item.
    pub const NONE: Grid = Grid {
        see_passwords: false,
        create: false,
        edit: false,
        delete: false,
        export: false,
        share: false,
        print: false,
        view_history: false,
        manage: false,
    };

    /// The preset upstream's three fields name. Upstream's "Can edit except
    /// passwords" keeps what upstream let it do, without the capabilities that
    /// need see passwords.
    pub fn preset(read_only: bool, hide_passwords: bool, manage: bool) -> Grid {
        if manage {
            return Self::ALL;
        }
        let see_passwords = !hide_passwords;
        let edit = !read_only;
        Grid {
            see_passwords,
            create: edit,
            edit,
            delete: edit,
            export: false,
            share: edit && see_passwords,
            print: see_passwords,
            view_history: true,
            manage: false,
        }
    }

    /// Upstream's three fields for this grid, (read_only, hide_passwords,
    /// manage): the closest preset, which upstream clients show.
    pub fn upstream(&self) -> (bool, bool, bool) {
        if self.manage {
            (false, false, true)
        } else {
            (!self.edit, !self.see_passwords, false)
        }
    }

    /// The grid's rules: export, print, and share need see passwords, since
    /// each puts an item's secrets somewhere this folder's rules don't reach;
    /// manage includes everything, since a manager could give themselves the
    /// rest. A grid that breaks them is refused, never filled in.
    pub fn check(&self) -> Result<(), &'static str> {
        if self.manage && *self != Self::ALL {
            return Err("Managing a shared folder includes every other permission in it");
        }
        if (self.export || self.print || self.share) && !self.see_passwords {
            return Err("Export, print, and share need see passwords");
        }
        Ok(())
    }

    /// For each capability, the more open of the two: someone with several
    /// ways into a folder, or an item in several folders.
    #[must_use]
    pub fn or(self, other: Grid) -> Grid {
        Grid {
            see_passwords: self.see_passwords || other.see_passwords,
            create: self.create || other.create,
            edit: self.edit || other.edit,
            delete: self.delete || other.delete,
            export: self.export || other.export,
            share: self.share || other.share,
            print: self.print || other.print,
            view_history: self.view_history || other.view_history,
            manage: self.manage || other.manage,
        }
    }

    /// Every capability here is also in `own`.
    pub fn within(&self, own: &Grid) -> bool {
        self.or(*own) == *own
    }

    pub fn to_json(self) -> Value {
        json!(self)
    }

    /// A grant as upstream's clients read it, with the grid beside it.
    pub fn grant_json(&self, id: &impl serde::Serialize) -> Value {
        let (read_only, hide_passwords, manage) = self.upstream();
        json!({
            "id": id,
            "readOnly": read_only,
            "hidePasswords": hide_passwords,
            "manage": manage,
            "keykeeper": self,
        })
    }
}

/// The grant a request asks for: our grid when it sends one, checked, or the
/// preset upstream's fields name.
pub fn requested(read_only: bool, hide_passwords: bool, manage: bool, keykeeper: Option<&Grid>) -> ApiResult<Grid> {
    match keykeeper {
        Some(grid) => {
            if let Err(e) = grid.check() {
                err!(e)
            }
            Ok(*grid)
        }
        None => Ok(Grid::preset(read_only, hide_passwords, manage)),
    }
}

#[expect(clippy::struct_excessive_bools, reason = "A grant's capabilities, one column each")]
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = keykeeper_users_collections)]
#[diesel(primary_key(user_uuid, collection_uuid))]
struct UserRow {
    user_uuid: UserId,
    collection_uuid: CollectionId,
    read_only: bool,
    hide_passwords: bool,
    manage: bool,
    can_create: bool,
    can_delete: bool,
    can_export: bool,
    can_share: bool,
    can_print: bool,
    can_view_history: bool,
}

#[expect(clippy::struct_excessive_bools, reason = "A grant's capabilities, one column each")]
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = keykeeper_collections_groups)]
#[diesel(primary_key(collections_uuid, groups_uuid))]
struct GroupRow {
    collections_uuid: CollectionId,
    groups_uuid: GroupId,
    read_only: bool,
    hide_passwords: bool,
    manage: bool,
    can_create: bool,
    can_delete: bool,
    can_export: bool,
    can_share: bool,
    can_print: bool,
    can_view_history: bool,
}

/// The six capabilities we keep, and the upstream values they were saved with.
#[expect(clippy::struct_excessive_bools, reason = "A grant's capabilities")]
#[derive(Clone, Copy)]
struct Extra {
    upstream: (bool, bool, bool),
    create: bool,
    delete: bool,
    export: bool,
    share: bool,
    print: bool,
    view_history: bool,
}

impl Extra {
    fn of(grid: &Grid) -> Self {
        Self {
            upstream: grid.upstream(),
            create: grid.create,
            delete: grid.delete,
            export: grid.export,
            share: grid.share,
            print: grid.print,
            view_history: grid.view_history,
        }
    }
}

/// A grant's grid from its upstream fields and our row, if any. A row saved
/// with other upstream values is stale: the grant was changed without us.
fn grid_of(upstream: (bool, bool, bool), extra: Option<&Extra>) -> Grid {
    let (read_only, hide_passwords, manage) = upstream;
    match extra {
        Some(e) if e.upstream == upstream && !manage => Grid {
            see_passwords: !hide_passwords,
            create: e.create,
            edit: !read_only,
            delete: e.delete,
            export: e.export,
            share: e.share,
            print: e.print,
            view_history: e.view_history,
            manage: false,
        },
        _ => Grid::preset(read_only, hide_passwords, manage),
    }
}

impl From<UserRow> for Extra {
    fn from(r: UserRow) -> Self {
        Self {
            upstream: (r.read_only, r.hide_passwords, r.manage),
            create: r.can_create,
            delete: r.can_delete,
            export: r.can_export,
            share: r.can_share,
            print: r.can_print,
            view_history: r.can_view_history,
        }
    }
}

impl From<GroupRow> for Extra {
    fn from(r: GroupRow) -> Self {
        Self {
            upstream: (r.read_only, r.hide_passwords, r.manage),
            create: r.can_create,
            delete: r.can_delete,
            export: r.can_export,
            share: r.can_share,
            print: r.can_print,
            view_history: r.can_view_history,
        }
    }
}

/// Our rows for a set of grants, to read their grids.
#[derive(Default)]
pub struct Extras {
    users: HashMap<(UserId, CollectionId), Extra>,
    groups: HashMap<(CollectionId, GroupId), Extra>,
}

impl Extras {
    /// Every row for these folders.
    pub async fn for_collections(collections: &[CollectionId], conn: &DbConn) -> Self {
        if collections.is_empty() {
            return Self::default();
        }
        let ids = collections.to_vec();
        let (users, groups) = conn
            .run(move |conn| {
                let users = keykeeper_users_collections::table
                    .filter(keykeeper_users_collections::collection_uuid.eq_any(&ids))
                    .load::<UserRow>(conn)
                    .unwrap_or_default();
                let groups = keykeeper_collections_groups::table
                    .filter(keykeeper_collections_groups::collections_uuid.eq_any(&ids))
                    .load::<GroupRow>(conn)
                    .unwrap_or_default();
                (users, groups)
            })
            .await;
        Self::from_rows(users, groups)
    }

    /// The rows for one person's own grants and their groups' grants.
    async fn for_user(user: &UserId, groups: &[GroupId], conn: &DbConn) -> Self {
        let user = user.clone();
        let groups = groups.to_vec();
        let (users, groups) = conn
            .run(move |conn| {
                let users = keykeeper_users_collections::table
                    .filter(keykeeper_users_collections::user_uuid.eq(&user))
                    .load::<UserRow>(conn)
                    .unwrap_or_default();
                let groups = if groups.is_empty() {
                    Vec::new()
                } else {
                    keykeeper_collections_groups::table
                        .filter(keykeeper_collections_groups::groups_uuid.eq_any(&groups))
                        .load::<GroupRow>(conn)
                        .unwrap_or_default()
                };
                (users, groups)
            })
            .await;
        Self::from_rows(users, groups)
    }

    fn from_rows(users: Vec<UserRow>, groups: Vec<GroupRow>) -> Self {
        Self {
            users: users
                .into_iter()
                .map(|r| ((r.user_uuid.clone(), r.collection_uuid.clone()), Extra::from(r)))
                .collect(),
            groups: groups
                .into_iter()
                .map(|r| ((r.collections_uuid.clone(), r.groups_uuid.clone()), Extra::from(r)))
                .collect(),
        }
    }

    /// A person's grant, from upstream's row.
    pub fn user(&self, cu: &CollectionUser) -> Grid {
        self.user_grant(&cu.user_uuid, &cu.collection_uuid, (cu.read_only, cu.hide_passwords, cu.manage))
    }

    pub fn user_grant(&self, user: &UserId, collection: &CollectionId, upstream: (bool, bool, bool)) -> Grid {
        grid_of(upstream, self.users.get(&(user.clone(), collection.clone())))
    }

    /// A group's grant, from upstream's row.
    pub fn group(&self, cg: &CollectionGroup) -> Grid {
        grid_of(
            (cg.read_only, cg.hide_passwords, cg.manage),
            self.groups.get(&(cg.collections_uuid.clone(), cg.groups_uuid.clone())),
        )
    }
}

/// Gives a person this grant to a folder: upstream's row with the closest
/// preset, and ours with the rest when the preset doesn't say it all.
pub async fn save_user(user: &UserId, collection: &CollectionId, grid: &Grid, conn: &DbConn) -> EmptyResult {
    let (read_only, hide_passwords, manage) = grid.upstream();
    CollectionUser::save(user, collection, read_only, hide_passwords, manage, conn).await?;
    let user = user.clone();
    let collection = collection.clone();
    let extra = (*grid != Grid::preset(read_only, hide_passwords, manage)).then(|| Extra::of(grid));
    conn.run(move |conn| {
        conn.transaction(|conn| {
            diesel::delete(
                keykeeper_users_collections::table
                    .filter(keykeeper_users_collections::user_uuid.eq(&user))
                    .filter(keykeeper_users_collections::collection_uuid.eq(&collection)),
            )
            .execute(conn)?;
            if let Some(e) = extra {
                diesel::insert_into(keykeeper_users_collections::table)
                    .values(UserRow {
                        user_uuid: user.clone(),
                        collection_uuid: collection.clone(),
                        read_only: e.upstream.0,
                        hide_passwords: e.upstream.1,
                        manage: e.upstream.2,
                        can_create: e.create,
                        can_delete: e.delete,
                        can_export: e.export,
                        can_share: e.share,
                        can_print: e.print,
                        can_view_history: e.view_history,
                    })
                    .execute(conn)?;
            }
            Ok::<_, diesel::result::Error>(())
        })
        .map_res("Error saving a shared folder's permissions")
    })
    .await
}

/// Gives a group this grant to a folder, as save_user does for a person.
pub async fn save_group(
    collection: &CollectionId,
    group: &GroupId,
    org: &OrganizationId,
    grid: &Grid,
    conn: &DbConn,
) -> EmptyResult {
    let (read_only, hide_passwords, manage) = grid.upstream();
    CollectionGroup::new(collection.clone(), group.clone(), read_only, hide_passwords, manage).save(org, conn).await?;
    let group = group.clone();
    let collection = collection.clone();
    let extra = (*grid != Grid::preset(read_only, hide_passwords, manage)).then(|| Extra::of(grid));
    conn.run(move |conn| {
        conn.transaction(|conn| {
            diesel::delete(
                keykeeper_collections_groups::table
                    .filter(keykeeper_collections_groups::collections_uuid.eq(&collection))
                    .filter(keykeeper_collections_groups::groups_uuid.eq(&group)),
            )
            .execute(conn)?;
            if let Some(e) = extra {
                diesel::insert_into(keykeeper_collections_groups::table)
                    .values(GroupRow {
                        collections_uuid: collection.clone(),
                        groups_uuid: group.clone(),
                        read_only: e.upstream.0,
                        hide_passwords: e.upstream.1,
                        manage: e.upstream.2,
                        can_create: e.create,
                        can_delete: e.delete,
                        can_export: e.export,
                        can_share: e.share,
                        can_print: e.print,
                        can_view_history: e.view_history,
                    })
                    .execute(conn)?;
            }
            Ok::<_, diesel::result::Error>(())
        })
        .map_res("Error saving a shared folder's permissions")
    })
    .await
}

/// What one person can do in their organizations' shared folders.
#[derive(Default)]
pub struct Access {
    /// Organizations where they reach every folder, and what they can do in
    /// each: everything for owners, admins, and managers with access to all
    /// items; every item without managing folders for other members with
    /// access to all items, or in a group with access to all.
    pub full: HashMap<OrganizationId, Grid>,
    /// Every folder they reach through a grant, merged over their ways in.
    pub folders: HashMap<CollectionId, Grid>,
}

/// What full access gives this member.
fn full_grid(member: &Membership) -> Grid {
    if member.atype >= MembershipType::Manager {
        Grid::ALL
    } else {
        Grid::EVERY_ITEM
    }
}

impl Access {
    /// Across every organization they're a confirmed member of.
    pub async fn of(user: &UserId, conn: &DbConn) -> Self {
        let members: HashMap<OrganizationId, Membership> =
            Membership::find_confirmed_by_user(user, conn).await.into_iter().map(|m| (m.org_uuid.clone(), m)).collect();
        let mut full: HashMap<OrganizationId, Grid> =
            members.values().filter(|m| m.has_full_access()).map(|m| (m.org_uuid.clone(), full_grid(m))).collect();
        let group_grants = if CONFIG.org_groups_enabled() {
            for org in Group::get_orgs_by_user_with_full_access(user, conn).await {
                if let Some(member) = members.get(&org) {
                    full.entry(org).or_insert_with(|| full_grid(member));
                }
            }
            CollectionGroup::find_by_user(user, conn).await
        } else {
            Vec::new()
        };
        let direct = CollectionUser::find_by_user(user, conn).await;
        Self::merged(user, full, direct, group_grants, conn).await
    }

    /// In one organization only.
    pub async fn in_org(user: &UserId, org: &OrganizationId, conn: &DbConn) -> Self {
        let Some(member) = Membership::find_confirmed_by_user_and_org(user, org, conn).await else {
            return Self::default();
        };
        let mut full = HashMap::new();
        if member.has_full_access()
            || (CONFIG.org_groups_enabled() && GroupUser::has_full_access_by_member(org, &member.uuid, conn).await)
        {
            full.insert(org.clone(), full_grid(&member));
        }
        let mut group_grants = Vec::new();
        if CONFIG.org_groups_enabled() {
            for gu in GroupUser::find_by_member(&member.uuid, conn).await {
                group_grants.extend(CollectionGroup::find_by_group(&gu.groups_uuid, org, conn).await);
            }
        }
        let direct = CollectionUser::find_by_organization_and_user_uuid(org, user, conn).await;
        Self::merged(user, full, direct, group_grants, conn).await
    }

    async fn merged(
        user: &UserId,
        full: HashMap<OrganizationId, Grid>,
        direct: Vec<CollectionUser>,
        group_grants: Vec<CollectionGroup>,
        conn: &DbConn,
    ) -> Self {
        let groups: Vec<GroupId> =
            group_grants.iter().map(|g| g.groups_uuid.clone()).collect::<HashSet<_>>().into_iter().collect();
        let extras = Extras::for_user(user, &groups, conn).await;
        let mut folders: HashMap<CollectionId, Grid> = HashMap::new();
        let mut add = |collection: &CollectionId, grid: Grid| {
            folders.entry(collection.clone()).and_modify(|g| *g = g.or(grid)).or_insert(grid);
        };
        for cu in &direct {
            add(&cu.collection_uuid, extras.user(cu));
        }
        for cg in &group_grants {
            add(&cg.collections_uuid, extras.group(cg));
        }
        Self {
            full,
            folders,
        }
    }

    /// Whether they reach every folder of this organization.
    pub fn has_full(&self, org: &OrganizationId) -> bool {
        self.full.contains_key(org)
    }

    /// Their capabilities in a folder of this organization, or None if they
    /// don't reach it.
    pub fn in_collection(&self, org: &OrganizationId, collection: &CollectionId) -> Option<Grid> {
        let full = self.full.get(org).copied();
        let granted = self.folders.get(collection).copied();
        match (full, granted) {
            (Some(a), Some(b)) => Some(a.or(b)),
            (a, b) => a.or(b),
        }
    }

    /// Their capabilities on an organization's item in these folders: what
    /// any of them allows. None if they reach none of them and don't reach
    /// every folder.
    pub fn for_item(&self, org: &OrganizationId, collections: &[CollectionId]) -> Option<Grid> {
        let granted = collections.iter().filter_map(|c| self.folders.get(c).copied()).reduce(Grid::or);
        match (self.full.get(org).copied(), granted) {
            (Some(a), Some(b)) => Some(a.or(b)),
            (a, b) => a.or(b),
        }
    }

    /// Whether they manage at least one folder of this organization.
    pub fn manages_any(&self, org: &OrganizationId, org_collections: &HashSet<CollectionId>) -> bool {
        self.full.get(org).is_some_and(|g| g.manage)
            || self.folders.iter().any(|(c, g)| g.manage && org_collections.contains(c))
    }
}

/// The folders an item is in, whoever reaches them.
pub async fn collections_of(cipher: &CipherId, conn: &DbConn) -> Vec<CollectionId> {
    let cipher = cipher.clone();
    conn.run(move |conn| {
        ciphers_collections::table
            .filter(ciphers_collections::cipher_uuid.eq(cipher))
            .select(ciphers_collections::collection_uuid)
            .load::<CollectionId>(conn)
            .unwrap_or_default()
    })
    .await
}

/// What a person can do with an item, without sync data at hand: everything
/// with their own item, what their folders allow with an organization's, or
/// None if they can't open it.
pub async fn for_cipher(cipher: &Cipher, user: &UserId, conn: &DbConn) -> Option<Grid> {
    if cipher.is_owned_by_user(user) {
        return Some(Grid::ALL);
    }
    let org = cipher.organization_uuid.as_ref()?;
    let access = Access::in_org(user, org, conn).await;
    access.for_item(org, &collections_of(&cipher.uuid, conn).await)
}

/// What a person can do in one folder, or None if they don't reach it.
pub async fn in_collection(
    user: &UserId,
    org: &OrganizationId,
    collection: &CollectionId,
    conn: &DbConn,
) -> Option<Grid> {
    Access::in_org(user, org, conn).await.in_collection(org, collection)
}

/// Whether a confirmed member manages this folder (or every folder).
pub async fn manages(user: &UserId, org: &OrganizationId, collection: &CollectionId, conn: &DbConn) -> bool {
    in_collection(user, org, collection, conn).await.is_some_and(|g| g.manage)
}

/// The endpoints a regular member reaches for a folder they manage: what the
/// web vault's dialog for that folder loads and saves. Making and deleting
/// folders stays with owners, admins, and managers.
const FOLDER_ROUTES: &[(Method, &str)] = &[
    (Method::Get, "/organizations/<org_id>/collections/<col_id>/details"),
    (Method::Get, "/organizations/<org_id>/collections/<col_id>/users"),
    (Method::Put, "/organizations/<org_id>/collections/<col_id>"),
];

/// And what that dialog loads for the organization, for a member who manages
/// at least one of its folders: the folder list (each folder's access only for
/// the folders they manage), the members' names and emails, and the group
/// names to choose from, plus bulk access, which checks each folder.
const ORG_ROUTES: &[(Method, &str)] = &[
    (Method::Get, "/organizations/<org_id>/collections/details"),
    (Method::Get, "/organizations/<org_id>/users/mini-details"),
    (Method::Get, "/organizations/<org_id>/groups"),
    (Method::Post, "/organizations/<org_id>/collections/bulk-access"),
];

fn route_in(request: &Request<'_>, routes: &[(Method, &str)]) -> bool {
    request.route().is_some_and(|route| {
        let path = route.uri.unmounted_origin.path();
        routes.iter().any(|(m, p)| *m == route.method && *p == path.as_str())
    })
}

/// For the manager guards: a confirmed regular member who manages this folder
/// (with one) or any folder of the organization (without), on a route listed
/// above. Owners, admins, and managers are admitted as before.
pub async fn admits_folder_manager(
    request: &Request<'_>,
    member: &Membership,
    collection: Option<&CollectionId>,
) -> bool {
    if member.status != MembershipStatus::Confirmed as i32 || member.atype != MembershipType::User as i32 {
        return false;
    }
    let routes = if collection.is_some() {
        FOLDER_ROUTES
    } else {
        ORG_ROUTES
    };
    if !route_in(request, routes) {
        return false;
    }
    let Outcome::Success(conn) = request.guard::<DbConn>().await else {
        return false;
    };
    if let Some(collection) = collection {
        return manages(&member.user_uuid, &member.org_uuid, collection, &conn).await;
    }
    let access = Access::in_org(&member.user_uuid, &member.org_uuid, &conn).await;
    let collections =
        super::Collection::find_by_organization(&member.org_uuid, &conn).await.into_iter().map(|c| c.uuid).collect();
    access.manages_any(&member.org_uuid, &collections)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: Grid = Grid::NONE;

    #[test]
    fn folder_managers_reach_their_folders_dialog_and_never_make_or_delete_folders() {
        for (method, path) in [
            (Method::Post, "/organizations/<org_id>/collections"),
            (Method::Delete, "/organizations/<org_id>/collections/<col_id>"),
            (Method::Delete, "/organizations/<org_id>/collections"),
            (Method::Get, "/organizations/<org_id>/collections"),
            (Method::Get, "/organizations/<org_id>/users"),
            (Method::Get, "/organizations/<org_id>/groups/details"),
        ] {
            assert!(
                !FOLDER_ROUTES.iter().chain(ORG_ROUTES).any(|(m, p)| *m == method && *p == path),
                "{method} {path}"
            );
        }
        assert!(FOLDER_ROUTES.iter().all(|(_, p)| p.contains("<col_id>")));
        assert!(ORG_ROUTES.iter().all(|(_, p)| !p.contains("<col_id>")));
    }

    #[test]
    fn upstream_presets_name_these_grids() {
        let view = Grid::preset(true, false, false);
        assert_eq!(
            view,
            Grid {
                see_passwords: true,
                print: true,
                view_history: true,
                ..NONE
            }
        );
        let view_hidden = Grid::preset(true, true, false);
        assert_eq!(
            view_hidden,
            Grid {
                view_history: true,
                ..NONE
            }
        );
        let edit = Grid::preset(false, false, false);
        assert_eq!(
            edit,
            Grid {
                see_passwords: true,
                create: true,
                edit: true,
                delete: true,
                share: true,
                print: true,
                view_history: true,
                ..NONE
            }
        );
        let edit_hidden = Grid::preset(false, true, false);
        assert_eq!(
            edit_hidden,
            Grid {
                create: true,
                edit: true,
                delete: true,
                view_history: true,
                ..NONE
            }
        );
        // Manage is everything, whatever else upstream's fields say.
        for (ro, hp) in [(false, false), (true, false), (false, true), (true, true)] {
            assert_eq!(Grid::preset(ro, hp, true), Grid::ALL);
        }
        // Every preset follows the grid's rules and round-trips upstream's fields.
        for (ro, hp, mn) in [(true, false, false), (true, true, false), (false, false, false), (false, true, false)] {
            let grid = Grid::preset(ro, hp, mn);
            assert!(grid.check().is_ok());
            assert_eq!(grid.upstream(), (ro, hp, mn));
        }
        assert_eq!(Grid::ALL.upstream(), (false, false, true));
    }

    #[test]
    fn the_closest_preset_follows_edit_and_see_passwords() {
        let drop_box = Grid {
            create: true,
            view_history: true,
            ..NONE
        };
        assert_eq!(drop_box.upstream(), (true, true, false));
        let edit_no_delete = Grid {
            see_passwords: true,
            edit: true,
            ..NONE
        };
        assert_eq!(edit_no_delete.upstream(), (false, false, false));
    }

    #[test]
    fn grids_that_break_the_rules_are_refused_not_filled_in() {
        for broken in [
            Grid {
                export: true,
                ..NONE
            },
            Grid {
                print: true,
                ..NONE
            },
            Grid {
                share: true,
                edit: true,
                ..NONE
            },
            Grid {
                manage: true,
                ..NONE
            },
            Grid {
                export: false,
                ..Grid::ALL
            },
        ] {
            assert!(broken.check().is_err(), "{broken:?}");
            assert!(requested(true, false, false, Some(&broken)).is_err());
        }
        assert!(NONE.check().is_ok());
        assert!(Grid::ALL.check().is_ok());
        // Without a grid, upstream's fields are taken at their word.
        assert_eq!(requested(false, false, false, None).ok(), Some(Grid::preset(false, false, false)));
    }

    #[test]
    fn several_ways_in_give_the_most_open_of_each() {
        let view_hidden = Grid::preset(true, true, false);
        let drop_box = Grid {
            create: true,
            ..NONE
        };
        let merged = view_hidden.or(drop_box);
        assert!(merged.create && merged.view_history && !merged.see_passwords && !merged.edit);
        // See passwords stays off only while every way turns it off.
        assert!(view_hidden.or(Grid::preset(true, false, false)).see_passwords);
        assert!(!view_hidden.or(Grid::preset(false, true, false)).see_passwords);
        assert!(drop_box.within(&merged));
        assert!(!merged.within(&drop_box));
        assert!(merged.within(&Grid::ALL));
    }

    #[test]
    fn a_row_counts_only_while_the_grant_has_the_values_it_was_saved_with() {
        let custom = Grid {
            see_passwords: true,
            edit: true,
            export: true,
            ..NONE
        };
        let extra = Extra::of(&custom);
        assert_eq!(grid_of(custom.upstream(), Some(&extra)), custom);
        // Changed by an upstream client: the preset its fields name.
        assert_eq!(grid_of((true, false, false), Some(&extra)), Grid::preset(true, false, false));
        assert_eq!(grid_of((false, false, true), Some(&extra)), Grid::ALL);
        // No row: the preset.
        assert_eq!(grid_of((false, true, false), None), Grid::preset(false, true, false));
    }

    #[test]
    fn an_item_gets_what_any_of_its_folders_allows() {
        let org: OrganizationId = "org".to_owned().into();
        let a: CollectionId = "a".to_owned().into();
        let b: CollectionId = "b".to_owned().into();
        let c: CollectionId = "c".to_owned().into();
        let access = Access {
            full: HashMap::new(),
            folders: HashMap::from([
                (a.clone(), Grid::preset(true, true, false)),
                (
                    b.clone(),
                    Grid {
                        see_passwords: true,
                        delete: true,
                        ..NONE
                    },
                ),
            ]),
        };
        let grid = access.for_item(&org, &[a.clone(), b.clone(), c.clone()]).unwrap_or_default();
        assert!(grid.see_passwords && grid.delete && grid.view_history && !grid.edit);
        assert_eq!(access.for_item(&org, std::slice::from_ref(&c)), None);
        assert_eq!(access.for_item(&org, &[]), None);
        assert_eq!(access.in_collection(&org, &c), None);
        let full = Access {
            full: HashMap::from([(org.clone(), Grid::ALL)]),
            folders: HashMap::new(),
        };
        assert_eq!(full.for_item(&org, &[]), Some(Grid::ALL));
        assert_eq!(full.in_collection(&org, &c), Some(Grid::ALL));
        // Every item without managing, plus a folder someone was given to manage.
        let technician = Access {
            full: HashMap::from([(org.clone(), Grid::EVERY_ITEM)]),
            folders: HashMap::from([(a.clone(), Grid::ALL)]),
        };
        assert_eq!(technician.in_collection(&org, &c), Some(Grid::EVERY_ITEM));
        assert_eq!(technician.in_collection(&org, &a), Some(Grid::ALL));
        assert!(technician.manages_any(&org, &HashSet::from([a])));
        assert!(!technician.manages_any(&org, &HashSet::from([b])));
    }
}

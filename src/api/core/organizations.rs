use std::collections::{HashMap, HashSet};

use num_traits::FromPrimitive;
use rocket::{Route, http::Status, serde::json::Json};
use serde_json::Value;

use crate::{
    CONFIG,
    api::admin::FAKE_ADMIN_UUID,
    api::{
        ApiResult, EmptyResult, JsonResult, Notify, PasswordOrOtpData, UpdateType,
        core::{CipherSyncData, CipherSyncType, accept_org_invite, log_event, two_factor},
    },
    auth::{
        AdminHeaders, ClientIp, Headers, ManagerHeaders, ManagerHeadersLoose, OrgMemberHeaders, OwnerHeaders,
        decode_invite,
    },
    db::{
        DbConn,
        models::{
            Cipher, CipherId, Collection, CollectionCipher, CollectionGroup, CollectionId, CollectionUser, Device,
            EventType, Group, GroupId, GroupUser, Invitation, Membership, MembershipId, MembershipStatus,
            MembershipType, OrgPolicy, OrgPolicyType, Organization, OrganizationApiKey, OrganizationId, TwoFactor,
            TwoFactorType, User, UserId, exempt_from_member_policies, invite_hours,
            keykeeper_folder_permissions::{self as folder_permissions, Access, Extras, Grid},
        },
    },
    mail,
    sso::FAKE_SSO_IDENTIFIER,
    util::{NumberOrString, convert_json_key_lcase_first},
};

pub fn routes() -> Vec<Route> {
    routes![
        get_organization,
        create_organization,
        delete_organization,
        leave_organization,
        get_user_collections,
        get_org_collections,
        get_org_collections_details,
        get_org_collection_detail,
        get_collection_users,
        put_organization,
        post_organization_collections,
        post_bulk_access_collections,
        put_organization_collection_update,
        delete_organization_collection,
        bulk_delete_organization_collections,
        post_bulk_collections,
        get_org_details,
        get_org_domain_sso_verified,
        get_members,
        send_invite,
        reinvite_member,
        bulk_reinvite_members,
        confirm_invite,
        bulk_confirm_invite,
        accept_invite,
        get_org_user_mini_details,
        get_user,
        edit_member,
        delete_member,
        bulk_delete_member,
        post_org_import,
        list_policies,
        list_policies_token,
        get_dummy_master_password_policy,
        get_master_password_policy,
        get_policy,
        put_policy,
        get_plans,
        post_org_keys,
        get_organization_keys,
        get_organization_public_key,
        bulk_public_keys,
        revoke_member,
        bulk_revoke_members,
        restore_member,
        restore_member_vnext,
        bulk_restore_members,
        get_groups,
        get_groups_details,
        post_groups,
        get_group,
        put_group,
        get_group_details,
        delete_group,
        bulk_delete_groups,
        get_group_members,
        put_reset_password_enrollment,
        get_reset_password_details,
        put_recover_account,
        get_org_export,
        post_api_key,
        rotate_api_key,
        get_billing_warnings,
        get_auto_enroll_status,
        get_self_host_billing_metadata,
    ]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgData {
    billing_email: String,
    collection_name: String,
    key: String,
    name: String,
    keys: Option<OrgKeyData>,
    #[allow(dead_code)]
    plan_type: NumberOrString, // Ignored, always use the same plan
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OrganizationUpdateData {
    billing_email: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullCollectionData {
    name: String,
    groups: Vec<CollectionGroupData>,
    users: Vec<CollectionMembershipData>,
    external_id: Option<String>,
}

impl FullCollectionData {
    pub async fn validate(&self, org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
        // Keykeeper: every grid follows the grid's rules, before anything changes.
        for g in &self.groups {
            g.grid()?;
        }
        for u in &self.users {
            u.grid()?;
        }

        let org_groups = Group::find_by_organization(org_id, conn).await;
        let org_group_ids: HashSet<&GroupId> = org_groups.iter().map(|c| &c.uuid).collect();
        if let Some(e) = self.groups.iter().find(|g| !org_group_ids.contains(&g.id)) {
            err!("Invalid group", format!("Group {} does not belong to organization {}!", e.id, org_id))
        }

        let org_memberships = Membership::find_by_org(org_id, conn).await;
        let org_membership_ids: HashSet<&MembershipId> = org_memberships.iter().map(|m| &m.uuid).collect();
        if let Some(e) = self.users.iter().find(|m| !org_membership_ids.contains(&m.id)) {
            err!("Invalid member", format!("Member {} does not belong to organization {}!", e.id, org_id))
        }

        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionGroupData {
    hide_passwords: bool,
    id: GroupId,
    read_only: bool,
    manage: bool,
    /// Keykeeper: the grant's grid. Without it, the preset upstream's fields
    /// name (DESIGN.md, "Folders and permissions").
    #[serde(default)]
    keykeeper: Option<Grid>,
}

impl CollectionGroupData {
    fn grid(&self) -> ApiResult<Grid> {
        folder_permissions::requested(self.read_only, self.hide_passwords, self.manage, self.keykeeper.as_ref())
    }

    /// The grant to save over the stored one (folder_permissions::resolve).
    fn grid_over(&self, stored: Option<Grid>) -> ApiResult<Grid> {
        folder_permissions::resolve(self.read_only, self.hide_passwords, self.manage, self.keykeeper.as_ref(), stored)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionMembershipData {
    hide_passwords: bool,
    id: MembershipId,
    read_only: bool,
    manage: bool,
    /// Keykeeper: as for CollectionGroupData.
    #[serde(default)]
    keykeeper: Option<Grid>,
}

impl CollectionMembershipData {
    fn grid(&self) -> ApiResult<Grid> {
        folder_permissions::requested(self.read_only, self.hide_passwords, self.manage, self.keykeeper.as_ref())
    }

    /// The grant to save over the stored one (folder_permissions::resolve).
    fn grid_over(&self, stored: Option<Grid>) -> ApiResult<Grid> {
        folder_permissions::resolve(self.read_only, self.hide_passwords, self.manage, self.keykeeper.as_ref(), stored)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgKeyData {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BulkGroupIds {
    ids: Vec<GroupId>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BulkMembershipIds {
    ids: Vec<MembershipId>,
}

#[post("/organizations", data = "<data>")]
async fn create_organization(headers: Headers, data: Json<OrgData>, conn: DbConn) -> JsonResult {
    if !CONFIG.is_org_creation_allowed(&headers.user.email) {
        err!("User not allowed to create organizations")
    }
    if OrgPolicy::is_applicable_to_user(&headers.user.uuid, OrgPolicyType::SingleOrg, None, &conn).await {
        err!(
            "You may not create an organization. You belong to an organization which has a policy that prohibits you from being a member of any other organization."
        )
    }

    let data: OrgData = data.into_inner();
    let (private_key, public_key) = if let Some(keys) = data.keys {
        (Some(keys.encrypted_private_key), Some(keys.public_key))
    } else {
        (None, None)
    };

    let org = Organization::new(data.name, &data.billing_email, private_key, public_key);
    let mut member = Membership::new(headers.user.uuid, org.uuid.clone(), None);
    let collection = Collection::new(org.uuid.clone(), data.collection_name, None);

    member.akey = data.key;
    member.access_all = true;
    member.atype = MembershipType::Owner as i32;
    member.status = MembershipStatus::Confirmed as i32;

    org.save(&conn).await?;
    member.save(&conn).await?;
    collection.save(&conn).await?;

    Ok(Json(org.to_json()))
}

#[delete("/organizations/<org_id>", data = "<data>")]
async fn delete_organization(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: PasswordOrOtpData = data.into_inner();

    data.validate(&headers.user, true, &conn).await?;
    // Keykeeper: an MSP's people can't delete a client that has owners of its own.
    super::keykeeper_offboarding::ensure_may_delete_org(&org_id, &headers.user, &conn).await?;

    match Organization::find_by_uuid(&org_id, &conn).await {
        None => err!("Organization not found"),
        Some(org) => org.delete(&conn).await,
    }
}

#[post("/organizations/<org_id>/leave")]
async fn leave_organization(org_id: OrganizationId, headers: OrgMemberHeaders, conn: DbConn) -> EmptyResult {
    if headers.membership.status != MembershipStatus::Confirmed as i32 {
        err!("You need to be a Member of the Organization to call this endpoint")
    }
    let membership = headers.membership;

    if membership.atype == MembershipType::Owner
        && Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1
    {
        err!("The last owner can't leave")
    }

    log_event(
        EventType::OrganizationUserLeft,
        &membership.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    membership.delete(&conn).await
}

#[get("/organizations/<org_id>")]
async fn get_organization(org_id: OrganizationId, headers: OwnerHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if let Some(organization) = Organization::find_by_uuid(&org_id, &conn).await {
        Ok(Json(organization.to_json()))
    } else {
        err!("Can't find organization details")
    }
}

#[put("/organizations/<org_id>", data = "<data>")]
async fn put_organization(
    org_id: OrganizationId,
    headers: OwnerHeaders,
    data: Json<OrganizationUpdateData>,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let data: OrganizationUpdateData = data.into_inner();

    let Some(mut org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err!("Organization not found")
    };

    org.name = data.name;
    org.billing_email = data.billing_email.to_lowercase();

    org.save(&conn).await?;

    log_event(
        EventType::OrganizationUpdated,
        org_id.as_ref(),
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    Ok(Json(org.to_json()))
}

// GET /api/collections?writeOnly=false
#[get("/collections")]
async fn get_user_collections(headers: Headers, conn: DbConn) -> Json<Value> {
    Json(json!({
        "data":
            Collection::find_by_user_uuid(headers.user.uuid, &conn).await
            .iter()
            .map(Collection::to_json)
            .collect::<Value>(),
        "object": "list",
        "continuationToken": null,
    }))
}

// Called during the SSO enrollment
// The `identifier` should be the value returned by `get_org_domain_sso_verified`
// The returned `Id` will then be passed to `get_master_password_policy` which will mainly ignore it
#[get("/organizations/<identifier>/auto-enroll-status")]
async fn get_auto_enroll_status(identifier: &str, headers: Headers, conn: DbConn) -> JsonResult {
    let org = if identifier == FAKE_SSO_IDENTIFIER {
        match Membership::find_main_user_org(&headers.user.uuid, &conn).await {
            Some(member) => Organization::find_by_uuid(&member.org_uuid, &conn).await,
            None => None,
        }
    } else if let Some(org) = super::keykeeper_sso::org_for_identifier(identifier, &conn).await {
        // Keykeeper: an organization's own SSO identifier.
        Some(org)
    } else {
        Organization::find_by_uuid(&identifier.into(), &conn).await
    };

    let (id, identifier, rp_auto_enroll) = match org {
        None => (identifier.to_owned(), identifier.to_owned(), false),
        Some(org) => (
            org.uuid.to_string(),
            org.uuid.to_string(),
            OrgPolicy::org_is_reset_password_auto_enroll(&org.uuid, &conn).await,
        ),
    };

    Ok(Json(json!({
        "id": id,
        "identifier": identifier,
        "resetPasswordEnabled": rp_auto_enroll,
    })))
}

#[get("/organizations/<org_id>/collections")]
async fn get_org_collections(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    // Keykeeper: a custom role the guard admitted here reads the list for the
    // Members page, without access to all items.
    if !headers.membership.has_full_access() && headers.custom_permissions.is_none() {
        err_code!("Resource not found.", "User does not have full access", Status::NotFound.code);
    }

    Ok(Json(json!({
        "data": get_org_collections_impl(&org_id, &conn).await,
        "object": "list",
        "continuationToken": null,
    })))
}

#[get("/organizations/<org_id>/collections/details")]
async fn get_org_collections_details(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    let Some(member) = Membership::find_by_user_and_org(&headers.user.uuid, &org_id, &conn).await else {
        err!("User is not part of organization")
    };

    // get all collection memberships for the current organization
    let col_users = CollectionUser::find_by_organization_swap_user_uuid_with_member_uuid(&org_id, &conn).await;

    // check if current user has full access to the organization (either directly or via any group)
    let has_full_access_to_org = member.has_full_access()
        || (CONFIG.org_groups_enabled() && GroupUser::has_full_access_by_member(&org_id, &member.uuid, &conn).await);

    // Keykeeper: what the caller can do in each folder, and each grant's grid
    // (DESIGN.md, "Folders and permissions"). Someone who doesn't manage a
    // folder sees no one else's access to it: a regular member who manages
    // some folders gets this list for their dialogs, and it lists who
    // reaches only the folders they manage.
    let access = Access::in_org(&headers.user.uuid, &org_id, &conn).await?;
    let collections = Collection::find_by_organization(&org_id, &conn).await;
    let collection_ids: Vec<CollectionId> = collections.iter().map(|c| c.uuid.clone()).collect();
    let extras = Extras::for_collections(&collection_ids, &conn).await?;
    let sees_access = |col: &CollectionId| {
        headers.custom_permissions.is_some()
            || headers.membership.atype >= MembershipType::Manager
            || access.in_collection(&org_id, col).is_some_and(|g| g.manage)
    };

    // Get all admins, owners and managers who can manage/access all
    // Those are currently not listed in the col_users but need to be listed too.
    let manage_all_members: Vec<Value> = Membership::find_confirmed_and_manage_all_by_org(&org_id, &conn)
        .await
        .into_iter()
        .map(|member| Grid::ALL.grant_json(&member.uuid))
        .collect();

    let mut data = Vec::new();
    for col in collections {
        // check whether the current user has access to the given collection
        let assigned = has_full_access_to_org
            || CollectionUser::has_access_to_collection_by_user(&col.uuid, &member.user_uuid, &conn).await
            || (CONFIG.org_groups_enabled()
                && GroupUser::has_access_to_collection_by_member(&col.uuid, &member.uuid, &conn).await);

        // If the user is a manager, and is not assigned to this collection, skip this and continue with the next collection
        if !assigned {
            continue;
        }

        let (users, groups): (Vec<Value>, Vec<Value>) = if sees_access(&col.uuid) {
            // get the users assigned directly to the given collection
            let mut users: Vec<Value> = col_users
                .iter()
                .filter(|collection_member| collection_member.collection_uuid == col.uuid)
                .map(|collection_member| collection_member.to_json_details_for_member(&extras))
                .collect();
            users.extend_from_slice(&manage_all_members);

            // get the group details for the given collection
            let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
                CollectionGroup::find_by_collection(&col.uuid, &conn)
                    .await
                    .iter()
                    .map(|g| g.to_json_details_for_group(&extras))
                    .collect()
            } else {
                Vec::new()
            };
            (users, groups)
        } else {
            (Vec::new(), Vec::new())
        };

        let mut json_object = col.to_json_with_grid(access.in_collection(&org_id, &col.uuid));
        json_object["assigned"] = json!(assigned);
        json_object["users"] = json!(users);
        json_object["groups"] = json!(groups);
        json_object["object"] = json!("collectionAccessDetails");
        json_object["unmanaged"] = json!(false);
        data.push(json_object);
    }

    Ok(Json(json!({
        "data": data,
        "object": "list",
        "continuationToken": null,
    })))
}

async fn get_org_collections_impl(org_id: &OrganizationId, conn: &DbConn) -> Value {
    Collection::find_by_organization(org_id, conn).await.iter().map(Collection::to_json).collect::<Value>()
}

#[post("/organizations/<org_id>/collections", data = "<data>")]
async fn post_organization_collections(
    org_id: OrganizationId,
    headers: ManagerHeadersLoose,
    data: Json<FullCollectionData>,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: FullCollectionData = data.into_inner();
    data.validate(&org_id, &conn).await?;

    // Keykeeper: and a regular member who manages a folder (admitted to read
    // what its dialog needs) doesn't make folders: owners and admins do.
    if (headers.membership.atype == MembershipType::Manager && !headers.membership.access_all)
        || headers.membership.atype == MembershipType::User
    {
        err!("You don't have permission to create collections")
    }

    let collection = Collection::new(org_id.clone(), data.name, data.external_id);
    collection.save(&conn).await?;

    log_event(
        EventType::CollectionCreated,
        &collection.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    // Keykeeper: each grant with its grid, checked in validate().
    for group in data.groups {
        folder_permissions::save_group(&collection.uuid, &group.id, &org_id, &group.grid()?, &conn).await?;
    }

    for user in data.users {
        let Some(member) = Membership::find_by_uuid_and_org(&user.id, &org_id, &conn).await else {
            err!("User is not part of organization")
        };

        if member.access_all {
            continue;
        }

        folder_permissions::save_user(&member.user_uuid, &collection.uuid, &user.grid()?, &conn).await?;
    }

    Ok(Json(collection.to_json_details(&headers.membership.user_uuid, None, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkCollectionAccessData {
    collection_ids: Vec<CollectionId>,
    groups: Vec<CollectionGroupData>,
    users: Vec<CollectionMembershipData>,
}

#[post("/organizations/<org_id>/collections/bulk-access", data = "<data>", rank = 1)]
async fn post_bulk_access_collections(
    org_id: OrganizationId,
    headers: ManagerHeadersLoose,
    data: Json<BulkCollectionAccessData>,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkCollectionAccessData = data.into_inner();

    if Organization::find_by_uuid(&org_id, &conn).await.is_none() {
        err!("Can't find organization details")
    }

    // The collections and members are checked below, the groups only here.
    let org_groups = Group::find_by_organization(&org_id, &conn).await;
    let org_group_ids: HashSet<&GroupId> = org_groups.iter().map(|g| &g.uuid).collect();
    if let Some(g) = data.groups.iter().find(|g| !org_group_ids.contains(&g.id)) {
        err!("Invalid group", format!("Group {} does not belong to organization {}!", g.id, org_id))
    }
    // Keykeeper: every grid follows the grid's rules, and every folder is
    // one the caller manages, before anything changes.
    for g in &data.groups {
        g.grid()?;
    }
    for u in &data.users {
        u.grid()?;
    }
    for col_id in &data.collection_ids {
        if !folder_permissions::manages(&headers.membership.user_uuid, &org_id, col_id, &conn).await? {
            err!("Collection not found", "The current user isn't a manager for this collection")
        }
    }

    for col_id in data.collection_ids {
        let Some(collection) = Collection::find_by_uuid_and_org(&col_id, &org_id, &conn).await else {
            err!("Collection not found")
        };

        if !collection.is_manageable_by_user(&headers.membership.user_uuid, &conn).await? {
            err!("Collection not found", "The current user isn't a manager for this collection")
        }

        // update collection modification date
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

        // Keykeeper: a grant sent back without our grid keeps the one it had.
        let stored = folder_permissions::Stored::of_collection(&col_id, &conn).await?;
        CollectionGroup::delete_all_by_collection(&col_id, &org_id, &conn).await?;
        for group in &data.groups {
            let grid = group.grid_over(stored.group(&col_id, &group.id))?;
            folder_permissions::save_group(&col_id, &group.id, &org_id, &grid, &conn).await?;
        }

        CollectionUser::delete_all_by_collection(&col_id, &conn).await?;
        for user in &data.users {
            let Some(member) = Membership::find_by_uuid_and_org(&user.id, &org_id, &conn).await else {
                err!("User is not part of organization")
            };

            if member.access_all {
                continue;
            }

            let grid = user.grid_over(stored.user(&member.user_uuid, &col_id))?;
            folder_permissions::save_user(&member.user_uuid, &col_id, &grid, &conn).await?;
        }
    }

    Ok(())
}

#[put("/organizations/<org_id>/collections/<col_id>", data = "<data>")]
async fn put_organization_collection_update(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: ManagerHeaders,
    data: Json<FullCollectionData>,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: FullCollectionData = data.into_inner();
    data.validate(&org_id, &conn).await?;

    if Organization::find_by_uuid(&org_id, &conn).await.is_none() {
        err!("Can't find organization details")
    }

    let Some(mut collection) = Collection::find_by_uuid_and_org(&col_id, &org_id, &conn).await else {
        err!("Collection not found")
    };

    collection.name = data.name;
    collection.external_id = match data.external_id {
        Some(external_id) if !external_id.trim().is_empty() => Some(external_id),
        _ => None,
    };

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

    // Keykeeper: each grant with its grid, checked in validate(). A grant
    // sent back without our grid keeps the one it had.
    let stored = folder_permissions::Stored::of_collection(&col_id, &conn).await?;
    CollectionGroup::delete_all_by_collection(&col_id, &org_id, &conn).await?;

    for group in data.groups {
        let grid = group.grid_over(stored.group(&col_id, &group.id))?;
        folder_permissions::save_group(&col_id, &group.id, &org_id, &grid, &conn).await?;
    }

    CollectionUser::delete_all_by_collection(&col_id, &conn).await?;

    for user in data.users {
        let Some(member) = Membership::find_by_uuid_and_org(&user.id, &org_id, &conn).await else {
            err!("User is not part of organization")
        };

        if member.access_all {
            continue;
        }

        let grid = user.grid_over(stored.user(&member.user_uuid, &col_id))?;
        folder_permissions::save_user(&member.user_uuid, &col_id, &grid, &conn).await?;
    }

    Ok(Json(collection.to_json_details(&headers.user.uuid, None, &conn).await))
}

async fn delete_organization_collection_impl(
    org_id: &OrganizationId,
    col_id: &CollectionId,
    headers: &ManagerHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(collection) = Collection::find_by_uuid_and_org(col_id, org_id, conn).await else {
        err!("Collection not found", "Collection does not exist or does not belong to this organization")
    };
    log_event(
        EventType::CollectionDeleted,
        &collection.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;
    collection.delete(conn).await
}

#[delete("/organizations/<org_id>/collections/<col_id>")]
async fn delete_organization_collection(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: ManagerHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_organization_collection_impl(&org_id, &col_id, &headers, &conn).await
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BulkCollectionIds {
    ids: Vec<CollectionId>,
}

#[delete("/organizations/<org_id>/collections", data = "<data>")]
async fn bulk_delete_organization_collections(
    org_id: OrganizationId,
    headers: ManagerHeadersLoose,
    data: Json<BulkCollectionIds>,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkCollectionIds = data.into_inner();

    let collections = data.ids;

    let headers = ManagerHeaders::from_loose(headers, &collections, &conn).await?;

    for col_id in collections {
        delete_organization_collection_impl(&org_id, &col_id, &headers, &conn).await?;
    }
    Ok(())
}

#[get("/organizations/<org_id>/collections/<col_id>/details")]
async fn get_org_collection_detail(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: ManagerHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match Collection::find_by_uuid_and_user(&col_id, headers.user.uuid.clone(), &conn).await {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.org_uuid != org_id {
                err!("Collection is not owned by organization")
            }

            let Some(member) = Membership::find_by_user_and_org(&headers.user.uuid, &org_id, &conn).await else {
                err!("User is not part of organization")
            };

            // Keykeeper: each grant's grid.
            let extras = Extras::for_collections(std::slice::from_ref(&collection.uuid), &conn).await?;
            let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
                CollectionGroup::find_by_collection(&collection.uuid, &conn)
                    .await
                    .iter()
                    .map(|g| g.to_json_details_for_group(&extras))
                    .collect()
            } else {
                // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
                // so just act as if there are no groups.
                Vec::new()
            };

            let users: Vec<Value> =
                CollectionUser::find_by_org_and_coll_swap_user_uuid_with_member_uuid(&org_id, &collection.uuid, &conn)
                    .await
                    .iter()
                    .map(|collection_member| collection_member.to_json_details_for_member(&extras))
                    .collect();

            let assigned = Collection::can_access_collection(&member, &collection.uuid, &conn).await;

            let mut json_object = collection.to_json_details(&headers.user.uuid, None, &conn).await;
            json_object["assigned"] = json!(assigned);
            json_object["users"] = json!(users);
            json_object["groups"] = json!(groups);
            json_object["object"] = json!("collectionAccessDetails");

            Ok(Json(json_object))
        }
    }
}

#[get("/organizations/<org_id>/collections/<col_id>/users")]
async fn get_collection_users(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: ManagerHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    // Get org and collection, check that collection is from org
    let Some(collection) = Collection::find_by_uuid_and_org(&col_id, &org_id, &conn).await else {
        err!("Collection not found in Organization")
    };

    // Keykeeper: each grant's grid.
    let extras = Extras::for_collections(std::slice::from_ref(&collection.uuid), &conn).await?;
    let mut member_list = Vec::new();
    for col_user in CollectionUser::find_by_collection(&collection.uuid, &conn).await {
        member_list.push(
            Membership::find_by_user_and_org(&col_user.user_uuid, &org_id, &conn)
                .await
                .unwrap()
                .to_json_user_access_restrictions(&extras.user(&col_user)),
        );
    }

    Ok(Json(json!(member_list)))
}

#[derive(FromForm)]
struct OrgIdData {
    #[field(name = "organizationId")]
    organization_id: OrganizationId,
}

#[get("/ciphers/organization-details?<data..>")]
async fn get_org_details(data: OrgIdData, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if data.organization_id != headers.membership.org_uuid {
        err_code!("Resource not found.", "Organization id's do not match", Status::NotFound.code);
    }

    if !headers.membership.has_full_access() {
        err_code!("Resource not found.", "User does not have full access", Status::NotFound.code);
    }

    Ok(Json(json!({
        "data": get_org_details_impl(&data.organization_id, &headers.host, &headers.user.uuid, &conn).await?,
        "object": "list",
        "continuationToken": null,
    })))
}

async fn get_org_details_impl(
    org_id: &OrganizationId,
    host: &str,
    user_id: &UserId,
    conn: &DbConn,
) -> Result<Value, crate::Error> {
    let ciphers = Cipher::find_by_org(org_id, conn).await;
    let cipher_sync_data = CipherSyncData::new(user_id, CipherSyncType::Organization, conn).await?;

    let mut ciphers_json = Vec::with_capacity(ciphers.len());
    for c in ciphers {
        ciphers_json.push(c.to_json(host, user_id, Some(&cipher_sync_data), CipherSyncType::Organization, conn).await?);
    }
    Ok(json!(ciphers_json))
}

// Returning a Domain/Organization here allow to prefill it and prevent prompting the user
// So we return a dummy value, since we only support a single SSO integration, and do not use the response anywhere
// In use since `v2025.6.0`, appears to use only the first `organizationIdentifier`
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgDomainSsoData {
    email: String,
}

// Keykeeper: the organization whose verified domain the email is at, if its
// single sign-on is on (keykeeper_sso). Upstream's server-wide SSO answered a
// dummy here.
#[post("/organizations/domain/sso/verified", data = "<data>")]
async fn get_org_domain_sso_verified(data: Json<OrgDomainSsoData>, ip: ClientIp, conn: DbConn) -> JsonResult {
    crate::ratelimit::check_limit_prelogin(&ip.ip)?;
    Ok(Json(super::keykeeper_sso::verified_for_email(&data.email, &conn).await))
}

#[derive(FromForm)]
struct GetOrgUserData {
    #[field(name = "includeCollections")]
    include_collections: Option<bool>,
    #[field(name = "includeGroups")]
    include_groups: Option<bool>,
}

#[get("/organizations/<org_id>/users?<data..>")]
async fn get_members(
    data: GetOrgUserData,
    org_id: OrganizationId,
    headers: ManagerHeadersLoose,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    // Keykeeper: or a custom role that manages members or account recovery.
    if !headers.membership.has_full_access() && headers.custom_permissions.is_none() {
        err_code!("Resource not found.", "User does not have full access", Status::NotFound.code);
    }

    let mut users_json = Vec::new();
    for u in Membership::find_by_org(&org_id, &conn).await {
        // The user can be a manager instead of an admin, but we've checked above that they have full access
        users_json.push(
            u.to_json_details_for_admin(
                data.include_collections.unwrap_or(false),
                data.include_groups.unwrap_or(false),
                &conn,
            )
            .await?,
        );
    }

    Ok(Json(json!({
        "data": users_json,
        "object": "list",
        "continuationToken": null,
    })))
}

#[post("/organizations/<org_id>/keys", data = "<data>")]
async fn post_org_keys(
    org_id: OrganizationId,
    data: Json<OrgKeyData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: OrgKeyData = data.into_inner();

    let mut org = if let Some(organization) = Organization::find_by_uuid(&org_id, &conn).await {
        if organization.private_key.is_some() && organization.public_key.is_some() {
            err!("Organization Keys already exist")
        }
        organization
    } else {
        err!("Can't find organization details")
    };

    org.private_key = Some(data.encrypted_private_key);
    org.public_key = Some(data.public_key);

    org.save(&conn).await?;

    Ok(Json(json!({
        "object": "organizationKeys",
        "publicKey": org.public_key,
        "privateKey": org.private_key,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteData {
    emails: Vec<String>,
    groups: Vec<GroupId>,
    r#type: NumberOrString,
    collections: Option<Vec<CollectionData>>,
    #[serde(default)]
    permissions: HashMap<String, Value>,
    /// Keykeeper: seals the inviter's app made, by email, so apps confirming
    /// in the background know an admin invited each person. See DESIGN.md,
    /// "Joins a hacked server can't forge".
    #[serde(default)]
    keykeeper_seals: HashMap<String, String>,
}

impl InviteData {
    async fn validate(&self, org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
        // Keykeeper: every grid follows the grid's rules, before anything changes.
        for c in self.collections.iter().flatten() {
            c.grid()?;
        }
        let org_collections = Collection::find_by_organization(org_id, conn).await;
        let org_collection_ids: HashSet<&CollectionId> = org_collections.iter().map(|c| &c.uuid).collect();
        if let Some(e) = self.collections.iter().flatten().find(|c| !org_collection_ids.contains(&c.id)) {
            err!("Invalid collection", format!("Collection {} does not belong to organization {}!", e.id, org_id))
        }

        let org_groups = Group::find_by_organization(org_id, conn).await;
        let org_group_ids: HashSet<&GroupId> = org_groups.iter().map(|c| &c.uuid).collect();
        if let Some(e) = self.groups.iter().find(|g| !org_group_ids.contains(g)) {
            err!("Invalid group", format!("Group {} does not belong to organization {}!", e, org_id))
        }

        // Keykeeper: seals are checked before anyone is invited.
        for seal in self.keykeeper_seals.values() {
            super::keykeeper_enrollment::checked_expiring_seal(Some(seal))?;
        }

        Ok(())
    }
}

#[post("/organizations/<org_id>/users/invite", data = "<data>")]
async fn send_invite(
    org_id: OrganizationId,
    data: Json<InviteData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: InviteData = data.into_inner();
    data.validate(&org_id, &conn).await?;

    // HACK: We need the raw user-type to be sure custom role is selected to determine the access_all permission
    // The from_str() will convert the custom role type into a manager role type
    let raw_type = &data.r#type.into_string();
    // Membership::from_str will convert custom (4) to manager (3)
    let new_type = if let Some(new_type) = MembershipType::from_str(raw_type) {
        new_type as i32
    } else {
        err!("Invalid type")
    };
    // Keykeeper: a Custom role with our permissions is a regular member plus those permissions.
    let custom_role = crate::db::models::keykeeper_roles::CustomPermissions::from_request(raw_type, &data.permissions)?;
    let new_type = if custom_role.is_some() {
        MembershipType::User as i32
    } else {
        new_type
    };

    if new_type != MembershipType::User && headers.membership_type != MembershipType::Owner {
        err!("Only Owners can invite Managers, Admins or Owners")
    }

    // HACK: This converts the Custom role which has the `Manage all collections` box checked into an access_all flag
    // Since the parent checkbox is not sent to the server we need to check and verify the child checkboxes
    // If the box is not checked, the user will still be a manager, but not with the access_all permission
    let access_all = new_type >= MembershipType::Admin
        || (raw_type.eq("4")
            && data.permissions.get("editAnyCollection") == Some(&json!(true))
            && data.permissions.get("deleteAnyCollection") == Some(&json!(true))
            && data.permissions.get("createNewCollections") == Some(&json!(true)));
    // Keykeeper: a custom role can only add regular members.
    crate::db::models::keykeeper_roles::ensure_regular_grant(
        headers.custom_permissions.as_ref(),
        new_type,
        custom_role.as_ref(),
        access_all,
    )?;
    // Keykeeper: and only to collections it reaches, without groups.
    if headers.custom_permissions.is_some() {
        if !data.groups.is_empty() {
            err!("Your role can't add people to groups")
        }
        let reach = crate::db::models::keykeeper_roles::Reach::of(&headers.user.uuid, &org_id, &conn).await?;
        for col in data.collections.iter().flatten() {
            reach.ensure_grant(&col.id, &col.grid()?)?;
        }
    }

    let mut user_created: bool;
    for email in &data.emails {
        let mut member_status = MembershipStatus::Invited as i32;
        let user = match User::find_by_mail(email, &conn).await {
            None => {
                if !CONFIG.invitations_allowed() {
                    err!(format!("User does not exist: {}", email.escape_debug()))
                }

                if !CONFIG.is_email_domain_allowed(email) {
                    err!("Email domain not eligible for invitations")
                }

                if !CONFIG.mail_enabled() {
                    Invitation::new(email).save(&conn).await?;
                }

                let mut new_user = User::new(email, None);
                new_user.save(&conn).await?;
                user_created = true;
                new_user
            }
            Some(user) => {
                if Membership::find_by_user_and_org(&user.uuid, &org_id, &conn).await.is_some() {
                    err!(format!("User already in organization: {}", email.escape_debug()))
                }
                // Keykeeper: a new invitation clears an earlier removal (keykeeper_offboarding.rs).
                super::keykeeper_offboarding::on_invite(&org_id, &user, &headers.user, &conn).await?;

                if !CONFIG.mail_enabled() {
                    if user.password_hash.is_empty() {
                        Invitation::new(email).save(&conn).await?;
                    } else {
                        // automatically accept existing users if mail is disabled
                        member_status = MembershipStatus::Accepted as i32;
                    }
                }
                user_created = false;
                user
            }
        };

        let mut new_member = Membership::new(user.uuid.clone(), org_id.clone(), Some(headers.user.email.clone()));
        new_member.access_all = access_all;
        new_member.atype = new_type;
        new_member.status = member_status;
        new_member.save(&conn).await?;
        if custom_role.is_some() {
            crate::db::models::keykeeper_roles::set(&new_member.uuid, custom_role.as_ref(), &conn).await?;
        }
        // Keykeeper: the invitation's seal, or none, so an earlier one never vouches for this.
        let seal = data.keykeeper_seals.iter().find(|(e, _)| e.eq_ignore_ascii_case(email)).map(|(_, seal)| seal);
        crate::db::models::JoinSeal::set(
            &org_id,
            email,
            crate::db::models::SealKind::Invite,
            super::keykeeper_enrollment::checked_expiring_seal(seal)?,
            &conn,
        )
        .await?;

        if CONFIG.mail_enabled() {
            let org_name = if let Some(org) = Organization::find_by_uuid(&org_id, &conn).await {
                org.name
            } else {
                err!("Error looking up organization")
            };

            if let Err(e) = mail::send_invite(
                &user,
                org_id.clone(),
                new_member.uuid.clone(),
                &org_name,
                Some(headers.user.email.clone()),
                // Keykeeper: the organization's invitation lifetime.
                invite_hours(&org_id, &conn).await,
            )
            .await
            {
                // Upon error delete the user, invite and org member records when needed
                if user_created {
                    user.delete(&conn).await?;
                } else {
                    new_member.delete(&conn).await?;
                }

                err!(format!("Error sending invite: {e:?} "));
            }
        }

        log_event(
            EventType::OrganizationUserInvited,
            &new_member.uuid,
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await;

        // If no accessAll, add the collections received
        // Keykeeper: each grant with its grid, checked in validate().
        if !access_all {
            for col in data.collections.iter().flatten() {
                match Collection::find_by_uuid_and_org(&col.id, &org_id, &conn).await {
                    None => err!("Collection not found in Organization"),
                    Some(collection) => {
                        folder_permissions::save_user(&user.uuid, &collection.uuid, &col.grid()?, &conn).await?;
                    }
                }
            }
        }

        for group_id in &data.groups {
            if Group::find_by_uuid_and_org(group_id, &org_id, &conn).await.is_none() {
                err!("Group not found in Organization")
            }
            let mut group_entry = GroupUser::new(group_id.clone(), new_member.uuid.clone());
            group_entry.save(&conn).await?;
        }
    }

    Ok(())
}

#[post("/organizations/<org_id>/users/reinvite", data = "<data>")]
async fn bulk_reinvite_members(
    org_id: OrganizationId,
    data: Json<BulkMembershipIds>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkMembershipIds = data.into_inner();

    let mut bulk_response = Vec::new();
    for member_id in data.ids {
        let err_msg = match async {
            ensure_may_reinvite(&org_id, &member_id, &headers, &conn).await?;
            reinvite_member_impl(&org_id, &member_id, &headers.user.email, &conn).await
        }
        .await
        {
            Ok(()) => String::new(),
            Err(e) => format!("{e:?}"),
        };

        bulk_response.push(json!(
            {
                "object": "OrganizationBulkConfirmResponseModel",
                "id": member_id,
                "error": err_msg
            }
        ));
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

#[post("/organizations/<org_id>/users/<member_id>/reinvite")]
async fn reinvite_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    ensure_may_reinvite(&org_id, &member_id, &headers, &conn).await?;
    reinvite_member_impl(&org_id, &member_id, &headers.user.email, &conn).await
}

/// Keykeeper: a custom role resends invitations only to regular members.
async fn ensure_may_reinvite(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &AdminHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if let Some(member) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await {
        crate::db::models::keykeeper_roles::ensure_regular_target(
            headers.custom_permissions.as_ref(),
            &headers.user.uuid,
            &member,
            conn,
        )
        .await?;
    }
    Ok(())
}

async fn reinvite_member_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    invited_by_email: &str,
    conn: &DbConn,
) -> EmptyResult {
    let Some(member) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await else {
        err!("The user hasn't been invited to the organization.")
    };

    if member.status != MembershipStatus::Invited as i32 {
        err!("The user is already accepted or confirmed to the organization")
    }

    let Some(user) = User::find_by_uuid(&member.user_uuid, conn).await else {
        err!("User not found.")
    };

    if !CONFIG.invitations_allowed() && user.password_hash.is_empty() {
        err!("Invitations are not allowed.")
    }

    let org_name = if let Some(org) = Organization::find_by_uuid(org_id, conn).await {
        org.name
    } else {
        err!("Error looking up organization.")
    };

    if CONFIG.mail_enabled() {
        // Keykeeper: the organization's invitation lifetime.
        let hours = invite_hours(org_id, conn).await;
        mail::send_invite(&user, org_id.clone(), member.uuid, &org_name, Some(invited_by_email.to_owned()), hours)
            .await?;
    } else if user.password_hash.is_empty() {
        let invitation = Invitation::new(&user.email);
        invitation.save(conn).await?;
    } else {
        Invitation::take(&user.email, conn).await;
        let mut member = member;
        member.status = MembershipStatus::Accepted as i32;
        member.save(conn).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcceptData {
    token: String,
    reset_password_key: Option<String>,
}

#[post("/organizations/<org_id>/users/<member_id>/accept", data = "<data>")]
async fn accept_invite(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: Json<AcceptData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    // The web-vault passes org_id and member_id in the URL, but we are just reading them from the JWT instead
    let data: AcceptData = data.into_inner();
    let claims = decode_invite(&data.token)?;

    // Don't allow other users from accepting an invitation.
    if !claims.email.eq(&headers.user.email) {
        err!("Invitation was issued to a different account", "Claim does not match user_id")
    }

    // If a claim org_id does not match the one in from the URI, something is wrong.
    if !claims.org_id.eq(&org_id) {
        err!("Error accepting the invitation", "Claim does not match the org_id")
    }

    // If a claim does not have a member_id or it does not match the one in from the URI, something is wrong.
    if !claims.member_id.eq(&member_id) {
        err!("Error accepting the invitation", "Claim does not match the member_id")
    }

    let member_id = &claims.member_id;
    Invitation::take(&claims.email, &conn).await;

    // skip invitation logic when we were invited via the /admin panel
    if **member_id != FAKE_ADMIN_UUID {
        let Some(mut membership) = Membership::find_by_uuid_and_org(member_id, &claims.org_id, &conn).await else {
            err!("Error accepting the invitation")
        };

        let reset_password_key = match OrgPolicy::org_is_reset_password_auto_enroll(&membership.org_uuid, &conn).await {
            true if data.reset_password_key.is_none() => err!("Reset password key is required, but not provided."),
            true => data.reset_password_key,
            false => None,
        };

        // In case the user was invited before the mail was saved in db.
        membership.invited_by_email = membership.invited_by_email.or(claims.invited_by_email);

        accept_org_invite(&headers.user, membership, reset_password_key, true, &conn).await?;
    } else if CONFIG.mail_enabled() {
        // User was invited from /admin, so they are automatically confirmed
        let org_name = CONFIG.invitation_org_name();
        mail::send_invite_confirmed(&claims.email, &org_name).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmData {
    id: Option<MembershipId>,
    key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkConfirmData {
    keys: Option<Vec<ConfirmData>>,
}

#[post("/organizations/<org_id>/users/confirm", data = "<data>")]
async fn bulk_confirm_invite(
    org_id: OrganizationId,
    data: Json<BulkConfirmData>,
    headers: AdminHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();

    let mut bulk_response = Vec::new();
    match data.keys {
        Some(keys) => {
            for invite in keys {
                let Some(member_id) = invite.id else {
                    err!("Member id is required")
                };
                let user_key = invite.key.unwrap_or_default();
                let err_msg = match confirm_invite_impl(&org_id, &member_id, &user_key, &headers, &conn, &nt).await {
                    Ok(()) => String::new(),
                    Err(e) => format!("{e:?}"),
                };

                bulk_response.push(json!(
                    {
                        "object": "OrganizationBulkConfirmResponseModel",
                        "id": member_id,
                        "error": err_msg
                    }
                ));
            }
        }
        None => error!("No keys to confirm"),
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

#[post("/organizations/<org_id>/users/<member_id>/confirm", data = "<data>")]
async fn confirm_invite(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: Json<ConfirmData>,
    headers: AdminHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let data = data.into_inner();
    let user_key = data.key.unwrap_or_default();
    confirm_invite_impl(&org_id, &member_id, &user_key, &headers, &conn, &nt).await
}

async fn confirm_invite_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    key: &str,
    headers: &AdminHeaders,
    conn: &DbConn,
    nt: &Notify<'_>,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if key.is_empty() || member_id.is_empty() {
        err!("Key or UserId is not set, unable to process request");
    }

    let Some(mut member_to_confirm) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await else {
        err!("The specified user isn't a member of the organization")
    };
    // Keykeeper: a custom role only confirms regular members.
    crate::db::models::keykeeper_roles::ensure_regular_target(
        headers.custom_permissions.as_ref(),
        &headers.user.uuid,
        &member_to_confirm,
        conn,
    )
    .await?;

    if member_to_confirm.atype != MembershipType::User && headers.membership_type != MembershipType::Owner {
        err!("Only Owners can confirm Managers, Admins or Owners")
    }

    if member_to_confirm.status != MembershipStatus::Accepted as i32 {
        err!("User in invalid state")
    }

    member_to_confirm.status = MembershipStatus::Confirmed as i32;
    member_to_confirm.akey = key.to_owned();

    // This check is also done at accept_invite, _confirm_invite, _activate_member, edit_member, admin::update_membership_type
    OrgPolicy::check_user_allowed(&member_to_confirm, "confirm", conn).await?;

    log_event(
        EventType::OrganizationUserConfirmed,
        &member_to_confirm.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;

    if CONFIG.mail_enabled() {
        let org_name = if let Some(org) = Organization::find_by_uuid(org_id, conn).await {
            org.name
        } else {
            err!("Error looking up organization.")
        };
        let address = if let Some(user) = User::find_by_uuid(&member_to_confirm.user_uuid, conn).await {
            user.email
        } else {
            err!("Error looking up user.")
        };
        mail::send_invite_confirmed(&address, &org_name).await?;
    }

    let save_result = member_to_confirm.save(conn).await;

    // Keykeeper: the seals that vouched for them are used up (DESIGN.md,
    // "Joins a hacked server can't forge").
    if save_result.is_ok()
        && let Some(user) = User::find_by_uuid(&member_to_confirm.user_uuid, conn).await
    {
        crate::db::models::JoinSeal::used_up(org_id, &user.email, conn).await?;
    }

    // Keykeeper: a client's own members get its Templates collection,
    // read-only, once they're in. Every way in ends here.
    if save_result.is_ok()
        && let Some(client) = crate::db::models::MspClient::find_by_org(org_id, conn).await
    {
        super::keykeeper_msp_templates::give_templates(&member_to_confirm, &client, conn).await?;
    }
    // Keykeeper: an approval settles an earlier removal, and the invitation's
    // seal has done its work (keykeeper_offboarding.rs).
    if save_result.is_ok() {
        super::keykeeper_offboarding::after_confirm(&member_to_confirm, conn).await?;
    }

    if let Some(user) = User::find_by_uuid(&member_to_confirm.user_uuid, conn).await {
        nt.send_user_update(UpdateType::SyncOrgKeys, &user, headers.device.push_uuid.as_ref(), conn).await;
    }

    // Keykeeper: confirmations in an MSP's clients go in the MSP's audit log.
    if save_result.is_ok() {
        super::keykeeper_msp::record_member_confirmed(
            org_id,
            &member_to_confirm.user_uuid,
            &headers.user,
            headers.ip.ip.to_string(),
            conn,
        )
        .await?;
    }

    save_result
}

// Keykeeper: a custom role that views event logs reads this too, so the event
// log can say who acted (keykeeper_roles.rs). The same fields, read only.
#[get("/organizations/<org_id>/users/mini-details", rank = 1)]
async fn get_org_user_mini_details(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    let mut members_json = Vec::new();
    for m in Membership::find_by_org(&org_id, &conn).await {
        // Keykeeper: a member admitted because they manage a folder gets the
        // people they can give it to: accepted and confirmed members, not
        // invitations or revoked members.
        if headers.folder_manager && m.status < MembershipStatus::Accepted as i32 {
            continue;
        }
        members_json.push(m.to_json_mini_details(&conn).await);
    }

    Ok(Json(json!({
        "data": members_json,
        "object": "list",
        "continuationToken": null,
    })))
}

#[get("/organizations/<org_id>/users/<member_id>?<data..>", rank = 2)]
async fn get_user(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: GetOrgUserData,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(user) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err!("The specified user isn't a member of the organization")
    };

    // In this case, when groups are requested we also need to include collections.
    // Else these will not be shown in the interface, and could lead to missing collections when saved.
    let include_groups = data.include_groups.unwrap_or(false);
    Ok(Json(
        user.to_json_details_for_admin(data.include_collections.unwrap_or(include_groups), include_groups, &conn)
            .await?,
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EditUserData {
    r#type: NumberOrString,
    collections: Option<Vec<CollectionData>>,
    groups: Option<Vec<GroupId>>,
    #[serde(default)]
    permissions: HashMap<String, Value>,
}

#[put("/organizations/<org_id>/users/<member_id>", data = "<data>", rank = 1)]
async fn edit_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: Json<EditUserData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: EditUserData = data.into_inner();
    // Keykeeper: every grid follows the grid's rules, before anything changes.
    for col in data.collections.iter().flatten() {
        col.grid()?;
    }

    // HACK: We need the raw user-type to be sure custom role is selected to determine the access_all permission
    // The from_str() will convert the custom role type into a manager role type
    let raw_type = &data.r#type.into_string();
    // MembershipType::from_str will convert custom (4) to manager (3)
    let Some(new_type) = MembershipType::from_str(raw_type) else {
        err!("Invalid type")
    };
    // Keykeeper: a Custom role with our permissions is a regular member plus those permissions.
    let custom_role = crate::db::models::keykeeper_roles::CustomPermissions::from_request(raw_type, &data.permissions)?;
    let new_type = if custom_role.is_some() {
        MembershipType::User
    } else {
        new_type
    };

    // HACK: This converts the Custom role which has the `Manage all collections` box checked into an access_all flag
    // Since the parent checkbox is not sent to the server we need to check and verify the child checkboxes
    // If the box is not checked, the user will still be a manager, but not with the access_all permission
    let access_all = new_type >= MembershipType::Admin
        || (raw_type.eq("4")
            && data.permissions.get("editAnyCollection") == Some(&json!(true))
            && data.permissions.get("deleteAnyCollection") == Some(&json!(true))
            && data.permissions.get("createNewCollections") == Some(&json!(true)));

    let Some(mut member_to_edit) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err!("The specified user isn't member of the organization")
    };
    // Keykeeper: a custom role only edits regular members, and only into regular members.
    crate::db::models::keykeeper_roles::ensure_regular_target(
        headers.custom_permissions.as_ref(),
        &headers.user.uuid,
        &member_to_edit,
        &conn,
    )
    .await?;
    crate::db::models::keykeeper_roles::ensure_regular_grant(
        headers.custom_permissions.as_ref(),
        new_type as i32,
        custom_role.as_ref(),
        access_all,
    )?;
    // Keykeeper: the member's grants as they are, so a grant sent back without
    // our grid keeps the one it had (folder_permissions::resolve).
    let stored = folder_permissions::Stored::of_member(&member_to_edit.user_uuid, &org_id, &conn).await?;
    // Keykeeper: a custom role changes only collections it reaches, giving no
    // more than it has, and leaves groups alone. A grant it leaves as it was
    // isn't one it gives.
    let reach = if headers.custom_permissions.is_some() {
        let current: HashSet<GroupId> =
            GroupUser::find_by_member(&member_to_edit.uuid, &conn).await.into_iter().map(|g| g.groups_uuid).collect();
        let requested: HashSet<GroupId> = data.groups.iter().flatten().cloned().collect();
        if current != requested {
            err!("Your role can't change someone's groups")
        }
        let reach = crate::db::models::keykeeper_roles::Reach::of(&headers.user.uuid, &org_id, &conn).await?;
        for col in data.collections.iter().flatten() {
            let had = stored.user(&member_to_edit.user_uuid, &col.id);
            let grid = col.grid_over(had)?;
            if had != Some(grid) {
                reach.ensure_grant(&col.id, &grid)?;
            }
        }
        Some(reach)
    } else {
        None
    };

    if new_type != member_to_edit.atype
        && (member_to_edit.atype >= MembershipType::Admin || new_type >= MembershipType::Admin)
        && headers.membership_type != MembershipType::Owner
    {
        err!("Only Owners can grant and remove Admin or Owner privileges")
    }
    // Keykeeper: the client sets its MSP's people's roles by removing or
    // revoking them, and an MSP's people don't demote the client's own owners
    // (keykeeper_offboarding.rs).
    super::keykeeper_offboarding::check_role_change(
        &member_to_edit,
        new_type,
        access_all,
        custom_role.as_ref(),
        &headers.user,
        &conn,
    )
    .await?;

    if member_to_edit.atype == MembershipType::Owner && headers.membership_type != MembershipType::Owner {
        err!("Only Owners can edit Owner users")
    }

    if member_to_edit.atype == MembershipType::Owner
        && new_type != MembershipType::Owner
        && member_to_edit.status == MembershipStatus::Confirmed as i32
    {
        // Removing owner permission, check that there is at least one other confirmed owner
        if Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1 {
            err!("Can't delete the last owner")
        }
    }

    member_to_edit.access_all = access_all;
    member_to_edit.atype = new_type as i32;

    // This check is also done at accept_invite, _confirm_invite, _activate_member, edit_member, admin::update_membership_type
    // We need to perform the check after changing the type since `admin` is exempt.
    OrgPolicy::check_user_allowed(&member_to_edit, "modify", &conn).await?;

    // Delete all the odd collections
    // Keykeeper: a custom role only the ones it reaches.
    for c in CollectionUser::find_by_organization_and_user_uuid(&org_id, &member_to_edit.user_uuid, &conn).await {
        if reach.as_ref().is_none_or(|r| r.contains(&c.collection_uuid)) {
            c.delete(&conn).await?;
        }
    }

    // If no accessAll, add the collections received
    // Keykeeper: each grant with its grid, checked before anything changed.
    if !access_all {
        for col in data.collections.iter().flatten() {
            match Collection::find_by_uuid_and_org(&col.id, &org_id, &conn).await {
                None => err!("Collection not found in Organization"),
                Some(collection) => {
                    let grid = col.grid_over(stored.user(&member_to_edit.user_uuid, &collection.uuid))?;
                    folder_permissions::save_user(&member_to_edit.user_uuid, &collection.uuid, &grid, &conn).await?;
                }
            }
        }
    }

    // Keykeeper: groups stay as they were for a custom role (checked above).
    if reach.is_none() {
        GroupUser::delete_all_by_member(&member_to_edit.uuid, &conn).await?;

        for group_id in data.groups.iter().flatten() {
            if Group::find_by_uuid_and_org(group_id, &org_id, &conn).await.is_none() {
                err!("Group not found in Organization")
            }
            let mut group_entry = GroupUser::new(group_id.clone(), member_to_edit.uuid.clone());
            group_entry.save(&conn).await?;
        }
    }

    log_event(
        EventType::OrganizationUserUpdated,
        &member_to_edit.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    // Keykeeper: keep the custom role in step with the edit.
    crate::db::models::keykeeper_roles::set(&member_to_edit.uuid, custom_role.as_ref(), &conn).await?;
    member_to_edit.save(&conn).await
}

#[delete("/organizations/<org_id>/users", data = "<data>")]
async fn bulk_delete_member(
    org_id: OrganizationId,
    data: Json<BulkMembershipIds>,
    headers: AdminHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkMembershipIds = data.into_inner();

    let mut bulk_response = Vec::new();
    for member_id in data.ids {
        let err_msg = match delete_member_impl(&org_id, &member_id, &headers, &conn, &nt).await {
            Ok(()) => String::new(),
            Err(e) => format!("{e:?}"),
        };

        bulk_response.push(json!(
            {
                "object": "OrganizationBulkConfirmResponseModel",
                "id": member_id,
                "error": err_msg
            }
        ));
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

#[delete("/organizations/<org_id>/users/<member_id>")]
async fn delete_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    delete_member_impl(&org_id, &member_id, &headers, &conn, &nt).await
}

async fn delete_member_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &AdminHeaders,
    conn: &DbConn,
    nt: &Notify<'_>,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(member_to_delete) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await else {
        err!("User to delete isn't member of the organization")
    };
    // Keykeeper: a custom role only removes regular members.
    crate::db::models::keykeeper_roles::ensure_regular_target(
        headers.custom_permissions.as_ref(),
        &headers.user.uuid,
        &member_to_delete,
        conn,
    )
    .await?;

    if member_to_delete.atype != MembershipType::User && headers.membership_type != MembershipType::Owner {
        err!("Only Owners can delete Admins or Owners")
    }

    if member_to_delete.atype == MembershipType::Owner && member_to_delete.status == MembershipStatus::Confirmed as i32
    {
        // Removing owner, check that there is at least one other confirmed owner
        if Membership::count_confirmed_by_org_and_type(org_id, MembershipType::Owner, conn).await <= 1 {
            err!("Can't delete the last owner")
        }
    }
    // Keykeeper: an MSP's people don't remove the client's own owners, and a
    // removal holds (keykeeper_offboarding.rs).
    super::keykeeper_offboarding::protect_own_owner(&member_to_delete, &headers.user, "remove", conn).await?;
    super::keykeeper_offboarding::before_removal(
        &member_to_delete,
        super::keykeeper_offboarding::By::Member(&headers.user),
        conn,
    )
    .await?;

    log_event(
        EventType::OrganizationUserRemoved,
        &member_to_delete.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;

    if let Some(user) = User::find_by_uuid(&member_to_delete.user_uuid, conn).await {
        nt.send_user_update(UpdateType::SyncOrgKeys, &user, headers.device.push_uuid.as_ref(), conn).await;

        if !CONFIG.mail_enabled()
            && !Membership::find_invited_by_user(&user.uuid, conn)
                .await
                .into_iter()
                .any(|m| m.uuid != member_to_delete.uuid)
        {
            Invitation::take(&user.email, conn).await;
        }
    }

    member_to_delete.delete(conn).await
}

#[post("/organizations/<org_id>/users/public-keys", data = "<data>")]
async fn bulk_public_keys(
    org_id: OrganizationId,
    data: Json<BulkMembershipIds>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkMembershipIds = data.into_inner();

    let mut bulk_response = Vec::new();
    // Check all received Membership UUID's and find the matching User to retrieve the public-key.
    // If the user does not exists, just ignore it, and do not return any information regarding that Membership UUID.
    // The web-vault will then ignore that user for the following steps.
    for member_id in data.ids {
        match Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await {
            Some(member) => match User::find_by_uuid(&member.user_uuid, &conn).await {
                Some(user) => bulk_response.push(json!(
                    {
                        "object": "organizationUserPublicKeyResponseModel",
                        "id": member_id,
                        "userId": user.uuid,
                        "key": user.public_key
                    }
                )),
                None => debug!("User doesn't exist"),
            },
            None => debug!("Membership doesn't exist"),
        }
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

use super::ciphers::CipherData;
use super::ciphers::update_cipher_from_data;
// Keykeeper: an import makes new items (keykeeper_cipher_versions).
use crate::db::models::ItemSave;

// The import endpoint only ever uses the name/id/external_id of a collection.
// Bitwarden's own server ignores `groups`/`users` here too, so do not make them
// mandatory: clients are free to leave them out.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportCollectionData {
    name: String,
    id: Option<CollectionId>,
    external_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportData {
    ciphers: Vec<CipherData>,
    collections: Vec<ImportCollectionData>,
    collection_relationships: Vec<RelationsData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelationsData {
    // Cipher index
    key: usize,
    // Collection index
    value: usize,
}

// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/Tools/Controllers/ImportCiphersController.cs#L62
#[post("/ciphers/import-organization?<query..>", data = "<data>")]
async fn post_org_import(
    query: OrgIdData,
    data: Json<ImportData>,
    headers: OrgMemberHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let org_id = query.organization_id;
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    // OrgMemberHeaders also allows invited and accepted members, which are not allowed to import
    if headers.membership.status != MembershipStatus::Confirmed as i32 {
        err!("You need to be a Member of the Organization to call this endpoint")
    }
    let data: ImportData = data.into_inner();

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_cipher_data(&data.ciphers)?;

    let existing_collections: HashMap<CollectionId, Collection> =
        Collection::find_by_organization(&org_id, &conn).await.into_iter().map(|c| (c.uuid.clone(), c)).collect();

    // Keykeeper: every relation names an item and a folder of this import,
    // checked before anything is saved, so nothing is left half done.
    let mut relations: HashMap<usize, Vec<usize>> = HashMap::new();
    for relation in &data.collection_relationships {
        if relation.key >= data.ciphers.len() || relation.value >= data.collections.len() {
            err!(Compact, "Invalid collection relationship")
        }
        relations.entry(relation.key).or_default().push(relation.value);
    }

    // Keykeeper: an import makes items, so each folder it puts them in needs
    // create, and someone who doesn't reach every folder can't leave an item
    // outside all of them (DESIGN.md, "Folders and permissions").
    let access = Access::in_org(&headers.membership.user_uuid, &org_id, &conn).await?;
    if !access.has_full(&org_id) && (0..data.ciphers.len()).any(|i| !relations.contains_key(&i)) {
        err!(Compact, "You don't have permission to import items outside your shared folders")
    }

    // Every folder is checked before any new one is made.
    for col in &data.collections {
        if let Some(collection) = col.id.as_ref().and_then(|col_id| existing_collections.get(col_id)) {
            // When not an Owner or Admin, check if the member is allowed to write to the collection.
            // Keykeeper: allowed to add items to it.
            if headers.membership.atype < MembershipType::Admin
                && !access.in_collection(&org_id, &collection.uuid).is_some_and(|g| g.create)
            {
                err!(Compact, "The current user isn't allowed to manage this collection")
            }
        } else if headers.membership.atype <= MembershipType::Manager && !headers.membership.has_full_access() {
            // We do not allow users or managers which can not manage all collections to create new collections
            // If there is any collection other than an existing import collection, abort the import.
            err!(Compact, "The current user isn't allowed to create new collections")
        }
    }
    let mut collections: Vec<CollectionId> = Vec::with_capacity(data.collections.len());
    for col in data.collections {
        let existing = col.id.as_ref().and_then(|col_id| existing_collections.get(col_id));
        let collection_uuid = if let Some(collection) = existing {
            collection.uuid.clone()
        } else {
            let new_collection = Collection::new(org_id.clone(), col.name, col.external_id);
            new_collection.save(&conn).await?;
            new_collection.uuid
        };

        collections.push(collection_uuid);
    }

    let headers: Headers = headers.into();

    // Keykeeper: each item goes into its folders as soon as it's saved, and
    // an item that can't be saved stops the import, rather than being
    // skipped: no item of this import is ever outside the folders it named.
    for (index, mut cipher_data) in data.ciphers.into_iter().enumerate() {
        // Always clear folder_id's via an organization import
        cipher_data.folder_id = None;
        // Replace the client-provided, unvalidated organizationId with the real target org
        cipher_data.organization_id = Some(org_id.clone());
        let mut cipher = Cipher::new(cipher_data.r#type, cipher_data.name.clone());
        if let Err(e) = update_cipher_from_data(
            &mut cipher,
            cipher_data,
            &headers,
            Some(collections.clone()),
            &conn,
            &nt,
            UpdateType::None,
            ItemSave::New,
        )
        .await
        {
            if Cipher::find_by_uuid(&cipher.uuid, &conn).await.is_some() {
                cipher.delete(&conn).await?;
            }
            return Err(e);
        }
        for col_index in relations.get(&index).into_iter().flatten() {
            let Some(col_id) = collections.get(*col_index) else {
                err!(Compact, "Invalid collection relationship")
            };
            CollectionCipher::save(&cipher.uuid, col_id, &conn).await?;
        }
    }

    let mut user = headers.user;
    user.update_revision(&conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkCollectionsData {
    organization_id: OrganizationId,
    cipher_ids: HashSet<CipherId>,
    collection_ids: HashSet<CollectionId>,
    remove_collections: bool,
}

// This endpoint is only reachable via the organization view, therefore this endpoint is located here
// Also Bitwarden does not send out Notifications for these changes, it only does this for individual cipher collection updates
#[post("/ciphers/bulk-collections", data = "<data>")]
async fn post_bulk_collections(data: Json<BulkCollectionsData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: BulkCollectionsData = data.into_inner();

    if Membership::find_confirmed_by_user_and_org(&headers.user.uuid, &data.organization_id, &conn).await.is_none() {
        err!("You need to be a Member of the Organization to call this endpoint")
    }

    // Keykeeper: the same rules as one item's folders (ciphers.rs,
    // change_item_folders): adding needs create in each folder and share on
    // the item, removing needs share there, the item must be editable with
    // its passwords showing, and
    // it stays in at least one folder for anyone who doesn't reach every
    // folder. Everything is checked before anything changes.
    let org_id = &data.organization_id;
    let access = Access::in_org(&headers.user.uuid, org_id, &conn).await?;
    for collection_uuid in &data.collection_ids {
        let grid = match Collection::find_by_uuid_and_org(collection_uuid, org_id, &conn).await {
            Some(_) => access.in_collection(org_id, collection_uuid),
            None => None,
        };
        let Some(grid) = grid else {
            err_code!("Resource not found", "User does not have access to a collection", 404)
        };
        let allowed = if data.remove_collections {
            grid.share
        } else {
            grid.create
        };
        if !allowed {
            err!(if data.remove_collections {
                "You don't have permission to move items out of this shared folder"
            } else {
                "You don't have permission to add items to this shared folder"
            })
        }
    }

    let mut changing = Vec::new();
    for cipher_id in &data.cipher_ids {
        // Only act on existing cipher uuid's
        // Do not abort the operation just ignore it, it could be a cipher was just deleted for example
        let Some(cipher) = Cipher::find_by_uuid_and_org(cipher_id, org_id, &conn).await else {
            continue;
        };
        let held: Vec<CollectionId> = folder_permissions::collections_of(&cipher.uuid, &conn).await?;
        let item = access.for_item(org_id, &held).unwrap_or(Grid::NONE);
        if !(item.edit && item.see_passwords) {
            err!("You don't have permission to change this item's shared folders")
        }
        let held: HashSet<CollectionId> = held.into_iter().collect();
        if data.remove_collections {
            if !access.has_full(org_id) && held.is_subset(&data.collection_ids) {
                err!("Items only leave their last shared folder by being deleted")
            }
        } else {
            // Adding an existing item to another folder needs share on it
            // (ciphers.rs, may_add_to); create in each folder was checked above.
            for collection in data.collection_ids.difference(&held) {
                super::ciphers::may_add_to(&item, access.in_collection(org_id, collection))?;
            }
        }
        changing.push(cipher);
    }

    for cipher in changing {
        // When selecting a specific collection from the left filter list, and use the bulk option, you can remove an item from that collection
        // In these cases the client will call this endpoint twice, once for adding the new collections and a second for deleting.
        if data.remove_collections {
            for collection in &data.collection_ids {
                CollectionCipher::delete(&cipher.uuid, collection, &conn).await?;
            }
        } else {
            for collection in &data.collection_ids {
                CollectionCipher::save(&cipher.uuid, collection, &conn).await?;
            }
        }
    }

    Ok(())
}

#[get("/organizations/<org_id>/policies")]
async fn list_policies(org_id: OrganizationId, headers: AdminHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let policies = OrgPolicy::find_by_org(&org_id, &conn).await;
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    Ok(Json(json!({
        "data": policies_json,
        "object": "list",
        "continuationToken": null
    })))
}

#[get("/organizations/<org_id>/policies/token?<token>")]
async fn list_policies_token(org_id: OrganizationId, token: &str, conn: DbConn) -> JsonResult {
    let invite = decode_invite(token)?;

    if invite.org_id != org_id {
        err!("Token doesn't match request organization");
    }

    // exit early when we have been invited via /admin panel
    if org_id.as_ref() == FAKE_ADMIN_UUID {
        return Ok(Json(json!({})));
    }

    // TODO: We receive the invite token as ?token=<>, validate it contains the org id
    let policies = OrgPolicy::find_by_org(&org_id, &conn).await;
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    Ok(Json(json!({
        "data": policies_json,
        "object": "list",
        "continuationToken": null
    })))
}

// Called during the SSO enrollment return the default policy
#[get("/organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password", rank = 1)]
fn get_dummy_master_password_policy() -> JsonResult {
    let (enabled, data) = match CONFIG.sso_master_password_policy_value() {
        Some(policy) if CONFIG.sso_enabled() => (true, policy.to_string()),
        _ => (false, "null".to_owned()),
    };
    let policy = OrgPolicy::new(FAKE_SSO_IDENTIFIER.into(), OrgPolicyType::MasterPassword, enabled, data);
    Ok(Json(policy.to_json()))
}

// Called during the SSO enrollment return the org policy if it exists
#[get("/organizations/<org_id>/policies/master-password", rank = 2)]
async fn get_master_password_policy(org_id: OrganizationId, _headers: OrgMemberHeaders, conn: DbConn) -> JsonResult {
    let policy =
        OrgPolicy::find_by_org_and_type(&org_id, OrgPolicyType::MasterPassword, &conn).await.unwrap_or_else(|| {
            let (enabled, data) = match CONFIG.sso_master_password_policy_value() {
                Some(policy) if CONFIG.sso_enabled() => (true, policy.to_string()),
                _ => (false, "null".to_owned()),
            };

            OrgPolicy::new(org_id, OrgPolicyType::MasterPassword, enabled, data)
        });

    Ok(Json(policy.to_json()))
}

#[get("/organizations/<org_id>/policies/<pol_type>", rank = 3)]
async fn get_policy(org_id: OrganizationId, pol_type: i32, headers: AdminHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let Some(pol_type_enum) = OrgPolicyType::from_i32(pol_type) else {
        err!("Invalid or unsupported policy type")
    };

    let policy = match OrgPolicy::find_by_org_and_type(&org_id, pol_type_enum, &conn).await {
        Some(p) => p,
        None => OrgPolicy::new(org_id.clone(), pol_type_enum, false, "null".to_owned()),
    };

    Ok(Json(policy.to_json()))
}

// Keykeeper: visible to keykeeper_msp_policies, which builds one per default.
#[derive(Deserialize)]
pub(super) struct PolicyData {
    pub enabled: bool,
    pub data: Option<Value>,
}

#[derive(Deserialize)]
struct PutPolicy {
    policy: PolicyData,
    // Ignore metadata for now as we do not yet support this
    // "metadata": {
    //     "defaultUserCollectionName": "2.xx|xx==|xx="
    // }
}

#[put("/organizations/<org_id>/policies/<pol_type>", data = "<data>")]
async fn put_policy(
    org_id: OrganizationId,
    pol_type: i32,
    data: Json<PutPolicy>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: PolicyData = data.into_inner().policy;

    let Some(pol_type_enum) = OrgPolicyType::from_i32(pol_type) else {
        err!("Invalid or unsupported policy type")
    };

    // Keykeeper: the rest is set_policy, shared with MSP default policies so a
    // default reaches each client with the same checks and side effects.
    let policy =
        set_policy(&org_id, pol_type_enum, data, &headers.user.uuid, headers.device.atype, &headers.ip.ip, &conn)
            .await?;

    Ok(Json(policy.to_json()))
}

/// Keykeeper: put_policy's body, unchanged except for its parameters. Also
/// used to apply an MSP's default policies to its clients.
pub(super) async fn set_policy(
    org_id: &OrganizationId,
    pol_type_enum: OrgPolicyType,
    data: PolicyData,
    act_user_id: &UserId,
    device_type: i32,
    ip: &std::net::IpAddr,
    conn: &DbConn,
) -> ApiResult<OrgPolicy> {
    // Bitwarden only allows the Reset Password policy when Single Org policy is enabled
    // Vaultwarden encouraged to use multiple orgs instead of groups because groups were not available in the past
    // Now that groups are available we can enforce this option when wanted.
    // We put this behind a config option to prevent breaking current installation.
    // Maybe we want to enable this by default in the future, but currently it is disabled by default.
    if CONFIG.enforce_single_org_with_reset_pw_policy() {
        if pol_type_enum == OrgPolicyType::ResetPassword && data.enabled {
            let single_org_policy_enabled =
                match OrgPolicy::find_by_org_and_type(org_id, OrgPolicyType::SingleOrg, conn).await {
                    Some(p) => p.enabled,
                    None => false,
                };

            if !single_org_policy_enabled {
                err!("Single Organization policy is not enabled. It is mandatory for this policy to be enabled.")
            }
        }

        // Also prevent the Single Org Policy to be disabled if the Reset Password policy is enabled
        if pol_type_enum == OrgPolicyType::SingleOrg && !data.enabled {
            let reset_pw_policy_enabled =
                match OrgPolicy::find_by_org_and_type(org_id, OrgPolicyType::ResetPassword, conn).await {
                    Some(p) => p.enabled,
                    None => false,
                };

            if reset_pw_policy_enabled {
                err!("Account recovery policy is enabled. It is not allowed to disable this policy.")
            }
        }
    }

    // Keykeeper: "Require single sign-on" needs the organization's single
    // sign-on and Single organization on, and keeps Single organization on.
    super::keykeeper_sso::check_policy(org_id, pol_type_enum, data.enabled, conn).await?;

    // Keykeeper: only vault lock data the clients can read.
    if pol_type_enum == OrgPolicyType::MaximumVaultTimeout {
        super::keykeeper_vault_lock::check(&data)?;
    }

    // When enabling the TwoFactorAuthentication policy, revoke all members that do not have 2FA
    if pol_type_enum == OrgPolicyType::TwoFactorAuthentication && data.enabled {
        two_factor::enforce_2fa_policy_for_org(org_id, act_user_id, device_type, ip, conn).await?;
    }

    // When enabling the SingleOrg policy, remove this org's members that are members of other orgs
    if pol_type_enum == OrgPolicyType::SingleOrg && data.enabled {
        for mut member in Membership::find_by_org(org_id, conn).await {
            // Policy only applies to non-Owner/non-Admin members who have accepted joining the org
            // Exclude invited and revoked users when checking for this policy.
            // Those users will not be allowed to accept or be activated because of the policy checks done there.
            // Keykeeper: and not to MSP staff.
            if !exempt_from_member_policies(&member, conn).await
                && member.status != MembershipStatus::Invited as i32
                && Membership::count_accepted_and_confirmed_by_user(&member.user_uuid, &member.org_uuid, conn).await > 0
            {
                if CONFIG.mail_enabled() {
                    let org = Organization::find_by_uuid(&member.org_uuid, conn).await.unwrap();
                    let user = User::find_by_uuid(&member.user_uuid, conn).await.unwrap();

                    mail::send_single_org_removed_from_org(&user.email, &org.name).await?;
                }

                log_event(EventType::OrganizationUserRemoved, &member.uuid, org_id, act_user_id, device_type, ip, conn)
                    .await;

                member.revoke();
                member.save(conn).await?;
            }
        }
    }

    let mut policy = match OrgPolicy::find_by_org_and_type(org_id, pol_type_enum, conn).await {
        Some(p) => p,
        None => OrgPolicy::new(org_id.clone(), pol_type_enum, false, "{}".to_owned()),
    };

    policy.enabled = data.enabled;
    policy.data = serde_json::to_string(&data.data)?;
    policy.save(conn).await?;

    // Keykeeper: an app syncs at unlock only when the account changed, so
    // each member's account changes with the policy. Otherwise a member's
    // browser extension wouldn't learn of a new vault lock or any other
    // policy until something else changed.
    for member in Membership::find_by_org(org_id, conn).await {
        User::update_uuid_revision(&member.user_uuid, conn).await;
    }

    log_event(EventType::PolicyUpdated, policy.uuid.as_ref(), org_id, act_user_id, device_type, ip, conn).await;

    Ok(policy)
}

#[get("/plans")]
fn get_plans() -> Json<Value> {
    // Respond with a minimal json just enough to allow the creation of an new organization.
    Json(json!({
        "object": "list",
        "data": [{
            "object": "plan",
            "type": 0,
            "product": 0,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 0,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        },{
            "object": "plan",
            "type": 0,
            "product": 1,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 1,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        }],
        "continuationToken": null
    }))
}

#[get("/organizations/<_org_id>/billing/vnext/warnings")]
fn get_billing_warnings(_org_id: OrganizationId, _headers: OrgMemberHeaders) -> Json<Value> {
    Json(json!({
        "freeTrial":null,
        "inactiveSubscription":null,
        "resellerRenewal":null,
        "taxId":null,
    }))
}

#[get("/organizations/<_org_id>/billing/vnext/self-host/metadata")]
fn get_self_host_billing_metadata(_org_id: OrganizationId, _headers: OrgMemberHeaders) -> Json<Value> {
    // Prevent a 404 error, which also causes Javascript errors.
    Json(json!({
        "isOnSecretsManagerStandalone": false, // Secrets Manager is not supported by Vaultwarden
        "organizationOccupiedSeats": 0 // Vaultwarden does not count seats
    }))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BulkRevokeMembershipIds {
    ids: Option<Vec<MembershipId>>,
}

#[put("/organizations/<org_id>/users/<member_id>/revoke")]
async fn revoke_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    revoke_member_impl(&org_id, &member_id, &headers, &conn).await
}

#[put("/organizations/<org_id>/users/revoke", data = "<data>")]
async fn bulk_revoke_members(
    org_id: OrganizationId,
    data: Json<BulkRevokeMembershipIds>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();

    let mut bulk_response = Vec::new();
    match data.ids {
        Some(members) => {
            for member_id in members {
                let err_msg = match revoke_member_impl(&org_id, &member_id, &headers, &conn).await {
                    Ok(()) => String::new(),
                    Err(e) => format!("{e:?}"),
                };

                bulk_response.push(json!(
                    {
                        "object": "OrganizationUserBulkResponseModel",
                        "id": member_id,
                        "error": err_msg
                    }
                ));
            }
        }
        None => error!("No users to revoke"),
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

async fn revoke_member_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &AdminHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match Membership::find_by_uuid_and_org(member_id, org_id, conn).await {
        Some(mut member) if member.status > MembershipStatus::Revoked as i32 => {
            if member.user_uuid == headers.user.uuid {
                err!("You cannot revoke yourself")
            }
            // Keykeeper: a custom role only revokes regular members.
            crate::db::models::keykeeper_roles::ensure_regular_target(
                headers.custom_permissions.as_ref(),
                &headers.user.uuid,
                &member,
                conn,
            )
            .await?;
            if member.atype == MembershipType::Owner && headers.membership_type != MembershipType::Owner {
                err!("Only owners can revoke other owners")
            }
            if member.atype == MembershipType::Owner
                && Membership::count_confirmed_by_org_and_type(org_id, MembershipType::Owner, conn).await <= 1
            {
                err!("Organization must have at least one confirmed owner")
            }
            // Keykeeper: an MSP's people don't revoke the client's own owners,
            // and a revoke of the MSP's people holds (keykeeper_offboarding.rs).
            super::keykeeper_offboarding::protect_own_owner(&member, &headers.user, "revoke", conn).await?;
            super::keykeeper_offboarding::before_revoke(
                &member,
                super::keykeeper_offboarding::By::Member(&headers.user),
                conn,
            )
            .await?;

            member.revoke();
            member.save(conn).await?;

            log_event(
                EventType::OrganizationUserRevoked,
                &member.uuid,
                org_id,
                &headers.user.uuid,
                headers.device.atype,
                &headers.ip.ip,
                conn,
            )
            .await;
        }
        Some(_) => err!("User is already revoked"),
        None => err!("User not found in organization"),
    }
    Ok(())
}

#[put("/organizations/<org_id>/users/<member_id>/restore/vnext")]
async fn restore_member_vnext(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    // Vaultwarden does not (yet) support the per User Collection linked to the `Enforce organization data ownership` policy.
    // Therefor we ignore the `defaultUserCollectionName` data sent and just call restore_member
    restore_member_impl(&org_id, &member_id, &headers, &conn).await
}

#[put("/organizations/<org_id>/users/<member_id>/restore")]
async fn restore_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    restore_member_impl(&org_id, &member_id, &headers, &conn).await
}

#[put("/organizations/<org_id>/users/restore", data = "<data>")]
async fn bulk_restore_members(
    org_id: OrganizationId,
    data: Json<BulkMembershipIds>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();

    let mut bulk_response = Vec::new();
    for member_id in data.ids {
        let err_msg = match restore_member_impl(&org_id, &member_id, &headers, &conn).await {
            Ok(()) => String::new(),
            Err(e) => format!("{e:?}"),
        };

        bulk_response.push(json!(
            {
                "object": "OrganizationUserBulkResponseModel",
                "id": member_id,
                "error": err_msg
            }
        ));
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

async fn restore_member_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &AdminHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match Membership::find_by_uuid_and_org(member_id, org_id, conn).await {
        Some(mut member) if member.status < MembershipStatus::Accepted as i32 => {
            if member.user_uuid == headers.user.uuid {
                err!("You cannot restore yourself")
            }
            // Keykeeper: a custom role only restores regular members.
            crate::db::models::keykeeper_roles::ensure_regular_target(
                headers.custom_permissions.as_ref(),
                &headers.user.uuid,
                &member,
                conn,
            )
            .await?;
            if member.atype == MembershipType::Owner && headers.membership_type != MembershipType::Owner {
                err!("Only owners can restore other owners")
            }
            // Keykeeper: only the client's own people restore its MSP's people
            // they revoked (keykeeper_offboarding.rs).
            let by = super::keykeeper_offboarding::By::Member(&headers.user);
            super::keykeeper_offboarding::check_restore(&member, by, conn).await?;

            member.restore();
            // This check is also done at accept_invite, _confirm_invite, _activate_member, edit_member, admin::update_membership_type
            // This check need to be done after restoring to work with the correct status
            OrgPolicy::check_user_allowed(&member, "restore", conn).await?;
            member.save(conn).await?;
            super::keykeeper_offboarding::after_restore(&member, by, conn).await?;

            log_event(
                EventType::OrganizationUserRestored,
                &member.uuid,
                org_id,
                &headers.user.uuid,
                headers.device.atype,
                &headers.ip.ip,
                conn,
            )
            .await;
        }
        Some(_) => err!("User is already active"),
        None => err!("User not found in organization"),
    }
    Ok(())
}

async fn get_groups_data(
    details: bool,
    org_id: OrganizationId,
    headers: ManagerHeadersLoose,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    // The details view (group→collection/user mappings) needs full org access; the plain list only
    // needs manage access to a collection, so a manager of a collection (directly or via a group)
    // can load it to assign groups.
    let has_full_access = headers.membership.has_full_access()
        || (CONFIG.org_groups_enabled()
            && GroupUser::has_full_access_by_member(&org_id, &headers.membership.uuid, &conn).await);
    // Keykeeper: a custom role the guard admitted here reads the groups, never
    // changes them (every other group endpoint needs an owner or admin): the
    // Members page lists each member's groups, and the member dialogs show
    // them and the collections they give.
    let custom = headers.custom_permissions.is_some();
    let allowed = custom
        || if details {
            has_full_access
        } else {
            has_full_access
                || Collection::has_manageable_collection_by_user(&org_id, &headers.membership.user_uuid, &conn).await
        };
    if !allowed {
        err_code!("Resource not found.", "User does not have access", Status::NotFound.code);
    }

    let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
        let groups = Group::find_by_organization(&org_id, &conn).await;
        let mut groups_json = Vec::with_capacity(groups.len());

        if details {
            // Keykeeper: without access to all items, a custom member sees in
            // each group only the collections they reach themselves, as in the
            // collection list the member dialogs load with it.
            let reach: Option<HashSet<String>> = if custom && !has_full_access {
                Some(
                    Collection::find_by_organization_and_user_uuid(&org_id, &headers.membership.user_uuid, &conn)
                        .await
                        .into_iter()
                        .map(|c| c.uuid.to_string())
                        .collect(),
                )
            } else {
                None
            };
            for g in groups {
                let mut group = g.to_json_details(&conn).await?;
                if custom || headers.folder_manager {
                    group["externalId"] = Value::Null;
                }
                if let (Some(reach), Some(collections)) = (&reach, group["collections"].as_array_mut()) {
                    collections.retain(|c| c["id"].as_str().is_some_and(|id| reach.contains(id)));
                }
                groups_json.push(group);
            }
        } else {
            for g in groups {
                let mut group = g.to_json();
                // Keykeeper: a directory's id is for owners and admins, not a
                // custom role or someone who manages a folder.
                if custom || headers.folder_manager {
                    group["externalId"] = Value::Null;
                }
                groups_json.push(group);
            }
        }
        groups_json
    } else {
        // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
        // so just act as if there are no groups.
        Vec::new()
    };

    Ok(Json(json!({
        "data": groups,
        "object": "list",
        "continuationToken": null,
    })))
}

#[get("/organizations/<org_id>/groups")]
async fn get_groups(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    get_groups_data(false, org_id, headers, conn).await
}

#[get("/organizations/<org_id>/groups/details", rank = 1)]
async fn get_groups_details(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    get_groups_data(true, org_id, headers, conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupRequest {
    name: String,
    #[serde(default)]
    access_all: bool,
    external_id: Option<String>,
    collections: Vec<CollectionData>,
    users: Vec<MembershipId>,
}

impl GroupRequest {
    pub fn to_group(&self, org_uuid: &OrganizationId) -> Group {
        Group::new(org_uuid.clone(), self.name.clone(), self.access_all, self.external_id.clone())
    }

    pub fn update_group(&self, mut group: Group) -> Group {
        group.name.clone_from(&self.name);
        group.access_all = self.access_all;
        // Group Updates do not support changing the external_id
        // These input fields are in a disabled state, and can only be updated/added via ldap_import

        group
    }

    /// Validate if all the collections and members belong to the provided organization
    pub async fn validate(&self, org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
        // Keykeeper: every grid follows the grid's rules, before anything changes.
        for c in &self.collections {
            c.grid()?;
        }
        let org_collections = Collection::find_by_organization(org_id, conn).await;
        let org_collection_ids: HashSet<&CollectionId> = org_collections.iter().map(|c| &c.uuid).collect();
        if let Some(e) = self.collections.iter().find(|c| !org_collection_ids.contains(&c.id)) {
            err!("Invalid collection", format!("Collection {} does not belong to organization {}!", e.id, org_id))
        }

        let org_memberships = Membership::find_by_org(org_id, conn).await;
        let org_membership_ids: HashSet<&MembershipId> = org_memberships.iter().map(|m| &m.uuid).collect();
        if let Some(e) = self.users.iter().find(|m| !org_membership_ids.contains(m)) {
            err!("Invalid member", format!("Member {} does not belong to organization {}!", e, org_id))
        }

        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CollectionData {
    id: CollectionId,
    read_only: bool,
    hide_passwords: bool,
    manage: bool,
    /// Keykeeper: the grant's grid. Without it, the preset upstream's fields
    /// name (DESIGN.md, "Folders and permissions").
    #[serde(default)]
    keykeeper: Option<Grid>,
}

impl CollectionData {
    fn grid(&self) -> ApiResult<Grid> {
        folder_permissions::requested(self.read_only, self.hide_passwords, self.manage, self.keykeeper.as_ref())
    }

    /// The grant to save over the stored one (folder_permissions::resolve).
    fn grid_over(&self, stored: Option<Grid>) -> ApiResult<Grid> {
        folder_permissions::resolve(self.read_only, self.hide_passwords, self.manage, self.keykeeper.as_ref(), stored)
    }
}

#[post("/organizations/<org_id>/groups", data = "<data>")]
async fn post_groups(
    org_id: OrganizationId,
    headers: AdminHeaders,
    data: Json<GroupRequest>,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let group_request = data.into_inner();
    group_request.validate(&org_id, &conn).await?;

    let group = group_request.to_group(&org_id);

    log_event(
        EventType::GroupCreated,
        &group.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    let stored = folder_permissions::Stored::default();
    add_update_group(group, group_request.collections, group_request.users, org_id, &stored, &headers, &conn).await
}

#[put("/organizations/<org_id>/groups/<group_id>", data = "<data>")]
async fn put_group(
    org_id: OrganizationId,
    group_id: GroupId,
    data: Json<GroupRequest>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err!("Group not found", "Group uuid is invalid or does not belong to the organization")
    };

    let group_request = data.into_inner();
    group_request.validate(&org_id, &conn).await?;

    let updated_group = group_request.update_group(group);

    // Keykeeper: a grant sent back without our grid keeps the one it had.
    let stored = folder_permissions::Stored::of_group(&group_id, &org_id, &conn).await?;
    CollectionGroup::delete_all_by_group(&group_id, &org_id, &conn).await?;
    GroupUser::delete_all_by_group(&group_id, &org_id, &conn).await?;

    log_event(
        EventType::GroupUpdated,
        &updated_group.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    add_update_group(updated_group, group_request.collections, group_request.users, org_id, &stored, &headers, &conn)
        .await
}

async fn add_update_group(
    mut group: Group,
    collections: Vec<CollectionData>,
    members: Vec<MembershipId>,
    org_id: OrganizationId,
    stored: &folder_permissions::Stored,
    headers: &AdminHeaders,
    conn: &DbConn,
) -> JsonResult {
    group.save(conn).await?;

    // Keykeeper: each grant with its grid, checked in validate(), over the
    // one it had (empty for a new group).
    for col_selection in collections {
        let grid = col_selection.grid_over(stored.group(&col_selection.id, &group.uuid))?;
        folder_permissions::save_group(&col_selection.id, &group.uuid, &org_id, &grid, conn).await?;
    }

    for assigned_member in members {
        let mut user_entry = GroupUser::new(group.uuid.clone(), assigned_member.clone());
        user_entry.save(conn).await?;

        log_event(
            EventType::OrganizationUserUpdatedGroups,
            &assigned_member,
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            conn,
        )
        .await;
    }

    Ok(Json(json!({
        "id": group.uuid,
        "organizationId": group.organizations_uuid,
        "name": group.name,
        "externalId": group.external_id,
        "object": "group"
    })))
}

#[get("/organizations/<org_id>/groups/<group_id>/details")]
async fn get_group_details(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err!("Group not found", "Group uuid is invalid or does not belong to the organization")
    };

    Ok(Json(group.to_json_details(&conn).await?))
}

#[delete("/organizations/<org_id>/groups/<group_id>")]
async fn delete_group(org_id: OrganizationId, group_id: GroupId, headers: AdminHeaders, conn: DbConn) -> EmptyResult {
    delete_group_impl(&org_id, &group_id, &headers, &conn).await
}

async fn delete_group_impl(
    org_id: &OrganizationId,
    group_id: &GroupId,
    headers: &AdminHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(group) = Group::find_by_uuid_and_org(group_id, org_id, conn).await else {
        err!("Group not found", "Group uuid is invalid or does not belong to the organization")
    };

    log_event(
        EventType::GroupDeleted,
        &group.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;

    group.delete(org_id, conn).await
}

#[delete("/organizations/<org_id>/groups", data = "<data>")]
async fn bulk_delete_groups(
    org_id: OrganizationId,
    data: Json<BulkGroupIds>,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let data: BulkGroupIds = data.into_inner();

    for group_id in data.ids {
        delete_group_impl(&org_id, &group_id, &headers, &conn).await?;
    }
    Ok(())
}

#[get("/organizations/<org_id>/groups/<group_id>", rank = 2)]
async fn get_group(org_id: OrganizationId, group_id: GroupId, headers: AdminHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err!("Group not found", "Group uuid is invalid or does not belong to the organization")
    };

    Ok(Json(group.to_json()))
}

#[get("/organizations/<org_id>/groups/<group_id>/users")]
async fn get_group_members(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    if Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await.is_none() {
        err!("Group could not be found!", "Group uuid is invalid or does not belong to the organization")
    }

    let group_members: Vec<MembershipId> = GroupUser::find_by_group(&group_id, &org_id, &conn)
        .await
        .iter()
        .map(|entry| entry.users_organizations_uuid.clone())
        .collect();

    Ok(Json(json!(group_members)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationUserResetPasswordEnrollmentRequest {
    reset_password_key: Option<String>,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationUserRecoverAccountRequest {
    new_master_password_hash: Option<String>,
    key: Option<String>,

    #[serde(default)]
    reset_master_password: bool,
    #[serde(default)]
    reset_two_factor: bool,
}

// Upstream reports this is the renamed endpoint instead of `/keys`
// But the clients do not seem to use this at all
// Just add it here in case they will
#[get("/organizations/<org_id>/public-key")]
async fn get_organization_public_key(org_id: OrganizationId, headers: OrgMemberHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err!("Organization not found")
    };

    Ok(Json(json!({
        "object": "organizationPublicKey",
        "publicKey": org.public_key,
    })))
}

// Obsolete - Renamed to public-key (2023.8), left for backwards compatibility with older clients
// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/AdminConsole/Controllers/OrganizationsController.cs#L487-L492
#[get("/organizations/<org_id>/keys")]
async fn get_organization_keys(org_id: OrganizationId, headers: OrgMemberHeaders, conn: DbConn) -> JsonResult {
    get_organization_public_key(org_id, headers, conn).await
}

// Will allow to reset 2FA too
// https://github.com/bitwarden/clients/blob/web-v2026.4.2/libs/admin-console/src/common/organization-user/models/requests/organization-user-reset-password.request.ts
#[put("/organizations/<org_id>/users/<member_id>/recover-account", data = "<data>")]
async fn put_recover_account(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    data: Json<OrganizationUserRecoverAccountRequest>,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    recover_account(org_id, member_id, headers, data.into_inner(), conn, nt).await
}

async fn recover_account(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    req: OrganizationUserRecoverAccountRequest,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err!("Required organization not found")
    };

    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &org.uuid, &conn).await else {
        err!("User to reset isn't member of required organization")
    };

    let Some(mut user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        err!("User not found")
    };

    check_reset_password_applicable_and_permissions(&org_id, &member_id, &headers, &conn).await?;

    if member.reset_password_key.is_none() {
        err!("Password reset not or not correctly enrolled");
    }
    if member.status != (MembershipStatus::Confirmed as i32) {
        err!("Organization user must be confirmed for password reset functionality");
    }

    let fallback_2fa_email =
        if req.reset_two_factor && CONFIG.mail_enabled() && CONFIG.email_2fa_auto_fallback() && user.verified() {
            TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::Email as i32, &conn).await.is_none()
        } else {
            false
        };

    // Sending email first ensure working email configuration and the resulting user notification.
    // Also this might add some protection against security flaws and misuse
    if let Err(e) = mail::send_admin_account_recovery(
        &user.email,
        user.display_name(),
        &org.name,
        req.reset_master_password,
        req.reset_two_factor,
        fallback_2fa_email,
    )
    .await
    {
        err!(format!("Error sending user reset password email: {e:#?}"));
    }

    if req.reset_master_password {
        if let Some(key) = req.key
            && let Some(hash) = req.new_master_password_hash
        {
            user.set_password(hash.as_str(), Some(key), true, None, &conn).await?;
        } else {
            err_code!("Unprocessable request", "Missing fields to reset password", Status::UnprocessableEntity.code);
        }
    }

    if req.reset_two_factor {
        TwoFactor::delete_all_by_user(&user.uuid, &conn).await?;
        Device::clear_twofactor_remember_by_user(&user.uuid, &conn).await?;
        if !fallback_2fa_email || two_factor::email::find_and_activate_email_2fa(&user.uuid, &conn).await.is_err() {
            two_factor::enforce_2fa_policy(&user, &headers.user.uuid, headers.device.atype, &headers.ip.ip, &conn)
                .await?;
        }
    }

    user.save(&conn).await?;

    nt.send_logout(&user, None, &conn).await;

    if req.reset_master_password {
        headers.log_event(EventType::OrganizationUserAdminResetPassword, &member_id, &org_id, &conn).await;
    }

    if req.reset_two_factor {
        headers.log_event(EventType::OrganizationUserAdminResetTwoFactor, &member_id, &org_id, &conn).await;
    }

    Ok(())
}

#[get("/organizations/<org_id>/users/<member_id>/reset-password-details")]
async fn get_reset_password_details(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err!("Required organization not found")
    };

    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err!("User to reset isn't member of required organization")
    };

    let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        err!("User not found")
    };

    check_reset_password_applicable_and_permissions(&org_id, &member_id, &headers, &conn).await?;

    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/AdminConsole/Models/Response/Organizations/OrganizationUserResponseModel.cs#L190
    Ok(Json(json!({
        "object": "organizationUserResetPasswordDetails",
        "organizationUserId": member_id,
        "kdf": user.client_kdf_type,
        "kdfIterations": user.client_kdf_iter,
        "kdfMemory": user.client_kdf_memory,
        "kdfParallelism": user.client_kdf_parallelism,
        "resetPasswordKey": member.reset_password_key,
        "encryptedPrivateKey": org.private_key,
    })))
}

async fn check_reset_password_applicable_and_permissions(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &AdminHeaders,
    conn: &DbConn,
) -> EmptyResult {
    check_reset_password_applicable(org_id, conn).await?;

    let Some(target_user) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await else {
        err!("Reset target user not found")
    };

    // Keykeeper: an MSP's staff are never recovered, through any membership:
    // their account reaches every client they work in. See DESIGN.md, "MSP
    // staff and account recovery".
    if super::keykeeper_msp::is_msp_membership(member_id, conn).await
        || crate::db::models::MspStaff::is_staff_anywhere(&target_user.user_uuid, conn).await
    {
        err!("MSP staff can't be recovered by an organization")
    }
    // Keykeeper: a custom role only recovers regular members.
    crate::db::models::keykeeper_roles::ensure_regular_target(
        headers.custom_permissions.as_ref(),
        &headers.user.uuid,
        &target_user,
        conn,
    )
    .await?;
    // Keykeeper: an MSP's people don't recover the client's own owners
    // (keykeeper_offboarding.rs).
    super::keykeeper_offboarding::protect_own_owner(&target_user, &headers.user, "recover", conn).await?;

    // Resetting user must be higher/equal to user to reset
    match headers.membership_type {
        MembershipType::Owner => Ok(()),
        MembershipType::Admin if target_user.atype <= MembershipType::Admin => Ok(()),
        _ => err!("No permission to reset this user's password"),
    }
}

async fn check_reset_password_applicable(org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
    if !CONFIG.mail_enabled() {
        err!("Password reset is not supported on an email-disabled instance.");
    }

    let Some(policy) = OrgPolicy::find_by_org_and_type(org_id, OrgPolicyType::ResetPassword, conn).await else {
        err!("Policy not found")
    };

    if !policy.enabled {
        err!("Reset password policy not enabled");
    }

    Ok(())
}

#[put("/organizations/<org_id>/users/<user_id>/reset-password-enrollment", data = "<data>")]
async fn put_reset_password_enrollment(
    org_id: OrganizationId,
    user_id: UserId,
    headers: OrgMemberHeaders,
    data: Json<OrganizationUserResetPasswordEnrollmentRequest>,
    conn: DbConn,
) -> EmptyResult {
    if user_id != headers.user.uuid {
        err!("User to enroll isn't member of required organization", "The user_id and acting user do not match");
    }

    let mut membership = headers.membership;

    check_reset_password_applicable(&org_id, &conn).await?;

    let reset_request = data.into_inner();

    let reset_password_key = match reset_request.reset_password_key {
        None => None,
        Some(ref key) if key.is_empty() => None,
        Some(key) => Some(key),
    };

    if reset_password_key.is_none() && OrgPolicy::org_is_reset_password_auto_enroll(&org_id, &conn).await {
        err!("Reset password can't be withdrawn due to an enterprise policy");
    }

    // Keykeeper: an MSP's staff never join any organization's account
    // recovery (see DESIGN.md, "MSP staff and account recovery").
    if reset_password_key.is_some()
        && (super::keykeeper_msp::is_msp_membership(&membership.uuid, &conn).await
            || crate::db::models::MspStaff::is_staff_anywhere(&membership.user_uuid, &conn).await)
    {
        err!("MSP staff can't join an organization's account recovery")
    }

    if reset_password_key.is_some() {
        PasswordOrOtpData {
            master_password_hash: reset_request.master_password_hash,
            otp: reset_request.otp,
        }
        .validate(&headers.user, true, &conn)
        .await?;
    }

    // Keykeeper: someone who just set their master password after their first
    // single sign-on joins here, with the recovery key, as accepting an
    // emailed invitation does (accounts.rs, post_set_password). Only for an
    // account the organization's single sign-on linked.
    if membership.status == MembershipStatus::Invited as i32
        && reset_password_key.is_some()
        && crate::db::models::SsoLink::find_by_user(&org_id, &headers.user.uuid, &conn).await.is_some()
    {
        let member_id = membership.uuid.clone();
        accept_org_invite(&headers.user, membership, reset_password_key, true, &conn).await?;
        log_event(
            EventType::OrganizationUserResetPasswordEnroll,
            &member_id,
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await;
        return Ok(());
    }

    membership.reset_password_key = reset_password_key;
    membership.save(&conn).await?;

    let event_type = if membership.reset_password_key.is_some() {
        EventType::OrganizationUserResetPasswordEnroll
    } else {
        EventType::OrganizationUserResetPasswordWithdraw
    };

    log_event(event_type, &membership.uuid, &org_id, &headers.user.uuid, headers.device.atype, &headers.ip.ip, &conn)
        .await;

    Ok(())
}

// NOTE: It seems clients can't handle uppercase-first keys!!
//       We need to convert all keys so they have the first character to be a lowercase.
//       Else the export will be just an empty JSON file.
// We currently only support exports by members of the Admin or Owner status.
// Vaultwarden does not yet support exporting only managed collections!
// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/Tools/Controllers/OrganizationExportController.cs#L52
#[get("/organizations/<org_id>/export")]
async fn get_org_export(org_id: OrganizationId, headers: AdminHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    // Keykeeper: the export holds every item, so a custom role exports only
    // with access to all items. A client's own custom roles can't have that
    // yet, so for them import and export covers import.
    if headers.custom_permissions.is_some()
        && !matches!(
            crate::db::models::keykeeper_roles::Reach::of(&headers.user.uuid, &org_id, &conn).await?,
            crate::db::models::keykeeper_roles::Reach::All
        )
    {
        err!("Exporting the organization's vault needs access to all items")
    }

    Ok(Json(json!({
        "collections": convert_json_key_lcase_first(get_org_collections_impl(&org_id, &conn).await),
        "ciphers": convert_json_key_lcase_first(get_org_details_impl(&org_id, &headers.host, &headers.user.uuid, &conn).await?),
    })))
}

async fn api_key(
    org_id: &OrganizationId,
    data: Json<PasswordOrOtpData>,
    rotate: bool,
    headers: OwnerHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    // Validate the owner users password/otp
    data.validate(&user, true, &conn).await?;

    let org_api_key = if let Some(mut org_api_key) = OrganizationApiKey::find_by_org_uuid(org_id, &conn).await {
        if rotate {
            org_api_key.api_key = crate::crypto::generate_api_key();
            org_api_key.revision_date = chrono::Utc::now().naive_utc();
            org_api_key.save(&conn).await.expect("Error rotating organization API Key");
        }
        org_api_key
    } else {
        let api_key = crate::crypto::generate_api_key();
        let new_org_api_key = OrganizationApiKey::new(org_id.clone(), api_key);
        new_org_api_key.save(&conn).await.expect("Error creating organization API Key");
        new_org_api_key
    };

    Ok(Json(json!({
      "apiKey": org_api_key.api_key,
      "revisionDate": crate::util::format_date(&org_api_key.revision_date),
      "object": "apiKey",
    })))
}

#[post("/organizations/<org_id>/api-key", data = "<data>")]
async fn post_api_key(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> JsonResult {
    api_key(&org_id, data, false, headers, conn).await
}

#[post("/organizations/<org_id>/rotate-api-key", data = "<data>")]
async fn rotate_api_key(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> JsonResult {
    api_key(&org_id, data, true, headers, conn).await
}

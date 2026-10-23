use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    CONFIG,
    api::EmptyResult,
    db::{
        DbConn,
        schema::{
            ciphers_collections, collections, collections_groups, groups, groups_users, users_collections,
            users_organizations,
        },
    },
    error::MapResult,
};
use macros::UuidFromParam;

use super::{
    CipherId, CollectionGroup, GroupUser, Membership, MembershipId, MembershipStatus, MembershipType, OrganizationId,
    User, UserId,
    keykeeper_folder_permissions::{self, Extras, Grid},
};

// See (v2026.7.0): https://github.com/bitwarden/server/blob/5d4461aa42cadbacfef8fe2166c5453a5c52773a/src/Core/AdminConsole/Entities/Collection.cs
#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = collections)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct Collection {
    pub uuid: CollectionId,
    pub org_uuid: OrganizationId,
    pub name: String,
    pub external_id: Option<String>,
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = users_collections)]
#[diesel(primary_key(user_uuid, collection_uuid))]
pub struct CollectionUser {
    pub user_uuid: UserId,
    pub collection_uuid: CollectionId,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = ciphers_collections)]
#[diesel(primary_key(cipher_uuid, collection_uuid))]
pub struct CollectionCipher {
    pub cipher_uuid: CipherId,
    pub collection_uuid: CollectionId,
}

/// Local methods
impl Collection {
    pub fn new(org_uuid: OrganizationId, name: String, external_id: Option<String>) -> Self {
        let mut new_model = Self {
            uuid: CollectionId(crate::util::get_uuid()),
            org_uuid,
            name,
            external_id: None,
        };

        new_model.set_external_id(external_id);
        new_model
    }

    pub fn to_json(&self) -> Value {
        json!({
            "externalId": self.external_id,
            "id": self.uuid,
            "organizationId": self.org_uuid,
            "name": self.name,
            // Collection types are either 0: SharedCollection or 1: DefaultUserCollection, of which we do not yet support DefaultUserCollection.
            // See (v2026.7.0): https://github.com/bitwarden/server/blob/5d4461aa42cadbacfef8fe2166c5453a5c52773a/src/Core/AdminConsole/Enums/CollectionType.cs
            "type": 0,
            // This is only used together with MyItems/DefaultUserCollection, which we do not yet support.
            "defaultUserCollectionEmail": null,
            "object": "collection",
        })
    }

    pub fn set_external_id(&mut self, external_id: Option<String>) {
        //Check if external id is empty. We don't want to have
        //empty strings in the database
        match external_id {
            Some(external_id) => {
                if external_id.is_empty() {
                    self.external_id = None;
                } else {
                    self.external_id = Some(external_id);
                }
            }
            None => self.external_id = None,
        }
    }

    /// The collection with the person's own capabilities in it. Keykeeper:
    /// upstream's three fields are the closest preset of their grid, which
    /// goes beside them (DESIGN.md, "Folders and permissions").
    pub async fn to_json_details(
        &self,
        user_uuid: &UserId,
        cipher_sync_data: Option<&crate::api::core::CipherSyncData>,
        conn: &DbConn,
    ) -> Value {
        let grid = if let Some(cipher_sync_data) = cipher_sync_data {
            cipher_sync_data.access.in_collection(&self.org_uuid, &self.uuid)
        } else {
            // A database error shows no capabilities, never more than they have.
            keykeeper_folder_permissions::in_collection(user_uuid, &self.org_uuid, &self.uuid, conn)
                .await
                .inspect_err(|e| error!("{e}"))
                .ok()
                .flatten()
        };
        self.to_json_with_grid(grid)
    }

    /// As to_json_details, with the person's capabilities already known.
    pub fn to_json_with_grid(&self, grid: Option<Grid>) -> Value {
        let grid = grid.unwrap_or(Grid::NONE);
        let (read_only, hide_passwords, manage) = grid.upstream();
        let mut json_object = self.to_json();
        json_object["object"] = json!("collectionDetails");
        json_object["readOnly"] = json!(read_only);
        json_object["hidePasswords"] = json!(hide_passwords);
        json_object["manage"] = json!(manage);
        json_object["keykeeper"] = grid.to_json();
        json_object
    }

    pub async fn can_access_collection(member: &Membership, col_id: &CollectionId, conn: &DbConn) -> bool {
        member.has_status(MembershipStatus::Confirmed)
            && (member.has_full_access()
                || CollectionUser::has_access_to_collection_by_user(col_id, &member.user_uuid, conn).await
                || (CONFIG.org_groups_enabled()
                    && (GroupUser::has_full_access_by_member(&member.org_uuid, &member.uuid, conn).await
                        || GroupUser::has_access_to_collection_by_member(col_id, &member.uuid, conn).await)))
    }
}

/// Database methods
impl Collection {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn).await;

        db_run! { conn:
            mysql {
                diesel::insert_into(collections::table)
                    .values(self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving collection")
            }
            postgresql, sqlite {
                diesel::insert_into(collections::table)
                    .values(self)
                    .on_conflict(collections::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving collection")
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn).await;
        CollectionCipher::delete_all_by_collection(&self.uuid, conn).await?;
        CollectionUser::delete_all_by_collection(&self.uuid, conn).await?;
        CollectionGroup::delete_all_by_collection(&self.uuid, &self.org_uuid, conn).await?;

        conn.run(move |conn| {
            diesel::delete(collections::table.filter(collections::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting collection")
        })
        .await
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        for collection in Self::find_by_organization(org_uuid, conn).await {
            collection.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn update_users_revision(&self, conn: &DbConn) {
        for member in &Membership::find_by_collection_and_org(&self.uuid, &self.org_uuid, conn).await {
            User::update_uuid_revision(&member.user_uuid, conn).await;
        }
    }

    pub async fn find_by_uuid(uuid: &CollectionId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| collections::table.filter(collections::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn find_by_user_uuid(user_uuid: UserId, conn: &DbConn) -> Vec<Self> {
        if CONFIG.org_groups_enabled() {
            conn.run(move |conn| {
                collections::table
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(collections::uuid)
                            .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        users_organizations::table.on(collections::org_uuid
                            .eq(users_organizations::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        groups_users::table.on(groups_users::users_organizations_uuid.eq(users_organizations::uuid)),
                    )
                    .left_join(
                        groups::table.on(groups::uuid
                            .eq(groups_users::groups_uuid)
                            .and(groups::organizations_uuid.eq(users_organizations::org_uuid))),
                    )
                    .left_join(
                        collections_groups::table.on(collections_groups::groups_uuid
                            .eq(groups_users::groups_uuid)
                            .and(collections_groups::collections_uuid.eq(collections::uuid))),
                    )
                    .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                    .filter(
                        users_collections::user_uuid
                            .eq(user_uuid)
                            .or(
                                // Directly accessed collection
                                users_organizations::access_all.eq(true), // access_all in Organization
                            )
                            .or(
                                groups::access_all.eq(true), // access_all in groups
                            )
                            .or(
                                // access via groups
                                groups_users::users_organizations_uuid
                                    .eq(users_organizations::uuid)
                                    .and(collections_groups::collections_uuid.is_not_null()),
                            ),
                    )
                    .select(collections::all_columns)
                    .distinct()
                    .load::<Self>(conn)
                    .expect("Error loading collections")
            })
            .await
        } else {
            conn.run(move |conn| {
                collections::table
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(collections::uuid)
                            .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        users_organizations::table.on(collections::org_uuid
                            .eq(users_organizations::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid.clone()))),
                    )
                    .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                    .filter(users_collections::user_uuid.eq(user_uuid).or(
                        // Directly accessed collection
                        users_organizations::access_all.eq(true), // access_all in Organization
                    ))
                    .select(collections::all_columns)
                    .distinct()
                    .load::<Self>(conn)
                    .expect("Error loading collections")
            })
            .await
        }
    }

    pub async fn find_by_organization_and_user_uuid(
        org_uuid: &OrganizationId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> Vec<Self> {
        Self::find_by_user_uuid(user_uuid.to_owned(), conn)
            .await
            .into_iter()
            .filter(|c| &c.org_uuid == org_uuid)
            .collect()
    }

    pub async fn find_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            collections::table
                .filter(collections::org_uuid.eq(org_uuid))
                .load::<Self>(conn)
                .expect("Error loading collections")
        })
        .await
    }

    pub async fn count_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> i64 {
        conn.run(move |conn| {
            collections::table.filter(collections::org_uuid.eq(org_uuid)).count().first::<i64>(conn).ok().unwrap_or(0)
        })
        .await
    }

    pub async fn find_by_uuid_and_org(uuid: &CollectionId, org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            collections::table
                .filter(collections::uuid.eq(uuid))
                .filter(collections::org_uuid.eq(org_uuid))
                .select(collections::all_columns)
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_uuid_and_user(uuid: &CollectionId, user_uuid: UserId, conn: &DbConn) -> Option<Self> {
        if CONFIG.org_groups_enabled() {
            conn.run(move |conn| {
                collections::table
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(collections::uuid)
                            .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        users_organizations::table.on(collections::org_uuid
                            .eq(users_organizations::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid))),
                    )
                    .left_join(
                        groups_users::table.on(groups_users::users_organizations_uuid.eq(users_organizations::uuid)),
                    )
                    .left_join(
                        groups::table.on(groups::uuid
                            .eq(groups_users::groups_uuid)
                            .and(groups::organizations_uuid.eq(users_organizations::org_uuid))),
                    )
                    .left_join(
                        collections_groups::table.on(collections_groups::groups_uuid
                            .eq(groups_users::groups_uuid)
                            .and(collections_groups::collections_uuid.eq(collections::uuid))),
                    )
                    .filter(collections::uuid.eq(uuid))
                    .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                    .filter(
                        users_collections::collection_uuid
                            .eq(uuid)
                            .or(
                                // Directly accessed collection
                                users_organizations::access_all.eq(true).or(
                                    // access_all in Organization
                                    users_organizations::atype.le(MembershipType::Admin as i32), // Org admin or owner
                                ),
                            )
                            .or(
                                groups::access_all.eq(true), // access_all in groups
                            )
                            .or(
                                // access via groups
                                groups_users::users_organizations_uuid
                                    .eq(users_organizations::uuid)
                                    .and(collections_groups::collections_uuid.is_not_null()),
                            ),
                    )
                    .select(collections::all_columns)
                    .first::<Self>(conn)
                    .ok()
            })
            .await
        } else {
            conn.run(move |conn| {
                collections::table
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(collections::uuid)
                            .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        users_organizations::table.on(collections::org_uuid
                            .eq(users_organizations::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid))),
                    )
                    .filter(collections::uuid.eq(uuid))
                    .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                    .filter(users_collections::collection_uuid.eq(uuid).or(
                        // Directly accessed collection
                        users_organizations::access_all.eq(true).or(
                            // access_all in Organization
                            users_organizations::atype.le(MembershipType::Admin as i32), // Org admin or owner
                        ),
                    ))
                    .select(collections::all_columns)
                    .first::<Self>(conn)
                    .ok()
            })
            .await
        }
    }

    /// Keykeeper: whether the person manages this folder, from the grid.
    pub async fn is_coll_manageable_by_user(uuid: &CollectionId, user_uuid: &UserId, conn: &DbConn) -> bool {
        match Self::find_by_uuid(uuid, conn).await {
            Some(collection) => {
                keykeeper_folder_permissions::manages(user_uuid, &collection.org_uuid, uuid, conn).await
            }
            None => false,
        }
    }

    pub async fn is_manageable_by_user(&self, user_uuid: &UserId, conn: &DbConn) -> bool {
        keykeeper_folder_permissions::manages(user_uuid, &self.org_uuid, &self.uuid, conn).await
    }

    /// Whether the person manages at least one folder of the organization,
    /// directly or through a group. Keykeeper: from the grid.
    pub async fn has_manageable_collection_by_user(
        org_uuid: &OrganizationId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> bool {
        let Ok(access) = keykeeper_folder_permissions::Access::in_org(user_uuid, org_uuid, conn).await else {
            return false;
        };
        let collections = Self::find_by_organization(org_uuid, conn).await.into_iter().map(|c| c.uuid).collect();
        access.manages_any(org_uuid, &collections)
    }
}

/// Database methods
impl CollectionUser {
    pub async fn find_by_organization_and_user_uuid(
        org_uuid: &OrganizationId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> Vec<Self> {
        conn.run(move |conn| {
            users_collections::table
                .filter(users_collections::user_uuid.eq(user_uuid))
                .inner_join(collections::table.on(collections::uuid.eq(users_collections::collection_uuid)))
                .filter(collections::org_uuid.eq(org_uuid))
                .select(users_collections::all_columns)
                .load::<Self>(conn)
                .expect("Error loading users_collections")
        })
        .await
    }

    pub async fn find_by_organization_swap_user_uuid_with_member_uuid(
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> Vec<CollectionMembership> {
        let col_users = conn
            .run(move |conn| {
                users_collections::table
                    .inner_join(collections::table.on(collections::uuid.eq(users_collections::collection_uuid)))
                    .filter(collections::org_uuid.eq(org_uuid))
                    .inner_join(
                        users_organizations::table.on(users_organizations::user_uuid.eq(users_collections::user_uuid)),
                    )
                    .filter(users_organizations::org_uuid.eq(org_uuid))
                    .select((
                        users_organizations::uuid,
                        users_collections::collection_uuid,
                        users_collections::read_only,
                        users_collections::hide_passwords,
                        users_collections::manage,
                        users_collections::user_uuid,
                    ))
                    .load::<(MembershipId, CollectionId, bool, bool, bool, UserId)>(conn)
                    .expect("Error loading users_collections")
            })
            .await;
        col_users.into_iter().map(Into::into).collect()
    }

    pub async fn save(
        user_uuid: &UserId,
        collection_uuid: &CollectionId,
        read_only: bool,
        hide_passwords: bool,
        manage: bool,
        conn: &DbConn,
    ) -> EmptyResult {
        User::update_uuid_revision(user_uuid, conn).await;

        let values = (
            users_collections::user_uuid.eq(user_uuid),
            users_collections::collection_uuid.eq(collection_uuid),
            users_collections::read_only.eq(read_only),
            users_collections::hide_passwords.eq(hide_passwords),
            users_collections::manage.eq(manage),
        );

        db_run! { conn:
            mysql {
                diesel::insert_into(users_collections::table)
                    .values(values)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(values)
                    .execute(conn)
                    .map_res("Error adding user to collection")
            }
            postgresql, sqlite {
                diesel::insert_into(users_collections::table)
                    .values(values)
                    .on_conflict((users_collections::user_uuid, users_collections::collection_uuid))
                    .do_update()
                    .set(values)
                    .execute(conn)
                    .map_res("Error adding user to collection")
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn).await;

        conn.run(move |conn| {
            diesel::delete(
                users_collections::table
                    .filter(users_collections::user_uuid.eq(&self.user_uuid))
                    .filter(users_collections::collection_uuid.eq(&self.collection_uuid)),
            )
            .execute(conn)
            .map_res("Error removing user from collection")
        })
        .await
    }

    pub async fn find_by_collection(collection_uuid: &CollectionId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_collections::table
                .filter(users_collections::collection_uuid.eq(collection_uuid))
                .select(users_collections::all_columns)
                .load::<Self>(conn)
                .expect("Error loading users_collections")
        })
        .await
    }

    pub async fn find_by_org_and_coll_swap_user_uuid_with_member_uuid(
        org_uuid: &OrganizationId,
        collection_uuid: &CollectionId,
        conn: &DbConn,
    ) -> Vec<CollectionMembership> {
        let col_users = conn
            .run(move |conn| {
                users_collections::table
                    .filter(users_collections::collection_uuid.eq(collection_uuid))
                    .filter(users_organizations::org_uuid.eq(org_uuid))
                    .inner_join(
                        users_organizations::table.on(users_organizations::user_uuid.eq(users_collections::user_uuid)),
                    )
                    .select((
                        users_organizations::uuid,
                        users_collections::collection_uuid,
                        users_collections::read_only,
                        users_collections::hide_passwords,
                        users_collections::manage,
                        users_collections::user_uuid,
                    ))
                    .load::<(MembershipId, CollectionId, bool, bool, bool, UserId)>(conn)
                    .expect("Error loading users_collections")
            })
            .await;
        col_users.into_iter().map(Into::into).collect()
    }

    pub async fn find_by_collection_and_user(
        collection_uuid: &CollectionId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> Option<Self> {
        conn.run(move |conn| {
            users_collections::table
                .filter(users_collections::collection_uuid.eq(collection_uuid))
                .filter(users_collections::user_uuid.eq(user_uuid))
                .select(users_collections::all_columns)
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    // Only returns the collections of organizations the user is a confirmed member of
    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_collections::table
                .inner_join(collections::table.on(collections::uuid.eq(users_collections::collection_uuid)))
                .inner_join(
                    users_organizations::table.on(users_organizations::org_uuid
                        .eq(collections::org_uuid)
                        .and(users_organizations::user_uuid.eq(users_collections::user_uuid))),
                )
                .filter(users_collections::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .select(users_collections::all_columns)
                .load::<Self>(conn)
                .expect("Error loading users_collections")
        })
        .await
    }

    pub async fn delete_all_by_collection(collection_uuid: &CollectionId, conn: &DbConn) -> EmptyResult {
        for collection in &CollectionUser::find_by_collection(collection_uuid, conn).await {
            User::update_uuid_revision(&collection.user_uuid, conn).await;
        }

        conn.run(move |conn| {
            diesel::delete(users_collections::table.filter(users_collections::collection_uuid.eq(collection_uuid)))
                .execute(conn)
                .map_res("Error deleting users from collection")
        })
        .await
    }

    pub async fn delete_all_by_user_and_org(
        user_uuid: &UserId,
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> EmptyResult {
        let collectionusers = Self::find_by_organization_and_user_uuid(org_uuid, user_uuid, conn).await;

        conn.run(move |conn| {
            for user in collectionusers {
                let _: () = diesel::delete(
                    users_collections::table.filter(
                        users_collections::user_uuid
                            .eq(user_uuid)
                            .and(users_collections::collection_uuid.eq(user.collection_uuid)),
                    ),
                )
                .execute(conn)
                .map_res("Error removing user from collections")?;
            }
            Ok(())
        })
        .await
    }

    pub async fn has_access_to_collection_by_user(col_id: &CollectionId, user_uuid: &UserId, conn: &DbConn) -> bool {
        Self::find_by_collection_and_user(col_id, user_uuid, conn).await.is_some()
    }
}

/// Database methods
impl CollectionCipher {
    pub async fn save(cipher_uuid: &CipherId, collection_uuid: &CollectionId, conn: &DbConn) -> EmptyResult {
        Self::update_users_revision(collection_uuid, conn).await;

        db_run! { conn:
            mysql {
                diesel::insert_into(ciphers_collections::table)
                    .values((
                        ciphers_collections::cipher_uuid.eq(cipher_uuid),
                        ciphers_collections::collection_uuid.eq(collection_uuid),
                    ))
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_nothing()
                    .execute(conn)
                    .map_res("Error adding cipher to collection")
            }
            postgresql, sqlite {
                diesel::insert_into(ciphers_collections::table)
                    .values((
                        ciphers_collections::cipher_uuid.eq(cipher_uuid),
                        ciphers_collections::collection_uuid.eq(collection_uuid),
                    ))
                    .on_conflict((ciphers_collections::cipher_uuid, ciphers_collections::collection_uuid))
                    .do_nothing()
                    .execute(conn)
                    .map_res("Error adding cipher to collection")
            }
        }
    }

    pub async fn delete(cipher_uuid: &CipherId, collection_uuid: &CollectionId, conn: &DbConn) -> EmptyResult {
        Self::update_users_revision(collection_uuid, conn).await;

        conn.run(move |conn| {
            diesel::delete(
                ciphers_collections::table
                    .filter(ciphers_collections::cipher_uuid.eq(cipher_uuid))
                    .filter(ciphers_collections::collection_uuid.eq(collection_uuid)),
            )
            .execute(conn)
            .map_res("Error deleting cipher from collection")
        })
        .await
    }

    pub async fn delete_all_by_cipher(cipher_uuid: &CipherId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(ciphers_collections::table.filter(ciphers_collections::cipher_uuid.eq(cipher_uuid)))
                .execute(conn)
                .map_res("Error removing cipher from collections")
        })
        .await
    }

    pub async fn delete_all_by_collection(collection_uuid: &CollectionId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(ciphers_collections::table.filter(ciphers_collections::collection_uuid.eq(collection_uuid)))
                .execute(conn)
                .map_res("Error removing ciphers from collection")
        })
        .await
    }

    pub async fn update_users_revision(collection_uuid: &CollectionId, conn: &DbConn) {
        if let Some(collection) = Collection::find_by_uuid(collection_uuid, conn).await {
            collection.update_users_revision(conn).await;
        }
    }
}

// Added in case we need the membership_uuid instead of the user_uuid
pub struct CollectionMembership {
    pub membership_uuid: MembershipId,
    pub collection_uuid: CollectionId,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
    /// Keykeeper: whose grant it is, to read its grid.
    pub user_uuid: UserId,
}

impl CollectionMembership {
    /// Keykeeper: the grant as upstream's clients read it, from its grid
    /// (DESIGN.md, "Folders and permissions"). Upstream showed a Manager's
    /// editable folders as managed without letting them manage; now what it
    /// shows is what the server allows.
    pub fn to_json_details_for_member(&self, extras: &Extras) -> Value {
        extras
            .user_grant(&self.user_uuid, &self.collection_uuid, (self.read_only, self.hide_passwords, self.manage))
            .grant_json(&self.membership_uuid)
    }
}

impl From<(MembershipId, CollectionId, bool, bool, bool, UserId)> for CollectionMembership {
    fn from(c: (MembershipId, CollectionId, bool, bool, bool, UserId)) -> Self {
        Self {
            membership_uuid: c.0,
            collection_uuid: c.1,
            read_only: c.2,
            hide_passwords: c.3,
            manage: c.4,
            user_uuid: c.5,
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
pub struct CollectionId(String);

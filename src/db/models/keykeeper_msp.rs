// Keykeeper: MSPs (managed service providers). An MSP has staff and client
// organizations. Staff are ordinary members of each client organization, and
// the memberships an MSP created are recorded in msp_memberships so they can be
// listed, re-roled, and removed together. No keys live here: staff get each
// organization's key the normal way, when a member who holds it confirms them.
// See DESIGN.md, "MSP console", in the keykeeper repo.
//
// Technicians can be limited: to chosen clients rather than every client, to a
// custom role rather than admin inside them (with or without vault items), and
// without the clients' install commands. MSP admins always reach every client
// as owners. See DESIGN.md, "Roles and permissions".

use std::collections::{HashMap, HashSet};

use chrono::{NaiveDateTime, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;

use crate::{
    api::{ApiResult, EmptyResult},
    db::{
        DbConn,
        keykeeper_schema::{
            enrollment_domains, msp_clients, msp_enrollment_joins, msp_events, msp_invites, msp_memberships,
            msp_policies, msp_staff, msp_staff_client_roles, msp_staff_clients, msp_template_clients,
            msp_template_copies, msp_templates, msps,
        },
    },
    error::MapResult,
};
use macros::UuidFromParam;

use super::{
    CipherId, CollectionId, Membership, MembershipId, MembershipType, OrganizationId, UserId,
    keykeeper_roles::CustomPermissions,
};

// Our migrations exist for SQLite and PostgreSQL only.
#[cfg(feature = "mysql")]
compile_error!("PassBundle supports SQLite and PostgreSQL only. See DESIGN.md, \"MSP console\".");

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
#[deref(forward)]
#[from(forward)]
pub struct MspId(String);

/// What someone may do in an MSP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MspRole {
    /// Manages the MSP, its staff, and its clients. An owner in every client.
    Admin = 0,
    /// Works in client organizations. An admin in every client.
    Technician = 1,
}

impl MspRole {
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Admin),
            1 => Some(Self::Technician),
            _ => None,
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Self::Admin),
            "technician" => Some(Self::Technician),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Technician => "technician",
        }
    }

    /// The role this gives someone in each client organization.
    pub fn membership_type(self) -> MembershipType {
        match self {
            Self::Admin => MembershipType::Owner,
            Self::Technician => MembershipType::Admin,
        }
    }
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msps)]
#[diesel(primary_key(uuid))]
pub struct Msp {
    pub uuid: MspId,
    pub name: String,
    pub created_at: NaiveDateTime,
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_staff)]
#[diesel(primary_key(msp_uuid, user_uuid))]
pub struct MspStaff {
    pub msp_uuid: MspId,
    pub user_uuid: UserId,
    pub role: i32,
    pub created_at: NaiveDateTime,
    /// Technicians: every client, or only those in msp_staff_clients.
    pub all_clients: bool,
    /// Technicians: a CustomRole as JSON, or none for admin in each client.
    pub client_access: Option<String>,
    /// Technicians: whether they see clients' install commands.
    pub install_commands: bool,
}

/// A technician's role in one client, when it differs from their role in the
/// rest: `client_access` empty for admin, or a CustomRole as JSON.
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_staff_client_roles)]
#[diesel(primary_key(msp_uuid, user_uuid, org_uuid))]
pub struct MspStaffClientRole {
    pub msp_uuid: MspId,
    pub user_uuid: UserId,
    pub org_uuid: OrganizationId,
    pub client_access: Option<String>,
}

/// A client a technician without every client reaches.
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_staff_clients)]
#[diesel(primary_key(msp_uuid, user_uuid, org_uuid))]
pub struct MspStaffClient {
    pub msp_uuid: MspId,
    pub user_uuid: UserId,
    pub org_uuid: OrganizationId,
}

/// What a technician gets in the MSP's clients. MSP admins don't have one:
/// they're owners of every client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TechnicianAccess {
    /// Every client, including new ones. Otherwise only `clients`.
    pub all_clients: bool,
    #[serde(default)]
    pub clients: Vec<OrganizationId>,
    /// A custom role in each client, or none for admin.
    #[serde(default)]
    pub custom: Option<CustomRole>,
    pub install_commands: bool,
    /// Clients where their role differs from `custom`: each only once, and
    /// only clients they reach.
    #[serde(default)]
    pub client_roles: Vec<ClientRole>,
}

/// A technician's role in one client, when it differs from their role in the
/// rest: a custom role, or none for admin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientRole {
    pub client: OrganizationId,
    /// Required, as an explicit null for admin: leaving it out isn't admin.
    #[serde(deserialize_with = "required_option")]
    pub custom: Option<CustomRole>,
}

/// An `Option` the JSON must name, even as null.
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    <Option<T> as serde::Deserialize>::deserialize(deserializer)
}

impl Default for TechnicianAccess {
    /// Every client, as admin, with install commands: what technicians got
    /// before access could be limited.
    fn default() -> Self {
        Self {
            all_clients: true,
            clients: Vec::new(),
            custom: None,
            install_commands: true,
            client_roles: Vec::new(),
        }
    }
}

/// A technician's custom role inside each client they reach.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomRole {
    pub permissions: CustomPermissions,
    /// Sees and edits every vault item in the client (access to all collections).
    #[serde(default)]
    pub vault_items: bool,
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_clients)]
#[diesel(primary_key(org_uuid))]
pub struct MspClient {
    pub org_uuid: OrganizationId,
    pub msp_uuid: MspId,
    pub created_at: NaiveDateTime,
    /// The defaults the client started with, such as "business".
    pub preset: Option<String>,
    /// Lets an account ask to join this client as a regular member, through
    /// the RMM install command. Never grants the org key.
    pub enrollment_token: Option<String>,
    pub enrollment_token_created_at: Option<NaiveDateTime>,
    /// The collection people who join get, such as "Everyone".
    pub everyone_collection: Option<CollectionId>,
    /// Where the MSP's templates go in this client. See DESIGN.md, "MSP templates".
    pub templates_collection: Option<CollectionId>,
    /// The install command's join secret, encrypted with the client's key by
    /// the MSP admin's browser. See DESIGN.md, "Joins a hacked server can't forge".
    pub enrollment_secret: Option<String>,
}

/// Someone who joined a client through its enrollment token, and when.
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_enrollment_joins)]
#[diesel(primary_key(membership_uuid))]
pub struct MspEnrollmentJoin {
    pub membership_uuid: MembershipId,
    pub org_uuid: OrganizationId,
    pub joined_at: NaiveDateTime,
    /// The proof the join came with, that it knew the command's join secret.
    pub proof: Option<String>,
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_memberships)]
#[diesel(primary_key(membership_uuid))]
pub struct MspMembership {
    pub membership_uuid: MembershipId,
    pub msp_uuid: MspId,
}

impl Msp {
    pub fn new(name: String) -> Self {
        Self {
            uuid: MspId(crate::util::get_uuid()),
            name,
            created_at: Utc::now().naive_utc(),
        }
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| diesel::insert_into(msps::table).values(self).execute(conn).map_res("Error saving MSP"))
            .await
    }

    pub async fn find_by_uuid(uuid: &MspId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| msps::table.filter(msps::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    /// The MSPs someone is staff of, with their role in each.
    pub async fn find_by_staff_user(user_uuid: &UserId, conn: &DbConn) -> Vec<(Self, MspStaff)> {
        let mut result = Vec::new();
        for staff in MspStaff::find_by_user(user_uuid, conn).await {
            if let Some(msp) = Self::find_by_uuid(&staff.msp_uuid, conn).await {
                result.push((msp, staff));
            }
        }
        result
    }
}

impl MspStaff {
    pub fn new(msp_uuid: MspId, user_uuid: UserId, role: MspRole) -> Self {
        Self {
            msp_uuid,
            user_uuid,
            role: role as i32,
            created_at: Utc::now().naive_utc(),
            all_clients: true,
            client_access: None,
            install_commands: true,
        }
    }

    pub fn role(&self) -> Option<MspRole> {
        MspRole::from_i32(self.role)
    }

    /// A technician's custom role, if they have one. A value that doesn't
    /// parse gives a custom role with no permissions, never admin.
    pub fn custom_role(&self) -> Option<CustomRole> {
        let raw = self.client_access.as_deref()?;
        Some(serde_json::from_str(raw).unwrap_or(CustomRole {
            permissions: CustomPermissions::default(),
            vault_items: false,
        }))
    }

    /// The clients this person reaches: None for every client. MSP admins
    /// always reach every client.
    pub async fn reach(&self, conn: &DbConn) -> Option<HashSet<OrganizationId>> {
        if self.role() == Some(MspRole::Admin) || self.all_clients {
            return None;
        }
        let (msp, user) = (self.msp_uuid.clone(), self.user_uuid.clone());
        let chosen: Vec<OrganizationId> = conn
            .run(move |conn| {
                msp_staff_clients::table
                    .filter(msp_staff_clients::msp_uuid.eq(msp))
                    .filter(msp_staff_clients::user_uuid.eq(user))
                    .select(msp_staff_clients::org_uuid)
                    .load(conn)
                    .unwrap_or_default()
            })
            .await;
        Some(chosen.into_iter().collect())
    }

    /// A technician's roles in clients where it differs from their role in
    /// the rest, by client: a custom role, or None for admin. A stored value
    /// that doesn't parse gives a custom role with no permissions, never admin.
    ///
    /// Fails if they can't be read, rather than read as none: none would put
    /// the default role, perhaps admin, where a narrower one was chosen.
    pub async fn client_roles(&self, conn: &DbConn) -> ApiResult<HashMap<OrganizationId, Option<CustomRole>>> {
        let (msp, user) = (self.msp_uuid.clone(), self.user_uuid.clone());
        let rows: Vec<MspStaffClientRole> = conn
            .run(move |conn| {
                msp_staff_client_roles::table
                    .filter(msp_staff_client_roles::msp_uuid.eq(msp))
                    .filter(msp_staff_client_roles::user_uuid.eq(user))
                    .load(conn)
                    .map_res("Error reading a technician's roles in clients")
            })
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let custom = row.client_access.as_deref().map(|raw| {
                    serde_json::from_str(raw).unwrap_or(CustomRole {
                        permissions: CustomPermissions::default(),
                        vault_items: false,
                    })
                });
                (row.org_uuid, custom)
            })
            .collect())
    }

    /// A technician's access, as stored. Fails if their roles in clients
    /// can't be read (`client_roles`).
    pub async fn access(&self, conn: &DbConn) -> ApiResult<TechnicianAccess> {
        let mut clients: Vec<OrganizationId> = self.reach(conn).await.unwrap_or_default().into_iter().collect();
        clients.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
        let mut client_roles: Vec<ClientRole> = self
            .client_roles(conn)
            .await?
            .into_iter()
            .map(|(client, custom)| ClientRole {
                client,
                custom,
            })
            .collect();
        client_roles.sort_by(|a, b| a.client.as_ref().cmp(b.client.as_ref()));
        Ok(TechnicianAccess {
            all_clients: self.all_clients,
            clients,
            custom: self.custom_role(),
            install_commands: self.install_commands,
            client_roles,
        })
    }

    /// Stores a technician's access. Doesn't touch their memberships.
    pub async fn set_access(&mut self, access: &TechnicianAccess, conn: &DbConn) -> EmptyResult {
        self.all_clients = access.all_clients;
        self.client_access = access.custom.as_ref().map(|c| serde_json::to_string(c).unwrap_or_default());
        self.install_commands = access.install_commands;
        let (msp, user) = (self.msp_uuid.clone(), self.user_uuid.clone());
        let (all_clients, client_access, install_commands) =
            (self.all_clients, self.client_access.clone(), self.install_commands);
        let chosen: Vec<MspStaffClient> = if access.all_clients {
            Vec::new()
        } else {
            access
                .clients
                .iter()
                .map(|org| MspStaffClient {
                    msp_uuid: msp.clone(),
                    user_uuid: user.clone(),
                    org_uuid: org.clone(),
                })
                .collect()
        };
        let roles: Vec<MspStaffClientRole> = access
            .client_roles
            .iter()
            .map(|role| MspStaffClientRole {
                msp_uuid: msp.clone(),
                user_uuid: user.clone(),
                org_uuid: role.client.clone(),
                client_access: role.custom.as_ref().map(|c| serde_json::to_string(c).unwrap_or_default()),
            })
            .collect();
        // All of it or none: a role row for a client that's gone would
        // otherwise leave the others half written.
        conn.run(move |conn| {
            conn.transaction(|conn| {
                diesel::update(
                    msp_staff::table.filter(msp_staff::msp_uuid.eq(&msp)).filter(msp_staff::user_uuid.eq(&user)),
                )
                .set((
                    msp_staff::all_clients.eq(all_clients),
                    msp_staff::client_access.eq(client_access),
                    msp_staff::install_commands.eq(install_commands),
                ))
                .execute(conn)?;
                diesel::delete(
                    msp_staff_clients::table
                        .filter(msp_staff_clients::msp_uuid.eq(&msp))
                        .filter(msp_staff_clients::user_uuid.eq(&user)),
                )
                .execute(conn)?;
                for row in &chosen {
                    diesel::insert_into(msp_staff_clients::table).values(row).execute(conn)?;
                }
                diesel::delete(
                    msp_staff_client_roles::table
                        .filter(msp_staff_client_roles::msp_uuid.eq(&msp))
                        .filter(msp_staff_client_roles::user_uuid.eq(&user)),
                )
                .execute(conn)?;
                for row in &roles {
                    diesel::insert_into(msp_staff_client_roles::table).values(row).execute(conn)?;
                }
                Ok::<(), diesel::result::Error>(())
            })
            .map_res("Error changing a technician's access")
        })
        .await
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(msp_staff::table).values(self).execute(conn).map_res("Error adding MSP staff")
        })
        .await
    }

    pub async fn set_role(&mut self, role: MspRole, conn: &DbConn) -> EmptyResult {
        self.role = role as i32;
        let (msp, user, role) = (&self.msp_uuid, &self.user_uuid, self.role);
        conn.run(move |conn| {
            diesel::update(msp_staff::table.filter(msp_staff::msp_uuid.eq(msp)).filter(msp_staff::user_uuid.eq(user)))
                .set(msp_staff::role.eq(role))
                .execute(conn)
                .map_res("Error changing MSP staff role")
        })
        .await
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(
                msp_staff_clients::table
                    .filter(msp_staff_clients::msp_uuid.eq(&self.msp_uuid))
                    .filter(msp_staff_clients::user_uuid.eq(&self.user_uuid)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error removing MSP staff")?;
            diesel::delete(
                msp_staff_client_roles::table
                    .filter(msp_staff_client_roles::msp_uuid.eq(&self.msp_uuid))
                    .filter(msp_staff_client_roles::user_uuid.eq(&self.user_uuid)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error removing MSP staff")?;
            diesel::delete(
                msp_staff::table
                    .filter(msp_staff::msp_uuid.eq(self.msp_uuid))
                    .filter(msp_staff::user_uuid.eq(self.user_uuid)),
            )
            .execute(conn)
            .map_res("Error removing MSP staff")
        })
        .await
    }

    pub async fn find(msp_uuid: &MspId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            msp_staff::table
                .filter(msp_staff::msp_uuid.eq(msp_uuid))
                .filter(msp_staff::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_msp(msp_uuid: &MspId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            msp_staff::table
                .filter(msp_staff::msp_uuid.eq(msp_uuid))
                .order(msp_staff::created_at.asc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            msp_staff::table.filter(msp_staff::user_uuid.eq(user_uuid)).load::<Self>(conn).unwrap_or_default()
        })
        .await
    }

    /// Whether someone is on any MSP's staff. Their account reaches every
    /// client they work in, so no organization may recover it: see
    /// DESIGN.md, "MSP staff and account recovery". A database error counts
    /// as staff, so the check fails closed.
    pub async fn is_staff_anywhere(user_uuid: &UserId, conn: &DbConn) -> bool {
        conn.run(move |conn| {
            msp_staff::table
                .filter(msp_staff::user_uuid.eq(user_uuid))
                .count()
                .get_result::<i64>(conn)
                .map_or(true, |n| n > 0)
        })
        .await
    }
}

impl MspClient {
    pub fn new(
        org_uuid: OrganizationId,
        msp_uuid: MspId,
        preset: Option<String>,
        everyone_collection: Option<CollectionId>,
    ) -> Self {
        Self {
            org_uuid,
            msp_uuid,
            created_at: Utc::now().naive_utc(),
            preset,
            enrollment_token: Some(Self::new_enrollment_token()),
            enrollment_token_created_at: Some(Utc::now().naive_utc()),
            everyone_collection,
            templates_collection: None,
            enrollment_secret: None,
        }
    }

    /// A new random enrollment token: 256 bits, URL-safe.
    pub fn new_enrollment_token() -> String {
        crate::crypto::encode_random_bytes::<32>(&data_encoding::BASE64URL_NOPAD)
    }

    /// Sets the install command's join secret, encrypted by the browser,
    /// keeping the token.
    pub async fn set_enrollment_secret(&mut self, secret: Option<String>, conn: &DbConn) -> EmptyResult {
        let org = self.org_uuid.clone();
        let saved = secret.clone();
        conn.run(move |conn| {
            diesel::update(msp_clients::table.filter(msp_clients::org_uuid.eq(org)))
                .set(msp_clients::enrollment_secret.eq(saved))
                .execute(conn)
                .map(|_| ())
                .map_res("Error saving the join secret")
        })
        .await?;
        self.enrollment_secret = secret;
        Ok(())
    }

    /// Replaces the enrollment token, with the new command's join secret
    /// (encrypted, from the browser that made it; none from an older app).
    /// Install commands with the old one stop letting new people join.
    pub async fn replace_enrollment_token(&mut self, secret: Option<String>, conn: &DbConn) -> EmptyResult {
        let token = Self::new_enrollment_token();
        let now = Utc::now().naive_utc();
        let org = self.org_uuid.clone();
        let saved = token.clone();
        let saved_secret = secret.clone();
        let updated: EmptyResult = conn
            .run(move |conn| {
                diesel::update(msp_clients::table.filter(msp_clients::org_uuid.eq(org)))
                    .set((
                        msp_clients::enrollment_token.eq(saved),
                        msp_clients::enrollment_token_created_at.eq(now),
                        msp_clients::enrollment_secret.eq(saved_secret),
                    ))
                    .execute(conn)
                    .map_res("Error replacing the enrollment token")
            })
            .await;
        updated?;
        self.enrollment_token = Some(token);
        self.enrollment_token_created_at = Some(now);
        self.enrollment_secret = secret;
        Ok(())
    }

    pub async fn find_by_enrollment_token(token: &str, conn: &DbConn) -> Option<Self> {
        let token = token.to_owned();
        conn.run(move |conn| {
            msp_clients::table.filter(msp_clients::enrollment_token.eq(token)).first::<Self>(conn).ok()
        })
        .await
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(msp_clients::table).values(self).execute(conn).map_res("Error adding MSP client")
        })
        .await
    }

    /// Ends the MSP's relationship with this client, including technicians'
    /// choice of it and their roles there.
    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(
                msp_staff_clients::table
                    .filter(msp_staff_clients::msp_uuid.eq(&self.msp_uuid))
                    .filter(msp_staff_clients::org_uuid.eq(&self.org_uuid)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error removing MSP client")?;
            diesel::delete(
                msp_staff_client_roles::table
                    .filter(msp_staff_client_roles::msp_uuid.eq(&self.msp_uuid))
                    .filter(msp_staff_client_roles::org_uuid.eq(&self.org_uuid)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error removing MSP client")?;
            diesel::delete(
                msp_template_clients::table
                    .filter(msp_template_clients::msp_uuid.eq(&self.msp_uuid))
                    .filter(msp_template_clients::org_uuid.eq(&self.org_uuid)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error removing MSP client")?;
            diesel::delete(msp_clients::table.filter(msp_clients::org_uuid.eq(self.org_uuid)))
                .execute(conn)
                .map_res("Error removing MSP client")
        })
        .await
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| msp_clients::table.filter(msp_clients::org_uuid.eq(org_uuid)).first::<Self>(conn).ok())
            .await
    }

    pub async fn set_templates_collection(&mut self, collection: CollectionId, conn: &DbConn) -> EmptyResult {
        let org = self.org_uuid.clone();
        let saved = collection.clone();
        let updated: EmptyResult = conn
            .run(move |conn| {
                diesel::update(msp_clients::table.filter(msp_clients::org_uuid.eq(org)))
                    .set(msp_clients::templates_collection.eq(saved))
                    .execute(conn)
                    .map_res("Error saving the Templates collection")
            })
            .await;
        updated?;
        self.templates_collection = Some(collection);
        Ok(())
    }

    /// Forgets the client's Templates collection, which the client deleted:
    /// the console makes a new one the next time it sends a template.
    pub async fn clear_templates_collection(&mut self, conn: &DbConn) -> EmptyResult {
        let org = self.org_uuid.clone();
        conn.run(move |conn| {
            diesel::update(msp_clients::table.filter(msp_clients::org_uuid.eq(org)))
                .set(msp_clients::templates_collection.eq(None::<CollectionId>))
                .execute(conn)
                .map(|_| ())
                .map_res("Error forgetting the Templates collection")
        })
        .await?;
        self.templates_collection = None;
        Ok(())
    }

    pub async fn find_by_msp(msp_uuid: &MspId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            msp_clients::table
                .filter(msp_clients::msp_uuid.eq(msp_uuid))
                .order(msp_clients::created_at.asc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }
}

/// Whether a client's member policies skip this membership: two-step login,
/// single organization, and the others upstream applies only below admin.
/// Upstream exempts owners and admins. An MSP's staff are exempt too, whatever
/// their role in the client, since they work in every client and a technician
/// with a custom role is a regular member there. See DESIGN.md, "How an MSP
/// reaches its clients".
pub async fn exempt_from_member_policies(member: &Membership, conn: &DbConn) -> bool {
    member.atype >= MembershipType::Admin || MspMembership::find_by_membership(&member.uuid, conn).await.is_some()
}

/// Whether a client's "Require two-step login" policy skips this membership.
/// Upstream exempts owners and admins; an MSP's staff aren't exempt, whatever
/// their role, since they reach the client's items: they can't be confirmed
/// into a client that requires it until they've set it up. See DESIGN.md,
/// "MSP staff and two-step login".
pub async fn exempt_from_two_step_policy(member: &Membership, conn: &DbConn) -> bool {
    member.atype >= MembershipType::Admin && MspMembership::find_by_membership(&member.uuid, conn).await.is_none()
}

impl MspMembership {
    pub fn new(membership_uuid: MembershipId, msp_uuid: MspId) -> Self {
        Self {
            membership_uuid,
            msp_uuid,
        }
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(msp_memberships::table)
                .values(self)
                .execute(conn)
                .map_res("Error recording MSP membership")
        })
        .await
    }

    pub async fn find_by_membership(membership_uuid: &MembershipId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            msp_memberships::table.filter(msp_memberships::membership_uuid.eq(membership_uuid)).first::<Self>(conn).ok()
        })
        .await
    }

    pub async fn find_by_msp(msp_uuid: &MspId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            msp_memberships::table.filter(msp_memberships::msp_uuid.eq(msp_uuid)).load::<Self>(conn).unwrap_or_default()
        })
        .await
    }

    /// The same, but a database error is an error, not an empty list: for
    /// removals, where an empty list would leave the MSP's people in place.
    pub async fn try_find_by_msp(msp_uuid: &MspId, conn: &DbConn) -> Result<Vec<Self>, crate::error::Error> {
        conn.run(move |conn| {
            msp_memberships::table
                .filter(msp_memberships::msp_uuid.eq(msp_uuid))
                .load::<Self>(conn)
                .map_res("Error loading MSP memberships")
        })
        .await
    }
}

/// The email domains whose accounts may join a client with its install
/// command. A client without them lets anyone with the command join.
#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = enrollment_domains)]
#[diesel(primary_key(org_uuid))]
pub struct EnrollmentDomains {
    pub org_uuid: OrganizationId,
    /// Lowercase, space-separated.
    pub domains: String,
}

/// At most this many domains per client.
pub const MAX_ENROLLMENT_DOMAINS: usize = 20;

/// Domains as people type them ("@Acme.com", " acme.com ") made plain
/// ("acme.com"), without repeats. An error names the first entry that isn't a
/// domain.
pub fn parse_enrollment_domains(entries: &[String]) -> Result<Vec<String>, String> {
    let mut domains: Vec<String> = Vec::new();
    for entry in entries {
        let domain = entry.trim().trim_start_matches('@').trim_end_matches('.').to_lowercase();
        if domain.is_empty() {
            continue;
        }
        let label_ok = |l: &str| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        };
        let labels: Vec<&str> = domain.split('.').collect();
        if domain.len() > 253 || labels.len() < 2 || !labels.iter().all(|l| label_ok(l)) {
            return Err(format!("\"{}\" isn't an email domain, like example.com", entry.trim()));
        }
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    if domains.len() > MAX_ENROLLMENT_DOMAINS {
        return Err(format!("At most {MAX_ENROLLMENT_DOMAINS} domains"));
    }
    Ok(domains)
}

/// Whether an account's email is at one of these domains: exactly, so
/// "acme.com" doesn't let in "mail.acme.com" or "notacme.com".
pub fn email_in_domains(email: &str, domains: &[String]) -> bool {
    email.rsplit_once('@').is_some_and(|(_, domain)| domains.iter().any(|d| d.eq_ignore_ascii_case(domain)))
}

impl EnrollmentDomains {
    pub fn list(&self) -> Vec<String> {
        self.domains.split_whitespace().map(str::to_owned).collect()
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            enrollment_domains::table.filter(enrollment_domains::org_uuid.eq(org_uuid)).first::<Self>(conn).ok()
        })
        .await
    }

    /// A client's domains, none meaning anyone with the command may join.
    pub async fn for_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<String> {
        Self::find_by_org(org_uuid, conn).await.map(|d| d.list()).unwrap_or_default()
    }

    /// Sets a client's domains; none removes the limit.
    pub async fn set(org_uuid: &OrganizationId, domains: &[String], conn: &DbConn) -> EmptyResult {
        let org = org_uuid.clone();
        let row = Self {
            org_uuid: org_uuid.clone(),
            domains: domains.join(" "),
        };
        let empty = domains.is_empty();
        conn.run(move |conn| {
            diesel::delete(enrollment_domains::table.filter(enrollment_domains::org_uuid.eq(org)))
                .execute(conn)
                .map(|_| ())
                .map_res("Error saving the install command's domains")?;
            if empty {
                return Ok(());
            }
            diesel::insert_into(enrollment_domains::table)
                .values(&row)
                .execute(conn)
                .map(|_| ())
                .map_res("Error saving the install command's domains")
        })
        .await
    }
}

impl MspEnrollmentJoin {
    pub fn new(membership_uuid: MembershipId, org_uuid: OrganizationId, proof: Option<String>) -> Self {
        Self {
            membership_uuid,
            org_uuid,
            joined_at: Utc::now().naive_utc(),
            proof,
        }
    }

    /// The proof a membership's install command join came with, if any.
    pub async fn proof_for(membership_uuid: &MembershipId, conn: &DbConn) -> Option<String> {
        conn.run(move |conn| {
            msp_enrollment_joins::table
                .filter(msp_enrollment_joins::membership_uuid.eq(membership_uuid))
                .select(msp_enrollment_joins::proof)
                .first::<Option<String>>(conn)
                .ok()
                .flatten()
        })
        .await
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(msp_enrollment_joins::table)
                .values(self)
                .execute(conn)
                .map_res("Error recording an enrollment join")
        })
        .await
    }

    /// Whether a membership came from the install command.
    pub async fn exists_for(membership_uuid: &MembershipId, conn: &DbConn) -> bool {
        conn.run(move |conn| {
            msp_enrollment_joins::table
                .filter(msp_enrollment_joins::membership_uuid.eq(membership_uuid))
                .count()
                .get_result::<i64>(conn)
                .is_ok_and(|n| n > 0)
        })
        .await
    }

    pub async fn count_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> i64 {
        conn.run(move |conn| {
            msp_enrollment_joins::table
                .filter(msp_enrollment_joins::org_uuid.eq(org_uuid))
                .count()
                .first::<i64>(conn)
                .unwrap_or(0)
        })
        .await
    }
}

/// One entry in an MSP's audit log.
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_events)]
#[diesel(primary_key(uuid))]
pub struct MspEvent {
    pub uuid: String,
    pub msp_uuid: MspId,
    pub created_at: NaiveDateTime,
    pub event: String,
    pub actor_uuid: Option<UserId>,
    pub actor_email: Option<String>,
    pub org_uuid: Option<OrganizationId>,
    pub org_name: Option<String>,
    pub target_email: Option<String>,
    pub detail: Option<String>,
    pub ip: Option<String>,
}

impl MspEvent {
    pub fn new(msp_uuid: MspId, event: &str) -> Self {
        Self {
            uuid: crate::util::get_uuid(),
            msp_uuid,
            created_at: Utc::now().naive_utc(),
            event: event.to_owned(),
            actor_uuid: None,
            actor_email: None,
            org_uuid: None,
            org_name: None,
            target_email: None,
            detail: None,
            ip: None,
        }
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        let inserted: EmptyResult = conn
            .run(move |conn| {
                diesel::insert_into(msp_events::table)
                    .values(self)
                    .execute(conn)
                    .map_res("Error recording an MSP event")
            })
            .await;
        inserted?;
        // And to the MSP's security tools, if it sends its events to any.
        super::keykeeper_event_streaming::stream_msp(self, conn).await;
        Ok(())
    }

    /// How many of an MSP's events of one kind happened since a time, about
    /// one person if `target` is given: for limits such as how many
    /// invitations it emails. A database error counts as too many.
    pub async fn count_since(
        msp_uuid: &MspId,
        event: &str,
        since: NaiveDateTime,
        target: Option<&str>,
        conn: &DbConn,
    ) -> i64 {
        let event = event.to_owned();
        let target = target.map(str::to_lowercase);
        conn.run(move |conn| {
            let mut query = msp_events::table
                .filter(msp_events::msp_uuid.eq(msp_uuid))
                .filter(msp_events::event.eq(event))
                .filter(msp_events::created_at.ge(since))
                .into_boxed();
            if let Some(target) = target {
                query = query.filter(msp_events::target_email.eq(target));
            }
            query.count().get_result::<i64>(conn).unwrap_or(i64::MAX)
        })
        .await
    }

    /// The newest events first, older than `before` if given. With `only`,
    /// just the MSP-wide events and those about the clients listed.
    pub async fn find_by_msp(
        msp_uuid: &MspId,
        before: Option<NaiveDateTime>,
        only: Option<Vec<OrganizationId>>,
        limit: i64,
        conn: &DbConn,
    ) -> Vec<Self> {
        conn.run(move |conn| {
            let mut query = msp_events::table.filter(msp_events::msp_uuid.eq(msp_uuid)).into_boxed();
            if let Some(before) = before {
                query = query.filter(msp_events::created_at.lt(before));
            }
            if let Some(only) = only {
                query = query.filter(msp_events::org_uuid.is_null().or(msp_events::org_uuid.eq_any(only)));
            }
            query.order(msp_events::created_at.desc()).limit(limit).load::<Self>(conn).unwrap_or_default()
        })
        .await
    }
}

/// An invitation to an MSP's staff. Accepting needs the token, which goes only
/// to the invited address, and an account with that address.
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_invites)]
#[diesel(primary_key(uuid))]
pub struct MspInvite {
    pub uuid: String,
    pub msp_uuid: MspId,
    pub email: String,
    pub role: i32,
    pub token: String,
    pub invited_by_email: String,
    pub created_at: NaiveDateTime,
    /// For a technician: the TechnicianAccess they get on joining, as JSON.
    pub access: Option<String>,
}

impl MspInvite {
    pub fn new(
        msp_uuid: MspId,
        email: &str,
        role: MspRole,
        access: Option<&TechnicianAccess>,
        invited_by_email: &str,
    ) -> Self {
        Self {
            uuid: crate::util::get_uuid(),
            msp_uuid,
            email: email.trim().to_lowercase(),
            role: role as i32,
            token: crate::crypto::encode_random_bytes::<32>(&data_encoding::BASE64URL_NOPAD),
            invited_by_email: invited_by_email.to_owned(),
            created_at: Utc::now().naive_utc(),
            access: access.map(|a| serde_json::to_string(a).unwrap_or_default()),
        }
    }

    pub fn role(&self) -> Option<MspRole> {
        MspRole::from_i32(self.role)
    }

    /// The access a technician invitation gives. A value that doesn't parse
    /// gives no clients, never every client.
    pub fn access(&self) -> Option<TechnicianAccess> {
        let raw = self.access.as_deref()?;
        Some(serde_json::from_str(raw).unwrap_or(TechnicianAccess {
            all_clients: false,
            clients: Vec::new(),
            custom: None,
            install_commands: false,
            client_roles: Vec::new(),
        }))
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(msp_invites::table).values(self).execute(conn).map_res("Error saving an MSP invite")
        })
        .await
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(msp_invites::table.filter(msp_invites::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error removing an MSP invite")
        })
        .await
    }

    pub async fn find_by_token(token: &str, conn: &DbConn) -> Option<Self> {
        let token = token.to_owned();
        conn.run(move |conn| msp_invites::table.filter(msp_invites::token.eq(token)).first::<Self>(conn).ok()).await
    }

    /// Whether the invitation is older than the server's invitation lifetime.
    pub fn expired(&self) -> bool {
        let hours = i64::from(crate::CONFIG.invitation_expiration_hours());
        Utc::now().naive_utc() - self.created_at > chrono::TimeDelta::hours(hours)
    }

    /// Removes an MSP's invitations for an email: once someone joins or
    /// leaves the staff, an old link must not bring them back.
    pub async fn delete_by_msp_and_email(msp_uuid: &MspId, email: &str, conn: &DbConn) -> EmptyResult {
        let email = email.trim().to_lowercase();
        conn.run(move |conn| {
            diesel::delete(
                msp_invites::table.filter(msp_invites::msp_uuid.eq(msp_uuid)).filter(msp_invites::email.eq(email)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error removing MSP invites")
        })
        .await
    }

    pub async fn find_by_msp_and_email(msp_uuid: &MspId, email: &str, conn: &DbConn) -> Option<Self> {
        let email = email.trim().to_lowercase();
        conn.run(move |conn| {
            msp_invites::table
                .filter(msp_invites::msp_uuid.eq(msp_uuid))
                .filter(msp_invites::email.eq(email))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_msp_and_uuid(msp_uuid: &MspId, uuid: &str, conn: &DbConn) -> Option<Self> {
        let uuid = uuid.to_owned();
        conn.run(move |conn| {
            msp_invites::table
                .filter(msp_invites::msp_uuid.eq(msp_uuid))
                .filter(msp_invites::uuid.eq(uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_msp(msp_uuid: &MspId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            msp_invites::table
                .filter(msp_invites::msp_uuid.eq(msp_uuid))
                .order(msp_invites::created_at.asc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }
}

/// One of an MSP's default policies: an upstream policy type, on or off, with
/// its options as upstream stores them. A type without a row is off. See
/// DESIGN.md, "Default policies".
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_policies)]
#[diesel(primary_key(msp_uuid, atype))]
pub struct MspPolicy {
    pub msp_uuid: MspId,
    pub atype: i32,
    pub enabled: bool,
    pub data: String,
}

impl MspPolicy {
    pub fn new(msp_uuid: MspId, atype: i32, enabled: bool, data: String) -> Self {
        Self {
            msp_uuid,
            atype,
            enabled,
            data,
        }
    }

    /// Saves this default, replacing the MSP's earlier one for the same type.
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(
                msp_policies::table
                    .filter(msp_policies::msp_uuid.eq(&self.msp_uuid))
                    .filter(msp_policies::atype.eq(self.atype)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error saving a default policy")?;
            diesel::insert_into(msp_policies::table).values(self).execute(conn).map_res("Error saving a default policy")
        })
        .await
    }

    pub async fn find_by_msp(msp_uuid: &MspId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            msp_policies::table
                .filter(msp_policies::msp_uuid.eq(msp_uuid))
                .order(msp_policies::atype.asc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }
}

/// An item template an MSP sends to its clients: which item is the source,
/// and whether every client gets it or only those in msp_template_clients.
/// The server never sees what's in it. See DESIGN.md, "MSP templates".
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_templates)]
#[diesel(primary_key(msp_uuid, template_id))]
pub struct MspTemplate {
    pub msp_uuid: MspId,
    pub template_id: String,
    pub source_cipher_uuid: CipherId,
    pub all_clients: bool,
    pub created_at: NaiveDateTime,
}

/// A client's copy of an MSP template, and the version of the source (its
/// revision date) it was made from.
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_template_copies)]
#[diesel(primary_key(org_uuid, template_id))]
pub struct MspTemplateCopy {
    pub org_uuid: OrganizationId,
    pub template_id: String,
    pub cipher_uuid: CipherId,
    pub source_revision: String,
}

#[derive(Insertable)]
#[diesel(table_name = msp_template_clients)]
struct MspTemplateClient {
    msp_uuid: MspId,
    template_id: String,
    org_uuid: OrganizationId,
}

impl MspTemplate {
    /// Saves the template and, unless it's for every client, the clients it's
    /// for, replacing what was saved before.
    pub async fn save(&self, clients: &[OrganizationId], conn: &DbConn) -> EmptyResult {
        let chosen: Vec<MspTemplateClient> = if self.all_clients {
            Vec::new()
        } else {
            clients
                .iter()
                .map(|org| MspTemplateClient {
                    msp_uuid: self.msp_uuid.clone(),
                    template_id: self.template_id.clone(),
                    org_uuid: org.clone(),
                })
                .collect()
        };
        conn.run(move |conn| {
            diesel::delete(
                msp_template_clients::table
                    .filter(msp_template_clients::msp_uuid.eq(&self.msp_uuid))
                    .filter(msp_template_clients::template_id.eq(&self.template_id)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error saving a template")?;
            diesel::delete(
                msp_templates::table
                    .filter(msp_templates::msp_uuid.eq(&self.msp_uuid))
                    .filter(msp_templates::template_id.eq(&self.template_id)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error saving a template")?;
            diesel::insert_into(msp_templates::table)
                .values(self)
                .execute(conn)
                .map(|_| ())
                .map_res("Error saving a template")?;
            for row in &chosen {
                diesel::insert_into(msp_template_clients::table)
                    .values(row)
                    .execute(conn)
                    .map(|_| ())
                    .map_res("Error saving a template")?;
            }
            Ok(())
        })
        .await
    }

    /// Stops sending the template, and forgets its copies in the MSP's clients.
    /// The copies themselves stay where they are.
    pub async fn delete(self, clients: Vec<OrganizationId>, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(
                msp_template_copies::table
                    .filter(msp_template_copies::template_id.eq(&self.template_id))
                    .filter(msp_template_copies::org_uuid.eq_any(&clients)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error removing a template")?;
            diesel::delete(
                msp_template_clients::table
                    .filter(msp_template_clients::msp_uuid.eq(&self.msp_uuid))
                    .filter(msp_template_clients::template_id.eq(&self.template_id)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error removing a template")?;
            diesel::delete(
                msp_templates::table
                    .filter(msp_templates::msp_uuid.eq(&self.msp_uuid))
                    .filter(msp_templates::template_id.eq(&self.template_id)),
            )
            .execute(conn)
            .map_res("Error removing a template")
        })
        .await
    }

    pub async fn find(msp_uuid: &MspId, template_id: &str, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            msp_templates::table
                .filter(msp_templates::msp_uuid.eq(msp_uuid))
                .filter(msp_templates::template_id.eq(template_id))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_msp(msp_uuid: &MspId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            msp_templates::table
                .filter(msp_templates::msp_uuid.eq(msp_uuid))
                .order(msp_templates::created_at.asc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    /// The clients a template for chosen clients goes to.
    pub async fn chosen_clients(&self, conn: &DbConn) -> Vec<OrganizationId> {
        conn.run(move |conn| {
            msp_template_clients::table
                .filter(msp_template_clients::msp_uuid.eq(&self.msp_uuid))
                .filter(msp_template_clients::template_id.eq(&self.template_id))
                .select(msp_template_clients::org_uuid)
                .load::<OrganizationId>(conn)
                .unwrap_or_default()
        })
        .await
    }
}

impl MspTemplateCopy {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(
                msp_template_copies::table
                    .filter(msp_template_copies::org_uuid.eq(&self.org_uuid))
                    .filter(msp_template_copies::template_id.eq(&self.template_id)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error recording a template copy")?;
            diesel::insert_into(msp_template_copies::table)
                .values(self)
                .execute(conn)
                .map_res("Error recording a template copy")
        })
        .await
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            msp_template_copies::table
                .filter(msp_template_copies::org_uuid.eq(org_uuid))
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }
}

#[cfg(test)]
mod enrollment_domain_tests {
    use super::{email_in_domains, parse_enrollment_domains};

    fn parse(entries: &[&str]) -> Result<Vec<String>, String> {
        parse_enrollment_domains(&entries.iter().map(|e| (*e).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn domains_are_made_plain_and_kept_once() {
        assert_eq!(
            parse(&["@Acme.com", " acme.com ", "", "branch.acme.com."]),
            Ok(vec!["acme.com".to_owned(), "branch.acme.com".to_owned()])
        );
        assert_eq!(parse(&[]), Ok(vec![]));
    }

    #[test]
    fn anything_but_a_domain_is_refused_by_name() {
        assert_eq!(parse(&["acme.com", "acme"]), Err("\"acme\" isn't an email domain, like example.com".to_owned()));
        for bad in ["dana@acme.com", "acme..com", "-acme.com", "acme-.com", "ac me.com", "acme.com/x", "*.acme.com"] {
            assert!(parse(&[bad]).is_err(), "{bad}");
        }
        let many: Vec<String> = (0..21).map(|i| format!("d{i}.com")).collect();
        assert_eq!(parse_enrollment_domains(&many), Err("At most 20 domains".to_owned()));
    }

    #[test]
    fn an_email_matches_its_exact_domain_only() {
        let domains = vec!["acme.com".to_owned()];
        assert!(email_in_domains("dana@acme.com", &domains));
        assert!(email_in_domains("Dana@ACME.com", &domains));
        assert!(!email_in_domains("dana@mail.acme.com", &domains));
        assert!(!email_in_domains("dana@notacme.com", &domains));
        assert!(!email_in_domains("acme.com", &domains));
        // The domain is after the last @.
        assert!(!email_in_domains("acme.com@evil.test", &domains));
    }
}

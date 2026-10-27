// Keykeeper: provisioning from Microsoft Entra ID, or any SCIM 2.0 client.
// An organization's owners and admins make a token; the directory uses it to
// invite people as regular members, turn them off and on, remove them, and
// keep groups' members in step. The server keeps only the token's SHA-256,
// what the directory sent about each member it knows, and which groups it
// made. Nothing here is a key or reaches a vault. See DESIGN.md,
// "Provisioning from Entra ID", in the meta repo.

use std::collections::HashSet;

use chrono::{NaiveDateTime, Utc};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    crypto::ct_eq,
    db::{
        DbConn,
        keykeeper_schema::{membership_permissions, msp_memberships, scim_groups, scim_tokens, scim_users},
        schema::{groups_users, users},
    },
    error::MapResult,
};

use super::{GroupId, Membership, MembershipId, MembershipType, OrganizationId, User};

/// What every token starts with, so secret scanners and people can tell what
/// it is. The version is for a later format, never for a weaker one.
pub const SCIM_TOKEN_PREFIX: &str = "pbscim1_";
/// The random part: 32 bytes, 43 base64url characters.
const SCIM_TOKEN_BYTES: usize = 32;

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Clone)]
#[diesel(table_name = scim_tokens)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(org_uuid))]
pub struct ScimToken {
    pub org_uuid: OrganizationId,
    pub token_hash: String,
    pub created_by: String,
    pub created_at: NaiveDateTime,
    pub last_used_at: Option<NaiveDateTime>,
    pub last_used_ip: Option<String>,
}

/// The base64 SHA-256 of a token, as the server keeps it. A token is 256
/// random bits, so a fast hash is enough: there's nothing to guess.
pub fn scim_token_hash(token: &str) -> String {
    BASE64.encode(ring::digest::digest(&ring::digest::SHA256, token.as_bytes()).as_ref())
}

/// Whether a string is shaped like a token, before anything is looked up.
pub fn looks_like_scim_token(token: &str) -> bool {
    token.strip_prefix(SCIM_TOKEN_PREFIX).is_some_and(|secret| {
        secret.len() == 43 && BASE64URL_NOPAD.decode(secret.as_bytes()).is_ok_and(|b| b.len() == SCIM_TOKEN_BYTES)
    })
}

impl ScimToken {
    /// A new token for an organization: the token itself, shown once, and the
    /// row that keeps only its hash.
    pub fn generate(org_uuid: OrganizationId, created_by: &str) -> (String, Self) {
        let secret = crate::crypto::get_random_bytes::<SCIM_TOKEN_BYTES>();
        let token = format!("{SCIM_TOKEN_PREFIX}{}", BASE64URL_NOPAD.encode(&secret));
        let row = Self {
            org_uuid,
            token_hash: scim_token_hash(&token),
            created_by: created_by.to_owned(),
            created_at: Utc::now().naive_utc(),
            last_used_at: None,
            last_used_ip: None,
        };
        (token, row)
    }

    /// Whether a presented token is this one, compared in constant time.
    pub fn matches(&self, presented: &str) -> bool {
        ct_eq(scim_token_hash(presented), &self.token_hash)
    }

    /// The same work as `matches`, for an organization with no token, so
    /// timing doesn't tell the two apart. Always false.
    pub fn matches_none(presented: &str) -> bool {
        // The base64 of 32 zero bytes: the length of a real hash, and no
        // token's (SHA-256 has no known preimage for it).
        const NO_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let _ = std::hint::black_box(ct_eq(scim_token_hash(presented), NO_TOKEN));
        false
    }

    pub async fn find(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| scim_tokens::table.filter(scim_tokens::org_uuid.eq(org_uuid)).first::<Self>(conn).ok())
            .await
    }

    /// Saves it, replacing the organization's earlier token: that one stops
    /// working at once.
    pub async fn replace(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            conn.transaction(|conn| {
                diesel::delete(scim_tokens::table.filter(scim_tokens::org_uuid.eq(&self.org_uuid))).execute(conn)?;
                diesel::insert_into(scim_tokens::table).values(self).execute(conn)?;
                Ok::<(), diesel::result::Error>(())
            })
            .map_res("Error saving a provisioning token")
        })
        .await
    }

    /// Revokes the organization's token: provisioning stops at once.
    pub async fn delete(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(scim_tokens::table.filter(scim_tokens::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error revoking a provisioning token")
        })
        .await
    }

    /// Records a request: when, and from where. Written at most once a minute
    /// from the same address, since the directory makes many requests.
    pub async fn mark_used(&self, ip: &str, conn: &DbConn) -> EmptyResult {
        let now = Utc::now().naive_utc();
        let recent = self.last_used_at.is_some_and(|at| now - at < chrono::TimeDelta::minutes(1));
        if recent && self.last_used_ip.as_deref() == Some(ip) {
            return Ok(());
        }
        let ip = ip.to_owned();
        conn.run(move |conn| {
            diesel::update(scim_tokens::table.filter(scim_tokens::org_uuid.eq(&self.org_uuid)))
                .set((scim_tokens::last_used_at.eq(now), scim_tokens::last_used_ip.eq(ip)))
                .execute(conn)
                .map_res("Error recording a provisioning request")
        })
        .await
    }
}

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Clone, Debug)]
#[diesel(table_name = scim_users)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(membership_uuid))]
pub struct ScimUser {
    pub membership_uuid: MembershipId,
    pub org_uuid: OrganizationId,
    pub user_name: String,
    pub user_name_key: String,
    pub external_id: Option<String>,
    pub attributes: String,
    pub provisioned: bool,
    pub turned_off: bool,
    pub refused_off_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl ScimUser {
    pub fn new(membership_uuid: MembershipId, org_uuid: OrganizationId, provisioned: bool) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            membership_uuid,
            org_uuid,
            user_name: String::new(),
            user_name_key: String::new(),
            external_id: None,
            attributes: "{}".to_owned(),
            provisioned,
            turned_off: false,
            refused_off_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn set_user_name(&mut self, user_name: &str) {
        user_name.clone_into(&mut self.user_name);
        self.user_name_key = user_name.to_lowercase();
    }

    pub async fn find(membership_uuid: &MembershipId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            scim_users::table.filter(scim_users::membership_uuid.eq(membership_uuid)).first::<Self>(conn).ok()
        })
        .await
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            scim_users::table.filter(scim_users::org_uuid.eq(org_uuid)).load::<Self>(conn).unwrap_or_default()
        })
        .await
    }

    /// The member the directory knows by this userName, compared without case.
    pub async fn find_by_user_name(org_uuid: &OrganizationId, user_name: &str, conn: &DbConn) -> Option<Self> {
        let key = user_name.to_lowercase();
        conn.run(move |conn| {
            scim_users::table
                .filter(scim_users::org_uuid.eq(org_uuid))
                .filter(scim_users::user_name_key.eq(key))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// An owner or admin revoked or restored this member in PassBundle. The
    /// directory may turn back on only someone it turned off itself, and
    /// that's no longer the last word: from now on, only an owner or admin
    /// turns them back on.
    pub async fn admin_decided(membership_uuid: &MembershipId, conn: &DbConn) -> EmptyResult {
        let membership_uuid = membership_uuid.clone();
        conn.run(move |conn| {
            diesel::update(scim_users::table.filter(scim_users::membership_uuid.eq(membership_uuid)))
                .set(scim_users::turned_off.eq(false))
                .execute(conn)
                .map(|_| ())
                .map_res("Error saving that an admin decided about a member")
        })
        .await
    }

    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.updated_at = Utc::now().naive_utc();
        let row = self.clone();
        conn.run(move |conn| {
            let exists = scim_users::table
                .filter(scim_users::membership_uuid.eq(&row.membership_uuid))
                .count()
                .get_result::<i64>(conn)
                .unwrap_or(0)
                > 0;
            if exists {
                diesel::update(scim_users::table.filter(scim_users::membership_uuid.eq(&row.membership_uuid)))
                    .set(&row)
                    .execute(conn)
            } else {
                diesel::insert_into(scim_users::table).values(&row).execute(conn)
            }
            .map_res("Error saving what the directory sent about a member")
        })
        .await
    }

    /// Whether provisioning invited this member and no owner's or admin's app
    /// has vouched for the invitation since: nothing but the directory chose
    /// them. Such an invitation doesn't exempt the address from the install
    /// command's email domains.
    pub async fn invited_unvouched(member: &Membership, email: &str, conn: &DbConn) -> bool {
        Self::find(&member.uuid, conn).await.is_some_and(|s| s.provisioned)
            && super::JoinSeal::find(&member.org_uuid, email, super::SealKind::Invite, conn).await.is_none()
    }

    /// The same, for a membership alone: whether an owner or admin still has
    /// to let this person in.
    pub async fn awaits_let_in(member: &Membership, conn: &DbConn) -> bool {
        if !Self::find(&member.uuid, conn).await.is_some_and(|s| s.provisioned) {
            return false;
        }
        match User::find_by_uuid(&member.user_uuid, conn).await {
            Some(user) => Self::invited_unvouched(member, &user.email, conn).await,
            None => true,
        }
    }
}

#[derive(Identifiable, Queryable, Insertable, Clone)]
#[diesel(table_name = scim_groups)]
#[diesel(primary_key(group_uuid))]
pub struct ScimGroup {
    pub group_uuid: GroupId,
    pub org_uuid: OrganizationId,
    pub created_at: NaiveDateTime,
}

impl ScimGroup {
    pub fn new(group_uuid: GroupId, org_uuid: OrganizationId) -> Self {
        Self {
            group_uuid,
            org_uuid,
            created_at: Utc::now().naive_utc(),
        }
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(scim_groups::table).values(self).execute(conn).map_res("Error saving a directory group")
        })
        .await
    }

    pub async fn find(group_uuid: &GroupId, org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            scim_groups::table
                .filter(scim_groups::group_uuid.eq(group_uuid))
                .filter(scim_groups::org_uuid.eq(org_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            scim_groups::table
                .filter(scim_groups::org_uuid.eq(org_uuid))
                .order(scim_groups::created_at.asc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn count_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> i64 {
        conn.run(move |conn| {
            scim_groups::table.filter(scim_groups::org_uuid.eq(org_uuid)).count().get_result::<i64>(conn).unwrap_or(0)
        })
        .await
    }
}

/// Takes one member out of one group.
pub async fn remove_group_member(group_uuid: &GroupId, member: &Membership, conn: &DbConn) -> EmptyResult {
    User::update_uuid_revision(&member.user_uuid, conn).await;
    let member_uuid = member.uuid.clone();
    conn.run(move |conn| {
        diesel::delete(
            groups_users::table
                .filter(groups_users::groups_uuid.eq(group_uuid))
                .filter(groups_users::users_organizations_uuid.eq(member_uuid)),
        )
        .execute(conn)
        .map_res("Error removing a member from a group")
    })
    .await
}

/// A member with what provisioning needs to know about them, loaded for a
/// whole organization at once: the directory asks about one person at a time,
/// and an organization's members fit in memory.
pub struct ScimPerson {
    pub member: Membership,
    pub user: User,
    pub scim: Option<ScimUser>,
    /// Owners, admins, custom roles, anyone with access to every item, and an
    /// MSP's staff: provisioning never changes them.
    pub protected: bool,
}

/// Whether provisioning must leave a membership alone. It only ever invites,
/// turns off, turns on, removes, and regroups regular members; anyone with a
/// role, every item, or a place through an MSP is managed in PassBundle.
pub fn protected_membership(atype: i32, access_all: bool, custom_role: bool, msp_staff: bool) -> bool {
    atype != MembershipType::User as i32 || access_all || custom_role || msp_staff
}

impl ScimPerson {
    pub async fn load(member: Membership, conn: &DbConn) -> Option<Self> {
        let user = User::find_by_uuid(&member.user_uuid, conn).await?;
        let custom = super::keykeeper_roles::find(&member.uuid, conn).await.is_some();
        let staff = super::MspMembership::find_by_membership(&member.uuid, conn).await.is_some();
        let scim = ScimUser::find(&member.uuid, conn).await;
        Some(Self {
            protected: protected_membership(member.atype, member.access_all, custom, staff),
            member,
            user,
            scim,
        })
    }

    /// Every member of an organization, in a handful of queries.
    pub async fn load_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        let members = Membership::find_by_org(org_uuid, conn).await;
        let ids: Vec<MembershipId> = members.iter().map(|m| m.uuid.clone()).collect();
        let user_ids: Vec<String> = members.iter().map(|m| m.user_uuid.to_string()).collect();
        let (users, custom, staff) = conn
            .run(move |conn| {
                let users = users::table.filter(users::uuid.eq_any(&user_ids)).load::<User>(conn).unwrap_or_default();
                let custom: HashSet<String> = membership_permissions::table
                    .filter(membership_permissions::membership_uuid.eq_any(&ids))
                    .select(membership_permissions::membership_uuid)
                    .load::<String>(conn)
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                let staff: HashSet<String> = msp_memberships::table
                    .filter(msp_memberships::membership_uuid.eq_any(&ids))
                    .select(msp_memberships::membership_uuid)
                    .load::<String>(conn)
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                (users, custom, staff)
            })
            .await;
        let mut scim: std::collections::HashMap<MembershipId, ScimUser> =
            ScimUser::find_by_org(org_uuid, conn).await.into_iter().map(|s| (s.membership_uuid.clone(), s)).collect();
        let mut users: std::collections::HashMap<String, User> =
            users.into_iter().map(|u| (u.uuid.to_string(), u)).collect();
        let mut people = Vec::with_capacity(members.len());
        for member in members {
            let Some(user) = users.remove(member.user_uuid.as_ref()) else {
                continue;
            };
            let id = member.uuid.to_string();
            people.push(Self {
                protected: protected_membership(
                    member.atype,
                    member.access_all,
                    custom.contains(&id),
                    staff.contains(&id),
                ),
                scim: scim.remove(&member.uuid),
                member,
                user,
            });
        }
        people
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_256_random_bits_with_a_prefix() {
        let (token, row) = ScimToken::generate(OrganizationId::from("org".to_owned()), "a@example.test");
        assert!(looks_like_scim_token(&token), "{token}");
        assert_eq!(token.len(), SCIM_TOKEN_PREFIX.len() + 43);
        assert_ne!(row.token_hash, token, "the token itself is never kept");
        assert!(row.matches(&token));
        let (other, _) = ScimToken::generate(OrganizationId::from("org".to_owned()), "a@example.test");
        assert_ne!(token, other);
        assert!(!row.matches(&other));
    }

    #[test]
    fn no_token_is_the_same_work_and_never_matches() {
        let (token, row) = ScimToken::generate(OrganizationId::from("org".to_owned()), "a@example.test");
        assert!(!ScimToken::matches_none(&token));
        assert!(!ScimToken::matches_none("pbscim1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        // The stand-in compared against is as long as a real hash.
        assert_eq!(row.token_hash.len(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".len());
    }

    #[test]
    fn the_hash_is_sha256_of_the_whole_token() {
        // printf %s 'pbscim1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | openssl dgst -sha256 -binary | base64
        assert_eq!(
            scim_token_hash("pbscim1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            "T3rOWPaFeaKLAhATZtR5wF/QSx/Zh6gT/+Z5vVPkPj8="
        );
    }

    #[test]
    fn only_token_shaped_strings_look_like_tokens() {
        assert!(looks_like_scim_token("pbscim1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        for bad in [
            "",
            "pbscim1_",
            "pbscim1_short",
            "pbscim2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "pbscim1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "pbscim1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
            "Bearer pbscim1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(!looks_like_scim_token(bad), "{bad}");
        }
    }

    #[test]
    fn provisioning_changes_only_regular_members() {
        let user = MembershipType::User as i32;
        assert!(!protected_membership(user, false, false, false));
        assert!(protected_membership(MembershipType::Owner as i32, false, false, false));
        assert!(protected_membership(MembershipType::Admin as i32, false, false, false));
        assert!(protected_membership(MembershipType::Manager as i32, false, false, false));
        assert!(protected_membership(user, true, false, false), "access to every item");
        assert!(protected_membership(user, false, true, false), "a custom role");
        assert!(protected_membership(user, false, false, true), "an MSP's staff");
    }
}

// Keykeeper: what lets an app confirm a join on its own without trusting the
// server. Owners' and admins' apps seal email invitations, MSP staff's places
// in clients, and joining settings with a key made from the organization's
// key, and the install command carries a secret the server only ever holds
// encrypted. The server can't read or make any of these; it keeps them for
// the apps and checks only that each looks like what it should be. See
// DESIGN.md, "Joins a hacked server can't forge".

use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        keykeeper_schema::{join_seals, joining_seals},
    },
    error::MapResult,
};

use super::OrganizationId;

/// A seal or proof: an HMAC-SHA256, standard base64.
pub fn valid_seal(seal: &str) -> bool {
    seal.len() == 44
        && seal.ends_with('=')
        && data_encoding::BASE64.decode(seal.as_bytes()).is_ok_and(|bytes| bytes.len() == 32)
}

/// The install command's join secret, encrypted with the organization's key
/// as upstream encrypts with symmetric keys: `2.<iv>|<data>|<mac>`.
pub fn valid_encrypted_secret(secret: &str) -> bool {
    let Some(parts) = secret.strip_prefix("2.") else {
        return false;
    };
    let parts: Vec<&str> = parts.split('|').collect();
    secret.len() <= 512
        && parts.len() == 3
        && parts.iter().all(|p| !p.is_empty() && data_encoding::BASE64.decode(p.as_bytes()).is_ok())
}

/// What a seal vouches for: an email invitation, or an MSP staff member's
/// place in a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealKind {
    Invite,
    Staff,
}

impl SealKind {
    fn as_str(self) -> &'static str {
        match self {
            SealKind::Invite => "invite",
            SealKind::Staff => "staff",
        }
    }
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = join_seals)]
#[diesel(primary_key(org_uuid, email, kind))]
pub struct JoinSeal {
    pub org_uuid: OrganizationId,
    pub email: String,
    pub kind: String,
    pub seal: String,
}

impl JoinSeal {
    /// Keeps a seal for someone, by their lowercased email, replacing any
    /// earlier one of the same kind. Without a seal, removes the earlier one,
    /// so a change made without sealing never keeps an old seal's word.
    pub async fn set(
        org_uuid: &OrganizationId,
        email: &str,
        kind: SealKind,
        seal: Option<&str>,
        conn: &DbConn,
    ) -> EmptyResult {
        let row = seal.map(|seal| Self {
            org_uuid: org_uuid.clone(),
            email: email.to_lowercase(),
            kind: kind.as_str().to_owned(),
            seal: seal.to_owned(),
        });
        let org = org_uuid.clone();
        let email = email.to_lowercase();
        conn.run(move |conn| {
            conn.transaction(|conn| {
                diesel::delete(
                    join_seals::table
                        .filter(join_seals::org_uuid.eq(&org))
                        .filter(join_seals::email.eq(&email))
                        .filter(join_seals::kind.eq(kind.as_str())),
                )
                .execute(conn)?;
                if let Some(row) = row {
                    diesel::insert_into(join_seals::table).values(&row).execute(conn)?;
                }
                Ok::<(), diesel::result::Error>(())
            })
            .map_res("Error saving a join seal")
        })
        .await
    }

    pub async fn find(org_uuid: &OrganizationId, email: &str, kind: SealKind, conn: &DbConn) -> Option<String> {
        let org = org_uuid.clone();
        let email = email.to_lowercase();
        conn.run(move |conn| {
            join_seals::table
                .filter(join_seals::org_uuid.eq(org))
                .filter(join_seals::email.eq(email))
                .filter(join_seals::kind.eq(kind.as_str()))
                .select(join_seals::seal)
                .first::<String>(conn)
                .ok()
        })
        .await
    }

    /// Removes someone's staff seals in these organizations, when they leave
    /// an MSP's staff or stop reaching some of its clients.
    pub async fn delete_staff(orgs: Vec<OrganizationId>, email: &str, conn: &DbConn) -> EmptyResult {
        let email = email.to_lowercase();
        conn.run(move |conn| {
            diesel::delete(
                join_seals::table
                    .filter(join_seals::org_uuid.eq_any(orgs))
                    .filter(join_seals::email.eq(email))
                    .filter(join_seals::kind.eq(SealKind::Staff.as_str())),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error removing staff seals")
        })
        .await
    }

    /// Removes every seal of one kind in an organization, such as all staff
    /// seals when a client removes its MSP. Returns how many went.
    pub async fn delete_kind(org_uuid: &OrganizationId, kind: SealKind, conn: &DbConn) -> Result<usize, crate::Error> {
        let org = org_uuid.clone();
        conn.run(move |conn| {
            diesel::delete(
                join_seals::table.filter(join_seals::org_uuid.eq(org)).filter(join_seals::kind.eq(kind.as_str())),
            )
            .execute(conn)
            .map_res("Error removing seals")
        })
        .await
    }
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = joining_seals)]
#[diesel(primary_key(org_uuid))]
pub struct JoiningSeal {
    pub org_uuid: OrganizationId,
    pub seal: String,
}

impl JoiningSeal {
    /// Keeps the seal over an organization's joining setting and domains, or
    /// removes it, so a setting changed without sealing means approval.
    pub async fn set(org_uuid: &OrganizationId, seal: Option<&str>, conn: &DbConn) -> EmptyResult {
        let row = seal.map(|seal| Self {
            org_uuid: org_uuid.clone(),
            seal: seal.to_owned(),
        });
        let org = org_uuid.clone();
        conn.run(move |conn| {
            conn.transaction(|conn| {
                diesel::delete(joining_seals::table.filter(joining_seals::org_uuid.eq(&org))).execute(conn)?;
                if let Some(row) = row {
                    diesel::insert_into(joining_seals::table).values(&row).execute(conn)?;
                }
                Ok::<(), diesel::result::Error>(())
            })
            .map_res("Error saving a joining seal")
        })
        .await
    }

    pub async fn find(org_uuid: &OrganizationId, conn: &DbConn) -> Option<String> {
        let org = org_uuid.clone();
        conn.run(move |conn| {
            joining_seals::table
                .filter(joining_seals::org_uuid.eq(org))
                .select(joining_seals::seal)
                .first::<String>(conn)
                .ok()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_are_hmacs_in_base64() {
        assert!(valid_seal("Lzxr28jrCFbS8FDbf7uxBHX4MyVhlz+g1h1WL/9m2SE="));
        assert!(!valid_seal("Lzxr28jrCFbS8FDbf7uxBHX4MyVhlz+g1h1WL/9m2SE"));
        assert!(!valid_seal("Lzxr28jrCFbS8FDbf7uxBHX4MyVhlz-g1h1WL_9m2SE="));
        assert!(!valid_seal(""));
        // 44 characters, but 31 bytes.
        assert!(!valid_seal(&format!("{}==", "A".repeat(42))));
    }

    #[test]
    fn secrets_are_encrypted_strings() {
        assert!(valid_encrypted_secret("2.AAECAw==|BAUGBw==|CAkKCw=="));
        assert!(!valid_encrypted_secret("0.AAECAw==|BAUGBw=="));
        assert!(!valid_encrypted_secret("2.AAECAw==|BAUGBw=="));
        assert!(!valid_encrypted_secret("2.AAECAw==||CAkKCw=="));
        assert!(!valid_encrypted_secret("2.not base64|BAUGBw==|CAkKCw=="));
        assert!(!valid_encrypted_secret(&format!("2.{}|BAUGBw==|CAkKCw==", "A".repeat(600))));
    }
}

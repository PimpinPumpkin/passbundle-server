// Keykeeper: script access. A token reads only its grants: copies of chosen
// fields of chosen items, encrypted by an admin's app with a token key the
// server never sees (derived from the token's seed, which only the admin's
// browser and the script have). The server keeps a hash of the token's auth
// secret, the token key sealed with the organization key (so apps that hold
// that key can refresh copies), and every read. See docs/script-access.md in
// the meta repo.

use std::net::IpAddr;

use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use ipnet::IpNet;

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        keykeeper_schema::{script_grants, script_reads, script_tokens},
    },
    error::MapResult,
    util::get_uuid,
};

use super::{CipherId, OrganizationId, UserId};

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Clone)]
#[diesel(table_name = script_tokens)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct ScriptToken {
    pub uuid: String,
    pub org_uuid: OrganizationId,
    pub name: String,
    pub created_by: UserId,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    pub revoked_at: Option<NaiveDateTime>,
    pub auth_hash: String,
    pub networks: String,
    pub sealed_key: String,
    pub last_used_at: Option<NaiveDateTime>,
    pub last_used_ip: Option<String>,
}

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Clone)]
#[diesel(table_name = script_grants)]
#[diesel(primary_key(token_uuid, cipher_uuid))]
pub struct ScriptGrant {
    pub token_uuid: String,
    pub cipher_uuid: CipherId,
    pub copy: String,
    pub revision: String,
    pub sealed_spec: String,
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = script_reads)]
#[diesel(primary_key(uuid))]
pub struct ScriptRead {
    pub uuid: String,
    pub token_uuid: String,
    pub cipher_uuid: Option<CipherId>,
    pub read_at: NaiveDateTime,
    pub ip: String,
    pub allowed: bool,
    pub reason: String,
}

/// The networks a token may be used from: IP ranges, or plain addresses as
/// one-address ranges. Empty means anywhere.
pub fn parse_networks(list: &[String]) -> Result<Vec<IpNet>, String> {
    if list.len() > 20 {
        return Err("At most 20 networks".into());
    }
    list.iter()
        .map(|entry| {
            let entry = entry.trim();
            entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .map(|net| net.trunc())
                .map_err(|_| format!("{entry} isn't an IP address or range, like 203.0.113.0/24"))
        })
        .collect()
}

impl ScriptToken {
    pub fn networks(&self) -> Vec<IpNet> {
        let list: Vec<String> = serde_json::from_str(&self.networks).unwrap_or_default();
        parse_networks(&list).unwrap_or_default()
    }

    /// Whether a request from this address may use the token.
    pub fn allows(&self, ip: &IpAddr) -> bool {
        let networks = self.networks();
        networks.is_empty() || networks.iter().any(|net| net.contains(ip))
    }

    /// Whether it still works: not revoked and not expired.
    pub fn is_live(&self, now: NaiveDateTime) -> bool {
        self.revoked_at.is_none() && now < self.expires_at
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(script_tokens::table).values(self).execute(conn).map_res("Error saving a script token")
        })
        .await
    }

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::update(script_tokens::table.filter(script_tokens::uuid.eq(&self.uuid)))
                .set(self)
                .execute(conn)
                .map_res("Error saving a script token")
        })
        .await
    }

    pub async fn find(uuid: &str, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| script_tokens::table.filter(script_tokens::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            script_tokens::table
                .filter(script_tokens::org_uuid.eq(org_uuid))
                .order(script_tokens::created_at.desc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    /// Revokes it: it stops working at once, and its copies are deleted.
    pub async fn revoke(&mut self, conn: &DbConn) -> EmptyResult {
        self.revoked_at = Some(Utc::now().naive_utc());
        self.save(conn).await?;
        ScriptGrant::delete_for_token(&self.uuid, conn).await
    }
}

impl ScriptGrant {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            let existing = script_grants::table
                .filter(script_grants::token_uuid.eq(&self.token_uuid))
                .filter(script_grants::cipher_uuid.eq(&self.cipher_uuid))
                .first::<Self>(conn)
                .ok();
            if existing.is_some() {
                diesel::update(
                    script_grants::table
                        .filter(script_grants::token_uuid.eq(&self.token_uuid))
                        .filter(script_grants::cipher_uuid.eq(&self.cipher_uuid)),
                )
                .set(self)
                .execute(conn)
            } else {
                diesel::insert_into(script_grants::table).values(self).execute(conn)
            }
            .map_res("Error saving a script grant")
        })
        .await
    }

    pub async fn find(token_uuid: &str, cipher_uuid: &CipherId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            script_grants::table
                .filter(script_grants::token_uuid.eq(token_uuid))
                .filter(script_grants::cipher_uuid.eq(cipher_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_for_token(token_uuid: &str, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            script_grants::table.filter(script_grants::token_uuid.eq(token_uuid)).load::<Self>(conn).unwrap_or_default()
        })
        .await
    }

    pub async fn find_for_cipher(cipher_uuid: &CipherId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            script_grants::table
                .filter(script_grants::cipher_uuid.eq(cipher_uuid))
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn delete(token_uuid: &str, cipher_uuid: &CipherId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(
                script_grants::table
                    .filter(script_grants::token_uuid.eq(token_uuid))
                    .filter(script_grants::cipher_uuid.eq(cipher_uuid)),
            )
            .execute(conn)
            .map_res("Error deleting a script grant")
        })
        .await
    }

    pub async fn delete_for_token(token_uuid: &str, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(script_grants::table.filter(script_grants::token_uuid.eq(token_uuid)))
                .execute(conn)
                .map_res("Error deleting script grants")
        })
        .await
    }
}

impl ScriptRead {
    pub async fn record(
        token_uuid: &str,
        cipher_uuid: Option<&CipherId>,
        ip: &IpAddr,
        allowed: bool,
        reason: &str,
        conn: &DbConn,
    ) -> EmptyResult {
        let read = Self {
            uuid: get_uuid(),
            token_uuid: token_uuid.to_owned(),
            cipher_uuid: cipher_uuid.cloned(),
            read_at: Utc::now().naive_utc(),
            ip: ip.to_string(),
            allowed,
            reason: reason.to_owned(),
        };
        conn.run(move |conn| {
            diesel::insert_into(script_reads::table).values(&read).execute(conn).map_res("Error logging a script read")
        })
        .await
    }

    /// The newest reads of a token, newest first.
    pub async fn recent(token_uuid: &str, limit: i64, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            script_reads::table
                .filter(script_reads::token_uuid.eq(token_uuid))
                .order(script_reads::read_at.desc())
                .limit(limit)
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    /// Whether the token was used from this address before.
    pub async fn seen_from(token_uuid: &str, ip: &str, conn: &DbConn) -> bool {
        conn.run(move |conn| {
            script_reads::table
                .filter(script_reads::token_uuid.eq(token_uuid))
                .filter(script_reads::ip.eq(ip))
                .filter(script_reads::allowed.eq(true))
                .count()
                .get_result::<i64>(conn)
                .unwrap_or(0)
                > 0
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_networks_as_ranges_or_single_addresses() {
        let nets = parse_networks(&["203.0.113.7".into(), "198.51.100.0/24".into(), "2001:db8::/32".into()]).unwrap();
        let addr = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(nets[0].contains(&addr("203.0.113.7")));
        assert!(!nets[0].contains(&addr("203.0.113.8")));
        assert!(nets[1].contains(&addr("198.51.100.200")));
        assert!(nets[2].contains(&addr("2001:db8::1")));
    }

    #[test]
    fn refuses_what_isnt_a_network() {
        assert!(parse_networks(&["office".into()]).is_err());
        assert!(parse_networks(&["300.1.1.1".into()]).is_err());
        assert!(parse_networks(&vec!["10.0.0.1".to_owned(); 21]).is_err());
    }
}

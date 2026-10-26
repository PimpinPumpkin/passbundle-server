// Keykeeper: sign in with Microsoft Entra ID, set up per organization. Each
// organization's owners and admins connect its own Entra tenant: an app
// registration's client id and secret, and an identifier people type. People
// are recognized by Entra's immutable tenant id and object id, never by the
// email Entra sends. Email domains an organization proves with a DNS TXT
// record let people find it by email and let accounts at them link. Nothing
// here is a key or reaches a vault: single sign-on proves who someone is, and
// their master password still unlocks. See DESIGN.md, "Sign in with
// Microsoft Entra ID", in the meta repo.

use chrono::{NaiveDateTime, TimeDelta, Utc};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        keykeeper_schema::{
            keykeeper_sso, keykeeper_sso_auth, keykeeper_sso_domains, keykeeper_sso_link_tickets, keykeeper_sso_links,
        },
    },
    error::MapResult,
};

use super::{OrganizationId, UserId};

/// How long a sign-in may take, from leaving for Microsoft to redeeming the
/// code this server hands back.
pub const SSO_AUTH_MINUTES: i64 = 10;

/// The base64 SHA-256 of a secret that travels in a URL (a state, a code, a
/// cookie), as the server keeps it. They're 256 random bits, so a fast hash
/// is enough.
pub fn sso_hash(secret: &str) -> String {
    BASE64.encode(ring::digest::digest(&ring::digest::SHA256, secret.as_bytes()).as_ref())
}

/// 32 random bytes as 43 base64url characters: states, nonces, codes, PKCE
/// verifiers, and DNS tokens.
pub fn sso_random() -> String {
    BASE64URL_NOPAD.encode(&crate::crypto::get_random_bytes::<32>())
}

/// The PKCE S256 challenge for a verifier (RFC 7636): base64url of its SHA-256.
pub fn pkce_challenge(verifier: &str) -> String {
    BASE64URL_NOPAD.encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}

/// What people type to find the organization's sign-in: 3 to 40 lowercase
/// letters, digits, and hyphens, starting and ending with a letter or digit.
/// The apps put it in URLs unescaped, so nothing else is allowed.
pub fn normalize_identifier(identifier: &str) -> Option<String> {
    let id = identifier.trim().to_lowercase();
    let ok = (3..=40).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-');
    ok.then_some(id)
}

/// A GUID (an Entra tenant id or client id), lowercase, or None.
pub fn normalize_guid(value: &str) -> Option<String> {
    let v = value.trim().to_lowercase();
    let groups: Vec<&str> = v.split('-').collect();
    let ok = groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, len)| g.len() == len && g.bytes().all(|b| b.is_ascii_hexdigit()));
    ok.then_some(v)
}

/// Microsoft's tenant for personal Microsoft accounts. An organization's
/// sign-in is always its own work tenant.
pub const CONSUMER_TENANT: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

/// An email domain as an organization adds it: lowercase, without a trailing
/// dot, at least two labels of letters, digits, and hyphens. Subdomains are
/// their own domains. Not an address.
pub fn normalize_domain(domain: &str) -> Option<String> {
    let d = domain.trim().trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = d.split('.').collect();
    let ok = d.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
        // The last label is a top-level domain, never all digits (an address).
        && labels.last().is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()));
    ok.then_some(d)
}

/// The domain of an email address, lowercase, if it has one.
pub fn email_domain(email: &str) -> Option<String> {
    let (_, domain) = email.trim().rsplit_once('@')?;
    normalize_domain(domain)
}

/// The TXT record's value that proves an organization controls a domain.
pub fn txt_value(token: &str) -> String {
    format!("passbundle-verification={token}")
}

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Clone)]
#[diesel(table_name = keykeeper_sso)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(org_uuid))]
pub struct SsoConfig {
    pub org_uuid: OrganizationId,
    pub enabled: bool,
    pub identifier: String,
    pub tenant_id: String,
    pub client_id: String,
    /// Sealed (see keykeeper_sso::secret). Never sent to anyone.
    pub client_secret: Option<String>,
    pub secret_set_at: Option<NaiveDateTime>,
    pub updated_by: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl SsoConfig {
    pub fn new(org_uuid: OrganizationId, updated_by: &str) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            org_uuid,
            enabled: false,
            identifier: String::new(),
            tenant_id: String::new(),
            client_id: String::new(),
            client_secret: None,
            secret_set_at: None,
            updated_by: updated_by.to_owned(),
            created_at: now,
            updated_at: now,
        }
    }

    /// On, with everything a sign-in needs.
    pub fn ready(&self) -> bool {
        self.enabled && self.client_secret.is_some() && !self.tenant_id.is_empty() && !self.client_id.is_empty()
    }

    pub async fn find(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| keykeeper_sso::table.filter(keykeeper_sso::org_uuid.eq(org_uuid)).first::<Self>(conn).ok())
            .await
    }

    pub async fn find_by_identifier(identifier: &str, conn: &DbConn) -> Option<Self> {
        let identifier = normalize_identifier(identifier)?;
        conn.run(move |conn| {
            keykeeper_sso::table.filter(keykeeper_sso::identifier.eq(identifier)).first::<Self>(conn).ok()
        })
        .await
    }

    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.updated_at = Utc::now().naive_utc();
        let row = self.clone();
        conn.run(move |conn| {
            let exists = keykeeper_sso::table
                .filter(keykeeper_sso::org_uuid.eq(&row.org_uuid))
                .count()
                .get_result::<i64>(conn)
                .unwrap_or(0)
                > 0;
            if exists {
                diesel::update(keykeeper_sso::table.filter(keykeeper_sso::org_uuid.eq(&row.org_uuid)))
                    .set(&row)
                    .execute(conn)
            } else {
                diesel::insert_into(keykeeper_sso::table).values(&row).execute(conn)
            }
            .map_res("Error saving the single sign-on settings")
        })
        .await
    }
}

#[derive(Identifiable, Queryable, Insertable, Clone)]
#[diesel(table_name = keykeeper_sso_domains)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct SsoDomain {
    pub uuid: String,
    pub org_uuid: OrganizationId,
    pub domain: String,
    pub txt_token: String,
    pub created_by: String,
    pub created_at: NaiveDateTime,
    pub verified_at: Option<NaiveDateTime>,
    pub last_checked_at: Option<NaiveDateTime>,
}

impl SsoDomain {
    pub fn new(org_uuid: OrganizationId, domain: String, created_by: &str) -> Self {
        Self {
            uuid: crate::util::get_uuid(),
            org_uuid,
            domain,
            txt_token: sso_random(),
            created_by: created_by.to_owned(),
            created_at: Utc::now().naive_utc(),
            verified_at: None,
            last_checked_at: None,
        }
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(keykeeper_sso_domains::table)
                .values(self)
                .execute(conn)
                .map_res("Error saving a domain")
        })
        .await
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            keykeeper_sso_domains::table
                .filter(keykeeper_sso_domains::org_uuid.eq(org_uuid))
                .order(keykeeper_sso_domains::created_at.asc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn find(uuid: &str, org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        let uuid = uuid.to_owned();
        conn.run(move |conn| {
            keykeeper_sso_domains::table
                .filter(keykeeper_sso_domains::uuid.eq(uuid))
                .filter(keykeeper_sso_domains::org_uuid.eq(org_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// The one verified row for a domain, in whichever organization has it.
    pub async fn find_verified(domain: &str, conn: &DbConn) -> Option<Self> {
        let domain = domain.to_owned();
        conn.run(move |conn| {
            keykeeper_sso_domains::table
                .filter(keykeeper_sso_domains::domain.eq(domain))
                .filter(keykeeper_sso_domains::verified_at.is_not_null())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// Whether this organization verified this domain.
    pub async fn is_verified_for(org_uuid: &OrganizationId, domain: &str, conn: &DbConn) -> bool {
        Self::find_verified(domain, conn).await.is_some_and(|d| &d.org_uuid == org_uuid)
    }

    /// Records a check that found the record: verified, unless another
    /// organization verified the domain first (the unique index decides a
    /// race). False if it couldn't be.
    pub async fn mark_verified(&self, conn: &DbConn) -> bool {
        let now = Utc::now().naive_utc();
        let uuid = self.uuid.clone();
        conn.run(move |conn| {
            diesel::update(keykeeper_sso_domains::table.filter(keykeeper_sso_domains::uuid.eq(uuid)))
                .set((keykeeper_sso_domains::verified_at.eq(now), keykeeper_sso_domains::last_checked_at.eq(now)))
                .execute(conn)
                .is_ok_and(|n| n == 1)
        })
        .await
    }

    /// Records a check that didn't find the record.
    pub async fn mark_checked(&self, conn: &DbConn) -> EmptyResult {
        let now = Utc::now().naive_utc();
        let uuid = self.uuid.clone();
        conn.run(move |conn| {
            diesel::update(keykeeper_sso_domains::table.filter(keykeeper_sso_domains::uuid.eq(uuid)))
                .set(keykeeper_sso_domains::last_checked_at.eq(now))
                .execute(conn)
                .map_res("Error recording a domain check")
        })
        .await
    }

    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        let uuid = self.uuid.clone();
        conn.run(move |conn| {
            diesel::delete(keykeeper_sso_domains::table.filter(keykeeper_sso_domains::uuid.eq(uuid)))
                .execute(conn)
                .map_res("Error removing a domain")
        })
        .await
    }
}

#[derive(Identifiable, Queryable, Insertable, Clone)]
#[diesel(table_name = keykeeper_sso_links)]
#[diesel(primary_key(org_uuid, tenant_id, object_id))]
pub struct SsoLink {
    pub org_uuid: OrganizationId,
    pub tenant_id: String,
    pub object_id: String,
    pub user_uuid: UserId,
    pub email: String,
    pub created_at: NaiveDateTime,
    pub last_used_at: Option<NaiveDateTime>,
}

impl SsoLink {
    pub fn new(
        org_uuid: OrganizationId,
        tenant_id: String,
        object_id: String,
        user_uuid: UserId,
        email: String,
    ) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            org_uuid,
            tenant_id,
            object_id,
            user_uuid,
            email,
            created_at: now,
            last_used_at: Some(now),
        }
    }

    /// The account a person in the organization's tenant signs in to.
    pub async fn find(org_uuid: &OrganizationId, tenant_id: &str, object_id: &str, conn: &DbConn) -> Option<Self> {
        let (tenant_id, object_id) = (tenant_id.to_owned(), object_id.to_owned());
        conn.run(move |conn| {
            keykeeper_sso_links::table
                .filter(keykeeper_sso_links::org_uuid.eq(org_uuid))
                .filter(keykeeper_sso_links::tenant_id.eq(tenant_id))
                .filter(keykeeper_sso_links::object_id.eq(object_id))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_user(org_uuid: &OrganizationId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            keykeeper_sso_links::table
                .filter(keykeeper_sso_links::org_uuid.eq(org_uuid))
                .filter(keykeeper_sso_links::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// Every organization this account is linked in.
    pub async fn find_all_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            keykeeper_sso_links::table
                .filter(keykeeper_sso_links::user_uuid.eq(user_uuid))
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            keykeeper_sso_links::table
                .filter(keykeeper_sso_links::org_uuid.eq(org_uuid))
                .order(keykeeper_sso_links::created_at.asc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    /// Saves a new link. False if the person or the account was linked in the
    /// meantime (both are unique in the organization).
    pub async fn insert(&self, conn: &DbConn) -> bool {
        conn.run(move |conn| {
            diesel::insert_into(keykeeper_sso_links::table).values(self).execute(conn).is_ok_and(|n| n == 1)
        })
        .await
    }

    pub async fn touch(&self, conn: &DbConn) -> EmptyResult {
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            diesel::update(
                keykeeper_sso_links::table
                    .filter(keykeeper_sso_links::org_uuid.eq(&self.org_uuid))
                    .filter(keykeeper_sso_links::tenant_id.eq(&self.tenant_id))
                    .filter(keykeeper_sso_links::object_id.eq(&self.object_id)),
            )
            .set(keykeeper_sso_links::last_used_at.eq(now))
            .execute(conn)
            .map_res("Error recording a sign-in")
        })
        .await
    }

    pub async fn delete(org_uuid: &OrganizationId, user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(
                keykeeper_sso_links::table
                    .filter(keykeeper_sso_links::org_uuid.eq(org_uuid))
                    .filter(keykeeper_sso_links::user_uuid.eq(user_uuid)),
            )
            .execute(conn)
            .map_res("Error unlinking an account")
        })
        .await
    }
}

/// How long a signed-in session's ticket to link single sign-on lasts.
pub const SSO_LINK_TICKET_MINUTES: i64 = 5;

/// A signed-in session's ticket to link its own account to an organization's
/// single sign-on (upstream's Link SSO): made by an authenticated request,
/// used once at /identity/connect/authorize, kept only as a hash.
#[derive(Identifiable, Queryable, Insertable, Clone)]
#[diesel(table_name = keykeeper_sso_link_tickets)]
#[diesel(primary_key(ticket_hash))]
pub struct SsoLinkTicket {
    pub ticket_hash: String,
    pub user_uuid: UserId,
    pub created_at: NaiveDateTime,
}

impl SsoLinkTicket {
    /// A new ticket for this account: the ticket itself, and its row.
    pub fn generate(user_uuid: UserId) -> (String, Self) {
        let ticket = sso_random();
        let row = Self {
            ticket_hash: sso_hash(&ticket),
            user_uuid,
            created_at: Utc::now().naive_utc(),
        };
        (ticket, row)
    }

    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            // An account's older tickets, and everyone's expired ones, go.
            let oldest = Utc::now().naive_utc() - TimeDelta::minutes(SSO_LINK_TICKET_MINUTES);
            diesel::delete(
                keykeeper_sso_link_tickets::table.filter(
                    keykeeper_sso_link_tickets::user_uuid
                        .eq(&self.user_uuid)
                        .or(keykeeper_sso_link_tickets::created_at.lt(oldest)),
                ),
            )
            .execute(conn)
            .ok();
            diesel::insert_into(keykeeper_sso_link_tickets::table)
                .values(self)
                .execute(conn)
                .map_res("Error saving a link ticket")
        })
        .await
    }

    /// Uses a ticket: the account it's for, once, within its five minutes.
    pub async fn take(ticket: &str, conn: &DbConn) -> Option<UserId> {
        let hash = sso_hash(ticket);
        let oldest = Utc::now().naive_utc() - TimeDelta::minutes(SSO_LINK_TICKET_MINUTES);
        conn.run(move |conn| {
            let row = keykeeper_sso_link_tickets::table
                .filter(keykeeper_sso_link_tickets::ticket_hash.eq(&hash))
                .first::<Self>(conn)
                .ok()?;
            let deleted = diesel::delete(
                keykeeper_sso_link_tickets::table.filter(keykeeper_sso_link_tickets::ticket_hash.eq(&hash)),
            )
            .execute(conn)
            .ok()?;
            (deleted == 1 && row.created_at >= oldest).then_some(row.user_uuid)
        })
        .await
    }
}

/// A sign-in in progress. See the migration for what each column holds.
#[derive(Identifiable, Queryable, Insertable, Clone)]
#[diesel(table_name = keykeeper_sso_auth)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(state_hash))]
pub struct SsoAuthRow {
    pub state_hash: String,
    pub org_uuid: OrganizationId,
    pub client_id: String,
    pub redirect_uri: String,
    pub client_state: String,
    pub client_challenge: String,
    pub nonce: String,
    pub code_verifier: String,
    pub binding_hash: String,
    pub code_hash: Option<String>,
    /// Linking from a signed-in session: the account that asked.
    pub link_user_uuid: Option<UserId>,
    pub identity: Option<String>,
    pub error: Option<String>,
    pub created_at: NaiveDateTime,
    pub returned_at: Option<NaiveDateTime>,
}

fn oldest() -> NaiveDateTime {
    Utc::now().naive_utc() - TimeDelta::minutes(SSO_AUTH_MINUTES)
}

impl SsoAuthRow {
    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(keykeeper_sso_auth::table)
                .values(self)
                .execute(conn)
                .map_res("Error starting a sign-in")
        })
        .await
    }

    /// A sign-in Microsoft hasn't answered yet, by its state.
    pub async fn find_waiting(state: &str, conn: &DbConn) -> Option<Self> {
        let (hash, oldest) = (sso_hash(state), oldest());
        conn.run(move |conn| {
            keykeeper_sso_auth::table
                .filter(keykeeper_sso_auth::state_hash.eq(hash))
                .filter(keykeeper_sso_auth::created_at.ge(oldest))
                .filter(keykeeper_sso_auth::returned_at.is_null())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// Takes Microsoft's answer for this sign-in, once: false if another
    /// request took it first, so a state never works twice.
    pub async fn take(&self, conn: &DbConn) -> bool {
        let now = Utc::now().naive_utc();
        let hash = self.state_hash.clone();
        conn.run(move |conn| {
            diesel::update(
                keykeeper_sso_auth::table
                    .filter(keykeeper_sso_auth::state_hash.eq(hash))
                    .filter(keykeeper_sso_auth::returned_at.is_null()),
            )
            .set(keykeeper_sso_auth::returned_at.eq(now))
            .execute(conn)
            .is_ok_and(|n| n == 1)
        })
        .await
    }

    /// Records what Microsoft's answer came to, and the code the app redeems.
    pub async fn finish(
        &self,
        code: &str,
        identity: Option<String>,
        error: Option<String>,
        conn: &DbConn,
    ) -> EmptyResult {
        let hash = self.state_hash.clone();
        let code_hash = sso_hash(code);
        conn.run(move |conn| {
            diesel::update(keykeeper_sso_auth::table.filter(keykeeper_sso_auth::state_hash.eq(hash)))
                .set((
                    keykeeper_sso_auth::code_hash.eq(code_hash),
                    keykeeper_sso_auth::identity.eq(identity),
                    keykeeper_sso_auth::error.eq(error),
                ))
                .execute(conn)
                .map_res("Error recording a sign-in")
        })
        .await
    }

    /// A sign-in Microsoft answered, by the code this server gave the app.
    pub async fn find_by_code(code: &str, conn: &DbConn) -> Option<Self> {
        let (hash, oldest) = (sso_hash(code), oldest());
        conn.run(move |conn| {
            keykeeper_sso_auth::table
                .filter(keykeeper_sso_auth::code_hash.eq(hash))
                .filter(keykeeper_sso_auth::created_at.ge(oldest))
                .filter(keykeeper_sso_auth::returned_at.is_not_null())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// Ends the sign-in: its code never works again.
    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        let hash = self.state_hash.clone();
        conn.run(move |conn| {
            diesel::delete(keykeeper_sso_auth::table.filter(keykeeper_sso_auth::state_hash.eq(hash)))
                .execute(conn)
                .map_res("Error ending a sign-in")
        })
        .await
    }

    /// Forgets sign-ins older than their ten minutes.
    pub async fn purge_expired(conn: &DbConn) {
        let oldest = oldest();
        conn.run(move |conn| {
            diesel::delete(keykeeper_sso_auth::table.filter(keykeeper_sso_auth::created_at.lt(oldest))).execute(conn)
        })
        .await
        .ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_short_and_url_safe() {
        assert_eq!(normalize_identifier(" Acme-Dental ").as_deref(), Some("acme-dental"));
        assert_eq!(normalize_identifier("abc").as_deref(), Some("abc"));
        for bad in ["", "ab", "-acme", "acme-", "acme dental", "acme_dental", "acme/dental", "a&b=c", &"a".repeat(41)] {
            assert_eq!(normalize_identifier(bad), None, "{bad}");
        }
    }

    #[test]
    fn guids_are_checked_and_lowercased() {
        assert_eq!(
            normalize_guid(" 72F988BF-86F1-41AF-91AB-2D7CD011DB47 ").as_deref(),
            Some("72f988bf-86f1-41af-91ab-2d7cd011db47")
        );
        for bad in
            ["", "contoso.onmicrosoft.com", "72f988bf86f141af91ab2d7cd011db47", "72f988bf-86f1-41af-91ab-2d7cd011db4g"]
        {
            assert_eq!(normalize_guid(bad), None, "{bad}");
        }
    }

    #[test]
    fn domains_are_names_never_addresses() {
        assert_eq!(normalize_domain("AcmeDental.com.").as_deref(), Some("acmedental.com"));
        assert_eq!(normalize_domain("mail.acme.co.uk").as_deref(), Some("mail.acme.co.uk"));
        for bad in
            ["", "com", "acme..com", "-acme.com", "acme-.com", "192.168.1.1", "acme.com/x", "ana@acme.com", "acme .com"]
        {
            assert_eq!(normalize_domain(bad), None, "{bad}");
        }
        assert_eq!(email_domain("Ana@AcmeDental.com").as_deref(), Some("acmedental.com"));
        assert_eq!(email_domain("no-at-sign"), None);
    }

    #[test]
    fn pkce_is_rfc_7636_s256() {
        // RFC 7636, Appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn random_values_are_256_bits() {
        let a = sso_random();
        assert_eq!(a.len(), 43);
        assert_ne!(a, sso_random());
        assert_ne!(sso_hash(&a), a);
    }
}

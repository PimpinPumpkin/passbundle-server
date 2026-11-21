// Keykeeper: a family's invite link (DESIGN.md, "A family's invite link", in
// the meta repo). The link is the web vault's address with the organization's
// id, a token, and a join secret. The owner's or admin's browser makes the
// token and the secret; the server keeps only the token's SHA-256, compares
// it in constant time, and never sees the secret. The link's settings (the
// token and the secret among them) are kept encrypted with the family's key
// by that browser, so owners and admins can show the link again and the
// server can't read it.
//
// Also each join with a link (its proof and whether approval was automatic
// then), and who said "No thanks" to the suggestion to add a legacy contact.

use chrono::{NaiveDateTime, TimeDelta};
use data_encoding::BASE64URL_NOPAD;
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        keykeeper_schema::{family_link_joins, family_links, legacy_contact_suggestions},
    },
    error::MapResult,
};

use super::{CollectionId, MembershipId, OrganizationId, UserId};

/// How long a link works, in days, as the owner picks it.
pub const FAMILY_LINK_DAYS: [i64; 3] = [1, 7, 30];

/// The most of a link's sealed settings the server keeps.
const MAX_SEALED: usize = 2048;

/// A link's token: 32 random bytes in base64url without padding.
pub fn valid_family_link_token(token: &str) -> bool {
    token.len() == 43 && BASE64URL_NOPAD.decode(token.as_bytes()).is_ok_and(|bytes| bytes.len() == 32)
}

/// A link's sealed settings: encrypted with the family's key as upstream
/// encrypts with symmetric keys, `2.<iv>|<data>|<mac>`. The server checks
/// only the form; it can't read them.
pub fn valid_sealed_settings(sealed: &str) -> bool {
    sealed.len() <= MAX_SEALED && super::valid_enc_string(sealed)
}

/// What the server keeps of a token: the base64 SHA-256 of it.
fn family_token_hash(token: &str) -> String {
    super::token_hash(token)
}

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Clone, Debug)]
#[diesel(table_name = family_links)]
#[diesel(primary_key(org_uuid))]
#[diesel(treat_none_as_null = true)]
pub struct FamilyLink {
    pub org_uuid: OrganizationId,
    /// The SHA-256 of the link's token, never the token. None while the link
    /// is off.
    pub token_hash: Option<String>,
    /// The link's settings, encrypted with the family's key by the browser
    /// that saved them. When the link is off, settings that say so.
    pub sealed: String,
    /// Whether people who join with it are let in without an owner's or
    /// admin's tap. Off by default.
    pub automatic: bool,
    /// When the link stops working. None while it's off.
    pub expires_at: Option<NaiveDateTime>,
    /// Who made it: the join page says they invited the person, and the link
    /// works only while they're one of the family's owners or admins.
    pub made_by: Option<UserId>,
    pub made_at: NaiveDateTime,
    /// The shared folder people who join with it get, Can edit.
    pub collection_uuid: Option<CollectionId>,
}

impl FamilyLink {
    /// A new link for a family, made by `by` at `now`: its token's hash, never
    /// the token, and the settings the browser sealed.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        org_uuid: OrganizationId,
        token: &str,
        sealed: String,
        automatic: bool,
        days: i64,
        by: UserId,
        collection: Option<CollectionId>,
        now: NaiveDateTime,
    ) -> Self {
        Self {
            org_uuid,
            token_hash: Some(family_token_hash(token)),
            sealed,
            automatic,
            expires_at: Some(now + TimeDelta::days(days)),
            made_by: Some(by),
            made_at: now,
            collection_uuid: collection,
        }
    }

    /// Whether `token` is this link's: its hash compared with the one kept, in
    /// constant time. Never for a link that's off.
    pub fn matches(&self, token: &str) -> bool {
        match &self.token_hash {
            Some(hash) => crate::crypto::ct_eq(family_token_hash(token), hash),
            None => no_link_matches(token),
        }
    }

    /// Whether the link works at `now`: on, and not ended.
    pub fn is_live(&self, now: NaiveDateTime) -> bool {
        self.token_hash.is_some() && self.expires_at.is_some_and(|ends| now < ends)
    }

    /// Turns the link off: no token works, and the settings the browser
    /// sealed say it's off.
    pub fn turn_off(&mut self, sealed: String) {
        self.token_hash = None;
        self.expires_at = None;
        self.automatic = false;
        self.sealed = sealed;
    }

    pub async fn find(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| family_links::table.filter(family_links::org_uuid.eq(org_uuid)).first::<Self>(conn).ok())
            .await
    }

    /// The live link of this family that `token` is, at `now`, or None,
    /// whatever the reason: no link, a wrong or replaced token, a link that
    /// ended or is off. The token is compared in constant time, with the same
    /// work when there's no link, so neither the answer nor its timing tells
    /// the reasons apart.
    pub async fn live_for_token(
        org_uuid: &OrganizationId,
        token: &str,
        now: NaiveDateTime,
        conn: &DbConn,
    ) -> Option<Self> {
        let Some(link) = Self::find(org_uuid, conn).await else {
            no_link_matches(token);
            return None;
        };
        (link.matches(token) && link.is_live(now)).then_some(link)
    }

    /// Saves it: a new link, a replaced one, or a change.
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(family_links::table.filter(family_links::org_uuid.eq(&self.org_uuid)))
                .execute(conn)
                .map(|_| ())
                .map_res("Error saving the invite link")?;
            diesel::insert_into(family_links::table)
                .values(self)
                .execute(conn)
                .map(|_| ())
                .map_res("Error saving the invite link")
        })
        .await
    }
}

/// The same work as comparing a token's hash, for no link, so timing doesn't
/// tell the two apart. Always false.
fn no_link_matches(token: &str) -> bool {
    // The base64 of 32 zero bytes: the length of a real hash, and no token's
    // (SHA-256 has no known preimage for it).
    const NO_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let _ = std::hint::black_box(crate::crypto::ct_eq(family_token_hash(token), NO_TOKEN));
    false
}

/// Someone who joined a family with its link.
#[derive(Identifiable, Queryable, Insertable, Clone, Debug)]
#[diesel(table_name = family_link_joins)]
#[diesel(primary_key(membership_uuid))]
pub struct FamilyLinkJoin {
    pub membership_uuid: MembershipId,
    pub org_uuid: OrganizationId,
    /// That the joining browser knew the link's join secret, bound to the
    /// person's public key (the install command's join proof), for the apps
    /// that let people in on their own.
    pub proof: Option<String>,
    /// Whether the link let people in automatically when they joined.
    pub automatic: bool,
    pub joined_at: NaiveDateTime,
}

impl FamilyLinkJoin {
    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(family_link_joins::table)
                .values(self)
                .execute(conn)
                .map(|_| ())
                .map_res("Error recording a join with the invite link")
        })
        .await
    }

    pub async fn find(membership_uuid: &MembershipId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            family_link_joins::table
                .filter(family_link_joins::membership_uuid.eq(membership_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// A family's joins with its link, newest first.
    pub async fn for_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            family_link_joins::table
                .filter(family_link_joins::org_uuid.eq(org_uuid))
                .order(family_link_joins::joined_at.desc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }
}

/// "No thanks" to the suggestion to add a legacy contact.
pub struct LegacyContactSuggestion;

impl LegacyContactSuggestion {
    pub async fn dismissed(user_uuid: &UserId, conn: &DbConn) -> bool {
        conn.run(move |conn| {
            legacy_contact_suggestions::table
                .filter(legacy_contact_suggestions::user_uuid.eq(user_uuid))
                .count()
                .get_result::<i64>(conn)
                .is_ok_and(|n| n > 0)
        })
        .await
    }

    pub async fn dismiss(user_uuid: &UserId, now: NaiveDateTime, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(
                legacy_contact_suggestions::table.filter(legacy_contact_suggestions::user_uuid.eq(user_uuid)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error saving the answer to the suggestion")?;
            diesel::insert_into(legacy_contact_suggestions::table)
                .values((
                    legacy_contact_suggestions::user_uuid.eq(user_uuid),
                    legacy_contact_suggestions::dismissed_at.eq(now),
                ))
                .execute(conn)
                .map(|_| ())
                .map_res("Error saving the answer to the suggestion")
        })
        .await
    }
}

#[cfg(all(test, sqlite))]
mod tests {
    use super::*;
    use crate::db::{
        DbPool,
        models::{Organization, User},
    };

    const TOKEN: &str = "dGhpcnR5LXR3byBieXRlcyBvZiBhIHRlc3QgdG9rZW4";
    const OTHER: &str = "YW5vdGhlciB0aGlydHktdHdvLWJ5dGUgdG9rZW4uLi4";
    const SEALED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|c2VhbGVk|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const OFF: &str = "2.AQEBAQEBAQEBAQEBAQEBAQ==|b2Zm|AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    fn at(hours: i64) -> NaiveDateTime {
        chrono::DateTime::from_timestamp(1_790_000_000, 0).unwrap().naive_utc() + TimeDelta::hours(hours)
    }

    async fn family(conn: &DbConn) -> (Organization, User) {
        let org = Organization::new("Rivera family".to_owned(), "owner@example.test", None, None);
        org.save(conn).await.unwrap();
        let mut owner = User::new(&format!("owner-{}@example.test", crate::util::get_uuid()), None);
        owner.save(conn).await.unwrap();
        (org, owner)
    }

    fn link(org: &Organization, owner: &User, token: &str, now: NaiveDateTime) -> FamilyLink {
        FamilyLink::new(org.uuid.clone(), token, SEALED.to_owned(), false, 7, owner.uuid.clone(), None, now)
    }

    #[test]
    fn a_token_is_32_random_bytes_in_base64url() {
        assert!(valid_family_link_token(TOKEN));
        assert!(valid_family_link_token(OTHER));
        for bad in ["", "short", &format!("{TOKEN}A"), &TOKEN.replace('G', "+"), &format!("{}=", &TOKEN[..42])] {
            assert!(!valid_family_link_token(bad), "{bad}");
        }
    }

    #[test]
    fn sealed_settings_must_look_encrypted() {
        assert!(valid_sealed_settings(SEALED));
        assert!(valid_sealed_settings(OFF));
        for bad in ["", "plain", "2.a|b", "2.AAAA|!!|AAAA", &format!("2.AAAA|{}|AAAA", "QUFB".repeat(600))] {
            assert!(!valid_sealed_settings(bad), "{}", &bad[..bad.len().min(40)]);
        }
    }

    /// The database holds the token's hash and the sealed settings as the
    /// browser sent them, and never the token.
    #[rocket::async_test]
    async fn the_token_is_kept_only_as_a_hash() {
        let conn = DbPool::for_test().await;
        let (org, owner) = family(&conn).await;
        link(&org, &owner, TOKEN, at(0)).save(&conn).await.unwrap();

        let kept = FamilyLink::find(&org.uuid, &conn).await.unwrap();
        assert_eq!(kept.token_hash.as_deref(), Some(super::super::token_hash(TOKEN).as_str()));
        assert_eq!(kept.sealed, SEALED);
        let every_column = format!("{kept:?}");
        assert!(!every_column.contains(TOKEN), "the token itself is nowhere in the row");
        assert!(kept.matches(TOKEN));
        assert!(!kept.matches(OTHER));
    }

    #[rocket::async_test]
    async fn a_link_works_until_it_ends() {
        let conn = DbPool::for_test().await;
        let (org, owner) = family(&conn).await;
        link(&org, &owner, TOKEN, at(0)).save(&conn).await.unwrap();

        assert!(FamilyLink::live_for_token(&org.uuid, TOKEN, at(0), &conn).await.is_some());
        assert!(FamilyLink::live_for_token(&org.uuid, TOKEN, at(7 * 24 - 1), &conn).await.is_some());
        assert!(FamilyLink::live_for_token(&org.uuid, TOKEN, at(7 * 24), &conn).await.is_none(), "it ended");
        assert!(FamilyLink::live_for_token(&org.uuid, TOKEN, at(30 * 24), &conn).await.is_none());
    }

    #[rocket::async_test]
    async fn replacing_stops_the_old_token_at_once_and_off_stops_every_token() {
        let conn = DbPool::for_test().await;
        let (org, owner) = family(&conn).await;
        link(&org, &owner, TOKEN, at(0)).save(&conn).await.unwrap();

        // Replaced: the old token stops, the new one works.
        link(&org, &owner, OTHER, at(1)).save(&conn).await.unwrap();
        assert!(FamilyLink::live_for_token(&org.uuid, TOKEN, at(1), &conn).await.is_none());
        assert!(FamilyLink::live_for_token(&org.uuid, OTHER, at(1), &conn).await.is_some());

        // Off: nothing works, and the sealed settings say so.
        let mut off = FamilyLink::find(&org.uuid, &conn).await.unwrap();
        off.turn_off(OFF.to_owned());
        off.save(&conn).await.unwrap();
        let kept = FamilyLink::find(&org.uuid, &conn).await.unwrap();
        assert_eq!((kept.token_hash.as_deref(), kept.expires_at, kept.automatic), (None, None, false));
        assert_eq!(kept.sealed, OFF);
        for token in [TOKEN, OTHER] {
            assert!(!kept.matches(token));
            assert!(FamilyLink::live_for_token(&org.uuid, token, at(1), &conn).await.is_none());
        }
    }

    /// No link, a wrong token, a replaced one, one that ended, and one that's
    /// off all come back as the same None.
    #[rocket::async_test]
    async fn every_bad_token_gets_the_same_answer() {
        let conn = DbPool::for_test().await;
        let (org, owner) = family(&conn).await;
        let (other_family, _) = family(&conn).await;
        link(&org, &owner, TOKEN, at(0)).save(&conn).await.unwrap();
        link(&org, &owner, OTHER, at(0)).save(&conn).await.unwrap();

        let answers = [
            FamilyLink::live_for_token(&other_family.uuid, OTHER, at(0), &conn).await.map(|l| l.org_uuid),
            FamilyLink::live_for_token(&org.uuid, "not-a-token", at(0), &conn).await.map(|l| l.org_uuid),
            FamilyLink::live_for_token(&org.uuid, TOKEN, at(0), &conn).await.map(|l| l.org_uuid),
            FamilyLink::live_for_token(&org.uuid, OTHER, at(8 * 24), &conn).await.map(|l| l.org_uuid),
        ];
        assert!(answers.iter().all(Option::is_none), "{answers:?}");
        let mut off = FamilyLink::find(&org.uuid, &conn).await.unwrap();
        off.turn_off(OFF.to_owned());
        off.save(&conn).await.unwrap();
        assert!(FamilyLink::live_for_token(&org.uuid, OTHER, at(0), &conn).await.is_none());
    }

    #[rocket::async_test]
    async fn no_thanks_is_kept_for_the_account() {
        let conn = DbPool::for_test().await;
        let (_, owner) = family(&conn).await;
        assert!(!LegacyContactSuggestion::dismissed(&owner.uuid, &conn).await);
        LegacyContactSuggestion::dismiss(&owner.uuid, at(0), &conn).await.unwrap();
        LegacyContactSuggestion::dismiss(&owner.uuid, at(1), &conn).await.unwrap();
        assert!(LegacyContactSuggestion::dismissed(&owner.uuid, &conn).await);
    }
}

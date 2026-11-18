// Keykeeper: the one-time codes an MSP gives the owner of an organization
// that already uses PassBundle, who enters one to join the organization to
// the MSP (DESIGN.md, "An organization that already uses PassBundle", in the
// meta repo). A code is 24 characters of Crockford's base32, 120 random bits:
// the first 8 find it, and the server keeps only a SHA-256 of the whole code,
// compared in constant time, never the code. It works once (its row goes when
// it's used or revoked) and for LINK_CODE_DAYS.
//
// Joining, and moving from one MSP to another, is one database transaction
// over several of the server's own steps on the request's connection
// (`begin_write`, `commit`, `rollback`), so it all happens or none of it does.

use chrono::{NaiveDateTime, TimeDelta};
use diesel::prelude::*;

use crate::{
    api::{ApiResult, EmptyResult},
    db::{DbConn, keykeeper_schema::msp_link_codes},
    error::MapResult,
};

use super::{MspId, OrganizationId, User, UserId};

/// How long a code works.
pub const LINK_CODE_DAYS: i64 = 7;

/// How many codes an MSP may have open at once.
pub const MAX_OPEN_LINK_CODES: i64 = 25;

/// Crockford's base32: no I, L, O, or U, so a code read aloud or typed
/// isn't mistaken.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A code's length, and how much of it finds it.
const CODE_LEN: usize = 24;
const SELECTOR_LEN: usize = 8;

/// The most of someone's typing the server reads: a code in groups of four
/// with dashes and a few spaces fits well inside it.
const MAX_TYPED: usize = 64;

/// A new code: 15 random bytes (120 bits) as 24 characters of the alphabet.
pub fn new_link_code() -> String {
    let bytes = crate::crypto::get_random_bytes::<15>();
    let mut code = String::with_capacity(CODE_LEN);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            code.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
        buffer &= (1 << bits) - 1;
    }
    code
}

/// A code as people see it: groups of four, with dashes.
pub fn shown_link_code(code: &str) -> String {
    code.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("-")
}

/// What someone typed, read as a code: case, spaces, and dashes don't
/// matter, O reads as 0, and I and L as 1. None unless that leaves exactly a
/// code's 24 characters of the alphabet.
pub fn read_link_code(typed: &str) -> Option<String> {
    if typed.len() > MAX_TYPED {
        return None;
    }
    let mut code = String::with_capacity(CODE_LEN);
    for c in typed.chars() {
        let c = match c.to_ascii_uppercase() {
            ' ' | '-' | '\t' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) {
            return None;
        }
        code.push(c);
    }
    (code.len() == CODE_LEN).then_some(code)
}

/// What the server keeps of a code: the base64 SHA-256 of all of it.
pub fn link_code_hash(code: &str) -> String {
    super::token_hash(code)
}

#[derive(Identifiable, Queryable, Insertable, Clone, Debug)]
#[diesel(table_name = msp_link_codes)]
#[diesel(primary_key(uuid))]
pub struct MspLinkCode {
    pub uuid: String,
    pub msp_uuid: MspId,
    /// The code's first 8 characters, to find it by.
    pub selector: String,
    /// link_code_hash of the whole code; never the code.
    pub code_hash: String,
    /// Who it's for, as the MSP admin who made it said.
    pub label: Option<String>,
    pub created_by_uuid: Option<UserId>,
    pub created_by_email: String,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
}

impl MspLinkCode {
    /// A new code for an MSP, made by one of its admins at `now`, and the
    /// code itself: the only place it ever is.
    pub fn new(msp_uuid: MspId, label: Option<String>, by: &User, now: NaiveDateTime) -> (Self, String) {
        let code = new_link_code();
        let row = Self {
            uuid: crate::util::get_uuid(),
            msp_uuid,
            selector: code[..SELECTOR_LEN].to_owned(),
            code_hash: link_code_hash(&code),
            label,
            created_by_uuid: Some(by.uuid.clone()),
            created_by_email: by.email.clone(),
            created_at: now,
            expires_at: now + TimeDelta::days(LINK_CODE_DAYS),
        };
        (row, code)
    }

    /// Whether `code` is this one: its hash compared with the one kept, in
    /// constant time.
    pub fn matches(&self, code: &str) -> bool {
        crate::crypto::ct_eq(link_code_hash(code), &self.code_hash)
    }

    pub fn expired(&self, now: NaiveDateTime) -> bool {
        now >= self.expires_at
    }

    /// Saves it. False, with nothing saved, if an open code already starts
    /// with the same 8 characters (one in a trillion), so the caller makes
    /// another.
    pub async fn insert(&self, conn: &DbConn) -> ApiResult<bool> {
        conn.run(move |conn| {
            let taken = msp_link_codes::table
                .filter(msp_link_codes::selector.eq(&self.selector))
                .count()
                .get_result::<i64>(conn)?;
            if taken > 0 {
                return Ok(false);
            }
            diesel::insert_into(msp_link_codes::table).values(self).execute(conn).map(|_| true)
        })
        .await
        .map_res("Error saving a code")
    }

    /// The code that starts with these 8 characters, whatever its MSP.
    pub async fn find_by_selector(selector: &str, conn: &DbConn) -> Option<Self> {
        let selector = selector.to_owned();
        conn.run(move |conn| {
            msp_link_codes::table.filter(msp_link_codes::selector.eq(selector)).first::<Self>(conn).ok()
        })
        .await
    }

    /// One of an MSP's codes, by its id.
    pub async fn find(msp_uuid: &MspId, uuid: &str, conn: &DbConn) -> Option<Self> {
        let uuid = uuid.to_owned();
        conn.run(move |conn| {
            msp_link_codes::table
                .filter(msp_link_codes::msp_uuid.eq(msp_uuid))
                .filter(msp_link_codes::uuid.eq(uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// An MSP's codes that still work at `now`, newest first. Ones that ended
    /// go first, since nothing can use them.
    pub async fn open_for_msp(msp_uuid: &MspId, now: NaiveDateTime, conn: &DbConn) -> ApiResult<Vec<Self>> {
        conn.run(move |conn| {
            diesel::delete(
                msp_link_codes::table
                    .filter(msp_link_codes::msp_uuid.eq(msp_uuid))
                    .filter(msp_link_codes::expires_at.le(now)),
            )
            .execute(conn)?;
            msp_link_codes::table
                .filter(msp_link_codes::msp_uuid.eq(msp_uuid))
                .order(msp_link_codes::created_at.desc())
                .load::<Self>(conn)
        })
        .await
        .map_res("Error loading an MSP's codes")
    }

    /// Uses the code up, or revokes it: deletes it, and says whether it was
    /// still there. A second request with the same code, at the same moment
    /// or later, finds nothing to delete.
    pub async fn delete(&self, conn: &DbConn) -> ApiResult<bool> {
        let uuid = self.uuid.clone();
        conn.run(move |conn| {
            diesel::delete(msp_link_codes::table.filter(msp_link_codes::uuid.eq(uuid))).execute(conn).map(|n| n == 1)
        })
        .await
        .map_res("Error using a code")
    }
}

/// The code someone entered, if it's one that works at `now`: found by its
/// first 8 characters, then checked on its hash in constant time. Malformed,
/// unknown, wrong, and ended codes are all the same None, so an answer never
/// says which.
pub async fn find_link_code(typed: &str, now: NaiveDateTime, conn: &DbConn) -> Option<MspLinkCode> {
    let code = read_link_code(typed)?;
    let found = MspLinkCode::find_by_selector(&code[..SELECTOR_LEN], conn).await?;
    (found.matches(&code) && !found.expired(now)).then_some(found)
}

/// Starts a transaction on the request's connection that several of the
/// server's own steps then run in, each with `conn.run` as usual: steps that
/// use a transaction of their own get a savepoint inside it. SQLite's is
/// immediate, holding the write lock from the start; PostgreSQL's locks the
/// organization's row, so two requests for one organization go one at a
/// time. End it with `commit`, or `rollback` on any error. A connection
/// dropped with it still open is discarded by the pool, which rolls it back.
pub async fn begin_write(org: &OrganizationId, conn: &DbConn) -> EmptyResult {
    #[cfg(not(postgresql))]
    let _ = org;
    let begun: Result<(), diesel::result::Error> = db_run! { conn:
        sqlite {
            diesel::connection::AnsiTransactionManager::begin_transaction_sql(conn, "BEGIN IMMEDIATE")
        }
        postgresql {
            use crate::db::schema::organizations;
            use diesel::{connection::TransactionManager, pg::PgConnection};
            type Manager = <PgConnection as Connection>::TransactionManager;
            Manager::begin_transaction(conn)?;
            let locked = organizations::table
                .filter(organizations::uuid.eq(org))
                .select(organizations::uuid)
                .for_update()
                .first::<OrganizationId>(conn)
                .map(|_| ());
            if locked.is_err() {
                drop(Manager::rollback_transaction(conn));
            }
            locked
        }
    };
    begun.map_res("Error starting a change")
}

/// Ends a `begin_write` transaction, keeping what it did.
pub async fn commit(conn: &DbConn) -> EmptyResult {
    use diesel::connection::TransactionManager;
    conn.run(<crate::db::DbConnInner as Connection>::TransactionManager::commit_transaction)
        .await
        .map_res("Error saving a change")
}

/// Ends a `begin_write` transaction, undoing what it did. A failure here is
/// logged: the pool discards a connection still in a transaction.
pub async fn rollback(conn: &DbConn) {
    use diesel::connection::TransactionManager;
    if let Err(e) = conn.run(<crate::db::DbConnInner as Connection>::TransactionManager::rollback_transaction).await {
        error!("Couldn't undo a change that failed: {e:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_code_is_24_characters_of_the_alphabet() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let code = new_link_code();
            assert_eq!(code.len(), 24, "{code}");
            assert!(code.bytes().all(|b| ALPHABET.contains(&b)), "{code}");
            assert_eq!(read_link_code(&code).as_deref(), Some(code.as_str()));
            assert!(seen.insert(code), "a code came up twice");
        }
    }

    #[test]
    fn every_character_of_the_alphabet_turns_up() {
        // 120 bits make 24 characters of 5 bits each, with none left over or
        // stuck: across many codes, each position takes every character.
        let mut first = std::collections::HashSet::new();
        let mut last = std::collections::HashSet::new();
        for _ in 0..2000 {
            let code = new_link_code();
            first.insert(code.as_bytes()[0]);
            last.insert(code.as_bytes()[23]);
        }
        assert_eq!(first.len(), 32);
        assert_eq!(last.len(), 32);
    }

    #[test]
    fn a_code_is_shown_in_groups_of_four() {
        assert_eq!(shown_link_code("7KQ2MXP4ZT9WHN3RVB8CJ5DF"), "7KQ2-MXP4-ZT9W-HN3R-VB8C-J5DF");
    }

    #[test]
    fn a_code_is_read_as_people_type_it() {
        let code = "7KQ2MXP4ZT9WHN3RVB8CJ5DF";
        for typed in [
            "7KQ2-MXP4-ZT9W-HN3R-VB8C-J5DF",
            "7kq2-mxp4-zt9w-hn3r-vb8c-j5df",
            " 7KQ2 MXP4 ZT9W HN3R VB8C J5DF ",
            "7KQ2MXP4ZT9WHN3RVB8CJ5DF",
        ] {
            assert_eq!(read_link_code(typed).as_deref(), Some(code), "{typed}");
        }
        // O reads as 0, and I and L as 1.
        assert_eq!(read_link_code("O000-0000-0000-0000-0000-000I").as_deref(), Some("000000000000000000000001"));
        assert_eq!(read_link_code("l000-0000-0000-0000-0000-0000").as_deref(), Some("100000000000000000000000"));
    }

    #[test]
    fn anything_else_is_no_code() {
        for typed in [
            "",
            "7KQ2-MXP4-ZT9W-HN3R-VB8C-J5D",
            "7KQ2-MXP4-ZT9W-HN3R-VB8C-J5DFF",
            "7KQ2-MXP4-ZT9W-HN3R-VB8C-J5DU",
            "7KQ2_MXP4_ZT9W_HN3R_VB8C_J5DF",
            "7KQ2-MXP4-ZT9W-HN3R-VB8C-J5D\u{0}",
            "7KQ2-MXP4-ZT9W-HN3R-VB8C-J5DÉ",
        ] {
            assert_eq!(read_link_code(typed), None, "{typed:?}");
        }
        assert_eq!(read_link_code(&"-".repeat(100)), None);
    }

    #[test]
    fn a_code_matches_only_itself_and_only_until_it_ends() {
        let now = chrono::Utc::now().naive_utc();
        let user = User::new("dana@example.test", None);
        let (row, code) = MspLinkCode::new(MspId::from("msp".to_owned()), None, &user, now);
        assert!(row.matches(&code));
        assert_eq!(row.selector, code[..8]);
        assert_ne!(row.code_hash, code);
        let mut other = code.clone().into_bytes();
        other[23] = if other[23] == b'0' {
            b'1'
        } else {
            b'0'
        };
        assert!(!row.matches(&String::from_utf8(other).unwrap()));
        assert!(!row.expired(now + TimeDelta::days(LINK_CODE_DAYS) - TimeDelta::seconds(1)));
        assert!(row.expired(now + TimeDelta::days(LINK_CODE_DAYS)));
    }
}

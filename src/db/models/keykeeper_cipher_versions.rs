// Keykeeper: every item's past versions. Before an edit replaces an item's
// contents, the server keeps the item as it was stored: its encrypted fields
// exactly as they were, which it can't read, with who saved that version and
// who replaced it. Apps decrypt a version like the item itself, and restore
// one by saving it as a normal edit. See DESIGN.md, "Item history".

use std::collections::HashMap;

use chrono::{NaiveDate, NaiveDateTime, Utc};
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        keykeeper_schema::{keykeeper_cipher_saves, keykeeper_cipher_versions},
        schema::ciphers,
    },
    error::MapResult,
};

use super::{Cipher, CipherId, UserId};

/// The newest versions an item keeps, every one of them.
pub const KEEP_NEWEST: usize = 20;
/// The most versions an item keeps: the newest, then one a day.
pub const MAX_VERSIONS: usize = 100;
/// The most each of an item's two kinds of versions take, encrypted: its
/// newest, and its one a day. Each kind has a budget of its own, so the
/// newest, however big, never push out the days before them.
pub const MAX_HISTORY_BYTES: i64 = 4 * 1024 * 1024;
/// A version this big or smaller is kept even when its organization's history
/// is full: real items are a few KB, and a note is at most 10,000
/// characters, so filling an organization's history with big saves can't
/// stop a normal item's history.
pub const ALWAYS_KEPT_BYTES: i32 = 64 * 1024;
/// The largest item the server saves, encrypted and without attachments,
/// which are stored apart. Real items are a few KB; a note is at most
/// 10,000 characters.
pub const MAX_ITEM_BYTES: usize = 512 * 1024;
/// The most password history entries an item keeps (upstream's apps keep 5).
pub const MAX_PASSWORD_HISTORY: usize = 100;

/// An item's encrypted fields' length in bytes, as the server stores them.
pub fn encrypted_size(cipher: &Cipher) -> usize {
    cipher.name.len()
        + cipher.key.as_ref().map_or(0, String::len)
        + cipher.notes.as_ref().map_or(0, String::len)
        + cipher.fields.as_ref().map_or(0, String::len)
        + cipher.data.len()
        + cipher.password_history.as_ref().map_or(0, String::len)
}

/// What a save does to an item's history.
pub enum ItemSave {
    /// A new item, made or imported by this person: no version yet.
    New,
    /// An existing item's contents replaced by this person: the version it
    /// replaces is kept, unless it's a personal item moving into an
    /// organization.
    Edit,
    /// The same contents encrypted with the owner's new key: nothing changes.
    Rotation,
}

/// The history part of a save, worked out before the item changes.
pub enum History {
    /// Record who saved the item, and keep nothing.
    Saved,
    /// Keep the version this edit replaces, if the edit changes it.
    Replaced(Box<CipherVersion>),
    /// Forget the item's versions: a personal item moving into an
    /// organization, whose versions are under its owner's own key.
    Moved,
    /// Leave history and who saved the item as they are.
    Untouched,
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = keykeeper_cipher_versions)]
#[diesel(primary_key(uuid))]
pub struct CipherVersion {
    pub uuid: String,
    pub cipher_uuid: CipherId,
    pub atype: i32,
    /// The item key, wrapped as it was, so the version opens even after the
    /// item gets a new one.
    pub akey: Option<String>,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<String>,
    pub data: String,
    pub password_history: Option<String>,
    pub reprompt: Option<i32>,
    pub size: i32,
    /// When this version was saved (the item's revision date then), and who
    /// saved it, when known.
    pub revision_date: NaiveDateTime,
    pub saved_by: Option<UserId>,
    /// When an edit replaced it, and who made that edit.
    pub replaced_at: NaiveDateTime,
    pub replaced_by: Option<UserId>,
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = keykeeper_cipher_saves)]
#[diesel(primary_key(cipher_uuid))]
struct CipherSave {
    cipher_uuid: CipherId,
    saved_by: Option<UserId>,
    saved_at: NaiveDateTime,
}

impl History {
    /// What `save` does to history, from the item as it's stored now.
    pub fn of(save: &ItemSave, cipher: &Cipher, moving_into_org: bool) -> Self {
        match save {
            ItemSave::Rotation => Self::Untouched,
            ItemSave::New => Self::Saved,
            ItemSave::Edit if moving_into_org => Self::Moved,
            ItemSave::Edit => Self::Replaced(Box::new(CipherVersion::of(cipher))),
        }
    }
}

impl CipherVersion {
    /// The item as it's stored now, to keep if an edit changes it.
    pub fn of(cipher: &Cipher) -> Self {
        Self {
            uuid: crate::util::get_uuid(),
            cipher_uuid: cipher.uuid.clone(),
            atype: cipher.atype,
            akey: cipher.key.clone(),
            name: cipher.name.clone(),
            notes: cipher.notes.clone(),
            fields: cipher.fields.clone(),
            data: cipher.data.clone(),
            password_history: cipher.password_history.clone(),
            reprompt: cipher.reprompt,
            size: i32::try_from(encrypted_size(cipher)).unwrap_or(i32::MAX),
            revision_date: cipher.updated_at,
            saved_by: None,
            replaced_at: Utc::now().naive_utc(),
            replaced_by: None,
        }
    }

    /// Whether the item's encrypted fields are still exactly these. Apps
    /// encrypt the whole item again on each save, so this says nothing about
    /// whether anything someone can see changed; apps compare decrypted
    /// versions for that.
    pub fn same_as(&self, cipher: &Cipher) -> bool {
        self.atype == cipher.atype
            && self.akey == cipher.key
            && self.name == cipher.name
            && self.notes == cipher.notes
            && self.fields == cipher.fields
            && self.data == cipher.data
            && self.password_history == cipher.password_history
            && self.reprompt == cipher.reprompt
    }

    /// The version as an item, for apps to read like any item: the item's id,
    /// owner, and creation date, with this version's encrypted fields.
    pub fn as_cipher(&self, current: &Cipher) -> Cipher {
        Cipher {
            uuid: current.uuid.clone(),
            created_at: current.created_at,
            updated_at: self.revision_date,
            user_uuid: current.user_uuid.clone(),
            organization_uuid: current.organization_uuid.clone(),
            key: self.akey.clone(),
            atype: self.atype,
            name: self.name.clone(),
            notes: self.notes.clone(),
            fields: self.fields.clone(),
            data: self.data.clone(),
            password_history: self.password_history.clone(),
            deleted_at: None,
            reprompt: self.reprompt,
        }
    }

    /// Saves an item and its history together, in one transaction: the
    /// version an edit replaces (then trims the item's history), or forgets
    /// the versions of an item moving into an organization, and records who
    /// saved the item. Upstream's `Cipher::save`, with history.
    pub async fn save_item(cipher: &mut Cipher, history: History, by: &UserId, conn: &DbConn) -> EmptyResult {
        cipher.update_users_revision(conn).await;
        cipher.updated_at = Utc::now().naive_utc();
        let by = by.clone();
        conn.run(move |conn| {
            conn.transaction(|conn| {
                let mut record_saver = true;
                match history {
                    History::Replaced(mut version) if !version.same_as(cipher) => {
                        let saved_by = keykeeper_cipher_saves::table
                            .filter(keykeeper_cipher_saves::cipher_uuid.eq(&cipher.uuid))
                            .select(keykeeper_cipher_saves::saved_by)
                            .first::<Option<UserId>>(conn)
                            .optional()?;
                        version.saved_by = saved_by.flatten();
                        version.replaced_by = Some(by.clone());
                        version.replaced_at = cipher.updated_at;
                        if usize::try_from(version.size).unwrap_or(usize::MAX) <= MAX_ITEM_BYTES
                            && !org_history_full(cipher, version.size, conn)?
                        {
                            diesel::insert_into(keykeeper_cipher_versions::table).values(&*version).execute(conn)?;
                            trim(&cipher.uuid, conn)?;
                        }
                    }
                    // The same encrypted fields again: its author doesn't change.
                    History::Replaced(_) | History::Untouched => record_saver = false,
                    History::Moved => {
                        diesel::delete(
                            keykeeper_cipher_versions::table
                                .filter(keykeeper_cipher_versions::cipher_uuid.eq(&cipher.uuid)),
                        )
                        .execute(conn)?;
                    }
                    History::Saved => {}
                }

                // Upstream's save, which inserts the item or replaces it.
                let updated = diesel::update(ciphers::table.filter(ciphers::uuid.eq(&cipher.uuid)))
                    .set(&*cipher)
                    .execute(conn)?;
                if updated == 0 {
                    diesel::insert_into(ciphers::table).values(&*cipher).execute(conn)?;
                }

                if record_saver {
                    let save = CipherSave {
                        cipher_uuid: cipher.uuid.clone(),
                        saved_by: Some(by),
                        saved_at: cipher.updated_at,
                    };
                    let updated = diesel::update(
                        keykeeper_cipher_saves::table.filter(keykeeper_cipher_saves::cipher_uuid.eq(&save.cipher_uuid)),
                    )
                    .set((
                        keykeeper_cipher_saves::saved_by.eq(&save.saved_by),
                        keykeeper_cipher_saves::saved_at.eq(save.saved_at),
                    ))
                    .execute(conn)?;
                    if updated == 0 {
                        diesel::insert_into(keykeeper_cipher_saves::table).values(&save).execute(conn)?;
                    }
                }
                Ok::<_, diesel::result::Error>(())
            })
            .map_res("Error saving cipher")
        })
        .await
    }

    /// Who saved the item as it is now, when known.
    pub async fn saved_by(cipher: &CipherId, conn: &DbConn) -> Option<UserId> {
        let cipher = cipher.clone();
        conn.run(move |conn| {
            keykeeper_cipher_saves::table
                .filter(keykeeper_cipher_saves::cipher_uuid.eq(cipher))
                .select(keykeeper_cipher_saves::saved_by)
                .first::<Option<UserId>>(conn)
                .ok()
                .flatten()
        })
        .await
    }

    /// An item's past versions, newest first.
    pub async fn find_by_cipher(cipher: &CipherId, conn: &DbConn) -> Result<Vec<Self>, crate::error::Error> {
        let cipher = cipher.clone();
        conn.run(move |conn| {
            keykeeper_cipher_versions::table
                .filter(keykeeper_cipher_versions::cipher_uuid.eq(cipher))
                .order((keykeeper_cipher_versions::replaced_at.desc(), keykeeper_cipher_versions::revision_date.desc()))
                .load::<Self>(conn)
                .map_res("Error reading the item's earlier versions")
        })
        .await
    }

    /// Forgets an item's past versions: someone cleared its history.
    pub async fn delete_all_by_cipher(cipher: &CipherId, conn: &DbConn) -> EmptyResult {
        let cipher = cipher.clone();
        conn.run(move |conn| {
            diesel::delete(keykeeper_cipher_versions::table.filter(keykeeper_cipher_versions::cipher_uuid.eq(cipher)))
                .execute(conn)
                .map_res("Error forgetting the item's earlier versions")
        })
        .await
    }

    /// Forgets one of an item's past versions. False when the item has no
    /// such version.
    pub async fn delete_one(cipher: &CipherId, version: &str, conn: &DbConn) -> Result<bool, crate::error::Error> {
        let cipher = cipher.clone();
        let version = version.to_owned();
        conn.run(move |conn| {
            diesel::delete(
                keykeeper_cipher_versions::table
                    .filter(keykeeper_cipher_versions::cipher_uuid.eq(cipher))
                    .filter(keykeeper_cipher_versions::uuid.eq(version)),
            )
            .execute(conn)
            .map(|deleted| deleted > 0)
            .map_res("Error forgetting the item's earlier version")
        })
        .await
    }

    /// Forgets everything history keeps about an item that's being deleted
    /// for good. The database's cascade does too; this doesn't rely on it.
    pub async fn delete_item(cipher: &CipherId, conn: &DbConn) -> EmptyResult {
        let cipher = cipher.clone();
        conn.run(move |conn| {
            conn.transaction(|conn| {
                diesel::delete(
                    keykeeper_cipher_versions::table.filter(keykeeper_cipher_versions::cipher_uuid.eq(&cipher)),
                )
                .execute(conn)?;
                diesel::delete(keykeeper_cipher_saves::table.filter(keykeeper_cipher_saves::cipher_uuid.eq(&cipher)))
                    .execute(conn)?;
                Ok::<_, diesel::result::Error>(())
            })
            .map_res("Error forgetting the item's history")
        })
        .await
    }

    /// Forgets the past versions of someone's own items: their account's key
    /// changed, so nothing could open them anymore. Organizations' items keep
    /// theirs.
    pub async fn delete_all_by_owner(user: &UserId, conn: &DbConn) -> EmptyResult {
        let user = user.clone();
        conn.run(move |conn| {
            conn.transaction(|conn| {
                let owned: Vec<CipherId> = ciphers::table
                    .filter(ciphers::user_uuid.eq(&user))
                    .filter(ciphers::organization_uuid.is_null())
                    .select(ciphers::uuid)
                    .load(conn)?;
                for chunk in owned.chunks(500) {
                    diesel::delete(
                        keykeeper_cipher_versions::table.filter(keykeeper_cipher_versions::cipher_uuid.eq_any(chunk)),
                    )
                    .execute(conn)?;
                }
                Ok::<_, diesel::result::Error>(())
            })
            .map_res("Error forgetting earlier versions of the account's items")
        })
        .await
    }
}

/// Whether keeping a version of this size would take an organization's item
/// history past ORG_ITEM_HISTORY_LIMIT. Versions of ALWAYS_KEPT_BYTES or less
/// are kept anyway, and personal items have no such limit.
fn org_history_full(
    cipher: &Cipher,
    size: i32,
    conn: &mut crate::db::DbConnInner,
) -> Result<bool, diesel::result::Error> {
    let Some(org) = &cipher.organization_uuid else {
        return Ok(false);
    };
    if size <= ALWAYS_KEPT_BYTES {
        return Ok(false);
    }
    let limit = crate::CONFIG.org_item_history_limit().saturating_mul(1024);
    // Only big saves get here, so this rarely runs.
    let items: Vec<CipherId> =
        ciphers::table.filter(ciphers::organization_uuid.eq(org)).select(ciphers::uuid).load(conn)?;
    let mut used = 0i64;
    for chunk in items.chunks(500) {
        let sum: Option<i64> = keykeeper_cipher_versions::table
            .filter(keykeeper_cipher_versions::cipher_uuid.eq_any(chunk))
            .select(diesel::dsl::sum(keykeeper_cipher_versions::size))
            .first(conn)?;
        used = used.saturating_add(sum.unwrap_or(0));
    }
    let full = used.saturating_add(i64::from(size)) > limit;
    if full {
        warn!(
            "Item history of organization {org} is full (ORG_ITEM_HISTORY_LIMIT): an edit of item {} kept no version of {size} bytes",
            cipher.uuid
        );
    }
    Ok(full)
}

/// Forgets the versions an item no longer keeps (see `to_forget`).
fn trim(cipher: &CipherId, conn: &mut crate::db::DbConnInner) -> Result<(), diesel::result::Error> {
    let kept: Vec<(String, NaiveDateTime, i32)> = keykeeper_cipher_versions::table
        .filter(keykeeper_cipher_versions::cipher_uuid.eq(cipher))
        .order((keykeeper_cipher_versions::replaced_at.desc(), keykeeper_cipher_versions::revision_date.desc()))
        .select((
            keykeeper_cipher_versions::uuid,
            keykeeper_cipher_versions::replaced_at,
            keykeeper_cipher_versions::size,
        ))
        .load(conn)?;
    let forget = to_forget(&kept);
    for chunk in forget.chunks(500) {
        diesel::delete(keykeeper_cipher_versions::table.filter(keykeeper_cipher_versions::uuid.eq_any(chunk)))
            .execute(conn)?;
    }
    Ok(())
}

/// Of an item's versions newest first (id, when replaced, size), the ones to
/// forget. An item keeps two kinds of versions, each within a budget of its
/// own: its newest KEEP_NEWEST versions, every one, within MAX_HISTORY_BYTES;
/// and before those, one a day (UTC), the first that day's edits replaced, so
/// the item as it was before them, at most MAX_VERSIONS in all and within
/// MAX_HISTORY_BYTES of their own, newest first. A burst of saves, however
/// many and however big, can push out only the newest, never the days before
/// them: those make room only for later days.
fn to_forget(newest_first: &[(String, NaiveDateTime, i32)]) -> Vec<String> {
    let newest: Vec<usize> = (0..newest_first.len().min(KEEP_NEWEST)).collect();
    // Newest first, so the last one seen of each day is its first replaced.
    let mut first_of_day: HashMap<NaiveDate, usize> = HashMap::new();
    for (i, (_, replaced_at, _)) in newest_first.iter().enumerate().skip(KEEP_NEWEST) {
        first_of_day.insert(replaced_at.date(), i);
    }
    let mut days: Vec<usize> = first_of_day.into_values().collect();
    days.sort_unstable();

    let mut keep = vec![false; newest_first.len()];
    for (kind, most) in [(newest, KEEP_NEWEST), (days, MAX_VERSIONS - KEEP_NEWEST)] {
        let mut bytes = 0i64;
        for (count, i) in kind.into_iter().enumerate() {
            bytes += i64::from(newest_first[i].2);
            if count >= most || bytes > MAX_HISTORY_BYTES {
                break;
            }
            keep[i] = true;
        }
    }
    newest_first.iter().zip(keep).filter(|(_, k)| !k).map(|((id, _, _), _)| id.clone()).collect()
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;

    use super::*;

    fn cipher() -> Cipher {
        let mut cipher = Cipher::new(1, "2.bmFtZQ==|bmFtZQ==|bWFj".to_owned());
        cipher.user_uuid = Some(UserId::from("owner".to_owned()));
        cipher.key = Some("2.a2V5|a2V5|bWFj".to_owned());
        cipher.data = r#"{"password":"2.cHc=|cHc=|bWFj"}"#.to_owned();
        cipher
    }

    #[test]
    fn a_version_is_the_item_as_stored() {
        let mut item = cipher();
        let before = CipherVersion::of(&item);
        assert!(before.same_as(&item));
        assert_eq!(before.revision_date, item.updated_at);
        assert_eq!(usize::try_from(before.size).unwrap(), encrypted_size(&item));

        // Any encrypted field that differs is a new version, the item key too.
        item.key = Some("2.bmV3|bmV3|bWFj".to_owned());
        assert!(!before.same_as(&item));
        let mut item = cipher();
        item.data = r#"{"password":"2.bmV3|bmV3|bWFj"}"#.to_owned();
        assert!(!before.same_as(&item));
        let mut item = cipher();
        item.reprompt = Some(1);
        assert!(!before.same_as(&item));

        // Read back as an item: the item's id and owner, the version's fields.
        let read = before.as_cipher(&item);
        assert_eq!(read.uuid, item.uuid);
        assert_eq!(read.user_uuid, item.user_uuid);
        assert_eq!(read.key, Some("2.a2V5|a2V5|bWFj".to_owned()));
        assert_eq!(read.reprompt, None);
        assert_eq!(read.updated_at, before.revision_date);
    }

    #[test]
    fn what_a_save_does_to_history() {
        let item = cipher();
        assert!(matches!(History::of(&ItemSave::New, &item, false), History::Saved));
        assert!(matches!(History::of(&ItemSave::Rotation, &item, false), History::Untouched));
        assert!(matches!(History::of(&ItemSave::Edit, &item, true), History::Moved));
        assert!(matches!(History::of(&ItemSave::Edit, &item, false), History::Replaced(_)));
    }

    #[test]
    fn an_items_size_is_its_encrypted_fields() {
        let mut item = cipher();
        let base = encrypted_size(&item);
        let notes = "2.bm90ZQ==|bm90ZQ==|bWFj";
        item.notes = Some(notes.to_owned());
        assert_eq!(encrypted_size(&item), base + notes.len());
    }

    fn at(day: u32, minute: i64) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 10, day).unwrap().and_hms_opt(9, 0, 0).unwrap() + TimeDelta::minutes(minute)
    }

    /// Newest first: (id, replaced at, size).
    fn versions(list: &[(&str, NaiveDateTime, i32)]) -> Vec<(String, NaiveDateTime, i32)> {
        list.iter().map(|(id, t, s)| ((*id).to_owned(), *t, *s)).collect()
    }

    #[test]
    fn a_burst_of_saves_keeps_the_newest_and_the_item_before_it() {
        // 60 saves in an hour on the 23rd, after edits on two earlier days.
        let mut list: Vec<(String, NaiveDateTime, i32)> =
            (0..60).rev().map(|m| (format!("burst-{m}"), at(23, m), 1000)).collect();
        list.extend(versions(&[
            ("21-late", at(21, 30), 1000),
            ("21-early", at(21, 0), 1000),
            ("20-only", at(20, 0), 1000),
        ]));
        let forget = to_forget(&list);
        let kept: Vec<&str> =
            list.iter().map(|(id, _, _)| id.as_str()).filter(|id| !forget.iter().any(|f| f == id)).collect();
        // The newest 20 of the burst, its first (the item before it), and the
        // first of each earlier day.
        let mut expected: Vec<String> = (40..60).rev().map(|m| format!("burst-{m}")).collect();
        expected.extend(["burst-0", "21-early", "20-only"].map(String::from));
        assert_eq!(kept, expected);
    }

    #[test]
    fn big_saves_cant_push_out_the_days_before_them() {
        // An editor who can't delete or see history saves a big item over
        // and over: the newest versions fill their budget, but the item as it
        // was on each earlier day stays, and so does the item before the burst.
        let big = i32::try_from(MAX_ITEM_BYTES).unwrap();
        let mut list: Vec<(String, NaiveDateTime, i32)> =
            (0..40).rev().map(|m| (format!("big-{m}"), at(23, m), big)).collect();
        list.extend(versions(&[("before", at(23, -5), 900), ("21", at(21, 0), 900), ("20", at(20, 0), 900)]));
        let forget = to_forget(&list);
        let kept: Vec<&str> =
            list.iter().map(|(id, _, _)| id.as_str()).filter(|id| !forget.iter().any(|f| f == id)).collect();
        // The newest 8 big ones fit their 4 MB; the first of the 23rd (the
        // item before the burst) and each earlier day are kept apart.
        let mut expected: Vec<String> = (32..40).rev().map(|m| format!("big-{m}")).collect();
        expected.extend(["before", "21", "20"].map(String::from));
        assert_eq!(kept, expected);

        // Big ones only make room for later days, one a day.
        let mut list: Vec<(String, NaiveDateTime, i32)> =
            (0..20).map(|m| (format!("new-{m}"), at(28, 0) - TimeDelta::minutes(m), 100)).collect();
        list.extend((0..10).map(|d| (format!("day-{d}"), at(27, 0) - TimeDelta::days(d), big)));
        let forget = to_forget(&list);
        assert_eq!(forget, (8..10).map(|d| format!("day-{d}")).collect::<Vec<_>>());
    }

    #[test]
    fn an_item_keeps_at_most_max_versions_and_bytes() {
        // A version a day for 150 days: the newest MAX_VERSIONS stay.
        let list: Vec<(String, NaiveDateTime, i32)> =
            (0..150).map(|d| (format!("day-{d}"), at(23, 0) - TimeDelta::days(d), 1000)).collect();
        let forget = to_forget(&list);
        assert_eq!(forget.len(), 150 - MAX_VERSIONS);
        assert_eq!(forget.first().map(String::as_str), Some("day-100"));

        // Large versions: only the newest that fit the budget.
        let big = i32::try_from(MAX_ITEM_BYTES).unwrap();
        let list: Vec<(String, NaiveDateTime, i32)> =
            (0..12).map(|m| (format!("big-{m}"), at(23, 0) - TimeDelta::minutes(m), big)).collect();
        let forget = to_forget(&list);
        assert_eq!(forget.len(), 12 - 8);
        assert_eq!(forget.first().map(String::as_str), Some("big-8"));

        assert!(to_forget(&[]).is_empty());
    }
}

// Keykeeper: every item's past versions. Before a save replaces an item's
// contents, the server keeps the item as it was stored: its encrypted fields
// exactly as they were, which it can't read. Apps decrypt a version like the
// item itself, and restore one by saving it as a normal edit. See DESIGN.md,
// "Item history".

use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    db::{DbConn, keykeeper_schema::keykeeper_cipher_versions, schema::ciphers},
    error::MapResult,
};

use super::{Cipher, CipherId, UserId};

/// How many past versions an item keeps; the oldest goes first. Even a long
/// note's 50 versions stay well under 1 MB, and 50 saves is years of edits
/// for most items. See DESIGN.md, "Item history".
pub const MAX_VERSIONS: usize = 50;

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
    /// When this version was saved: the item's revision date then.
    pub revision_date: NaiveDateTime,
    /// When a save replaced it, and who saved that.
    pub replaced_at: NaiveDateTime,
    pub replaced_by: Option<UserId>,
}

impl CipherVersion {
    /// The item as it's stored now, to keep if a save by `by` changes it.
    pub fn of(cipher: &Cipher, by: &UserId) -> Self {
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
            revision_date: cipher.updated_at,
            replaced_at: Utc::now().naive_utc(),
            replaced_by: Some(by.clone()),
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

    /// Keeps this version, and forgets the item's oldest beyond MAX_VERSIONS.
    pub async fn keep(self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            conn.transaction(|conn| {
                diesel::insert_into(keykeeper_cipher_versions::table).values(&self).execute(conn)?;
                let kept: Vec<String> = keykeeper_cipher_versions::table
                    .filter(keykeeper_cipher_versions::cipher_uuid.eq(&self.cipher_uuid))
                    .order((
                        keykeeper_cipher_versions::replaced_at.desc(),
                        keykeeper_cipher_versions::revision_date.desc(),
                    ))
                    .select(keykeeper_cipher_versions::uuid)
                    .load(conn)?;
                let oldest = beyond_limit(&kept);
                if !oldest.is_empty() {
                    diesel::delete(
                        keykeeper_cipher_versions::table.filter(keykeeper_cipher_versions::uuid.eq_any(oldest)),
                    )
                    .execute(conn)?;
                }
                Ok::<_, diesel::result::Error>(())
            })
            .map_res("Error keeping the item's earlier version")
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

    /// Forgets an item's past versions, as when it moves into an organization:
    /// they're encrypted with its owner's own key.
    pub async fn delete_all_by_cipher(cipher: &CipherId, conn: &DbConn) -> EmptyResult {
        let cipher = cipher.clone();
        conn.run(move |conn| {
            diesel::delete(keykeeper_cipher_versions::table.filter(keykeeper_cipher_versions::cipher_uuid.eq(cipher)))
                .execute(conn)
                .map_res("Error forgetting the item's earlier versions")
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
                let owned: Vec<CipherId> =
                    ciphers::table.filter(ciphers::user_uuid.eq(&user)).select(ciphers::uuid).load(conn)?;
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

    /// Who saved each version, of an item's versions newest first: whoever
    /// replaced the version before it. Nobody is recorded for the oldest,
    /// except that only its owner edits a personal item (moving it into an
    /// organization forgets its versions).
    pub fn saved_by<'a>(newest_first: &'a [Self], owner: Option<&'a UserId>) -> Vec<Option<&'a UserId>> {
        (0..newest_first.len())
            .map(|i| match newest_first.get(i + 1) {
                Some(older) => older.replaced_by.as_ref(),
                None => owner,
            })
            .collect()
    }
}

/// The versions to forget, of an item's versions newest first.
fn beyond_limit(newest_first: &[String]) -> &[String] {
    newest_first.get(MAX_VERSIONS..).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> Cipher {
        let mut cipher = Cipher::new(1, "2.bmFtZQ==|bmFtZQ==|bWFj".to_owned());
        cipher.user_uuid = Some(UserId::from("owner".to_owned()));
        cipher.key = Some("2.a2V5|a2V5|bWFj".to_owned());
        cipher.data = r#"{"password":"2.cHc=|cHc=|bWFj"}"#.to_owned();
        cipher
    }

    fn version(replaced_by: &str) -> CipherVersion {
        CipherVersion::of(&cipher(), &UserId::from(replaced_by.to_owned()))
    }

    #[test]
    fn a_version_is_the_item_as_stored() {
        let mut item = cipher();
        let before = CipherVersion::of(&item, &UserId::from("editor".to_owned()));
        assert!(before.same_as(&item));
        assert_eq!(before.revision_date, item.updated_at);
        assert_eq!(before.replaced_by.as_deref(), Some("editor"));

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
    fn only_the_newest_versions_are_kept() {
        let ids: Vec<String> = (0..MAX_VERSIONS + 2).map(|i| format!("v{i}")).collect();
        assert_eq!(beyond_limit(&ids), &ids[MAX_VERSIONS..]);
        assert_eq!(beyond_limit(&ids).len(), 2);
        assert!(beyond_limit(&ids[..MAX_VERSIONS]).is_empty());
        assert!(beyond_limit(&[]).is_empty());
    }

    #[test]
    fn each_version_was_saved_by_whoever_replaced_the_one_before() {
        let versions = [version("carol"), version("ben"), version("ana")];
        let names = |owner| -> Vec<Option<String>> {
            CipherVersion::saved_by(&versions, owner).into_iter().map(|u| u.map(|u| u.to_string())).collect()
        };
        assert_eq!(names(None), vec![Some("ben".to_owned()), Some("ana".to_owned()), None]);
        let owner = UserId::from("owner".to_owned());
        assert_eq!(names(Some(&owner)), vec![Some("ben".to_owned()), Some("ana".to_owned()), Some("owner".to_owned())]);
        assert!(CipherVersion::saved_by(&[], None).is_empty());
    }
}

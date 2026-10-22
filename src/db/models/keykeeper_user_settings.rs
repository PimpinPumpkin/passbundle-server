// Keykeeper: settings that follow someone to each of their devices, such as
// the password generator's. Apps encrypt them with the account's key, so the
// server keeps a ciphertext it can't read and only checks its shape. See
// DESIGN.md, "Generator settings".

use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    db::{DbConn, keykeeper_schema::keykeeper_user_settings},
    error::MapResult,
};

use super::UserId;

/// The longest encrypted settings the server keeps: generator settings are
/// well under 2 KB encrypted, with room for more settings later.
pub const MAX_SETTINGS: usize = 16 * 1024;

/// Encrypted with a symmetric key as upstream does: `2.<iv>|<data>|<mac>`.
pub fn valid_settings(data: &str) -> bool {
    let Some(parts) = data.strip_prefix("2.") else {
        return false;
    };
    let parts: Vec<&str> = parts.split('|').collect();
    data.len() <= MAX_SETTINGS
        && parts.len() == 3
        && parts.iter().all(|p| !p.is_empty() && data_encoding::BASE64.decode(p.as_bytes()).is_ok())
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = keykeeper_user_settings)]
#[diesel(primary_key(user_uuid))]
pub struct UserSettings {
    pub user_uuid: UserId,
    pub data: String,
    pub revision_date: NaiveDateTime,
}

impl UserSettings {
    /// Someone's settings, or none saved. A database error is an error, not
    /// "none": an app given none saves its own over the account's.
    pub async fn find(user: &UserId, conn: &DbConn) -> Result<Option<Self>, crate::error::Error> {
        let user = user.clone();
        conn.run(move |conn| {
            keykeeper_user_settings::table
                .filter(keykeeper_user_settings::user_uuid.eq(user))
                .first::<Self>(conn)
                .optional()
                .map_res("Error reading settings")
        })
        .await
    }

    /// Replaces someone's settings with these, already checked.
    pub async fn save(user: &UserId, data: &str, conn: &DbConn) -> Result<Self, crate::error::Error> {
        let row = Self {
            user_uuid: user.clone(),
            data: data.to_owned(),
            revision_date: Utc::now().naive_utc(),
        };
        conn.run(move |conn| {
            conn.transaction(|conn| {
                let updated = diesel::update(
                    keykeeper_user_settings::table.filter(keykeeper_user_settings::user_uuid.eq(&row.user_uuid)),
                )
                .set((
                    keykeeper_user_settings::data.eq(&row.data),
                    keykeeper_user_settings::revision_date.eq(row.revision_date),
                ))
                .execute(conn)?;
                if updated == 0 {
                    diesel::insert_into(keykeeper_user_settings::table).values(&row).execute(conn)?;
                }
                Ok::<_, diesel::result::Error>(())
            })
            .map_res("Error saving settings")?;
            Ok(row)
        })
        .await
    }

    /// Forgets someone's settings: their account's key changed, so no app of
    /// theirs can read them anymore. The next app to save writes them anew.
    pub async fn delete_by_user(user: &UserId, conn: &DbConn) -> EmptyResult {
        let user = user.clone();
        conn.run(move |conn| {
            diesel::delete(keykeeper_user_settings::table.filter(keykeeper_user_settings::user_uuid.eq(user)))
                .execute(conn)
                .map_res("Error forgetting settings")
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_encrypted_settings_are_kept() {
        assert!(valid_settings("2.UFFSU1RVVldYWVpbXF1eXw==|eyJsZW5ndGgiOjIwfQ==|bWFj"));
        assert!(!valid_settings(r#"{"length":20}"#));
        assert!(!valid_settings("2.only|two"));
        assert!(!valid_settings("2.UFFSU1RVVldYWVpbXF1eXw==||bWFj"));
        assert!(!valid_settings("2.not base64!|YQ==|YQ=="));
        assert!(!valid_settings(&format!("2.YQ==|{}|YQ==", "A".repeat(MAX_SETTINGS))));
    }
}

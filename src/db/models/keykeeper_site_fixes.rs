// Keykeeper: site fixes people chose to share from the fill picker, problem
// reports about sites, and MSPs' site rules. A fix says how to recognize a
// field on a site and which kind of value goes there (username, password,
// one-time code, or never), never a value. No stored row says which account
// sent it: a person is counted once per fix by a keyed hash only this server
// can make, with a key derived from the server's RSA key, never kept in the
// database, so a copy of the database can't tell who sent what. The tables
// are bounded: so many problem reports at most, and fixes nobody confirmed
// are forgotten. See DESIGN.md, "Site fixes (opt-in)".

use std::sync::OnceLock;

use chrono::{NaiveDateTime, TimeDelta, Utc};
use diesel::prelude::*;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        keykeeper_schema::{msp_site_fix_reports, msp_site_rules, site_fix_reporters, site_fixes, site_problems},
    },
    error::MapResult,
    util::get_uuid,
};

use super::{MspId, UserId};

/// Which kind of value goes in a field. Custom fields are never shared: their
/// names can say something about the person.
pub const FILLS: [&str; 4] = ["username", "password", "totp", "never"];

/// How a fix recognizes a field: what a fill rule records. Missing parts are
/// empty strings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct FixField {
    pub id: String,
    pub name: String,
    pub label: String,
}

/// A fix as an app sends it, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fix {
    pub host: String,
    pub field: FixField,
    pub fill: String,
}

const MAX_TEXT: usize = 200;

/// A site's host as the extension records it (a URL's host, with any port),
/// lowercased, or an error that names what's wrong.
pub fn checked_host(host: &str) -> Result<String, String> {
    let host = host.trim().to_lowercase();
    let ok = !host.is_empty()
        && host.len() <= 253
        && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    if ok {
        Ok(host)
    } else {
        Err("That isn't a website's host, like example.com".into())
    }
}

/// A short piece of page text: a field's id, name, label, type, or hint.
fn checked_text(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.chars().count() > MAX_TEXT || text.chars().any(char::is_control) {
        return Err(format!("A field's id, name, or label is at most {MAX_TEXT} characters"));
    }
    Ok(text.to_owned())
}

impl Fix {
    pub fn checked(host: &str, field: &FixField, fill: &str) -> Result<Self, String> {
        let field = FixField {
            id: checked_text(&field.id)?,
            name: checked_text(&field.name)?,
            label: checked_text(&field.label)?.to_lowercase(),
        };
        if field.id.is_empty() && field.name.is_empty() && field.label.is_empty() {
            return Err("A fix needs the field's id, name, or label".into());
        }
        if !FILLS.contains(&fill) {
            return Err("A fix fills the username, the password, the one-time code, or nothing".into());
        }
        Ok(Self {
            host: checked_host(host)?,
            field,
            fill: fill.to_owned(),
        })
    }

    pub fn to_json(&self) -> Value {
        json!({ "host": self.host, "field": self.field, "fill": self.fill })
    }
}

/// The key for reporters' hashes: HMAC-SHA256 keyed with the server's
/// private RSA key (PKCS#1 DER) over this label, as event streaming derives
/// its key over its own. Test vectors: docs/vectors/server-derived-keys-v1.json
/// in the meta repo (a copy is in vectors/ here).
const REPORTER_LABEL: &[u8] = b"passbundle site fix reporters v1";
static REPORTER_KEY: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();

/// Derives and keeps the reporters' key. Called once at startup, by
/// auth::initialize_keys.
pub fn init_reporter_key(rsa_private_der: &[u8]) {
    // A second call (tests) keeps the first key.
    drop(REPORTER_KEY.set(crate::keykeeper_streaming::secrets::derive_key_for(REPORTER_LABEL, rsa_private_der)));
}

fn reporter_key() -> Result<&'static [u8; 32], crate::error::Error> {
    let Some(key) = REPORTER_KEY.get() else {
        err!("The server's keys aren't loaded yet")
    };
    Ok(key)
}

/// A person, for one fix: the same person sending it twice gives the same
/// hash, and nothing links it to them or to their other fixes without the key.
fn reporter_hash(key: &[u8; 32], user: &UserId, fix_uuid: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let tag = ring::hmac::sign(&key, format!("{user}\u{0}{fix_uuid}").as_bytes());
    data_encoding::BASE64.encode(tag.as_ref())
}

/// Fixes nobody else confirmed are forgotten after this long without anyone
/// sending them again.
const UNCONFIRMED_DAYS: i64 = 180;
/// The most fixes kept that don't apply yet; past it, the ones sent longest
/// ago go first.
const MAX_UNCONFIRMED: i64 = 20_000;
/// The most problem reports kept; past it, the oldest go first.
pub const MAX_PROBLEMS: i64 = 5_000;
/// Problem reports are kept this long.
const PROBLEM_DAYS: i64 = 90;

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = site_fixes)]
#[diesel(primary_key(uuid))]
pub struct SiteFix {
    pub uuid: String,
    pub host: String,
    pub field_id: String,
    pub field_name: String,
    pub field_label: String,
    pub fill: String,
    pub reporters: i32,
    pub first_seen: NaiveDateTime,
    pub last_seen: NaiveDateTime,
    /// When the server's operator approved it, where SITE_FIXES_NEED_APPROVAL
    /// asks for that.
    pub approved_at: Option<NaiveDateTime>,
}

/// Whether a fix applies to everyone: enough different people sent it, and
/// the server's operator approved it where they must.
pub fn fix_applies(reporters: i32, approved: bool) -> bool {
    let threshold = i32::try_from(crate::CONFIG.site_fix_reporters()).unwrap_or(i32::MAX);
    reporters >= threshold && (approved || !crate::CONFIG.site_fixes_need_approval())
}

impl SiteFix {
    fn fix(&self) -> Fix {
        Fix {
            host: self.host.clone(),
            field: FixField {
                id: self.field_id.clone(),
                name: self.field_name.clone(),
                label: self.field_label.clone(),
            },
            fill: self.fill.clone(),
        }
    }

    /// Records that someone sent a fix, counting each person once. Returns
    /// whether it applies to everyone now.
    pub async fn record(fix: &Fix, user: &UserId, conn: &DbConn) -> Result<bool, crate::error::Error> {
        let key = reporter_key()?;
        let fix = fix.clone();
        let user = user.clone();
        conn.run(move |conn| {
            conn.transaction(|conn| {
                let now = Utc::now().naive_utc();
                let found = site_fixes::table
                    .filter(site_fixes::host.eq(&fix.host))
                    .filter(site_fixes::field_id.eq(&fix.field.id))
                    .filter(site_fixes::field_name.eq(&fix.field.name))
                    .filter(site_fixes::field_label.eq(&fix.field.label))
                    .filter(site_fixes::fill.eq(&fix.fill))
                    .first::<SiteFix>(conn)
                    .optional()?;
                let uuid = if let Some(row) = found {
                    row.uuid
                } else {
                    let row = SiteFix {
                        uuid: get_uuid(),
                        host: fix.host.clone(),
                        field_id: fix.field.id.clone(),
                        field_name: fix.field.name.clone(),
                        field_label: fix.field.label.clone(),
                        fill: fix.fill.clone(),
                        reporters: 0,
                        first_seen: now,
                        last_seen: now,
                        approved_at: None,
                    };
                    diesel::insert_into(site_fixes::table).values(&row).execute(conn)?;
                    forget_unconfirmed(conn)?;
                    row.uuid
                };
                let hash = reporter_hash(key, &user, &uuid);
                let seen = site_fix_reporters::table
                    .filter(site_fix_reporters::fix_uuid.eq(&uuid))
                    .filter(site_fix_reporters::reporter_hash.eq(&hash))
                    .count()
                    .get_result::<i64>(conn)?;
                if seen == 0 {
                    diesel::insert_into(site_fix_reporters::table)
                        .values((site_fix_reporters::fix_uuid.eq(&uuid), site_fix_reporters::reporter_hash.eq(&hash)))
                        .execute(conn)?;
                    diesel::update(site_fixes::table.filter(site_fixes::uuid.eq(&uuid)))
                        .set((site_fixes::reporters.eq(site_fixes::reporters + 1), site_fixes::last_seen.eq(now)))
                        .execute(conn)?;
                }
                site_fixes::table
                    .filter(site_fixes::uuid.eq(&uuid))
                    .select((site_fixes::reporters, site_fixes::approved_at))
                    .first::<(i32, Option<NaiveDateTime>)>(conn)
            })
            .map(|(reporters, approved_at)| fix_applies(reporters, approved_at.is_some()))
            .map_res("Error recording a site fix")
        })
        .await
    }

    /// The fixes that apply to everyone, for every app on the server.
    pub async fn confirmed(conn: &DbConn) -> Vec<Fix> {
        let threshold = i32::try_from(crate::CONFIG.site_fix_reporters()).unwrap_or(i32::MAX);
        conn.run(move |conn| {
            site_fixes::table
                .filter(site_fixes::reporters.ge(threshold))
                .order(site_fixes::host.asc())
                .load::<SiteFix>(conn)
                .unwrap_or_default()
        })
        .await
        .iter()
        .filter(|row| fix_applies(row.reporters, row.approved_at.is_some()))
        .map(SiteFix::fix)
        .collect()
    }

    /// The server's operator approves a fix, or takes the approval back.
    /// False when there's no such fix.
    pub async fn set_approved(uuid: &str, approved: bool, conn: &DbConn) -> Result<bool, crate::error::Error> {
        let uuid = uuid.to_owned();
        let at = approved.then(|| Utc::now().naive_utc());
        conn.run(move |conn| {
            diesel::update(site_fixes::table.filter(site_fixes::uuid.eq(uuid)))
                .set(site_fixes::approved_at.eq(at))
                .execute(conn)
                .map(|n| n > 0)
                .map_res("Error approving a site fix")
        })
        .await
    }

    /// Every fix with its count, newest first, for the server's admin page.
    pub async fn all(conn: &DbConn) -> Vec<Value> {
        conn.run(move |conn| {
            site_fixes::table.order(site_fixes::last_seen.desc()).limit(500).load::<SiteFix>(conn).unwrap_or_default()
        })
        .await
        .iter()
        .map(|row| {
            let mut json = row.fix().to_json();
            json["id"] = json!(row.uuid);
            json["reporters"] = json!(row.reporters);
            json["lastSeen"] = json!(crate::util::format_date(&row.last_seen));
            json["approved"] = json!(row.approved_at.is_some());
            json["applies"] = json!(fix_applies(row.reporters, row.approved_at.is_some()));
            json
        })
        .collect()
    }
}

/// Forgets fixes that don't apply yet and nobody sent for UNCONFIRMED_DAYS,
/// and past MAX_UNCONFIRMED of them, the ones sent longest ago, with their
/// reporters' hashes. A fix the operator approved stays.
fn forget_unconfirmed(conn: &mut crate::db::DbConnInner) -> Result<(), diesel::result::Error> {
    let threshold = i32::try_from(crate::CONFIG.site_fix_reporters()).unwrap_or(i32::MAX);
    let unconfirmed =
        || site_fixes::table.filter(site_fixes::reporters.lt(threshold)).filter(site_fixes::approved_at.is_null());
    let since = Utc::now().naive_utc() - TimeDelta::days(UNCONFIRMED_DAYS);
    let mut forget: Vec<String> =
        unconfirmed().filter(site_fixes::last_seen.lt(since)).select(site_fixes::uuid).load(conn)?;
    let count: i64 = unconfirmed().count().get_result(conn)?;
    let over = count - i64::try_from(forget.len()).unwrap_or(0) - MAX_UNCONFIRMED;
    if over > 0 {
        forget.extend(
            unconfirmed()
                .filter(site_fixes::last_seen.ge(since))
                .order(site_fixes::last_seen.asc())
                .limit(over)
                .select(site_fixes::uuid)
                .load::<String>(conn)?,
        );
    }
    for chunk in forget.chunks(500) {
        diesel::delete(site_fix_reporters::table.filter(site_fix_reporters::fix_uuid.eq_any(chunk))).execute(conn)?;
        diesel::delete(site_fixes::table.filter(site_fixes::uuid.eq_any(chunk))).execute(conn)?;
    }
    Ok(())
}

/// At most this many problem reports per site a day are kept.
pub const PROBLEMS_PER_SITE_PER_DAY: i64 = 20;

/// One field of a page, as a problem report describes it.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct ProblemField {
    pub id: String,
    pub name: String,
    pub label: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub autocomplete: String,
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = site_problems)]
#[diesel(primary_key(uuid))]
pub struct SiteProblem {
    pub uuid: String,
    pub host: String,
    pub fields: String,
    pub note: Option<String>,
    pub created_at: NaiveDateTime,
}

impl SiteProblem {
    /// A report, checked: the host, at most 50 fields' shapes, and a short note.
    pub fn checked(host: &str, fields: &[ProblemField], note: Option<&str>) -> Result<Self, String> {
        if fields.len() > 50 {
            return Err("At most 50 fields".into());
        }
        let fields = fields
            .iter()
            .map(|f| {
                Ok(ProblemField {
                    id: checked_text(&f.id)?,
                    name: checked_text(&f.name)?,
                    label: checked_text(&f.label)?,
                    kind: checked_text(&f.kind)?,
                    autocomplete: checked_text(&f.autocomplete)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let note = note.map(str::trim).filter(|n| !n.is_empty());
        if note.is_some_and(|n| n.chars().count() > 1000 || n.chars().any(|c| c.is_control() && c != '\n')) {
            return Err("A note is at most 1,000 characters".into());
        }
        Ok(Self {
            uuid: get_uuid(),
            host: checked_host(host)?,
            fields: serde_json::to_string(&fields).unwrap_or_default(),
            note: note.map(str::to_owned),
            created_at: Utc::now().naive_utc(),
        })
    }

    /// Keeps the report, unless the site already has today's share. Returns
    /// whether it was kept. Reports older than PROBLEM_DAYS go, and past
    /// MAX_PROBLEMS, the oldest.
    pub async fn save(self, conn: &DbConn) -> Result<bool, crate::error::Error> {
        conn.run(move |conn| {
            let now = Utc::now().naive_utc();
            let since = now - TimeDelta::days(1);
            let today = site_problems::table
                .filter(site_problems::host.eq(&self.host))
                .filter(site_problems::created_at.gt(since))
                .count()
                .get_result::<i64>(conn)
                .unwrap_or(0);
            if today >= PROBLEMS_PER_SITE_PER_DAY {
                return Ok::<_, diesel::result::Error>(false);
            }
            diesel::insert_into(site_problems::table).values(&self).execute(conn)?;
            diesel::delete(
                site_problems::table.filter(site_problems::created_at.lt(now - TimeDelta::days(PROBLEM_DAYS))),
            )
            .execute(conn)?;
            let count: i64 = site_problems::table.count().get_result(conn)?;
            if count > MAX_PROBLEMS {
                let oldest: Vec<String> = site_problems::table
                    .order(site_problems::created_at.asc())
                    .limit(count - MAX_PROBLEMS)
                    .select(site_problems::uuid)
                    .load(conn)?;
                for chunk in oldest.chunks(500) {
                    diesel::delete(site_problems::table.filter(site_problems::uuid.eq_any(chunk))).execute(conn)?;
                }
            }
            Ok(true)
        })
        .await
        .map_res("Error saving a site problem report")
    }

    /// The newest reports, for the server's admin page.
    pub async fn recent(conn: &DbConn) -> Vec<Value> {
        conn.run(move |conn| {
            site_problems::table
                .order(site_problems::created_at.desc())
                .limit(500)
                .load::<SiteProblem>(conn)
                .unwrap_or_default()
        })
        .await
        .iter()
        .map(|row| {
            json!({
                "host": row.host,
                "fields": serde_json::from_str::<Value>(&row.fields).unwrap_or_default(),
                "note": row.note,
                "createdAt": crate::util::format_date(&row.created_at),
            })
        })
        .collect()
    }
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_site_fix_reports)]
#[diesel(primary_key(uuid))]
pub struct MspSiteFixReport {
    pub uuid: String,
    pub msp_uuid: MspId,
    pub host: String,
    pub field_id: String,
    pub field_name: String,
    pub field_label: String,
    pub fill: String,
    pub reporter_email: String,
    pub created_at: NaiveDateTime,
}

/// An MSP's console shows its staff's latest fixes, this many at most.
const MSP_REPORTS_KEPT: i64 = 200;

impl MspSiteFixReport {
    pub async fn record(msp: &MspId, fix: &Fix, email: &str, conn: &DbConn) -> EmptyResult {
        let row = Self {
            uuid: get_uuid(),
            msp_uuid: msp.clone(),
            host: fix.host.clone(),
            field_id: fix.field.id.clone(),
            field_name: fix.field.name.clone(),
            field_label: fix.field.label.clone(),
            fill: fix.fill.clone(),
            reporter_email: email.to_owned(),
            created_at: Utc::now().naive_utc(),
        };
        conn.run(move |conn| {
            diesel::insert_into(msp_site_fix_reports::table).values(&row).execute(conn)?;
            // Only the newest are kept.
            let keep: Vec<String> = msp_site_fix_reports::table
                .filter(msp_site_fix_reports::msp_uuid.eq(&row.msp_uuid))
                .order(msp_site_fix_reports::created_at.desc())
                .limit(MSP_REPORTS_KEPT)
                .select(msp_site_fix_reports::uuid)
                .load(conn)?;
            diesel::delete(
                msp_site_fix_reports::table
                    .filter(msp_site_fix_reports::msp_uuid.eq(&row.msp_uuid))
                    .filter(msp_site_fix_reports::uuid.ne_all(keep)),
            )
            .execute(conn)
            .map(|_| ())
        })
        .await
        .map_res("Error recording an MSP's site fix")
    }

    pub async fn find_by_msp(msp: &MspId, conn: &DbConn) -> Vec<Value> {
        let msp = msp.clone();
        conn.run(move |conn| {
            msp_site_fix_reports::table
                .filter(msp_site_fix_reports::msp_uuid.eq(msp))
                .order(msp_site_fix_reports::created_at.desc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
        .iter()
        .map(|row| {
            let fix = Fix {
                host: row.host.clone(),
                field: FixField {
                    id: row.field_id.clone(),
                    name: row.field_name.clone(),
                    label: row.field_label.clone(),
                },
                fill: row.fill.clone(),
            };
            let mut json = fix.to_json();
            json["id"] = json!(row.uuid);
            json["reportedBy"] = json!(row.reporter_email);
            json["reportedAt"] = json!(crate::util::format_date(&row.created_at));
            json
        })
        .collect()
    }
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_site_rules)]
#[diesel(primary_key(uuid))]
pub struct MspSiteRule {
    pub uuid: String,
    pub msp_uuid: MspId,
    pub host: String,
    pub field_id: String,
    pub field_name: String,
    pub field_label: String,
    pub fill: String,
    pub created_at: NaiveDateTime,
}

impl MspSiteRule {
    pub fn fix(&self) -> Fix {
        Fix {
            host: self.host.clone(),
            field: FixField {
                id: self.field_id.clone(),
                name: self.field_name.clone(),
                label: self.field_label.clone(),
            },
            fill: self.fill.clone(),
        }
    }

    pub fn to_json(&self) -> Value {
        let mut json = self.fix().to_json();
        json["id"] = json!(self.uuid);
        json["createdAt"] = json!(crate::util::format_date(&self.created_at));
        json
    }

    /// Adds a rule; the same one twice stays one. Returns the rule.
    pub async fn add(msp: &MspId, fix: &Fix, conn: &DbConn) -> Result<Self, crate::error::Error> {
        let row = Self {
            uuid: get_uuid(),
            msp_uuid: msp.clone(),
            host: fix.host.clone(),
            field_id: fix.field.id.clone(),
            field_name: fix.field.name.clone(),
            field_label: fix.field.label.clone(),
            fill: fix.fill.clone(),
            created_at: Utc::now().naive_utc(),
        };
        conn.run(move |conn| {
            let existing = msp_site_rules::table
                .filter(msp_site_rules::msp_uuid.eq(&row.msp_uuid))
                .filter(msp_site_rules::host.eq(&row.host))
                .filter(msp_site_rules::field_id.eq(&row.field_id))
                .filter(msp_site_rules::field_name.eq(&row.field_name))
                .filter(msp_site_rules::field_label.eq(&row.field_label))
                .filter(msp_site_rules::fill.eq(&row.fill))
                .first::<Self>(conn)
                .optional()?;
            match existing {
                Some(existing) => Ok(existing),
                None => diesel::insert_into(msp_site_rules::table).values(&row).execute(conn).map(|_| row),
            }
        })
        .await
        .map_res("Error adding a site rule")
    }

    pub async fn find_by_msp(msp: &MspId, conn: &DbConn) -> Vec<Self> {
        let msp = msp.clone();
        conn.run(move |conn| {
            msp_site_rules::table
                .filter(msp_site_rules::msp_uuid.eq(msp))
                .order(msp_site_rules::host.asc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn find(msp: &MspId, uuid: &str, conn: &DbConn) -> Option<Self> {
        let msp = msp.clone();
        let uuid = uuid.to_owned();
        conn.run(move |conn| {
            msp_site_rules::table
                .filter(msp_site_rules::msp_uuid.eq(msp))
                .filter(msp_site_rules::uuid.eq(uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(msp_site_rules::table.filter(msp_site_rules::uuid.eq(self.uuid)))
                .execute(conn)
                .map(|_| ())
                .map_res("Error removing a site rule")
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fix_is_a_host_a_field_and_a_kind_of_value() {
        let field = FixField {
            id: "custno".into(),
            name: String::new(),
            label: "  Customer Number ".into(),
        };
        let fix = Fix::checked("Bank.Example.com:8443", &field, "username").unwrap();
        assert_eq!(fix.host, "bank.example.com:8443");
        assert_eq!(fix.field.label, "customer number");
        // Custom fields, values, and anything that isn't a host are refused.
        assert!(Fix::checked("bank.example.com", &field, "field").is_err());
        assert!(Fix::checked("https://bank.example.com/login", &field, "password").is_err());
        assert!(Fix::checked("bank.example.com", &FixField::default(), "password").is_err());
        let long = FixField {
            id: "x".repeat(201),
            ..FixField::default()
        };
        assert!(Fix::checked("bank.example.com", &long, "password").is_err());
    }

    #[test]
    fn a_person_is_the_same_hash_for_one_fix_and_unlinkable_across_fixes() {
        let user: UserId = "user-1".to_string().into();
        let a = reporter_hash(&[1; 32], &user, "fix-a");
        assert_eq!(a, reporter_hash(&[1; 32], &user, "fix-a"));
        assert_ne!(a, reporter_hash(&[1; 32], &user, "fix-b"));
        assert_ne!(a, reporter_hash(&[2; 32], &user, "fix-a"));
    }

    /// docs/vectors/server-derived-keys-v1.json, made with Node's crypto.
    #[test]
    fn the_reporters_key_and_hashes_match_the_test_vectors() {
        let v: Value = serde_json::from_str(include_str!("vectors/server-derived-keys-v1.json")).unwrap();
        let der = data_encoding::BASE64.decode(v["rsaPkcs1Der"].as_str().unwrap().as_bytes()).unwrap();
        let r = &v["siteFixReporters"];
        assert_eq!(r["label"].as_str().unwrap().as_bytes(), REPORTER_LABEL);
        let key = crate::keykeeper_streaming::secrets::derive_key_for(REPORTER_LABEL, &der);
        assert_eq!(data_encoding::HEXLOWER.encode(key.as_ref()), r["key"].as_str().unwrap());
        for case in r["cases"].as_array().unwrap() {
            let user: UserId = case["user"].as_str().unwrap().to_owned().into();
            assert_eq!(reporter_hash(&key, &user, case["fix"].as_str().unwrap()), case["hash"].as_str().unwrap());
        }
    }

    #[test]
    fn a_problem_report_has_only_the_fields_shape_and_a_short_note() {
        let field = ProblemField {
            id: "pw".into(),
            kind: "password".into(),
            ..ProblemField::default()
        };
        let report = SiteProblem::checked("bank.example.com", &[field.clone()], Some("Fills the PIN box")).unwrap();
        assert!(report.fields.contains("\"type\":\"password\""));
        assert!(SiteProblem::checked("bank.example.com", &vec![field; 51], None).is_err());
        assert!(SiteProblem::checked("bank.example.com", &[], Some(&"n".repeat(1001))).is_err());
    }
}

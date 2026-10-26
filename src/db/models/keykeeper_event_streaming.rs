// Keykeeper: where an organization's events go besides its event log (its
// security tools: a SIEM or an MDR service), and the queue of events waiting
// to go there. An organization's owners and admins set up its destinations; an
// MSP's admins can set up one for the MSP that gets every client's events and
// the MSP's own activity log. Every event saved to the event log is copied
// into event_deliveries for each destination that takes it, in the one format
// every destination shares (event_json), so a restart loses nothing and a
// slow destination holds up no one else. The worker in keykeeper_streaming
// sends them. Nothing here holds vault data: events name items, folders, and
// members by id, and people by email.
// See DESIGN.md, "Sending events to security tools".

use std::sync::LazyLock;

use chrono::{NaiveDateTime, TimeDelta, Utc};
use diesel::prelude::*;
use serde_json::{Value, json};
use tokio::sync::Notify;

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        keykeeper_schema::{event_deliveries, event_destinations},
    },
    error::MapResult,
    util::format_date,
};

use super::{
    DeviceType, Event, Membership, MembershipId, Msp, MspClient, MspEvent, MspId, OrgPolicy, Organization,
    OrganizationId, User, UserId,
};

/// Destinations per organization, and per MSP.
pub const MAX_DESTINATIONS: i64 = 5;
/// The organizations and MSPs one person can have set up destinations in,
/// so no one account (which can make as many organizations as it likes) can
/// take up the worker with hundreds of them. An MSP's feed covers every
/// client in one.
pub const MAX_SCOPES_PER_PERSON: usize = 20;
/// Events waiting per destination. When it's full, the oldest go, and the
/// destination counts them as dropped.
pub const MAX_QUEUED: i64 = 10_000;

/// Wakes the delivery worker when there's something new to send.
pub static WAKE: LazyLock<Notify> = LazyLock::new(Notify::new);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// HTTPS POST of each event as JSON, signed.
    Webhook,
    /// RFC 5424 messages over TLS (RFC 5425), JSON or CEF.
    Syslog,
    /// Microsoft Sentinel, through Azure Monitor's Logs Ingestion API.
    Sentinel,
}

impl Kind {
    pub fn from_str(text: &str) -> Option<Self> {
        match text {
            "webhook" => Some(Self::Webhook),
            "syslog" => Some(Self::Syslog),
            "sentinel" => Some(Self::Sentinel),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::Syslog => "syslog",
            Self::Sentinel => "sentinel",
        }
    }
}

/// A destination's settings that aren't secret, as stored (JSON).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// Syslog: the collector's host and port, and the message format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Webhook and syslog: a certificate authority (PEM) to trust instead of
    /// the system's, for a collector with a private CA. Public, not secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_certificate: Option<String>,
    /// Webhook: an extra header's name, such as Authorization. Its value is a secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
    /// Sentinel: the app registration and the data collection rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<String>,
}

/// A destination's secrets, stored encrypted (keykeeper_streaming::secrets).
/// Missing ones read as none.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Secrets {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

impl Drop for Secrets {
    /// Wiped from memory once they're no longer needed.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for secret in [&mut self.url, &mut self.signing_secret, &mut self.header_value, &mut self.client_secret] {
            if let Some(s) = secret.as_mut() {
                s.zeroize();
            }
        }
    }
}

#[derive(Clone, Debug, Identifiable, Queryable, Insertable)]
#[diesel(table_name = event_destinations)]
#[diesel(primary_key(uuid))]
pub struct EventDestination {
    pub uuid: String,
    pub org_uuid: Option<OrganizationId>,
    pub msp_uuid: Option<MspId>,
    pub name: String,
    pub kind: String,
    pub settings: String,
    pub secrets: String,
    /// What the console shows of where events go: a webhook's host, never its path.
    pub shown_target: String,
    pub enabled: bool,
    /// Why the server turned it off, when it did.
    pub paused_reason: Option<String>,
    /// Failed attempts in a row.
    pub failures: i32,
    pub failing_since: Option<NaiveDateTime>,
    pub last_success_at: Option<NaiveDateTime>,
    pub last_error: Option<String>,
    pub last_error_at: Option<NaiveDateTime>,
    /// Events that never went: the queue was full, or they waited too long.
    pub dropped: i32,
    /// A worker owns the destination until then, so two never send its events at once.
    pub lease_until: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    /// Not tried again before then: it failed or answered slowly.
    pub retry_at: Option<NaiveDateTime>,
    /// When its people were last emailed that it stopped (at most once a day).
    pub notified_at: Option<NaiveDateTime>,
    /// Events waiting, kept as a running count so queueing an event doesn't
    /// count the queue. Recounted whenever it looks full.
    pub queued: i32,
    /// Who set it up: the worker shares its time fairly between people, as
    /// well as between organizations and MSPs. None once that account is
    /// deleted (the destination stays with its organization or MSP).
    pub created_by: Option<UserId>,
    /// Turns in a row that were slow (but delivered): it's held back longer
    /// each time, without counting as failing.
    pub slow_count: i32,
    /// When its earliest waiting event is due, so finding work never scans
    /// the queue.
    pub next_due_at: Option<NaiveDateTime>,
}

/// Whose destinations one shares a turn with: its organization's or MSP's.
fn scope_key(org: Option<&OrganizationId>, msp: Option<&MspId>, uuid: &str) -> String {
    match (org, msp) {
        (Some(org), _) => format!("org:{org}"),
        (None, Some(msp)) => format!("msp:{msp}"),
        (None, None) => format!("dest:{uuid}"),
    }
}

/// What adding a destination ran into.
#[derive(Debug, PartialEq, Eq)]
pub enum Added {
    Yes,
    /// The organization or MSP has MAX_DESTINATIONS.
    ScopeFull,
    /// The person has destinations in MAX_SCOPES_PER_PERSON others.
    PersonFull,
}

impl EventDestination {
    pub fn new(
        org_uuid: Option<OrganizationId>,
        msp_uuid: Option<MspId>,
        name: String,
        kind: Kind,
        created_by: UserId,
    ) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            uuid: crate::util::get_uuid(),
            org_uuid,
            msp_uuid,
            name,
            kind: kind.as_str().to_owned(),
            settings: "{}".into(),
            secrets: String::new(),
            shown_target: String::new(),
            enabled: true,
            paused_reason: None,
            failures: 0,
            failing_since: None,
            last_success_at: None,
            last_error: None,
            last_error_at: None,
            dropped: 0,
            lease_until: None,
            created_at: now,
            updated_at: now,
            retry_at: None,
            notified_at: None,
            queued: 0,
            created_by: Some(created_by),
            slow_count: 0,
            next_due_at: None,
        }
    }

    pub fn kind(&self) -> Option<Kind> {
        Kind::from_str(&self.kind)
    }

    /// Whose it is: the organization's or the MSP's id.
    pub fn owner(&self) -> &str {
        match (&self.org_uuid, &self.msp_uuid) {
            (Some(org), _) => org.as_ref(),
            (None, Some(msp)) => msp.as_ref(),
            (None, None) => "",
        }
    }

    /// What its secrets' encryption is bound to.
    pub fn binding(&self) -> crate::keykeeper_streaming::secrets::Binding<'_> {
        crate::keykeeper_streaming::secrets::Binding {
            id: &self.uuid,
            owner: self.owner(),
            kind: &self.kind,
        }
    }

    /// Whose destinations it shares a turn with, so one organization or MSP
    /// never has more than one being sent to at a time.
    pub fn scope_key(&self) -> String {
        scope_key(self.org_uuid.as_ref(), self.msp_uuid.as_ref(), &self.uuid)
    }

    pub fn settings(&self) -> Settings {
        serde_json::from_str(&self.settings).unwrap_or_default()
    }

    /// Adds it unless its organization or MSP already has `max`, or the
    /// person adding it already has destinations in MAX_SCOPES_PER_PERSON
    /// other organizations or MSPs. The counts and the insert are one
    /// transaction that holds a write lock, so two requests at once can't
    /// both get under a limit: SQLite's immediate transaction, or
    /// PostgreSQL's locks on the owner's and the person's rows.
    pub async fn insert_capped(&self, max: i64, conn: &DbConn) -> Result<Added, crate::Error> {
        let row = self.clone();
        // The same counts and insert for either database.
        macro_rules! count_and_insert {
            ($conn:ident) => {{
                let mut mine = event_destinations::table.into_boxed();
                mine = match (&row.org_uuid, &row.msp_uuid) {
                    (Some(org), _) => mine.filter(event_destinations::org_uuid.eq(org)),
                    (None, Some(msp)) => mine.filter(event_destinations::msp_uuid.eq(msp)),
                    (None, None) => mine,
                };
                let have: i64 = mine.count().get_result($conn)?;
                let scopes: std::collections::HashSet<(Option<String>, Option<String>)> = match &row.created_by {
                    Some(person) => event_destinations::table
                        .filter(event_destinations::created_by.eq(person))
                        .select((event_destinations::org_uuid, event_destinations::msp_uuid))
                        .load::<(Option<String>, Option<String>)>($conn)?
                        .into_iter()
                        .collect(),
                    None => std::collections::HashSet::new(),
                };
                let here =
                    (row.org_uuid.as_ref().map(ToString::to_string), row.msp_uuid.as_ref().map(ToString::to_string));
                if have >= max {
                    Ok(Added::ScopeFull)
                } else if !scopes.contains(&here) && scopes.len() >= MAX_SCOPES_PER_PERSON {
                    Ok(Added::PersonFull)
                } else {
                    diesel::insert_into(event_destinations::table).values(&row).execute($conn)?;
                    Ok(Added::Yes)
                }
            }};
        }
        let result: Result<Added, diesel::result::Error> = db_run! { conn:
            sqlite {
                conn.immediate_transaction(|conn| count_and_insert!(conn))
            }
            postgresql {
                conn.transaction(|conn| {
                    use crate::db::{keykeeper_schema::msps, schema::{organizations, users}};
                    if let Some(person) = &row.created_by {
                        users::table
                            .filter(users::uuid.eq(person))
                            .select(users::uuid)
                            .for_update()
                            .first::<UserId>(conn)?;
                    }
                    match (&row.org_uuid, &row.msp_uuid) {
                        (Some(org), _) => {
                            organizations::table
                                .filter(organizations::uuid.eq(org))
                                .select(organizations::uuid)
                                .for_update()
                                .first::<OrganizationId>(conn)?;
                        }
                        (None, Some(msp)) => {
                            msps::table.filter(msps::uuid.eq(msp)).select(msps::uuid).for_update().first::<MspId>(conn)?;
                        }
                        (None, None) => {}
                    }
                    count_and_insert!(conn)
                })
            }
        };
        result.map_err(Into::into)
    }

    /// Saves what people change: the name, settings, and secrets. Turning it
    /// on or off is set_enabled; what the worker records (its lease, errors,
    /// counts, a pause) is left as the worker last wrote it.
    pub async fn save_settings(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::update(event_destinations::table.filter(event_destinations::uuid.eq(&self.uuid)))
                .set((
                    event_destinations::name.eq(&self.name),
                    event_destinations::settings.eq(&self.settings),
                    event_destinations::secrets.eq(&self.secrets),
                    event_destinations::shown_target.eq(&self.shown_target),
                    event_destinations::updated_at.eq(self.updated_at),
                ))
                .execute(conn)
                .map_res("Error saving an event destination")
        })
        .await
    }

    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        let uuid = self.uuid.clone();
        conn.run(move |conn| {
            diesel::delete(event_destinations::table.filter(event_destinations::uuid.eq(uuid)))
                .execute(conn)
                .map_res("Error removing an event destination")
        })
        .await
    }

    pub async fn find(uuid: &str, conn: &DbConn) -> Option<Self> {
        let uuid = uuid.to_owned();
        conn.run(move |conn| {
            event_destinations::table.filter(event_destinations::uuid.eq(uuid)).first::<Self>(conn).ok()
        })
        .await
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        let org_uuid = org_uuid.clone();
        conn.run(move |conn| {
            event_destinations::table
                .filter(event_destinations::org_uuid.eq(org_uuid))
                .order(event_destinations::created_at.asc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn find_by_msp(msp_uuid: &MspId, conn: &DbConn) -> Vec<Self> {
        let msp_uuid = msp_uuid.clone();
        conn.run(move |conn| {
            event_destinations::table
                .filter(event_destinations::msp_uuid.eq(msp_uuid))
                .order(event_destinations::created_at.asc())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    /// The destinations an organization's events go to: its own, and its
    /// MSP's, while they're on or paused by the server (they keep queueing
    /// then, so turning one back on sends what it missed). One turned off on
    /// purpose takes nothing.
    async fn taking_org(org_uuid: &OrganizationId, msp_uuid: Option<MspId>, conn: &DbConn) -> Vec<Self> {
        let org_uuid = org_uuid.clone();
        conn.run(move |conn| {
            let mut query = event_destinations::table
                .filter(event_destinations::enabled.eq(true).or(event_destinations::paused_reason.is_not_null()))
                .into_boxed();
            query = match msp_uuid {
                Some(msp) => {
                    query.filter(event_destinations::org_uuid.eq(org_uuid).or(event_destinations::msp_uuid.eq(msp)))
                }
                None => query.filter(event_destinations::org_uuid.eq(org_uuid)),
            };
            query.load::<Self>(conn).unwrap_or_default()
        })
        .await
    }

    async fn taking_msp(msp_uuid: &MspId, conn: &DbConn) -> Vec<Self> {
        let msp_uuid = msp_uuid.clone();
        conn.run(move |conn| {
            event_destinations::table
                .filter(event_destinations::enabled.eq(true).or(event_destinations::paused_reason.is_not_null()))
                .filter(event_destinations::msp_uuid.eq(msp_uuid))
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    /// Takes the destination for a worker for `lease`, unless another holds
    /// it, and returns the lease's end, which only that worker knows. In whole
    /// seconds, so it compares equal however the database stores it.
    pub async fn claim(uuid: &str, lease: TimeDelta, conn: &DbConn) -> Option<NaiveDateTime> {
        let uuid = uuid.to_owned();
        let now = Utc::now();
        let until = chrono::DateTime::from_timestamp(now.timestamp() + lease.num_seconds(), 0)?.naive_utc();
        let now = now.naive_utc();
        conn.run(move |conn| {
            diesel::update(
                event_destinations::table
                    .filter(event_destinations::uuid.eq(uuid))
                    .filter(event_destinations::enabled.eq(true))
                    .filter(event_destinations::lease_until.is_null().or(event_destinations::lease_until.lt(now))),
            )
            .set(event_destinations::lease_until.eq(Some(until)))
            .execute(conn)
            .is_ok_and(|n| n == 1)
            .then_some(until)
        })
        .await
    }

    /// Gives the destination back, if this worker still holds it.
    pub async fn release(uuid: &str, lease: NaiveDateTime, conn: &DbConn) {
        let uuid = uuid.to_owned();
        conn.run(move |conn| {
            diesel::update(
                event_destinations::table
                    .filter(event_destinations::uuid.eq(uuid))
                    .filter(event_destinations::lease_until.eq(Some(lease))),
            )
            .set(event_destinations::lease_until.eq(None::<NaiveDateTime>))
            .execute(conn)
            .ok();
        })
        .await;
    }

    /// Records a turn that delivered, quickly: no longer failing or slow.
    pub async fn succeeded(uuid: &str, conn: &DbConn) {
        let uuid = uuid.to_owned();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            diesel::update(event_destinations::table.filter(event_destinations::uuid.eq(uuid)))
                .set((
                    event_destinations::failures.eq(0),
                    event_destinations::failing_since.eq(None::<NaiveDateTime>),
                    event_destinations::last_success_at.eq(Some(now)),
                    event_destinations::retry_at.eq(None::<NaiveDateTime>),
                    event_destinations::slow_count.eq(0),
                ))
                .execute(conn)
                .ok();
        })
        .await;
    }

    /// Records a turn that delivered, but slowly: it's held back for a while
    /// that grows with each slow turn in a row (10 seconds to 10 minutes),
    /// without counting as failing, so it's never turned off for being slow.
    pub async fn slowed(uuid: &str, why: &str, conn: &DbConn) {
        let uuid = uuid.to_owned();
        let why: String = why.chars().take(500).collect();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            let row = event_destinations::table.filter(event_destinations::uuid.eq(&uuid));
            // One update, so nobody sees it slow without its wait (the worker
            // holds the lease, so the count can't change in between).
            let slow = row.select(event_destinations::slow_count).first::<i32>(conn).unwrap_or(0) + 1;
            let wait = backoff(slow).min(TimeDelta::seconds(600));
            diesel::update(row)
                .set((
                    event_destinations::failures.eq(0),
                    event_destinations::failing_since.eq(None::<NaiveDateTime>),
                    event_destinations::last_success_at.eq(Some(now)),
                    event_destinations::slow_count.eq(slow),
                    event_destinations::last_error.eq(Some(why)),
                    event_destinations::last_error_at.eq(Some(now)),
                    event_destinations::retry_at.eq(Some(now + wait)),
                ))
                .execute(conn)
                .ok();
        })
        .await;
    }

    /// Records an attempt that failed, holds the destination back for a
    /// growing while, and returns it as it is now.
    pub async fn failed(uuid: &str, error: &str, conn: &DbConn) -> Option<Self> {
        let uuid = uuid.to_owned();
        let error: String = error.chars().take(500).collect();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            // One update, so nobody sees it failing without its wait (the
            // worker holds the lease, so nothing else changes these meanwhile).
            let row = event_destinations::table.filter(event_destinations::uuid.eq(&uuid));
            let before = row.first::<Self>(conn).ok()?;
            let failures = before.failures + 1;
            let failing_since = before.failing_since.unwrap_or(now);
            let retry_at = now + backoff(failures);
            diesel::update(row)
                .set((
                    event_destinations::failures.eq(failures),
                    event_destinations::failing_since.eq(Some(failing_since)),
                    event_destinations::last_error.eq(Some(error.clone())),
                    event_destinations::last_error_at.eq(Some(now)),
                    event_destinations::retry_at.eq(Some(retry_at)),
                ))
                .execute(conn)
                .ok()?;
            Some(Self {
                failures,
                failing_since: Some(failing_since),
                last_error: Some(error),
                last_error_at: Some(now),
                retry_at: Some(retry_at),
                ..before
            })
        })
        .await
    }

    /// The destinations with events due now and nothing holding them back,
    /// soonest first, at most `limit`, as (id, scope, who set it up): one
    /// query on the destinations' `next_due_at` index, never a scan of the
    /// queue. A destination held back (failing or slow) has `next_due_at` no
    /// earlier than its `retry_at`, so it's outside the range until then.
    pub async fn due(limit: i64, conn: &DbConn) -> Vec<(String, String, Option<UserId>)> {
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            event_destinations::table
                .filter(event_destinations::next_due_at.le(now))
                .filter(event_destinations::enabled.eq(true))
                .filter(event_destinations::retry_at.is_null().or(event_destinations::retry_at.le(now)))
                .order(event_destinations::next_due_at.asc())
                .select((
                    event_destinations::uuid,
                    event_destinations::org_uuid,
                    event_destinations::msp_uuid,
                    event_destinations::created_by,
                ))
                .limit(limit)
                .load::<(String, Option<OrganizationId>, Option<MspId>, Option<UserId>)>(conn)
                .unwrap_or_default()
        })
        .await
        .into_iter()
        .map(|(uuid, org, msp, person)| {
            let scope = scope_key(org.as_ref(), msp.as_ref(), &uuid);
            (uuid, scope, person)
        })
        .collect()
    }

    /// Sets when it next has something to send: its earliest waiting event,
    /// but not before it's no longer held back.
    pub async fn refresh_due(uuid: &str, conn: &DbConn) {
        let uuid = uuid.to_owned();
        conn.run(move |conn| {
            let next: Option<NaiveDateTime> = event_deliveries::table
                .filter(event_deliveries::destination_uuid.eq(&uuid))
                .select(diesel::dsl::min(event_deliveries::next_attempt_at))
                .first(conn)
                .unwrap_or(None);
            let retry_at: Option<NaiveDateTime> = event_destinations::table
                .filter(event_destinations::uuid.eq(&uuid))
                .select(event_destinations::retry_at)
                .first(conn)
                .unwrap_or(None);
            let next = match (next, retry_at) {
                (Some(next), Some(retry)) => Some(next.max(retry)),
                (next, _) => next,
            };
            diesel::update(event_destinations::table.filter(event_destinations::uuid.eq(&uuid)))
                .set(event_destinations::next_due_at.eq(next))
                .execute(conn)
                .ok();
        })
        .await;
    }

    /// Whether its people should be emailed that it stopped: not if they were
    /// in the last day. Marks it emailed.
    pub async fn take_notice(uuid: &str, conn: &DbConn) -> bool {
        let uuid = uuid.to_owned();
        let now = Utc::now().naive_utc();
        let day_ago = now - TimeDelta::hours(24);
        conn.run(move |conn| {
            diesel::update(
                event_destinations::table
                    .filter(event_destinations::uuid.eq(uuid))
                    .filter(event_destinations::notified_at.is_null().or(event_destinations::notified_at.lt(day_ago))),
            )
            .set(event_destinations::notified_at.eq(Some(now)))
            .execute(conn)
            .is_ok_and(|n| n == 1)
        })
        .await
    }

    /// Moves the running count of waiting events by `by`.
    async fn count_queue(uuid: &str, by: i32, conn: &DbConn) {
        if by == 0 {
            return;
        }
        let uuid = uuid.to_owned();
        conn.run(move |conn| {
            diesel::update(event_destinations::table.filter(event_destinations::uuid.eq(uuid)))
                .set(event_destinations::queued.eq(event_destinations::queued + by))
                .execute(conn)
                .ok();
        })
        .await;
    }

    /// Turns the destination off, saying why. Its queue stays, held until
    /// it's turned on again, so the worker doesn't keep finding it due.
    pub async fn pause(uuid: &str, reason: &str, conn: &DbConn) {
        let id = uuid.to_owned();
        let reason: String = reason.chars().take(500).collect();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            diesel::update(event_destinations::table.filter(event_destinations::uuid.eq(&id)))
                .set((
                    event_destinations::enabled.eq(false),
                    event_destinations::paused_reason.eq(Some(reason)),
                    event_destinations::updated_at.eq(now),
                ))
                .execute(conn)
                .ok();
            diesel::update(event_deliveries::table.filter(event_deliveries::destination_uuid.eq(&id)))
                .set(event_deliveries::next_attempt_at.eq(held()))
                .execute(conn)
                .ok();
        })
        .await;
        Self::refresh_due(uuid, conn).await;
    }

    /// Turns the destination on (a fresh start: no failures, no pause) or
    /// off on purpose. Only these columns, so nothing the worker wrote in the
    /// meantime is overwritten.
    pub async fn set_enabled(uuid: &str, enabled: bool, conn: &DbConn) -> EmptyResult {
        let uuid = uuid.to_owned();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            let row = event_destinations::table.filter(event_destinations::uuid.eq(uuid));
            if enabled {
                diesel::update(row)
                    .set((
                        event_destinations::enabled.eq(true),
                        event_destinations::paused_reason.eq(None::<String>),
                        event_destinations::failures.eq(0),
                        event_destinations::failing_since.eq(None::<NaiveDateTime>),
                        event_destinations::retry_at.eq(None::<NaiveDateTime>),
                        event_destinations::slow_count.eq(0),
                        event_destinations::updated_at.eq(now),
                    ))
                    .execute(conn)
            } else {
                diesel::update(row)
                    .set((
                        event_destinations::enabled.eq(false),
                        event_destinations::paused_reason.eq(None::<String>),
                        event_destinations::updated_at.eq(now),
                    ))
                    .execute(conn)
            }
            .map_res("Error saving an event destination")
        })
        .await
    }

    async fn add_dropped(uuid: &str, count: i32, conn: &DbConn) {
        if count == 0 {
            return;
        }
        let uuid = uuid.to_owned();
        conn.run(move |conn| {
            diesel::update(event_destinations::table.filter(event_destinations::uuid.eq(uuid)))
                .set(event_destinations::dropped.eq(event_destinations::dropped + count))
                .execute(conn)
                .ok();
        })
        .await;
    }
}

/// An event waiting to go to one destination.
#[derive(Clone, Debug, Identifiable, Queryable, Insertable)]
#[diesel(table_name = event_deliveries)]
#[diesel(primary_key(destination_uuid, event_uuid))]
pub struct EventDelivery {
    pub destination_uuid: String,
    pub event_uuid: String,
    /// The event as every destination gets it (event_json), as JSON text.
    pub payload: String,
    pub created_at: NaiveDateTime,
    pub attempts: i32,
    pub next_attempt_at: NaiveDateTime,
    /// 0 to 3, low, medium, high, and kept (changes to who can do what): a
    /// full queue drops the least important events first and never drops a
    /// kept one, so a flood can't push out an export or a removed member.
    pub priority: i32,
    /// Events that are merged while they wait (anything an app reports, and
    /// failed logins): one row per kind, person, and minute, with a count.
    pub merge_key: Option<String>,
    /// The organization the event came from. In an MSP's feed, a full queue
    /// drops from the client with the most waiting, so one client can't
    /// crowd out the others.
    pub source: Option<String>,
}

/// Kept: never dropped from a full queue.
pub const KEPT: i32 = 3;

/// An event's priority in the queue: kept for changes to who can do what
/// (members, groups, shared folders, the organization's settings, single
/// sign-on and its domains, policies, where events go, and the MSP's staff
/// and clients), otherwise by severity. Single sign-on's sign-ins and
/// refusals (1590 and 1591) go by severity, as logins do.
pub fn priority(code: i32, severity: &str) -> i32 {
    let kept = matches!(code, 1300..=1302 | 1400..=1499 | 1600 | 1601 | 1604 | 1605 | 1690..=1699 | 1700 | 2000..=2002)
        || (matches!(code, 1500..=1599) && !matches!(code, 1522 | 1590 | 1591))
        || (matches!(code, 9100..=9199) && !matches!(code, 9120 | 9121 | 9199));
    if kept {
        return KEPT;
    }
    match severity {
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

/// Which events are merged while they wait, by type: what apps report
/// (views, shows, copies, fills, exports, notice clicks), failed logins, and
/// single sign-on's refusals, which anyone can make many of (anyone can start
/// a sign-in and send back a bad answer). Not what the server records itself,
/// such as moving items to the trash.
pub fn merges(code: i32) -> bool {
    matches!(code, 1005 | 1006 | 1007 | 1107..=1114 | 1117..=1132 | 1522 | 1591 | 1602)
}

/// When a paused destination's events are due: not until it's turned on again.
fn held() -> NaiveDateTime {
    Utc::now().naive_utc() + TimeDelta::days(3650)
}

/// How long an event keeps being retried before it's dropped: three days, as
/// Standard Webhooks suggests.
pub const GIVE_UP_AFTER: TimeDelta = TimeDelta::days(3);

/// A full queue can grow past MAX_QUEUED with kept events only, up to this.
const MAX_WITH_KEPT: i64 = 2 * MAX_QUEUED;

/// What an event adds to a destination's queue.
pub struct Queued<'a> {
    pub event_uuid: &'a str,
    pub payload: String,
    pub priority: i32,
    pub merge_key: Option<String>,
    pub source: Option<String>,
}

/// Adds one more to a merged event's payload: its count, its last time, and
/// up to 20 different targets and addresses.
fn merge_into(waiting: &str, new: &str) -> Option<String> {
    let mut w: Value = serde_json::from_str(waiting).ok()?;
    let n: Value = serde_json::from_str(new).ok()?;
    let count = w["count"].as_i64().unwrap_or(1) + 1;
    w["count"] = json!(count);
    w["lastTime"] = n["time"].clone();
    for (field, from) in [("targets", "target"), ("ips", "ip")] {
        let mut list: Vec<Value> = w[field]
            .as_array()
            .cloned()
            .unwrap_or_else(|| w.get(from).filter(|v| !v.is_null()).map(|v| vec![v.clone()]).unwrap_or_default());
        if let Some(v) = n.get(from).filter(|v| !v.is_null())
            && !list.contains(v)
            && list.len() < 20
        {
            list.push(v.clone());
        }
        if !list.is_empty() {
            w[field] = Value::Array(list);
        }
    }
    Some(w.to_string())
}

impl EventDelivery {
    /// Queues an event for a destination: due now (the worker skips a
    /// destination that's waiting out a failure), or held while the server
    /// has it paused. An event that merges joins one of its kind, person, and
    /// minute that's still waiting. A full queue loses its least important,
    /// oldest events (in an MSP's feed, from the client with the most
    /// waiting), never kept ones, counted on the destination. Each step is
    /// its own statement, not one transaction, so SQLite's busy wait covers
    /// each.
    pub async fn enqueue(destination: &EventDestination, event: Queued<'_>, conn: &DbConn) -> EmptyResult {
        let now = Utc::now().naive_utc();
        let next_attempt_at = if destination.enabled {
            now
        } else {
            held()
        };
        let row = Self {
            destination_uuid: destination.uuid.clone(),
            event_uuid: event.event_uuid.to_owned(),
            payload: event.payload,
            created_at: now,
            attempts: 0,
            next_attempt_at,
            priority: event.priority,
            merge_key: event.merge_key,
            source: event.source,
        };
        let enabled = destination.enabled;
        let is_feed = destination.msp_uuid.is_some();
        let dropped = conn
            .run(move |conn| {
                let mine = event_deliveries::destination_uuid.eq(row.destination_uuid.clone());
                let dest = event_destinations::table.filter(event_destinations::uuid.eq(&row.destination_uuid));
                if let Some(key) = &row.merge_key {
                    // Joins the waiting one, unless the worker has taken it
                    // to send (it then has no merge key) or another event
                    // joined it meanwhile (its payload changed): then it
                    // looks again, and after a few tries it waits on its own.
                    for _ in 0..3 {
                        let waiting: Option<(String, String)> = event_deliveries::table
                            .filter(mine.clone())
                            .filter(event_deliveries::merge_key.eq(key))
                            .select((event_deliveries::event_uuid, event_deliveries::payload))
                            .first(conn)
                            .optional()?;
                        let Some((uuid, payload)) = waiting else {
                            break;
                        };
                        let Some(merged) = merge_into(&payload, &row.payload) else {
                            break;
                        };
                        let joined = diesel::update(
                            event_deliveries::table
                                .filter(mine.clone())
                                .filter(event_deliveries::event_uuid.eq(uuid))
                                .filter(event_deliveries::merge_key.eq(key))
                                .filter(event_deliveries::payload.eq(payload)),
                        )
                        .set(event_deliveries::payload.eq(merged))
                        .execute(conn)?;
                        if joined == 1 {
                            return Ok(0);
                        }
                    }
                }
                match diesel::insert_into(event_deliveries::table).values(&row).execute(conn) {
                    Ok(_) => {}
                    // The same event queued twice is queued once.
                    Err(diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::UniqueViolation,
                        _,
                    )) => return Ok(0),
                    Err(e) => return Err(e),
                }
                diesel::update(dest)
                    .set(event_destinations::queued.eq(event_destinations::queued + 1))
                    .execute(conn)?;
                if enabled {
                    // It has something due now, or when it's no longer held back.
                    diesel::update(
                        dest.filter(event_destinations::retry_at.is_null().or(event_destinations::retry_at.le(now)))
                            .filter(
                                event_destinations::next_due_at.is_null().or(event_destinations::next_due_at.gt(now)),
                            ),
                    )
                    .set(event_destinations::next_due_at.eq(Some(now)))
                    .execute(conn)?;
                    diesel::update(
                        dest.filter(event_destinations::retry_at.gt(now)).filter(
                            event_destinations::next_due_at
                                .is_null()
                                .or(event_destinations::next_due_at.gt(event_destinations::retry_at)),
                        ),
                    )
                    .set(event_destinations::next_due_at.eq(event_destinations::retry_at))
                    .execute(conn)?;
                }
                let counted: i32 = dest.select(event_destinations::queued).first(conn)?;
                if i64::from(counted) <= MAX_QUEUED {
                    return Ok(0);
                }
                // Looks full: count for real, drop the least important (from
                // the busiest client, in an MSP's feed), and set the count to
                // what's left.
                let queued: i64 = event_deliveries::table.filter(mine.clone()).count().get_result(conn)?;
                let droppable: i64 = event_deliveries::table
                    .filter(mine.clone())
                    .filter(event_deliveries::priority.lt(KEPT))
                    .count()
                    .get_result(conn)?;
                let over = queued - MAX_QUEUED;
                let mut gone = 0;
                if over > 0 && droppable > 0 {
                    let mut least = event_deliveries::table
                        .filter(mine.clone())
                        .filter(event_deliveries::priority.lt(KEPT))
                        .into_boxed();
                    if is_feed {
                        let busiest: Option<Option<String>> = event_deliveries::table
                            .filter(mine.clone())
                            .filter(event_deliveries::priority.lt(KEPT))
                            .group_by(event_deliveries::source)
                            .select(event_deliveries::source)
                            .order(diesel::dsl::count_star().desc())
                            .first(conn)
                            .optional()?;
                        if let Some(Some(source)) = busiest {
                            least = least.filter(event_deliveries::source.eq(source));
                        }
                    }
                    let ids: Vec<String> = least
                        .order((
                            event_deliveries::priority.asc(),
                            event_deliveries::created_at.asc(),
                            event_deliveries::event_uuid.asc(),
                        ))
                        .select(event_deliveries::event_uuid)
                        .limit(over)
                        .load(conn)?;
                    gone = diesel::delete(
                        event_deliveries::table.filter(mine).filter(event_deliveries::event_uuid.eq_any(ids)),
                    )
                    .execute(conn)?;
                } else if queued > MAX_WITH_KEPT {
                    // Only kept events, and too many even for those: the oldest go.
                    let ids: Vec<String> = event_deliveries::table
                        .filter(mine.clone())
                        .order((event_deliveries::created_at.asc(), event_deliveries::event_uuid.asc()))
                        .select(event_deliveries::event_uuid)
                        .limit(queued - MAX_WITH_KEPT)
                        .load(conn)?;
                    gone = diesel::delete(
                        event_deliveries::table.filter(mine).filter(event_deliveries::event_uuid.eq_any(ids)),
                    )
                    .execute(conn)?;
                }
                let left = i32::try_from(queued).unwrap_or(i32::MAX) - i32::try_from(gone).unwrap_or(0);
                diesel::update(dest).set(event_destinations::queued.eq(left)).execute(conn)?;
                Ok(gone)
            })
            .await
            .map_err(Into::<crate::Error>::into)?;
        EventDestination::add_dropped(&destination.uuid, i32::try_from(dropped).unwrap_or(i32::MAX), conn).await;
        Ok(())
    }

    /// A destination's events due now, oldest first.
    /// A destination's events due now, oldest first, taken to send: from
    /// now on, nothing more merges into them (an event that would waits on
    /// its own), so a count can't grow after it was read to send. They stop
    /// merging first and are read after, so nothing that merged is missed.
    pub async fn due(destination: &str, limit: i64, conn: &DbConn) -> Vec<Self> {
        let destination = destination.to_owned();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            let mine = event_deliveries::destination_uuid.eq(destination);
            let ids: Vec<String> = event_deliveries::table
                .filter(mine.clone())
                .filter(event_deliveries::next_attempt_at.le(now))
                .order((event_deliveries::created_at.asc(), event_deliveries::event_uuid.asc()))
                .select(event_deliveries::event_uuid)
                .limit(limit)
                .load(conn)
                .unwrap_or_default();
            diesel::update(
                event_deliveries::table
                    .filter(mine.clone())
                    .filter(event_deliveries::event_uuid.eq_any(&ids))
                    .filter(event_deliveries::merge_key.is_not_null()),
            )
            .set(event_deliveries::merge_key.eq(None::<String>))
            .execute(conn)
            .ok();
            event_deliveries::table
                .filter(mine)
                .filter(event_deliveries::event_uuid.eq_any(&ids))
                .order((event_deliveries::created_at.asc(), event_deliveries::event_uuid.asc()))
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn count(destination: &str, conn: &DbConn) -> i64 {
        let destination = destination.to_owned();
        conn.run(move |conn| {
            event_deliveries::table
                .filter(event_deliveries::destination_uuid.eq(destination))
                .count()
                .get_result(conn)
                .unwrap_or(0)
        })
        .await
    }

    /// Delivered: forgotten.
    pub async fn done(destination: &str, events: Vec<String>, conn: &DbConn) {
        let dest = destination.to_owned();
        let gone = conn
            .run(move |conn| {
                diesel::delete(
                    event_deliveries::table
                        .filter(event_deliveries::destination_uuid.eq(dest))
                        .filter(event_deliveries::event_uuid.eq_any(events)),
                )
                .execute(conn)
                .unwrap_or(0)
            })
            .await;
        EventDestination::count_queue(destination, -i32::try_from(gone).unwrap_or(0), conn).await;
    }

    /// Not delivered: tried again after a growing wait (with some jitter),
    /// or dropped once it has waited too long. Returns how many were dropped.
    pub async fn retry_later(destination: &str, deliveries: Vec<Self>, conn: &DbConn) -> i32 {
        let now = Utc::now().naive_utc();
        let mut dropped = Vec::new();
        let mut later = Vec::new();
        for d in deliveries {
            if now - d.created_at >= GIVE_UP_AFTER {
                dropped.push(d.event_uuid);
            } else {
                let attempts = d.attempts + 1;
                later.push((d.event_uuid, attempts, now + backoff(attempts)));
            }
        }
        let dest = destination.to_owned();
        let count = conn
            .run(move |conn| {
                let gone = diesel::delete(
                    event_deliveries::table
                        .filter(event_deliveries::destination_uuid.eq(&dest))
                        .filter(event_deliveries::event_uuid.eq_any(dropped)),
                )
                .execute(conn)
                .unwrap_or(0);
                for (event, attempts, next) in later {
                    diesel::update(
                        event_deliveries::table
                            .filter(event_deliveries::destination_uuid.eq(&dest))
                            .filter(event_deliveries::event_uuid.eq(event)),
                    )
                    .set((event_deliveries::attempts.eq(attempts), event_deliveries::next_attempt_at.eq(next)))
                    .execute(conn)
                    .ok();
                }
                i32::try_from(gone).unwrap_or(0)
            })
            .await;
        EventDestination::add_dropped(destination, count, conn).await;
        EventDestination::count_queue(destination, -count, conn).await;
        count
    }

    /// Forgets everything queued for a destination, as when it's turned off on purpose.
    pub async fn forget_all(destination: &str, conn: &DbConn) {
        let destination = destination.to_owned();
        conn.run(move |conn| {
            diesel::delete(event_deliveries::table.filter(event_deliveries::destination_uuid.eq(&destination)))
                .execute(conn)
                .ok();
            diesel::update(event_destinations::table.filter(event_destinations::uuid.eq(&destination)))
                .set((event_destinations::queued.eq(0), event_destinations::next_due_at.eq(None::<NaiveDateTime>)))
                .execute(conn)
                .ok();
        })
        .await;
    }

    /// Everything queued for a destination is due now, for when it's turned on again.
    pub async fn due_now(destination: &str, conn: &DbConn) {
        let destination = destination.to_owned();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            let changed =
                diesel::update(event_deliveries::table.filter(event_deliveries::destination_uuid.eq(&destination)))
                    .set(event_deliveries::next_attempt_at.eq(now))
                    .execute(conn)
                    .unwrap_or(0);
            if changed > 0 {
                diesel::update(event_destinations::table.filter(event_destinations::uuid.eq(&destination)))
                    .set(event_destinations::next_due_at.eq(Some(now)))
                    .execute(conn)
                    .ok();
            }
        })
        .await;
    }
}

/// The wait before attempt `attempts + 1`: 10 seconds, then growing to at
/// most an hour, plus up to a fifth more at random so destinations that
/// failed together don't all retry together.
pub fn backoff(attempts: i32) -> TimeDelta {
    let base: i64 = match attempts {
        ..=1 => 10,
        2 => 30,
        3 => 120,
        4 => 300,
        5 => 900,
        6 => 1800,
        _ => 3600,
    };
    let jitter = i64::from(crate::keykeeper_streaming::secrets::random::<1>()[0]) * base / 5 / 255;
    TimeDelta::seconds(base + jitter)
}

/// What kind of thing an event is about, its name in words, and how much a
/// security team should care, by upstream's event type codes. Codes 1190,
/// 1191, 1590, 1591, and 1690 to 1694 are ours.
pub fn describe(code: i32) -> (&'static str, &'static str, &'static str) {
    let (name, severity) = match code {
        1000 => ("Logged in", "low"),
        1001 => ("Changed their master password", "medium"),
        1002 => ("Updated two-step login", "medium"),
        1003 => ("Turned off two-step login", "high"),
        1004 => ("Recovered their account with a two-step recovery code", "high"),
        // Medium, not high: anyone can make many, and a full queue drops
        // medium before high.
        1005 => ("Failed to log in: wrong password", "medium"),
        1006 => ("Failed to log in: wrong two-step code", "medium"),
        1007 => ("Exported their vault", "high"),
        1010 => ("Asked to approve a new device", "low"),
        1100 => ("Created an item", "low"),
        1101 => ("Edited an item", "low"),
        1102 => ("Deleted an item for good", "medium"),
        1103 => ("Added an attachment", "low"),
        1104 => ("Deleted an attachment", "low"),
        1105 => ("Moved an item to the organization", "low"),
        1106 => ("Changed an item's shared folders", "low"),
        1107 => ("Viewed an item", "low"),
        1108 => ("Showed an item's password", "low"),
        1109 => ("Showed an item's hidden field", "low"),
        1110 => ("Showed a card's security code", "low"),
        1111 => ("Copied an item's password", "low"),
        1112 => ("Copied an item's hidden field", "low"),
        1113 => ("Copied a card's security code", "low"),
        1114 => ("Filled an item", "low"),
        1115 => ("Moved an item to the trash", "low"),
        1116 => ("Restored an item from the trash", "low"),
        1117 => ("Showed a card's number", "low"),
        1118 => ("Showed an item's authenticator key", "low"),
        1119 => ("Copied a bank account number", "low"),
        1120 => ("Copied a bank account PIN", "low"),
        1121 => ("Showed a bank account number", "low"),
        1122 => ("Showed a bank account PIN", "low"),
        1123 => ("Copied a license number", "low"),
        1124 => ("Showed a license number", "low"),
        1125 => ("Copied a passport number", "low"),
        1126 => ("Showed a passport number", "low"),
        1127 => ("Copied a SWIFT code", "low"),
        1128 => ("Showed a SWIFT code", "low"),
        1129 => ("Copied an IBAN", "low"),
        1130 => ("Showed an IBAN", "low"),
        1131 => ("Copied a national ID number", "low"),
        1132 => ("Showed a national ID number", "low"),
        1190 => ("Cleared an item's history", "medium"),
        1191 => ("Deleted a past version of an item", "medium"),
        1300 => ("Created a shared folder", "low"),
        1301 => ("Edited a shared folder", "low"),
        1302 => ("Deleted a shared folder", "medium"),
        1400 => ("Created a group", "low"),
        1401 => ("Edited a group", "low"),
        1402 => ("Deleted a group", "medium"),
        1500 => ("Invited a member", "low"),
        1501 => ("Confirmed a member", "low"),
        1502 => ("Edited a member's role or access", "high"),
        1503 => ("Removed a member", "medium"),
        1504 => ("Changed a member's groups", "low"),
        1505 => ("Unlinked a member's single sign-on", "medium"),
        1506 => ("Enrolled in account recovery", "low"),
        1507 => ("Withdrew from account recovery", "medium"),
        1508 => ("Reset a member's master password", "high"),
        1510 => ("Linked an account to single sign-on", "high"),
        1511 => ("Revoked a member", "medium"),
        1512 => ("Restored a member", "low"),
        1513 => ("Approved a device for a member", "medium"),
        1514 => ("Denied a device for a member", "low"),
        1515 => ("Deleted a member's account", "high"),
        1516 => ("Left the organization", "low"),
        1519 => ("Reset a member's two-step login", "high"),
        1522 => ("Opened a notice from the organization", "low"),
        1590 => ("Signed in with single sign-on", "low"),
        1591 => ("Single sign-on refused someone", "medium"),
        1600 => ("Edited the organization's settings", "medium"),
        1601 => ("Purged the organization's vault", "high"),
        1602 => ("Exported the organization's vault", "high"),
        1604 => ("Turned on single sign-on", "high"),
        1605 => ("Turned off single sign-on", "high"),
        1690 => ("Added a place events are sent", "high"),
        1691 => ("Changed a place events are sent", "high"),
        1692 => ("Removed a place events are sent", "high"),
        1693 => ("The server stopped sending to a place events are sent", "high"),
        1694 => ("Changed the single sign-on settings", "high"),
        1700 => ("Changed a policy", "medium"),
        2000 => ("Added a domain for single sign-on", "high"),
        2001 => ("Removed a domain from single sign-on", "high"),
        2002 => ("Verified a domain for single sign-on", "high"),
        2003 => ("Checked a domain that isn't verified yet", "low"),
        crate::keykeeper_streaming::TEST_EVENT_TYPE => ("Test event", "low"),
        _ => ("Event", "low"),
    };
    let category = match code {
        1000..=1099 => "user",
        1100..=1199 => "item",
        1300..=1399 => "folder",
        1400..=1499 => "group",
        1500..=1599 => "member",
        // 2000 to 2099: single sign-on's domains.
        1600..=1699 | 2000..=2099 => "organization",
        1700..=1799 => "policy",
        9100..=9199 => "msp",
        crate::keykeeper_streaming::TEST_EVENT_TYPE => "test",
        _ => "other",
    };
    (category, name, severity)
}

/// The event as every destination gets it. Ids and emails, never names of
/// items or folders (the server can't read them anyway), never values.
pub async fn event_json(event: &Event, org: &Organization, msp: Option<&Msp>, conn: &DbConn) -> Value {
    let (category, name, severity) = describe(event.event_type);
    let mut out = json!({
        "id": event.uuid,
        "time": format_date(&event.event_date),
        "type": event.event_type,
        "name": name,
        "category": category,
        "severity": severity,
        "organization": { "id": org.uuid, "name": org.name },
        "actor": actor_json(event.act_user_uuid.as_ref(), event.system_actor, conn).await,
    });
    if let Some(target) = target_json(event, conn).await {
        out["target"] = target;
    }
    if let Some(device) = event.device_type {
        out["device"] = json!({ "type": device, "name": DeviceType::from_i32(device).to_string() });
    }
    if let Some(ip) = &event.ip_address {
        out["ip"] = json!(ip);
    }
    if let Some(msp) = msp {
        out["msp"] = json!({ "id": msp.uuid, "name": msp.name });
    }
    // Single sign-on's events say what changed, which domain, or why someone
    // was refused (keykeeper_sso): never a secret.
    if let Some(detail) = &event.keykeeper_detail {
        out["detail"] = json!(detail);
    }
    out
}

async fn actor_json(user: Option<&UserId>, system: Option<i32>, conn: &DbConn) -> Value {
    match (user, system) {
        (Some(id), _) => {
            let email = User::find_by_uuid(id, conn).await.map(|u| u.email);
            json!({ "type": "user", "id": id, "email": email })
        }
        // No person acted: provisioning from the directory (upstream's
        // system user 1), or something else the server did.
        (None, Some(1)) => json!({ "type": "system", "name": "scim" }),
        (None, _) => json!({ "type": "system" }),
    }
}

async fn member_target(member: &MembershipId, conn: &DbConn) -> Value {
    let mut target = json!({ "type": "member", "id": member });
    if let Some(m) = Membership::find_by_uuid(member, conn).await {
        target["userId"] = json!(m.user_uuid);
        if let Some(user) = User::find_by_uuid(&m.user_uuid, conn).await {
            target["email"] = json!(user.email);
        }
    }
    target
}

async fn target_json(event: &Event, conn: &DbConn) -> Option<Value> {
    if let Some(item) = &event.cipher_uuid {
        return Some(json!({ "type": "item", "id": item }));
    }
    if let Some(folder) = &event.collection_uuid {
        return Some(json!({ "type": "folder", "id": folder }));
    }
    if let Some(group) = &event.group_uuid {
        return Some(json!({ "type": "group", "id": group }));
    }
    if let Some(policy) = &event.policy_uuid {
        let mut target = json!({ "type": "policy", "id": policy });
        if let Some(org) = &event.org_uuid
            && let Some(p) = OrgPolicy::find_by_org(org, conn).await.into_iter().find(|p| &p.uuid == policy)
        {
            target["policyType"] = json!(p.atype);
        }
        return Some(target);
    }
    if let Some(member) = &event.org_user_uuid {
        // A person's own events (logins and the like) are about themselves.
        if event.event_type >= 1500 {
            return Some(member_target(member, conn).await);
        }
    }
    None
}

/// Copies an event that was just saved into the queue of each destination
/// that takes it. Called for every saved event; costs two small queries for
/// an organization without destinations. Never fails the action that logged
/// it.
pub async fn stream(event: &Event, conn: &DbConn) {
    let Some(org_uuid) = &event.org_uuid else {
        return;
    };
    let msp_uuid = MspClient::find_by_org(org_uuid, conn).await.map(|c| c.msp_uuid);
    let destinations = EventDestination::taking_org(org_uuid, msp_uuid.clone(), conn).await;
    if destinations.is_empty() {
        return;
    }
    let Some(org) = Organization::find_by_uuid(org_uuid, conn).await else {
        return;
    };
    let msp = match &msp_uuid {
        Some(id) if destinations.iter().any(|d| d.msp_uuid.is_some()) => Msp::find_by_uuid(id, conn).await,
        _ => None,
    };
    let mut own = event_json(event, &org, None, conn).await;
    // What the code that logged it added for destinations (which destination
    // changed, and how).
    if let Some((_, extra)) = EVENT_EXTRAS.remove(event.uuid.as_str())
        && let Some(extra) = extra.as_object()
    {
        for (k, v) in extra {
            own[k] = v.clone();
        }
    }
    let own = own.to_string();
    let rank = priority(event.event_type, describe(event.event_type).2);
    let merge_key = merge_key(event, Utc::now().timestamp() / 60);
    let for_msp = msp.as_ref().map(|m| {
        let mut v: Value = serde_json::from_str(&own).unwrap_or_default();
        v["msp"] = json!({ "id": m.uuid, "name": m.name });
        v.to_string()
    });
    for d in destinations {
        let payload = if d.msp_uuid.is_some() {
            for_msp.clone()
        } else {
            Some(own.clone())
        };
        if let Some(payload) = payload {
            let queued = Queued {
                event_uuid: event.uuid.as_str(),
                payload,
                priority: rank,
                merge_key: merge_key.clone(),
                source: Some(org_uuid.to_string()),
            };
            if let Err(e) = EventDelivery::enqueue(&d, queued, conn).await {
                warn!("Couldn't queue an event for destination {}: {e:?}", d.uuid);
            }
        }
    }
    WAKE.notify_one();
}

/// What an event merges with while it waits, if it's of a kind that merges:
/// the same kind, organization, and person (or account, for failed logins),
/// in the same minute of the server's clock (an app says when its events
/// happened, so not theirs). The organization keeps a person in several of
/// an MSP's clients from merging across them in the MSP's feed.
fn merge_key(event: &Event, minute: i64) -> Option<String> {
    if !merges(event.event_type) {
        return None;
    }
    let org = event.org_uuid.as_ref().map(ToString::to_string).unwrap_or_default();
    let who = event.act_user_uuid.as_ref().or(event.user_uuid.as_ref()).map(ToString::to_string).unwrap_or_default();
    Some(format!("{}:{org}:{who}:{minute}", event.event_type))
}

/// Fields that the code logging an event adds to what destinations get, by
/// the event's id, taken when it's saved: which destination an event about
/// event streaming is about, and what changed. Use save_with_extras.
pub static EVENT_EXTRAS: LazyLock<dashmap::DashMap<String, Value>> = LazyLock::new(dashmap::DashMap::new);

/// Saves an organization event (when the server keeps them) with fields
/// that only destinations get (the event log has no place for them).
pub async fn save_with_extras(event: &Event, extras: Value, conn: &DbConn) {
    if !crate::CONFIG.org_events_enabled() {
        return;
    }
    EVENT_EXTRAS.insert(event.uuid.as_str().to_owned(), extras);
    if let Err(e) = event.save(conn).await {
        warn!("Couldn't save an event about event streaming: {e:?}");
    }
    // Not left behind if it wasn't streamed.
    EVENT_EXTRAS.remove(event.uuid.as_str());
}

/// What events about a destination say it is: its id, name, kind, and what
/// the console shows of where it sends (never a secret).
pub fn destination_target(d: &EventDestination) -> Value {
    json!({
        "type": "eventDestination",
        "id": d.uuid,
        "name": d.name,
        "kind": d.kind,
        "shownTarget": d.shown_target,
        "enabled": d.enabled,
    })
}

/// The MSP activity log's entries, by the codes destinations get. 9100 to
/// 9199 are PassBundle's own; an entry without a code here gets 9199 with its
/// action named.
fn msp_code(action: &str) -> (i32, &'static str, &'static str) {
    match action {
        "msp_created" => (9100, "Created the MSP", "low"),
        "client_created" => (9101, "Added a client", "low"),
        "client_removed_msp" => (9102, "A client stopped being managed by the MSP", "high"),
        "staff_invited" => (9110, "Invited someone to the MSP's staff", "medium"),
        "staff_added" => (9116, "Added someone to the MSP's staff", "medium"),
        "staff_invite_accepted" => (9111, "Joined the MSP's staff", "medium"),
        "staff_invite_cancelled" => (9112, "Cancelled a staff invitation", "low"),
        "staff_role_changed" => (9113, "Changed a staff member's role", "high"),
        "staff_access_changed" => (9114, "Changed a technician's access", "high"),
        "staff_removed" => (9115, "Removed someone from the MSP's staff", "medium"),
        "member_confirmed" => (9120, "Confirmed a member in a client", "low"),
        "joined_with_install_command" => (9121, "Joined a client with its install command", "low"),
        "install_token_replaced" => (9122, "Replaced a client's install command", "medium"),
        "install_domains_set" => (9123, "Changed which email domains a client's install command takes", "medium"),
        "joining_default_set" => (9124, "Changed how people join clients by default", "medium"),
        "client_joining_set" => (9125, "A client set how people join it", "medium"),
        "client_joining_default" => (9126, "A client went back to the MSP's joining default", "low"),
        "default_policy_changed" => (9130, "Changed a default policy", "medium"),
        "client_policy_default" => (9131, "Put a client back on a default policy", "medium"),
        "template_added" | "template_sent" => (9140, "Shared a template with clients", "low"),
        "template_changed" => (9141, "Changed a shared template", "low"),
        "template_stopped" => (9142, "Stopped sharing a template", "low"),
        "templates_collection_set" => (9143, "Set a client's templates folder", "low"),
        "site_rule_added" => (9150, "Added a site rule for every client", "low"),
        "site_rule_removed" => (9151, "Removed a site rule", "low"),
        "script_token_created" => (9160, "Made a script access token in a client", "high"),
        "script_token_revoked" => (9161, "Revoked a script access token", "medium"),
        "script_token_new_address" => (9162, "A script access token was used from a new address", "medium"),
        "provisioning_token_created" => (9165, "Made a provisioning token for a client", "high"),
        "provisioning_token_replaced" => (9166, "Replaced a client's provisioning token", "high"),
        "provisioning_token_revoked" => (9167, "Revoked a client's provisioning token", "medium"),
        "provisioning_let_in" => (9168, "Let in people the directory added to a client", "medium"),
        "event_stream_added" => (9170, "Added a place the MSP's events are sent", "high"),
        "event_stream_changed" => (9171, "Changed a place the MSP's events are sent", "high"),
        "event_stream_removed" => (9172, "Removed a place the MSP's events are sent", "high"),
        "event_stream_paused" => (9173, "Stopped sending to a place that kept failing", "high"),
        "sso_turned_on" => (9180, "Turned on a client's single sign-on", "high"),
        "sso_turned_off" => (9181, "Turned off a client's single sign-on", "high"),
        "sso_settings_changed" => (9182, "Changed a client's single sign-on settings", "high"),
        "sso_domain_added" => (9183, "Added a domain to a client's single sign-on", "high"),
        "sso_domain_verified" => (9184, "Verified a domain for a client's single sign-on", "high"),
        "sso_domain_removed" => (9185, "Removed a domain from a client's single sign-on", "high"),
        "sso_unlinked" => (9186, "Unlinked someone's single sign-on in a client", "medium"),
        "sso_api_keys_replaced" => (9187, "Replaced a client's members' API keys for single sign-on", "high"),
        _ => (9199, "MSP activity", "low"),
    }
}

/// An MSP activity log entry as the MSP's destinations get it.
pub fn msp_event_json(event: &MspEvent, msp: &Msp) -> Value {
    let (code, name, severity) = msp_code(&event.event);
    let mut out = json!({
        "id": event.uuid,
        "time": format_date(&event.created_at),
        "type": code,
        "name": name,
        "category": "msp",
        "severity": severity,
        "action": event.event,
        "msp": { "id": msp.uuid, "name": msp.name },
        "actor": match &event.actor_uuid {
            Some(id) => json!({ "type": "user", "id": id, "email": event.actor_email }),
            None => json!({ "type": "system" }),
        },
    });
    if let Some(org) = &event.org_uuid {
        out["organization"] = json!({ "id": org, "name": event.org_name });
    }
    if let Some(email) = &event.target_email {
        out["target"] = json!({ "type": "person", "email": email });
    }
    if let Some(detail) = &event.detail {
        out["detail"] = json!(detail);
    }
    if let Some(ip) = &event.ip {
        out["ip"] = json!(ip);
    }
    out
}

/// Copies an MSP activity log entry into the MSP's destinations' queues.
pub async fn stream_msp(event: &MspEvent, conn: &DbConn) {
    let destinations = EventDestination::taking_msp(&event.msp_uuid, conn).await;
    if destinations.is_empty() {
        return;
    }
    let Some(msp) = Msp::find_by_uuid(&event.msp_uuid, conn).await else {
        return;
    };
    let payload = msp_event_json(event, &msp).to_string();
    let (code, _, severity) = msp_code(&event.event);
    let rank = priority(code, severity);
    for d in destinations {
        let queued = Queued {
            event_uuid: &event.uuid,
            payload: payload.clone(),
            priority: rank,
            merge_key: None,
            source: event.org_uuid.as_ref().map(ToString::to_string),
        };
        if let Err(e) = EventDelivery::enqueue(&d, queued, conn).await {
            warn!("Couldn't queue an MSP event for destination {}: {e:?}", d.uuid);
        }
    }
    WAKE.notify_one();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_upstream_event_type_has_a_name() {
        for code in [1000, 1005, 1100, 1107, 1300, 1400, 1500, 1503, 1600, 1700, 1690, 1691, 1692, 1693] {
            assert_ne!(describe(code).1, "Event", "{code}");
        }
        assert_eq!(describe(1005), ("user", "Failed to log in: wrong password", "medium"));
        assert_eq!(describe(1503).0, "member");
        assert_eq!(describe(1131), ("item", "Copied a national ID number", "low"));
        assert_eq!(describe(1189), ("item", "Event", "low"));
        assert_eq!(describe(9101).0, "msp");
    }

    #[test]
    fn retries_wait_longer_each_time_up_to_an_hour() {
        let mut last = TimeDelta::zero();
        for attempts in 1..=7 {
            let wait = backoff(attempts);
            assert!(wait > last, "{attempts}");
            last = TimeDelta::seconds(match attempts {
                1 => 10,
                2 => 30,
                3 => 120,
                4 => 300,
                5 => 900,
                6 => 1800,
                _ => 3600,
            });
            assert!(wait >= last && wait <= last + last / 5, "{attempts}: {wait}");
        }
        assert!(backoff(50) <= TimeDelta::seconds(3600 + 720));
    }

    #[test]
    fn changes_to_who_can_do_what_are_kept_and_floods_merge() {
        // Members, groups, shared folders, settings, policies, destinations,
        // and the MSP's staff: never dropped from a full queue.
        for code in [1300, 1400, 1401, 1500, 1502, 1503, 1508, 1511, 1600, 1601, 1690, 1693, 1700, 9113, 9170, 9173] {
            assert_eq!(priority(code, describe(code).2), KEPT, "{code}");
        }
        // What anyone can make many of isn't kept, and merges.
        for code in [1005, 1006, 1107, 1111, 1114, 1522, 1602] {
            assert!(priority(code, describe(code).2) < KEPT, "{code}");
            assert!(merges(code), "{code}");
        }
        for code in [1000, 1100, 1115, 1116, 1502, 1690] {
            assert!(!merges(code), "{code}");
        }
        assert_eq!(priority(1007, "high"), 2);
        assert_eq!(priority(1101, "low"), 0);
    }

    #[test]
    fn single_sign_on_events_are_described_and_its_changes_kept() {
        assert_eq!(describe(1510), ("member", "Linked an account to single sign-on", "high"));
        assert_eq!(describe(1590), ("member", "Signed in with single sign-on", "low"));
        assert_eq!(describe(1591), ("member", "Single sign-on refused someone", "medium"));
        assert_eq!(describe(1604), ("organization", "Turned on single sign-on", "high"));
        assert_eq!(describe(1605), ("organization", "Turned off single sign-on", "high"));
        assert_eq!(describe(1694), ("organization", "Changed the single sign-on settings", "high"));
        for code in [2000, 2001, 2002] {
            assert_eq!(describe(code).0, "organization", "{code}");
            assert_eq!(describe(code).2, "high", "{code}");
        }
        assert_eq!(describe(2003).2, "low");
        // Settings, domains, and links are never dropped from a full queue.
        for code in [1510, 1604, 1605, 1694, 2000, 2001, 2002] {
            assert_eq!(priority(code, describe(code).2), KEPT, "{code}");
            assert!(!merges(code), "{code}");
        }
        // Sign-ins go by severity, as logins do, and refusals merge, as
        // failed logins do.
        assert_eq!(priority(1590, describe(1590).2), 0);
        assert_eq!(priority(1591, describe(1591).2), 1);
        assert!(!merges(1590));
        assert!(merges(1591));
        // In an MSP's feed, too.
        for (action, code, severity) in [
            ("sso_turned_on", 9180, "high"),
            ("sso_turned_off", 9181, "high"),
            ("sso_settings_changed", 9182, "high"),
            ("sso_domain_added", 9183, "high"),
            ("sso_domain_verified", 9184, "high"),
            ("sso_domain_removed", 9185, "high"),
            ("sso_unlinked", 9186, "medium"),
            ("sso_api_keys_replaced", 9187, "high"),
        ] {
            let (c, _, s) = msp_code(action);
            assert_eq!((c, s), (code, severity), "{action}");
            assert_eq!(priority(c, s), KEPT, "{action}");
        }
    }

    #[test]
    fn events_merge_only_within_one_organization_person_and_minute() {
        let event = |org: &str, user: &str, code: i32| {
            let mut e = Event::new(code, None);
            e.org_uuid = Some(org.to_owned().into());
            e.user_uuid = Some(user.to_owned().into());
            e.act_user_uuid = Some(user.to_owned().into());
            e
        };
        let a = merge_key(&event("org-a", "x", 1005), 100).unwrap();
        // The same person failing to log in to two of an MSP's clients: two
        // events in the MSP's feed, one per client.
        assert_ne!(a, merge_key(&event("org-b", "x", 1005), 100).unwrap());
        assert_ne!(a, merge_key(&event("org-a", "y", 1005), 100).unwrap());
        assert_ne!(a, merge_key(&event("org-a", "x", 1006), 100).unwrap());
        assert_ne!(a, merge_key(&event("org-a", "x", 1005), 101).unwrap());
        assert_eq!(a, merge_key(&event("org-a", "x", 1005), 100).unwrap());
        assert!(merge_key(&event("org-a", "x", 1502), 100).is_none());
    }

    #[test]
    fn merged_events_count_and_keep_a_few_targets_and_addresses() {
        let first = json!({ "id": "e1", "time": "t1", "type": 1107, "target": { "type": "item", "id": "c1" }, "ip": "203.0.113.1" });
        let mut waiting = first.to_string();
        for i in 2..=30 {
            let next = json!({ "id": format!("e{i}"), "time": format!("t{i}"), "type": 1107, "target": { "type": "item", "id": format!("c{}", i % 25) }, "ip": "203.0.113.1" });
            waiting = merge_into(&waiting, &next.to_string()).unwrap();
        }
        let merged: Value = serde_json::from_str(&waiting).unwrap();
        assert_eq!(merged["id"], "e1");
        assert_eq!(merged["count"], 30);
        assert_eq!(merged["time"], "t1");
        assert_eq!(merged["lastTime"], "t30");
        assert_eq!(merged["targets"].as_array().unwrap().len(), 20);
        assert_eq!(merged["ips"], json!(["203.0.113.1"]));
        assert!(merge_into("not json", &first.to_string()).is_none());
    }

    #[test]
    fn msp_entries_carry_their_action_and_no_more_than_the_log_has() {
        let msp = Msp {
            uuid: MspId::from("msp-1".to_owned()),
            name: "Northwind IT".into(),
            created_at: Utc::now().naive_utc(),
        };
        let mut event = MspEvent::new(msp.uuid.clone(), "staff_access_changed");
        event.actor_uuid = Some(UserId::from("user-1".to_owned()));
        event.actor_email = Some("boss@northwind.example".into());
        event.target_email = Some("tech@northwind.example".into());
        event.detail = Some("Admin in Contoso".into());
        let json = msp_event_json(&event, &msp);
        assert_eq!(json["type"], 9114);
        assert_eq!(json["category"], "msp");
        assert_eq!(json["action"], "staff_access_changed");
        assert_eq!(json["severity"], "high");
        assert_eq!(json["actor"]["email"], "boss@northwind.example");
        assert_eq!(json["target"], json!({ "type": "person", "email": "tech@northwind.example" }));
        assert_eq!(json["msp"]["name"], "Northwind IT");
        assert!(json.get("organization").is_none());
        let unknown = msp_event_json(&MspEvent::new(msp.uuid.clone(), "something_new"), &msp);
        assert_eq!(unknown["type"], 9199);
        assert_eq!(unknown["action"], "something_new");
        assert_eq!(unknown["actor"], json!({ "type": "system" }));
    }
}

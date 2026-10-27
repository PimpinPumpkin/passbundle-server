// Keykeeper: reload keys, so a web vault tab stays unlocked across a reload.
//
// Upstream's web vault keeps the user key only in the page's memory, so every
// reload locks it. At a real unlock, a tab now wraps the user key with a new
// random key R, keeps the wrapped user key in its own sessionStorage, and
// gives R to this server. After a reload, the tab asks for R back and unwraps
// the user key. R lives only in this process's memory: never in the database,
// a file, or a log, so a restart forgets every one.
//
// An entry belongs to one account, one device (the session its access token
// is for), and one tab, and only that tab, signed in as that account on that
// device, gets R back. It also needs the tab's reload cookie: a random value
// this server sets when it keeps R (HttpOnly, Secure, SameSite=Strict, a
// session cookie, on the reload endpoints' path only) and keeps only a hash
// of. Page scripts can't read it, and Chrome and Edge encrypt cookies at rest
// with the OS's own key, which sessionStorage doesn't get, so a copy of the
// tab's storage alone no longer opens the vault. It goes when:
// - the tab hasn't checked in for GRACE (the browser closed, or the computer
//   slept), checked whenever an entry is used;
// - the person hasn't used the tab for their vault timeout, as the tab
//   reports it and the organization's Vault lock policy caps it;
// - the tab locks or signs out, and asks to forget it;
// - the tab is closed or navigated away (its page says it's leaving), and no
//   reload asks for R within LEAVING;
// - the account's security stamp changes (a new master password, key
//   rotation, "Deauthorize sessions", an admin's deauthorization) or its
//   devices are removed: see `forget_user`, called from those places.
// Whenever an entry goes and its tab asks again, the answer also expires the
// tab's cookie.
//
// See DESIGN.md, "Staying unlocked across a reload", in the meta repo.

use std::{
    num::NonZeroU32,
    sync::{LazyLock, Once},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use data_encoding::BASE64;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use rocket::{
    Route,
    http::{Cookie, CookieJar, SameSite},
    serde::json::Json,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult},
    auth::{ClientIp, Headers},
    crypto,
    db::{
        DbConn,
        models::{DeviceId, OrgPolicy, OrgPolicyType, UserId},
    },
    error::Error,
};

pub fn routes() -> Vec<Route> {
    routes![keep, check_in, release, leaving, forget]
}

/// R: an AES-256-CBC key with its HMAC-SHA256 key, as upstream's own keys.
const KEY_LEN: usize = 64;
/// R in base64, with padding: 88 characters, decoding to at most 66 bytes.
const KEY_B64_LEN: usize = 88;
/// A tab's id: 16 random bytes, in lowercase hex.
const TAB_ID_LEN: usize = 32;
/// How long a tab may go without checking in. Tabs check in every 30 seconds
/// while open; browsers slow a hidden tab's timers to once a minute.
const GRACE: Duration = Duration::from_secs(120);
/// How long an entry lasts after its page says it's leaving (closed, or
/// navigated away), for the reload that follows to ask for R. A tab closed and
/// reopened, or gone back to, after that finds nothing.
const LEAVING: Duration = Duration::from_secs(15);
/// The longest vault timeout a tab may ask for, in minutes: a year. A tab
/// that stops checking in loses its entry long before.
const MAX_MINUTES: u64 = 365 * 24 * 60;
/// The web vault's wait under "when the computer locks" when the policy
/// doesn't say. The same default as the web vault's.
const DEFAULT_WEB_MINUTES: u64 = 15;
/// The tabs one account can keep at once; a new one replaces the stalest.
const MAX_TABS_PER_ACCOUNT: usize = 20;
/// A page's id, for its beacon: 16 random bytes in lowercase hex, new at
/// every page load.
const PAGE_ID_LEN: usize = 32;
/// How often expired entries are wiped, and the limiters trimmed.
const SWEEP_EVERY: Duration = Duration::from_secs(30);

/// A tab's reload cookie is named for its tab, so tabs signed in apart in one
/// browser each keep their own. `__Secure-` makes browsers take it only with
/// Secure from an https page; `__Host-` would also pin it to the host, but
/// only with a path of "/", and the path is what keeps it off every other
/// request.
const COOKIE_PREFIX: &str = "__Secure-pb-reload-";

fn cookie_name(tab: &str) -> String {
    format!("{COOKIE_PREFIX}{tab}")
}

/// Sent only to the reload endpoints, under the server's own path.
fn cookie_path() -> String {
    format!("{}/api/keykeeper/reload-key", CONFIG.domain_path())
}

/// The reload cookie for a tab: HttpOnly, Secure, SameSite=Strict, the reload
/// endpoints' path, and no Expires or Max-Age, so the browser drops it when it
/// closes (unless it restores its session).
fn reload_cookie(tab: &str, value: String, path: String) -> Cookie<'static> {
    Cookie::build((cookie_name(tab), value)).path(path).http_only(true).secure(true).same_site(SameSite::Strict).build()
}

/// What expires a tab's reload cookie: the same name, path, and attributes,
/// or browsers keep a `__Secure-` cookie.
fn cookie_removal(tab: &str, path: String) -> Cookie<'static> {
    Cookie::build(cookie_name(tab)).path(path).http_only(true).secure(true).same_site(SameSite::Strict).build()
}

/// Expires the tab's reload cookie, if the request carried one.
fn expire_cookie(jar: &CookieJar<'_>, tab: &str) {
    if jar.get(&cookie_name(tab)).is_some() {
        jar.remove(cookie_removal(tab, cookie_path()));
    }
}

/// Every refusal of a tab that has no entry (none kept, a different account,
/// device, or tab, expired, or forgotten) answers the same.
fn not_found() -> Error {
    Error::new_msg("Not found").with_code(404)
}

/// A refused or unreadable request to keep a key.
fn refused() -> Error {
    Error::new_msg("This vault can't stay unlocked across a reload")
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Slot {
    user: UserId,
    device: DeviceId,
    tab: String,
}

/// R, on the heap (always KEY_LEN bytes), so the map moves only a pointer
/// when it grows or removes an entry; wiped when dropped.
type Key = Zeroizing<Box<[u8]>>;

struct Entry {
    /// Whose it is: only this account, on this device, gets R back.
    user: UserId,
    device: DeviceId,
    key: Key,
    /// SHA-256 of the tab's reload cookie, in hex.
    cookie_hash: String,
    /// The page that has R now (the one that kept it, or the last reload's):
    /// only its own leaving counts, not a late beacon from an earlier page.
    page: Option<String>,
    idle_limit: Duration,
    last_active: Instant,
    last_check_in: Instant,
    /// When the tab's page said it was leaving, until a reload asks for R.
    leaving_since: Option<Instant>,
}

impl Entry {
    fn owned_by(&self, slot: &Slot) -> bool {
        self.user == slot.user && self.device == slot.device
    }

    /// Whether a request carried this tab's reload cookie.
    fn cookie_matches(&self, cookie: Option<&str>) -> bool {
        cookie.is_some_and(|value| crypto::ct_eq(&self.cookie_hash, crypto::sha256_hex(value.as_bytes())))
    }

    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_check_in) > GRACE
            || now.saturating_duration_since(self.last_active) >= self.idle_limit
            || self.leaving_since.is_some_and(|since| now.saturating_duration_since(since) > LEAVING)
    }
}

/// The kept keys, by tab id, so a call finds its own entry at once. Each call
/// takes the time, so tests can move it. Every call checks its own entry's
/// expiry; `sweep`, on a timer, wipes the rest.
#[derive(Default)]
struct Store {
    entries: DashMap<String, Entry>,
}

impl Store {
    fn sweep(&self, now: Instant) {
        self.entries.retain(|_, e| !e.expired(now));
    }

    /// Keeps R for a tab. Refused (false) when another account or device
    /// already has an entry under that tab id.
    fn keep(
        &self,
        slot: Slot,
        key: Key,
        cookie_hash: String,
        page: Option<String>,
        idle_limit: Duration,
        now: Instant,
    ) -> bool {
        if self.entries.get(&slot.tab).is_some_and(|e| !e.owned_by(&slot) && !e.expired(now)) {
            return false;
        }
        let mut others: Vec<(String, Instant)> = self
            .entries
            .iter()
            .filter(|e| e.value().user == slot.user && *e.key() != slot.tab && !e.value().expired(now))
            .map(|e| (e.key().clone(), e.value().last_check_in))
            .collect();
        if others.len() >= MAX_TABS_PER_ACCOUNT {
            others.sort_by_key(|(_, at)| *at);
            for (stale, _) in others.iter().take(others.len() + 1 - MAX_TABS_PER_ACCOUNT) {
                self.entries.remove(stale);
            }
        }
        self.entries.insert(
            slot.tab,
            Entry {
                user: slot.user,
                device: slot.device,
                key,
                cookie_hash,
                page,
                idle_limit,
                last_active: now,
                last_check_in: now,
                leaving_since: None,
            },
        );
        true
    }

    /// A tab is still open, last used `idle` ago. Whether its entry stays.
    /// Without the tab's cookie, nothing changes and the answer is the same
    /// as for no entry. A check-in doesn't undo leaving: only a reload does.
    fn check_in(&self, slot: &Slot, cookie: Option<&str>, idle: Duration, idle_limit: Duration, now: Instant) -> bool {
        let Some(mut entry) = self.entries.get_mut(&slot.tab) else {
            return false;
        };
        if !entry.owned_by(slot) || !entry.cookie_matches(cookie) {
            return false;
        }
        let gone = entry.expired(now) || {
            entry.last_check_in = now;
            entry.idle_limit = idle_limit;
            // The tab only says how long ago it was last used, so its clock
            // being off doesn't matter; this server's clock says when.
            match now.checked_sub(idle) {
                Some(used) => {
                    entry.last_active = used;
                    entry.expired(now)
                }
                None => true,
            }
        };
        drop(entry);
        if gone {
            self.entries.remove(&slot.tab);
        }
        !gone
    }

    /// R, for the tab it belongs to, while its entry lasts, under a policy
    /// cap that may have shrunk since the tab's last check-in. Asking isn't
    /// use: only the tab's check-ins say when it was last used. It is the
    /// reload a leaving page was waiting for, so the entry stays, and the
    /// asking page is now the entry's page.
    fn release(
        &self,
        slot: &Slot,
        cookie: Option<&str>,
        page: Option<String>,
        cap: Option<Duration>,
        now: Instant,
    ) -> Option<Key> {
        let mut entry = self.entries.get_mut(&slot.tab)?;
        if !entry.owned_by(slot) || !entry.cookie_matches(cookie) {
            return None;
        }
        if let Some(cap) = cap {
            entry.idle_limit = entry.idle_limit.min(cap);
        }
        if entry.expired(now) {
            drop(entry);
            self.entries.remove(&slot.tab);
            return None;
        }
        entry.last_check_in = now;
        entry.leaving_since = None;
        entry.page = page;
        Some(entry.key.clone())
    }

    /// The tab's page is going (closed, navigated away, or reloading): unless
    /// a reload asks for R within LEAVING, the entry ends. Only the tab's own
    /// cookie, from the page that has R now, can say so, and it only ever
    /// shortens an entry: the first leaving's deadline stands. Whether it
    /// found one.
    fn leaving(&self, tab: &str, cookie: Option<&str>, page: Option<&str>, now: Instant) -> bool {
        let Some(mut entry) = self.entries.get_mut(tab) else {
            return false;
        };
        if !entry.cookie_matches(cookie) || entry.page.as_deref() != page {
            return false;
        }
        entry.leaving_since.get_or_insert(now);
        true
    }

    fn forget(&self, slot: &Slot) {
        self.entries.remove_if(&slot.tab, |_, e| e.owned_by(slot));
    }

    /// Whether any account keeps an entry for this tab id.
    fn has_tab(&self, tab: &str, now: Instant) -> bool {
        self.entries.get(tab).is_some_and(|e| !e.expired(now))
    }

    fn forget_user(&self, user: &UserId) {
        self.entries.retain(|_, e| e.user != *user);
    }
}

static STORE: LazyLock<Store> = LazyLock::new(Store::default);

/// Forgets every tab's key for an account at once: called when its security
/// stamp changes or its devices are removed, which also end its sessions.
pub fn forget_user(user: &UserId) {
    STORE.forget_user(user);
}

type Limiter<K> = RateLimiter<K, DashMapStateStore<K>, DefaultClock>;

/// Each tab's calls: a check-in twice a minute, and reloads now and then.
static LIMITER_TAB: LazyLock<Limiter<(UserId, String)>> = LazyLock::new(|| {
    RateLimiter::keyed(
        Quota::with_period(Duration::from_secs(3))
            .expect("Non-zero period")
            .allow_burst(NonZeroU32::new(20).expect("Non-zero burst")),
    )
});

/// Each account's calls, all its tabs together: a technician with twenty
/// tabs open checks in 40 times a minute.
static LIMITER_ACCOUNT: LazyLock<Limiter<UserId>> = LazyLock::new(|| {
    RateLimiter::keyed(
        Quota::with_period(Duration::from_millis(500))
            .expect("Non-zero period")
            .allow_burst(NonZeroU32::new(60).expect("Non-zero burst")),
    )
});

/// Leaving beacons that match no entry, per network address: they come
/// without a session, so they can't count per account. Beacons that match an
/// entry (they carry its cookie) aren't counted at all, so nothing here can
/// keep a real tab's leaving from counting, and this is apart from the
/// server's shared limit for requests without a session, which sign-ups,
/// password hints, and other features draw on.
static LIMITER_LEAVING: LazyLock<Limiter<std::net::IpAddr>> = LazyLock::new(|| {
    RateLimiter::keyed(
        Quota::with_period(Duration::from_millis(200))
            .expect("Non-zero period")
            .allow_burst(NonZeroU32::new(300).expect("Non-zero burst")),
    )
});

fn check_limit(user: &UserId, tab: &str) -> EmptyResult {
    start_sweeping();
    if LIMITER_ACCOUNT.check_key(user).is_err() || LIMITER_TAB.check_key(&(user.clone(), tab.to_owned())).is_err() {
        return Err(Error::new_msg("Too many requests").with_code(429));
    }
    Ok(())
}

/// Wipes expired entries, and trims the limiters' memory, every SWEEP_EVERY,
/// from the first call on.
fn start_sweeping() {
    static SWEEPER: Once = Once::new();
    SWEEPER.call_once(|| {
        tokio::spawn(async {
            let mut every = tokio::time::interval(SWEEP_EVERY);
            loop {
                every.tick().await;
                STORE.sweep(Instant::now());
                LIMITER_TAB.retain_recent();
                LIMITER_ACCOUNT.retain_recent();
                LIMITER_LEAVING.retain_recent();
            }
        });
    });
}

fn hex_id(id: &str, len: usize) -> bool {
    id.len() == len && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_tab(tab: &str) -> bool {
    hex_id(tab, TAB_ID_LEN)
}

/// A page id, if one was sent and it's well formed.
fn page_id(page: Option<&str>) -> Result<Option<String>, ()> {
    match page {
        None => Ok(None),
        Some(page) if hex_id(page, PAGE_ID_LEN) => Ok(Some(page.to_owned())),
        Some(_) => Err(()),
    }
}

fn slot(headers: &Headers, tab: String) -> Result<Slot, Error> {
    if !valid_tab(&tab) {
        return Err(not_found());
    }
    Ok(Slot {
        user: headers.user.uuid.clone(),
        device: headers.device.uuid.clone(),
        tab,
    })
}

/// What Vault lock policies allow a reload key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Allowed {
    /// None at all.
    Refused,
    /// A wait of at most this many minutes.
    UpTo(u64),
    /// Whatever wait the person chose.
    Unlimited,
}

/// What one Vault lock policy allows a reload key. Refused: "immediately" and upstream's "on app restart" (a reload has to
/// lock), signing out at the timeout (a reload would sign out in the web
/// vault, so nothing is kept), and `webReload: false`, which turns reload
/// keys off. The data was checked when saved (keykeeper_vault_lock).
fn policy_minutes(data: &Value) -> Allowed {
    let present = |key: &str| data.get(key).filter(|v| !v.is_null());
    if present("webReload").and_then(Value::as_bool) == Some(false)
        || present("action").and_then(Value::as_str) == Some("logOut")
    {
        return Allowed::Refused;
    }
    match present("type").and_then(Value::as_str) {
        None | Some("custom") => present("minutes").and_then(Value::as_u64).map_or(Allowed::Unlimited, Allowed::UpTo),
        Some("onSystemLock") => {
            Allowed::UpTo(present("webMinutes").and_then(Value::as_u64).unwrap_or(DEFAULT_WEB_MINUTES))
        }
        Some("immediately" | "onAppRestart") => Allowed::Refused,
        Some(_) => Allowed::Unlimited,
    }
}

/// The strictest of several policies: refused when any refuses a reload key,
/// otherwise the shortest cap, if any.
fn strictest<'a>(policies: impl IntoIterator<Item = &'a Value>) -> Allowed {
    let mut allowed = Allowed::Unlimited;
    for data in policies {
        allowed = match (allowed, policy_minutes(data)) {
            (_, Allowed::Refused) => return Allowed::Refused,
            (Allowed::UpTo(a), Allowed::UpTo(b)) => Allowed::UpTo(a.min(b)),
            (Allowed::Unlimited, other) => other,
            (current, Allowed::Unlimited) => current,
            (Allowed::Refused, _) => Allowed::Refused,
        };
    }
    allowed
}

/// The strictest of the account's Vault lock policies, from every
/// organization it has joined, owners and MSP staff included: unlike the
/// policy's other effects, which exempt owners as upstream does, refusing a
/// reload key only means one more master password prompt, and our apps' lock
/// policy binds admins and MSP staff too.
async fn longest_wait(user: &UserId, conn: &DbConn) -> Allowed {
    let policies: Vec<Value> =
        OrgPolicy::find_confirmed_by_user_and_active_policy(user, OrgPolicyType::MaximumVaultTimeout, conn)
            .await
            .iter()
            .map(|policy| serde_json::from_str::<Value>(&policy.data).unwrap_or(Value::Null))
            .collect();
    strictest(&policies)
}

/// The wait a tab asked for, capped by policy, or `None` when it can't have
/// a reload key at all.
async fn idle_limit(minutes: u64, headers: &Headers, conn: &DbConn) -> Option<Duration> {
    if !(1..=MAX_MINUTES).contains(&minutes) {
        return None;
    }
    match longest_wait(&headers.user.uuid, conn).await {
        Allowed::Refused => None,
        Allowed::UpTo(cap) => Some(Duration::from_secs(60 * cap.min(minutes))),
        Allowed::Unlimited => Some(Duration::from_secs(60 * minutes)),
    }
}

/// The body that carries R, read by hand so that no parse error can ever
/// put it in a log. R's text is wiped when dropped.
struct KeepData {
    tab_id: String,
    page: Option<String>,
    key: Zeroizing<String>,
    timeout_minutes: u64,
}

fn read_keep(body: String) -> Option<KeepData> {
    let body = Zeroizing::new(body);
    let mut value = serde_json::from_str::<Value>(&body).ok()?;
    let key = match value.get_mut("key").map(Value::take) {
        Some(Value::String(k)) => Zeroizing::new(k),
        _ => return None,
    };
    let page = match value.get("pageId") {
        None | Some(Value::Null) => None,
        Some(page) => Some(page.as_str()?.to_owned()),
    };
    Some(KeepData {
        tab_id: value.get("tabId")?.as_str()?.to_owned(),
        page,
        key,
        timeout_minutes: value.get("timeoutMinutes")?.as_u64()?,
    })
}

/// R from its base64, decoded into heap buffers that are wiped when dropped.
fn decode_key(b64: &str) -> Option<Key> {
    let input = b64.as_bytes();
    if input.len() != KEY_B64_LEN {
        return None;
    }
    let room = BASE64.decode_len(input.len()).ok()?;
    let mut buffer: Key = Zeroizing::new(vec![0u8; room].into_boxed_slice());
    let written = BASE64.decode_mut(input, &mut buffer).ok()?;
    if written != KEY_LEN {
        return None;
    }
    let mut key: Key = Zeroizing::new(vec![0u8; KEY_LEN].into_boxed_slice());
    key.copy_from_slice(&buffer[..KEY_LEN]);
    Some(key)
}

/// Keeps a tab's R, at a real unlock, and sets the tab's reload cookie. A new
/// one for the same tab replaces both.
#[post("/keykeeper/reload-key", data = "<body>")]
async fn keep(body: String, headers: Headers, conn: DbConn, jar: &CookieJar<'_>) -> EmptyResult {
    let data = read_keep(body).ok_or_else(refused)?;
    if !valid_tab(&data.tab_id) {
        return Err(refused());
    }
    let page = page_id(data.page.as_deref()).map_err(|()| refused())?;
    check_limit(&headers.user.uuid, &data.tab_id)?;
    let key = decode_key(&data.key).ok_or_else(refused)?;
    let limit = idle_limit(data.timeout_minutes, &headers, &conn).await.ok_or_else(refused)?;
    let slot = slot(&headers, data.tab_id.clone())?;
    let now = Instant::now();

    // Reload cookies of tabs nothing is kept for any more (closed without
    // locking, or expired) go, so they don't pile up in the browser.
    let stale: Vec<String> = jar
        .iter()
        .filter_map(|c| c.name().strip_prefix(COOKIE_PREFIX).map(str::to_owned))
        .filter(|tab| *tab != data.tab_id && !STORE.has_tab(tab, now))
        .collect();
    for tab in stale {
        jar.remove(cookie_removal(&tab, cookie_path()));
    }

    let value = Zeroizing::new(data_encoding::BASE64URL_NOPAD.encode(&crypto::get_random_bytes::<32>()));
    if !STORE.keep(slot, key, crypto::sha256_hex(value.as_bytes()), page, limit, now) {
        return Err(refused());
    }
    jar.add(reload_cookie(&data.tab_id, value.to_string(), cookie_path()));
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckInData {
    tab_id: String,
    idle_seconds: u64,
    timeout_minutes: u64,
}

/// An open tab, every 30 seconds: how long since the person last used it,
/// and their vault timeout now. Not found once the entry is gone.
#[post("/keykeeper/reload-key/check-in", data = "<data>")]
async fn check_in(data: Json<CheckInData>, headers: Headers, conn: DbConn, jar: &CookieJar<'_>) -> EmptyResult {
    let data = data.into_inner();
    let slot = slot(&headers, data.tab_id)?;
    check_limit(&slot.user, &slot.tab)?;
    let Some(limit) = idle_limit(data.timeout_minutes, &headers, &conn).await else {
        STORE.forget(&slot);
        expire_cookie(jar, &slot.tab);
        return Err(not_found());
    };
    // A wait longer than any allowed is past every limit anyway.
    let idle = Duration::from_secs(data.idle_seconds.min(MAX_MINUTES * 60));
    let cookie = jar.get(&cookie_name(&slot.tab)).map(|c| c.value().to_owned());
    if STORE.check_in(&slot, cookie.as_deref(), idle, limit, Instant::now()) {
        Ok(())
    } else {
        expire_cookie(jar, &slot.tab);
        Err(not_found())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TabData {
    tab_id: String,
    /// The asking page's id (release).
    page_id: Option<String>,
}

/// R, after a reload, for the tab it belongs to.
#[post("/keykeeper/reload-key/release", data = "<data>")]
async fn release(data: Json<TabData>, headers: Headers, conn: DbConn, jar: &CookieJar<'_>) -> JsonResult {
    let data = data.into_inner();
    let page = page_id(data.page_id.as_deref()).map_err(|()| not_found())?;
    let slot = slot(&headers, data.tab_id)?;
    check_limit(&slot.user, &slot.tab)?;
    // A policy that now refuses reload keys, or caps them lower (one the
    // tab's account just joined, or just changed), applies at once.
    let cap = match longest_wait(&headers.user.uuid, &conn).await {
        Allowed::Refused => {
            STORE.forget(&slot);
            expire_cookie(jar, &slot.tab);
            return Err(not_found());
        }
        Allowed::UpTo(minutes) => Some(Duration::from_secs(60 * minutes)),
        Allowed::Unlimited => None,
    };
    let cookie = jar.get(&cookie_name(&slot.tab)).map(|c| Zeroizing::new(c.value().to_owned()));
    let Some(key) = STORE.release(&slot, cookie.as_deref().map(String::as_str), page, cap, Instant::now()) else {
        expire_cookie(jar, &slot.tab);
        return Err(not_found());
    };
    Ok(Json(json!({
        "object": "keykeeperReloadKey",
        "key": BASE64.encode(&key[..]),
    })))
}

/// The tab's page is going away (`pagehide`: closed, navigated elsewhere, or
/// reloading), sent as a beacon that outlives it, so without an access token:
/// the tab's cookie, and the page's id, are what say so, and it can only
/// shorten the entry. A reload asks for R within LEAVING; a closed tab
/// reopened later, or a Back to it, finds nothing. Answers the same whether
/// there was one. Only beacons that match nothing count against a limit, a
/// limit of their own.
#[post("/keykeeper/reload-key/leaving", data = "<body>")]
fn leaving(body: String, ip: ClientIp, jar: &CookieJar<'_>) -> EmptyResult {
    start_sweeping();
    let ip = ip.ip;
    let parsed = serde_json::from_str::<Value>(&{ body }).ok();
    let field = |key: &str| parsed.as_ref().and_then(|v| v.get(key)).and_then(Value::as_str).map(str::to_owned);
    let found = match (field("tabId"), page_id(field("pageId").as_deref())) {
        (Some(tab), Ok(page)) if valid_tab(&tab) => {
            let cookie = jar.get(&cookie_name(&tab)).map(|c| Zeroizing::new(c.value().to_owned()));
            STORE.leaving(&tab, cookie.as_deref().map(String::as_str), page.as_deref(), Instant::now())
        }
        _ => false,
    };
    if !found && LIMITER_LEAVING.check_key(&ip).is_err() {
        return Err(Error::new_msg("Too many requests").with_code(429));
    }
    Ok(())
}

/// The tab locked or signed out: R, the cookie's hash, and the cookie go.
/// Answers the same whether there was one.
#[post("/keykeeper/reload-key/forget", data = "<data>")]
fn forget(data: Json<TabData>, headers: Headers, jar: &CookieJar<'_>) -> EmptyResult {
    let tab = data.into_inner().tab_id;
    if !valid_tab(&tab) {
        return Ok(());
    }
    check_limit(&headers.user.uuid, &tab)?;
    expire_cookie(jar, &tab);
    STORE.forget(&Slot {
        user: headers.user.uuid,
        device: headers.device.uuid,
        tab,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(user: &str, device: &str, tab: &str) -> Slot {
        Slot {
            user: UserId::from(user.to_owned()),
            device: DeviceId::from(device.to_owned()),
            tab: tab.to_owned(),
        }
    }

    /// The tab's reload cookie in these tests, and its hash.
    const COOKIE: &str = "the-tabs-cookie";

    fn hash() -> String {
        crypto::sha256_hex(COOKIE.as_bytes())
    }

    /// The store's calls, with the tab's own cookie.
    impl Store {
        fn check_in_with(&self, slot: &Slot, idle: Duration, idle_limit: Duration, now: Instant) -> bool {
            self.check_in(slot, Some(COOKIE), idle, idle_limit, now)
        }

        fn release_with(&self, slot: &Slot, cap: Option<Duration>, now: Instant) -> Option<Key> {
            self.release(slot, Some(COOKIE), None, cap, now)
        }
    }

    fn key(byte: u8) -> Key {
        Zeroizing::new(vec![byte; KEY_LEN].into_boxed_slice())
    }

    const TAB: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_TAB: &str = "1123456789abcdef0123456789abcdef";
    const THIRD_TAB: &str = "2123456789abcdef0123456789abcdef";
    const PAGE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NEXT_PAGE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn only_the_same_account_device_and_tab_gets_it_back() {
        let store = Store::default();
        let now = Instant::now();
        let mine = at("alice", "laptop", TAB);
        store.keep(mine.clone(), key(7), hash(), None, 15 * MIN, now);

        assert_eq!(store.release_with(&mine, None, now).map(|k| k[0]), Some(7));
        assert!(store.release_with(&at("bob", "laptop", TAB), None, now).is_none());
        assert!(store.release_with(&at("alice", "phone", TAB), None, now).is_none());
        assert!(store.release_with(&at("alice", "laptop", "ffffffffffffffffffffffffffffffff"), None, now).is_none());
        // Asking doesn't use it up: a second reload works too.
        assert!(store.release_with(&mine, None, now).is_some());
    }

    #[test]
    fn only_the_tabs_cookie_gets_it_back_and_a_wrong_one_changes_nothing() {
        let store = Store::default();
        let now = Instant::now();
        let tab = at("alice", "laptop", TAB);
        store.keep(tab.clone(), key(7), hash(), None, 15 * MIN, now);

        for cookie in [None, Some(""), Some("another-value"), Some("THE-TABS-COOKIE")] {
            assert!(store.release(&tab, cookie, None, None, now).is_none(), "{cookie:?}");
            assert!(!store.check_in(&tab, cookie, Duration::ZERO, 15 * MIN, now), "{cookie:?}");
        }
        // Still there for the tab itself, with its cookie.
        assert_eq!(store.release(&tab, Some(COOKIE), None, None, now).map(|k| k[0]), Some(7));
        assert!(store.check_in(&tab, Some(COOKIE), Duration::ZERO, 15 * MIN, now));
        assert!(store.has_tab(TAB, now));
        store.forget(&tab);
        assert!(!store.has_tab(TAB, now));
    }

    #[test]
    fn the_reload_cookie_is_http_only_secure_strict_on_the_reload_path_for_the_session() {
        let cookie = reload_cookie(TAB, "value".to_owned(), "/api/keykeeper/reload-key".to_owned());
        assert_eq!(cookie.name(), format!("__Secure-pb-reload-{TAB}"));
        assert_eq!(cookie.value(), "value");
        assert_eq!(cookie.path(), Some("/api/keykeeper/reload-key"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.domain(), None);
        assert_eq!(cookie.max_age(), None);
        assert!(cookie.expires().is_none());
        let header = cookie.to_string();
        for part in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/api/keykeeper/reload-key"] {
            assert!(header.contains(part), "{header}");
        }
        assert!(!header.contains("Max-Age") && !header.contains("Expires"), "{header}");

        // The removal keeps the name, path, and Secure, so browsers take it.
        let mut removal = cookie_removal(TAB, "/vault/api/keykeeper/reload-key".to_owned());
        removal.make_removal();
        let header = removal.to_string();
        assert!(header.starts_with(&format!("__Secure-pb-reload-{TAB}=;")), "{header}");
        for part in ["Secure", "Path=/vault/api/keykeeper/reload-key", "Max-Age=0"] {
            assert!(header.contains(part), "{header}");
        }
    }

    #[test]
    fn a_tab_that_stops_checking_in_loses_it_after_the_grace() {
        let store = Store::default();
        let now = Instant::now();
        let tab = at("alice", "laptop", TAB);
        store.keep(tab.clone(), key(1), hash(), None, 60 * MIN, now);

        // Checking in keeps it, past the first grace.
        assert!(store.check_in_with(&tab, Duration::ZERO, 60 * MIN, now + 100 * Duration::from_secs(1)));
        assert!(store.release_with(&tab, None, now + 200 * Duration::from_secs(1)).is_some());
        // Then nothing for longer than the grace: gone.
        assert!(
            store
                .release_with(&tab, None, now + 200 * Duration::from_secs(1) + GRACE + Duration::from_secs(1))
                .is_none()
        );
        assert!(store.entries.is_empty());
    }

    #[test]
    fn a_tab_unused_for_its_timeout_loses_it() {
        let store = Store::default();
        let now = Instant::now();
        let tab = at("alice", "laptop", TAB);
        store.keep(tab.clone(), key(1), hash(), None, 5 * MIN, now);

        // Used 10 seconds before each check-in: stays, well past 5 minutes.
        let mut t = now;
        for _ in 0..20 {
            t += Duration::from_secs(30);
            assert!(store.check_in_with(&tab, Duration::from_secs(10), 5 * MIN, t));
        }
        // Then the person stops: still checking in, but not used since.
        let last_use = t.checked_sub(Duration::from_secs(10)).expect("later than ten seconds after boot");
        for _ in 0..9 {
            t += Duration::from_secs(30);
            assert!(store.check_in_with(&tab, t - last_use, 5 * MIN, t), "{:?}", t - last_use);
        }
        // Five minutes after the last use: gone.
        t += Duration::from_secs(30);
        assert!(!store.check_in_with(&tab, t - last_use, 5 * MIN, t));
        assert!(store.release_with(&tab, None, t).is_none());
    }

    #[test]
    fn the_tab_says_when_it_was_last_used() {
        let store = Store::default();
        let now = Instant::now();
        let tab = at("alice", "laptop", TAB);
        store.keep(tab.clone(), key(1), hash(), None, 5 * MIN, now);
        let s = Duration::from_secs;
        assert!(store.check_in_with(&tab, Duration::ZERO, 5 * MIN, now + s(90)));
        assert!(store.check_in_with(&tab, s(100), 5 * MIN, now + s(120)));
        assert!(store.check_in_with(&tab, s(299), 5 * MIN, now + s(150)));
        assert!(!store.check_in_with(&tab, s(300), 5 * MIN, now + s(180)));

        // A smaller limit applies at once: a minute unused is past one.
        store.keep(tab.clone(), key(1), hash(), None, 5 * MIN, now);
        assert!(!store.check_in_with(&tab, MIN, MIN, now + s(30)));
    }

    #[test]
    fn a_tabs_clock_moving_forward_ends_it() {
        let store = Store::default();
        let now = Instant::now();
        let tab = at("alice", "laptop", TAB);
        store.keep(tab.clone(), key(1), hash(), None, MIN, now);
        // Its next check-in says it hasn't been used for 20 minutes.
        assert!(!store.check_in_with(&tab, 20 * MIN, MIN, now + Duration::from_secs(30)));
        assert!(store.release_with(&tab, None, now + Duration::from_secs(31)).is_none());
    }

    #[test]
    fn forgetting_a_tab_or_an_account() {
        let store = Store::default();
        let now = Instant::now();
        let a = at("alice", "laptop", TAB);
        let b = at("alice", "desktop", OTHER_TAB);
        let c = at("bob", "laptop", THIRD_TAB);
        for s in [&a, &b, &c] {
            store.keep(s.clone(), key(1), hash(), None, 15 * MIN, now);
        }
        // Only its owner forgets it.
        store.forget(&at("bob", "laptop", TAB));
        assert!(store.release_with(&a, None, now).is_some());
        store.forget(&a);
        assert!(store.release_with(&a, None, now).is_none());
        assert!(store.release_with(&b, None, now).is_some());
        store.forget_user(&UserId::from("alice".to_owned()));
        assert!(store.release_with(&b, None, now).is_none());
        assert!(store.release_with(&c, None, now).is_some());
    }

    #[test]
    fn another_account_cant_take_a_tab_id_thats_in_use() {
        let store = Store::default();
        let now = Instant::now();
        assert!(store.keep(at("alice", "laptop", TAB), key(1), hash(), None, 15 * MIN, now));
        assert!(!store.keep(at("bob", "laptop", TAB), key(2), hash(), None, 15 * MIN, now));
        assert!(!store.keep(at("alice", "phone", TAB), key(2), hash(), None, 15 * MIN, now));
        assert_eq!(store.release_with(&at("alice", "laptop", TAB), None, now).map(|k| k[0]), Some(1));
        // The same tab keeping a new R replaces it; an expired one is free.
        assert!(store.keep(at("alice", "laptop", TAB), key(3), hash(), None, MIN, now));
        assert!(store.keep(at("bob", "laptop", TAB), key(4), hash(), None, MIN, now + 2 * MIN));
    }

    #[test]
    fn an_account_keeps_a_bounded_number_of_tabs() {
        let store = Store::default();
        let now = Instant::now();
        for i in 0..(MAX_TABS_PER_ACCOUNT + 5) {
            let t = now + Duration::from_secs(i as u64);
            store.keep(at("alice", "laptop", &format!("{i:032x}")), key(1), hash(), None, 15 * MIN, t);
        }
        assert_eq!(store.entries.len(), MAX_TABS_PER_ACCOUNT);
        // The stalest went; the newest stayed.
        let later = now + Duration::from_secs(60);
        assert!(store.release_with(&at("alice", "laptop", &format!("{:032x}", 0)), None, later).is_none());
        let newest = format!("{:032x}", MAX_TABS_PER_ACCOUNT + 4);
        assert!(store.release_with(&at("alice", "laptop", &newest), None, later).is_some());
    }

    #[test]
    fn a_policy_cap_that_shrank_applies_at_the_next_reload() {
        let store = Store::default();
        let now = Instant::now();
        let tab = at("alice", "laptop", TAB);
        store.keep(tab.clone(), key(1), hash(), None, 15 * MIN, now);
        // 90 seconds unused: within 15 minutes and a new cap of 5, past one of 1.
        let later = now + Duration::from_secs(90);
        assert!(store.release_with(&tab, Some(5 * MIN), later).is_some());
        assert!(store.release_with(&tab, Some(MIN), later).is_none());
        assert!(store.entries.is_empty());
    }

    #[test]
    fn the_vault_lock_policy_caps_or_refuses_it() {
        assert_eq!(policy_minutes(&json!({ "type": "custom", "minutes": 30, "action": "lock" })), Allowed::UpTo(30));
        assert_eq!(policy_minutes(&json!({ "minutes": 240 })), Allowed::UpTo(240));
        assert_eq!(policy_minutes(&json!({ "type": "onSystemLock", "minutes": null })), Allowed::UpTo(15));
        assert_eq!(policy_minutes(&json!({ "type": "onSystemLock", "webMinutes": 1 })), Allowed::UpTo(1));
        assert_eq!(policy_minutes(&json!({ "type": "never" })), Allowed::Unlimited);
        assert_eq!(policy_minutes(&json!({ "type": "immediately" })), Allowed::Refused);
        assert_eq!(policy_minutes(&json!({ "type": "onAppRestart" })), Allowed::Refused);
        // Signing out at the timeout, or reload keys turned off, refuses it
        // whatever the type.
        assert_eq!(policy_minutes(&json!({ "type": "custom", "minutes": 30, "action": "logOut" })), Allowed::Refused);
        assert_eq!(policy_minutes(&json!({ "type": "onSystemLock", "action": "logOut" })), Allowed::Refused);
        assert_eq!(policy_minutes(&json!({ "type": "onSystemLock", "webReload": false })), Allowed::Refused);
        assert_eq!(policy_minutes(&json!({ "type": "never", "webReload": false })), Allowed::Refused);
        assert_eq!(policy_minutes(&json!({ "type": "custom", "minutes": 30, "webReload": true })), Allowed::UpTo(30));
        assert_eq!(policy_minutes(&json!({ "minutes": 30, "action": "lock", "webReload": null })), Allowed::UpTo(30));
    }

    #[test]
    fn several_policies_give_the_strictest() {
        let policies = |list: Vec<Value>| strictest(&list);
        assert_eq!(policies(vec![]), Allowed::Unlimited);
        assert_eq!(policies(vec![json!({ "type": "never" })]), Allowed::Unlimited);
        assert_eq!(
            policies(vec![
                json!({ "type": "custom", "minutes": 60 }),
                json!({ "type": "onSystemLock", "webMinutes": 5 }),
                json!({ "type": "never" }),
                json!({ "minutes": 10 }),
            ]),
            Allowed::UpTo(5)
        );
        assert_eq!(policies(vec![json!({ "type": "onSystemLock" }), json!({ "minutes": 30 })]), Allowed::UpTo(15));
        // One that refuses wins over any cap.
        assert_eq!(
            policies(vec![json!({ "type": "custom", "minutes": 60 }), json!({ "type": "immediately" })]),
            Allowed::Refused
        );
        assert_eq!(
            policies(vec![json!({ "minutes": 60 }), json!({ "type": "onSystemLock", "webReload": false })]),
            Allowed::Refused
        );
        assert_eq!(
            policies(vec![json!({ "minutes": 60, "action": "logOut" }), json!({ "minutes": 5 })]),
            Allowed::Refused
        );
    }

    #[test]
    fn a_page_leaving_ends_the_entry_unless_a_reload_asks_soon() {
        let store = Store::default();
        let now = Instant::now();
        let s = Duration::from_secs;
        let tab = at("alice", "laptop", TAB);
        store.keep(tab.clone(), key(1), hash(), None, 15 * MIN, now);

        // A reload: the page leaves, and the new one asks within the window.
        assert!(store.leaving(TAB, Some(COOKIE), None, now + s(10)));
        assert!(store.release_with(&tab, None, now + s(14)).is_some());
        // That ended the leaving: later is fine.
        assert!(store.check_in_with(&tab, Duration::ZERO, 15 * MIN, now + s(60)));

        // Closed: nothing asks; a check-in doesn't count, a late reopen finds nothing.
        assert!(store.leaving(TAB, Some(COOKIE), None, now + s(70)));
        assert!(store.check_in_with(&tab, Duration::ZERO, 15 * MIN, now + s(80)));
        assert!(store.release_with(&tab, None, now + s(70) + LEAVING + s(1)).is_none());
        assert!(store.entries.is_empty());

        // Without the tab's cookie, or with another, leaving changes nothing.
        store.keep(tab.clone(), key(1), hash(), None, 15 * MIN, now);
        assert!(!store.leaving(TAB, None, None, now + s(10)));
        assert!(!store.leaving(TAB, Some("another"), None, now + s(10)));
        assert!(!store.leaving("ffffffffffffffffffffffffffffffff", Some(COOKIE), None, now + s(10)));
        assert!(store.release_with(&tab, None, now + s(10) + LEAVING + s(1)).is_some());
    }

    #[test]
    fn repeated_leaving_cant_push_the_deadline_back() {
        let store = Store::default();
        let now = Instant::now();
        let s = Duration::from_secs;
        let tab = at("alice", "laptop", TAB);
        store.keep(tab.clone(), key(1), hash(), None, 15 * MIN, now);
        assert!(store.leaving(TAB, Some(COOKIE), None, now + s(10)));
        assert!(store.leaving(TAB, Some(COOKIE), None, now + s(20)));
        // The first deadline stands: 10 + 15 seconds.
        assert!(store.release_with(&tab, None, now + s(10) + LEAVING + s(1)).is_none());
    }

    #[test]
    fn a_late_leaving_from_an_earlier_page_doesnt_end_the_reloaded_one() {
        let store = Store::default();
        let now = Instant::now();
        let s = Duration::from_secs;
        let tab = at("alice", "laptop", TAB);
        store.keep(tab.clone(), key(1), hash(), Some(PAGE.to_owned()), 15 * MIN, now);

        // The first page reloads: it leaves, and the next page asks.
        assert!(store.leaving(TAB, Some(COOKIE), Some(PAGE), now + s(10)));
        assert!(store.release(&tab, Some(COOKIE), Some(NEXT_PAGE.to_owned()), None, now + s(11)).is_some());
        // A late beacon from the first page changes nothing now.
        assert!(!store.leaving(TAB, Some(COOKIE), Some(PAGE), now + s(12)));
        assert!(!store.leaving(TAB, Some(COOKIE), None, now + s(12)));
        assert!(store.release(&tab, Some(COOKIE), Some(NEXT_PAGE.to_owned()), None, now + s(60)).is_some());
        // The page that has it now still can.
        assert!(store.leaving(TAB, Some(COOKIE), Some(NEXT_PAGE), now + s(61)));
        assert!(store.check_in_with(&tab, Duration::ZERO, 15 * MIN, now + s(70)));
        assert!(store.release_with(&tab, None, now + s(61) + LEAVING + s(1)).is_none());
    }

    #[test]
    fn the_sweep_wipes_every_expired_entry() {
        let store = Store::default();
        let now = Instant::now();
        store.keep(at("alice", "laptop", TAB), key(1), hash(), None, MIN, now);
        store.keep(at("bob", "laptop", OTHER_TAB), key(2), hash(), None, 15 * MIN, now);
        store.sweep(now + Duration::from_secs(61));
        assert_eq!(store.entries.len(), 1);
        assert!(!store.has_tab(OTHER_TAB, now + GRACE + Duration::from_secs(1)));
        store.sweep(now + GRACE + Duration::from_secs(1));
        assert!(store.entries.is_empty());
    }

    #[test]
    fn the_body_carrying_the_key_is_read_strictly() {
        let good = r#"{"tabId":"0123456789abcdef0123456789abcdef","key":"a2V5","timeoutMinutes":15}"#;
        let data = read_keep(good.to_owned()).expect("readable");
        assert_eq!(data.tab_id, TAB);
        assert_eq!(data.key.as_str(), "a2V5");
        assert_eq!(data.timeout_minutes, 15);
        for bad in [
            "",
            "{",
            r#"{"tabId":"x","key":5,"timeoutMinutes":15}"#,
            r#"{"tabId":"x","key":"a2V5","timeoutMinutes":-1}"#,
            r#"{"tabId":"x","key":"a2V5","timeoutMinutes":"15"}"#,
            r#"{"key":"a2V5","timeoutMinutes":15}"#,
        ] {
            assert!(read_keep(bad.to_owned()).is_none(), "{bad}");
        }
        let decoded = decode_key(&BASE64.encode(&[7u8; KEY_LEN])).expect("64 bytes");
        assert_eq!(&decoded[..], &[7u8; KEY_LEN]);
        assert!(decode_key(&BASE64.encode(&[1u8; 32])).is_none());
        assert!(decode_key(&BASE64.encode(&[1u8; 65])).is_none());
        assert!(decode_key(&BASE64.encode(&[1u8; 66])).is_none());
        assert!(decode_key("not base64!").is_none());
        assert!(decode_key(&format!("{}!", &BASE64.encode(&[1u8; KEY_LEN])[1..])).is_none());
        assert!(valid_tab(TAB));
        assert!(!valid_tab("0123456789ABCDEF0123456789ABCDEF"));
        assert!(!valid_tab("0123"));
        assert_eq!(page_id(None), Ok(None));
        assert_eq!(page_id(Some(PAGE)), Ok(Some(PAGE.to_owned())));
        assert_eq!(page_id(Some("not-a-page")), Err(()));
    }
}

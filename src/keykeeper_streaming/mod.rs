// Keykeeper: sending organizations' events to their security tools (a SIEM
// or an MDR service such as Huntress, Blumira, or Microsoft Sentinel), by a
// signed webhook, syslog over TLS, or Sentinel's Logs Ingestion API.
//
// Events wait in the database (event_deliveries) until a destination takes
// them, so a restart loses none. Delivery is at least once: an event can
// arrive twice (a receiver dedupes by the event's id), and events aren't
// promised to arrive in order. One worker per server sends them, sharing its
// sending time fairly: by the time each person (who set the destination up)
// and then each organization or MSP has used, one destination per
// organization or MSP and two per person at a time, and a turn ends after
// some seconds or events. A destination that answers slowly (or takes more
// than a second an event over a turn) is sent to less often, but never
// counts as failing; one that fails waits longer and longer before its next
// try. So a slow or broken receiver, or one person with many, holds up only
// their own events. The worker takes a lease on a destination before
// sending, so two servers sharing a database don't send the same events at
// once. A destination that keeps failing for a day is turned off, and its
// owners are told by email (at most once a day).
// See DESIGN.md, "Sending events to security tools", and docs/event-streaming.md
// in the meta repo.

pub mod format;
pub mod guard;
pub mod secrets;

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    num::NonZeroU32,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use chrono::{TimeDelta, Utc};
use dashmap::DashMap;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use reqwest::{Client, StatusCode, header};
use serde_json::{Value, json};
use tokio::{io::AsyncWriteExt, sync::Semaphore};

use crate::{
    CONFIG,
    db::{
        DbConn, DbPool,
        models::{
            Event, EventDelivery, EventDestination, EventKind, EventSecrets, EventSettings, Membership,
            MembershipStatus, MembershipType, Msp, MspClient, MspEvent, MspMembership, MspRole, MspStaff, Organization,
            User, WAKE, destination_target, save_with_extras,
        },
    },
};

use format::MessageFormat;
use guard::Policy;

/// The type code of the event the Test button sends.
pub const TEST_EVENT_TYPE: i32 = 9000;

/// How many events one batch takes from a destination's queue, and how many
/// one turn sends at most, by kind.
const WEBHOOK_BATCH: i64 = 25;
const SYSLOG_BATCH: i64 = 200;
const SENTINEL_BATCH: i64 = 200;
const WEBHOOK_TURN: usize = 50;
const BULK_TURN: usize = 400;
/// How long a turn with one destination lasts at most before the worker
/// moves on. A request already under way finishes (10 seconds at most).
const TURN: Duration = Duration::from_secs(20);
/// Answers slower than these count against a destination: it's tried less
/// often, as if it had failed (what it took is still counted delivered).
const SLOW_WEBHOOK: Duration = Duration::from_secs(5);
const SLOW_BULK: Duration = Duration::from_secs(10);
/// Rate limits: the least time between two webhook requests, or two Sentinel
/// uploads, to one destination.
const WEBHOOK_GAP: Duration = Duration::from_millis(50);
const SENTINEL_GAP: Duration = Duration::from_millis(200);
/// Destinations sent to at once, at most one per organization or MSP and
/// PER_PERSON per person.
const PARALLEL: usize = 16;
/// Syslog collectors: the addresses of a name tried, at most.
const SYSLOG_ADDRESSES: usize = 3;
/// Sentinel's limit for one upload is 1 MB; stay under it.
const SENTINEL_MAX_BODY: usize = 900_000;
/// A destination failing for this long, and at least this many times in a
/// row, is turned off.
const PAUSE_AFTER: TimeDelta = TimeDelta::hours(24);
const PAUSE_AFTER_FAILURES: i32 = 10;
/// How long a worker holds a destination: longer than a turn can take.
const LEASE: TimeDelta = TimeDelta::seconds(120);

/// Why a send didn't work, and whether trying again can help.
#[derive(Debug)]
pub struct Failure {
    /// What the console shows (receiver text redacted, by Target::redact).
    pub message: String,
    /// Stop sending to this destination: it said it's gone (HTTP 410), or its
    /// secrets can't be read.
    pub stop: bool,
    /// The receiver's HTTP status, when it answered: all the email says.
    pub status: Option<u16>,
    /// It went wrong before a connection and its TLS handshake were complete
    /// (the one message for all of those). The Test button answers these
    /// after the same time every time.
    pub before_tls: bool,
    /// Not a failure: what was sent arrived, but slowly. The destination is
    /// held back for a while, never turned off for it.
    pub slow: bool,
}

impl Failure {
    fn retry(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            stop: false,
            status: None,
            before_tls: false,
            slow: false,
        }
    }

    fn stop(message: impl Into<String>) -> Self {
        Self {
            stop: true,
            ..Self::retry(message)
        }
    }

    fn answered(status: StatusCode, message: String, stop: bool) -> Self {
        Self {
            stop,
            status: Some(status.as_u16()),
            ..Self::retry(message)
        }
    }

    fn slow(message: impl Into<String>) -> Self {
        Self {
            slow: true,
            ..Self::retry(message)
        }
    }

    /// For an email: the status, or what kind of trouble, never what a
    /// receiver said.
    pub fn summary(&self) -> String {
        match self.status {
            Some(status) => format!("It answered HTTP {status}."),
            None if self.stop => self.message.clone(),
            None if self.before_tls => "It couldn't be reached.".into(),
            None => "Sending to it failed.".into(),
        }
    }
}

/// The one thing anyone is told about trouble before a connection is fully
/// made (looking up the name, a refused address, connecting, TLS): the
/// details go to the server's log, so a destination can't be used to tell
/// which hosts and ports exist inside a network. Without the destination's
/// secrets: a webhook's URL often has a token in its path or query.
fn unreachable(host: &str, detail: &str, target: &Target) -> Failure {
    info!("Event destination {} couldn't reach {host}: {}", target.id, target.scrub(detail));
    Failure {
        before_tls: true,
        ..Failure::retry(format!(
            "Couldn't connect or complete TLS with {host}. It must be reachable at a public address (or one this server's admin allows), with a valid certificate."
        ))
    }
}

/// What a destination needs to send: its settings and its opened secrets.
pub struct Target {
    pub id: String,
    pub kind: EventKind,
    pub settings: EventSettings,
    pub secrets: EventSecrets,
}

/// The longest receiver text kept, in characters.
const SHOWN: usize = 200;

impl Target {
    pub fn open(destination: &EventDestination) -> Result<Self, Failure> {
        let kind = destination.kind().ok_or_else(|| Failure::stop("Unknown kind of destination"))?;
        let secrets = secrets::open(&destination.binding(), &destination.secrets).map_err(Failure::stop)?;
        let secrets: EventSecrets =
            serde_json::from_str(secrets.as_str()).map_err(|_| Failure::stop("Unreadable secrets"))?;
        Ok(Self {
            id: destination.uuid.clone(),
            kind,
            settings: destination.settings(),
            secrets,
        })
    }

    /// Everything a receiver might echo back that must not be shown: the
    /// secrets, the URL and its query (raw and decoded), each of its query
    /// values, and each path segment of 8 or more characters (collectors put
    /// tokens there), also as JSON writes them.
    fn hidden(&self) -> Vec<String> {
        let mut hidden: Vec<String> = Vec::new();
        let s = &self.secrets;
        for secret in [&s.header_value, &s.signing_secret, &s.client_secret].into_iter().flatten() {
            hidden.push(secret.clone());
            // A header value is often "Bearer <token>"; hide the token alone too.
            if let Some((_, token)) = secret.split_once(' ') {
                hidden.push(token.to_owned());
            }
        }
        if let Some(url) = &s.url {
            hidden.push(url.clone());
            if let Ok(parsed) = url::Url::parse(url) {
                if let Some(query) = parsed.query() {
                    hidden.push(query.to_owned());
                }
                for (_, value) in parsed.query_pairs() {
                    hidden.push(value.into_owned());
                }
                hidden.push(parsed.path().to_owned());
                for segment in parsed.path().split('/') {
                    if segment.len() >= 8 {
                        hidden.push(segment.to_owned());
                        if let Ok(decoded) = percent_encoding::percent_decode_str(segment).decode_utf8() {
                            hidden.push(decoded.into_owned());
                        }
                    }
                }
            }
        }
        // As JSON escapes them ("/" as "\/").
        let escaped: Vec<String> = hidden.iter().filter(|h| h.contains('/')).map(|h| h.replace('/', "\\/")).collect();
        hidden.extend(escaped);
        hidden.retain(|h| h.len() >= 4 && h != "/");
        hidden.sort_by_key(|h| std::cmp::Reverse(h.len()));
        hidden.dedup();
        hidden
    }

    /// Text for the server's log with this destination's secrets taken out,
    /// uncut.
    pub fn scrub(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for h in &self.hidden() {
            out = out.replace(h.as_str(), "[hidden]");
        }
        out
    }

    /// Text about this destination with its secrets taken out, cut to
    /// SHOWN characters. Redacted before it's cut; and since a cut (this
    /// one, or reading only the first few KB of an answer) can leave the
    /// start of something hidden at the end, an end that starts something
    /// hidden goes too.
    pub fn redact(&self, text: &str) -> String {
        let hidden = self.hidden();
        let mut out = text.to_owned();
        for h in &hidden {
            out = out.replace(h.as_str(), "[hidden]");
        }
        if out.chars().count() > SHOWN {
            out = out.chars().take(SHOWN).collect();
        }
        for h in &hidden {
            // The longest start of `h` that the text now ends with.
            let cut = (3..h.len()).rev().filter(|&n| h.is_char_boundary(n)).find(|&n| out.ends_with(&h[..n]));
            if let Some(n) = cut {
                out.truncate(out.len() - n);
                out.push_str("[hidden]");
                break;
            }
        }
        out
    }
}

fn version() -> &'static str {
    crate::VERSION.unwrap_or("dev")
}

/// This server's host name, for syslog's HOSTNAME field.
fn hostname() -> String {
    url::Url::parse(&CONFIG.domain()).ok().and_then(|u| u.host_str().map(str::to_owned)).unwrap_or_default()
}

/// Certificate authorities to trust for Sentinel's sign-in and uploads
/// instead of the system's, from the server's EVENT_STREAMING_AZURE_CA_FILE
/// (for a test stand-in, only with EVENT_STREAMING_AZURE_TEST; a destination
/// can't choose one).
fn azure_ca() -> Option<String> {
    if !CONFIG.event_streaming_azure_test() {
        return None;
    }
    let path = CONFIG.event_streaming_azure_ca_file()?;
    match std::fs::read_to_string(&path) {
        Ok(pem) => Some(pem),
        Err(e) => {
            warn!("Couldn't read EVENT_STREAMING_AZURE_CA_FILE {path}: {e}");
            None
        }
    }
}

/// A client for one turn: it connects only to the addresses checked for
/// each host (pinned, so there's no second lookup), resolves anything else
/// through the guard, never uses a proxy, never follows redirects, and
/// trusts the system's certificate authorities or only `ca_pem`.
fn http_client(pinned: &[(String, Vec<SocketAddr>)], ca_pem: Option<&str>) -> Result<Client, String> {
    let mut builder = Client::builder()
        .user_agent(format!("PassBundle event streaming/{}", version()))
        .dns_resolver(Arc::new(guard::GuardedResolver))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(30));
    for (host, addrs) in pinned {
        builder = builder.resolve_to_addrs(host, addrs);
    }
    if let Some(pem) = ca_pem {
        let certs = reqwest::Certificate::from_pem_bundle(pem.as_bytes())
            .map_err(|_| "The certificate authority isn't a PEM certificate".to_owned())?;
        builder = builder.tls_certs_only(certs);
    }
    builder.build().map_err(|e| format!("Couldn't set up HTTPS: {e}"))
}

/// Resolves and checks a URL's host for a pinned client: (host, addresses),
/// or nothing to pin for an address (checked as it is).
async fn pin(url: &url::Url, policy: &Policy) -> Result<Option<(String, Vec<SocketAddr>)>, String> {
    let host = url.host_str().unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(443);
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if bare.parse::<std::net::IpAddr>().is_ok() {
        guard::checked_host(bare, port, policy)?;
        return Ok(None);
    }
    Ok(Some((bare.to_owned(), guard::resolve(bare, port, policy).await?)))
}

/// What a receiver answered, for the console: its status, and what it
/// said, from the first few KB (read no further), redacted, then cut to
/// SHOWN characters. The words only when no private networks are allowed:
/// otherwise a destination could be used to read services inside the
/// server's network.
async fn answer(mut response: reqwest::Response, target: &Target) -> String {
    let status = response.status();
    let mut body = Vec::new();
    if !Policy::current().any() {
        while body.len() < 4096 {
            match tokio::time::timeout(Duration::from_secs(2), response.chunk()).await {
                Ok(Ok(Some(chunk))) => body.extend_from_slice(&chunk),
                _ => break,
            }
        }
    }
    drop(response);
    let text: String = String::from_utf8_lossy(&body[..body.len().min(4096)])
        .chars()
        .map(|c| {
            if c.is_control() {
                ' '
            } else {
                c
            }
        })
        .collect();
    let text = target.redact(text.trim());
    if text.is_empty() {
        format!("It answered {status}")
    } else {
        format!("It answered {status}: {text}")
    }
}

async fn send_webhook(target: &Target, events: &[(String, String)], deadline: Instant) -> (usize, Option<Failure>) {
    let Some(url) = &target.secrets.url else {
        return (0, Some(Failure::stop("No URL")));
    };
    let policy = Policy::current();
    // Checked again, in case the server's settings changed since it was saved.
    let url = match guard::checked_url(url, &policy) {
        Ok(u) => u,
        Err(e) => return (0, Some(Failure::retry(e))),
    };
    let host = url.host_str().unwrap_or_default().to_owned();
    let pinned = match pin(&url, &policy).await {
        Ok(p) => p.into_iter().collect::<Vec<_>>(),
        Err(e) => return (0, Some(unreachable(&host, &e, target))),
    };
    let client = match http_client(&pinned, target.settings.ca_certificate.as_deref()) {
        Ok(c) => c,
        Err(e) => return (0, Some(Failure::retry(e))),
    };
    let Some(secret) = &target.secrets.signing_secret else {
        return (0, Some(Failure::stop("No signing secret")));
    };
    let mut sent = 0;
    for (id, body) in events {
        if sent > 0 && Instant::now() >= deadline {
            break;
        }
        let started = Instant::now();
        let timestamp = Utc::now().timestamp();
        let Some(signature) = format::sign(secret, id, timestamp, body.as_bytes()) else {
            return (sent, Some(Failure::stop("The signing secret is unreadable")));
        };
        let mut request = client
            .post(url.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .header(format::HEADER_ID, id.as_str())
            .header(format::HEADER_TIMESTAMP, timestamp.to_string())
            .header(format::HEADER_SIGNATURE, signature)
            .body(body.clone());
        if let (Some(name), Some(value)) = (&target.settings.header_name, &target.secrets.header_value) {
            request = request.header(name.as_str(), value.as_str());
        }
        match request.send().await {
            Ok(r) if r.status().is_success() => sent += 1,
            Ok(r) if r.status() == StatusCode::GONE => {
                let status = r.status();
                let text = format!("{} (a webhook that's gone)", answer(r, target).await);
                return (sent, Some(Failure::answered(status, text, true)));
            }
            Ok(r) if r.status().is_redirection() => {
                let status = r.status();
                let text = format!("{}. Redirects aren't followed.", answer(r, target).await);
                return (sent, Some(Failure::answered(status, text, false)));
            }
            Ok(r) => {
                let status = r.status();
                return (sent, Some(Failure::answered(status, answer(r, target).await, false)));
            }
            Err(e) => return (sent, Some(unreachable(&host, &format!("{:?}", e.without_url()), target))),
        }
        let took = started.elapsed();
        if took > SLOW_WEBHOOK {
            // Delivered, but slow: it's held back for a while.
            return (
                sent,
                Some(Failure::slow(format!(
                    "It took {} seconds to answer. A webhook should answer within {} seconds, so it's sent to less often until it does.",
                    took.as_secs(),
                    SLOW_WEBHOOK.as_secs()
                ))),
            );
        }
        if let Some(rest) = WEBHOOK_GAP.checked_sub(took) {
            tokio::time::sleep(rest).await;
        }
    }
    (sent, None)
}

/// TLS settings for a syslog collector: the system's certificate
/// authorities, or only the destination's own.
fn syslog_tls(ca_pem: Option<&str>) -> Result<rustls::ClientConfig, String> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    match ca_pem {
        None => {
            use rustls_platform_verifier::ConfigVerifierExt;
            rustls::ClientConfig::with_platform_verifier().map_err(|e| format!("Couldn't set up TLS: {e}"))
        }
        Some(pem) => {
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
                let cert = cert.map_err(|_| "The certificate authority isn't a PEM certificate".to_owned())?;
                roots.add(cert).map_err(|_| "The certificate authority isn't a certificate".to_owned())?;
            }
            Ok(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
        }
    }
}

/// Where a syslog send got to when it went wrong.
enum SyslogError {
    /// Before the TLS handshake finished: said only generically.
    Connecting(String),
    /// After: the collector closed or stalled while events were going out.
    Sending,
    Setup(String),
}

async fn send_syslog(target: &Target, events: &[(String, String)], deadline: Instant) -> (usize, Option<Failure>) {
    let host = target.settings.host.clone().unwrap_or_default();
    // The whole exchange, from looking up the name to closing, in the time
    // the turn has left (at least 10 seconds, at most 30).
    let budget =
        deadline.saturating_duration_since(Instant::now()).clamp(Duration::from_secs(10), Duration::from_secs(30));
    let started = Instant::now();
    let result = match tokio::time::timeout(budget, send_syslog_inner(target, events)).await {
        Ok(r) => r,
        Err(_) => Err(SyslogError::Connecting("the whole exchange timed out".into())),
    };
    match result {
        Ok(()) if started.elapsed() > SLOW_BULK => (
            events.len(),
            Some(Failure::slow(format!(
                "Sending to the collector took {} seconds, so it's sent to less often until it's faster.",
                started.elapsed().as_secs()
            ))),
        ),
        Ok(()) => (events.len(), None),
        Err(SyslogError::Connecting(detail)) => (0, Some(unreachable(&host, &detail, target))),
        Err(SyslogError::Sending) => (
            0,
            Some(Failure::retry(format!("{host} closed the connection or stopped reading while events were sent."))),
        ),
        Err(SyslogError::Setup(e)) => (0, Some(Failure::retry(e))),
    }
}

async fn send_syslog_inner(target: &Target, events: &[(String, String)]) -> Result<(), SyslogError> {
    let host = target.settings.host.clone().ok_or_else(|| SyslogError::Setup("No host".into()))?;
    let port = target.settings.port.unwrap_or(6514);
    let format = target.settings.format.as_deref().and_then(MessageFormat::from_str).unwrap_or(MessageFormat::Json);
    let addrs = guard::resolve(&host, port, &Policy::current()).await.map_err(SyslogError::Connecting)?;
    let config = syslog_tls(target.settings.ca_certificate.as_deref()).map_err(SyslogError::Setup)?;
    let name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|_| SyslogError::Setup("Bad host name".into()))?;
    let mut last = String::from("no address");
    for addr in addrs.into_iter().take(SYSLOG_ADDRESSES) {
        let tcp = match tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(e)) => {
                last = format!("connecting to {addr}: {e}");
                continue;
            }
            Err(_) => {
                last = format!("connecting to {addr} timed out");
                continue;
            }
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config.clone()));
        // Never repeat rustls's error to the person: it can list the
        // certificate's names.
        let mut tls = match tokio::time::timeout(Duration::from_secs(10), connector.connect(name.clone(), tcp)).await {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => return Err(SyslogError::Connecting(format!("TLS with {addr}: {e}"))),
            Err(_) => return Err(SyslogError::Connecting(format!("TLS with {addr} timed out"))),
        };
        let hostname = hostname();
        let mut out = Vec::new();
        for (_, payload) in events {
            let event: Value = serde_json::from_str(payload).unwrap_or_default();
            out.extend(format::frame(&format::syslog_message(&event, format, &hostname, version())));
        }
        let write = async {
            tls.write_all(&out).await?;
            tls.flush().await?;
            tls.shutdown().await
        };
        return match tokio::time::timeout(Duration::from_secs(15), write).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                info!("Event destination {} lost {host} while sending: {}", target.id, target.scrub(&e.to_string()));
                Err(SyslogError::Sending)
            }
            Err(_) => Err(SyslogError::Sending),
        };
    }
    Err(SyslogError::Connecting(last))
}

/// Sentinel tokens, by destination, until shortly before they expire.
static SENTINEL_TOKENS: LazyLock<DashMap<String, (String, Instant)>> = LazyLock::new(DashMap::new);

/// The Entra sign-in that Sentinel destinations get tokens from.
fn sentinel_token_url(tenant: &str) -> String {
    format!("{}/{tenant}/oauth2/v2.0/token", CONFIG.event_streaming_azure_login_url().trim_end_matches('/'))
}

async fn sentinel_token(target: &Target, client: &Client, token_url: &str) -> Result<String, Failure> {
    if let Some(entry) = SENTINEL_TOKENS.get(&target.id)
        && entry.1 > Instant::now()
    {
        return Ok(entry.0.clone());
    }
    let s = &target.settings;
    let (Some(client_id), Some(secret)) = (&s.client_id, &target.secrets.client_secret) else {
        return Err(Failure::stop("The Sentinel settings are incomplete"));
    };
    let form = [
        ("grant_type", "client_credentials"),
        ("client_id", client_id.as_str()),
        ("client_secret", secret.as_str()),
        ("scope", &CONFIG.event_streaming_azure_scope()),
    ];
    let response = match client.post(token_url).form(&form).send().await {
        Ok(r) => r,
        Err(e) => return Err(unreachable("Microsoft Entra", &format!("{:?}", e.without_url()), target)),
    };
    if !response.status().is_success() {
        let status = response.status();
        let text = format!("Microsoft Entra refused the app's sign-in. {}", answer(response, target).await);
        return Err(Failure::answered(status, text, false));
    }
    let body: Value = response.json().await.map_err(|_| Failure::retry("Microsoft Entra sent no token"))?;
    let token = body["access_token"].as_str().ok_or_else(|| Failure::retry("Microsoft Entra sent no token"))?;
    let lifetime = body["expires_in"].as_u64().unwrap_or(3600).saturating_sub(300).max(60);
    SENTINEL_TOKENS.insert(target.id.clone(), (token.to_owned(), Instant::now() + Duration::from_secs(lifetime)));
    Ok(token.to_owned())
}

/// Forgets a destination's Sentinel token, as when its settings change.
pub fn forget_token(destination: &str) {
    SENTINEL_TOKENS.remove(destination);
}

async fn send_sentinel(target: &Target, events: &[(String, String)], deadline: Instant) -> (usize, Option<Failure>) {
    let s = &target.settings;
    let (Some(endpoint), Some(rule), Some(stream), Some(tenant)) = (&s.endpoint, &s.rule_id, &s.stream, &s.tenant_id)
    else {
        return (0, Some(Failure::stop("The Sentinel settings are incomplete")));
    };
    let policy = Policy::current();
    // Checked again: the bearer token goes only to Azure Monitor.
    let endpoint = match guard::checked_sentinel_endpoint(endpoint, &policy) {
        Ok(e) => e,
        Err(e) => return (0, Some(Failure::retry(e))),
    };
    let url = format!("{endpoint}/dataCollectionRules/{rule}/streams/{stream}?api-version=2023-01-01");
    let token_url = sentinel_token_url(tenant);
    let mut pinned = Vec::new();
    for u in [&url, &token_url] {
        let Ok(parsed) = url::Url::parse(u) else {
            return (0, Some(Failure::retry("The Sentinel settings are incomplete")));
        };
        match pin(&parsed, &policy).await {
            Ok(Some(p)) if !pinned.iter().any(|(h, _): &(String, Vec<SocketAddr>)| *h == p.0) => pinned.push(p),
            Ok(_) => {}
            Err(e) => return (0, Some(unreachable(parsed.host_str().unwrap_or_default(), &e, target))),
        }
    }
    let client = match http_client(&pinned, azure_ca().as_deref()) {
        Ok(c) => c,
        Err(e) => return (0, Some(Failure::retry(e))),
    };
    let mut sent = 0;
    let mut start = 0;
    while start < events.len() {
        if sent > 0 && Instant::now() >= deadline {
            break;
        }
        // As many rows as fit in one upload.
        let mut rows = Vec::new();
        let mut size = 2;
        let mut end = start;
        while end < events.len() {
            let event: Value = serde_json::from_str(&events[end].1).unwrap_or_default();
            let row = format::sentinel_row(&event);
            let len = row.to_string().len() + 1;
            if !rows.is_empty() && size + len > SENTINEL_MAX_BODY {
                break;
            }
            size += len;
            rows.push(row);
            end += 1;
        }
        let started = Instant::now();
        let token = match sentinel_token(target, &client, &token_url).await {
            Ok(t) => t,
            Err(f) => return (sent, Some(f)),
        };
        let response = client
            .post(&url)
            .bearer_auth(token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Value::Array(rows).to_string())
            .send()
            .await;
        match response {
            Ok(r) if r.status().is_success() => sent = end,
            Ok(r) => {
                let status = r.status();
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    forget_token(&target.id);
                }
                let text = format!("Sentinel didn't take the events. {}", answer(r, target).await);
                return (sent, Some(Failure::answered(status, text, false)));
            }
            Err(e) => {
                return (
                    sent,
                    Some(unreachable(
                        url::Url::parse(&endpoint).ok().as_ref().and_then(url::Url::host_str).unwrap_or_default(),
                        &format!("{:?}", e.without_url()),
                        target,
                    )),
                );
            }
        }
        start = end;
        if started.elapsed() > SLOW_BULK {
            return (
                sent,
                Some(Failure::slow(
                    "Sentinel took more than 10 seconds to take the events, so it's sent to less often for a while.",
                )),
            );
        }
        if let Some(rest) = SENTINEL_GAP.checked_sub(started.elapsed()) {
            tokio::time::sleep(rest).await;
        }
    }
    (sent, None)
}

/// Sends events (id, payload) to a destination, in order, and says how many
/// arrived before anything went wrong. It starts no new request after the
/// deadline, so fewer may be sent with nothing wrong.
pub async fn send(target: &Target, events: &[(String, String)], deadline: Instant) -> (usize, Option<Failure>) {
    let (sent, failure) = match target.kind {
        EventKind::Webhook => send_webhook(target, events, deadline).await,
        EventKind::Syslog => send_syslog(target, events, deadline).await,
        EventKind::Sentinel => send_sentinel(target, events, deadline).await,
    };
    // What's kept and shown never carries the destination's secrets.
    let failure = failure.map(|f| Failure {
        message: target.redact(&f.message),
        ..f
    });
    (sent, failure)
}

/// An event that goes straight to one destination, not through the queue:
/// the Test button's sample (type 9000), or the notice a destination gets
/// when it's turned off, removed, or pointed elsewhere. `scope` adds the
/// organization or MSP.
pub fn direct_event(code: i32, scope: &Value, actor: &User, ip: &str, detail: Option<&str>) -> (String, String) {
    let id = uuid::Uuid::from_bytes(secrets::random::<16>()).hyphenated().to_string();
    let (category, name, severity) = crate::db::models::describe_event(code);
    let mut event = json!({
        "id": id,
        "time": crate::util::format_date(&Utc::now().naive_utc()),
        "type": code,
        "name": name,
        "category": category,
        "severity": severity,
        "actor": { "type": "user", "id": actor.uuid, "email": actor.email },
        "ip": ip,
    });
    if let Some(detail) = detail {
        event["detail"] = json!(detail);
    }
    if let Some(obj) = scope.as_object() {
        for (k, v) in obj {
            event[k] = v.clone();
        }
    }
    (id, event.to_string())
}

/// Notices to a place a destination no longer sends to, at once, at most.
static NOTICES_RUNNING: Semaphore = Semaphore::const_new(2);

/// Notices per organization or MSP: a few in a row, then one every 10
/// seconds, so switching a destination back and forth can't make the server
/// knock on a host over and over.
static NOTICE_LIMIT: LazyLock<RateLimiter<String, DashMapStateStore<String>, DefaultClock>> = LazyLock::new(|| {
    RateLimiter::keyed(
        Quota::with_period(Duration::from_secs(10))
            .expect("non-zero")
            .allow_burst(NonZeroU32::new(3).expect("non-zero")),
    )
});

/// Tells a destination it's being turned off, removed, or pointed
/// elsewhere, so its SIEM sees the last word even if nothing else is sent
/// there again: in the background, a few tries (now, after 5 seconds, after
/// 30), two at a time on the server, and within the scope's limit. Not kept
/// across a restart.
pub fn farewell(target: Target, event: (String, String), scope: &str) {
    if NOTICE_LIMIT.check_key(&scope.to_owned()).is_err() {
        info!("Skipped a last notice to an event destination of {scope}: too many just now");
        return;
    }
    tokio::spawn(async move {
        for wait in [0, 5, 30] {
            tokio::time::sleep(Duration::from_secs(wait)).await;
            let Ok(_running) = NOTICES_RUNNING.acquire().await else {
                return;
            };
            match send(&target, std::slice::from_ref(&event), Instant::now() + Duration::from_secs(15)).await {
                (1, _) => return,
                (_, Some(f)) => debug!("A destination's last notice didn't arrive: {}", f.message),
                _ => {}
            }
        }
    });
}

/// Tests per person: a few in a row, then one every 5 seconds, whichever
/// destinations they test. Old entries are pruned by the worker.
pub static TEST_LIMIT: LazyLock<RateLimiter<String, DashMapStateStore<String>, DefaultClock>> = LazyLock::new(|| {
    RateLimiter::keyed(
        Quota::with_period(Duration::from_secs(5))
            .expect("non-zero")
            .allow_burst(NonZeroU32::new(3).expect("non-zero")),
    )
});

/// Tests under way on this server at once, at most.
pub static TESTS_RUNNING: Semaphore = Semaphore::const_new(4);

/// Tests under way, by organization or MSP and by person: one each.
static TESTS_UNDER_WAY: LazyLock<DashMap<String, ()>> = LazyLock::new(DashMap::new);

/// One test at a time for whatever `key` names (a scope, or a person),
/// while it's held.
pub struct TestTurn(String);

impl TestTurn {
    pub fn take(key: &str) -> Option<Self> {
        match TESTS_UNDER_WAY.entry(key.to_owned()) {
            dashmap::mapref::entry::Entry::Occupied(_) => None,
            dashmap::mapref::entry::Entry::Vacant(v) => {
                v.insert(());
                Some(Self(key.to_owned()))
            }
        }
    }
}

impl Drop for TestTurn {
    fn drop(&mut self) {
        TESTS_UNDER_WAY.remove(&self.0);
    }
}

/// The most events one request to /events/collect (what apps report:
/// views, copies, exports) may carry; a request with more is refused.
pub const MAX_COLLECTED: usize = 500;

/// Requests to /events/collect per person: a burst, then one every 2 seconds.
static COLLECT_LIMIT: LazyLock<RateLimiter<String, DashMapStateStore<String>, DefaultClock>> = LazyLock::new(|| {
    RateLimiter::keyed(
        Quota::with_period(Duration::from_secs(2))
            .expect("non-zero")
            .allow_burst(NonZeroU32::new(30).expect("non-zero")),
    )
});

/// Whether this person's app may report events now.
pub fn collect_allowed(user: &crate::db::models::UserId) -> bool {
    COLLECT_LIMIT.check_key(user.as_ref()).is_ok()
}

/// Starts the delivery worker. It wakes when an event is queued, and every
/// few seconds for retries. If it ever stops (a bug), it starts again.
pub fn start(pool: DbPool) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = tokio::spawn(run(pool.clone())).await {
                error!("The event streaming worker stopped ({e}); starting it again");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// At most this many destinations one person set up are sent to at once.
const PER_PERSON: usize = 2;

/// A destination that can take a turn: its id, its scope (organization or
/// MSP), and the person who set it up.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    dest: String,
    scope: String,
    person: String,
}

/// How the worker shares its time: who's being sent to now, and how much
/// sending time each person and each scope has used (seconds, a virtual
/// clock that decays). Turns go to the person, then the scope, that has used
/// the least, so a person with many slow destinations, or with many
/// organizations, gets no more time than anyone else, and never more than
/// PER_PERSON turns at once.
#[derive(Default)]
struct Fair {
    busy_scopes: HashSet<String>,
    busy_people: HashMap<String, usize>,
    people: HashMap<String, f64>,
    scopes: HashMap<String, f64>,
}

/// The least anyone in `used` has used.
fn floor(used: &HashMap<String, f64>) -> f64 {
    used.values().copied().reduce(f64::min).unwrap_or(0.0)
}

impl Fair {
    /// Puts people and scopes seen for the first time level with the least
    /// anyone has used, so they neither jump ahead of everyone (and starve
    /// those already waiting) nor wait behind old debts.
    fn register(&mut self, due: &[Candidate]) {
        let (people, scopes) = (floor(&self.people), floor(&self.scopes));
        for c in due {
            self.people.entry(c.person.clone()).or_insert(people);
            self.scopes.entry(c.scope.clone()).or_insert(scopes);
        }
    }

    fn used(&self, c: &Candidate) -> (f64, f64) {
        (
            self.people.get(&c.person).copied().unwrap_or_else(|| floor(&self.people)),
            self.scopes.get(&c.scope).copied().unwrap_or_else(|| floor(&self.scopes)),
        )
    }

    /// Adds what a turn took (at least a little, so turns that fail at once
    /// still count).
    fn charge(&mut self, c: &Candidate, took: Duration) {
        let seconds = took.as_secs_f64().max(0.05);
        let (person, scope) = self.used(c);
        self.people.insert(c.person.clone(), person + seconds);
        self.scopes.insert(c.scope.clone(), scope + seconds);
    }

    /// Halves what everyone has used beyond the least, and forgets those
    /// level with it, every few minutes, so the clock stays small and old
    /// slowness is forgiven.
    fn decay(&mut self) {
        for used in [&mut self.people, &mut self.scopes] {
            let least = floor(used);
            for v in used.values_mut() {
                *v = (*v - least) / 2.0;
            }
            used.retain(|_, v| *v > 0.01);
        }
    }
}

/// Which destinations get a turn now: the person and then the scope that
/// have used the least time first, at most one per scope and PER_PERSON per
/// person (counting turns under way), up to `slots`.
fn pick(due: &[Candidate], fair: &Fair, slots: usize) -> Vec<Candidate> {
    let mut order: Vec<&Candidate> = due.iter().filter(|c| !fair.busy_scopes.contains(&c.scope)).collect();
    order.sort_by(|a, b| {
        fair.used(a).partial_cmp(&fair.used(b)).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.dest.cmp(&b.dest))
    });
    let mut scopes: HashSet<&str> = HashSet::new();
    let mut people: HashMap<&str, usize> = HashMap::new();
    let mut chosen = Vec::new();
    for c in order {
        if chosen.len() >= slots {
            break;
        }
        let running =
            fair.busy_people.get(&c.person).copied().unwrap_or(0) + people.get(c.person.as_str()).copied().unwrap_or(0);
        if running >= PER_PERSON || !scopes.insert(c.scope.as_str()) {
            continue;
        }
        *people.entry(c.person.as_str()).or_default() += 1;
        chosen.push(c.clone());
    }
    chosen
}

/// While a turn lasts: frees its scope and person, and charges the time.
struct Turn {
    fair: Arc<Mutex<Fair>>,
    who: Candidate,
    started: Instant,
}

impl Drop for Turn {
    fn drop(&mut self) {
        if let Ok(mut f) = self.fair.lock() {
            f.busy_scopes.remove(&self.who.scope);
            if let Some(n) = f.busy_people.get_mut(&self.who.person) {
                *n = n.saturating_sub(1);
            }
            f.charge(&self.who, self.started.elapsed());
        }
    }
}

/// Finds the destinations with events due, and gives them turns fairly, each
/// on its own task.
async fn run(pool: DbPool) {
    let slots = Arc::new(Semaphore::new(PARALLEL));
    let fair: Arc<Mutex<Fair>> = Arc::default();
    let mut pruned = Instant::now();
    loop {
        let due = candidates(&pool).await;
        let chosen = match fair.lock() {
            Ok(mut f) => {
                f.register(&due);
                pick(&due, &f, slots.available_permits())
            }
            Err(_) => return,
        };
        for who in chosen {
            let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                break;
            };
            let turn = {
                let Ok(mut f) = fair.lock() else {
                    return;
                };
                f.busy_scopes.insert(who.scope.clone());
                *f.busy_people.entry(who.person.clone()).or_default() += 1;
                Turn {
                    fair: Arc::clone(&fair),
                    who: who.clone(),
                    started: Instant::now(),
                }
            };
            let pool = pool.clone();
            tokio::spawn(async move {
                let again = deliver(&pool, &who.dest).await;
                // Free before waking the loop, so it can give this scope
                // another turn.
                drop(turn);
                drop(slot);
                if again {
                    WAKE.notify_one();
                }
            });
        }
        if pruned.elapsed() > Duration::from_secs(300) {
            pruned = Instant::now();
            for limit in [&*TEST_LIMIT, &*COLLECT_LIMIT, &*NOTICE_LIMIT] {
                limit.retain_recent();
                limit.shrink_to_fit();
            }
            if let Ok(mut f) = fair.lock() {
                f.decay();
            }
        }
        tokio::select! {
            () = WAKE.notified() => {}
            () = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}

/// The destinations that can take a turn now (on, with events due, not
/// held back), soonest first: one indexed query, at most 500.
async fn candidates(pool: &DbPool) -> Vec<Candidate> {
    let Ok(conn) = pool.get().await else {
        return Vec::new();
    };
    EventDestination::due(500, &conn)
        .await
        .into_iter()
        .map(|(dest, scope, person)| Candidate {
            person: person_key(person.as_ref(), &scope),
            dest,
            scope,
        })
        .collect()
}

/// Whose share of the worker's time a destination uses: the person who set
/// it up, or, once their account is deleted, its organization or MSP's own
/// (never one shared by every such destination).
fn person_key(created_by: Option<&crate::db::models::UserId>, scope: &str) -> String {
    match created_by {
        Some(person) => format!("person:{person}"),
        None => format!("nobody:{scope}"),
    }
}

/// Sends what's due for one destination, for one turn. True when it sent
/// something or stopped with more due: then the worker looks again right
/// away, for events queued meanwhile.
async fn deliver(pool: &DbPool, uuid: &str) -> bool {
    let Ok(conn) = pool.get().await else {
        return false;
    };
    let Some(lease) = EventDestination::claim(uuid, LEASE, &conn).await else {
        return false;
    };
    drop(conn);
    let again = deliver_claimed(pool, uuid).await;
    if let Ok(conn) = pool.get().await {
        EventDestination::refresh_due(uuid, &conn).await;
        EventDestination::release(uuid, lease, &conn).await;
    }
    again
}

/// How a turn ended.
enum End {
    /// Nothing more due.
    Done,
    /// It used its share of events; more are due.
    More,
    /// It delivered, slowly: held back for a while.
    Slow(String),
    /// It failed (recorded already).
    Failed,
}

/// A turn whose sending averaged more than this per event, over at least
/// SLOW_TURN_MIN of sending, counts as slow. Only the time spent sending
/// counts (the receiver's), never the server's own waits.
const SLOW_PER_EVENT: Duration = Duration::from_secs(1);
const SLOW_TURN_MIN: Duration = Duration::from_secs(2);

async fn deliver_claimed(pool: &DbPool, uuid: &str) -> bool {
    let started = Instant::now();
    let deadline = started + TURN;
    let mut sent_total = 0usize;
    let mut sending = Duration::ZERO;
    let mut was_failing = false;
    let end = loop {
        let Ok(conn) = pool.get().await else {
            break End::Failed;
        };
        // Read again for every batch: someone may have changed its settings,
        // turned it off, or removed it.
        let now = Utc::now().naive_utc();
        let Some(destination) =
            EventDestination::find(uuid, &conn).await.filter(|d| d.enabled && d.retry_at.is_none_or(|at| at <= now))
        else {
            break End::Done;
        };
        was_failing |= destination.failures > 0;
        let target = match Target::open(&destination) {
            Ok(t) => t,
            Err(f) => {
                stop(&destination, &f, false, &conn).await;
                break End::Failed;
            }
        };
        let (batch, turn_events) = match target.kind {
            EventKind::Webhook => (WEBHOOK_BATCH, WEBHOOK_TURN),
            EventKind::Syslog => (SYSLOG_BATCH, BULK_TURN),
            EventKind::Sentinel => (SENTINEL_BATCH, BULK_TURN),
        };
        let due = EventDelivery::due(uuid, batch, &conn).await;
        drop(conn);
        if due.is_empty() {
            break End::Done;
        }
        let events: Vec<(String, String)> = due.iter().map(|d| (d.event_uuid.clone(), d.payload.clone())).collect();
        let sent_at = Instant::now();
        let (sent, failure) = send(&target, &events, deadline).await;
        sending += sent_at.elapsed();
        let Ok(conn) = pool.get().await else {
            break End::Failed;
        };
        let delivered: Vec<String> = due[..sent].iter().map(|d| d.event_uuid.clone()).collect();
        sent_total += sent;
        if !delivered.is_empty() {
            EventDelivery::done(uuid, delivered, &conn).await;
        }
        if let Some(failure) = failure {
            if failure.slow {
                break End::Slow(failure.message);
            }
            EventDelivery::retry_later(uuid, due[sent..].to_vec(), &conn).await;
            if failure.stop {
                stop(&destination, &failure, false, &conn).await;
            } else if let Some(now) = EventDestination::failed(uuid, &failure.message, &conn).await
                && now.failures >= PAUSE_AFTER_FAILURES
                && now.failing_since.is_some_and(|since| Utc::now().naive_utc() - since >= PAUSE_AFTER)
            {
                let stopped = Failure {
                    message: format!("Turned off after failing for a day. The last error: {}", failure.message),
                    ..Failure::retry("")
                };
                let stopped = Failure {
                    status: failure.status,
                    before_tls: failure.before_tls,
                    ..stopped
                };
                stop(&destination, &stopped, true, &conn).await;
            }
            break End::Failed;
        }
        if sent < due.len() || (Instant::now() >= deadline && sending * 2 >= TURN) {
            // It used the whole turn, most of it taking events, without
            // catching up: slow.
            break End::Slow(format!(
                "It took {} seconds to take {sent_total} events, so it's sent to less often until it's faster.",
                sending.as_secs()
            ));
        }
        if Instant::now() >= deadline {
            // The turn is over (mostly the server's own waits): more later.
            break End::More;
        }
        if sent_total >= turn_events {
            break End::More;
        }
        if due.len() < usize::try_from(batch).unwrap_or(usize::MAX) {
            break End::Done;
        }
    };
    let end = match end {
        // Done quickly overall, or slower than an event a second.
        End::Done | End::More
            if sent_total > 0
                && sending >= SLOW_TURN_MIN
                && sending.as_secs_f64() / f64::from(u32::try_from(sent_total).unwrap_or(u32::MAX))
                    > SLOW_PER_EVENT.as_secs_f64() =>
        {
            End::Slow(format!(
                "It took {} seconds to take {sent_total} events, more than a second each, so it's sent to less often until it's faster.",
                sending.as_secs()
            ))
        }
        other => other,
    };
    let Ok(conn) = pool.get().await else {
        return false;
    };
    match end {
        End::Slow(why) => {
            EventDestination::slowed(uuid, &why, &conn).await;
            false
        }
        End::Done | End::More if sent_total > 0 => {
            EventDestination::succeeded(uuid, &conn).await;
            if was_failing {
                // It works again: what waited out its failures goes now.
                EventDelivery::due_now(uuid, &conn).await;
            }
            true
        }
        End::Done | End::More | End::Failed => false,
    }
}

/// Turns a destination off and tells the people who set it up: an
/// organization's owners and admins (not its MSP's technicians, who can't
/// change it), or an MSP's admins. The organization's event log (or the
/// MSP's activity log) records it, and so the other destinations hear. The
/// email says only what kind of trouble (a status code, never a receiver's
/// words), at most once a day per destination, and goes out in the
/// background. Only failures turn a destination off, never slowness.
async fn stop(destination: &EventDestination, failure: &Failure, for_a_day: bool, conn: &DbConn) {
    let reason = &failure.message;
    let summary = if for_a_day {
        format!("It kept failing for a day. {}", failure.summary())
    } else {
        failure.summary()
    };
    warn!("Event destination {} turned off: {reason}", destination.uuid);
    EventDestination::failed(&destination.uuid, reason, conn).await;
    EventDestination::pause(&destination.uuid, reason, conn).await;
    let (scope, url, recipients) = if let Some(org_id) = &destination.org_uuid {
        // In the organization's event log, by no one (the server did it).
        let mut event = Event::new(crate::db::models::EventType::KeykeeperEventStreamStopped as i32, None);
        event.org_uuid = Some(org_id.clone());
        let mut target = destination_target(destination);
        target["enabled"] = json!(false);
        let extras = json!({
            "target": target,
            "changes": ["turned off"],
            "detail": format!("The server turned this destination off. {summary}"),
        });
        save_with_extras(&event, extras, conn).await;
        let name = Organization::find_by_uuid(org_id, conn).await.map(|o| o.name).unwrap_or_default();
        let msp = MspClient::find_by_org(org_id, conn).await.map(|c| c.msp_uuid);
        let mut recipients = Vec::new();
        for m in Membership::find_by_org(org_id, conn).await {
            if m.status != MembershipStatus::Confirmed as i32
                || (m.atype != MembershipType::Owner as i32 && m.atype != MembershipType::Admin as i32)
            {
                continue;
            }
            if MspMembership::find_by_membership(&m.uuid, conn).await.is_some() {
                let admin = match &msp {
                    Some(msp) => {
                        MspStaff::find(msp, &m.user_uuid, conn).await.and_then(|s| s.role()) == Some(MspRole::Admin)
                    }
                    None => false,
                };
                if !admin {
                    continue;
                }
            }
            if let Some(user) = User::find_by_uuid(&m.user_uuid, conn).await {
                recipients.push(user.email);
            }
        }
        (name, format!("{}/#/organizations/{org_id}/reporting/event-streaming", CONFIG.domain()), recipients)
    } else if let Some(msp_id) = &destination.msp_uuid {
        let name = Msp::find_by_uuid(msp_id, conn).await.map(|m| m.name).unwrap_or_default();
        let mut recipients = Vec::new();
        for staff in MspStaff::find_by_msp(msp_id, conn).await {
            if staff.role() == Some(MspRole::Admin)
                && let Some(user) = User::find_by_uuid(&staff.user_uuid, conn).await
            {
                recipients.push(user.email);
            }
        }
        let mut entry = MspEvent::new(msp_id.clone(), "event_stream_paused");
        entry.detail = Some(format!(
            "{} (id {}, {}: {}): the server turned it off. {summary}",
            destination.name, destination.uuid, destination.kind, destination.shown_target
        ));
        entry.insert(conn).await.ok();
        (name, format!("{}/#/msp", CONFIG.domain()), recipients)
    } else {
        return;
    };
    if CONFIG.mail_enabled() && EventDestination::take_notice(&destination.uuid, conn).await {
        let name = destination.name.clone();
        tokio::spawn(async move {
            for address in recipients {
                if let Err(e) = crate::mail::send_event_stream_paused(&address, &scope, &name, &summary, &url).await {
                    warn!("Couldn't email {address} about a paused event destination: {e:?}");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn due(list: &[(&str, &str, &str)]) -> Vec<Candidate> {
        list.iter()
            .map(|(dest, scope, person)| Candidate {
                dest: (*dest).to_owned(),
                scope: (*scope).to_owned(),
                person: (*person).to_owned(),
            })
            .collect()
    }

    #[test]
    fn turns_go_one_per_scope_and_two_per_person() {
        let list = due(&[
            ("a1", "org:a", "p"),
            ("a2", "org:a", "p"),
            ("b1", "org:b", "p"),
            ("c1", "org:c", "p"),
            ("d1", "msp:d", "q"),
        ]);
        let mut fair = Fair::default();
        fair.register(&list);
        let picked = pick(&list, &fair, 16);
        // One destination per scope, and p, with three scopes due, gets two.
        assert_eq!(picked.iter().filter(|c| c.person == "p").count(), PER_PERSON);
        assert_eq!(picked.iter().filter(|c| c.scope == "org:a").count(), 1);
        assert!(picked.iter().any(|c| c.person == "q"));
        // Turns under way count: a busy scope waits, and so does a person
        // at their limit.
        fair.busy_scopes.insert("msp:d".into());
        fair.busy_people.insert("p".into(), 1);
        let picked = pick(&list, &fair, 16);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].person, "p");
        assert_eq!(pick(&list, &fair, 0).len(), 0);
    }

    #[test]
    fn destinations_whose_creator_is_gone_share_only_with_their_own_scope() {
        let person: crate::db::models::UserId = "u1".to_owned().into();
        assert_eq!(person_key(Some(&person), "org:a"), "person:u1");
        assert_eq!(person_key(Some(&person), "org:b"), "person:u1");
        assert_eq!(person_key(None, "org:a"), "nobody:org:a");
        assert_ne!(person_key(None, "org:a"), person_key(None, "org:b"));
        // Two orphaned destinations in different organizations don't count
        // against one another's two at a time.
        let list =
            due(&[("a1", "org:a", "nobody:org:a"), ("b1", "org:b", "nobody:org:b"), ("c1", "org:c", "nobody:org:c")]);
        let mut fair = Fair::default();
        fair.register(&list);
        assert_eq!(pick(&list, &fair, 16).len(), 3);
    }

    #[test]
    fn whoever_has_used_the_least_time_goes_first() {
        let list = due(&[("a1", "org:a", "p"), ("b1", "org:b", "q"), ("c1", "org:c", "q")]);
        let mut fair = Fair::default();
        fair.register(&list);
        fair.charge(&list[0], Duration::from_secs(30));
        let picked = pick(&list, &fair, 1);
        assert_eq!(picked[0].person, "q");
        // Within a person, the scope that has used the least.
        fair.charge(&list[1], Duration::from_secs(5));
        let picked = pick(&list, &fair, 1);
        assert_eq!(picked[0].dest, "c1");
        // Someone new starts level with the least anyone has used, not at 0.
        let mut more = list.clone();
        more.extend(due(&[("e1", "org:e", "r")]));
        fair.register(&more);
        assert!(fair.used(&more[3]).0 > 0.0);
        // Decay keeps the order but forgives.
        let before = fair.used(&list[0]).0;
        fair.decay();
        assert!(fair.used(&list[0]).0 < before);
        assert_eq!(pick(&list, &fair, 1)[0].person, "q");
    }

    /// One owner with many slow destinations (each turn takes the whole
    /// turn) against one ordinary destination that takes a tenth of a
    /// second: on a worker with few slots, the ordinary one still gets a
    /// turn in every round after the first, and the owner never has more
    /// than PER_PERSON at once.
    #[test]
    fn many_slow_scopes_from_one_owner_dont_starve_anyone_else() {
        let mut list: Vec<Candidate> = (0..40)
            .map(|i| Candidate {
                dest: format!("slow{i:02}"),
                scope: format!("org:slow{i:02}"),
                person: "owner".into(),
            })
            .collect();
        list.push(Candidate {
            dest: "normal".into(),
            scope: "org:normal".into(),
            person: "someone".into(),
        });
        let mut fair = Fair::default();
        let mut normal_turns = 0;
        for round in 0..50 {
            fair.register(&list);
            let picked = pick(&list, &fair, 3);
            assert!(picked.iter().filter(|c| c.person == "owner").count() <= PER_PERSON);
            if picked.iter().any(|c| c.dest == "normal") {
                normal_turns += 1;
            } else {
                assert_eq!(round, 0, "the ordinary destination waited in round {round}");
            }
            for c in &picked {
                let took = if c.person == "owner" {
                    TURN
                } else {
                    Duration::from_millis(100)
                };
                fair.charge(c, took);
            }
            if round % 10 == 9 {
                fair.decay();
            }
        }
        assert!(normal_turns >= 49);
    }

    #[test]
    fn what_receivers_echo_has_the_destination_s_secrets_taken_out() {
        let target = Target {
            id: "d".into(),
            kind: EventKind::Webhook,
            settings: EventSettings::default(),
            secrets: EventSecrets {
                url: Some("https://siem.example/in/abc123?token=s3cr3t&x=1".into()),
                signing_secret: Some("whsec_abcdef".into()),
                header_value: Some("Bearer tok-xyz".into()),
                client_secret: None,
            },
        };
        let text = "401: bad token tok-xyz for /in/abc123?token=s3cr3t&x=1 (Bearer tok-xyz)";
        let out = target.redact(text);
        for secret in ["tok-xyz", "s3cr3t", "/in/abc123", "token=s3cr3t"] {
            assert!(!out.contains(secret), "{out}");
        }
        assert!(out.starts_with("401: bad token [hidden]"), "{out}");
    }

    fn webhook_to(url: &str) -> Target {
        Target {
            id: "d".into(),
            kind: EventKind::Webhook,
            settings: EventSettings::default(),
            secrets: EventSecrets {
                url: Some(url.to_owned()),
                signing_secret: Some("whsec_abcdef".into()),
                header_value: Some("Bearer tok-xyz".into()),
                client_secret: None,
            },
        }
    }

    /// What the server's log says when a destination can't be reached: the
    /// error as reqwest or the TLS library describes it, which can name the
    /// URL, without the URL's secret path and query, or any other secret.
    #[test]
    fn the_log_never_gets_a_destinations_secrets() {
        let target = webhook_to("https://collector.example/hooks/8f3a9c1e7b2d4f60/in?code=s3cr3t-value&x=1");
        let error = "reqwest::Error { kind: Request, url: \"https://collector.example/hooks/8f3a9c1e7b2d4f60/in?code=s3cr3t-value&x=1\", source: ConnectError(\"tcp connect error\", Os { code: 61 }) } tok-xyz";
        let logged = target.scrub(error);
        for secret in ["8f3a9c1e7b2d4f60", "s3cr3t-value", "code=", "tok-xyz", "/hooks/"] {
            assert!(!logged.contains(secret), "{logged}");
        }
        assert!(logged.contains("tcp connect error"), "{logged}");
        // Unlike what people are shown, the log isn't cut short.
        let long = "x".repeat(SHOWN * 2);
        assert_eq!(target.scrub(&long), long);
    }

    /// A collector that echoes the path, where the cut to 200 characters
    /// would fall inside a token in it: the token is hidden before the cut,
    /// so no part of it shows, whether it's echoed raw, decoded, or as JSON
    /// escapes it.
    #[test]
    fn an_echoed_path_is_hidden_even_where_the_cut_would_split_it() {
        let token = "8f3a9c1e7b2d4f60a5e9c3b1d7f2a4e8";
        let target = Target {
            id: "d".into(),
            kind: EventKind::Webhook,
            settings: EventSettings::default(),
            secrets: EventSecrets {
                url: Some(format!("https://collector.example/hooks/{token}/ingest%20me")),
                signing_secret: Some("whsec_abcdef".into()),
                header_value: None,
                client_secret: None,
            },
        };
        for echoed in [
            format!("/hooks/{token}/ingest%20me"),
            format!("\\/hooks\\/{token}\\/ingest me"),
            format!("{token}/ingest me"),
        ] {
            // Put the token across the 200th character.
            let text = format!("{}{echoed} was not found", "x".repeat(SHOWN - 10));
            let out = target.redact(&text);
            assert!(out.chars().count() <= SHOWN + "[hidden]".len(), "{out}");
            assert!(!out.contains(&token[..3]), "{out}");
        }
        // Only the start of the token at the end (the answer was read only
        // so far): that start goes too.
        let out = target.redact(&format!("not found: {}", &token[..12]));
        assert_eq!(out, "not found: [hidden]");
        // Short path segments (shared words) stay.
        assert!(target.redact("no such hook").contains("hook"));
    }

    #[test]
    fn slow_isnt_failing() {
        let slow = Failure::slow("It took 9 seconds to answer.");
        assert!(slow.slow && !slow.stop && !slow.before_tls);
        let gone = unreachable("siem.example", "connection refused", &webhook_to("https://siem.example/in"));
        assert!(gone.before_tls && !gone.slow);
    }

    #[test]
    fn emails_say_only_the_status_or_the_kind_of_trouble() {
        let f = Failure::answered(StatusCode::GONE, "It answered 410 Gone: secret text".into(), true);
        assert_eq!(f.summary(), "It answered HTTP 410.");
        assert_eq!(
            unreachable("10.0.0.1", "refused", &webhook_to("https://10.0.0.1/in")).summary(),
            "It couldn't be reached."
        );
        assert_eq!(Failure::retry("10.0.0.1 closed the connection").summary(), "Sending to it failed.");
        assert_eq!(Failure::stop("Its secrets can't be read").summary(), "Its secrets can't be read");
    }
}

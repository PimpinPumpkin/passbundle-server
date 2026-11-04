//! Keykeeper: the change-password page lookup that upstream's apps ask the
//! icons service for (`GET /icons/change-password-uri?uri=`), so "Change
//! password" opens a site's own page instead of its home page. A site that
//! supports the W3C "well-known URL for changing passwords" gets that address;
//! anything else gets `null`, and the apps fall back to the site itself. The
//! apps check Apple's published list on the device before asking.
//!
//! The server reaches sites only the way it downloads icons: not when icon
//! downloads are off or go to an outside service, never to a blocked address
//! (the same HTTP client, which checks every address it resolves and every
//! redirect), only on the web's own ports (443, and 80), and at most two
//! requests per site a day. Anyone may ask, as for icons, so each address
//! (an IPv6 /64) gets a limited number of answers, the server looks up only
//! so many new sites a minute, and people asking about one site at once share
//! one lookup. See DESIGN.md, "Health (better than Watchtower)".

use std::{
    collections::HashMap,
    net::IpAddr,
    num::NonZeroU32,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use reqwest::Client;
use rocket::{Route, serde::json::Json};
use serde_json::{Value, json};
use tokio::sync::OnceCell;
use url::Url;

use crate::{
    CONFIG,
    api::ApiResult,
    auth::ClientIp,
    http_client::{get_reqwest_client_builder, get_valid_host, should_block_host},
    util::Cached,
};

pub fn routes() -> Vec<Route> {
    routes![change_password_uri]
}

const CHANGE_PASSWORD_PATH: &str = "/.well-known/change-password";
/// A path no site has. A site that answers it with success answers everything
/// that way, so its change-password answer means nothing.
const PROBE_PATH: &str = "/.well-known/resource-that-should-not-exist-whose-status-code-should-not-be-200";

/// How long an answer about a site is kept, here and by whoever asked.
const ANSWER_TTL: Duration = Duration::from_hours(24);
const MAX_ANSWERS: usize = 10_000;

static CLIENT: LazyLock<Client> = LazyLock::new(|| {
    get_reqwest_client_builder(true)
        .timeout(Duration::from_secs(CONFIG.icon_download_timeout()))
        .build()
        .expect("Failed to build client")
});

/// A site's change-password page (or none), and when that was found out.
type Answer = (Option<String>, Instant);

/// Recent answers by site, so many people asking about one site cost it two requests a day.
static ANSWERS: LazyLock<Mutex<HashMap<String, Answer>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Lookups under way by site, which everyone asking about that site meanwhile
/// waits for. Holds `None` when the server was looking up too many sites.
type Lookup = Arc<OnceCell<Option<Option<String>>>>;
static UNDER_WAY: LazyLock<Mutex<HashMap<String, Lookup>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Answers per address: 30 at once, then one every 2 seconds. Apps ask when
/// someone changes a password, so people rarely come near it.
static PER_ADDRESS: LazyLock<RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>> = LazyLock::new(|| {
    RateLimiter::keyed(
        Quota::with_period(Duration::from_secs(2))
            .expect("non-zero")
            .allow_burst(NonZeroU32::new(30).expect("non-zero")),
    )
});
static CHECKS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Sites the server looks up, across everyone: 60 at once, then one a second.
/// Past that, a site's answer is "none" for now, and isn't kept.
static NEW_SITES: LazyLock<DefaultDirectRateLimiter> = LazyLock::new(|| {
    RateLimiter::direct(
        Quota::with_period(Duration::from_secs(1))
            .expect("non-zero")
            .allow_burst(NonZeroU32::new(60).expect("non-zero")),
    )
});

#[get("/change-password-uri?<uri>")]
async fn change_password_uri(uri: Option<&str>, ip: ClientIp) -> ApiResult<Cached<Json<Value>>> {
    if CHECKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 1024 == 1023 {
        PER_ADDRESS.retain_recent();
        PER_ADDRESS.shrink_to_fit();
    }
    if PER_ADDRESS.check_key(&crate::ratelimit::ip_key(&ip.ip)).is_err() {
        err_code!("Too many requests", 429)
    }
    let page = match uri.and_then(site_of) {
        Some(site) if downloads_allowed() => lookup(&site).await,
        _ => None,
    };
    Ok(Cached::ttl(Json(json!({ "uri": page })), ANSWER_TTL.as_secs(), false))
}

/// Whether the server may reach sites at all: the same rule as icon downloads.
fn downloads_allowed() -> bool {
    !CONFIG.disable_icon_download() && CONFIG.icon_service() == "internal"
}

/// The site (host, with a port other than the default) of an item's website,
/// with or without its scheme, or None when it isn't one the server may reach:
/// only the web's own ports, so the server can't be used to knock on others.
fn site_of(uri: &str) -> Option<String> {
    let uri = uri.trim();
    let url = Url::parse(&if uri.contains("://") {
        uri.to_owned()
    } else {
        format!("https://{uri}")
    })
    .ok()
    .filter(|url| url.scheme() == "https" || url.scheme() == "http")?;
    let host = get_valid_host(url.host_str()?).ok()?;
    should_block_host(&host).ok()?;
    let host = host.to_string().to_lowercase();
    match url.port() {
        Some(port @ (80 | 443)) => Some(format!("{host}:{port}")),
        Some(_) => None,
        None => Some(host),
    }
}

/// The site's change-password page, by the W3C check: the change-password
/// address answers with success, and a path no site has doesn't.
fn page_from_answers(site: &str, change_password: Option<u16>, probe: Option<u16>) -> Option<String> {
    let success = |status: Option<u16>| matches!(status, Some(200..=299));
    (success(change_password) && !success(probe)).then(|| format!("https://{site}{CHANGE_PASSWORD_PATH}"))
}

async fn status_of(url: String) -> Option<u16> {
    CLIENT.get(url).send().await.ok().map(|response| response.status().as_u16())
}

async fn lookup(site: &str) -> Option<String> {
    lookup_using(site, look_up).await
}

/// `lookup`, asking the site with `ask`.
async fn lookup_using(site: &str, ask: impl AsyncFnOnce(&str) -> Option<String>) -> Option<String> {
    if let Some((page, at)) = ANSWERS.lock().unwrap().get(site)
        && at.elapsed() < ANSWER_TTL
    {
        return page.clone();
    }
    // Join a lookup of this site that's under way, or start one.
    let under_way = Arc::clone(UNDER_WAY.lock().unwrap().entry(site.to_owned()).or_default());
    let found = under_way
        .get_or_init(async || {
            if NEW_SITES.check().is_err() {
                return None;
            }
            Some(ask(site).await)
        })
        .await
        .clone();
    {
        let mut lookups = UNDER_WAY.lock().unwrap();
        if lookups.get(site).is_some_and(|l| Arc::ptr_eq(l, &under_way)) {
            lookups.remove(site);
        }
    }
    let page = found?;
    remember(site, page.clone());
    page
}

/// Asks the site itself.
async fn look_up(site: &str) -> Option<String> {
    let probe = status_of(format!("https://{site}{PROBE_PATH}")).await;
    if matches!(probe, Some(200..=299)) {
        None
    } else {
        page_from_answers(site, status_of(format!("https://{site}{CHANGE_PASSWORD_PATH}")).await, probe)
    }
}

/// Keeps a site's answer for ANSWER_TTL, within MAX_ANSWERS.
fn remember(site: &str, page: Option<String>) {
    let mut answers = ANSWERS.lock().unwrap();
    if answers.len() >= MAX_ANSWERS {
        answers.retain(|_, (_, at)| at.elapsed() < ANSWER_TTL);
        if answers.len() >= MAX_ANSWERS {
            answers.clear();
        }
    }
    answers.insert(site.to_owned(), (page, Instant::now()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_site_that_supports_the_standard_gets_its_change_password_address() {
        assert_eq!(
            page_from_answers("accounts.example.com", Some(200), Some(404)),
            Some("https://accounts.example.com/.well-known/change-password".to_owned())
        );
        // The probe failing outright still means the site doesn't answer everything.
        assert_eq!(
            page_from_answers("example.com:8443", Some(204), None),
            Some("https://example.com:8443/.well-known/change-password".to_owned())
        );
    }

    #[test]
    fn a_site_that_answers_everything_or_lacks_the_page_gets_nothing() {
        assert_eq!(page_from_answers("example.com", Some(200), Some(200)), None);
        assert_eq!(page_from_answers("example.com", Some(404), Some(404)), None);
        assert_eq!(page_from_answers("example.com", Some(500), Some(404)), None);
        assert_eq!(page_from_answers("example.com", None, Some(404)), None);
    }

    #[test]
    fn reads_an_items_website_with_or_without_its_scheme() {
        assert_eq!(site_of("https://Accounts.Example.com/login?next=/"), Some("accounts.example.com".to_owned()));
        assert_eq!(site_of("example.com/login"), Some("example.com".to_owned()));
        assert_eq!(site_of("https://example.com:443/"), Some("example.com".to_owned()));
        assert_eq!(site_of("http://example.com:443/"), Some("example.com:443".to_owned()));
        assert_eq!(site_of("http://example.com"), Some("example.com".to_owned()));
    }

    #[test]
    fn refuses_what_isnt_a_website_the_server_may_reach() {
        assert_eq!(site_of(""), None);
        assert_eq!(site_of("androidapp://com.example.app"), None);
        assert_eq!(site_of("ftp://example.com"), None);
        assert_eq!(site_of("https://127.0.0.1/"), None);
        assert_eq!(site_of("https://192.168.1.10/"), None);
        assert_eq!(site_of("https://[::1]/"), None);
        // Only the web's own ports.
        assert_eq!(site_of("https://example.com:8443/"), None);
        assert_eq!(site_of("example.com:22"), None);
        assert_eq!(site_of("http://example.com:6379"), None);
        // Never the cloud's metadata services, whatever the settings.
        assert_eq!(site_of("http://168.63.129.16/"), None);
        assert_eq!(site_of("https://[64:ff9b::a9fe:a9fe]/"), None);
    }

    #[tokio::test]
    async fn people_asking_about_one_site_at_once_share_one_lookup() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let site = "shared-lookup.example";
        let page = format!("https://{site}{CHANGE_PASSWORD_PATH}");
        let asked = AtomicUsize::new(0);
        let ask = async |s: &str| {
            asked.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            Some(format!("https://{s}{CHANGE_PASSWORD_PATH}"))
        };
        // Five people at once: the site is asked once, and they all get its answer.
        let answers = futures::future::join_all((0..5).map(|_| lookup_using(site, ask))).await;
        assert!(answers.iter().all(|a| a.as_ref() == Some(&page)), "{answers:?}");
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert!(!UNDER_WAY.lock().unwrap().contains_key(site));
        // And the answer is kept: asking again doesn't ask the site.
        assert_eq!(lookup_using(site, ask).await, Some(page));
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }
}

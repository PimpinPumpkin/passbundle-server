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
//! redirect), and at most two requests per site a day. See DESIGN.md, "Health
//! (better than Watchtower)".

use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

use reqwest::Client;
use rocket::{Route, serde::json::Json};
use serde_json::{Value, json};
use url::Url;

use crate::{
    CONFIG,
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

#[get("/change-password-uri?<uri>")]
async fn change_password_uri(uri: Option<&str>) -> Cached<Json<Value>> {
    let page = match uri.and_then(site_of) {
        Some(site) if downloads_allowed() => lookup(&site).await,
        _ => None,
    };
    Cached::ttl(Json(json!({ "uri": page })), ANSWER_TTL.as_secs(), false)
}

/// Whether the server may reach sites at all: the same rule as icon downloads.
fn downloads_allowed() -> bool {
    !CONFIG.disable_icon_download() && CONFIG.icon_service() == "internal"
}

/// The site (host, with a port other than the default) of an item's website,
/// with or without its scheme, or None when it isn't one the server may reach.
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
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
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
    if let Some((page, at)) = ANSWERS.lock().unwrap().get(site)
        && at.elapsed() < ANSWER_TTL
    {
        return page.clone();
    }
    let probe = status_of(format!("https://{site}{PROBE_PATH}")).await;
    let page = if matches!(probe, Some(200..=299)) {
        None
    } else {
        page_from_answers(site, status_of(format!("https://{site}{CHANGE_PASSWORD_PATH}")).await, probe)
    };
    let mut answers = ANSWERS.lock().unwrap();
    if answers.len() >= MAX_ANSWERS {
        answers.retain(|_, (_, at)| at.elapsed() < ANSWER_TTL);
        if answers.len() >= MAX_ANSWERS {
            answers.clear();
        }
    }
    answers.insert(site.to_owned(), (page.clone(), Instant::now()));
    page
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
        assert_eq!(site_of("https://example.com:8443/"), Some("example.com:8443".to_owned()));
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
    }
}

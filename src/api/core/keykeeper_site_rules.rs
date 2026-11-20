//! Keykeeper: the server's mirror of a signed site rules feed, for the
//! extension's fill rules (the meta repo's DESIGN.md, "Fill rules for
//! everyone", "Shipping: a signed feed"). `SITE_RULES_FEED`, set only in the
//! environment, says whose feed: `passbundle` (the default, PassBundle's own,
//! at https://rules.passbundle.com/), the URL of the operator's own feed with
//! its Ed25519 public key in `SITE_RULES_FEED_KEY`, or `none`.
//!
//! Every 6 hours the server fetches the feed's `manifest.json`, through the
//! same guard as its other fetches ("What the server fetches"), and only when
//! the manifest changed its signature, and the rules file only when the
//! SHA-256 the manifest names changed. It keeps a set only when the rules
//! file is the one its manifest names, and serves the three files unchanged
//! at `/api/keykeeper/site-rules/<name>` to anyone signed in, with whose feed
//! it is at `/api/keykeeper/site-rules`. It never checks the signature or
//! changes a byte: the extension checks the signature on the device, so the
//! server can only hold a feed back, and clients drop a feed when it expires.
//! A fetch that fails (PassBundle's feed isn't published yet) is one quiet
//! log line, and the next try is the next check.

use std::{
    net::IpAddr,
    sync::{Arc, LazyLock, RwLock},
    time::Duration,
};

use reqwest::Client;
use rocket::{
    Route,
    http::{ContentType, Status},
    serde::json::Json,
};
use serde_json::{Value, json};
use url::Url;

use crate::{CONFIG, auth::Headers, http_client::get_reqwest_client_builder};

pub fn routes() -> Vec<Route> {
    routes![source, file]
}

/// PassBundle's own feed, `SITE_RULES_FEED=passbundle`.
pub const PASSBUNDLE_FEED: &str = "https://rules.passbundle.com/";

/// How often the server checks the feed.
pub const CHECK_EVERY: Duration = Duration::from_hours(6);

/// The most each file may be. The extension's limits are the same.
const MAX_MANIFEST: usize = 64 * 1024;
const MAX_SIGNATURE: usize = 1024;
const MAX_RULES: usize = 4 * 1024 * 1024;

const MANIFEST: &str = "manifest.json";
const SIGNATURE: &str = "manifest.json.sig";

/// Whose feed the server mirrors, from `SITE_RULES_FEED` and `SITE_RULES_FEED_KEY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedSetting {
    /// PassBundle's own feed, checked with the keys built into the extension.
    PassBundle,
    /// The operator's own feed, at this address, checked with this key (64 lowercase hex digits).
    Operator {
        url: Url,
        key: String,
    },
    /// No feed.
    None,
}

impl FeedSetting {
    /// Where the feed's files are, if there's a feed.
    fn base(&self) -> Option<Url> {
        match self {
            FeedSetting::PassBundle => Url::parse(PASSBUNDLE_FEED).ok(),
            FeedSetting::Operator {
                url,
                ..
            } => Some(url.clone()),
            FeedSetting::None => None,
        }
    }
}

/// Reads `SITE_RULES_FEED` and `SITE_RULES_FEED_KEY`: `passbundle` or
/// `none` without a key, or an operator's feed: an https address (or http to
/// this machine only), with a host and without credentials, a query, a
/// fragment, or surrounding whitespace, and its Ed25519 public key as 64
/// lowercase hex digits. A feed's address is a folder: a trailing `/` is
/// added when it's missing.
pub fn parse_setting(feed: &str, key: &str) -> Result<FeedSetting, String> {
    match feed {
        "passbundle" | "none" => {
            if !key.is_empty() {
                return Err(format!(
                    "`SITE_RULES_FEED_KEY` is only for your own feed's address, not with `SITE_RULES_FEED={feed}`."
                ));
            }
            Ok(if feed == "passbundle" {
                FeedSetting::PassBundle
            } else {
                FeedSetting::None
            })
        }
        _ => {
            let url = feed_url(feed).ok_or_else(|| {
                "`SITE_RULES_FEED` must be `passbundle`, `none`, or your own feed's address: https (or http to this \
                 machine only), without credentials, query parameters, fragments, or surrounding whitespace."
                    .to_owned()
            })?;
            if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err(
                    "`SITE_RULES_FEED_KEY` must be your feed's Ed25519 public key, as 64 lowercase hex digits."
                        .to_owned(),
                );
            }
            Ok(FeedSetting::Operator {
                url,
                key: key.to_owned(),
            })
        }
    }
}

fn feed_url(text: &str) -> Option<Url> {
    if text.trim() != text || text.is_empty() {
        return None;
    }
    let mut url = Url::parse(text).ok()?;
    let to_this_machine = match url.host()? {
        url::Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => IpAddr::V4(ip).is_loopback(),
        url::Host::Ipv6(ip) => IpAddr::V6(ip).is_loopback(),
    };
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && to_this_machine);
    if !scheme_ok
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Some(url)
}

/// The setting as configured. The config check at start refuses a bad one.
pub fn setting() -> FeedSetting {
    parse_setting(&CONFIG.site_rules_feed(), &CONFIG.site_rules_feed_key()).unwrap_or(FeedSetting::None)
}

/// A feed's files as mirrored: exactly the bytes fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mirrored {
    pub manifest: Vec<u8>,
    pub signature: Vec<u8>,
    pub rules_name: String,
    pub rules: Vec<u8>,
    pub sha256: String,
}

static MIRROR: LazyLock<RwLock<Option<Arc<Mirrored>>>> = LazyLock::new(|| RwLock::new(None));

fn mirrored() -> Option<Arc<Mirrored>> {
    MIRROR.read().ok().and_then(|m| m.clone())
}

/// The rules file a manifest names, and its SHA-256: read without checking
/// the signature, only to know which file to fetch and that it's the one.
fn named_rules(manifest: &[u8]) -> Option<(String, String)> {
    let raw: Value = serde_json::from_slice(manifest).ok()?;
    let forms = raw.get("maps")?.get("forms")?.get("v1")?;
    let name = forms.get("filename")?.as_str()?;
    let sha256 = forms.get("sha256")?.as_str()?;
    let name_ok = name.len() <= 105
        // As the extension reads it: `.json`, in lower case.
        && name.as_bytes().ends_with(b".json")
        && name != MANIFEST
        && name.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    let sha_ok = sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    (name_ok && sha_ok).then(|| (name.to_owned(), sha256.to_owned()))
}

/// One check of the feed at `base`, against the set mirrored now. `Ok(None)`
/// when nothing changed; `Ok(Some(set))` for a new set to serve. Fetches the
/// signature only when the manifest changed, and the rules file only when the
/// manifest names another one.
pub async fn check(
    base: &Url,
    current: Option<&Mirrored>,
    get: impl AsyncFn(Url, usize) -> Result<Vec<u8>, String>,
) -> Result<Option<Mirrored>, String> {
    let join = |name: &str| base.join(name).map_err(|e| e.to_string());
    let manifest = get(join(MANIFEST)?, MAX_MANIFEST).await?;
    if current.is_some_and(|c| c.manifest == manifest) {
        return Ok(None);
    }
    let signature = get(join(SIGNATURE)?, MAX_SIGNATURE).await?;
    let (rules_name, sha256) = named_rules(&manifest).ok_or("its manifest names no rules file")?;
    let rules = match current {
        Some(c) if c.sha256 == sha256 && c.rules_name == rules_name => c.rules.clone(),
        _ => {
            let rules = get(join(&rules_name)?, MAX_RULES).await?;
            if crate::crypto::sha256_hex(&rules) != sha256 {
                return Err("its rules file isn't the one its manifest names".to_owned());
            }
            rules
        }
    };
    Ok(Some(Mirrored {
        manifest,
        signature,
        rules_name,
        rules,
        sha256,
    }))
}

static CLIENT: LazyLock<Client> = LazyLock::new(|| {
    // Every address a name resolves to, and every redirect, is checked by the
    // same guard as icons and the change-password lookup.
    get_reqwest_client_builder(true).timeout(Duration::from_secs(30)).build().expect("Failed to build client")
});

/// A file of the feed, at most `max` bytes, through the server's fetch guard.
async fn fetch(url: Url, max: usize) -> Result<Vec<u8>, String> {
    let host = url.host().ok_or("no host")?.to_owned();
    crate::http_client::should_block_host(&host).map_err(|e| e.to_string())?;
    let mut response = CLIENT.get(url).send().await.map_err(|e| e.without_url().to_string())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("it answered {}", response.status().as_u16()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.without_url().to_string())? {
        if body.len() + chunk.len() > max {
            return Err(format!("a file is larger than {max} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Checks the feed now and every 6 hours, unless the setting is `none`.
pub fn start() {
    let setting = setting();
    let Some(base) = setting.base() else {
        return;
    };
    tokio::spawn(async move {
        loop {
            let current = mirrored();
            match check(&base, current.as_deref(), fetch).await {
                Ok(Some(set)) => {
                    if let Ok(mut mirror) = MIRROR.write() {
                        *mirror = Some(Arc::new(set));
                    }
                }
                Ok(None) => {}
                Err(why) => info!("Site rules feed: couldn't check {base} ({why}). The next check is in 6 hours."),
            }
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}

/// Whose feed this server mirrors, so the extension knows which key checks it.
#[get("/keykeeper/site-rules")]
fn source(_headers: Headers) -> Json<Value> {
    Json(match setting() {
        FeedSetting::PassBundle => json!({ "feed": "passbundle" }),
        FeedSetting::Operator {
            key,
            ..
        } => json!({ "feed": "operator", "key": key }),
        FeedSetting::None => json!({ "feed": "none" }),
    })
}

/// One of the mirrored files, exactly as fetched.
#[get("/keykeeper/site-rules/<name>")]
fn file(name: &str, _headers: Headers) -> Result<(ContentType, Vec<u8>), Status> {
    let set = mirrored().ok_or(Status::NotFound)?;
    if name == MANIFEST {
        Ok((ContentType::JSON, set.manifest.clone()))
    } else if name == SIGNATURE {
        Ok((ContentType::Plain, set.signature.clone()))
    } else if name == set.rules_name {
        Ok((ContentType::JSON, set.rules.clone()))
    } else {
        Err(Status::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn the_setting_is_passbundle_none_or_an_operators_feed_with_its_key() {
        let key = "8bb04e1c1b83dddf311f5bcddf7c50ede3c0802f47ec796e2a131cf41298d9f3";
        assert_eq!(parse_setting("passbundle", ""), Ok(FeedSetting::PassBundle));
        assert_eq!(parse_setting("none", ""), Ok(FeedSetting::None));
        assert_eq!(
            parse_setting("https://rules.example.com/feed", key),
            Ok(FeedSetting::Operator {
                url: Url::parse("https://rules.example.com/feed/").unwrap(),
                key: key.to_owned(),
            })
        );
        assert_eq!(
            parse_setting("https://rules.example.com/", key).unwrap().base().unwrap().as_str(),
            "https://rules.example.com/"
        );
        // Plain http only to this machine.
        for local in ["http://127.0.0.1:8182/", "http://localhost:8182/feed/", "http://[::1]/"] {
            assert!(matches!(parse_setting(local, key), Ok(FeedSetting::Operator { .. })), "{local}");
        }
        for bad in [
            "",
            "PassBundle",
            " passbundle",
            "http://rules.example.com/",
            "http://10.0.0.2/",
            "ftp://rules.example.com/",
            "https://user:pass@rules.example.com/",
            "https://rules.example.com/?x=1",
            "https://rules.example.com/#x",
            "https://rules.example.com/ ",
            "rules.example.com",
        ] {
            assert!(parse_setting(bad, key).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_operators_feed_needs_its_key_and_ours_takes_none() {
        let url = "https://rules.example.com/";
        let key = "8bb04e1c1b83dddf311f5bcddf7c50ede3c0802f47ec796e2a131cf41298d9f3";
        assert!(parse_setting(url, "").is_err());
        assert!(parse_setting(url, &key.to_uppercase()).is_err());
        assert!(parse_setting(url, &key[2..]).is_err());
        assert!(parse_setting(url, &format!("{key} ")).is_err());
        assert!(parse_setting(url, "i7BOHBuD3d8xX7XN33xQ7ePAgC9H7HluKhMc9BKY2fM=").is_err());
        assert!(parse_setting("passbundle", key).is_err());
        assert!(parse_setting("none", key).is_err());
    }

    #[test]
    fn the_default_is_passbundles_feed() {
        assert_eq!(FeedSetting::PassBundle.base().unwrap().as_str(), PASSBUNDLE_FEED);
        assert_eq!(FeedSetting::None.base(), None);
    }

    /// A stand-in feed host: its files, and every URL asked for.
    struct Feed {
        files: Mutex<Vec<(String, Vec<u8>)>>,
        asked: Mutex<Vec<String>>,
    }

    impl Feed {
        fn new(files: &[(&str, Vec<u8>)]) -> Self {
            Feed {
                files: Mutex::new(files.iter().map(|(n, b)| ((*n).to_owned(), b.clone())).collect()),
                asked: Mutex::new(Vec::new()),
            }
        }

        fn set(&self, name: &str, bytes: Vec<u8>) {
            let mut files = self.files.lock().unwrap();
            files.retain(|(n, _)| n != name);
            files.push((name.to_owned(), bytes));
        }

        fn asked(&self) -> Vec<String> {
            std::mem::take(&mut *self.asked.lock().unwrap())
        }

        async fn get(&self, url: Url, max: usize) -> Result<Vec<u8>, String> {
            let name = url.path().rsplit('/').next().unwrap_or("").to_owned();
            self.asked.lock().unwrap().push(name.clone());
            let files = self.files.lock().unwrap();
            let bytes = files.iter().find(|(n, _)| *n == name).map(|(_, b)| b.clone()).ok_or("404")?;
            if bytes.len() > max {
                return Err("too large".to_owned());
            }
            Ok(bytes)
        }
    }

    fn manifest(name: &str, rules: &[u8], sequence: u32) -> Vec<u8> {
        let sha = crate::crypto::sha256_hex(rules);
        format!(
            r#"{{"maps":{{"forms":{{"v1":{{"filename":"{name}","cid":"{sha}","sha256":"{sha}"}}}}}},"passbundle":{{"sequence":{sequence},"issued":"2026-11-18T00:00:00Z","expires":"2026-12-02T00:00:00Z"}}}}"#
        )
        .into_bytes()
    }

    async fn check_with(feed: &Feed, current: Option<&Mirrored>) -> Result<Option<Mirrored>, String> {
        let base = Url::parse("https://rules.example.com/").unwrap();
        check(&base, current, async |url, max| feed.get(url, max).await).await
    }

    #[tokio::test]
    async fn the_mirror_downloads_only_what_changed() {
        let rules = br#"{"schemaVersion":"1.0.0","hosts":{}}"#.to_vec();
        let feed = Feed::new(&[
            ("manifest.json", manifest("forms-a.json", &rules, 1)),
            ("manifest.json.sig", b"signature-1\n".to_vec()),
            ("forms-a.json", rules.clone()),
        ]);

        // The first check fetches all three, exactly as served.
        let first = check_with(&feed, None).await.unwrap().unwrap();
        assert_eq!(feed.asked(), ["manifest.json", "manifest.json.sig", "forms-a.json"]);
        assert_eq!(first.rules, rules);
        assert_eq!(first.signature, b"signature-1\n");

        // Nothing changed: only the manifest.
        assert_eq!(check_with(&feed, Some(&first)).await, Ok(None));
        assert_eq!(feed.asked(), ["manifest.json"]);

        // Signed again (a new sequence), the same rules: no rules download.
        feed.set("manifest.json", manifest("forms-a.json", &rules, 2));
        feed.set("manifest.json.sig", b"signature-2\n".to_vec());
        let second = check_with(&feed, Some(&first)).await.unwrap().unwrap();
        assert_eq!(feed.asked(), ["manifest.json", "manifest.json.sig"]);
        assert_eq!(second.signature, b"signature-2\n");
        assert_eq!(second.rules, rules);

        // New rules: downloaded.
        let newer = br#"{"schemaVersion":"1.0.0","hosts":{"a.example.test":null}}"#.to_vec();
        feed.set("manifest.json", manifest("forms-b.json", &newer, 3));
        feed.set("forms-b.json", newer.clone());
        let third = check_with(&feed, Some(&second)).await.unwrap().unwrap();
        assert_eq!(feed.asked(), ["manifest.json", "manifest.json.sig", "forms-b.json"]);
        assert_eq!(third.rules, newer);
        assert_eq!(third.rules_name, "forms-b.json");
    }

    #[tokio::test]
    async fn the_mirror_keeps_a_set_only_when_its_rules_file_is_the_one_named() {
        let rules = br#"{"schemaVersion":"1.0.0","hosts":{}}"#.to_vec();
        let feed = Feed::new(&[
            ("manifest.json", manifest("forms-a.json", &rules, 1)),
            ("manifest.json.sig", b"sig\n".to_vec()),
            ("forms-a.json", br#"{"schemaVersion":"1.0.0","hosts":{"x":null}}"#.to_vec()),
        ]);
        assert!(check_with(&feed, None).await.is_err());

        // A rules file name that could leave the feed's folder isn't fetched.
        feed.set("manifest.json", manifest("../forms-a.json", &rules, 1));
        assert!(check_with(&feed, None).await.is_err());
        assert_eq!(
            feed.asked(),
            ["manifest.json", "manifest.json.sig", "forms-a.json", "manifest.json", "manifest.json.sig"]
        );

        // Not JSON, or naming no rules file.
        feed.set("manifest.json", b"not json".to_vec());
        assert!(check_with(&feed, None).await.is_err());
    }

    #[tokio::test]
    async fn a_failed_fetch_changes_nothing() {
        let feed = Feed::new(&[]);
        assert!(check_with(&feed, None).await.is_err());
        assert_eq!(feed.asked(), ["manifest.json"]);
    }

    #[test]
    fn a_rules_file_name_stays_in_the_feeds_folder() {
        let named = |name: &str| named_rules(&manifest(name, b"x", 1)).map(|(n, _)| n);
        assert_eq!(named("forms-0123.json").as_deref(), Some("forms-0123.json"));
        for bad in ["../x.json", "a/b.json", "a\\\\b.json", "forms.txt", "manifest.json", ".hidden.json", "x%2f.json"] {
            assert_eq!(named(bad), None, "{bad}");
        }
    }
}

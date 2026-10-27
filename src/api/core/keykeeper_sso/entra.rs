// Keykeeper: talking to Microsoft Entra ID for an organization's single
// sign-on: its tenant's OpenID configuration, its signing keys, and the token
// endpoint that redeems a sign-in's code. Everything is per tenant, at
// `https://login.microsoftonline.com/<tenant id>/v2.0`, as Microsoft's
// "OpenID Connect on the Microsoft identity platform" describes. Discovery
// and keys are cached per tenant (keys refetched when a token names one we
// don't have, at most every five minutes, as Microsoft's "Signing key
// rollover" asks). No redirects are followed, and answers are capped in size.

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use reqwest::Client;
use serde_json::Value;

use super::token::{Jwk, issuer, parse_jwks};
use crate::{CONFIG, http_client::get_reqwest_client_builder};

/// The largest answer read from Microsoft.
const MAX_ANSWER: usize = 256 * 1024;
/// How soon a tenant's keys may be fetched again for an unknown key id.
const KEY_REFETCH: Duration = Duration::from_mins(5);

static CLIENT: LazyLock<Client> = LazyLock::new(|| {
    get_reqwest_client_builder(false)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to build the Microsoft sign-in client")
});

/// A tenant's OpenID configuration, the parts this server uses.
#[derive(Clone, Debug)]
pub struct Provider {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

static PROVIDERS: LazyLock<moka::sync::Cache<String, Arc<Provider>>> =
    LazyLock::new(|| moka::sync::Cache::builder().max_capacity(10_000).time_to_live(Duration::from_hours(12)).build());
static KEYS: LazyLock<moka::sync::Cache<String, Arc<Vec<Jwk>>>> =
    LazyLock::new(|| moka::sync::Cache::builder().max_capacity(10_000).time_to_live(Duration::from_hours(24)).build());
static KEYS_FETCHED: LazyLock<Mutex<HashMap<String, Instant>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Where Entra sign-in lives: Microsoft's, unless a test server points it at
/// a stand-in (SSO_ENTRA_AUTHORITY). No trailing slash.
pub fn authority() -> String {
    CONFIG.sso_entra_authority().trim_end_matches('/').to_owned()
}

async fn get_json(url: &str) -> Result<Value, String> {
    let answer = CLIENT.get(url).send().await.map_err(|e| format!("couldn't reach Microsoft ({e})"))?;
    read_json(answer).await
}

async fn read_json(answer: reqwest::Response) -> Result<Value, String> {
    let status = answer.status();
    if answer.content_length().is_some_and(|n| n > MAX_ANSWER as u64) {
        return Err("Microsoft's answer was too large".to_owned());
    }
    let body = answer.bytes().await.map_err(|e| format!("couldn't read Microsoft's answer ({e})"))?;
    if body.len() > MAX_ANSWER {
        return Err("Microsoft's answer was too large".to_owned());
    }
    let json: Value = serde_json::from_slice(&body).map_err(|_| format!("Microsoft answered {status} with no JSON"))?;
    if !status.is_success() {
        // Microsoft's error codes and descriptions (AADSTS...) say what to fix.
        let error = json.get("error").and_then(Value::as_str).unwrap_or("error");
        let description = json.get("error_description").and_then(Value::as_str).unwrap_or("");
        let description: String = description.lines().next().unwrap_or("").chars().take(300).collect();
        return Err(format!("Microsoft answered {status}: {error} {description}").trim().to_owned());
    }
    Ok(json)
}

/// An endpoint from the tenant's configuration, which must be on the same
/// sign-in host, over HTTPS unless the authority itself isn't (a test
/// stand-in on this machine).
fn endpoint(config: &Value, name: &str, authority: &str) -> Result<String, String> {
    let url =
        config.get(name).and_then(Value::as_str).ok_or_else(|| format!("the tenant's configuration has no {name}"))?;
    if !url.starts_with(&format!("{authority}/")) {
        return Err(format!("the tenant's {name} isn't on {authority}"));
    }
    Ok(url.to_owned())
}

/// The tenant's OpenID configuration, checked: its issuer is the tenant's
/// own, and its endpoints are on the sign-in host.
pub async fn provider(tenant_id: &str) -> Result<Arc<Provider>, String> {
    if let Some(p) = PROVIDERS.get(tenant_id) {
        return Ok(p);
    }
    let authority = authority();
    let config = get_json(&format!("{authority}/{tenant_id}/v2.0/.well-known/openid-configuration")).await?;
    let expected = issuer(&authority, tenant_id);
    if config.get("issuer").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err(format!("the tenant's configuration doesn't name its own issuer ({expected})"));
    }
    let p = Arc::new(Provider {
        issuer: expected,
        authorization_endpoint: endpoint(&config, "authorization_endpoint", &authority)?,
        token_endpoint: endpoint(&config, "token_endpoint", &authority)?,
        jwks_uri: endpoint(&config, "jwks_uri", &authority)?,
    });
    PROVIDERS.insert(tenant_id.to_owned(), Arc::clone(&p));
    Ok(p)
}

/// The tenant's signing keys. `refresh` fetches them again (a token named a
/// key we don't have), unless that happened in the last five minutes.
pub async fn keys(tenant_id: &str, provider: &Provider, refresh: bool) -> Result<Arc<Vec<Jwk>>, String> {
    if let Some(k) = KEYS.get(tenant_id) {
        let recent =
            KEYS_FETCHED.lock().map_or(true, |m| m.get(tenant_id).is_some_and(|at| at.elapsed() < KEY_REFETCH));
        if !refresh || recent {
            return Ok(k);
        }
    }
    let keys = Arc::new(parse_jwks(&get_json(&provider.jwks_uri).await?));
    if keys.is_empty() {
        return Err("the tenant publishes no signing keys".to_owned());
    }
    KEYS.insert(tenant_id.to_owned(), Arc::clone(&keys));
    if let Ok(mut m) = KEYS_FETCHED.lock() {
        // Forget tenants that haven't needed keys in a day, so the map stays small.
        m.retain(|_, at| at.elapsed() < Duration::from_hours(24));
        m.insert(tenant_id.to_owned(), Instant::now());
    }
    Ok(keys)
}

/// What redeeming a code needs.
pub struct Redeem<'a> {
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub code: &'a str,
    pub code_verifier: &'a str,
    pub redirect_uri: &'a str,
}

/// Redeems the authorization code at the tenant's token endpoint (with the
/// app's client secret and this server's PKCE verifier) and returns the ID
/// token. Nothing else in the answer is kept: single sign-on only proves who
/// someone is, and the session is PassBundle's own.
pub async fn redeem(provider: &Provider, r: &Redeem<'_>) -> Result<String, String> {
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", r.client_id),
        ("client_secret", r.client_secret),
        ("code", r.code),
        ("code_verifier", r.code_verifier),
        ("redirect_uri", r.redirect_uri),
        ("scope", super::SCOPES),
    ];
    let answer = CLIENT
        .post(&provider.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("couldn't reach Microsoft's token endpoint ({e})"))?;
    let json = read_json(answer).await?;
    json.get("id_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "Microsoft's token endpoint returned no ID token".to_owned())
}

/// Forgets what's cached for a tenant, when an organization's settings change.
pub fn forget(tenant_id: &str) {
    PROVIDERS.invalidate(tenant_id);
    KEYS.invalidate(tenant_id);
    if let Ok(mut m) = KEYS_FETCHED.lock() {
        m.remove(tenant_id);
    }
}

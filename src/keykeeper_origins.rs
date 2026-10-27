//! PassBundle: which pages may frame the vault's pages, where a security
//! key's answer may come from, and HTTPS only (DESIGN.md, "Connector pages").
//!
//! The web vault's connector pages (`*-connector.html`) read their inputs from
//! the address, so a page anywhere could frame one. Upstream sent them with no
//! Content-Security-Policy and no X-Frame-Options, and the security key
//! connector answered whatever `parent` the address named: a phishing page
//! could frame it, relay the vault's sign-in challenge, and receive the key's
//! signature. The server now lets only the vault itself and PassBundle's own
//! extension frame any page, gives connector pages a policy of their own, and
//! refuses every security key answer made in a frame, whichever page asked
//! for it.

use serde::Deserialize;

use crate::{CONFIG, db::models::EventType, error::Error};

/// PassBundle's browser extension on Chrome and Edge: the ID Chromium derives
/// from the public key in the extension's manifest (passbundle-clients,
/// brand/brand.json "extension"). EXTENSION_IDS replaces this list, for a
/// development build loaded with another key.
pub const PASSBUNDLE_EXTENSION_IDS: &str = "cenoidjoogmoieibpcokkafjnaabhokg";

/// Checks EXTENSION_IDS: Chromium extension IDs (32 letters a to p),
/// separated by commas.
pub fn validate_extension_ids(ids: &str) -> Result<(), String> {
    for id in ids.split(',').map(str::trim) {
        if id.len() != 32 || !id.bytes().all(|b| (b'a'..=b'p').contains(&b)) {
            return Err(format!(
                "EXTENSION_IDS has '{id}', which isn't a Chrome or Edge extension ID (32 letters a to p)"
            ));
        }
    }
    Ok(())
}

/// The origins of PassBundle's extensions: `chrome-extension://<id>`.
pub fn extension_origins() -> Vec<String> {
    CONFIG
        .extension_ids()
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(|id| format!("chrome-extension://{id}"))
        .collect()
}

/// The frame-ancestors sources for every page the server sends: the vault
/// itself and PassBundle's extensions. No other extension (upstream's IDs and
/// every Firefox extension were allowed before), and nothing else on
/// connector pages; the vault's other pages add ALLOWED_IFRAME_ANCESTORS.
/// The extension opens connector pages in tabs of their own, never in frames,
/// and a security key answer made in a frame is refused anyway.
pub fn frame_ancestors() -> String {
    let mut sources = vec!["'self'".to_owned()];
    sources.extend(extension_origins());
    sources.join(" ")
}

/// The policy for connector pages: their own scripts, styles, images, and
/// translations, nothing else, no plugins, and frame-ancestors above. Duo's
/// connector leaves for Duo by navigating, which the policy doesn't limit;
/// there are no captcha connectors anymore.
pub fn connector_csp() -> String {
    format!(
        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors {}",
        frame_ancestors()
    )
}

/// The Strict-Transport-Security value for a server at this DOMAIN: none
/// unless it's https on a real host name, since browsers would then insist on
/// HTTPS for localhost or an address (the Windows Hello test kit runs at
/// https://localhost, and the e2e tests at an address). includeSubDomains
/// only when HSTS_INCLUDE_SUBDOMAINS is on, since it binds every name under
/// the vault's host too.
pub fn hsts_value(domain: &str, include_subdomains: bool) -> Option<&'static str> {
    let url = url::Url::parse(domain).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    match url.host()? {
        url::Host::Domain(host) if host != "localhost" && !host.ends_with(".localhost") => {}
        _ => return None,
    }
    Some(if include_subdomains {
        "max-age=31536000; includeSubDomains"
    } else {
        "max-age=31536000"
    })
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "crossOrigin")]
    cross_origin: Option<bool>,
    #[serde(rename = "topOrigin")]
    top_origin: Option<String>,
}

/// Refuses a security key's answer (its clientDataJSON) that was made in a
/// frame: `crossOrigin` true, whatever page was around it, and any answer
/// that names a `topOrigin` at all. No PassBundle flow asks a key in a frame
/// that isn't on the vault's own origin: the web vault frames its own
/// connector, and the extension opens a tab. webauthn-rs checks crossOrigin
/// when a key is added, but not when it signs in.
pub fn check_assertion_origin(client_data_json: &[u8]) -> Result<(), Error> {
    let Ok(data) = serde_json::from_slice::<ClientData>(client_data_json) else {
        err!(
            "Unreadable security key answer",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        )
    };
    match (data.cross_origin.unwrap_or(false), &data.top_origin) {
        (true, _) | (_, Some(_)) => err!(
            "Your security key was used inside another page. Sign in on your vault's own page.",
            format!(
                "Refused a security key answer made in a frame (crossOrigin {:?}, topOrigin {:?})",
                data.cross_origin, data.top_origin
            ),
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        ),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(client_data: &str) -> bool {
        check_assertion_origin(client_data.as_bytes()).is_ok()
    }

    #[test]
    fn extension_ids_must_be_chromium_ids() {
        assert!(validate_extension_ids(PASSBUNDLE_EXTENSION_IDS).is_ok());
        assert!(validate_extension_ids("cenoidjoogmoieibpcokkafjnaabhokg, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_ok());
        assert!(validate_extension_ids("*").is_err());
        assert!(validate_extension_ids("").is_err());
        assert!(validate_extension_ids("cenoidjoogmoieibpcokkafjnaabhokz").is_err());
        assert!(validate_extension_ids("chrome-extension://cenoidjoogmoieibpcokkafjnaabhokg").is_err());
    }

    #[test]
    fn frame_ancestors_are_the_vault_and_our_extension() {
        assert_eq!(frame_ancestors(), "'self' chrome-extension://cenoidjoogmoieibpcokkafjnaabhokg");
        assert_eq!(
            connector_csp(),
            "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; \
             frame-ancestors 'self' chrome-extension://cenoidjoogmoieibpcokkafjnaabhokg"
        );
    }

    #[test]
    fn hsts_only_for_https_on_a_host_name() {
        assert_eq!(hsts_value("https://vault.example.com", false), Some("max-age=31536000"));
        assert_eq!(hsts_value("https://vault.example.com:8443/path", false), Some("max-age=31536000"));
        assert_eq!(hsts_value("https://vault.example.com", true), Some("max-age=31536000; includeSubDomains"));
        for domain in [
            "http://vault.example.com",
            "https://localhost",
            "https://localhost:8443",
            "https://vault.localhost",
            "https://127.0.0.1:8091",
            "https://10.0.0.5",
            "https://[::1]:8443",
            "not a url",
        ] {
            assert_eq!(hsts_value(domain, true), None, "{domain}");
        }
    }

    #[test]
    fn same_origin_answers_pass() {
        let origin = CONFIG.domain_origin();
        assert!(check(&format!(
            r#"{{"type":"webauthn.get","challenge":"abc","origin":"{origin}","crossOrigin":false}}"#
        )));
        // Older browsers leave crossOrigin out.
        assert!(check(&format!(r#"{{"type":"webauthn.get","challenge":"abc","origin":"{origin}"}}"#)));
    }

    #[test]
    fn answers_made_in_a_frame_are_refused_whatever_page_is_around_it() {
        let origin = CONFIG.domain_origin();
        for top in [
            origin.as_str(),
            "chrome-extension://cenoidjoogmoieibpcokkafjnaabhokg",
            "https://attacker.example.net",
            "chrome-extension://nngceckbapebfimnlniiiahkandclblb",
            "moz-extension://4b1e6a52-0000-4000-8000-000000000000",
            "null",
        ] {
            assert!(!check(&format!(r#"{{"origin":"{origin}","crossOrigin":true,"topOrigin":"{top}"}}"#)), "{top}");
            // Naming a page around it is refused whatever crossOrigin says.
            assert!(!check(&format!(r#"{{"origin":"{origin}","crossOrigin":false,"topOrigin":"{top}"}}"#)), "{top}");
        }
        // Cross-origin, without saying where.
        assert!(!check(&format!(r#"{{"origin":"{origin}","crossOrigin":true}}"#)));
    }

    #[test]
    fn odd_client_data_is_refused() {
        let origin = CONFIG.domain_origin();
        assert!(!check("not json"));
        assert!(!check(&format!(r#"{{"origin":"{origin}","crossOrigin":"true"}}"#)));
        assert!(!check(&format!(r#"{{"origin":"{origin}","crossOrigin":false,"crossOrigin":true}}"#)));
    }
}

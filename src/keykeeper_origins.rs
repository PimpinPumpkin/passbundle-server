//! PassBundle: which pages may frame the vault's pages, and where a security
//! key's answer may come from (DESIGN.md, "Connector pages").
//!
//! The web vault's connector pages (`*-connector.html`) read their inputs from
//! the address, so a page anywhere could frame one. Upstream sent them with no
//! Content-Security-Policy and no X-Frame-Options, and the security key
//! connector answered whatever `parent` the address named: a phishing page
//! could frame it, relay the vault's sign-in challenge, and receive the key's
//! signature. The server now lets only the vault itself and PassBundle's own
//! extension frame any page, and refuses a security key's answer made in a
//! frame on another site, whichever page asked for it.

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
/// so its origin here only keeps a framed flow of our own possible.
pub fn frame_ancestors() -> String {
    let mut sources = vec!["'self'".to_owned()];
    sources.extend(extension_origins());
    sources.join(" ")
}

/// Whether a page at this origin may ask for a security key's answer to the
/// vault from a frame: the vault itself, or PassBundle's extension.
fn is_allowed_top_origin(origin: &str) -> bool {
    origin == CONFIG.domain_origin() || extension_origins().iter().any(|o| o == origin)
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "crossOrigin")]
    cross_origin: Option<bool>,
    #[serde(rename = "topOrigin")]
    top_origin: Option<String>,
}

/// Refuses a security key's answer (its clientDataJSON) that was made in a
/// frame on another site: `crossOrigin` true, unless the page around it
/// (`topOrigin`) is the vault itself or PassBundle's extension. webauthn-rs
/// checks crossOrigin when a key is added, but not when it signs in. An
/// answer that says it's cross-origin without naming the page around it is
/// refused too, as is one that names a page elsewhere either way.
pub fn check_assertion_origin(client_data_json: &[u8]) -> Result<(), Error> {
    let Ok(data) = serde_json::from_slice::<ClientData>(client_data_json) else {
        err!(
            "Unreadable security key answer",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        )
    };
    let top_allowed = data.top_origin.as_deref().map(is_allowed_top_origin);
    match (data.cross_origin.unwrap_or(false), top_allowed) {
        (_, Some(false)) | (true, None) => err!(
            "Your security key was used on a page of another site. Sign in on your vault's own page.",
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
    fn answers_framed_by_the_vault_or_our_extension_pass() {
        let origin = CONFIG.domain_origin();
        assert!(check(&format!(r#"{{"origin":"{origin}","crossOrigin":true,"topOrigin":"{origin}"}}"#)));
        assert!(check(&format!(
            r#"{{"origin":"{origin}","crossOrigin":true,"topOrigin":"chrome-extension://cenoidjoogmoieibpcokkafjnaabhokg"}}"#
        )));
    }

    #[test]
    fn answers_framed_elsewhere_are_refused() {
        let origin = CONFIG.domain_origin();
        for top in [
            "https://attacker.example.net",
            "chrome-extension://nngceckbapebfimnlniiiahkandclblb",
            "moz-extension://4b1e6a52-0000-4000-8000-000000000000",
            "null",
        ] {
            assert!(!check(&format!(r#"{{"origin":"{origin}","crossOrigin":true,"topOrigin":"{top}"}}"#)), "{top}");
            // Naming a page elsewhere is refused whatever crossOrigin says.
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

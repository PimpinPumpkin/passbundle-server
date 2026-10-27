// Keykeeper: an organization's single sign-on client secret at rest. The
// server sends it to Microsoft whenever it redeems a sign-in's code, so it
// can't be hashed. It's sealed with event streaming's sealed-secrets module
// (keykeeper_streaming::secrets: AES-256-GCM under a key derived from the
// server's private RSA key, which lives with that key and never in the
// database), so a copy of the database, such as a backup kept at another
// company, doesn't reveal it. The key is single sign-on's own, derived over
// another label, so neither feature's ciphertexts open as the other's, and
// each secret is bound (as associated data) to its organization, so it can't
// be moved to another one. The key opens these secrets only: the server holds no key that can
// decrypt a vault. If the RSA key changes, the secret can't be read and
// sign-ins are refused until an admin enters it again.
// Test vectors: docs/vectors/sso-client-secret-v1.json in the meta repo (a
// copy is in vectors/ here), made with Node's crypto alone.
// See DESIGN.md, "Sign in with Microsoft Entra ID", "The client secret".

use std::sync::OnceLock;

use ring::aead::NONCE_LEN;
use zeroize::Zeroizing;

use crate::{db::models::OrganizationId, keykeeper_streaming::secrets};

static KEY: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();

/// The label single sign-on's key is derived over (event streaming's is
/// another).
const LABEL: &[u8] = b"passbundle sso client secrets v1";

const CANT: &str = "This server can't read the organization's single sign-on client secret anymore (its keys \
                    changed). An admin needs to enter it again on the Single sign-on page.";

/// Derives and keeps the key. Called once at startup, by auth::initialize_keys.
pub fn init(rsa_private_der: &[u8]) {
    // A second call (tests) keeps the first key.
    drop(KEY.set(secrets::derive_key_for(LABEL, rsa_private_der)));
}

fn key() -> Result<&'static [u8; 32], String> {
    KEY.get().map(|k| &**k).ok_or_else(|| "The server's keys aren't loaded yet".to_owned())
}

/// What a secret is bound to: its organization.
fn aad(org: &str) -> Vec<u8> {
    format!("sso client secret\u{0}organization {org}").into_bytes()
}

/// Seals an organization's client secret for the database.
pub fn seal(org: &OrganizationId, secret: &str) -> Result<String, String> {
    seal_with(key()?, secrets::random::<NONCE_LEN>(), org, secret)
}

/// `seal` with a given key and nonce. The nonce must never repeat under one
/// key; only `seal` (random nonces) and the test vectors call this.
fn seal_with(key: &[u8; 32], nonce: [u8; NONCE_LEN], org: &str, secret: &str) -> Result<String, String> {
    secrets::seal_aad_with(key, nonce, &aad(org), secret)
}

/// Opens what `seal` made for this organization, or says why it can't.
pub fn open(org: &OrganizationId, sealed: &str) -> Result<Zeroizing<String>, String> {
    open_with(key()?, org, sealed)
}

fn open_with(key: &[u8; 32], org: &str, sealed: &str) -> Result<Zeroizing<String>, String> {
    secrets::open_aad_with(key, &aad(org), sealed).ok_or_else(|| CANT.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap().try_into().unwrap()
    }

    /// docs/vectors/sso-client-secret-v1.json, made with Node's crypto.
    #[test]
    fn the_test_vectors_hold() {
        let v: serde_json::Value = serde_json::from_str(include_str!("vectors/sso-client-secret-v1.json")).unwrap();
        let s = |key: &str| v[key].as_str().unwrap().to_owned();
        assert_eq!(s("label").as_bytes(), LABEL);
        let der = data_encoding::BASE64.decode(s("rsaPkcs1Der").as_bytes()).unwrap();
        let key = hex32(&s("key"));
        let streaming_key = hex32(&s("streamingKey"));
        assert_eq!(*secrets::derive_key_for(LABEL, &der), key);
        // Event streaming's key, from the same RSA key, is another one.
        assert_eq!(*secrets::derive_key(&der), streaming_key);
        assert_ne!(key, streaming_key);

        let cases = v["cases"].as_array().unwrap();
        for case in cases {
            let org = case["organization"].as_str().unwrap();
            assert_eq!(aad(org), case["aad"].as_str().unwrap().as_bytes());
            let nonce: [u8; NONCE_LEN] =
                data_encoding::HEXLOWER.decode(case["nonce"].as_str().unwrap().as_bytes()).unwrap().try_into().unwrap();
            let plaintext = case["plaintext"].as_str().unwrap();
            let sealed = seal_with(&key, nonce, org, plaintext).unwrap();
            assert_eq!(sealed, case["sealed"].as_str().unwrap());
            assert_eq!(open_with(&key, org, &sealed).unwrap().as_str(), plaintext);
        }

        let first = &cases[0];
        let org = first["organization"].as_str().unwrap();
        let sealed = first["sealed"].as_str().unwrap();
        // Bound to its organization.
        for other in v["wrongOrganizations"].as_array().unwrap() {
            assert!(open_with(&key, other.as_str().unwrap(), sealed).is_err());
        }
        // Sealed with event streaming's key, even over this organization's
        // associated data, it isn't a client secret...
        let streamed = s("streamingSealed");
        assert_eq!(
            secrets::open_aad_with(&streaming_key, &aad(org), &streamed).unwrap().as_str(),
            first["plaintext"].as_str().unwrap()
        );
        assert_eq!(open_with(&key, org, &streamed).unwrap_err(), CANT);
        // ...and a client secret doesn't open with event streaming's key, as
        // a client secret or as a destination's secrets.
        assert!(secrets::open_aad_with(&streaming_key, &aad(org), sealed).is_none());
        let as_destination = secrets::Binding {
            id: org,
            owner: org,
            kind: "webhook",
        };
        assert!(secrets::open_with(&streaming_key, &as_destination, sealed).is_err());
    }

    #[test]
    fn event_streaming_vectors_dont_open_as_client_secrets() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../keykeeper_streaming/vectors/event-streaming-secrets-v1.json"))
                .unwrap();
        let der = data_encoding::BASE64.decode(v["rsaPkcs1Der"].as_str().unwrap().as_bytes()).unwrap();
        let key = secrets::derive_key_for(LABEL, &der);
        for case in v["cases"].as_array().unwrap() {
            let sealed = case["sealed"].as_str().unwrap();
            for org in [case["binding"]["id"].as_str().unwrap(), case["binding"]["owner"].as_str().unwrap()] {
                assert!(open_with(&key, org, sealed).is_err());
            }
        }
    }

    #[test]
    fn secrets_round_trip_only_for_their_organization() {
        init(b"0\x82\x01 test DER");
        let org = OrganizationId::from("2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e".to_owned());
        let other = OrganizationId::from("2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6f".to_owned());
        let sealed = seal(&org, "s3cr3t~value").unwrap();
        assert!(sealed.starts_with("v1."));
        assert!(!sealed.contains("s3cr3t"));
        assert_eq!(open(&org, &sealed).unwrap().as_str(), "s3cr3t~value");
        assert_eq!(open(&other, &sealed).unwrap_err(), CANT);
        // Nor does anything else.
        assert!(open(&org, "s3cr3t~value").is_err());
        assert!(open(&org, "v1.AAAA").is_err());
        // A fresh nonce every time.
        assert_ne!(seal(&org, "x").unwrap(), seal(&org, "x").unwrap());
    }
}

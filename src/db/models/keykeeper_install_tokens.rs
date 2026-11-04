// Keykeeper: install command tokens at rest (an MSP client's, or a company's
// own organization's). The database keeps a token's SHA-256, to find it by,
// as it keeps SCIM and script tokens, and never the token itself. Admins see
// the install command again whenever they open it, so the token is also kept
// sealed with AES-256-GCM under a key derived from the server's private RSA
// key, over a label of its own (as event streaming and single sign-on derive
// theirs), and bound to its organization: a copy of the database alone, such
// as a backup kept at another company, reveals no token. If the RSA key
// changes, the token still works, but admins make a new command to see one.
// Test vectors: docs/vectors/server-derived-keys-v1.json in the meta repo (a
// copy is in vectors/ here), made with Node's crypto alone.
// See DESIGN.md, "Onboarding through the RMM".

use std::sync::OnceLock;

use diesel::prelude::*;
use ring::aead::NONCE_LEN;
use zeroize::Zeroizing;

use crate::{
    db::{
        DbConn,
        keykeeper_schema::{msp_clients, org_setups},
    },
    error::MapResult,
    keykeeper_streaming::secrets,
};

use super::OrganizationId;

const LABEL: &[u8] = b"passbundle install command tokens v1";
static KEY: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();

/// Derives and keeps the key. Called once at startup, by auth::initialize_keys.
pub fn init_install_token_key(rsa_private_der: &[u8]) {
    // A second call (tests) keeps the first key.
    drop(KEY.set(secrets::derive_key_for(LABEL, rsa_private_der)));
}

/// The base64 SHA-256 of a token, as the server keeps it. A token is 256
/// random bits, so a fast hash is enough: there's nothing to guess.
pub fn token_hash(token: &str) -> String {
    data_encoding::BASE64.encode(ring::digest::digest(&ring::digest::SHA256, token.as_bytes()).as_ref())
}

/// What a sealed token is bound to: its organization.
fn aad(org: &str) -> Vec<u8> {
    format!("install command token\u{0}organization {org}").into_bytes()
}

/// A new install command token: 256 random bits, URL-safe.
pub fn new_install_token() -> String {
    crate::crypto::encode_random_bytes::<32>(&data_encoding::BASE64URL_NOPAD)
}

/// What the database keeps of a token: sealed, and its hash.
pub struct StoredToken {
    pub sealed: String,
    pub hash: String,
}

impl StoredToken {
    /// A new token for an organization, as the database keeps it.
    pub fn new(org: &OrganizationId) -> Result<Self, crate::error::Error> {
        Self::of(org, &new_install_token())
    }

    fn of(org: &OrganizationId, token: &str) -> Result<Self, crate::error::Error> {
        let Some(key) = KEY.get() else {
            err!("The server's keys aren't loaded yet")
        };
        match secrets::seal_aad_with(key, secrets::random::<NONCE_LEN>(), &aad(org.as_ref()), token) {
            Ok(sealed) => Ok(Self {
                sealed,
                hash: token_hash(token),
            }),
            Err(e) => err!(e),
        }
    }
}

/// The token a sealed one holds, for the install command admins see, or
/// None when it can't be opened (the server's RSA key changed).
pub fn open_install_token(org: &OrganizationId, sealed: &str) -> Option<String> {
    secrets::open_aad_with(KEY.get()?, &aad(org.as_ref()), sealed).map(|t| t.as_str().to_owned())
}

/// Tokens kept the old way, as they are, get sealed and hashed. Runs at
/// startup; there's nothing to do once every row has a hash.
pub async fn upgrade_install_tokens(conn: &DbConn) -> crate::api::EmptyResult {
    let clients: Vec<(OrganizationId, String)> = conn
        .run(|conn| {
            msp_clients::table
                .filter(msp_clients::enrollment_token_hash.is_null())
                .filter(msp_clients::enrollment_token.is_not_null())
                .select((msp_clients::org_uuid, msp_clients::enrollment_token.assume_not_null()))
                .load(conn)
                .map_res("Error reading install command tokens")
        })
        .await?;
    for (org, token) in clients {
        let stored = StoredToken::of(&org, &token)?;
        conn.run(move |conn| {
            diesel::update(msp_clients::table.filter(msp_clients::org_uuid.eq(org)))
                .set((
                    msp_clients::enrollment_token.eq(stored.sealed),
                    msp_clients::enrollment_token_hash.eq(stored.hash),
                ))
                .execute(conn)
                .map(|_| ())
                .map_res("Error sealing an install command token")
        })
        .await?;
    }
    let setups: Vec<(OrganizationId, String)> = conn
        .run(|conn| {
            org_setups::table
                .filter(org_setups::enrollment_token_hash.is_null())
                .filter(org_setups::enrollment_token.is_not_null())
                .select((org_setups::org_uuid, org_setups::enrollment_token.assume_not_null()))
                .load(conn)
                .map_res("Error reading install command tokens")
        })
        .await?;
    for (org, token) in setups {
        let stored = StoredToken::of(&org, &token)?;
        conn.run(move |conn| {
            diesel::update(org_setups::table.filter(org_setups::org_uuid.eq(org)))
                .set((
                    org_setups::enrollment_token.eq(stored.sealed),
                    org_setups::enrollment_token_hash.eq(stored.hash),
                ))
                .execute(conn)
                .map(|_| ())
                .map_res("Error sealing an install command token")
        })
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/vectors/server-derived-keys-v1.json, made with Node's crypto.
    #[test]
    fn the_test_vectors_hold() {
        let v: serde_json::Value = serde_json::from_str(include_str!("vectors/server-derived-keys-v1.json")).unwrap();
        let der = data_encoding::BASE64.decode(v["rsaPkcs1Der"].as_str().unwrap().as_bytes()).unwrap();
        let t = &v["installTokens"];
        assert_eq!(t["label"].as_str().unwrap().as_bytes(), LABEL);
        let key = secrets::derive_key_for(LABEL, &der);
        assert_eq!(data_encoding::HEXLOWER.encode(key.as_ref()), t["key"].as_str().unwrap());
        for case in t["cases"].as_array().unwrap() {
            let s = |k: &str| case[k].as_str().unwrap().to_owned();
            assert_eq!(aad(&s("organization")), s("aad").into_bytes());
            let nonce: [u8; NONCE_LEN] =
                data_encoding::HEXLOWER.decode(s("nonce").as_bytes()).unwrap().try_into().unwrap();
            let sealed = secrets::seal_aad_with(&key, nonce, &aad(&s("organization")), &s("token")).unwrap();
            assert_eq!(sealed, s("sealed"));
            assert_eq!(token_hash(&s("token")), s("hash"));
            let opened = secrets::open_aad_with(&key, &aad(&s("organization")), &sealed).unwrap();
            assert_eq!(opened.as_str(), s("token"));
        }
        // Bound to its organization.
        let first = &t["cases"][0];
        for other in t["wrongOrganizations"].as_array().unwrap() {
            let sealed = first["sealed"].as_str().unwrap();
            assert!(secrets::open_aad_with(&key, &aad(other.as_str().unwrap()), sealed).is_none());
        }
    }

    #[test]
    fn a_token_is_256_url_safe_bits_and_its_hash_isnt_it() {
        let token = new_install_token();
        assert_eq!(data_encoding::BASE64URL_NOPAD.decode(token.as_bytes()).unwrap().len(), 32);
        assert_ne!(token_hash(&token), token);
        assert_eq!(token_hash(&token).len(), 44);
    }
}

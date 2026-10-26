// Keykeeper: a destination's secrets at rest. A webhook's URL (collectors
// often put their token in it, as Azure Logic Apps and Sumo Logic do), its
// signing secret, an extra header's value, and a Sentinel app's client secret
// are sent or used by the server, so they can't be hashed. They're encrypted
// with AES-256-GCM under a key derived from the server's private RSA key, the
// way upstream derives its pre-login key, but from the key's DER encoding,
// so rewriting rsa_key.pem in another PEM form keeps the same key. The key
// lives with the RSA key (in the data folder or its bucket), never in the
// database, so a copy of the database, such as a backup kept at another
// company, doesn't reveal them. Each ciphertext is bound to its destination's
// id, owner, and kind, so it can't be moved to another destination. If the
// RSA key changes, the secrets can't be read and the destination pauses
// until someone enters them again. Plaintexts are wiped from memory when
// they're dropped, as far as this code holds them (best effort: see DESIGN).
// Test vectors: docs/vectors/event-streaming-secrets-v1.json in the meta repo
// (a copy is in vectors/ here), made with Node's crypto alone.
// See DESIGN.md, "Sending events to security tools".

use std::sync::OnceLock;

use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use zeroize::{Zeroize, Zeroizing};

static KEY: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();

const PREFIX: &str = "v1.";
const LABEL: &[u8] = b"passbundle event streaming secrets v1";

/// The key for the secrets: HMAC-SHA256 keyed with the server's private
/// RSA key, DER-encoded (PKCS#1), over a fixed label.
pub fn derive_key(rsa_private_der: &[u8]) -> Zeroizing<[u8; 32]> {
    derive_key_for(LABEL, rsa_private_der)
}

/// `derive_key` over another feature's label. Each feature that keeps its
/// secrets with this module has a label of its own, so a key of its own, and
/// what one seals can't be opened as another's: single sign-on's client
/// secrets (keykeeper_sso::secret) use it.
pub fn derive_key_for(label: &[u8], rsa_private_der: &[u8]) -> Zeroizing<[u8; 32]> {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, rsa_private_der), label);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(tag.as_ref());
    key
}

/// Derives and keeps the key. Called once at startup, by auth::initialize_keys.
pub fn init(rsa_private_der: &[u8]) {
    // A second call (tests) keeps the first key.
    drop(KEY.set(derive_key(rsa_private_der)));
}

/// What a ciphertext is bound to: the destination, whose it is (an
/// organization's or an MSP's id), and its kind.
pub struct Binding<'a> {
    pub id: &'a str,
    pub owner: &'a str,
    pub kind: &'a str,
}

impl Binding<'_> {
    fn aad(&self) -> Vec<u8> {
        format!("event destination {}\u{0}owner {}\u{0}kind {}", self.id, self.owner, self.kind).into_bytes()
    }
}

fn aead_key(bytes: &[u8; 32]) -> Result<LessSafeKey, String> {
    let unbound = UnboundKey::new(&AES_256_GCM, bytes).map_err(|_| "Bad key")?;
    Ok(LessSafeKey::new(unbound))
}

fn server_key() -> Result<&'static [u8; 32], String> {
    KEY.get().map(|k| &**k).ok_or_else(|| "The server's keys aren't loaded yet".to_owned())
}

/// Encrypts a destination's secrets (JSON) for the database.
pub fn seal(binding: &Binding<'_>, plaintext: &str) -> Result<String, String> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).map_err(|_| "No randomness")?;
    seal_with(server_key()?, nonce, binding, plaintext)
}

/// `seal` with a given key and nonce: "v1." and base64 of the nonce, the
/// ciphertext, and the tag. The nonce must never repeat under one key; only
/// `seal` (random nonces) and the test vectors call this.
pub fn seal_with(
    key: &[u8; 32],
    nonce: [u8; NONCE_LEN],
    binding: &Binding<'_>,
    plaintext: &str,
) -> Result<String, String> {
    let key = aead_key(key)?;
    let mut data = Zeroizing::new(plaintext.as_bytes().to_vec());
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(binding.aad()), &mut *data)
        .map_err(|_| "Couldn't encrypt")?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&data);
    Ok(format!("{PREFIX}{}", data_encoding::BASE64.encode(&out)))
}

/// Decrypts what `seal` made for this destination, or says why it can't.
pub fn open(binding: &Binding<'_>, sealed: &str) -> Result<Zeroizing<String>, String> {
    open_with(server_key()?, binding, sealed)
}

/// `open` with a given key.
pub fn open_with(key: &[u8; 32], binding: &Binding<'_>, sealed: &str) -> Result<Zeroizing<String>, String> {
    const CANT: &str = "This server can't read the destination's secrets anymore (its keys changed). Enter them again.";
    let key = aead_key(key)?;
    let bytes =
        sealed.strip_prefix(PREFIX).and_then(|b| data_encoding::BASE64.decode(b.as_bytes()).ok()).ok_or(CANT)?;
    if bytes.len() < NONCE_LEN {
        return Err(CANT.into());
    }
    let (nonce, data) = bytes.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| CANT)?;
    let mut data = Zeroizing::new(data.to_vec());
    let plain = key.open_in_place(nonce, Aad::from(binding.aad()), &mut data).map_err(|_| CANT)?;
    match String::from_utf8(plain.to_vec()) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(e) => {
            e.into_bytes().zeroize();
            Err(CANT.into())
        }
    }
}

/// Random bytes, for signing secrets and event ids.
pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    SystemRandom::new().fill(&mut bytes).expect("system randomness");
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/vectors/event-streaming-secrets-v1.json, made with Node's crypto.
    #[test]
    fn the_test_vectors_hold() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("vectors/event-streaming-secrets-v1.json")).unwrap();
        let s = |key: &str| v[key].as_str().unwrap().to_owned();
        assert_eq!(s("label").as_bytes(), LABEL);
        // The DER openssl writes for either PEM form of the key, as the server
        // does at startup, and the key derived from it.
        for pem in [s("rsaPkcs1Pem"), s("rsaPkcs8Pem")] {
            let der = openssl::rsa::Rsa::private_key_from_pem(pem.as_bytes()).unwrap().private_key_to_der().unwrap();
            assert_eq!(data_encoding::BASE64.encode(&der), s("rsaPkcs1Der"));
            assert_eq!(data_encoding::HEXLOWER.encode(derive_key(&der).as_ref()), s("key"));
        }
        let key: [u8; 32] = data_encoding::HEXLOWER.decode(s("key").as_bytes()).unwrap().try_into().unwrap();
        let cases = v["cases"].as_array().unwrap();
        for case in cases {
            let b = &case["binding"];
            let binding = Binding {
                id: b["id"].as_str().unwrap(),
                owner: b["owner"].as_str().unwrap(),
                kind: b["kind"].as_str().unwrap(),
            };
            assert_eq!(binding.aad(), case["aad"].as_str().unwrap().as_bytes());
            let nonce: [u8; NONCE_LEN] =
                data_encoding::HEXLOWER.decode(case["nonce"].as_str().unwrap().as_bytes()).unwrap().try_into().unwrap();
            let plaintext = case["plaintext"].as_str().unwrap();
            let sealed = seal_with(&key, nonce, &binding, plaintext).unwrap();
            assert_eq!(sealed, case["sealed"].as_str().unwrap());
            assert_eq!(open_with(&key, &binding, &sealed).unwrap().as_str(), plaintext);
        }
        let first = &cases[0];
        for wrong in v["wrongBindings"].as_array().unwrap() {
            let binding = Binding {
                id: wrong["id"].as_str().unwrap(),
                owner: wrong["owner"].as_str().unwrap(),
                kind: wrong["kind"].as_str().unwrap(),
            };
            assert!(open_with(&key, &binding, first["sealed"].as_str().unwrap()).is_err());
        }
    }

    const A: Binding<'static> = Binding {
        id: "dest-a",
        owner: "org-1",
        kind: "webhook",
    };

    #[test]
    fn secrets_round_trip_only_for_their_destination() {
        init(b"0\x82\x01 test DER");
        let sealed = seal(&A, r#"{"url":"https://example.com/hook?sig=abc"}"#).unwrap();
        assert!(sealed.starts_with("v1."));
        assert!(!sealed.contains("example.com"));
        assert_eq!(open(&A, &sealed).unwrap().as_str(), r#"{"url":"https://example.com/hook?sig=abc"}"#);
        // Bound to the destination, its owner, and its kind.
        for other in [
            Binding {
                id: "dest-b",
                ..A
            },
            Binding {
                owner: "org-2",
                ..A
            },
            Binding {
                kind: "sentinel",
                ..A
            },
        ] {
            assert!(open(&other, &sealed).is_err());
        }
        // Tampered or not ours.
        let mut tampered = sealed.into_bytes();
        let last = tampered.len() - 3;
        tampered[last] = if tampered[last] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert!(open(&A, &String::from_utf8(tampered).unwrap()).is_err());
        assert!(open(&A, "plain text").is_err());
        assert!(open(&A, "v1.AAAA").is_err());
        // A fresh nonce every time.
        assert_ne!(seal(&A, "x").unwrap(), seal(&A, "x").unwrap());
    }
}

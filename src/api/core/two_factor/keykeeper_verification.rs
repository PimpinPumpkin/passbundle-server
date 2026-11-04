// Keykeeper: the proof a two-step login settings dialog carries that the
// person just confirmed it was them, as upstream's clients expect it
// (`userVerificationToken`). The web vault's dialogs (security key,
// authenticator app, email, YubiKey, Duo) ask for the master password or a
// one-time code once, get this token in the first answer, and send it with
// the requests that follow ("Read key", "Turn on", "Remove") instead of the
// password. See DESIGN.md, "Two-step login settings".
//
// The token is the time it stops working and an HMAC over the person and
// their security stamp, with a key derived from the server's RSA key like
// the other server-derived keys (test vectors: docs/vectors/
// server-derived-keys-v1.json in the meta repo, "twoStepSettings"; a copy is
// in db/models/vectors/ here). Nothing is stored. It works for one person, for
// TOKEN_SECONDS, and only on the two-step login settings endpoints; changing
// the password (or anything else that changes the security stamp) ends it.

use std::sync::OnceLock;

use data_encoding::BASE64URL_NOPAD;
use ring::hmac;
use zeroize::Zeroizing;

use crate::db::models::User;

/// How long a dialog may take after the person confirms.
pub const TOKEN_SECONDS: i64 = 10 * 60;

const LABEL: &[u8] = b"passbundle two-step settings verification v1";
static KEY: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();

/// Derives and keeps the key. Called once at startup, by auth::initialize_keys.
pub fn init(rsa_private_der: &[u8]) {
    // A second call (tests) keeps the first key.
    drop(KEY.set(crate::keykeeper_streaming::secrets::derive_key_for(LABEL, rsa_private_der)));
}

fn message(user: &str, security_stamp: &str, expires: i64) -> String {
    format!("two-step settings\u{0}{user}\u{0}{security_stamp}\u{0}{expires}")
}

/// The token for a person, good until `expires` (seconds since 1970).
pub fn token_with(key: &[u8; 32], user: &str, security_stamp: &str, expires: i64) -> String {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), message(user, security_stamp, expires).as_bytes());
    let mut raw = expires.to_be_bytes().to_vec();
    raw.extend_from_slice(tag.as_ref());
    format!("v1.{}", BASE64URL_NOPAD.encode(&raw))
}

/// Whether a token is this person's and still good at `now`.
pub fn check_with(key: &[u8; 32], token: &str, user: &str, security_stamp: &str, now: i64) -> bool {
    let Some(raw) = token.strip_prefix("v1.").and_then(|t| BASE64URL_NOPAD.decode(t.as_bytes()).ok()) else {
        return false;
    };
    if raw.len() != 8 + 32 {
        return false;
    }
    let mut expires = [0u8; 8];
    expires.copy_from_slice(&raw[..8]);
    let expires = i64::from_be_bytes(expires);
    if now > expires || expires - now > TOKEN_SECONDS {
        return false;
    }
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), message(user, security_stamp, expires).as_bytes(), &raw[8..])
        .is_ok()
}

/// A token for the person, good for TOKEN_SECONDS from now. None before the
/// server's keys are loaded, so the dialogs fall back to asking again.
pub fn token(user: &User) -> Option<String> {
    let key = KEY.get()?;
    let now = chrono::Utc::now().timestamp();
    Some(token_with(key, user.uuid.as_ref(), &user.security_stamp, now + TOKEN_SECONDS))
}

/// Whether a token a dialog sent is the person's and still good.
pub fn is_valid(token: &str, user: &User) -> bool {
    KEY.get().is_some_and(|key| {
        check_with(key, token, user.uuid.as_ref(), &user.security_stamp, chrono::Utc::now().timestamp())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../db/models/vectors/server-derived-keys-v1.json")).unwrap();
        v
    }

    /// docs/vectors/server-derived-keys-v1.json, made with Node's crypto.
    #[test]
    fn the_key_and_tokens_match_the_test_vectors() {
        let v = vectors();
        let der = data_encoding::BASE64.decode(v["rsaPkcs1Der"].as_str().unwrap().as_bytes()).unwrap();
        let s = &v["twoStepSettings"];
        assert_eq!(s["label"].as_str().unwrap().as_bytes(), LABEL);
        let key = crate::keykeeper_streaming::secrets::derive_key_for(LABEL, &der);
        assert_eq!(data_encoding::HEXLOWER.encode(key.as_ref()), s["key"].as_str().unwrap());
        for case in s["cases"].as_array().unwrap() {
            let (user, stamp) = (case["user"].as_str().unwrap(), case["securityStamp"].as_str().unwrap());
            let expires = case["expires"].as_i64().unwrap();
            let token = case["token"].as_str().unwrap();
            assert_eq!(token_with(&key, user, stamp, expires), token);
            assert!(check_with(&key, token, user, stamp, expires));
            assert!(check_with(&key, token, user, stamp, expires - TOKEN_SECONDS));
        }
    }

    #[test]
    fn a_token_is_one_persons_for_ten_minutes_and_ends_with_their_security_stamp() {
        let key = [7u8; 32];
        let now = 1_800_000_000;
        let token = token_with(&key, "user-1", "stamp-1", now + TOKEN_SECONDS);
        assert!(check_with(&key, &token, "user-1", "stamp-1", now));
        // Expired, someone else's, after a password change, or under another key.
        assert!(!check_with(&key, &token, "user-1", "stamp-1", now + TOKEN_SECONDS + 1));
        assert!(!check_with(&key, &token, "user-2", "stamp-1", now));
        assert!(!check_with(&key, &token, "user-1", "stamp-2", now));
        assert!(!check_with(&[8u8; 32], &token, "user-1", "stamp-1", now));
        // A token can't say it lasts longer.
        let long = token_with(&key, "user-1", "stamp-1", now + TOKEN_SECONDS + 60);
        assert!(!check_with(&key, &long, "user-1", "stamp-1", now));
        // Nor be anything else.
        for bad in ["", "v1.", "v2.AAAA", "v1.!!!!", &token[..token.len() - 2]] {
            assert!(!check_with(&key, bad, "user-1", "stamp-1", now), "{bad}");
        }
    }
}

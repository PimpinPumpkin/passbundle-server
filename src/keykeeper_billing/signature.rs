// Keykeeper: whether a webhook is really the payment provider's (DESIGN.md,
// "Plans and billing", "Checking a webhook"), by Stripe's published scheme
// (docs.stripe.com, "Verify webhook signatures manually"), which the stand-in
// uses too, so Stripe's adapter can reuse this check:
//
// - The header is entries separated by commas, each a name, "=", and a value.
//   `t` is when it was signed, in seconds since 1970, and each `v1` is a
//   signature: one for each signing secret in use, so two while a secret is
//   being replaced. Every other entry is ignored (`v0`, any other scheme, and
//   the debugging entries Stripe may add), in any order.
// - A signature is HMAC-SHA256, keyed with the signing secret as it's
//   written, over the timestamp as the header writes it, a period, and the
//   body byte for byte, in hex.
// - The header is taken when one of its `v1` signatures is one of the
//   signatures made with a secret in use, compared in constant time, and its
//   timestamp is no more than five minutes from the server's clock, either
//   way.
//
// Test vectors: docs/vectors/billing-webhook-v1.json in the meta repo (a copy
// is in vectors/ here), made with Node's crypto alone.

use data_encoding::HEXLOWER_PERMISSIVE;
use ring::hmac;

use super::Secret;

/// The most a webhook's timestamp may be from the server's clock, either way:
/// five minutes, as Stripe's own libraries allow.
pub const TOLERANCE_SECONDS: u64 = 300;

/// Why a webhook's signature was refused, for the server's log only. The
/// answer to the sender never says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// No header, or one without a timestamp, with two, or without a `v1`.
    Unreadable,
    /// No `v1` signature is one made with a secret in use.
    Unsigned,
    /// Signed, but more than five minutes from the server's clock.
    Stale,
}

impl Refused {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "its signature header couldn't be read",
            Self::Unsigned => "it isn't signed with a signing secret in use",
            Self::Stale => "it was signed more than five minutes from this server's clock",
        }
    }
}

/// The timestamp as the header writes it, the same as a number, and each
/// `v1` signature's bytes. A `v1` that isn't hex can't match anything, so
/// it's left out.
fn parse(header: &str) -> Result<(&str, i64, Vec<Vec<u8>>), Refused> {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for entry in header.split(',') {
        let Some((name, value)) = entry.split_once('=') else {
            continue;
        };
        match name {
            "t" => {
                if timestamp.replace(value).is_some() {
                    return Err(Refused::Unreadable);
                }
            }
            "v1" => {
                if let Ok(signature) = HEXLOWER_PERMISSIVE.decode(value.as_bytes()) {
                    signatures.push(signature);
                }
            }
            // Other schemes, which would allow a downgrade, and anything else.
            _ => {}
        }
    }
    let Some(timestamp) = timestamp else {
        return Err(Refused::Unreadable);
    };
    if timestamp.is_empty() || !timestamp.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refused::Unreadable);
    }
    let Ok(seconds) = timestamp.parse::<i64>() else {
        return Err(Refused::Unreadable);
    };
    if signatures.is_empty() {
        return Err(Refused::Unsigned);
    }
    Ok((timestamp, seconds, signatures))
}

/// Whether `header` signs `body` with one of `secrets`, at a time no more
/// than five minutes from `now` (seconds since 1970). The signature is
/// checked first and the timestamp after, as Stripe's documentation does it,
/// and nothing in the body is read.
pub fn check(header: Option<&str>, body: &[u8], secrets: &[Secret], now: i64) -> Result<(), Refused> {
    let (timestamp, seconds, signatures) = parse(header.ok_or(Refused::Unreadable)?)?;
    let mut signed = Vec::with_capacity(timestamp.len() + 1 + body.len());
    signed.extend_from_slice(timestamp.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);
    // ring's verify works out the signature itself and compares it in
    // constant time. Every pair is compared, so how long this takes doesn't
    // say which secret or signature matched.
    let mut matched = false;
    for secret in secrets {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose().as_bytes());
        for signature in &signatures {
            matched |= hmac::verify(&key, &signed, signature).is_ok();
        }
    }
    if !matched {
        return Err(Refused::Unsigned);
    }
    if now.abs_diff(seconds) > TOLERANCE_SECONDS {
        return Err(Refused::Stale);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("vectors/billing-webhook-v1.json")).unwrap()
    }

    fn secrets_named(v: &Value, names: &Value) -> Vec<Secret> {
        names
            .as_array()
            .unwrap()
            .iter()
            .map(|name| Secret::new(v["secrets"][name.as_str().unwrap()].as_str().unwrap().to_owned()))
            .collect()
    }

    /// docs/vectors/billing-webhook-v1.json, made with Node's crypto.
    #[test]
    fn the_vectors() {
        let v = vectors();
        assert_eq!(v["tolerance"].as_u64(), Some(TOLERANCE_SECONDS));
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 20);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let body = case["body"].as_str().or(v["body"].as_str()).unwrap();
            let secrets = secrets_named(&v, &case["secrets"]);
            let checked =
                check(Some(case["header"].as_str().unwrap()), body.as_bytes(), &secrets, case["now"].as_i64().unwrap());
            assert_eq!(checked.is_ok(), case["valid"].as_bool().unwrap(), "{name}: {checked:?}");
        }
    }

    /// A header made here the way the vectors' generator makes one.
    fn signed(secret: &str, timestamp: &str, body: &[u8]) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let mut message = timestamp.as_bytes().to_vec();
        message.push(b'.');
        message.extend_from_slice(body);
        HEXLOWER_PERMISSIVE.encode(hmac::sign(&key, &message).as_ref())
    }

    #[test]
    fn the_timestamps_edges_either_way() {
        let secrets = [Secret::new("whsec_edges".to_owned())];
        let t = 1_800_000_000_i64;
        let header = format!("t={t},v1={}", signed("whsec_edges", &t.to_string(), b"{}"));
        for (now, taken) in [
            (t, true),
            (t + 299, true),
            (t + 300, true),
            (t + 301, false),
            (t - 300, true),
            (t - 301, false),
            (0, false),
            (i64::MAX, false),
            (i64::MIN, false),
        ] {
            let checked = check(Some(&header), b"{}", &secrets, now);
            assert_eq!(checked.is_ok(), taken, "now {now}");
            if !taken {
                assert_eq!(checked, Err(Refused::Stale), "a good signature at the wrong time is stale");
            }
        }
    }

    #[test]
    fn both_secrets_while_one_is_replaced() {
        let body = br#"{"id":"evt_1"}"#;
        let t = "1800000000";
        let now = 1_800_000_000;
        let new = signed("whsec_new", t, body);
        let old = signed("whsec_old", t, body);
        let both = [Secret::new("whsec_new".to_owned()), Secret::new("whsec_old".to_owned())];
        let only_new = [Secret::new("whsec_new".to_owned())];
        // The provider sends one signature for each secret while both are in use.
        assert!(check(Some(&format!("t={t},v1={old},v1={new}")), body, &both, now).is_ok());
        assert!(check(Some(&format!("t={t},v1={old},v1={new}")), body, &only_new, now).is_ok());
        // Either one alone, while the server has both.
        assert!(check(Some(&format!("t={t},v1={old}")), body, &both, now).is_ok());
        assert!(check(Some(&format!("t={t},v1={new}")), body, &both, now).is_ok());
        // Once the old one is gone, it signs nothing.
        assert_eq!(check(Some(&format!("t={t},v1={old}")), body, &only_new, now), Err(Refused::Unsigned));
        // And no secrets at all take nothing.
        assert_eq!(check(Some(&format!("t={t},v1={new}")), body, &[], now), Err(Refused::Unsigned));
    }

    #[test]
    fn the_header_is_read_as_stripe_writes_it() {
        let body = b"{}";
        let t = "1800000000";
        let now = 1_800_000_000;
        let good = signed("whsec_h", t, body);
        let secrets = [Secret::new("whsec_h".to_owned())];
        let at = |header: &str| check(Some(header), body, &secrets, now);
        assert!(at(&format!("t={t},v1={good}")).is_ok());
        // Upper-case hex is the same signature.
        assert!(at(&format!("t={t},v1={}", good.to_uppercase())).is_ok());
        // Another scheme is ignored, even with the right signature in it.
        assert_eq!(at(&format!("t={t},v0={good}")), Err(Refused::Unsigned));
        assert_eq!(at(&format!("t={t},V1={good}")), Err(Refused::Unsigned));
        assert_eq!(at(&format!("t={t},v1 ={good}")), Err(Refused::Unsigned));
        assert_eq!(at(&format!("t={t},v10={good}")), Err(Refused::Unsigned));
        // Entries without "=", and empty ones, are ignored.
        assert!(at(&format!(",t={t},,debug,v1={good},")).is_ok());
        // Values may hold "=", and only the first one splits.
        assert!(at(&format!("t={t},secret=a=b,v1={good}")).is_ok());
        // A value with "=" in it isn't the timestamp or a signature.
        assert_eq!(at(&format!("t={t}=1,v1={good}")), Err(Refused::Unreadable));
        assert_eq!(at(&format!("t={t},v1={good}=")), Err(Refused::Unsigned));
        // No header, an empty one, and one that's only a timestamp.
        assert_eq!(check(None, body, &secrets, now), Err(Refused::Unreadable));
        assert_eq!(at(""), Err(Refused::Unreadable));
        assert_eq!(at(&format!("t={t}")), Err(Refused::Unsigned));
        // Timestamps a number can't hold, or that aren't plain digits.
        assert_eq!(at(&format!("t=99999999999999999999,v1={good}")), Err(Refused::Unreadable));
        assert_eq!(at(&format!("t=+{t},v1={good}")), Err(Refused::Unreadable));
        assert_eq!(at(&format!("t=,v1={good}")), Err(Refused::Unreadable));
    }

    /// The comparison is ring's `hmac::verify`, which is constant time. What
    /// a test can show is that nothing short of the whole signature passes:
    /// a near miss at either end, a prefix, or the signature with more after it.
    #[test]
    fn only_the_whole_signature_matches() {
        let body = b"{}";
        let t = "1800000000";
        let now = 1_800_000_000;
        let secrets = [Secret::new("whsec_whole".to_owned())];
        let good = signed("whsec_whole", t, body);
        let flip = |at: usize| {
            let mut s = good.clone().into_bytes();
            s[at] = if s[at] == b'0' {
                b'1'
            } else {
                b'0'
            };
            String::from_utf8(s).unwrap()
        };
        for near in [flip(0), flip(63), good[..62].to_owned(), good[..2].to_owned(), format!("{good}00"), String::new()]
        {
            assert_eq!(check(Some(&format!("t={t},v1={near}")), body, &secrets, now), Err(Refused::Unsigned), "{near}");
        }
        assert!(check(Some(&format!("t={t},v1={good}")), body, &secrets, now).is_ok());
    }
}

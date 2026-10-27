// Keykeeper: checking the ID token Microsoft Entra ID returns for an
// organization's single sign-on, from the OpenID Connect Core 1.0 spec
// (section 3.1.3.7) and Microsoft's public "ID token claims reference". The
// signature is checked with `jsonwebtoken` against the tenant's published
// keys; every claim is checked here, against this sign-in's own expectations,
// so each check is one line a reviewer can read:
//
// - the algorithm is RS256 and the key is one the tenant publishes (by kid),
// - `iss` is exactly the tenant's own issuer, `.../<tenant id>/v2.0`,
// - `tid` is the organization's tenant, and `ver` is 2.0,
// - `aud` is exactly the app's client id (one audience; `azp` agrees),
// - `exp`, `nbf`, and `iat` are in range (five minutes of clock skew),
// - `nonce` is the one this server sent with this sign-in,
// - `oid` (the person's immutable object id) is there.
//
// People are identified by `tid` and `oid` only. The `email` claim is kept
// as a suggestion for linking an invitation the first time, with Entra's
// `xms_edov` (whether the email's domain owner is verified) and whether the
// person is a guest (`acct`, `idp`), never as an identity. See DESIGN.md,
// "Sign in with Microsoft Entra ID".

use jsonwebtoken::{Algorithm, DecodingKey, Validation, errors::ErrorKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{crypto::ct_eq, db::models::normalize_guid};

/// Clock skew allowed between this server and Microsoft, in seconds.
pub const LEEWAY: i64 = 300;
/// The oldest an ID token's `iat` may be. It comes straight from the token
/// endpoint, so it's minutes old at most.
pub const MAX_AGE: i64 = 10 * 60;

/// A signing key the tenant publishes (its JWKS), RSA only.
#[derive(Clone, Debug)]
pub struct Jwk {
    pub kid: String,
    pub n: String,
    pub e: String,
}

/// The RSA signing keys in a JWKS document. Keys for other uses or
/// algorithms are left out.
pub fn parse_jwks(jwks: &Value) -> Vec<Jwk> {
    let Some(keys) = jwks.get("keys").and_then(Value::as_array) else {
        return Vec::new();
    };
    keys.iter()
        .filter(|k| k.get("kty").and_then(Value::as_str) == Some("RSA"))
        .filter(|k| k.get("use").and_then(Value::as_str).is_none_or(|u| u == "sig"))
        .filter(|k| k.get("alg").and_then(Value::as_str).is_none_or(|a| a == "RS256"))
        .filter_map(|k| {
            Some(Jwk {
                kid: k.get("kid")?.as_str()?.to_owned(),
                n: k.get("n")?.as_str()?.to_owned(),
                e: k.get("e")?.as_str()?.to_owned(),
            })
        })
        .collect()
}

/// The issuer a tenant's v2.0 tokens carry: `<authority>/<tenant id>/v2.0`.
pub fn issuer(authority: &str, tenant_id: &str) -> String {
    format!("{authority}/{tenant_id}/v2.0")
}

/// What this sign-in expects of the token.
pub struct Expected<'a> {
    /// The tenant's issuer (see `issuer`).
    pub issuer: &'a str,
    /// The organization's tenant id, lowercase.
    pub tenant_id: &'a str,
    /// The organization's app (client) id, lowercase.
    pub client_id: &'a str,
    /// The nonce this server sent when the sign-in started.
    pub nonce: &'a str,
    /// Now, in seconds since 1970.
    pub now: i64,
}

/// Who Entra says signed in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub tenant_id: String,
    pub object_id: String,
    /// The email claim, lowercase, and only if it's plain ASCII (lowercasing
    /// other characters can turn one into a letter, as U+212A becomes k).
    /// Mutable and unverified: only ever a suggestion for which invitation to
    /// link the first time.
    pub email: Option<String>,
    /// Entra's `xms_edov` for that email: Some(true) when the email's domain
    /// owner is verified, Some(false) when Entra says it isn't, None when the
    /// claim wasn't sent.
    pub email_edov: Option<bool>,
    /// A guest in the tenant (`acct` 1, or an `idp` other than the issuer):
    /// signed in somewhere else, so the tenant's domains don't vouch for them.
    pub guest: bool,
    pub name: Option<String>,
}

/// Why a token was refused. The words are for the event log and the person
/// signing in; none of them carries a token's contents.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    Algorithm,
    UnknownKey,
    Signature,
    Issuer,
    Tenant,
    Audience,
    Expired,
    NotYetValid,
    IssuedAt,
    Nonce,
    Version,
    NoObjectId,
}

impl Refusal {
    /// A fixed code for the reason, for security tools: refusals for
    /// different reasons are never merged into one event.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed => "token_malformed",
            Self::Algorithm => "token_algorithm",
            Self::UnknownKey => "token_unknown_key",
            Self::Signature => "token_signature",
            Self::Issuer => "token_issuer",
            Self::Tenant => "token_tenant",
            Self::Audience => "token_audience",
            Self::Expired => "token_expired",
            Self::NotYetValid => "token_not_yet_valid",
            Self::IssuedAt => "token_issued_at",
            Self::Nonce => "token_nonce",
            Self::Version => "token_version",
            Self::NoObjectId => "token_no_object_id",
        }
    }

    /// A few words for the organization's event log.
    pub fn detail(&self) -> &'static str {
        match self {
            Self::Malformed => "Microsoft's ID token couldn't be read",
            Self::Algorithm => "the ID token wasn't signed with RS256",
            Self::UnknownKey => "the ID token was signed with a key the tenant doesn't publish",
            Self::Signature => "the ID token's signature didn't check out",
            Self::Issuer => "the ID token came from another issuer",
            Self::Tenant => "the ID token was for another tenant",
            Self::Audience => "the ID token was for another app",
            Self::Expired => "the ID token had expired",
            Self::NotYetValid => "the ID token wasn't valid yet",
            Self::IssuedAt => "the ID token's issue time was out of range",
            Self::Nonce => "the ID token's nonce didn't match this sign-in",
            Self::Version => "the ID token wasn't a v2.0 token",
            Self::NoObjectId => "the ID token had no object id",
        }
    }
}

#[derive(Deserialize)]
struct Claims {
    iss: Option<String>,
    aud: Option<Value>,
    azp: Option<String>,
    sub: Option<String>,
    exp: Option<i64>,
    nbf: Option<i64>,
    iat: Option<i64>,
    tid: Option<String>,
    oid: Option<String>,
    nonce: Option<String>,
    ver: Option<String>,
    email: Option<String>,
    name: Option<String>,
    xms_edov: Option<Value>,
    acct: Option<Value>,
    idp: Option<String>,
}

/// Whether the token names exactly one audience, the app.
fn audience_is(aud: Option<&Value>, client_id: &str) -> bool {
    let one = match aud {
        Some(Value::String(a)) => a.as_str(),
        Some(Value::Array(list)) if list.len() == 1 => match list[0].as_str() {
            Some(a) => a,
            None => return false,
        },
        _ => return false,
    };
    one.eq_ignore_ascii_case(client_id)
}

/// `xms_edov` as Entra sends it: a boolean, or "1"/"true" and "0"/"false".
/// Anything else counts as not sent.
fn edov(value: Option<&Value>) -> Option<bool> {
    match value? {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s == "1" || s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s == "0" || s.eq_ignore_ascii_case("false") => Some(false),
        Value::Number(n) if n.as_i64() == Some(1) => Some(true),
        Value::Number(n) if n.as_i64() == Some(0) => Some(false),
        _ => None,
    }
}

/// `acct` 1 is a guest; so is anyone whose `idp` isn't the tenant's issuer.
fn is_guest(acct: Option<&Value>, idp: Option<&str>, issuer: &str) -> bool {
    let guest_acct = match acct {
        Some(Value::Number(n)) => n.as_i64() == Some(1),
        Some(Value::String(s)) => s == "1",
        _ => false,
    };
    guest_acct || idp.is_some_and(|idp| idp != issuer)
}

/// Checks an ID token against the tenant's keys and this sign-in, and says
/// who signed in. `UnknownKey` means the caller may fetch the tenant's keys
/// again (Microsoft rolls them) and try once more.
pub fn validate(id_token: &str, keys: &[Jwk], expected: &Expected<'_>) -> Result<Identity, Refusal> {
    let header = jsonwebtoken::decode_header(id_token).map_err(|_| Refusal::Malformed)?;
    // Only RS256: never "none", never an HMAC keyed with a public key.
    if header.alg != Algorithm::RS256 {
        return Err(Refusal::Algorithm);
    }
    let kid = header.kid.ok_or(Refusal::UnknownKey)?;
    let key = keys.iter().find(|k| k.kid == kid).ok_or(Refusal::UnknownKey)?;
    let key = DecodingKey::from_rsa_components(&key.n, &key.e).map_err(|_| Refusal::UnknownKey)?;

    // The signature only: every claim is checked below, against `expected`.
    let mut only_signature = Validation::new(Algorithm::RS256);
    only_signature.validate_exp = false;
    only_signature.validate_nbf = false;
    only_signature.validate_aud = false;
    only_signature.required_spec_claims.clear();
    let claims = match jsonwebtoken::decode::<Claims>(id_token, &key, &only_signature) {
        Ok(data) => data.claims,
        Err(e) => {
            return Err(match e.kind() {
                ErrorKind::InvalidSignature => Refusal::Signature,
                ErrorKind::InvalidAlgorithm => Refusal::Algorithm,
                _ => Refusal::Malformed,
            });
        }
    };

    if claims.iss.as_deref() != Some(expected.issuer) {
        return Err(Refusal::Issuer);
    }
    match claims.tid.as_deref().and_then(normalize_guid) {
        Some(tid) if tid == expected.tenant_id => {}
        _ => return Err(Refusal::Tenant),
    }
    if claims.ver.as_deref() != Some("2.0") {
        return Err(Refusal::Version);
    }
    if !audience_is(claims.aud.as_ref(), expected.client_id) {
        return Err(Refusal::Audience);
    }
    if claims.azp.as_deref().is_some_and(|azp| !azp.eq_ignore_ascii_case(expected.client_id)) {
        return Err(Refusal::Audience);
    }
    let now = expected.now;
    match claims.exp {
        Some(exp) if exp + LEEWAY > now => {}
        Some(_) => return Err(Refusal::Expired),
        None => return Err(Refusal::Malformed),
    }
    match claims.nbf {
        Some(nbf) if nbf - LEEWAY <= now => {}
        Some(_) => return Err(Refusal::NotYetValid),
        None => return Err(Refusal::Malformed),
    }
    match claims.iat {
        Some(iat) if iat - LEEWAY <= now && iat >= now - MAX_AGE - LEEWAY => {}
        _ => return Err(Refusal::IssuedAt),
    }
    match claims.nonce.as_deref() {
        Some(nonce) if !expected.nonce.is_empty() && ct_eq(nonce, expected.nonce) => {}
        _ => return Err(Refusal::Nonce),
    }
    if claims.sub.as_deref().is_none_or(str::is_empty) {
        return Err(Refusal::Malformed);
    }
    let Some(object_id) = claims.oid.as_deref().and_then(normalize_guid) else {
        return Err(Refusal::NoObjectId);
    };

    let email = claims
        .email
        .map(|e| e.trim().to_owned())
        .filter(|e| e.is_ascii() && e.contains('@') && e.len() <= 254)
        .map(|e| e.to_ascii_lowercase());
    Ok(Identity {
        tenant_id: expected.tenant_id.to_owned(),
        object_id,
        email_edov: email.as_ref().and(edov(claims.xms_edov.as_ref())),
        email,
        guest: is_guest(claims.acct.as_ref(), claims.idp.as_deref(), expected.issuer),
        name: claims.name.map(|n| n.chars().take(50).collect()),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use data_encoding::BASE64URL_NOPAD;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    use super::*;

    const AUTHORITY: &str = "https://login.microsoftonline.com";
    const TENANT: &str = "11111111-2222-3333-4444-555555555555";
    const OTHER_TENANT: &str = "99999999-8888-7777-6666-555555555555";
    const CLIENT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const OID: &str = "0f0f0f0f-1e1e-2d2d-3c3c-4b4b4b4b4b4b";
    const NONCE: &str = "n-0S6_WzA2Mj";
    const NOW: i64 = 1_793_000_000;

    /// Keys made when the tests run: the tenant's, and someone else's.
    struct TestKey {
        pem: Vec<u8>,
        jwk: Jwk,
    }

    fn make_key(kid: &str) -> TestKey {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        TestKey {
            pem: rsa.private_key_to_pem().unwrap(),
            jwk: Jwk {
                kid: kid.to_owned(),
                n: BASE64URL_NOPAD.encode(&rsa.n().to_vec()),
                e: BASE64URL_NOPAD.encode(&rsa.e().to_vec()),
            },
        }
    }

    static TENANT_KEY: LazyLock<TestKey> = LazyLock::new(|| make_key("tenant-key-1"));
    static ATTACKER_KEY: LazyLock<TestKey> = LazyLock::new(|| make_key("tenant-key-1"));

    fn claims() -> Value {
        json!({
            "iss": issuer(AUTHORITY, TENANT),
            "aud": CLIENT,
            "sub": "pairwise-subject",
            "exp": NOW + 3600,
            "nbf": NOW - 60,
            "iat": NOW - 60,
            "tid": TENANT,
            "oid": OID,
            "nonce": NONCE,
            "ver": "2.0",
            "email": "Ana@AcmeDental.com",
            "name": "Ana Lima",
        })
    }

    fn sign_with(claims: &Value, key: &TestKey) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key.jwk.kid.clone());
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_rsa_pem(&key.pem).unwrap()).unwrap()
    }

    fn sign(claims: &Value) -> String {
        sign_with(claims, &TENANT_KEY)
    }

    fn with(change: impl FnOnce(&mut Value)) -> String {
        let mut c = claims();
        change(&mut c);
        sign(&c)
    }

    fn without(claim: &str) -> String {
        let mut c = claims();
        c.as_object_mut().unwrap().remove(claim);
        sign(&c)
    }

    fn expected() -> Expected<'static> {
        static ISSUER: LazyLock<String> = LazyLock::new(|| issuer(AUTHORITY, TENANT));
        Expected {
            issuer: &ISSUER,
            tenant_id: TENANT,
            client_id: CLIENT,
            nonce: NONCE,
            now: NOW,
        }
    }

    fn check(token: &str) -> Result<Identity, Refusal> {
        validate(token, std::slice::from_ref(&TENANT_KEY.jwk), &expected())
    }

    #[test]
    fn each_check_has_its_own_reason_code() {
        let all = [
            Refusal::Malformed,
            Refusal::Algorithm,
            Refusal::UnknownKey,
            Refusal::Signature,
            Refusal::Issuer,
            Refusal::Tenant,
            Refusal::Audience,
            Refusal::Expired,
            Refusal::NotYetValid,
            Refusal::IssuedAt,
            Refusal::Nonce,
            Refusal::Version,
            Refusal::NoObjectId,
        ];
        let codes: std::collections::HashSet<_> = all.iter().map(Refusal::code).collect();
        assert_eq!(codes.len(), all.len());
        assert!(codes.iter().all(|c| c.starts_with("token_")));
    }

    #[test]
    fn a_good_token_names_the_person_by_tenant_and_object_id() {
        let who = check(&sign(&claims())).unwrap();
        assert_eq!(who.tenant_id, TENANT);
        assert_eq!(who.object_id, OID);
        assert_eq!(who.email.as_deref(), Some("ana@acmedental.com"));
        assert_eq!(who.email_edov, None, "no xms_edov");
        assert!(!who.guest);
        assert_eq!(who.name.as_deref(), Some("Ana Lima"));
    }

    #[test]
    fn xms_edov_is_read_as_true_false_or_not_sent() {
        for (value, read) in [
            (json!(true), Some(true)),
            (json!("1"), Some(true)),
            (json!("true"), Some(true)),
            (json!(1), Some(true)),
            (json!(false), Some(false)),
            (json!("0"), Some(false)),
            (json!("False"), Some(false)),
            (json!(0), Some(false)),
            (json!(null), None),
            (json!("yes"), None),
        ] {
            let who = check(&with(|c| c["xms_edov"] = value.clone())).unwrap();
            assert_eq!(who.email_edov, read, "{value}");
        }
        // xms_edov without an email vouches for nothing.
        let who = check(&with(|c| {
            c.as_object_mut().unwrap().remove("email");
            c["xms_edov"] = json!(true);
        }))
        .unwrap();
        assert_eq!(who.email, None);
        assert_eq!(who.email_edov, None);
    }

    #[test]
    fn guests_are_told_apart_by_acct_and_idp() {
        assert!(check(&with(|c| c["acct"] = json!(1))).unwrap().guest);
        assert!(check(&with(|c| c["acct"] = json!("1"))).unwrap().guest);
        assert!(!check(&with(|c| c["acct"] = json!(0))).unwrap().guest);
        assert!(check(&with(|c| c["idp"] = json!("live.com"))).unwrap().guest);
        assert!(
            check(&with(|c| c["idp"] = json!("https://sts.windows.net/99999999-8888-7777-6666-555555555555/")))
                .unwrap()
                .guest
        );
        // idp equal to the issuer is a member of the tenant.
        assert!(!check(&with(|c| c["idp"] = json!(issuer(AUTHORITY, TENANT)))).unwrap().guest);
    }

    #[test]
    fn only_plain_ascii_emails_are_kept() {
        // U+212A (Kelvin sign) lowercases to k: never match an address by it.
        let who = check(&with(|c| c["email"] = json!("\u{212A}im@acmedental.com"))).unwrap();
        assert_eq!(who.email, None);
        let who = check(&with(|c| c["email"] = json!("ana@acmedentál.com"))).unwrap();
        assert_eq!(who.email, None);
        let who = check(&with(|c| c["email"] = json!(" Kim@AcmeDental.com "))).unwrap();
        assert_eq!(who.email.as_deref(), Some("kim@acmedental.com"));
    }

    #[test]
    fn wrong_issuer_is_refused() {
        for iss in [
            issuer(AUTHORITY, OTHER_TENANT),
            // Another tenant's issuer, and the multi-tenant placeholders.
            format!("{AUTHORITY}/common/v2.0"),
            format!("{AUTHORITY}/organizations/v2.0"),
            format!("{AUTHORITY}/{{tenantid}}/v2.0"),
            // The v1.0 issuer, and look-alikes.
            format!("https://sts.windows.net/{TENANT}/"),
            format!("{AUTHORITY}/{TENANT}/v2.0/"),
            format!("https://login.microsoftonline.com.evil.test/{TENANT}/v2.0"),
        ] {
            assert_eq!(check(&with(|c| c["iss"] = json!(iss))), Err(Refusal::Issuer), "{iss}");
        }
        assert_eq!(check(&with(|c| c["iss"] = json!(null))), Err(Refusal::Issuer));
    }

    #[test]
    fn wrong_tenant_is_refused_even_with_the_right_issuer() {
        assert_eq!(check(&with(|c| c["tid"] = json!(OTHER_TENANT))), Err(Refusal::Tenant));
        assert_eq!(check(&with(|c| c["tid"] = json!("9188040d-6c67-4c5b-b112-36a304b66dad"))), Err(Refusal::Tenant));
        assert_eq!(check(&without("tid")), Err(Refusal::Tenant));
        // The same GUID in capitals is the same tenant.
        assert!(check(&with(|c| c["tid"] = json!(TENANT.to_uppercase()))).is_ok());
    }

    #[test]
    fn wrong_audience_is_refused() {
        assert_eq!(
            check(&with(|c| c["aud"] = json!("00000003-0000-0000-c000-000000000000"))),
            Err(Refusal::Audience),
            "Microsoft Graph's id"
        );
        assert_eq!(check(&with(|c| c["aud"] = json!([CLIENT, "another-app"]))), Err(Refusal::Audience));
        assert_eq!(check(&with(|c| c["aud"] = json!([]))), Err(Refusal::Audience));
        assert_eq!(check(&with(|c| c["aud"] = json!(null))), Err(Refusal::Audience));
        assert_eq!(check(&with(|c| c["azp"] = json!("another-app"))), Err(Refusal::Audience));
        assert!(check(&with(|c| c["aud"] = json!([CLIENT]))).is_ok());
        assert!(check(&with(|c| c["azp"] = json!(CLIENT))).is_ok());
    }

    #[test]
    fn expired_or_early_tokens_are_refused() {
        assert_eq!(check(&with(|c| c["exp"] = json!(NOW - LEEWAY - 1))), Err(Refusal::Expired));
        assert!(check(&with(|c| c["exp"] = json!(NOW - LEEWAY + 30))).is_ok(), "within the clock skew");
        assert_eq!(check(&with(|c| c["nbf"] = json!(NOW + LEEWAY + 1))), Err(Refusal::NotYetValid));
        assert_eq!(check(&with(|c| c["iat"] = json!(NOW + LEEWAY + 1))), Err(Refusal::IssuedAt));
        assert_eq!(check(&with(|c| c["iat"] = json!(NOW - MAX_AGE - LEEWAY - 1))), Err(Refusal::IssuedAt));
        for missing in ["exp", "nbf"] {
            assert_eq!(check(&without(missing)), Err(Refusal::Malformed), "{missing}");
        }
        assert_eq!(check(&without("iat")), Err(Refusal::IssuedAt));
    }

    #[test]
    fn a_bad_signature_is_refused() {
        // Someone else's key, with the tenant's key id.
        assert_eq!(check(&sign_with(&claims(), &ATTACKER_KEY)), Err(Refusal::Signature));
        // The tenant's signature over other claims.
        let good = sign(&claims());
        let forged = sign_with(&with_email("ceo@acmedental.com"), &ATTACKER_KEY);
        let parts: Vec<&str> = good.split('.').collect();
        let forged_parts: Vec<&str> = forged.split('.').collect();
        let spliced = format!("{}.{}.{}", parts[0], forged_parts[1], parts[2]);
        assert_eq!(check(&spliced), Err(Refusal::Signature));
        // No signature at all.
        assert!(matches!(check(&format!("{}.{}.", parts[0], parts[1])), Err(Refusal::Signature | Refusal::Malformed)));
        assert_eq!(check("not a token"), Err(Refusal::Malformed));
    }

    fn with_email(email: &str) -> Value {
        let mut c = claims();
        c["email"] = json!(email);
        c
    }

    #[test]
    fn other_algorithms_are_refused() {
        // alg none: anyone could write it.
        let payload = BASE64URL_NOPAD.encode(claims().to_string().as_bytes());
        let none = format!("{}.{payload}.", BASE64URL_NOPAD.encode(br#"{"alg":"none","kid":"tenant-key-1"}"#));
        assert!(matches!(check(&none), Err(Refusal::Malformed | Refusal::Algorithm)));
        // HS256 keyed with the public key's modulus (key confusion).
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("tenant-key-1".into());
        let hs =
            jsonwebtoken::encode(&header, &claims(), &EncodingKey::from_secret(TENANT_KEY.jwk.n.as_bytes())).unwrap();
        assert_eq!(check(&hs), Err(Refusal::Algorithm));
    }

    #[test]
    fn an_unknown_key_asks_for_the_tenants_keys_again() {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("rolled-key".into());
        let token =
            jsonwebtoken::encode(&header, &claims(), &EncodingKey::from_rsa_pem(&TENANT_KEY.pem).unwrap()).unwrap();
        assert_eq!(check(&token), Err(Refusal::UnknownKey));
        let mut no_kid = Header::new(Algorithm::RS256);
        no_kid.kid = None;
        let token =
            jsonwebtoken::encode(&no_kid, &claims(), &EncodingKey::from_rsa_pem(&TENANT_KEY.pem).unwrap()).unwrap();
        assert_eq!(check(&token), Err(Refusal::UnknownKey));
    }

    #[test]
    fn missing_or_wrong_nonce_is_refused() {
        assert_eq!(check(&without("nonce")), Err(Refusal::Nonce));
        assert_eq!(check(&with(|c| c["nonce"] = json!("another-sign-in"))), Err(Refusal::Nonce));
        assert_eq!(check(&with(|c| c["nonce"] = json!(""))), Err(Refusal::Nonce));
        // A sign-in that somehow has no nonce matches nothing, not even "".
        let token = with(|c| c["nonce"] = json!(""));
        let mut e = expected();
        e.nonce = "";
        assert_eq!(validate(&token, std::slice::from_ref(&TENANT_KEY.jwk), &e), Err(Refusal::Nonce));
    }

    #[test]
    fn a_token_replayed_into_another_sign_in_is_refused() {
        // A valid ID token from one sign-in, presented in another (whose state
        // and nonce are new): its nonce is the old sign-in's. States are taken
        // once by the database (SsoAuthRow::take), which the API tests replay.
        let first = sign(&claims());
        assert!(check(&first).is_ok());
        let mut next = expected();
        next.nonce = "the-next-sign-ins-nonce";
        assert_eq!(validate(&first, std::slice::from_ref(&TENANT_KEY.jwk), &next), Err(Refusal::Nonce));
        // And an old one, even with the right nonce, is too old.
        let mut later = expected();
        later.now = NOW + MAX_AGE + LEEWAY + 120;
        assert_eq!(validate(&first, std::slice::from_ref(&TENANT_KEY.jwk), &later), Err(Refusal::IssuedAt));
    }

    #[test]
    fn v1_tokens_and_tokens_without_an_object_id_are_refused() {
        assert_eq!(check(&with(|c| c["ver"] = json!("1.0"))), Err(Refusal::Version));
        assert_eq!(check(&without("oid")), Err(Refusal::NoObjectId));
        assert_eq!(check(&with(|c| c["oid"] = json!("ana@acmedental.com"))), Err(Refusal::NoObjectId));
        assert_eq!(check(&with(|c| c["sub"] = json!(""))), Err(Refusal::Malformed));
    }

    #[test]
    fn the_email_claim_never_changes_who_it_is() {
        // Entra lets an admin set a user's mail to anything, so a spoofed email
        // comes in a perfectly valid token. Validation names the same person
        // by tenant and object id; linking decides what the email may do
        // (link.rs), and an existing link ignores it.
        let real = check(&sign(&claims())).unwrap();
        let spoofed = check(&sign(&with_email("ceo@acmedental.com"))).unwrap();
        assert_eq!((real.tenant_id, real.object_id), (spoofed.tenant_id, spoofed.object_id));
        assert_eq!(spoofed.email.as_deref(), Some("ceo@acmedental.com"));
        assert_eq!(spoofed.email_edov, None);
    }

    #[test]
    fn jwks_keeps_only_rsa_signing_keys() {
        let jwks = json!({ "keys": [
            { "kty": "RSA", "use": "sig", "kid": "a", "n": "AQAB", "e": "AQAB", "x5t": "a" },
            { "kty": "RSA", "kid": "b", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "use": "enc", "kid": "c", "n": "AQAB", "e": "AQAB" },
            { "kty": "EC", "use": "sig", "kid": "d", "crv": "P-256", "x": "AQAB", "y": "AQAB" },
            { "kty": "RSA", "use": "sig", "alg": "RS512", "kid": "e", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "use": "sig", "n": "AQAB", "e": "AQAB" },
        ]});
        let kids: Vec<String> = parse_jwks(&jwks).into_iter().map(|k| k.kid).collect();
        assert_eq!(kids, ["a", "b"]);
        assert!(parse_jwks(&json!({})).is_empty());
    }
}

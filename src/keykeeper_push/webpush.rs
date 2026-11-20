// Keykeeper: Web Push's message encryption (RFC 8291) and the server's VAPID
// signature (RFC 8292), for push to phones. A message is encrypted to the
// phone's own P-256 key and auth secret, with a key pair and salt made for
// that message alone, so the push service carries only ciphertext. The
// VAPID key is the server's own, made on its first start and kept beside its
// RSA key. Test vector: RFC 8291's example (vectors/web-push-rfc8291.json, a
// copy of the meta repo's docs/vectors/web-push-rfc8291.json). See
// DESIGN.md, "Push to phones".

use data_encoding::BASE64URL_NOPAD;
use openssl::{
    bn::BigNumContext,
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::{PKey, Private},
};
use ring::{
    aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    hmac,
};
use zeroize::Zeroizing;

/// The one record's size, as the RFC's example has it: more than any
/// message PassBundle sends, plus the delimiter and the tag.
pub const RECORD_SIZE: u32 = 4096;
/// An uncompressed P-256 point: 0x04, then x and y.
pub const PUBLIC_KEY_LEN: usize = 65;
/// The auth secret's length (RFC 8291, section 3.2).
pub const AUTH_LEN: usize = 16;
const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;

fn group() -> Result<EcGroup, String> {
    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|e| format!("P-256: {e}"))
}

/// A phone's public key, checked: 65 bytes, uncompressed, on the curve.
pub fn public_key(bytes: &[u8]) -> Result<EcKey<openssl::pkey::Public>, String> {
    if bytes.len() != PUBLIC_KEY_LEN || bytes[0] != 4 {
        return Err("The public key isn't an uncompressed P-256 key".into());
    }
    let group = group()?;
    let mut ctx = BigNumContext::new().map_err(|e| e.to_string())?;
    let point =
        EcPoint::from_bytes(&group, bytes, &mut ctx).map_err(|_| "The public key isn't a point on P-256".to_owned())?;
    let key = EcKey::from_public_key(&group, &point).map_err(|e| e.to_string())?;
    key.check_key().map_err(|_| "The public key isn't a valid P-256 key".to_owned())?;
    Ok(key)
}

fn uncompressed(key: &EcKey<Private>) -> Result<Vec<u8>, String> {
    let group = group()?;
    let mut ctx = BigNumContext::new().map_err(|e| e.to_string())?;
    key.public_key().to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx).map_err(|e| e.to_string())
}

/// HKDF-SHA-256 for one block (RFC 5869): extract under `salt`, then expand
/// `info` to `len` bytes, at most 32.
fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let prk = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, salt), ikm);
    let mut input = Vec::with_capacity(info.len() + 1);
    input.extend_from_slice(info);
    input.push(1);
    let okm = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, prk.as_ref()), &input);
    Zeroizing::new(okm.as_ref()[..len].to_vec())
}

/// The content key and nonce for a message (RFC 8291, section 3.4, and RFC
/// 8188, section 2.2), from the ECDH secret between the two keys.
fn content_key(
    ecdh_secret: &[u8],
    auth: &[u8],
    ua_public: &[u8],
    as_public: &[u8],
    salt: &[u8],
) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let mut key_info = Vec::with_capacity(14 + 2 * PUBLIC_KEY_LEN);
    key_info.extend_from_slice(b"WebPush: info\0");
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let ikm = hkdf(auth, ecdh_secret, &key_info, 32);
    let cek = hkdf(salt, &ikm, b"Content-Encoding: aes128gcm\0", 16);
    let nonce = hkdf(salt, &ikm, b"Content-Encoding: nonce\0", 12);
    (cek, nonce)
}

fn ecdh(own: &EcKey<Private>, peer: &EcKey<openssl::pkey::Public>) -> Result<Zeroizing<Vec<u8>>, String> {
    let own = PKey::from_ec_key(own.clone()).map_err(|e| e.to_string())?;
    let peer = PKey::from_ec_key(peer.clone()).map_err(|e| e.to_string())?;
    let mut deriver = Deriver::new(&own).map_err(|e| e.to_string())?;
    deriver.set_peer(&peer).map_err(|e| e.to_string())?;
    deriver.derive_to_vec().map(Zeroizing::new).map_err(|e| e.to_string())
}

/// Encrypts a message to a phone's public key and auth secret, with a new
/// key pair and salt: the body to post, `Content-Encoding: aes128gcm`.
pub fn encrypt(ua_public: &[u8], auth: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let group = group()?;
    let as_key = EcKey::generate(&group).map_err(|e| e.to_string())?;
    let salt = crate::crypto::get_random_bytes::<SALT_LEN>();
    encrypt_with(ua_public, auth, plaintext, &as_key, &salt)
}

/// `encrypt`, with the server's key pair and the salt given (the RFC's
/// example uses fixed ones).
pub fn encrypt_with(
    ua_public: &[u8],
    auth: &[u8],
    plaintext: &[u8],
    as_key: &EcKey<Private>,
    salt: &[u8; SALT_LEN],
) -> Result<Vec<u8>, String> {
    if auth.len() != AUTH_LEN {
        return Err("The auth secret isn't 16 bytes".into());
    }
    // The plaintext, the delimiter, and the tag fit in the one record.
    if plaintext.len() + 1 + TAG_LEN > RECORD_SIZE as usize {
        return Err("The message is too long".into());
    }
    let peer = public_key(ua_public)?;
    let as_public = uncompressed(as_key)?;
    let secret = ecdh(as_key, &peer)?;
    let (cek, nonce) = content_key(&secret, auth, ua_public, &as_public, salt);

    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &cek).map_err(|_| "Bad content key".to_owned())?);
    let nonce = Nonce::try_assume_unique_for_key(&nonce).map_err(|_| "Bad nonce".to_owned())?;
    // One record, the last: the plaintext, then the delimiter 0x02.
    let mut record = Vec::with_capacity(plaintext.len() + 1 + TAG_LEN);
    record.extend_from_slice(plaintext);
    record.push(2);
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut record).map_err(|_| "Couldn't encrypt".to_owned())?;

    // The header (RFC 8188, section 2.1): salt, record size, and the
    // server's public key as the key id.
    let mut body = Vec::with_capacity(SALT_LEN + 4 + 1 + as_public.len() + record.len());
    body.extend_from_slice(salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(u8::try_from(as_public.len()).map_err(|_| "Bad key id".to_owned())?);
    body.extend_from_slice(&as_public);
    body.extend_from_slice(&record);
    Ok(body)
}

/// The server's VAPID key (RFC 8292).
pub struct Vapid {
    key: EcKey<Private>,
    public: Vec<u8>,
}

impl Vapid {
    /// A new key, as PEM (PKCS#8), to keep.
    pub fn generate_pem() -> Result<Vec<u8>, String> {
        let group = group()?;
        let key = EcKey::generate(&group).map_err(|e| e.to_string())?;
        PKey::from_ec_key(key).and_then(|k| k.private_key_to_pem_pkcs8()).map_err(|e| e.to_string())
    }

    /// The kept key, from its PEM: P-256 only.
    pub fn from_pem(pem: &[u8]) -> Result<Self, String> {
        let key = PKey::private_key_from_pem(pem)
            .and_then(|k| k.ec_key())
            .map_err(|_| "The VAPID key isn't an EC private key in PEM".to_owned())?;
        if key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            return Err("The VAPID key isn't a P-256 key".into());
        }
        key.check_key().map_err(|_| "The VAPID key isn't a valid key".to_owned())?;
        let public = uncompressed(&key)?;
        Ok(Self {
            key,
            public,
        })
    }

    /// Its public key, uncompressed, base64url without padding: what the
    /// phone gives its distributor, and the `k` of each message.
    pub fn public_key(&self) -> String {
        BASE64URL_NOPAD.encode(&self.public)
    }

    /// The ES256 JWT for one push service (`aud`, its origin), good until
    /// `exp` (seconds since 1970), with `sub` to reach the server's operator.
    pub fn jwt(&self, aud: &str, sub: &str, exp: i64) -> Result<String, String> {
        let header = BASE64URL_NOPAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = serde_json::json!({ "aud": aud, "exp": exp, "sub": sub });
        let claims = BASE64URL_NOPAD.encode(claims.to_string().as_bytes());
        let input = format!("{header}.{claims}");
        let digest = openssl::sha::sha256(input.as_bytes());
        let sig = EcdsaSig::sign(&digest, &self.key).map_err(|e| e.to_string())?;
        // JWS wants r and s, 32 bytes each (RFC 7518, section 3.4).
        let mut raw = sig.r().to_vec_padded(32).map_err(|e| e.to_string())?;
        raw.extend(sig.s().to_vec_padded(32).map_err(|e| e.to_string())?);
        Ok(format!("{input}.{}", BASE64URL_NOPAD.encode(&raw)))
    }

    /// The `Authorization` header for a message (RFC 8292, section 3).
    pub fn authorization(&self, aud: &str, sub: &str, exp: i64) -> Result<String, String> {
        Ok(format!("vapid t={}, k={}", self.jwt(aud, sub, exp)?, self.public_key()))
    }
}

/// A key from its private scalar, for the RFC's fixed keys in tests.
#[cfg(test)]
fn key_from_private(d: &[u8]) -> EcKey<Private> {
    let group = group().unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let d = openssl::bn::BigNum::from_slice(d).unwrap();
    let mut point = EcPoint::new(&group).unwrap();
    point.mul_generator2(&group, &d, &mut ctx).unwrap();
    EcKey::from_private_components(&group, &d, &point).unwrap()
}

/// Opens a message as a phone does, for the tests: the plaintext.
#[cfg(test)]
pub fn decrypt(ua_private: &[u8], auth: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
    let ua_key = key_from_private(ua_private);
    let ua_public = uncompressed(&ua_key)?;
    let salt = &body[..SALT_LEN];
    let rs = u32::from_be_bytes(body[SALT_LEN..SALT_LEN + 4].try_into().unwrap());
    let idlen = usize::from(body[SALT_LEN + 4]);
    let as_public = &body[SALT_LEN + 5..SALT_LEN + 5 + idlen];
    let mut record = body[SALT_LEN + 5 + idlen..].to_vec();
    if record.len() > rs as usize {
        return Err("More than one record".into());
    }
    let secret = ecdh(&ua_key, &public_key(as_public)?)?;
    let (cek, nonce) = content_key(&secret, auth, &ua_public, as_public, salt);
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &cek).unwrap());
    let nonce = Nonce::try_assume_unique_for_key(&nonce).unwrap();
    let plain = key.open_in_place(nonce, Aad::empty(), &mut record).map_err(|_| "Doesn't open".to_owned())?;
    let end = plain.iter().rposition(|b| *b != 0).ok_or("No delimiter")?;
    if plain[end] != 2 {
        return Err("Not the last record's delimiter".into());
    }
    Ok(plain[..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector(name: &str) -> Vec<u8> {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("vectors/web-push-rfc8291.json")).expect("the vector file");
        BASE64URL_NOPAD.decode(v[name].as_str().unwrap_or_else(|| panic!("{name}")).as_bytes()).expect(name)
    }

    #[test]
    fn rfc_8291_example_encrypts_to_its_message_byte_for_byte() {
        let as_key = key_from_private(&vector("as_private"));
        assert_eq!(uncompressed(&as_key).unwrap(), vector("as_public"));
        let salt: [u8; 16] = vector("salt").try_into().unwrap();
        let body = encrypt_with(&vector("ua_public"), &vector("auth_secret"), &vector("plaintext"), &as_key, &salt)
            .expect("it encrypts");
        assert_eq!(BASE64URL_NOPAD.encode(&body), BASE64URL_NOPAD.encode(&vector("message")));
    }

    #[test]
    fn rfc_8291_intermediate_values() {
        let as_key = key_from_private(&vector("as_private"));
        let secret = ecdh(&as_key, &public_key(&vector("ua_public")).unwrap()).unwrap();
        assert_eq!(*secret, vector("ecdh_secret"));
        let (cek, nonce) =
            content_key(&secret, &vector("auth_secret"), &vector("ua_public"), &vector("as_public"), &vector("salt"));
        assert_eq!(*cek, vector("cek"));
        assert_eq!(*nonce, vector("nonce"));
        assert_eq!(*hkdf(&vector("auth_secret"), &secret, &vector("key_info"), 32), vector("ikm"));
    }

    #[test]
    fn rfc_8291_message_opens_with_the_receivers_key() {
        let plain = decrypt(&vector("ua_private"), &vector("auth_secret"), &vector("message")).expect("it opens");
        assert_eq!(plain, vector("plaintext"));
        // And with another auth secret, it doesn't.
        assert!(decrypt(&vector("ua_private"), &[7u8; 16], &vector("message")).is_err());
    }

    #[test]
    fn each_message_has_its_own_key_and_salt_and_opens() {
        let ua = key_from_private(&vector("ua_private"));
        let ua_public = uncompressed(&ua).unwrap();
        let auth = vector("auth_secret");
        let a = encrypt(&ua_public, &auth, br#"{"kind":"sign-in"}"#).unwrap();
        let b = encrypt(&ua_public, &auth, br#"{"kind":"sign-in"}"#).unwrap();
        assert_ne!(a[..16], b[..16], "a salt of its own");
        assert_ne!(a[21..86], b[21..86], "a key of its own");
        assert_eq!(u32::from_be_bytes(a[16..20].try_into().unwrap()), RECORD_SIZE);
        assert_eq!(a[20], 65);
        assert_eq!(decrypt(&vector("ua_private"), &auth, &a).unwrap(), br#"{"kind":"sign-in"}"#);
        assert_eq!(decrypt(&vector("ua_private"), &auth, &b).unwrap(), br#"{"kind":"sign-in"}"#);
    }

    #[test]
    fn bad_keys_and_secrets_are_refused() {
        let auth = vector("auth_secret");
        let plain = b"x";
        let mut not_on_curve = vector("ua_public");
        not_on_curve[64] ^= 1;
        assert!(encrypt(&not_on_curve, &auth, plain).is_err());
        let mut compressed = vector("ua_public")[..33].to_vec();
        compressed[0] = 2;
        assert!(encrypt(&compressed, &auth, plain).is_err());
        assert!(encrypt(&[4u8; 65], &auth, plain).is_err());
        assert!(encrypt(&vector("ua_public"), &auth[..15], plain).is_err());
        assert!(encrypt(&vector("ua_public"), &[auth.clone(), vec![0]].concat(), plain).is_err());
        assert!(encrypt(&vector("ua_public"), &auth, &[0u8; 4096]).is_err());
    }

    #[test]
    fn the_vapid_jwt_is_es256_over_its_header_and_claims() {
        let pem = Vapid::generate_pem().unwrap();
        let vapid = Vapid::from_pem(&pem).unwrap();
        let public = BASE64URL_NOPAD.decode(vapid.public_key().as_bytes()).unwrap();
        assert_eq!(public.len(), 65);
        // The same key from its file each time.
        assert_eq!(Vapid::from_pem(&pem).unwrap().public_key(), vapid.public_key());

        let header =
            vapid.authorization("https://push.example.net", "https://vault.example.com", 1_800_000_000).unwrap();
        let (t, k) = header.strip_prefix("vapid t=").unwrap().split_once(", k=").unwrap();
        assert_eq!(k, vapid.public_key());
        let parts: Vec<&str> = t.split('.').collect();
        assert_eq!(parts.len(), 3);
        let head: serde_json::Value =
            serde_json::from_slice(&BASE64URL_NOPAD.decode(parts[0].as_bytes()).unwrap()).unwrap();
        assert_eq!(head, serde_json::json!({ "typ": "JWT", "alg": "ES256" }));
        let claims: serde_json::Value =
            serde_json::from_slice(&BASE64URL_NOPAD.decode(parts[1].as_bytes()).unwrap()).unwrap();
        assert_eq!(
            claims,
            serde_json::json!({ "aud": "https://push.example.net", "exp": 1_800_000_000, "sub": "https://vault.example.com" })
        );
        // The signature checks with the public key alone.
        let raw = BASE64URL_NOPAD.decode(parts[2].as_bytes()).unwrap();
        assert_eq!(raw.len(), 64);
        let sig = EcdsaSig::from_private_components(
            openssl::bn::BigNum::from_slice(&raw[..32]).unwrap(),
            openssl::bn::BigNum::from_slice(&raw[32..]).unwrap(),
        )
        .unwrap();
        let digest = openssl::sha::sha256(format!("{}.{}", parts[0], parts[1]).as_bytes());
        assert!(sig.verify(&digest, &public_key(&public).unwrap()).unwrap());
        let other = openssl::sha::sha256(b"something else");
        assert!(!sig.verify(&other, &public_key(&public).unwrap()).unwrap());
    }

    #[test]
    fn a_vapid_key_that_isnt_p256_is_refused() {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap().private_key_to_pem().unwrap();
        assert!(Vapid::from_pem(&rsa).is_err());
        let p384 = EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap();
        let p384 = PKey::from_ec_key(p384).unwrap().private_key_to_pem_pkcs8().unwrap();
        assert!(Vapid::from_pem(&p384).is_err());
        assert!(Vapid::from_pem(b"not a key").is_err());
    }
}

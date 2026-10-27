// Keykeeper: approving a sign-in from another device, upstream's "log in with
// device" (accounts.rs, the auth-request endpoints). A device the account
// already knows asks to sign in; one of the account's devices that signed in
// with the master password sends it the user key, wrapped to the request's
// own public key, which the server stores and never opens. What's ours: the
// 15 minutes everything stops at, a device's new request replacing its last,
// at most a few waiting per account, the shapes the server stores, and which
// sessions may approve. See DESIGN.md, "Approving a sign-in from another
// device".

use data_encoding::BASE64;
use rocket::{
    Request,
    request::{FromRequest, Outcome},
};

use crate::auth::{AuthMethod, decode_login};

/// How the session making a call signed in, from its access token
/// (`LoginJwtClaims::keykeeper_signin`). Use it after `Headers`, which
/// checks the token: a token that doesn't decode here says nothing.
pub struct SignInMethod(Option<AuthMethod>);

impl SignInMethod {
    /// Only a session that signed in with the master password approves a
    /// sign-in: not one that itself came from a device's approval, an API
    /// key, or SSO (which has its own trusted-device design to come).
    pub fn may_approve(&self) -> bool {
        self.0 == Some(AuthMethod::Password)
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SignInMethod {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let method = request
            .headers()
            .get_one("Authorization")
            .and_then(|a| a.strip_prefix("Bearer "))
            .and_then(|token| decode_login(token).ok())
            .and_then(|claims| claims.keykeeper_signin);
        Outcome::Success(SignInMethod(method))
    }
}

/// A request's public key as the server keeps it: base64 of a public key of
/// a sensible size (an RSA-2048 key's SubjectPublicKeyInfo is 294 bytes).
/// The apps check the key itself before they wrap anything to it.
pub fn valid_public_key(public_key: &str) -> bool {
    BASE64.decode(public_key.as_bytes()).is_ok_and(|der| (64..=1100).contains(&der.len()))
}

/// A request's access code: what the requesting device signs in with once
/// the request is approved. Upstream's apps make 25 characters.
pub fn valid_access_code(code: &str) -> bool {
    (8..=128).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_graphic())
}

/// An approval's wrapped key: an encrypted string the requesting device
/// opens (type 4, RSA-OAEP, from our apps and upstream's), which the server
/// stores as it came.
pub fn valid_approval_key(key: &str) -> bool {
    (3..=4096).contains(&key.len())
        && key.bytes().all(|b| b.is_ascii_graphic())
        && key.split_once('.').is_some_and(|(kind, rest)| kind.bytes().all(|b| b.is_ascii_digit()) && !rest.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_master_password_session_approves() {
        assert!(SignInMethod(Some(AuthMethod::Password)).may_approve());
        for method in [AuthMethod::AuthRequest, AuthMethod::Sso, AuthMethod::UserApiKey, AuthMethod::OrgApiKey] {
            assert!(!SignInMethod(Some(method)).may_approve());
        }
        assert!(!SignInMethod(None).may_approve());
    }

    #[test]
    fn what_a_request_and_an_approval_may_hold() {
        // An RSA-2048 key's SubjectPublicKeyInfo, as the apps send it.
        let spki = BASE64.encode(&[0x30; 294]);
        assert!(valid_public_key(&spki));
        assert!(!valid_public_key("not base64!"));
        assert!(!valid_public_key(""));
        assert!(!valid_public_key(&BASE64.encode(&[0; 8])));
        assert!(!valid_public_key(&BASE64.encode(&[0; 4096])));

        assert!(valid_access_code("Zq3vXkP9wT2mLr8sYb4nHc6dJ"));
        assert!(!valid_access_code("short"));
        assert!(!valid_access_code("has a space in it"));
        assert!(!valid_access_code(&"x".repeat(129)));

        assert!(valid_approval_key(&format!("4.{}", BASE64.encode(&[7; 256]))));
        assert!(!valid_approval_key(""));
        assert!(!valid_approval_key("not an encrypted string"));
        assert!(!valid_approval_key("4."));
        assert!(!valid_approval_key(&format!("4.{}", "A".repeat(5000))));
    }
}

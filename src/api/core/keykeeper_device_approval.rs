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

use crate::{
    api::{EmptyResult, core::keykeeper_sso},
    auth::{AuthMethod, decode_login},
    db::{
        DbConn,
        models::{AuthRequest, Device, DeviceId, User},
    },
};

/// How the session making a call signed in, from its access token
/// (`LoginJwtClaims::keykeeper_signin`). Use it after `Headers`, which
/// checks the token: a token that doesn't decode here says nothing.
pub struct SignInMethod(Option<AuthMethod>);

impl SignInMethod {
    /// Whether the session signed in with the master password: not with a
    /// device's approval, an API key, or SSO (which has its own
    /// trusted-device design to come). Only such a session approves a
    /// sign-in.
    pub fn is_master_password(&self) -> bool {
        self.0 == Some(AuthMethod::Password)
    }

    /// Whether the person proved who they are to start this session: with
    /// the master password, or with an organization's single sign-on. Not a
    /// session a device's approval began, an API key's, or one that doesn't
    /// say. Only such a session uses emergency access, on either side
    /// (emergency_access.rs), so one mistaken approval can't set up, or
    /// start, a takeover; members an organization requires to use single
    /// sign-on still can.
    pub fn proved_who_they_are(&self) -> bool {
        matches!(self.0, Some(AuthMethod::Password | AuthMethod::Sso))
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

/// An approval's wrapped key: the user key as an encrypted string of type 4
/// (RSA-OAEP with SHA-1), what our apps and upstream's send, which the
/// requesting device opens and the server stores as it came. Nothing else
/// is taken.
pub fn valid_approval_key(key: &str) -> bool {
    key.strip_prefix("4.")
        .and_then(|b64| BASE64.decode(b64.as_bytes()).ok())
        .is_some_and(|ciphertext| (128..=512).contains(&ciphertext.len()))
}

/// Whether a sign-in with an approved request comes from the device that
/// asked, as the type it asked as: the access code alone isn't enough.
pub fn is_requesting_device(request: &AuthRequest, device_identifier: Option<&DeviceId>, device_type: i32) -> bool {
    device_identifier == Some(&request.request_device_identifier) && device_type == request.device_type
}

/// The organizations' rules for a sign-in with a device's approval, once the
/// request, the device, and two-step login checked out (identity.rs,
/// password_login). Such a sign-in proves no password, so any rule that
/// must hold for every sign-in goes here as well as on the password's path:
/// - Requiring single sign-on: someone an organization requires to sign in
///   with its single sign-on does so, linked or not. The password grant
///   checks it for both kinds already (keykeeper_sso::password_requirement);
///   this holds it here too, so it can't come apart from this path.
/// - An admin two-step rule, when there is one, belongs here too.
pub async fn approved_sign_in_rules(user: &User, _device: &Device, conn: &DbConn) -> EmptyResult {
    if let Some(identifier) = keykeeper_sso::required_identifier(&user.uuid, conn).await {
        let message = "Your organization requires you to sign in with single sign-on.";
        err_json!(
            json!({
                "error": "invalid_grant",
                "error_description": message,
                "SsoOrganizationIdentifier": identifier,
                "ErrorModel": { "Message": message, "Object": "error" },
            }),
            "Single sign-on required; a device's approval doesn't stand in for it."
        )
    }
    Ok(())
}

/// For the server's request log: a request's answer is read with its access
/// code in the address (`?code=`), so that path is logged without it.
pub fn redacts(path: &str) -> bool {
    path.starts_with("/api/auth-requests/") && path.ends_with("/response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_or_sso_session_uses_emergency_access() {
        for method in [AuthMethod::Password, AuthMethod::Sso] {
            assert!(SignInMethod(Some(method)).proved_who_they_are());
        }
        for method in [AuthMethod::AuthRequest, AuthMethod::UserApiKey, AuthMethod::OrgApiKey] {
            assert!(!SignInMethod(Some(method)).proved_who_they_are());
        }
        assert!(!SignInMethod(None).proved_who_they_are());
    }

    #[test]
    fn only_a_master_password_session_approves() {
        assert!(SignInMethod(Some(AuthMethod::Password)).is_master_password());
        for method in [AuthMethod::AuthRequest, AuthMethod::Sso, AuthMethod::UserApiKey, AuthMethod::OrgApiKey] {
            assert!(!SignInMethod(Some(method)).is_master_password());
        }
        assert!(!SignInMethod(None).is_master_password());
    }

    #[test]
    fn only_the_device_that_asked_signs_in_with_its_approval() {
        let request = AuthRequest::new(
            "user".to_owned().into(),
            "phone".to_owned().into(),
            9,
            "203.0.113.7".to_owned(),
            "code".to_owned(),
            "key".to_owned(),
        );
        let phone: DeviceId = "phone".to_owned().into();
        let other: DeviceId = "other".to_owned().into();
        assert!(is_requesting_device(&request, Some(&phone), 9));
        assert!(!is_requesting_device(&request, Some(&other), 9));
        assert!(!is_requesting_device(&request, Some(&phone), 10));
        assert!(!is_requesting_device(&request, None, 9));
    }

    #[test]
    fn the_answer_with_its_access_code_isnt_logged() {
        assert!(redacts("/api/auth-requests/6f1c2b0e-0000-4000-8000-000000000001/response"));
        assert!(!redacts("/api/auth-requests/pending"));
        assert!(!redacts("/api/auth-requests/6f1c2b0e-0000-4000-8000-000000000001"));
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
        assert!(!valid_approval_key("4.not base64!"));
        assert!(!valid_approval_key(&format!("4.{}", BASE64.encode(&[7; 64]))));
        assert!(!valid_approval_key(&format!("4.{}", BASE64.encode(&[7; 1024]))));
        // Only type 4: not a symmetric string, not OAEP with SHA-256.
        for kind in ["2", "3", "6", "40"] {
            assert!(!valid_approval_key(&format!("{kind}.{}", BASE64.encode(&[7; 256]))), "{kind}");
        }
    }
}

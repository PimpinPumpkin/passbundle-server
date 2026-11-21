// Keykeeper: approving a sign-in from another device, upstream's "log in with
// device" (accounts.rs, the auth-request endpoints). A device the account
// already knows asks to sign in; one of the account's devices that signed in
// with the master password or single sign-on sends it the user key, wrapped
// to the request's own public key, which the server stores and never opens.
// What's ours: the 15 minutes everything stops at, a device's new request
// replacing its last, at most a few waiting per account, the shapes the
// server stores, which sessions may approve, and no approval taken that its
// sign-in couldn't use. See DESIGN.md, "Approving a sign-in from another
// device".

use data_encoding::BASE64;
use rocket::{
    Request,
    request::{FromRequest, Outcome},
};
use serde_json::Value;

use crate::{
    api::{
        EmptyResult,
        core::{keykeeper_sso, keykeeper_two_step},
    },
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
    /// Whether the session may approve a "Sign in with a device" request,
    /// sending the user key: one that signed in with the master password, or
    /// with an organization's single sign-on, which only proves who's signing
    /// in (the vault still opens with the master password, so such a session
    /// holds the same user key). Not a session a device's approval began, so
    /// one mistaken approval doesn't spread; not an API key's; and not one
    /// that doesn't say. The clients ask the person to confirm it's them
    /// before they send the key, as for a password session.
    pub fn may_approve_sign_in(&self) -> bool {
        matches!(self.0, Some(AuthMethod::Password | AuthMethod::Sso))
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

    /// Whether the session may answer a new device's sign-in (DESIGN.md,
    /// "New-device check"): one that began with the master password, single
    /// sign-on, or a device's approval. Not an API key's, or one that doesn't
    /// say. No key moves, so a session from an approval may answer too.
    pub fn may_approve_new_device(&self) -> bool {
        matches!(self.0, Some(AuthMethod::Password | AuthMethod::Sso | AuthMethod::AuthRequest))
    }

    /// A session that signed in with the master password, for tests that
    /// call a route needing one.
    #[cfg(test)]
    pub fn master_password() -> Self {
        Self(Some(AuthMethod::Password))
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

/// A request's answer to the account's own devices, with where the request
/// comes from added for their prompts, in the new-device check's fields and
/// words: `location`, roughly where its address is ("Berlin, Germany", or
/// null for an address the database doesn't have, or a private one), and
/// `locationSource`, who to credit beside it. Both null without the
/// server's own location database (`keykeeper_location::shown`), the only
/// source: no other service is asked. A hint for the person, never a check:
/// nothing is refused because of it. Upstream's fields stay as they are.
pub fn with_location(mut answer: Value, (location, source): (Option<String>, Option<Value>)) -> Value {
    answer["location"] = json!(location);
    answer["locationSource"] = json!(source);
    answer
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
/// - Two-step login for admins: someone it covers who has no method that
///   counts is refused, with no setup session, since that takes a password
///   (keykeeper_two_step::check_approved_sign_in). The password's path starts
///   one instead (keykeeper_two_step::check_sign_in).
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
    keykeeper_two_step::check_approved_sign_in(user, conn).await
}

/// What the person approving is told when the account must sign in with an
/// organization's single sign-on (`approval_can_sign_in`): why, and what to
/// do on the device that asked instead, whichever it is (a browser, our apps,
/// or the command-line tool).
pub const SSO_REQUIRED_APPROVAL: &str = "Your organization requires single sign-on, so an approval can't sign that device in. On that device, sign in with single sign-on instead.";

/// Whether an approval could sign the device that asked in, checked when it's
/// approved (accounts.rs, put_auth_request), before any key is taken. Someone
/// an organization requires to sign in with its single sign-on is sent there
/// at the sign-in, approval or not (`approved_sign_in_rules`), so an approval
/// for them would never be used: the person approving would see it approved,
/// the device that asked would be refused, and the user key, wrapped to that
/// device, would be handed to it for a sign-in the server refuses. So it's
/// refused here, with what to do instead, and nothing is kept; the request
/// waits as before, and denying it is open as always. The check at the sign-in stays, for a
/// requirement that starts after the approval. It's the same account on both
/// devices (a request is the account's own), so it says nothing the person
/// approving doesn't know.
///
/// The same goes for two-step login for admins: someone it covers who has no
/// method that counts is refused at the sign-in (check_approved_sign_in), so
/// their approval is refused here too, saying who requires it and to set it
/// up, then approve again (keykeeper_two_step::check_approval). Single
/// sign-on first, as at the sign-in.
pub async fn approval_can_sign_in(user: &User, conn: &DbConn) -> EmptyResult {
    if keykeeper_sso::required_identifier(&user.uuid, conn).await.is_some() {
        err!(SSO_REQUIRED_APPROVAL)
    }
    keykeeper_two_step::check_approval(user, conn).await
}

/// For the server's request log: a request's answer is read with its access
/// code in the address (`?code=`), so that path is logged without it, with or
/// without a slash at the end.
pub fn redacts(path: &str) -> bool {
    let path = path.trim_end_matches('/');
    path.starts_with("/api/auth-requests/") && path.ends_with("/response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_requests_answer_is_logged_without_its_access_code() {
        for path in [
            "/api/auth-requests/0b1c/response",
            "/api/auth-requests/0b1c/response/",
            "/api/auth-requests/0b1c/response//",
        ] {
            assert!(redacts(path), "{path}");
        }
        assert!(!redacts("/api/auth-requests/0b1c"));
        assert!(!redacts("/api/accounts/profile"));
    }

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
    fn a_new_devices_sign_in_is_answered_by_a_signed_in_session_but_not_an_api_keys() {
        for method in [AuthMethod::Password, AuthMethod::Sso, AuthMethod::AuthRequest] {
            assert!(SignInMethod(Some(method)).may_approve_new_device());
        }
        for method in [AuthMethod::UserApiKey, AuthMethod::OrgApiKey] {
            assert!(!SignInMethod(Some(method)).may_approve_new_device());
        }
        assert!(!SignInMethod(None).may_approve_new_device());
    }

    #[test]
    fn a_password_or_sso_session_approves_a_sign_in() {
        for method in [AuthMethod::Password, AuthMethod::Sso] {
            assert!(SignInMethod(Some(method)).may_approve_sign_in());
        }
        for method in [AuthMethod::AuthRequest, AuthMethod::UserApiKey, AuthMethod::OrgApiKey] {
            assert!(!SignInMethod(Some(method)).may_approve_sign_in());
        }
        assert!(!SignInMethod(None).may_approve_sign_in());
    }

    #[test]
    fn the_session_an_approval_began_never_approves_whatever_else_it_may_do() {
        // It answers a new device's sign-in (no key moves), but never sends
        // the user key on, and never uses emergency access.
        let from_approval = SignInMethod(Some(AuthMethod::AuthRequest));
        assert!(from_approval.may_approve_new_device());
        assert!(!from_approval.may_approve_sign_in());
        assert!(!from_approval.proved_who_they_are());
    }

    #[test]
    fn the_access_tokens_words_for_how_a_session_signed_in() {
        // `keykeeper_signin` as the access token carries it: "sso" is what an
        // organization's single sign-on puts there (identity.rs).
        for (said, approves) in
            [("password", true), ("sso", true), ("authrequest", false), ("userapikey", false), ("orgapikey", false)]
        {
            let method: Option<AuthMethod> = serde_json::from_value(json!(said)).unwrap();
            assert_eq!(SignInMethod(method).may_approve_sign_in(), approves, "{said}");
        }
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
    fn a_requests_answer_says_where_it_comes_from_only_with_a_location_file() {
        use crate::keykeeper_location::{shown_from, tests::TestFile};
        let upstream = json!({
            "id": "6f1c2b0e-0000-4000-8000-000000000001",
            "requestDeviceType": "Chrome",
            "requestIpAddress": "203.0.113.7",
            "object": "auth-request",
        });
        let file = TestFile::new("device-approval");
        let credit = json!({ "name": "IP Geolocation by DB-IP", "url": "https://db-ip.com" });

        let located = with_location(upstream.clone(), shown_from(file.path(), "203.0.113.7"));
        assert_eq!(located["location"], json!("Berlin, Germany"));
        assert_eq!(located["locationSource"], credit);
        // Upstream's fields stay as they were, and upstream's own country
        // field isn't filled: its dialog would show it without the credit.
        for field in ["id", "requestDeviceType", "requestIpAddress", "object"] {
            assert_eq!(located[field], upstream[field], "{field}");
        }
        assert!(located.get("requestCountryName").is_none());

        // An address the database can't place: no location, still the credit.
        let private = with_location(upstream.clone(), shown_from(file.path(), "10.1.2.3"));
        assert_eq!(private["location"], Value::Null);
        assert_eq!(private["locationSource"], credit);

        // No location file: both null, and nothing else changes.
        let missing = file.path().with_file_name("missing.mmdb");
        let without = with_location(upstream.clone(), shown_from(&missing, "203.0.113.7"));
        assert_eq!(without["location"], Value::Null);
        assert_eq!(without["locationSource"], Value::Null);
        let mut rest = without.as_object().unwrap().clone();
        rest.remove("location");
        rest.remove("locationSource");
        assert_eq!(Value::Object(rest), upstream);
    }

    #[test]
    fn the_answer_with_its_access_code_isnt_logged() {
        assert!(redacts("/api/auth-requests/6f1c2b0e-0000-4000-8000-000000000001/response"));
        assert!(!redacts("/api/auth-requests/pending"));
        assert!(!redacts("/api/auth-requests/6f1c2b0e-0000-4000-8000-000000000001"));
    }

    /// Someone who has joined `org` as `atype`, with that status.
    async fn joined(
        name: &str,
        atype: crate::db::models::MembershipType,
        status: crate::db::models::MembershipStatus,
        org: &crate::db::models::OrganizationId,
        conn: &DbConn,
    ) -> User {
        let mut user = User::new(&format!("{name}@contoso.example.test"), None);
        user.save(conn).await.unwrap();
        let mut member = crate::db::models::Membership::new(user.uuid.clone(), org.clone(), None);
        member.atype = atype as i32;
        member.status = status as i32;
        member.save(conn).await.unwrap();
        user
    }

    #[rocket::async_test]
    async fn an_approval_for_someone_who_must_use_single_sign_on_is_refused_with_what_to_do_instead() {
        use crate::db::{
            DbPool,
            models::{MembershipStatus, MembershipType, OrgPolicy, OrgPolicyType, Organization, SsoConfig},
        };
        let conn = DbPool::for_test().await;
        let org = Organization::new("Contoso".to_owned(), "billing@contoso.example.test", None, None);
        org.save(&conn).await.unwrap();
        let member = joined("gus", MembershipType::User, MembershipStatus::Confirmed, &org.uuid, &conn).await;
        let accepted = joined("ana", MembershipType::Admin, MembershipStatus::Accepted, &org.uuid, &conn).await;
        let owner = joined("owner", MembershipType::Owner, MembershipStatus::Confirmed, &org.uuid, &conn).await;
        let invited = joined("lee", MembershipType::User, MembershipStatus::Invited, &org.uuid, &conn).await;
        let everyone = [&member, &accepted, &owner, &invited];

        // Single sign-on set up, not required: every approval is taken.
        let mut sso = SsoConfig::new(org.uuid.clone(), "owner@contoso.example.test");
        sso.enabled = true;
        sso.identifier = "contoso".to_owned();
        sso.tenant_id = "tenant".to_owned();
        sso.client_id = "client".to_owned();
        sso.client_secret = Some("sealed".to_owned());
        sso.save(&conn).await.unwrap();
        for user in everyone {
            assert!(approval_can_sign_in(user, &conn).await.is_ok(), "{}", user.email);
        }

        // Required: members who joined are refused, with what to do instead,
        // as a plain 400. The owner, whom it never binds, and someone only
        // invited, still approve.
        let mut required = OrgPolicy::new(org.uuid.clone(), OrgPolicyType::RequireSso, true, "null".to_owned());
        required.save(&conn).await.unwrap();
        for user in [&member, &accepted] {
            let refused = approval_can_sign_in(user, &conn).await.unwrap_err();
            assert_eq!(refused.message(), SSO_REQUIRED_APPROVAL, "{}", user.email);
            assert_eq!(refused.status_code(), 400);
        }
        for user in [&owner, &invited] {
            assert!(approval_can_sign_in(user, &conn).await.is_ok(), "{}", user.email);
        }

        // Single sign-on turned off, or the requirement off: taken again.
        sso.enabled = false;
        sso.save(&conn).await.unwrap();
        assert!(approval_can_sign_in(&member, &conn).await.is_ok());
        sso.enabled = true;
        sso.save(&conn).await.unwrap();
        assert!(approval_can_sign_in(&member, &conn).await.is_err());
        required.enabled = false;
        required.save(&conn).await.unwrap();
        for user in everyone {
            assert!(approval_can_sign_in(user, &conn).await.is_ok(), "{}", user.email);
        }
    }

    #[rocket::async_test]
    async fn an_approval_for_someone_two_step_login_for_admins_refuses_is_refused_with_what_to_do_instead() {
        use crate::{
            CONFIG,
            db::{
                DbPool,
                models::{
                    MembershipStatus, MembershipType, OrgAdminTwoStep, Organization, TwoFactor, TwoFactorType,
                    TwoStepScope,
                },
            },
        };
        let conn = DbPool::for_test().await;
        let org = Organization::new("Contoso".to_owned(), "billing@contoso.example.test", None, None);
        org.save(&conn).await.unwrap();
        // People with a master password (a hash stands in for it).
        let with_password = async |name: &str, atype: MembershipType| {
            let mut user = joined(name, atype, MembershipStatus::Confirmed, &org.uuid, &conn).await;
            user.password_hash = b"hash".to_vec();
            user.save(&conn).await.unwrap();
            user
        };
        let admin = with_password("ana", MembershipType::Admin).await;
        let owner = with_password("owner", MembershipType::Owner).await;
        let set_up = with_password("ben", MembershipType::Admin).await;
        TwoFactor::new(set_up.uuid.clone(), TwoFactorType::Authenticator, String::new()).save(&conn).await.unwrap();
        // Email codes don't count.
        let by_email = with_password("cy", MembershipType::Admin).await;
        TwoFactor::new(by_email.uuid.clone(), TwoFactorType::Email, String::new()).save(&conn).await.unwrap();
        let member = with_password("gus", MembershipType::User).await;
        // An admin without a master password yet (an invitation's first
        // single sign-on, which goes on to set one).
        let no_password = joined("dee", MembershipType::Admin, MembershipStatus::Confirmed, &org.uuid, &conn).await;
        let everyone = [&admin, &owner, &set_up, &by_email, &member, &no_password];

        // The approval is refused exactly where the sign-in it's for would be.
        let agrees = async |user: &User| {
            assert_eq!(
                approval_can_sign_in(user, &conn).await.is_ok(),
                keykeeper_two_step::check_approved_sign_in(user, &conn).await.is_ok(),
                "{}",
                user.email
            );
        };

        // Not required: every approval is taken.
        for user in everyone {
            assert!(approval_can_sign_in(user, &conn).await.is_ok(), "{}", user.email);
            agrees(user).await;
        }

        // Required for admins: those it covers without a method that counts
        // are refused, with who requires it and what to do, as a plain 400.
        OrgAdminTwoStep::set(&org.uuid, TwoStepScope::Admins, &conn).await.unwrap();
        let said = format!(
            "Contoso requires two-step login for your role. Until you set it up, an approval can't sign that device in. Set up an authenticator app, a security key or passkey, or Duo in the web vault at {} (Settings, Security, Two-step login), then approve again.",
            CONFIG.domain()
        );
        for user in [&admin, &owner, &by_email] {
            let refused = approval_can_sign_in(user, &conn).await.unwrap_err();
            assert_eq!(refused.message(), said, "{}", user.email);
            assert_eq!(refused.status_code(), 400);
        }
        // Someone it covers with a method that counts, someone it doesn't
        // cover, and an account without a master password, whose sign-in
        // isn't held up: taken.
        for user in [&set_up, &member, &no_password] {
            assert!(approval_can_sign_in(user, &conn).await.is_ok(), "{}", user.email);
        }
        for user in everyone {
            agrees(user).await;
        }

        // Required of everyone: the member too.
        OrgAdminTwoStep::set(&org.uuid, TwoStepScope::Everyone, &conn).await.unwrap();
        assert_eq!(approval_can_sign_in(&member, &conn).await.unwrap_err().message(), said);
        agrees(&member).await;

        // Once the admin sets up a method that counts, theirs is taken.
        TwoFactor::new(admin.uuid.clone(), TwoFactorType::Authenticator, String::new()).save(&conn).await.unwrap();
        assert!(approval_can_sign_in(&admin, &conn).await.is_ok());
        agrees(&admin).await;
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

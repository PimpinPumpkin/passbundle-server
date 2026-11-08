use std::collections::HashSet;

use chrono::Utc;
use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
    serde::json::Json,
};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        AnonymousNotify, ApiResult, EmptyResult, JsonResult, Notify, PasswordOrOtpData, UpdateType,
        core::{accept_org_invite, log_user_event, two_factor::email},
        master_password_policy, push_logout_to_relay, register_push_device, unregister_push_device,
    },
    auth::{ClientHeaders, ClientIp, Headers, decode_delete, decode_invite, decode_verify_email},
    crypto,
    db::{
        DbConn, DbPool,
        models::{
            AuthRequest, AuthRequestId, Cipher, CipherId, CipherVersion, Device, DeviceId, DeviceType,
            DeviceWithAuthRequest, EmergencyAccess, EmergencyAccessId, EventType, Folder, FolderId, Invitation,
            ItemSave, KeyId, MAX_PENDING_AUTH_REQUESTS, Membership, MembershipId, OrgPolicy, OrgPolicyType,
            Organization, OrganizationId, Send, SendId, User, UserId, UserKdfType, UserSettings,
        },
    },
    mail,
    util::{NumberOrString, deser_opt_nonempty_str, format_date},
};

use super::{
    ciphers::{CipherData, update_cipher_from_data},
    keykeeper_device_approval::{SignInMethod, valid_access_code, valid_approval_key, valid_public_key},
    sends::SendData,
};

pub fn routes() -> Vec<rocket::Route> {
    routes![
        profile,
        put_profile,
        post_profile,
        put_avatar,
        get_public_keys,
        get_keys,
        post_keys,
        post_password,
        post_set_password,
        post_kdf,
        post_rotatekey,
        post_user_key,
        post_sstamp,
        post_email_token,
        post_email,
        post_verify_email,
        post_verify_email_token,
        post_delete_recover,
        post_delete_recover_token,
        post_delete_account,
        delete_account,
        revision_date,
        password_hint,
        verify_password,
        post_api_key,
        rotate_api_key,
        get_known_device,
        get_all_devices,
        get_device,
        post_device_token,
        put_device_token,
        put_clear_device_token,
        post_clear_device_token,
        get_tasks,
        post_auth_request,
        get_auth_request,
        put_auth_request,
        get_auth_request_response,
        get_auth_requests,
        get_auth_requests_pending,
    ]
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KDFData {
    #[serde(alias = "kdfType")]
    kdf: i32,
    #[serde(alias = "iterations")]
    kdf_iterations: i32,
    #[serde(alias = "memory")]
    kdf_memory: Option<i32>,
    #[serde(alias = "parallelism")]
    kdf_parallelism: Option<i32>,
}

impl KDFData {
    /// Keykeeper: settings an account can have (`check_kdf`).
    pub(super) fn check(&self) -> EmptyResult {
        check_kdf(self.kdf, self.kdf_iterations, self.kdf_memory, self.kdf_parallelism)
    }

    pub(super) fn matches_user(&self, user: &User) -> bool {
        self.kdf == user.client_kdf_type
            && self.kdf_iterations == user.client_kdf_iter
            && self.kdf_memory == user.client_kdf_memory
            && self.kdf_parallelism == user.client_kdf_parallelism
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterData {
    email: String,

    #[serde(flatten)]
    compat: RegisterDataCompat,

    #[serde(alias = "userAsymmetricKeys")]
    keys: Option<KeysData>,

    master_password_hint: Option<String>,

    organization_user_id: Option<MembershipId>,

    email_verification_token: Option<String>,
    accept_emergency_access_id: Option<EmergencyAccessId>,
    accept_emergency_access_invite_token: Option<String>,
    #[serde(alias = "token")]
    org_invite_token: Option<String>,
}

impl RegisterData {
    fn hash(&self) -> String {
        self.compat.fold(|rdc| &rdc.master_password_hash, |rdcu| &rdcu.master_password_authentication.hash).to_owned()
    }

    fn kdf(&self) -> &KDFData {
        self.compat.fold(|rdc| &rdc.kdf, |rdcu| &rdcu.master_password_authentication.kdf)
    }

    fn key(&self) -> String {
        self.compat.fold(|rdc| &rdc.key, |rdcu| &rdcu.master_password_unlock.key).to_owned()
    }

    // When comparing with salt, email need to be normalized:
    //  - https://github.com/bitwarden/clients/blob/web-v2026.5.0/libs/common/src/key-management/master-password/services/master-password.service.ts#L171
    fn unprocessable(&self) -> bool {
        let mut unprocessable = false;
        *self.compat.fold(
            |_| &false,
            |rdcu| {
                let email = self.email.trim().to_lowercase();
                unprocessable = rdcu.master_password_authentication.kdf != rdcu.master_password_unlock.kdf
                    || rdcu.master_password_authentication.salt != email
                    || rdcu.master_password_unlock.salt != email;
                &unprocessable
            },
        )
    }
}

#[derive(Debug, Deserialize)]
struct RegisterDataOld {
    #[serde(flatten)]
    kdf: KDFData,

    #[serde(alias = "userSymmetricKey")]
    key: String,

    #[serde(alias = "masterPasswordHash")]
    master_password_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterDataCur {
    #[serde(alias = "MasterPasswordAuthentication")]
    master_password_authentication: MasterPasswordAuthentication,
    #[serde(alias = "MasterPasswordUnlock")]
    master_password_unlock: MasterPasswordUnlock,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RegisterDataCompat {
    RegisterDataOld(RegisterDataOld),
    RegisterDataCur(RegisterDataCur),
}

impl RegisterDataCompat {
    fn fold<'a, T>(
        &'a self,
        fct: impl FnOnce(&'a RegisterDataOld) -> &'a T,
        fcu: impl FnOnce(&'a RegisterDataCur) -> &'a T,
    ) -> &'a T {
        match self {
            RegisterDataCompat::RegisterDataOld(rdc) => fct(rdc),
            RegisterDataCompat::RegisterDataCur(rdcu) => fcu(rdcu),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeysData {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordAuthentication {
    #[serde(alias = "Kdf")]
    kdf: KDFData,
    #[serde(alias = "Salt")]
    salt: String,

    #[serde(alias = "masterPasswordAuthenticationHash", alias = "MasterPasswordAuthenticationHash")]
    hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordUnlock {
    kdf: KDFData,
    salt: String,

    #[serde(alias = "masterKeyWrappedUserKey")]
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordData {
    #[serde(flatten)]
    kdf: KDFData,

    key: String,
    keys: Option<KeysData>,
    master_password_hash: String,
    master_password_hint: Option<String>,
    org_identifier: Option<String>,
}

/// Trims whitespace from password hints, and converts blank password hints to `None`.
fn clean_password_hint(password_hint: Option<&String>) -> Option<String> {
    match password_hint {
        None => None,
        Some(h) => match h.trim() {
            "" => None,
            ht => Some(ht.to_owned()),
        },
    }
}

fn enforce_password_hint_setting(password_hint: Option<&String>) -> EmptyResult {
    if password_hint.is_some() && !CONFIG.password_hints_allowed() {
        err!("Password hints have been disabled by the administrator. Remove the hint and try again.");
    }
    Ok(())
}
async fn is_email_2fa_required(member_id: Option<MembershipId>, conn: &DbConn) -> bool {
    if !CONFIG._enable_email_2fa() {
        return false;
    }
    if CONFIG.email_2fa_enforce_on_verified_invite() {
        return true;
    }
    if let Some(member_id) = member_id {
        return OrgPolicy::is_enabled_for_member(&member_id, OrgPolicyType::TwoFactorAuthentication, conn).await;
    }
    false
}

pub async fn register(data: Json<RegisterData>, conn: DbConn) -> JsonResult {
    let data: RegisterData = data.into_inner();
    let email = data.email.to_lowercase();

    let mut name = None;
    let mut pending_emergency_access = None;

    if data.unprocessable() {
        err_code!("Unexpected RegisterData format", Status::UnprocessableEntity.code);
    }

    // Keykeeper: the KDF settings first, so that a refused registration keeps its invitation (taken below), as
    // the password hint check does.
    data.kdf().check()?;

    // First, validate the provided verification tokens
    let mut email_verified = match (
        &data.email_verification_token,
        &data.accept_emergency_access_id,
        &data.accept_emergency_access_invite_token,
        &data.organization_user_id,
        &data.org_invite_token,
    ) {
        // Normal user registration, when email verification is required
        (Some(email_verification_token), None, None, None, None) => {
            let claims = crate::auth::decode_register_verify(email_verification_token)?;
            if claims.sub != data.email {
                err!("Email verification token does not match email");
            }

            // During this call we don't get the name, so extract it from the claims
            name = claims.name;
            claims.verified
        }
        // Emergency access registration
        (None, Some(accept_emergency_access_id), Some(accept_emergency_access_invite_token), None, None) => {
            if !CONFIG.emergency_access_allowed() {
                err!("Emergency access is not enabled.")
            }

            let claims = crate::auth::decode_emergency_access_invite(accept_emergency_access_invite_token)?;

            if claims.email != data.email {
                err!("Claim email does not match email")
            }
            if &claims.emer_id != accept_emergency_access_id {
                err!("Claim emer_id does not match accept_emergency_access_id")
            }

            pending_emergency_access = Some((accept_emergency_access_id, claims));
            true
        }
        // Org invite
        (None, None, None, Some(organization_user_id), Some(org_invite_token)) => {
            let claims = decode_invite(org_invite_token)?;

            if claims.email != data.email {
                err!("Claim email does not match email")
            }

            if &claims.member_id != organization_user_id {
                err!("Claim org_user_id does not match organization_user_id")
            }

            true
        }

        _ => {
            err!("Registration is missing required parameters")
        }
    };

    // Check if the length of the username exceeds 50 characters (Same is Upstream Bitwarden)
    // This also prevents issues with very long usernames causing to large JWT's. See #2419
    if let Some(ref name) = name
        && name.len() > 50
    {
        err!("The field Name must be a string with a maximum length of 50.");
    }

    // Check against the password hint setting here so if it fails, the user
    // can retry without losing their invitation below.
    let password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(password_hint.as_ref())?;

    let mut user = match User::find_by_mail(&email, &conn).await {
        Some(user) => {
            if !user.password_hash.is_empty() {
                err!("Registration not allowed or user already exists")
            }

            if let Some(token) = data.org_invite_token.as_ref() {
                let claims = decode_invite(token)?;
                if claims.email == email {
                    // Verify the email address when signing up via a valid invite token
                    email_verified = true;
                    user
                } else {
                    err!("Registration email does not match invite email")
                }
            } else if Invitation::take(&email, &conn).await {
                accept_invitations_for_them(&user.uuid, &conn).await?;
                user
            } else if CONFIG.is_signup_allowed(&email)
                || (CONFIG.emergency_access_allowed()
                    && EmergencyAccess::find_invited_by_grantee_email(&email, &conn).await.is_some())
            {
                user
            } else {
                err!("Registration not allowed or user already exists")
            }
        }
        None => {
            // Order is important here; the invitation check must come first
            // because the vaultwarden admin can invite anyone, regardless
            // of other signup restrictions.
            if Invitation::take(&email, &conn).await
                || CONFIG.is_signup_allowed(&email)
                || pending_emergency_access.is_some()
            {
                User::new(&email, None)
            } else {
                err!("Registration not allowed or user already exists")
            }
        }
    };

    // Make sure we don't leave a lingering invitation.
    Invitation::take(&email, &conn).await;

    set_kdf_data(&mut user, data.kdf())?;

    user.set_password(&data.hash(), Some(data.key()), true, None, &conn).await?;
    user.password_hint = password_hint;

    // Add extra fields if present
    if let Some(name) = name {
        user.name = name;
    }

    if let Some(keys) = data.keys {
        user.private_key = Some(keys.encrypted_private_key);
        user.public_key = Some(keys.public_key);
    }

    if email_verified {
        user.verified_at = Some(Utc::now().naive_utc());
    }

    if CONFIG.mail_enabled() {
        if CONFIG.signups_verify() && !email_verified {
            if let Err(e) = mail::send_welcome_must_verify(&user.email, &user.uuid).await {
                error!("Error sending welcome email: {e:#?}");
            }
            user.last_verifying_at = Some(user.created_at);
        } else if let Err(e) = mail::send_welcome(&user.email).await {
            error!("Error sending welcome email: {e:#?}");
        }

        if email_verified && is_email_2fa_required(data.organization_user_id, &conn).await {
            email::activate_email_2fa(&user, &conn).await.ok();
        }
    }

    user.save(&conn).await?;

    // accept any open emergency access invitations
    if !CONFIG.mail_enabled() && CONFIG.emergency_access_allowed() {
        for mut emergency_invite in EmergencyAccess::find_all_invited_by_grantee_email(&user.email, &conn).await {
            emergency_invite.accept_invite(&user.uuid, &user.email, &conn).await.ok();
        }
    }

    Ok(Json(json!({
      "object": "registerFinish",
    })))
}

/// Upstream's acceptance of every invitation waiting for an account, on a
/// server that sends no email. Keykeeper: the server accepted these, not the
/// person, so two-step login for admins doesn't count them until they do.
async fn accept_invitations_for_them(user_id: &UserId, conn: &DbConn) -> EmptyResult {
    let invited: Vec<MembershipId> = Membership::find_any_state_by_user(user_id, conn)
        .await
        .into_iter()
        .filter(|m| m.status == crate::db::models::MembershipStatus::Invited as i32)
        .map(|m| m.uuid)
        .collect();
    Membership::accept_user_invitations(user_id, conn).await?;
    super::keykeeper_two_step::accepted_without_them(invited, conn).await
}

#[post("/accounts/set-password", data = "<data>")]
async fn post_set_password(data: Json<SetPasswordData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: SetPasswordData = data.into_inner();
    let mut user = headers.user;

    if user.private_key.is_some() || !user.password_hash.is_empty() {
        err!("Account already initialized, cannot set password")
    }

    // Check against the password hint setting here so if it fails,
    // the user can retry without losing their invitation below.
    let password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(password_hint.as_ref())?;

    set_kdf_data(&mut user, &data.kdf)?;

    user.set_password(
        &data.master_password_hash,
        Some(data.key),
        false,
        Some(vec![String::from("revision_date")]), // We need to allow revision-date to use the old security_timestamp
        &conn,
    )
    .await?;
    user.password_hint = password_hint;

    if let Some(keys) = data.keys {
        user.private_key = Some(keys.encrypted_private_key);
        user.public_key = Some(keys.public_key);
    }

    // Keykeeper: an invitation to an organization that enrolls everyone in
    // account recovery isn't accepted here, without the recovery key: the
    // app's enrollment request, which follows at once, accepts it with the key
    // (organizations.rs, put_reset_password_enrollment). Until then the
    // person waits, invited, and nobody can confirm them. Account recovery
    // needs a server that sends email.
    if let Some(identifier) = data.org_identifier
        && identifier != crate::sso::FAKE_SSO_IDENTIFIER
        && identifier != crate::api::admin::FAKE_ADMIN_UUID
    {
        // Keykeeper: the organization's own SSO identifier, or its id.
        let org = match crate::api::core::keykeeper_sso::org_for_identifier(&identifier, &conn).await {
            Some(org) => Some(org),
            None => Organization::find_by_uuid(&identifier.into(), &conn).await,
        };
        let Some(org) = org else {
            err!("Failed to retrieve the associated organization")
        };

        let Some(membership) = Membership::find_by_user_and_org(&user.uuid, &org.uuid, &conn).await else {
            err!("Failed to retrieve the invitation")
        };

        let waits_for_enrollment = CONFIG.mail_enabled()
            && OrgPolicy::org_is_reset_password_auto_enroll(&org.uuid, &conn).await
            && !crate::db::models::MspStaff::is_staff_anywhere(&user.uuid, &conn).await;
        if !waits_for_enrollment {
            accept_org_invite(&user, membership, None, true, &conn).await?;
        }
    }

    if CONFIG.mail_enabled() {
        mail::send_welcome(&user.email.to_lowercase()).await?;
    } else {
        accept_invitations_for_them(&user.uuid, &conn).await?;
    }

    log_user_event(EventType::UserChangedPassword, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await;

    user.save(&conn).await?;

    Ok(Json(json!({
      "object": "set-password",
    })))
}

#[get("/accounts/profile")]
async fn profile(headers: Headers, conn: DbConn) -> Json<Value> {
    Json(headers.user.to_json(&conn).await)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileData {
    // culture: String, // Ignored, always use en-US
    name: String,
}

#[put("/accounts/profile", data = "<data>")]
async fn put_profile(data: Json<ProfileData>, headers: Headers, conn: DbConn) -> JsonResult {
    post_profile(data, headers, conn).await
}

#[post("/accounts/profile", data = "<data>")]
async fn post_profile(data: Json<ProfileData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: ProfileData = data.into_inner();

    // Check if the length of the username exceeds 50 characters (Same is Upstream Bitwarden)
    // This also prevents issues with very long usernames causing to large JWT's. See #2419
    if data.name.len() > 50 {
        err!("The field Name must be a string with a maximum length of 50.");
    }

    let mut user = headers.user;
    user.name = data.name;

    user.save(&conn).await?;
    Ok(Json(user.to_json(&conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AvatarData {
    avatar_color: Option<String>,
}

#[put("/accounts/avatar", data = "<data>")]
async fn put_avatar(data: Json<AvatarData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: AvatarData = data.into_inner();

    // It looks like it only supports the 6 hex color format.
    // If you try to add the short value it will not show that color.
    // Check and force 7 chars, including the #.
    if let Some(color) = &data.avatar_color
        && color.len() != 7
    {
        err!("The field AvatarColor must be a HTML/Hex color code with a length of 7 characters")
    }

    let mut user = headers.user;
    user.avatar_color = data.avatar_color;

    user.save(&conn).await?;
    Ok(Json(user.to_json(&conn).await))
}

#[get("/users/<user_id>/public-key")]
async fn get_public_keys(user_id: UserId, _headers: Headers, conn: DbConn) -> JsonResult {
    let user = match User::find_by_uuid(&user_id, &conn).await {
        Some(user) if user.public_key.is_some() => user,
        Some(_) => err_code!("User has no public_key", Status::NotFound.code),
        None => err_code!("User doesn't exist", Status::NotFound.code),
    };

    Ok(Json(json!({
        "userId": user.uuid,
        "publicKey": user.public_key,
        "object":"userKey"
    })))
}

#[get("/accounts/keys")]
fn get_keys(headers: Headers) -> JsonResult {
    let user = headers.user;

    // The SDK reads a 404 as the user having no key pair yet
    if user.private_key.is_none() || user.public_key.is_none() {
        err_code!("User has no key pair", Status::NotFound.code)
    }

    Ok(Json(json!({
        "key": (!user.akey.is_empty()).then_some(&user.akey),
        "publicKey": user.public_key,
        "privateKey": user.private_key,
        "accountKeys": user.account_keys_json(),
        "object": "keys",
    })))
}

#[post("/accounts/keys", data = "<data>")]
async fn post_keys(data: Json<KeysData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: KeysData = data.into_inner();

    let mut user = headers.user;

    if user.private_key.is_some() || user.public_key.is_some() {
        err!("User has existing keypair")
    }

    user.private_key = Some(data.encrypted_private_key);
    user.public_key = Some(data.public_key);

    user.save(&conn).await?;

    Ok(Json(json!({
        "privateKey": user.private_key,
        "publicKey": user.public_key,
        "object":"keys"
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePassData {
    master_password_hash: String,
    master_password_hint: Option<String>,
    authentication_data: Option<AuthenticationData>,
    unlock_data: Option<UnlockData>,

    // Outdated values, might still be used by older clients
    new_master_password_hash: Option<String>,
    key: Option<String>,
}

#[post("/accounts/password", data = "<data>")]
async fn post_password(data: Json<ChangePassData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: ChangePassData = data.into_inner();
    let user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    log_user_event(EventType::UserChangedPassword, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await;

    let (new_master_password_hash, new_key) =
        if let (Some(unlock_data), Some(authentication_data)) = (data.unlock_data, data.authentication_data) {
            if authentication_data.kdf != unlock_data.kdf {
                err!("KDF settings must be equal for authentication and unlock")
            }
            // Keykeeper: settings an account can have, as on every path that takes them.
            authentication_data.kdf.check()?;

            if user.email != authentication_data.salt || user.email != unlock_data.salt {
                err!("Invalid master password salt")
            }

            (authentication_data.master_password_authentication_hash, unlock_data.master_key_wrapped_user_key)
        } else if let (Some(new_master_password_hash), Some(new_key)) = (data.new_master_password_hash, data.key) {
            (new_master_password_hash, new_key)
        } else {
            err!("Invalid request!")
        };

    let mut user = user;

    user.password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(user.password_hint.as_ref())?;

    user.set_password(
        &new_master_password_hash,
        Some(new_key),
        true,
        Some(vec![
            String::from("post_rotatekey"),
            String::from("get_contacts"),
            String::from("get_public_keys"),
            String::from("get_api_webauthn"),
        ]),
        &conn,
    )
    .await?;

    let save_result = user.save(&conn).await;

    // Prevent logging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
    nt.send_logout(&user, Some(&headers.device), &conn).await;

    save_result
}

/// Keykeeper: the KDF settings an account can have, the same bounds PassBundle's apps accept (passbundle-apps
/// `core/src/kdf.rs`; docs/core.md, "KDF settings are checked before anything is derived") and the web vault's KDF
/// form offers. Upstream takes PBKDF2 from 100,000 iterations with no maximum, and Argon2id from 1 iteration and
/// 15 MiB, so an account could be set to something the apps refuse (DESIGN.md, "KDF settings an account can have").
const PBKDF2_ITERATIONS: std::ops::RangeInclusive<i32> = 600_000..=2_000_000;
const ARGON2ID_ITERATIONS: std::ops::RangeInclusive<i32> = 2..=10;
const ARGON2ID_MEMORY_MIB: std::ops::RangeInclusive<i32> = 16..=1024;
const ARGON2ID_PARALLELISM: std::ops::RangeInclusive<i32> = 1..=16;

/// Keykeeper: the one check of the KDF settings a client sends, on every path that takes them: registration,
/// setting a first password, changing the KDF or the master password, emergency access takeover, account
/// recovery, and key rotation. The messages are the apps' own.
pub(super) fn check_kdf(kdf: i32, iterations: i32, memory: Option<i32>, parallelism: Option<i32>) -> EmptyResult {
    if kdf == UserKdfType::Pbkdf2 as i32 {
        if iterations < *PBKDF2_ITERATIONS.start() {
            err!("PBKDF2 needs at least 600,000 iterations.")
        }
        if iterations > *PBKDF2_ITERATIONS.end() {
            err!("PBKDF2 allows at most 2,000,000 iterations.")
        }
    } else if kdf == UserKdfType::Argon2id as i32 {
        if !ARGON2ID_ITERATIONS.contains(&iterations) {
            err!("Argon2id needs 2 to 10 iterations.")
        }
        let Some(memory) = memory else {
            err!("Argon2 memory parameter is required.")
        };
        if !ARGON2ID_MEMORY_MIB.contains(&memory) {
            err!("Argon2id needs 16 to 1,024 MiB of memory.")
        }
        let Some(parallelism) = parallelism else {
            err!("Argon2 parallelism parameter is required.")
        };
        if !ARGON2ID_PARALLELISM.contains(&parallelism) {
            err!("Argon2id needs a parallelism of 1 to 16.")
        }
    } else {
        err!("Unknown KDF type.")
    }
    Ok(())
}

fn set_kdf_data(user: &mut User, data: &KDFData) -> EmptyResult {
    data.check()?;

    if data.kdf == UserKdfType::Argon2id as i32 {
        user.client_kdf_memory = data.kdf_memory;
        user.client_kdf_parallelism = data.kdf_parallelism;
    } else {
        user.client_kdf_memory = None;
        user.client_kdf_parallelism = None;
    }
    user.client_kdf_iter = data.kdf_iterations;
    user.client_kdf_type = data.kdf;

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticationData {
    #[serde(alias = "Salt")]
    salt: String,
    #[serde(alias = "Kdf")]
    pub(super) kdf: KDFData,
    #[serde(alias = "MasterPasswordAuthenticationHash")]
    pub(super) master_password_authentication_hash: String,
}

impl AuthenticationData {
    pub(super) fn check(&self, user: &User, unlock: &UnlockData) -> EmptyResult {
        if self.kdf != unlock.kdf {
            err!("KDF settings must be equal for authentication and unlock")
        }
        // Keykeeper: changing the KDF, emergency access takeover, and account recovery all check here.
        self.kdf.check()?;

        if self.salt != user.master_password_salt() || self.salt != unlock.salt {
            err!("Invalid master password salt")
        }

        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UnlockData {
    salt: String,
    kdf: KDFData,
    pub(super) master_key_wrapped_user_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeKdfData {
    authentication_data: AuthenticationData,
    unlock_data: UnlockData,
    master_password_hash: String,
}

#[post("/accounts/kdf", data = "<data>")]
async fn post_kdf(data: Json<ChangeKdfData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: ChangeKdfData = data.into_inner();

    if !headers.user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    data.authentication_data.check(&headers.user, &data.unlock_data)?;

    let mut user = headers.user;

    set_kdf_data(&mut user, &data.unlock_data.kdf)?;

    user.set_password(
        &data.authentication_data.master_password_authentication_hash,
        Some(data.unlock_data.master_key_wrapped_user_key),
        true,
        None,
        &conn,
    )
    .await?;
    let save_result = user.save(&conn).await;

    nt.send_logout(&user, Some(&headers.device), &conn).await;

    save_result
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateFolderData {
    // There is a bug in 2024.3.x which adds a `null` item.
    // To bypass this we allow a Option here, but skip it during the updates
    // See: https://github.com/bitwarden/clients/issues/8453
    #[serde(default, deserialize_with = "deser_opt_nonempty_str")]
    id: Option<FolderId>,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateEmergencyAccessData {
    id: EmergencyAccessId,
    key_encrypted: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateResetPasswordData {
    organization_id: OrganizationId,
    reset_password_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyData {
    account_unlock_data: RotateAccountUnlockData,
    account_keys: RotateAccountKeys,
    account_data: RotateAccountData,
    old_master_key_authentication_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountUnlockData {
    emergency_access_unlock_data: Vec<UpdateEmergencyAccessData>,
    master_password_unlock_data: MasterPasswordUnlockData,
    organization_account_recovery_unlock_data: Vec<UpdateResetPasswordData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MasterPasswordUnlockData {
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_parallelism: Option<i32>,
    kdf_memory: Option<i32>,
    email: String,
    master_key_authentication_hash: String,
    master_key_encrypted_user_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountKeys {
    user_key_encrypted_account_private_key: String,
    account_public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountData {
    ciphers: Vec<CipherData>,
    folders: Vec<UpdateFolderData>,
    sends: Vec<SendData>,
}

fn validate_keydata(
    data: &KeyData,
    existing_ciphers: &[Cipher],
    existing_folders: &[Folder],
    existing_emergency_access: &[EmergencyAccess],
    existing_memberships: &[Membership],
    existing_sends: &[Send],
    user: &User,
) -> EmptyResult {
    // Keykeeper: settings an account can have, as on every path that takes them.
    let unlock = &data.account_unlock_data.master_password_unlock_data;
    check_kdf(unlock.kdf_type, unlock.kdf_iterations, unlock.kdf_memory, unlock.kdf_parallelism)?;

    if user.client_kdf_type != data.account_unlock_data.master_password_unlock_data.kdf_type
        || user.client_kdf_iter != data.account_unlock_data.master_password_unlock_data.kdf_iterations
        || user.client_kdf_memory != data.account_unlock_data.master_password_unlock_data.kdf_memory
        || user.client_kdf_parallelism != data.account_unlock_data.master_password_unlock_data.kdf_parallelism
        || user.email != data.account_unlock_data.master_password_unlock_data.email
    {
        err!("Changing the kdf variant or email is not supported during key rotation");
    }
    if user.public_key.as_ref() != Some(&data.account_keys.account_public_key) {
        err!("Changing the asymmetric keypair is not possible during key rotation")
    }

    // Check that we're correctly rotating all the user's ciphers
    let existing_cipher_ids = existing_ciphers.iter().map(|c| &c.uuid).collect::<HashSet<&CipherId>>();
    let provided_cipher_ids = data
        .account_data
        .ciphers
        .iter()
        .filter(|c| c.organization_id.is_none())
        .filter_map(|c| c.id.as_ref())
        .collect::<HashSet<&CipherId>>();
    if !provided_cipher_ids.is_superset(&existing_cipher_ids) {
        err!("All existing ciphers must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's folders
    let existing_folder_ids = existing_folders.iter().map(|f| &f.uuid).collect::<HashSet<&FolderId>>();
    let provided_folder_ids =
        data.account_data.folders.iter().filter_map(|f| f.id.as_ref()).collect::<HashSet<&FolderId>>();
    if !provided_folder_ids.is_superset(&existing_folder_ids) {
        err!("All existing folders must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's emergency access keys
    let existing_emergency_access_ids =
        existing_emergency_access.iter().map(|ea| &ea.uuid).collect::<HashSet<&EmergencyAccessId>>();
    let provided_emergency_access_ids = data
        .account_unlock_data
        .emergency_access_unlock_data
        .iter()
        .map(|ea| &ea.id)
        .collect::<HashSet<&EmergencyAccessId>>();
    if !provided_emergency_access_ids.is_superset(&existing_emergency_access_ids) {
        err!("All existing emergency access keys must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's reset password keys
    let existing_reset_password_ids =
        existing_memberships.iter().map(|m| &m.org_uuid).collect::<HashSet<&OrganizationId>>();
    let provided_reset_password_ids = data
        .account_unlock_data
        .organization_account_recovery_unlock_data
        .iter()
        .map(|rp| &rp.organization_id)
        .collect::<HashSet<&OrganizationId>>();
    if !provided_reset_password_ids.is_superset(&existing_reset_password_ids) {
        err!("All existing reset password keys must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's sends
    let existing_send_ids = existing_sends.iter().map(|s| &s.uuid).collect::<HashSet<&SendId>>();
    let provided_send_ids = data.account_data.sends.iter().filter_map(|s| s.id.as_ref()).collect::<HashSet<&SendId>>();
    if !provided_send_ids.is_superset(&existing_send_ids) {
        err!("All existing sends must be included in the rotation")
    }

    Ok(())
}

#[post("/accounts/key-management/rotate-user-account-keys", data = "<data>")]
async fn post_rotatekey(data: Json<KeyData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    // TODO: See if we can wrap everything within a SQL Transaction. If something fails it should revert everything.
    let data: KeyData = data.into_inner();

    if !headers.user.check_valid_password(&data.old_master_key_authentication_hash) {
        err!("Invalid password")
    }

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_cipher_data(&data.account_data.ciphers)?;

    let user_id = &headers.user.uuid;

    // TODO: Ideally we'd do everything after this point in a single transaction.

    let mut existing_ciphers = Cipher::find_owned_by_user(user_id, &conn).await;
    let mut existing_folders = Folder::find_by_user(user_id, &conn).await;
    let mut existing_emergency_access = EmergencyAccess::find_all_confirmed_by_grantor_uuid(user_id, &conn).await;
    let mut existing_memberships = Membership::find_by_user(user_id, &conn).await;
    // We only rotate the reset password key if it is set.
    existing_memberships.retain(|m| m.reset_password_key.is_some());
    let mut existing_sends = Send::find_by_user(user_id, &conn).await;

    validate_keydata(
        &data,
        &existing_ciphers,
        &existing_folders,
        &existing_emergency_access,
        &existing_memberships,
        &existing_sends,
        &headers.user,
    )?;

    // Update folder data
    for folder_data in data.account_data.folders {
        // Skip `null` folder id entries.
        // See: https://github.com/bitwarden/clients/issues/8453
        if let Some(folder_id) = folder_data.id {
            let Some(saved_folder) = existing_folders.iter_mut().find(|f| f.uuid == folder_id) else {
                err!("Folder doesn't exist")
            };

            saved_folder.name = folder_data.name;
            saved_folder.save(&conn).await?;
        }
    }

    // Update emergency access data
    for emergency_access_data in data.account_unlock_data.emergency_access_unlock_data {
        let Some(saved_emergency_access) =
            existing_emergency_access.iter_mut().find(|ea| ea.uuid == emergency_access_data.id)
        else {
            err!("Emergency access doesn't exist or is not owned by the user")
        };

        saved_emergency_access.key_encrypted = Some(emergency_access_data.key_encrypted);
        saved_emergency_access.save(&conn).await?;
    }

    // Update reset password data
    for reset_password_data in data.account_unlock_data.organization_account_recovery_unlock_data {
        let Some(membership) =
            existing_memberships.iter_mut().find(|m| m.org_uuid == reset_password_data.organization_id)
        else {
            err!("Reset password doesn't exist")
        };

        membership.reset_password_key = Some(reset_password_data.reset_password_key);
        membership.save(&conn).await?;
    }

    // Update send data
    for send_data in data.account_data.sends {
        let Some(send) = send_data.id.as_ref().and_then(|id| existing_sends.iter_mut().find(|s| &s.uuid == id)) else {
            err!("Send doesn't exist")
        };

        // Like upstream, only the key changes on rotation
        send.akey = send_data.key;
        send.save(&conn).await?;
    }

    // Update cipher data
    for cipher_data in data.account_data.ciphers {
        if cipher_data.organization_id.is_none() {
            let Some(saved_cipher) =
                cipher_data.id.as_ref().and_then(|id| existing_ciphers.iter_mut().find(|c| &c.uuid == id))
            else {
                err!("Cipher doesn't exist")
            };

            // Prevent triggering cipher updates via WebSockets by settings UpdateType::None
            // The user sessions are invalidated because all the ciphers were re-encrypted and thus triggering an update could cause issues.
            // We force the users to logout after the user has been saved to try and prevent these issues.
            update_cipher_from_data(
                saved_cipher,
                cipher_data,
                &headers,
                None,
                &conn,
                &nt,
                UpdateType::None,
                ItemSave::Rotation,
            )
            .await?;
        }
    }

    // Update user data
    let mut user = headers.user;

    user.private_key = Some(data.account_keys.user_key_encrypted_account_private_key);
    user.set_password(
        &data.account_unlock_data.master_password_unlock_data.master_key_authentication_hash,
        Some(data.account_unlock_data.master_password_unlock_data.master_key_encrypted_user_key),
        true,
        None,
        &conn,
    )
    .await?;

    let save_result = user.save(&conn).await;

    // Keykeeper: settings saved with the old key can't be read with the new
    // one; the next app to save them writes them anew (keykeeper_user_settings).
    // Only once the new key is saved, and never failing the rotation.
    if save_result.is_ok()
        && let Err(e) = UserSettings::delete_by_user(&user.uuid, &conn).await
    {
        warn!("Couldn't forget settings after a key rotation: {e:#?}");
    }
    // Keykeeper: and so can't the past versions of their own items
    // (keykeeper_cipher_versions). Organizations' items keep theirs.
    if save_result.is_ok()
        && let Err(e) = CipherVersion::delete_all_by_owner(&user.uuid, &conn).await
    {
        warn!("Couldn't forget earlier versions of items after a key rotation: {e:#?}");
    }

    // Prevent logging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
    nt.send_logout(&user, Some(&headers.device), &conn).await;

    save_result
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyIdData {
    user_key_id: KeyId,
}

#[post("/accounts/key-management/user-key-id", data = "<data>")]
async fn post_user_key(data: Json<KeyIdData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let mut user = headers.user;
    if user.key_id.is_some() {
        err_code!("Unexpected data", Status::UnprocessableEntity.code);
    }

    user.key_id = Some(data.into_inner().user_key_id);
    user.save(&conn).await
}

#[post("/accounts/security-stamp", data = "<data>")]
async fn post_sstamp(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: PasswordOrOtpData = data.into_inner();
    let mut user = headers.user;

    data.validate(&user, true, &conn).await?;

    user.reset_security_stamp(&conn).await?;
    let save_result = user.save(&conn).await;

    nt.send_logout(&user, None, &conn).await;

    Device::delete_all_by_user(&user.uuid, &conn).await?;

    save_result
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailTokenData {
    master_password_hash: String,
    new_email: String,
}

#[post("/accounts/email-token", data = "<data>")]
async fn post_email_token(data: Json<EmailTokenData>, headers: Headers, conn: DbConn) -> EmptyResult {
    if !CONFIG.email_change_allowed() {
        err!("Email change is not allowed.");
    }

    let data: EmailTokenData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    if let Some(existing_user) = User::find_by_mail(&data.new_email, &conn).await {
        if CONFIG.mail_enabled() {
            // check if existing_user has already registered
            if existing_user.password_hash.is_empty() {
                // inform an invited user about how to delete their temporary account if the
                // request was done intentionally and they want to update their mail address
                if let Err(e) = mail::send_change_email_invited(&data.new_email, &user.email).await {
                    error!("Error sending change-email-invited email: {e:#?}");
                }
            } else {
                // inform existing user about the failed attempt to change their mail address
                if let Err(e) = mail::send_change_email_existing(&data.new_email, &user.email).await {
                    error!("Error sending change-email-existing email: {e:#?}");
                }
            }
        }
        err!("Email already in use");
    }

    if !CONFIG.is_email_domain_allowed(&data.new_email) {
        err!("Email domain not allowed");
    }

    let token = crypto::generate_email_token(6);

    if CONFIG.mail_enabled() {
        if let Err(e) = mail::send_change_email(&data.new_email, &token).await {
            error!("Error sending change-email email: {e:#?}");
        }
    } else {
        debug!(
            "Email change request for user ({}) to email ({}) with token ({token})",
            user.uuid,
            data.new_email.escape_debug()
        );
    }

    user.email_new = Some(data.new_email);
    user.email_new_token = Some(token);
    user.save(&conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeEmailData {
    master_password_hash: String,
    new_email: String,

    key: String,
    new_master_password_hash: String,
    token: NumberOrString,
}

#[post("/accounts/email", data = "<data>")]
async fn post_email(data: Json<ChangeEmailData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    if !CONFIG.email_change_allowed() {
        err!("Email change is not allowed.");
    }

    let data: ChangeEmailData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    if User::find_by_mail(&data.new_email, &conn).await.is_some() {
        err!("Email already in use");
    }

    if let Some(ref val) = user.email_new {
        if val != &data.new_email {
            err!("Email change mismatch");
        }
    } else {
        err!("No email change pending")
    }

    if CONFIG.mail_enabled() {
        // Only check the token if we sent out an email...
        if let Some(ref val) = user.email_new_token {
            if *val != data.token.into_string() {
                err!("Token mismatch");
            }
        } else {
            err!("No email change pending")
        }
        user.verified_at = Some(Utc::now().naive_utc());
    } else {
        user.verified_at = None;
    }

    user.email = data.new_email;
    user.email_new = None;
    user.email_new_token = None;

    user.set_password(&data.new_master_password_hash, Some(data.key), true, None, &conn).await?;

    let save_result = user.save(&conn).await;

    nt.send_logout(&user, None, &conn).await;

    save_result
}

#[post("/accounts/verify-email")]
async fn post_verify_email(headers: Headers) -> EmptyResult {
    let user = headers.user;

    if !CONFIG.mail_enabled() {
        err!("Cannot verify email address");
    }

    if let Err(e) = mail::send_verify_email(&user.email, &user.uuid).await {
        error!("Error sending verify_email email: {e:#?}");
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyEmailTokenData {
    user_id: UserId,
    token: String,
}

#[post("/accounts/verify-email-token", data = "<data>")]
async fn post_verify_email_token(data: Json<VerifyEmailTokenData>, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: VerifyEmailTokenData = data.into_inner();

    let Some(mut user) = User::find_by_uuid(&data.user_id, &conn).await else {
        err!("User doesn't exist")
    };

    let Ok(claims) = decode_verify_email(&data.token) else {
        err!("Invalid claim")
    };
    if claims.sub != *user.uuid {
        err!("Invalid claim");
    }
    user.verified_at = Some(Utc::now().naive_utc());
    user.last_verifying_at = None;
    user.login_verify_count = 0;
    // Keykeeper: saving moves the account's revision date, and the person's
    // open apps are told to sync, so a vault that's open (on this device or
    // another) learns the address is verified and stops asking for it.
    match user.save(&conn).await {
        Ok(()) => nt.send_user_update(UpdateType::SyncSettings, &user, None, &conn).await,
        Err(e) => error!("Error saving email verification: {e:#?}"),
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteRecoverData {
    email: String,
}

#[post("/accounts/delete-recover", data = "<data>")]
async fn post_delete_recover(data: Json<DeleteRecoverData>, ip: ClientIp, conn: DbConn) -> EmptyResult {
    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;

    let data: DeleteRecoverData = data.into_inner();

    if CONFIG.mail_enabled() {
        if let Some(user) = User::find_by_mail(&data.email, &conn).await
            && let Err(e) = mail::send_delete_account(&user.email, &user.uuid).await
        {
            error!("Error sending delete account email: {e:#?}");
        }
        Ok(())
    } else {
        // We don't support sending emails, but we shouldn't allow anybody
        // to delete accounts without at least logging in... And if the user
        // cannot remember their password then they will need to contact
        // the administrator to delete it...
        err!("Please contact the administrator to delete your account");
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteRecoverTokenData {
    user_id: UserId,
    token: String,
}

#[post("/accounts/delete-recover-token", data = "<data>")]
async fn post_delete_recover_token(data: Json<DeleteRecoverTokenData>, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: DeleteRecoverTokenData = data.into_inner();

    let Ok(claims) = decode_delete(&data.token) else {
        err!("Invalid claim")
    };

    let Some(user) = User::find_by_uuid(&data.user_id, &conn).await else {
        err!("User doesn't exist")
    };

    if claims.sub != *user.uuid {
        err!("Invalid claim");
    }

    // The devices are deleted together with the user, so check for push devices beforehand
    let has_push_device = CONFIG.push_enabled() && Device::check_user_has_push_device(&user.uuid, &conn).await;
    user.delete(&conn).await?;

    nt.send_logout(&user, None, &conn).await;
    if has_push_device {
        push_logout_to_relay(&user, None);
    }
    Ok(())
}

#[post("/accounts/delete", data = "<data>")]
async fn post_delete_account(
    data: Json<PasswordOrOtpData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    delete_account(data, headers, conn, nt).await
}

#[delete("/accounts", data = "<data>")]
async fn delete_account(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, true, &conn).await?;

    // The devices are deleted together with the user, so check for push devices beforehand
    let has_push_device = CONFIG.push_enabled() && Device::check_user_has_push_device(&user.uuid, &conn).await;
    user.delete(&conn).await?;

    nt.send_logout(&user, None, &conn).await;
    if has_push_device {
        push_logout_to_relay(&user, None);
    }
    Ok(())
}

#[expect(clippy::needless_pass_by_value, reason = "Not beneficial for Headers")]
#[get("/accounts/revision-date")]
fn revision_date(headers: Headers) -> JsonResult {
    let revision_date = headers.user.updated_at.and_utc().timestamp_millis();
    Ok(Json(json!(revision_date)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordHintData {
    email: String,
}

#[post("/accounts/password-hint", data = "<data>")]
async fn password_hint(data: Json<PasswordHintData>, ip: ClientIp, conn: DbConn) -> EmptyResult {
    const NO_HINT: &str = "Sorry, you have no password hint...";

    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;

    if !CONFIG.password_hints_allowed() || (!CONFIG.mail_enabled() && !CONFIG.show_password_hint()) {
        err!("This server is not configured to provide password hints.");
    }

    let data: PasswordHintData = data.into_inner();
    let email = &data.email;

    match User::find_by_mail(email, &conn).await {
        None => {
            // To prevent user enumeration, act as if the user exists.
            if CONFIG.mail_enabled() {
                // There is still a timing side channel here in that the code
                // paths that send mail take noticeably longer than ones that
                // don't. Add a randomized sleep to mitigate this somewhat.
                use rand::{RngExt, rngs::SmallRng};
                let mut rng: SmallRng = rand::make_rng();
                let sleep_ms: u64 = rng.random_range(900..=1100);
                tokio::time::sleep(tokio::time::Duration::from_millis(sleep_ms)).await;
                Ok(())
            } else {
                err!(NO_HINT);
            }
        }
        Some(user) => {
            let hint: Option<String> = user.password_hint;
            if CONFIG.mail_enabled() {
                mail::send_password_hint(email, hint).await?;
                Ok(())
            } else if let Some(hint) = hint {
                err_silent!(format!("Your password hint is: {hint}"));
            } else {
                err!(NO_HINT);
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginData {
    email: String,
}

/// The KDF settings an unknown email can get, as (type, iterations, memory, parallelism). The default is in it
/// twice to give it more weight, as upstream's list has it. Keykeeper: upstream's list also has PBKDF2 at 5,000 and
/// 100,000 iterations, for its legacy accounts. A PassBundle account can't have either (`check_kdf` refuses PBKDF2
/// under 600,000), so that answer would say the email has no account, and PassBundle's apps refuse PBKDF2 under
/// 600,000, so they'd say an unknown email's settings are too weak instead of a wrong email or password. Every
/// setting here is one an account could have that the apps accept (DESIGN.md, "Unknown emails at prelogin").
const UNKNOWN_EMAIL_KDF_SETTINGS: [(i32, i32, Option<i32>, Option<i32>); 6] = [
    (User::CLIENT_KDF_TYPE_DEFAULT, User::CLIENT_KDF_ITER_DEFAULT, None, None),
    (User::CLIENT_KDF_TYPE_DEFAULT, User::CLIENT_KDF_ITER_DEFAULT, None, None),
    (UserKdfType::Pbkdf2 as i32, 800_000, None, None),
    (UserKdfType::Pbkdf2 as i32, 1_000_000, None, None),
    (UserKdfType::Argon2id as i32, 3, Some(64), Some(4)),
    (UserKdfType::Argon2id as i32, 6, Some(32), Some(4)),
];

/// Like upstream, an unknown email gets KDF settings picked from a list of common ones by a keyed hash of the email,
/// so they stay the same between requests. The salt stays null, as for existing users.
fn unknown_email_kdf(email: &str) -> (i32, i32, Option<i32>, Option<i32>) {
    UNKNOWN_EMAIL_KDF_SETTINGS[crate::auth::prelogin_kdf_index(email, UNKNOWN_EMAIL_KDF_SETTINGS.len())]
}

pub async fn prelogin(data: Json<PreloginData>, ip: ClientIp, conn: DbConn) -> JsonResult {
    // Keykeeper: an address's login allowance, not the shared one (ratelimit.rs).
    crate::ratelimit::check_limit_prelogin(&ip.ip)?;

    let data: PreloginData = data.into_inner();
    // Normalized once, so the lookup and the settings for an unknown email use the same value
    let email = data.email.trim().to_lowercase();

    let (kdf_type, kdf_iter, kdf_mem, kdf_para) = match User::find_by_mail(&email, &conn).await {
        Some(user) => (user.client_kdf_type, user.client_kdf_iter, user.client_kdf_memory, user.client_kdf_parallelism),
        None => unknown_email_kdf(&email),
    };

    Ok(Json(json!({
        "kdf": kdf_type,
        "kdfIterations": kdf_iter,
        "kdfMemory": kdf_mem,
        "kdfParallelism": kdf_para,
        "kdfSettings": {
            "iterations": kdf_iter,
            "kdfType": kdf_type,
            "memory": kdf_mem,
            "parallelism": kdf_para
        },
        "salt": null,
    })))
}

// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/Auth/Models/Request/Accounts/SecretVerificationRequestModel.cs
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretVerificationRequest {
    master_password_hash: String,
}

// Change the KDF Iterations if necessary
pub async fn kdf_upgrade(user: &mut User, pwd_hash: &str, conn: &DbConn) -> ApiResult<()> {
    if user.password_iterations < CONFIG.password_iterations() {
        user.password_iterations = CONFIG.password_iterations();
        user.set_password(pwd_hash, None, false, None, conn).await?;

        if let Err(e) = user.save(conn).await {
            error!("Error updating user: {e:#?}");
        }
    }
    Ok(())
}

#[post("/accounts/verify-password", data = "<data>")]
async fn verify_password(data: Json<SecretVerificationRequest>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: SecretVerificationRequest = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    kdf_upgrade(&mut user, &data.master_password_hash, &conn).await?;

    Ok(Json(master_password_policy(&user, &conn).await))
}

async fn update_api_key(data: Json<PasswordOrOtpData>, rotate: bool, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let mut user = headers.user;

    data.validate(&user, true, &conn).await?;

    if rotate || user.api_key.is_none() {
        user.api_key = Some(crypto::generate_api_key());
        user.save(&conn).await.expect("Error saving API key");
    }

    Ok(Json(json!({
      "apiKey": user.api_key,
      "revisionDate": format_date(&user.updated_at),
      "object": "apiKey",
    })))
}

#[post("/accounts/api-key", data = "<data>")]
async fn post_api_key(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    update_api_key(data, false, headers, conn).await
}

#[post("/accounts/rotate-api-key", data = "<data>")]
async fn rotate_api_key(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    update_api_key(data, true, headers, conn).await
}

#[get("/devices/knowndevice")]
async fn get_known_device(device: KnownDevice, conn: DbConn) -> JsonResult {
    let result = if let Some(user) = User::find_by_mail(&device.email, &conn).await {
        Device::find_by_uuid_and_user(&device.uuid, &user.uuid, &conn).await.is_some()
    } else {
        false
    };
    Ok(Json(json!(result)))
}

struct KnownDevice {
    email: String,
    uuid: DeviceId,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for KnownDevice {
    type Error = &'static str;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let email = if let Some(email_b64) = req.headers().get_one("X-Request-Email") {
            // Bitwarden seems to send padded Base64 strings since 2026.2.1
            // Since these values are not streamed and Headers are always split by newlines
            // we can safely ignore padding here and remove any '=' appended.
            let email_b64 = email_b64.trim_end_matches('=');

            let Ok(email_bytes) = data_encoding::BASE64URL_NOPAD.decode(email_b64.as_bytes()) else {
                return Outcome::Error((Status::BadRequest, "X-Request-Email value failed to decode as base64url"));
            };
            match String::from_utf8(email_bytes) {
                Ok(email) => email,
                Err(_) => {
                    return Outcome::Error((Status::BadRequest, "X-Request-Email value failed to decode as UTF-8"));
                }
            }
        } else {
            return Outcome::Error((Status::BadRequest, "X-Request-Email value is required"));
        };

        let uuid = if let Some(uuid) = req.headers().get_one("X-Device-Identifier") {
            uuid.to_owned().into()
        } else {
            return Outcome::Error((Status::BadRequest, "X-Device-Identifier value is required"));
        };

        Outcome::Success(KnownDevice {
            email,
            uuid,
        })
    }
}

#[get("/devices")]
async fn get_all_devices(headers: Headers, conn: DbConn) -> JsonResult {
    let devices = Device::find_with_auth_request_by_user(&headers.user.uuid, &conn).await;
    let devices = devices.iter().map(DeviceWithAuthRequest::to_json).collect::<Vec<Value>>();

    Ok(Json(json!({
        "data": devices,
        "continuationToken": null,
        "object": "list"
    })))
}

#[get("/devices/identifier/<device_id>")]
async fn get_device(device_id: DeviceId, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(device) = Device::find_by_uuid_and_user(&device_id, &headers.user.uuid, &conn).await else {
        err!("No device found");
    };
    Ok(Json(device.to_json()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushToken {
    push_token: String,
}

#[post("/devices/identifier/<device_id>/token", data = "<data>")]
async fn post_device_token(device_id: DeviceId, data: Json<PushToken>, headers: Headers, conn: DbConn) -> EmptyResult {
    put_device_token(device_id, data, headers, conn).await
}

#[put("/devices/identifier/<device_id>/token", data = "<data>")]
async fn put_device_token(device_id: DeviceId, data: Json<PushToken>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data = data.into_inner();
    let token = data.push_token;

    let Some(mut device) = Device::find_by_uuid_and_user(&headers.device.uuid, &headers.user.uuid, &conn).await else {
        err!(format!("Error: device {device_id} should be present before a token can be assigned"))
    };

    // Check if the new token is the same as the registered token
    // Although upstream seems to always register a device on login, we do not.
    // Unless this causes issues, lets keep it this way, else we might need to also register on every login.
    if device.push_token.as_ref() == Some(&token) {
        debug!("Device {device_id} for user {} is already registered and token is identical", headers.user.uuid);
        return Ok(());
    }

    device.push_token = Some(token);
    if let Err(e) = device.save(true, &conn).await {
        err!(format!("An error occurred while trying to save the device push token: {e}"));
    }

    register_push_device(&mut device, &conn).await?;

    Ok(())
}

#[put("/devices/identifier/<device_id>/clear-token")]
async fn put_clear_device_token(device_id: DeviceId, ip: ClientIp, conn: DbConn) -> EmptyResult {
    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;

    // This only clears push token
    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/Controllers/DevicesController.cs#L215
    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/Services/Implementations/DeviceService.cs#L37
    // This is somehow not implemented in any app, added it in case it is required
    // 2025: Also, it looks like it only clears the first found device upstream, which is probably faulty.
    //       This because currently multiple accounts could be on the same device/app and that would cause issues.
    //       Vaultwarden removes the push-token for all devices, but this probably means we should also unregister all these devices.
    if !CONFIG.push_enabled() {
        return Ok(());
    }

    if let Some(device) = Device::find_by_uuid(&device_id, &conn).await {
        Device::clear_push_token_by_uuid(&device_id, &conn).await?;
        unregister_push_device(device.push_uuid.as_ref()).await?;
    }

    Ok(())
}

// On upstream server, both PUT and POST are declared. Implementing the POST method in case it would be useful somewhere
#[post("/devices/identifier/<device_id>/clear-token")]
async fn post_clear_device_token(device_id: DeviceId, ip: ClientIp, conn: DbConn) -> EmptyResult {
    put_clear_device_token(device_id, ip, conn).await
}

#[get("/tasks")]
fn get_tasks(_client_headers: ClientHeaders) -> JsonResult {
    Ok(Json(json!({
        "data": [],
        "object": "list"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthRequestRequest {
    access_code: String,
    device_identifier: DeviceId,
    email: String,
    public_key: String,
    // Not used for now
    // #[serde(alias = "type")]
    // _type: i32,
}

#[post("/auth-requests", data = "<data>")]
async fn post_auth_request(
    data: Json<AuthRequestRequest>,
    client_headers: ClientHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    crate::ratelimit::check_limit_unauthenticated(&client_headers.ip.ip)?;

    let data = data.into_inner();

    // Keykeeper: a request counts against the account's own login limits,
    // as a password would (DESIGN.md, "Login limits"), and holds what a
    // request should: a public key and an access code of sensible sizes.
    crate::ratelimit::check_limit_login_account(&data.email, &client_headers.ip.ip)?;
    if !valid_public_key(&data.public_key) || !valid_access_code(&data.access_code) {
        err!("That sign-in request isn't one PassBundle can use")
    }

    let Some(user) = User::find_by_mail(&data.email, &conn).await else {
        err!("AuthRequest doesn't exist", "User not found")
    };

    // Validate device uuid and type
    let device = match Device::find_by_uuid_and_user(&data.device_identifier, &user.uuid, &conn).await {
        Some(device) if device.atype == client_headers.device_type => device,
        _ => err!("AuthRequest doesn't exist", "Device verification failed"),
    };

    // Keykeeper: a device asks a few times an hour at most, so "Resend"
    // can't keep the account's devices prompting.
    crate::ratelimit::check_limit_auth_request_device(&user.uuid, &device.uuid)?;

    // Keykeeper: a device's new request replaces the one it had waiting
    // ("resend"), and an account has a few waiting at most, so nobody can
    // fill its devices' lists. See DESIGN.md, "Approving a sign-in from
    // another device".
    AuthRequest::delete_pending_from_device(&user.uuid, &device.uuid, &conn).await?;
    let waiting = AuthRequest::find_pending_by_user(&user.uuid, Utc::now().naive_utc(), &conn).await;
    if waiting.len() >= MAX_PENDING_AUTH_REQUESTS {
        err_code!("Too many sign-in requests are waiting for this account. Answer them, or wait 15 minutes.", 429)
    }

    let auth_request = AuthRequest::new(
        user.uuid.clone(),
        data.device_identifier.clone(),
        client_headers.device_type,
        client_headers.ip.ip.to_string(),
        data.access_code,
        data.public_key,
    );
    auth_request.save(&conn).await?;

    nt.send_auth_request(&user.uuid, &auth_request.uuid, &device, &conn).await;

    log_user_event(
        EventType::UserRequestedDeviceApproval,
        &user.uuid,
        client_headers.device_type,
        &client_headers.ip.ip,
        &conn,
    )
    .await;

    Ok(Json(json!({
        "id": auth_request.uuid,
        "publicKey": auth_request.public_key,
        "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
        "requestIpAddress": auth_request.request_ip,
        "key": null,
        "masterPasswordHash": null,
        "creationDate": format_date(&auth_request.creation_date),
        "responseDate": null,
        "requestApproved": false,
        "origin": CONFIG.domain_origin(),
        "object": "auth-request"
    })))
}

#[get("/auth-requests/<auth_request_id>")]
async fn get_auth_request(auth_request_id: AuthRequestId, headers: Headers, conn: DbConn) -> JsonResult {
    // Keykeeper: with the requesting device's identifier, as upstream's
    // answer has it, so the apps prompt once per device (a "Resend" replaces
    // the request in place).
    // Keykeeper: a request that's gone (answered no, replaced, or cleaned up
    // after it expired) and one that has expired but is still kept answer the
    // same: 404, whenever the cleanup runs.
    let Some(auth_request) = AuthRequest::find_by_uuid_and_user(&auth_request_id, &headers.user.uuid, &conn).await
    else {
        err_code!("This sign-in request has expired or was answered", 404)
    };
    if auth_request.is_expired() {
        err_code!("This sign-in request has expired or was answered", 404)
    }

    let response_date_utc = auth_request.response_date.map(|response_date| format_date(&response_date));

    Ok(Json(json!({
        "id": &auth_request_id,
        "publicKey": auth_request.public_key,
        "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
        "requestDeviceIdentifier": auth_request.request_device_identifier,
        "requestIpAddress": auth_request.request_ip,
        "key": auth_request.enc_key,
        // Keykeeper: never a master password hash.
        "masterPasswordHash": null,
        "creationDate": format_date(&auth_request.creation_date),
        "responseDate": response_date_utc,
        "requestApproved": auth_request.approved,
        "origin": CONFIG.domain_origin(),
        "object":"auth-request"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponseRequest {
    device_identifier: DeviceId,
    // Keykeeper: only an approval needs the key; a denial needn't send one.
    // A master password hash, which upstream's clients may send, is ignored.
    key: Option<String>,
    request_approved: bool,
}

#[put("/auth-requests/<auth_request_id>", data = "<data>")]
async fn put_auth_request(
    auth_request_id: AuthRequestId,
    data: Json<AuthResponseRequest>,
    headers: Headers,
    signed_in: SignInMethod,
    conn: DbConn,
    ant: AnonymousNotify<'_>,
    nt: Notify<'_>,
) -> JsonResult {
    let data = data.into_inner();
    // Keykeeper: gone or expired, the same 404, whenever the cleanup runs.
    let Some(mut auth_request) = AuthRequest::find_by_uuid_and_user(&auth_request_id, &headers.user.uuid, &conn).await
    else {
        err_code!("This sign-in request has expired or was answered", 404)
    };

    if headers.device.uuid != data.device_identifier {
        err!("AuthRequest doesn't exist", "Device verification failed")
    }

    if auth_request.is_expired() {
        err_code!("This sign-in request has expired or was answered", 404)
    }

    if auth_request.approved.is_some() {
        err!("An authentication request with the same device already exists")
    }

    // Keykeeper: a device never answers its own request, and only a device
    // that signed in with the master password approves one: not a session
    // that itself came from an approval, an API key, or SSO. The key must
    // be an encrypted string. See DESIGN.md, "Approving a sign-in from
    // another device".
    if auth_request.request_device_identifier == headers.device.uuid {
        err!("A device can't answer its own sign-in request")
    }
    if data.request_approved {
        if !signed_in.is_master_password() {
            err!("Approve sign-ins from a device where you signed in with your master password")
        }
        if !data.key.as_deref().is_some_and(valid_approval_key) {
            err!("That approval doesn't carry a key PassBundle can use")
        }
    }

    let response_date = Utc::now().naive_utc();
    let response_date_utc = format_date(&response_date);

    if data.request_approved {
        auth_request.approved = Some(data.request_approved);
        auth_request.enc_key = data.key;
        // Keykeeper: an approval carries the user key and nothing else: no
        // master password hash is kept, whatever a client sends.
        auth_request.master_password_hash = None;
        auth_request.response_device_id = Some(data.device_identifier.clone());
        auth_request.response_date = Some(response_date);
        auth_request.save(&conn).await?;

        ant.send_auth_response(&auth_request.user_uuid, &auth_request.uuid).await;
        nt.send_auth_response(&auth_request.user_uuid, &auth_request.uuid, &headers.device, &conn).await;

        log_user_event(
            EventType::OrganizationUserApprovedAuthRequest,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await;
    } else {
        // If denied, there's no reason to keep the request
        auth_request.delete(&conn).await?;
        log_user_event(
            EventType::OrganizationUserRejectedAuthRequest,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await;
    }

    Ok(Json(json!({
        "id": &auth_request_id,
        "publicKey": auth_request.public_key,
        "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
        "requestIpAddress": auth_request.request_ip,
        "key": auth_request.enc_key,
        // Keykeeper: never a master password hash.
        "masterPasswordHash": null,
        "creationDate": format_date(&auth_request.creation_date),
        "responseDate": response_date_utc,
        "requestApproved": auth_request.approved,
        "origin": CONFIG.domain_origin(),
        "object":"auth-request"
    })))
}

#[get("/auth-requests/<auth_request_id>/response?<code>")]
async fn get_auth_request_response(
    auth_request_id: AuthRequestId,
    code: &str,
    client_headers: ClientHeaders,
    conn: DbConn,
) -> JsonResult {
    crate::ratelimit::check_limit_unauthenticated(&client_headers.ip.ip)?;

    let Some(auth_request) = AuthRequest::find_by_uuid(&auth_request_id, &conn).await else {
        err!("AuthRequest doesn't exist", "User not found")
    };

    if auth_request.device_type != client_headers.device_type
        || auth_request.request_ip != client_headers.ip.ip.to_string()
        || !auth_request.check_access_code(code)
        // Keykeeper: an expired request is gone.
        || auth_request.is_expired()
    {
        err!("AuthRequest doesn't exist", "Invalid device, IP or code")
    }

    let response_date_utc = auth_request.response_date.map(|response_date| format_date(&response_date));

    Ok(Json(json!({
        "id": &auth_request_id,
        "publicKey": auth_request.public_key,
        "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
        "requestIpAddress": auth_request.request_ip,
        "key": auth_request.enc_key,
        // Keykeeper: never a master password hash.
        "masterPasswordHash": null,
        "creationDate": format_date(&auth_request.creation_date),
        "responseDate": response_date_utc,
        "requestApproved": auth_request.approved,
        "origin": CONFIG.domain_origin(),
        "object":"auth-request"
    })))
}

// Now unused but not yet removed
// cf https://github.com/bitwarden/clients/blob/9b2fbdba1c028bf3394064609630d2ec224baefa/libs/common/src/services/api.service.ts#L245
#[get("/auth-requests")]
async fn get_auth_requests(headers: Headers, conn: DbConn) -> JsonResult {
    get_auth_requests_pending(headers, conn).await
}

#[get("/auth-requests/pending")]
async fn get_auth_requests_pending(headers: Headers, conn: DbConn) -> JsonResult {
    // Keykeeper: the requests still waiting, newest first, from the account's
    // other devices: an expired one is gone, and a device doesn't answer its own.
    let auth_requests = AuthRequest::find_pending_by_user(&headers.user.uuid, Utc::now().naive_utc(), &conn).await;

    Ok(Json(json!({
        "data": auth_requests
            .iter()
            .filter(|request| request.request_device_identifier != headers.device.uuid)
            .map(|request| {
            let response_date_utc = request.response_date.map(|response_date| format_date(&response_date));

            json!({
                "id": request.uuid,
                "publicKey": request.public_key,
                "requestDeviceType": DeviceType::from_i32(request.device_type).to_string(),
                "requestDeviceIdentifier": request.request_device_identifier,
                "requestIpAddress": request.request_ip,
                "key": request.enc_key,
                "masterPasswordHash": null,
                "creationDate": format_date(&request.creation_date),
                "responseDate": response_date_utc,
                "requestApproved": request.approved,
                "origin": CONFIG.domain_origin(),
                "object":"auth-request"
            })
        }).collect::<Vec<Value>>(),
        "continuationToken": null,
        "object": "list"
    })))
}

pub async fn purge_auth_requests(pool: DbPool) {
    debug!("Purging auth requests");
    if let Ok(conn) = pool.get().await {
        AuthRequest::purge_expired_auth_requests(&conn).await;
    } else {
        error!("Failed to get DB connection while purging auth requests");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every KDF setting an unknown email can get is one a PassBundle account could have (the server's own check
    /// takes it) and that PassBundle's apps accept (the shared bounds, which are the apps'), so neither the answer
    /// nor the apps tell an email with no account from one with an account. The default keeps its weight.
    #[test]
    fn unknown_emails_get_settings_an_account_could_have_and_the_apps_take() {
        for (kdf, iterations, memory, parallelism) in UNKNOWN_EMAIL_KDF_SETTINGS {
            let data: KDFData = serde_json::from_value(json!({
                "kdf": kdf,
                "kdfIterations": iterations,
                "kdfMemory": memory,
                "kdfParallelism": parallelism,
            }))
            .unwrap();
            let mut user = User::new("decoy@example.test", None);
            assert!(
                set_kdf_data(&mut user, &data).is_ok(),
                "the server refuses {kdf} {iterations} {memory:?} {parallelism:?}"
            );
            assert_eq!(
                (user.client_kdf_type, user.client_kdf_iter, user.client_kdf_memory, user.client_kdf_parallelism),
                (kdf, iterations, memory, parallelism)
            );
            // The shared bounds, which the_kdf_bounds_are_the_apps pins to the apps' own.
            match kdf {
                k if k == UserKdfType::Pbkdf2 as i32 => {
                    assert!(PBKDF2_ITERATIONS.contains(&iterations), "the apps refuse PBKDF2 at {iterations}");
                    assert_eq!((memory, parallelism), (None, None));
                }
                k if k == UserKdfType::Argon2id as i32 => {
                    assert!(
                        ARGON2ID_ITERATIONS.contains(&iterations),
                        "the apps refuse Argon2id at {iterations} iterations"
                    );
                    assert!(
                        memory.is_some_and(|m| ARGON2ID_MEMORY_MIB.contains(&m)),
                        "the apps refuse Argon2id at {memory:?} MiB"
                    );
                    assert!(
                        parallelism.is_some_and(|p| ARGON2ID_PARALLELISM.contains(&p)),
                        "the apps refuse Argon2id at a parallelism of {parallelism:?}"
                    );
                }
                _ => panic!("a KDF type the apps don't know: {kdf}"),
            }
        }
        let default = (User::CLIENT_KDF_TYPE_DEFAULT, User::CLIENT_KDF_ITER_DEFAULT, None, None);
        assert_eq!(UNKNOWN_EMAIL_KDF_SETTINGS.iter().filter(|s| **s == default).count(), 2);
    }

    #[test]
    fn test_register_data_current_format() {
        // Web and iOS since the master password authentication/unlock split
        let data: RegisterData = serde_json::from_str(
            r#"{
                "email": "user@example.com",
                "emailVerificationToken": "token",
                "userAsymmetricKeys": {"publicKey": "pub", "encryptedPrivateKey": "priv"},
                "masterPasswordAuthentication": {
                    "kdf": {"kdfType": 0, "iterations": 600000},
                    "salt": "user@example.com",
                    "masterPasswordAuthenticationHash": "hash"
                },
                "masterPasswordUnlock": {
                    "kdf": {"kdfType": 0, "iterations": 600000},
                    "salt": "user@example.com",
                    "masterKeyWrappedUserKey": "key"
                }
            }"#,
        )
        .unwrap();

        assert!(!data.unprocessable());
        assert_eq!(data.hash(), "hash");
        assert_eq!(data.key(), "key");
        assert_eq!(data.kdf().kdf_iterations, 600_000);
        assert!(data.keys.is_some());
        assert_eq!(data.email_verification_token.as_deref(), Some("token"));
    }

    #[test]
    fn test_register_data_flat_format() {
        // Android before 2026.9.0
        let data: RegisterData = serde_json::from_str(
            r#"{
                "email": "user@example.com",
                "emailVerificationToken": "token",
                "masterPasswordHash": "hash",
                "masterPasswordHint": null,
                "userSymmetricKey": "key",
                "userAsymmetricKeys": {"publicKey": "pub", "encryptedPrivateKey": "priv"},
                "kdf": 0,
                "kdfIterations": 600000
            }"#,
        )
        .unwrap();

        assert!(!data.unprocessable());
        assert_eq!(data.hash(), "hash");
        assert_eq!(data.key(), "key");
        assert_eq!(data.kdf().kdf_iterations, 600_000);
        assert!(data.keys.is_some());
    }

    // Keykeeper: the KDF settings an account can have, on every path that takes them (DESIGN.md, "KDF settings an
    // account can have").

    const TOO_FEW: &str = "PBKDF2 needs at least 600,000 iterations.";

    fn refusal<T: std::fmt::Debug>(result: ApiResult<T>) -> String {
        result.expect_err("refused").message().to_owned()
    }

    fn pbkdf2(iterations: i32) -> Value {
        json!({"kdfType": 0, "iterations": iterations})
    }

    async fn headers(user_id: &UserId, conn: &DbConn) -> Headers {
        Headers {
            host: "https://127.0.0.1".to_owned(),
            device: Device::new(DeviceId::from(format!("device-{user_id}")), user_id.clone(), "test".to_owned(), 9),
            user: User::find_by_uuid(user_id, conn).await.unwrap(),
            ip: ClientIp {
                ip: "127.0.0.1".parse().unwrap(),
            },
        }
    }

    /// An account with this master password hash. The server's own rounds on the hash (not the KDF) are fewer
    /// than its default, to keep the test quick.
    async fn account(email: &str, hash: &str, conn: &DbConn) -> User {
        let mut user = User::new(email, None);
        user.password_iterations = 1_000;
        user.set_password(hash, Some("2.key".to_owned()), false, None, conn).await.unwrap();
        user.save(conn).await.unwrap();
        user
    }

    /// The server's bounds are the apps' (passbundle-apps `core/src/kdf.rs`) and the web vault's KDF form's
    /// (`PBKDF2KdfConfig`, `Argon2KdfConfig`), so no account can be set to anything an app refuses.
    #[test]
    fn the_kdf_bounds_are_the_apps() {
        assert_eq!(PBKDF2_ITERATIONS, 600_000..=2_000_000);
        assert_eq!(ARGON2ID_ITERATIONS, 2..=10);
        assert_eq!(ARGON2ID_MEMORY_MIB, 16..=1024);
        assert_eq!(ARGON2ID_PARALLELISM, 1..=16);
        assert_eq!(*PBKDF2_ITERATIONS.start(), User::CLIENT_KDF_ITER_DEFAULT);
    }

    #[test]
    fn the_shared_check_takes_the_bounds_and_nothing_outside_them() {
        let pbkdf2 = |iterations| check_kdf(UserKdfType::Pbkdf2 as i32, iterations, None, None);
        assert_eq!(refusal(pbkdf2(100_000)), TOO_FEW);
        assert_eq!(refusal(pbkdf2(599_999)), TOO_FEW);
        assert!(pbkdf2(600_000).is_ok());
        assert!(pbkdf2(2_000_000).is_ok());
        assert_eq!(refusal(pbkdf2(2_000_001)), "PBKDF2 allows at most 2,000,000 iterations.");

        let argon2id =
            |iterations, memory, parallelism| check_kdf(UserKdfType::Argon2id as i32, iterations, memory, parallelism);
        assert!(argon2id(2, Some(16), Some(1)).is_ok());
        assert!(argon2id(10, Some(1024), Some(16)).is_ok());
        for iterations in [0, 1, 11] {
            assert_eq!(refusal(argon2id(iterations, Some(64), Some(4))), "Argon2id needs 2 to 10 iterations.");
        }
        for memory in [15, 1025] {
            assert_eq!(refusal(argon2id(3, Some(memory), Some(4))), "Argon2id needs 16 to 1,024 MiB of memory.");
        }
        assert_eq!(refusal(argon2id(3, None, Some(4))), "Argon2 memory parameter is required.");
        for parallelism in [0, 17] {
            assert_eq!(refusal(argon2id(3, Some(64), Some(parallelism))), "Argon2id needs a parallelism of 1 to 16.");
        }
        assert_eq!(refusal(argon2id(3, Some(64), None)), "Argon2 parallelism parameter is required.");

        // A type the apps don't know is no way around the bounds.
        assert_eq!(refusal(check_kdf(2, 1, None, None)), "Unknown KDF type.");
    }

    fn registration(iterations: i32, current_format: bool) -> RegisterData {
        let email = "ana@example.test";
        serde_json::from_value(if current_format {
            json!({
                "email": email,
                "masterPasswordAuthentication": {
                    "kdf": pbkdf2(iterations),
                    "salt": email,
                    "masterPasswordAuthenticationHash": "hash"
                },
                "masterPasswordUnlock": {"kdf": pbkdf2(iterations), "salt": email, "masterKeyWrappedUserKey": "2.key"}
            })
        } else {
            json!({
                "email": email,
                "masterPasswordHash": "hash",
                "userSymmetricKey": "2.key",
                "kdf": 0,
                "kdfIterations": iterations
            })
        })
        .unwrap()
    }

    /// Registration, in both formats the apps send: 599,999 iterations is refused first, before the invitation
    /// is taken; 600,000 gets past that, to the verification token this request doesn't have. What a
    /// registration stores is the same check's.
    #[rocket::async_test]
    async fn registration_needs_600000_iterations() {
        for current_format in [true, false] {
            let refused = register(Json(registration(599_999, current_format)), DbPool::for_test().await).await;
            assert_eq!(refusal(refused), TOO_FEW);
            let next = register(Json(registration(600_000, current_format)), DbPool::for_test().await).await;
            assert_eq!(refusal(next), "Registration is missing required parameters");
        }
        let mut user = User::new("ana@example.test", None);
        assert_eq!(refusal(set_kdf_data(&mut user, registration(599_999, true).kdf())), TOO_FEW);
        user.client_kdf_iter = 800_000;
        set_kdf_data(&mut user, registration(600_000, true).kdf()).unwrap();
        assert_eq!((user.client_kdf_type, user.client_kdf_iter), (UserKdfType::Pbkdf2 as i32, 600_000));
    }

    fn first_password(iterations: i32) -> Json<SetPasswordData> {
        Json(
            serde_json::from_value(json!({
                "kdf": 0,
                "kdfIterations": iterations,
                "key": "2.key",
                "keys": null,
                "masterPasswordHash": "hash",
                "masterPasswordHint": null,
                "orgIdentifier": null
            }))
            .unwrap(),
        )
    }

    /// Setting a first master password (someone who joined with single sign-on): 599,999 iterations is refused and
    /// the account still has none; 600,000 sets it.
    #[rocket::async_test]
    async fn a_first_password_needs_600000_iterations() {
        let pool = DbPool::for_test_pool();
        let conn = pool.get().await.unwrap();
        let mut sso = User::new("sso@example.test", None);
        sso.save(&conn).await.unwrap();

        let refused = post_set_password(first_password(599_999), headers(&sso.uuid, &conn).await, conn).await;
        assert_eq!(refusal(refused), TOO_FEW);
        let conn = pool.get().await.unwrap();
        assert_eq!(User::find_by_uuid(&sso.uuid, &conn).await.unwrap().password_hash, Vec::<u8>::new());

        post_set_password(first_password(600_000), headers(&sso.uuid, &conn).await, conn).await.unwrap();
        let conn = pool.get().await.unwrap();
        let sso = User::find_by_uuid(&sso.uuid, &conn).await.unwrap();
        assert_ne!(sso.password_hash, Vec::<u8>::new());
        assert_eq!((sso.client_kdf_type, sso.client_kdf_iter), (UserKdfType::Pbkdf2 as i32, 600_000));
    }

    fn kdf_change(email: &str, iterations: i32) -> Json<ChangeKdfData> {
        Json(
            serde_json::from_value(json!({
                "authenticationData": {
                    "salt": email,
                    "kdf": pbkdf2(iterations),
                    "masterPasswordAuthenticationHash": "new"
                },
                "unlockData": {"salt": email, "kdf": pbkdf2(iterations), "masterKeyWrappedUserKey": "2.new-key"},
                "masterPasswordHash": "hash"
            }))
            .unwrap(),
        )
    }

    /// Changing the KDF: to 599,999 iterations is refused and the account keeps its settings and password; to
    /// 600,000 is saved.
    #[rocket::async_test]
    async fn changing_the_kdf_needs_600000_iterations() {
        let pool = DbPool::for_test_pool();
        let conn = pool.get().await.unwrap();
        let mut kim = account("kim@example.test", "hash", &conn).await;
        kim.client_kdf_iter = 800_000;
        kim.save(&conn).await.unwrap();
        let nt: Notify<'_> = (&*crate::api::WS_USERS).into();

        let refused = post_kdf(kdf_change(&kim.email, 599_999), headers(&kim.uuid, &conn).await, conn, nt).await;
        assert_eq!(refusal(refused), TOO_FEW);
        let conn = pool.get().await.unwrap();
        let unchanged = User::find_by_uuid(&kim.uuid, &conn).await.unwrap();
        assert_eq!(unchanged.client_kdf_iter, 800_000);
        assert!(unchanged.check_valid_password("hash"));

        post_kdf(kdf_change(&kim.email, 600_000), headers(&kim.uuid, &conn).await, conn, nt).await.unwrap();
        let conn = pool.get().await.unwrap();
        let changed = User::find_by_uuid(&kim.uuid, &conn).await.unwrap();
        assert_eq!((changed.client_kdf_type, changed.client_kdf_iter), (UserKdfType::Pbkdf2 as i32, 600_000));
        assert!(changed.check_valid_password("new"));
    }

    fn password_change(email: &str, iterations: i32) -> Json<ChangePassData> {
        Json(
            serde_json::from_value(json!({
                "masterPasswordHash": "hash",
                "masterPasswordHint": null,
                "authenticationData": {
                    "salt": email,
                    "kdf": pbkdf2(iterations),
                    "masterPasswordAuthenticationHash": "new"
                },
                "unlockData": {"salt": email, "kdf": pbkdf2(iterations), "masterKeyWrappedUserKey": "2.new-key"}
            }))
            .unwrap(),
        )
    }

    /// Changing the master password, which sends the KDF settings too: with 599,999 iterations it's refused and
    /// the old password still works; with the account's 600,000 the new one is set.
    #[rocket::async_test]
    async fn a_new_master_password_needs_600000_iterations() {
        let pool = DbPool::for_test_pool();
        let conn = pool.get().await.unwrap();
        let lee = account("lee@example.test", "hash", &conn).await;
        let nt: Notify<'_> = (&*crate::api::WS_USERS).into();

        let refused =
            post_password(password_change(&lee.email, 599_999), headers(&lee.uuid, &conn).await, conn, nt).await;
        assert_eq!(refusal(refused), TOO_FEW);
        let conn = pool.get().await.unwrap();
        assert!(User::find_by_uuid(&lee.uuid, &conn).await.unwrap().check_valid_password("hash"));

        post_password(password_change(&lee.email, 600_000), headers(&lee.uuid, &conn).await, conn, nt).await.unwrap();
        let conn = pool.get().await.unwrap();
        assert!(User::find_by_uuid(&lee.uuid, &conn).await.unwrap().check_valid_password("new"));
    }

    fn rotation(email: &str, iterations: i32) -> KeyData {
        serde_json::from_value(json!({
            "accountUnlockData": {
                "emergencyAccessUnlockData": [],
                "masterPasswordUnlockData": {
                    "kdfType": 0,
                    "kdfIterations": iterations,
                    "kdfParallelism": null,
                    "kdfMemory": null,
                    "email": email,
                    "masterKeyAuthenticationHash": "new",
                    "masterKeyEncryptedUserKey": "2.new-key"
                },
                "organizationAccountRecoveryUnlockData": []
            },
            "accountKeys": {"userKeyEncryptedAccountPrivateKey": "2.private-key", "accountPublicKey": "public-key"},
            "accountData": {"ciphers": [], "folders": [], "sends": []},
            "oldMasterKeyAuthenticationHash": "hash"
        }))
        .unwrap()
    }

    /// Key rotation keeps the account's KDF settings, and checks them as every other path does: 599,999
    /// iterations is refused with the same message; the account's 600,000 passes.
    #[test]
    fn key_rotation_needs_600000_iterations() {
        let mut max = User::new("max@example.test", None);
        max.public_key = Some("public-key".to_owned());
        let check = |data: &KeyData| validate_keydata(data, &[], &[], &[], &[], &[], &max);
        assert_eq!(refusal(check(&rotation(&max.email, 599_999))), TOO_FEW);
        assert!(check(&rotation(&max.email, 600_000)).is_ok());
    }
}

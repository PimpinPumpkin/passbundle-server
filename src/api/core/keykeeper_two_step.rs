// Keykeeper: two-step login for the people who run an organization or an
// MSP. "Client admins def need SSO or 2FA of some sort."
//
// Who: an organization's owners, admins, custom roles that manage members,
// policies, or account recovery, and everyone an MSP's membership brings in,
// where the organization requires it (its own setting: on with the Business
// preset and an MSP's default policies); and everyone on an MSP's staff,
// where the MSP requires it (on by default).
//
// What counts: an authenticator app, a security key or passkey with at least
// one key, or Duo with this server's own Duo account. Email codes don't: a
// client's email admins could read them, the same reason a link to single
// sign-on never trusts an email. Nor does Duo with someone's own Duo
// application, whose policy (bypass, or "allow without two-step") they set
// themselves. A sign-in with an organization's own single sign-on meets that
// organization's requirement for its admins and custom roles, since the
// tenant's MFA covers them (unless the ID token says the sign-in had none);
// owners and MSP staff can always sign in with a password (Require single
// sign-on exempts them, and no client's single sign-on signs in MSP staff),
// so for them two-step login is the protection.
//
// How: a sign-in that checks out (the password and any email code, or single
// sign-on) by someone it covers who has no method that counts gets a setup
// session instead of a login (check_sign_in): an opaque token, kept as a hash,
// with no refresh token, for fifteen minutes, which only the endpoints that
// set up two-step login take (SetupHeaders), and which ends when a method that
// counts is set up. The web vault shows "Set up two-step login to continue";
// the other apps send the person there. A session goes on refreshing only
// while its person still meets the rule (may_refresh). When a change brings
// someone under the rule without a method that counts, or takes their last
// one, every session of theirs ends at once (Watch). An API key doesn't sign
// in someone who doesn't meet it (check_api_key), and for someone it covers,
// an API key's token isn't taken where admins act (api_key_refused).
//
// See DESIGN.md, "Two-step login for admins", in the meta repo.

use std::net::IpAddr;

use num_traits::FromPrimitive;
use rocket::{
    Request, Route,
    http::Status,
    request::{FromRequest, Outcome},
    serde::json::Json,
};
use serde_json::Value;

use super::{
    keykeeper_msp::{Audit, require_admin, staff_member},
    keykeeper_script_access::is_token_admin,
    keykeeper_sso, log_event,
    two_factor::has_global_duo_credentials,
};
use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult, JsonResult, WS_USERS},
    auth::{ClientIp, Headers, decode_login},
    db::{
        DbConn,
        models::{
            Device, EventType, Membership, MembershipStatus, MembershipType, Msp, MspClient, MspId, MspMembership,
            MspStaff, MspStaffTwoStep, OrgAdminTwoStep, Organization, OrganizationId, TwoFactor, TwoFactorType,
            TwoStepSetupSession, User, UserId, keykeeper_roles, qualifying_two_step,
        },
    },
};

pub fn routes() -> Vec<Route> {
    routes![setup_info, get_org_setting, put_org_setting, get_msp_setting, put_msp_setting]
}

// ---------------------------------------------------------------------------
// The rule.

/// Why two-step login is required of someone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Requirement {
    /// An organization requires it of their role there.
    Organization {
        org: OrganizationId,
        name: String,
        owner: bool,
        /// The membership came through an MSP.
        through_msp: bool,
    },
    /// An MSP requires it of its staff.
    MspStaff {
        msp: MspId,
        name: String,
    },
}

impl Requirement {
    fn name(&self) -> &str {
        match self {
            Self::Organization {
                name,
                ..
            }
            | Self::MspStaff {
                name,
                ..
            } => name,
        }
    }

    /// Whether a sign-in with these organizations' single sign-on meets it:
    /// for an organization's admins and custom roles, a sign-in with that
    /// organization's own single sign-on, whose tenant's MFA covers them.
    /// Never for owners, who can always sign in with their password, nor for
    /// MSP staff, whom no client's single sign-on signs in.
    pub fn met_by_sso(&self, sso_orgs: &[OrganizationId]) -> bool {
        match self {
            Self::Organization {
                org,
                owner,
                through_msp,
                ..
            } => !owner && !through_msp && sso_orgs.contains(org),
            Self::MspStaff {
                ..
            } => false,
        }
    }
}

/// The custom role permissions that make a member one the rule covers.
fn elevated_permissions(p: &keykeeper_roles::CustomPermissions) -> bool {
    use keykeeper_roles::Permission::{ManagePolicies, ManageResetPassword, ManageUsers};
    p.has(ManageUsers) || p.has(ManagePolicies) || p.has(ManageResetPassword)
}

/// Whether an organization's setting covers this membership: an owner, an
/// admin, a custom role that manages members, policies, or account recovery,
/// or anyone an MSP's membership brought in (its admins and technicians,
/// whatever their role there: a technician with every vault item and export
/// reaches as much as an admin), who has joined (accepted or confirmed).
/// Invited and revoked memberships reach nothing, so they aren't covered.
pub async fn covered_membership(member: &Membership, conn: &DbConn) -> bool {
    if member.status < MembershipStatus::Accepted as i32 {
        return false;
    }
    if member.atype == MembershipType::Owner as i32 || member.atype == MembershipType::Admin as i32 {
        return true;
    }
    if MspMembership::find_by_membership(&member.uuid, conn).await.is_some() {
        return true;
    }
    member.atype == MembershipType::User as i32
        && keykeeper_roles::find(&member.uuid, conn).await.is_some_and(|p| elevated_permissions(&p))
}

/// Everything that requires two-step login of this person. A database error
/// is an error, so nothing is let through on one.
pub async fn requirements(user_id: &UserId, conn: &DbConn) -> ApiResult<Vec<Requirement>> {
    let mut out = Vec::new();
    for (msp, staff) in Msp::find_by_staff_user(user_id, conn).await {
        if staff.role().is_some() && MspStaffTwoStep::required(&msp.uuid, conn).await? {
            out.push(Requirement::MspStaff {
                msp: msp.uuid,
                name: msp.name,
            });
        }
    }
    for member in Membership::find_by_user(user_id, conn).await {
        if !covered_membership(&member, conn).await || !OrgAdminTwoStep::required(&member.org_uuid, conn).await? {
            continue;
        }
        let name = Organization::find_by_uuid(&member.org_uuid, conn).await.map(|o| o.name).unwrap_or_default();
        out.push(Requirement::Organization {
            owner: member.atype == MembershipType::Owner as i32,
            through_msp: MspMembership::find_by_membership(&member.uuid, conn).await.is_some(),
            org: member.org_uuid,
            name,
        });
    }
    Ok(out)
}

/// Whether someone has set up a method that counts and this server can use.
pub async fn has_qualifying(user_id: &UserId, conn: &DbConn) -> bool {
    TwoFactor::find_by_user(user_id, conn).await.iter().any(counts)
}

/// Whether one method counts: an authenticator app; a security key or
/// passkey, with at least one key left; or Duo with this server's own Duo
/// account. Duo with someone's own Duo application doesn't, since they set its
/// policy, which can let a sign-in through without a second step.
fn counts(tf: &TwoFactor) -> bool {
    if !tf.enabled || !qualifying_two_step(tf.atype) {
        return false;
    }
    match TwoFactorType::from_i32(tf.atype) {
        Some(TwoFactorType::Authenticator) => true,
        Some(TwoFactorType::Webauthn) => CONFIG.is_webauthn_2fa_supported() && has_keys(&tf.data),
        Some(TwoFactorType::Duo) => duo_uses_server_keys(&tf.data) && has_global_duo_credentials(),
        _ => false,
    }
}

/// Whether a security key or passkey method has a key left: upstream leaves
/// the method on with none when the last one is removed.
fn has_keys(data: &str) -> bool {
    serde_json::from_str::<Vec<Value>>(data).is_ok_and(|keys| !keys.is_empty())
}

/// Whether a Duo method uses this server's Duo account: it was set up without
/// keys of its own (upstream keeps those as JSON, and uses them when they
/// parse).
fn duo_uses_server_keys(data: &str) -> bool {
    #[derive(Deserialize)]
    struct OwnKeys {
        #[allow(dead_code)]
        host: String,
        #[allow(dead_code)]
        ik: String,
        #[allow(dead_code)]
        sk: String,
    }
    serde_json::from_str::<OwnKeys>(data).is_err()
}

/// What requires two-step login of this person that they don't meet, for a
/// sign-in with these organizations' single sign-on (none for a password).
pub async fn unmet(user_id: &UserId, sso_orgs: &[OrganizationId], conn: &DbConn) -> ApiResult<Vec<Requirement>> {
    if has_qualifying(user_id, conn).await {
        return Ok(Vec::new());
    }
    Ok(requirements(user_id, conn).await?.into_iter().filter(|r| !r.met_by_sso(sso_orgs)).collect())
}

/// Whether a sign-in's second step can't be an email code: the person's role
/// requires two-step login and they have a method that counts, which they use
/// instead. (Without one, an email code still proves the mailbox, and the
/// sign-in then gets a setup session.) A database error counts as yes.
pub async fn email_codes_refused(user_id: &UserId, conn: &DbConn) -> bool {
    has_qualifying(user_id, conn).await && requirements(user_id, conn).await.map_or(true, |r| !r.is_empty())
}

/// The names in a sentence: "A", "A and B", "A, B, and C".
fn names_phrase(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

/// Who requires it, each named once.
fn requirer_names(unmet: &[Requirement]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for r in unmet {
        if !names.iter().any(|n| n == r.name()) {
            names.push(r.name().to_owned());
        }
    }
    names
}

/// "Acme Dental requires two-step login for your role." and the like.
fn required_sentence(names: &[String]) -> String {
    let verb = if names.len() == 1 {
        "requires"
    } else {
        "require"
    };
    format!("{} {verb} two-step login for your role.", names_phrase(names))
}

/// Whether the rule lets this sign-in through, once the password (or single
/// sign-on) and any email code checked out. Someone it covers who has no
/// method that counts gets a setup session instead (the answer carries
/// `KeykeeperTwoStepSetup`), which only the setup endpoints take. A sign-in
/// with a device's approval goes to check_approved_sign_in instead.
///
/// An account without a master password yet (an invitation's first single
/// sign-on, which goes on to set one) isn't held up: the rule applies from its
/// next sign-in, and its session stops refreshing once it has a password and
/// still no method that counts.
pub async fn check_sign_in(
    user: &User,
    sso_org: Option<&OrganizationId>,
    device_type: i32,
    conn: &DbConn,
) -> EmptyResult {
    if user.password_hash.is_empty() {
        return Ok(());
    }
    let sso_orgs: Vec<OrganizationId> = sso_org.cloned().into_iter().collect();
    let unmet = unmet(&user.uuid, &sso_orgs, conn).await?;
    if unmet.is_empty() {
        return Ok(());
    }
    let names = requirer_names(&unmet);
    let required = required_sentence(&names);
    let (token, row) = TwoStepSetupSession::generate(user.uuid.clone(), device_type);
    row.insert(conn).await?;
    let message = format!(
        "{required} Set it up in the web vault at {} (an authenticator app, a security key or passkey, or Duo), then sign in again.",
        CONFIG.domain()
    );
    err_json!(
        json!({
            "error": "invalid_grant",
            "error_description": message,
            "KeykeeperTwoStepSetup": token,
            "KeykeeperTwoStepRequiredBy": names,
            "ErrorModel": { "Message": message, "Object": "error" },
        }),
        format!("Two-step login required for {}; started a setup session.", user.email)
    )
}

/// The rule for a sign-in with a device's approval
/// (keykeeper_device_approval::approved_sign_in_rules). It proves no
/// password, so it starts no setup session: someone the rule covers who has no
/// method that counts is refused, and signs in with their master password to
/// set one up. An account without a master password isn't held up, as in
/// check_sign_in.
pub async fn check_approved_sign_in(user: &User, conn: &DbConn) -> EmptyResult {
    if user.password_hash.is_empty() {
        return Ok(());
    }
    let unmet = unmet(&user.uuid, &[], conn).await?;
    if unmet.is_empty() {
        return Ok(());
    }
    err!(format!(
        "{} Sign in with your master password in the web vault at {} to set it up.",
        required_sentence(&requirer_names(&unmet)),
        CONFIG.domain()
    ))
}

/// The organization whose single sign-on started a session, as the rule counts
/// it: only while that single sign-on still signs this account in.
async fn counted_sso_orgs(user_id: &UserId, sso_org: Option<&OrganizationId>, conn: &DbConn) -> Vec<OrganizationId> {
    match sso_org {
        Some(org) if keykeeper_sso::live_sso_orgs(user_id, conn).await.contains(org) => vec![org.clone()],
        _ => Vec::new(),
    }
}

/// Whether a session may refresh: its person still meets the rule (or has no
/// master password yet; see check_sign_in). A session single sign-on started
/// counts for that one organization (the session's `kk_sso_org`, set only when
/// the sign-in counts), while its single sign-on still signs this account in.
/// A database error counts as no.
pub async fn may_refresh(user: &User, sso_org: Option<&OrganizationId>, conn: &DbConn) -> bool {
    if user.password_hash.is_empty() {
        return true;
    }
    let sso_orgs = counted_sso_orgs(&user.uuid, sso_org, conn).await;
    unmet(&user.uuid, &sso_orgs, conn).await.is_ok_and(|u| u.is_empty())
}

/// What a refresh says when the rule ends a session.
pub const REFRESH_REFUSED: &str = "Your role now requires two-step login. Sign in again to set it up.";

/// What the caller's access token says about how its session began.
pub struct SessionFacts {
    /// An API key's token (the CLI's client_credentials): its scope has no
    /// `offline_access`, since it never refreshes, and no second step was
    /// asked for.
    pub api_key: bool,
    /// The organization whose single sign-on started the session, when that
    /// counts for this rule.
    pub sso_org: Option<OrganizationId>,
}

impl SessionFacts {
    fn of(request: &Request<'_>) -> Option<Self> {
        // The token as the Headers guard reads it, so both see the same one.
        let token = request.headers().get_one("Authorization")?.rsplit("Bearer ").next()?;
        let claims = decode_login(token).ok()?;
        Some(Self {
            api_key: !claims.scope.iter().any(|s| s == "offline_access"),
            sso_org: claims.kk_sso_org,
        })
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SessionFacts {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match Self::of(request) {
            Some(facts) => Outcome::Success(facts),
            None => Outcome::Error((Status::Unauthorized, "Invalid claim")),
        }
    }
}

/// What an admin endpoint says to an API key's token the rule refuses.
pub const API_KEY_REFUSED: &str = "Your role requires two-step login, which an API key skips, so it can't do admin work. Sign in with two-step login instead.";

/// Whether to refuse this request: an API key's token, from someone the rule
/// covers, where admins act (upstream's endpoints for an organization's
/// owners, admins, and managers, and the MSP console's and organizations'
/// own endpoints, admin_path). An API key skips two-step login, so it reads
/// and edits its person's own vault, as the CLI and scripts do, but doesn't do
/// admin work for someone the rule covers. A database error counts as yes.
pub async fn api_key_refused(request: &Request<'_>, user_id: &UserId) -> bool {
    if !SessionFacts::of(request).is_some_and(|f| f.api_key) {
        return false;
    }
    let Outcome::Success(conn) = request.guard::<DbConn>().await else {
        return true;
    };
    requirements(user_id, &conn).await.map_or(true, |r| !r.is_empty())
}

/// Whether the request's matched route is one of Keykeeper's own endpoints
/// where admins act (admin_path). Decided on the route Rocket matched, never
/// the address as sent: Rocket skips empty segments and decodes the rest, so
/// `/api//keykeeper/msp/...` and `/api/keykeeper/%6Dsp/...` reach the same
/// handlers.
pub fn admin_route(request: &Request<'_>) -> bool {
    request.route().is_some_and(|route| admin_path(route.uri.path()))
}

/// Keykeeper's own endpoints where admins act, under `/api`: the MSP console's
/// (`/keykeeper/msp...`) and organizations' (`/keykeeper/organizations...`),
/// by a route's path (admin_route).
pub fn admin_path(path: &str) -> bool {
    path.split_once("/api/keykeeper/")
        .is_some_and(|(_, rest)| rest.starts_with("msp") || rest.starts_with("organizations"))
}

/// What turning the rule off says to someone who doesn't meet it.
const TURN_OFF_REFUSED: &str = "Set up two-step login for your own account before you turn this off.";

/// Only someone who meets the rule themselves turns it off (an organization's
/// setting, an MSP's for its staff, or its default for clients): otherwise a
/// session that never had a second step could turn it off for good.
pub async fn require_caller_meets(user: &User, session: &SessionFacts, conn: &DbConn) -> EmptyResult {
    let sso_orgs = counted_sso_orgs(&user.uuid, session.sso_org.as_ref(), conn).await;
    if !unmet(&user.uuid, &sso_orgs, conn).await?.is_empty() {
        err!(TURN_OFF_REFUSED)
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Ending sessions when someone comes under the rule.

/// What the rule asks of someone at one moment.
struct Standing {
    requirements: Vec<Requirement>,
    qualifying: bool,
}

impl Standing {
    async fn of(user_id: &UserId, conn: &DbConn) -> ApiResult<Self> {
        Ok(Self {
            requirements: requirements(user_id, conn).await?,
            qualifying: has_qualifying(user_id, conn).await,
        })
    }
}

/// People a change may bring under the rule, or leave without a method that
/// counts, watched from before the change (Watch::user, Watch::users) to after
/// it (Watch::settle). Their sessions began under the old standing, and an
/// access token is good for two hours, while only a refresh checks the rule.
pub struct Watch(Vec<(UserId, Standing)>);

impl Watch {
    pub async fn user(user_id: &UserId, conn: &DbConn) -> ApiResult<Self> {
        Self::users([user_id.clone()], conn).await
    }

    pub async fn users(user_ids: impl IntoIterator<Item = UserId>, conn: &DbConn) -> ApiResult<Self> {
        let mut watched: Vec<(UserId, Standing)> = Vec::new();
        for user_id in user_ids {
            if watched.iter().any(|(id, _)| id == &user_id) {
                continue;
            }
            let standing = Standing::of(&user_id, conn).await?;
            watched.push((user_id, standing));
        }
        Ok(Self(watched))
    }

    /// After the change. Someone the rule now covers where it didn't (a
    /// promotion, a new membership or staff role, a setting turned on) forgets
    /// every device remembered for two-step login, since one may have been
    /// remembered with an email code. Someone it covers who now has no method
    /// that counts (newly covered, or their last one went) is signed out
    /// everywhere at once (end_sessions), and sets one up at their next sign-in.
    pub async fn settle(self, conn: &DbConn) -> EmptyResult {
        for (user_id, before) in self.0 {
            let now = Standing::of(&user_id, conn).await?;
            let newly = now.requirements.iter().any(|r| !before.requirements.contains(r));
            if newly {
                Device::clear_twofactor_remember_by_user(&user_id, conn).await?;
            }
            if !now.qualifying && !now.requirements.is_empty() && (newly || before.qualifying) {
                end_sessions(&user_id, conn).await?;
            }
        }
        Ok(())
    }
}

/// Signs someone out everywhere now: a new security stamp ends every access
/// token, refresh token, and setup session (User::reset_security_stamp), and
/// the apps hear it at once where they listen. An account without a master
/// password yet is left alone, as at sign-in (check_sign_in).
async fn end_sessions(user_id: &UserId, conn: &DbConn) -> EmptyResult {
    let Some(mut user) = User::find_by_uuid(user_id, conn).await else {
        return Ok(());
    };
    if user.password_hash.is_empty() {
        return Ok(());
    }
    user.reset_security_stamp(conn).await?;
    user.save(conn).await?;
    WS_USERS.send_logout(&user, None, conn).await;
    Ok(())
}

/// An API key (the CLI's client_credentials) skips two-step login, so it
/// doesn't sign in someone the rule covers who has no method that counts. Once
/// they set one up in the web vault, their API key works again.
pub async fn check_api_key(user: &User, conn: &DbConn) -> EmptyResult {
    let unmet = unmet(&user.uuid, &[], conn).await?;
    if unmet.is_empty() {
        return Ok(());
    }
    let required = required_sentence(&requirer_names(&unmet));
    err!(format!("{required} An API key can't sign in until you set it up in the web vault at {}.", CONFIG.domain()))
}

// ---------------------------------------------------------------------------
// The setup session.

/// Who's setting up two-step login: a signed-in session (upstream's, as
/// before), or a setup session from a sign-in the rule held up. A setup
/// session's token isn't a login token, so no other request takes it.
/// Upstream's setup endpoints still check the master password (or a one-time
/// code for an account without one), for either.
pub struct SetupHeaders {
    pub user: User,
    pub device_type: i32,
    pub ip: ClientIp,
    /// The setup session, when it's one (None for a signed-in session).
    pub session: Option<TwoStepSetupSession>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SetupHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(token) = request.headers().get_one("Authorization").and_then(|a| a.strip_prefix("Bearer ")) else {
            return Outcome::Error((Status::Unauthorized, "No access token provided"));
        };
        // A login token (a JWT) is a signed-in session, checked as upstream
        // checks it. A setup session's token is 43 base64url characters.
        if token.contains('.') {
            return request.guard::<Headers>().await.map(|h| Self {
                user: h.user,
                device_type: h.device.atype,
                ip: h.ip,
                session: None,
            });
        }
        let Outcome::Success(conn) = request.guard::<DbConn>().await else {
            return Outcome::Error((Status::ServiceUnavailable, "Error getting DB"));
        };
        let Outcome::Success(ip) = request.guard::<ClientIp>().await else {
            return Outcome::Error((Status::BadRequest, "Error getting Client IP"));
        };
        let Some(session) = TwoStepSetupSession::find(token, &conn).await else {
            return Outcome::Error((Status::Unauthorized, "This setup session expired. Sign in again."));
        };
        match User::find_by_uuid(&session.user_uuid, &conn).await {
            Some(user) if user.enabled => Outcome::Success(Self {
                user,
                device_type: session.device_type,
                ip,
                session: Some(session),
            }),
            _ => Outcome::Error((Status::Unauthorized, "This setup session expired. Sign in again.")),
        }
    }
}

/// After a method was set up. For someone the rule covers, devices
/// remembered for two-step login are forgotten: they may have been remembered
/// with an email code, so each proves the new method once. A setup session
/// ends here, once the method counts, and the answer carries a new recovery
/// code (any earlier one stops working), which the person can't fetch later
/// without signing in.
pub async fn finish_setup(
    session: Option<&TwoStepSetupSession>,
    user: &mut User,
    answer: &mut Value,
    conn: &DbConn,
) -> EmptyResult {
    if !requirements(&user.uuid, conn).await?.is_empty() {
        Device::clear_twofactor_remember_by_user(&user.uuid, conn).await?;
    }
    if session.is_none() {
        return Ok(());
    }
    if !has_qualifying(&user.uuid, conn).await {
        err!("That doesn't count for two-step login for your role. Choose another method.")
    }
    TwoStepSetupSession::end_for_user(&user.uuid, conn).await?;
    user.totp_recover = Some(crate::crypto::encode_random_bytes::<20>(&data_encoding::BASE32));
    user.save(conn).await?;
    answer["keykeeperRecoveryCode"] = json!(user.totp_recover);
    Ok(())
}

/// What the web vault's setup page shows: whose rule it is, the account, and
/// which methods this server can set up. And whether the person has a method
/// that counts, which the web vault also asks a signed-in session before
/// someone takes on a role that requires it (creating a Business organization
/// or an MSP).
#[get("/keykeeper/two-step-setup")]
async fn setup_info(headers: SetupHeaders, conn: DbConn) -> JsonResult {
    let unmet = unmet(&headers.user.uuid, &[], &conn).await?;
    Ok(Json(json!({
        "email": headers.user.email,
        "requiredBy": requirer_names(&unmet),
        "qualifying": has_qualifying(&headers.user.uuid, &conn).await,
        "hasMasterPassword": !headers.user.password_hash.is_empty(),
        "methods": {
            "authenticator": true,
            "webauthn": CONFIG.is_webauthn_2fa_supported(),
            // Only with this server's own Duo account (see counts).
            "duo": has_global_duo_credentials(),
        },
    })))
}

// ---------------------------------------------------------------------------
// The settings, and who hasn't set it up.

/// Someone the rule covers (or would) who has no method that counts.
async fn person_json(member: &Membership, conn: &DbConn) -> Option<Value> {
    let user = User::find_by_uuid(&member.user_uuid, conn).await?;
    let role = if member.atype == MembershipType::Owner as i32 {
        "owner"
    } else if member.atype == MembershipType::Admin as i32 {
        "admin"
    } else {
        "custom"
    };
    let through_msp = MspMembership::find_by_membership(&member.uuid, conn).await.is_some();
    let sso = !through_msp
        && member.atype != MembershipType::Owner as i32
        && keykeeper_sso::live_sso_orgs(&user.uuid, conn).await.contains(&member.org_uuid);
    Some(json!({
        "id": member.uuid,
        "userId": user.uuid,
        "email": user.email,
        "name": user.name,
        "role": role,
        "fromMsp": through_msp,
        "singleSignOn": sso,
    }))
}

/// An organization's members its setting covers (or would) who have no method
/// that counts. MSP staff come from the MSP, so `own_only` leaves them out.
async fn not_set_up(org_id: &OrganizationId, own_only: bool, conn: &DbConn) -> Vec<Value> {
    let mut out = Vec::new();
    for member in Membership::find_by_org(org_id, conn).await {
        if !covered_membership(&member, conn).await || has_qualifying(&member.user_uuid, conn).await {
            continue;
        }
        if own_only && MspMembership::find_by_membership(&member.uuid, conn).await.is_some() {
            continue;
        }
        if let Some(person) = person_json(&member, conn).await {
            out.push(person);
        }
    }
    out
}

/// Turns an organization's setting on or off, if that's a change, with an
/// event in its log (high for security tools). Used by the Settings page, the
/// Business preset, and an MSP's default policies. Turned on, it ends the
/// sessions of the people it now covers who have no method that counts
/// (Watch). Whoever turns it off must meet it (require_caller_meets), which
/// each endpoint checks first.
pub async fn set_org_required(
    org_id: &OrganizationId,
    required: bool,
    actor: &UserId,
    device_type: i32,
    ip: &IpAddr,
    conn: &DbConn,
) -> ApiResult<bool> {
    if OrgAdminTwoStep::required(org_id, conn).await? == required {
        return Ok(false);
    }
    let watch = if required {
        let mut covered = Vec::new();
        for member in Membership::find_by_org(org_id, conn).await {
            if covered_membership(&member, conn).await {
                covered.push(member.user_uuid);
            }
        }
        Watch::users(covered, conn).await?
    } else {
        Watch::users([], conn).await?
    };
    OrgAdminTwoStep::set(org_id, required, conn).await?;
    let event = if required {
        EventType::KeykeeperAdminTwoStepOn
    } else {
        EventType::KeykeeperAdminTwoStepOff
    };
    log_event(event, org_id, org_id, actor, device_type, ip, conn).await;
    watch.settle(conn).await?;
    Ok(true)
}

async fn org_view(org_id: &OrganizationId, conn: &DbConn) -> ApiResult<Value> {
    let msp = match MspClient::find_by_org(org_id, conn).await {
        Some(client) => {
            Msp::find_by_uuid(&client.msp_uuid, conn).await.map(|m| json!({ "id": m.uuid, "name": m.name }))
        }
        None => None,
    };
    Ok(json!({
        "required": OrgAdminTwoStep::required(org_id, conn).await?,
        "msp": msp,
        "notSetUp": not_set_up(org_id, false, conn).await,
    }))
}

/// The organization's setting and who it covers without a method that counts,
/// for its owners and admins (and its MSP's admins, not technicians), as its
/// Settings page shows them. Anyone else gets "not found": upstream's web
/// vault signs out on 403.
#[get("/keykeeper/organizations/<org_id>/admin-two-step")]
async fn get_org_setting(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    if !is_token_admin(&org_id, &headers.user.uuid, &conn).await {
        err_code!("Organization not found", Status::NotFound.code)
    }
    Ok(Json(org_view(&org_id, &conn).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgSettingData {
    required: bool,
}

/// Turns the organization's setting on or off. For an MSP's client, the
/// change is its own setting from then on, and goes in the MSP's activity log.
/// Only someone who meets the rule turns it off.
#[put("/keykeeper/organizations/<org_id>/admin-two-step", data = "<data>")]
async fn put_org_setting(
    org_id: OrganizationId,
    headers: Headers,
    session: SessionFacts,
    data: Json<OrgSettingData>,
    conn: DbConn,
) -> JsonResult {
    if !is_token_admin(&org_id, &headers.user.uuid, &conn).await {
        err_code!("Organization not found", Status::NotFound.code)
    }
    let required = data.into_inner().required;
    if !required && OrgAdminTwoStep::required(&org_id, &conn).await? {
        require_caller_meets(&headers.user, &session, &conn).await?;
    }
    let changed =
        set_org_required(&org_id, required, &headers.user.uuid, headers.device.atype, &headers.ip.ip, &conn).await?;
    if changed && let Some(client) = MspClient::find_by_org(&org_id, &conn).await {
        let name = Organization::find_by_uuid(&org_id, &conn).await.map(|o| o.name).unwrap_or_default();
        Audit::by("client_admin_two_step_set", &headers)
            .org(&org_id, &name)
            .detail(if required {
                "on"
            } else {
                "off"
            })
            .record(&client.msp_uuid, &conn)
            .await?;
    }
    Ok(Json(org_view(&org_id, &conn).await?))
}

/// The MSP's setting for its staff, who on its staff hasn't set up a method
/// that counts, and for each client the caller reaches, its setting and its
/// own people it covers without one. For any of the MSP's staff.
#[get("/keykeeper/msp/<msp_id>/two-step")]
async fn get_msp_setting(msp_id: MspId, headers: Headers, conn: DbConn) -> JsonResult {
    let caller = staff_member(&msp_id, &headers.user.uuid, &conn).await?;
    Ok(Json(msp_view(&msp_id, &caller, &conn).await?))
}

async fn msp_view(msp_id: &MspId, caller: &MspStaff, conn: &DbConn) -> ApiResult<Value> {
    let mut staff = Vec::new();
    for s in MspStaff::find_by_msp(msp_id, conn).await {
        if has_qualifying(&s.user_uuid, conn).await {
            continue;
        }
        if let Some(user) = User::find_by_uuid(&s.user_uuid, conn).await {
            staff.push(json!({
                "userId": user.uuid,
                "email": user.email,
                "name": user.name,
                "role": s.role().map(crate::db::models::MspRole::as_str),
            }));
        }
    }
    let reach = caller.reach(conn).await;
    let mut clients = Vec::new();
    for client in MspClient::find_by_msp(msp_id, conn).await {
        if reach.as_ref().is_some_and(|r| !r.contains(&client.org_uuid)) {
            continue;
        }
        let Some(org) = Organization::find_by_uuid(&client.org_uuid, conn).await else {
            continue;
        };
        clients.push(json!({
            "id": org.uuid,
            "name": org.name,
            "required": OrgAdminTwoStep::required(&org.uuid, conn).await?,
            "notSetUp": not_set_up(&org.uuid, true, conn).await,
        }));
    }
    Ok(json!({
        "staffRequired": MspStaffTwoStep::required(msp_id, conn).await?,
        "staffNotSetUp": staff,
        "clients": clients,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MspSettingData {
    staff_required: bool,
}

/// Turns the MSP's requirement for its staff on or off. MSP admins only, and
/// only one who meets the rule turns it off; the change goes in the activity
/// log (high for security tools). Turned on, it ends the sessions of staff
/// with no method that counts (Watch).
#[put("/keykeeper/msp/<msp_id>/two-step", data = "<data>")]
async fn put_msp_setting(
    msp_id: MspId,
    headers: Headers,
    session: SessionFacts,
    data: Json<MspSettingData>,
    conn: DbConn,
) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let caller = staff_member(&msp_id, &headers.user.uuid, &conn).await?;
    let required = data.into_inner().staff_required;
    if MspStaffTwoStep::required(&msp_id, &conn).await? != required {
        if !required {
            require_caller_meets(&headers.user, &session, &conn).await?;
        }
        let staff = if required {
            MspStaff::find_by_msp(&msp_id, &conn).await.into_iter().map(|s| s.user_uuid).collect()
        } else {
            Vec::new()
        };
        let watch = Watch::users(staff, &conn).await?;
        MspStaffTwoStep::set(&msp_id, required, &conn).await?;
        watch.settle(&conn).await?;
        Audit::by("staff_two_step_set", &headers)
            .detail(if required {
                "on"
            } else {
                "off"
            })
            .record(&msp_id, &conn)
            .await?;
    }
    Ok(Json(msp_view(&msp_id, &caller, &conn).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org(id: &str, owner: bool, through_msp: bool) -> Requirement {
        Requirement::Organization {
            org: OrganizationId::from(id.to_owned()),
            name: id.to_owned(),
            owner,
            through_msp,
        }
    }

    #[test]
    fn single_sign_on_meets_only_its_own_organizations_rule_for_admins() {
        let a = OrganizationId::from("a".to_owned());
        let b = OrganizationId::from("b".to_owned());
        assert!(org("a", false, false).met_by_sso(std::slice::from_ref(&a)));
        assert!(!org("a", false, false).met_by_sso(std::slice::from_ref(&b)));
        assert!(!org("a", false, false).met_by_sso(&[]));
        // Owners can always sign in with their password.
        assert!(!org("a", true, false).met_by_sso(std::slice::from_ref(&a)));
        // No client's single sign-on signs in MSP staff.
        assert!(!org("a", false, true).met_by_sso(std::slice::from_ref(&a)));
        let staff = Requirement::MspStaff {
            msp: MspId::from("m".to_owned()),
            name: "m".to_owned(),
        };
        assert!(!staff.met_by_sso(&[a, b]));
    }

    #[test]
    fn a_security_key_method_counts_only_with_a_key() {
        assert!(has_keys(r#"[{"id":1,"name":"Key"}]"#));
        assert!(!has_keys("[]"));
        assert!(!has_keys(""));
        assert!(!has_keys("not json"));
    }

    #[test]
    fn duo_counts_only_with_this_servers_keys() {
        // Set up without keys of its own: upstream stores nothing, and uses
        // the server's.
        assert!(duo_uses_server_keys(""));
        // Someone's own Duo application, whose policy they set.
        assert!(!duo_uses_server_keys(r#"{"host":"api-1.duosecurity.com","ik":"DIXXX","sk":"secret"}"#));
    }

    #[test]
    fn admin_paths_are_the_msp_console_and_organizations_settings() {
        assert!(admin_path("/api/keykeeper/msp"));
        assert!(admin_path("/api/keykeeper/msp/5d7f/two-step"));
        assert!(admin_path("/api/keykeeper/organizations/5d7f/admin-two-step"));
        assert!(admin_path("/vault/api/keykeeper/organizations/5d7f/sso"));
        // Route paths, as admin_route reads them.
        assert!(admin_path("/api/keykeeper/msp/<msp_id>/two-step"));
        assert!(admin_path("/api/keykeeper/organizations/<org_id>/admin-two-step"));
        assert!(!admin_path("/api/keykeeper/ciphers/5d7f/history"));
        assert!(!admin_path("/api/keykeeper/settings"));
        assert!(!admin_path("/api/sync"));
        assert!(!admin_path("/api/organizations/5d7f/users"));
    }

    #[test]
    fn the_sentence_names_who_requires_it() {
        assert_eq!(
            required_sentence(&["Acme Dental".to_owned()]),
            "Acme Dental requires two-step login for your role."
        );
        assert_eq!(
            required_sentence(&["Acme Dental".to_owned(), "Contoso IT".to_owned()]),
            "Acme Dental and Contoso IT require two-step login for your role."
        );
        assert_eq!(
            required_sentence(&["A".to_owned(), "B".to_owned(), "C".to_owned()]),
            "A, B, and C require two-step login for your role."
        );
    }

    #[test]
    fn each_requirer_is_named_once() {
        let unmet = vec![
            org("Acme", true, false),
            Requirement::MspStaff {
                msp: MspId::from("m".to_owned()),
                name: "Contoso IT".to_owned(),
            },
            org("Acme", false, false),
        ];
        assert_eq!(requirer_names(&unmet), vec!["Acme".to_owned(), "Contoso IT".to_owned()]);
    }
}

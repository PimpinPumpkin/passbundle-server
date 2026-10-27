// Keykeeper: two-step login for the people who run an organization or an
// MSP. "Client admins def need SSO or 2FA of some sort."
//
// Who: an organization's owners, admins, and custom roles that manage
// members, policies, or account recovery, where the organization requires it
// (its own setting: on with the Business preset and an MSP's default
// policies); and everyone on an MSP's staff, where the MSP requires it (on by
// default).
//
// What counts: an authenticator app, a security key or passkey, or Duo. Email
// codes don't: a client's email admins could read them, the same reason a
// link to single sign-on never trusts an email. A sign-in with an
// organization's own single sign-on meets that organization's requirement for
// its admins and custom roles, since the tenant's MFA covers them; owners and
// MSP staff can always sign in with a password (Require single sign-on exempts
// them, and no client's single sign-on signs in MSP staff), so for them
// two-step login is the protection.
//
// How: a sign-in that checks out (the password and any email code, or single
// sign-on) by someone it covers who has no method that counts gets a setup
// session instead of a login (check_sign_in): an opaque token, kept as a hash,
// with no refresh token, for fifteen minutes, which only the endpoints that
// set up two-step login take (SetupHeaders), and which ends when a method that
// counts is set up. The web vault shows "Set up two-step login to continue";
// the other apps send the person there. A session goes on refreshing only
// while its person still meets the rule (may_refresh), and an API key doesn't
// sign in someone who doesn't (check_api_key).
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
    two_factor::is_twofactor_provider_usable,
};
use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult, JsonResult},
    auth::{ClientIp, Headers},
    db::{
        DbConn,
        models::{
            EventType, Membership, MembershipStatus, MembershipType, Msp, MspClient, MspId, MspMembership, MspStaff,
            MspStaffTwoStep, OrgAdminTwoStep, Organization, OrganizationId, TwoFactor, TwoFactorType,
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
/// admin, or a custom role that manages members, policies, or account
/// recovery, who has joined (accepted or confirmed). Invited and revoked
/// memberships reach nothing, so they aren't covered.
pub async fn covered_membership(member: &Membership, conn: &DbConn) -> bool {
    if member.status < MembershipStatus::Accepted as i32 {
        return false;
    }
    if member.atype == MembershipType::Owner as i32 || member.atype == MembershipType::Admin as i32 {
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

/// Whether someone has set up a method that counts and this server can use:
/// an authenticator app, a security key or passkey, or Duo.
pub async fn has_qualifying(user_id: &UserId, conn: &DbConn) -> bool {
    TwoFactor::find_by_user(user_id, conn).await.iter().any(|tf| {
        tf.enabled
            && qualifying_two_step(tf.atype)
            && TwoFactorType::from_i32(tf.atype).is_some_and(|t| is_twofactor_provider_usable(&t, Some(&tf.data)))
    })
}

/// What requires two-step login of this person that they don't meet, for a
/// sign-in with these organizations' single sign-on (none for a password).
pub async fn unmet(user_id: &UserId, sso_orgs: &[OrganizationId], conn: &DbConn) -> ApiResult<Vec<Requirement>> {
    if has_qualifying(user_id, conn).await {
        return Ok(Vec::new());
    }
    Ok(requirements(user_id, conn).await?.into_iter().filter(|r| !r.met_by_sso(sso_orgs)).collect())
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
/// with a device's approval proves no password, so it starts none: the person
/// signs in with their master password to set it up.
///
/// An account without a master password yet (an invitation's first single
/// sign-on, which goes on to set one) isn't held up: the rule applies from its
/// next sign-in, and its session stops refreshing once it has a password and
/// still no method that counts.
pub async fn check_sign_in(
    user: &User,
    sso_org: Option<&OrganizationId>,
    approved_by_device: bool,
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
    if approved_by_device {
        err!(format!(
            "{required} Sign in with your master password in the web vault at {} to set it up.",
            CONFIG.domain()
        ))
    }
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

/// Whether a session may refresh: its person still meets the rule (or has no
/// master password yet; see check_sign_in). A session single sign-on started
/// counts for the organizations whose single sign-on still signs this account
/// in. A database error counts as no.
pub async fn may_refresh(user: &User, sso_session: bool, conn: &DbConn) -> bool {
    if user.password_hash.is_empty() {
        return true;
    }
    let sso_orgs = if sso_session {
        keykeeper_sso::live_sso_orgs(&user.uuid, conn).await
    } else {
        Vec::new()
    };
    unmet(&user.uuid, &sso_orgs, conn).await.is_ok_and(|u| u.is_empty())
}

/// What a refresh says when the rule ends a session.
pub const REFRESH_REFUSED: &str = "Your role now requires two-step login. Sign in again to set it up.";

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

impl SetupHeaders {
    /// Whether this is a setup session, not a signed-in one.
    pub fn is_setup_session(&self) -> bool {
        self.session.is_some()
    }
}

/// After a method that counts was set up: a setup session ends here, and the
/// answer carries the account's recovery code, which the person can't fetch
/// later without signing in. Nothing changes for a signed-in session.
pub async fn finish_setup(
    session: Option<&TwoStepSetupSession>,
    user: &User,
    answer: &mut Value,
    conn: &DbConn,
) -> EmptyResult {
    if session.is_none() {
        return Ok(());
    }
    TwoStepSetupSession::end_for_user(&user.uuid, conn).await?;
    answer["keykeeperRecoveryCode"] = json!(user.totp_recover);
    Ok(())
}

/// What the web vault's setup page shows: whose rule it is, the account, and
/// which methods this server can set up. Only for a setup session.
#[get("/keykeeper/two-step-setup")]
async fn setup_info(headers: SetupHeaders, conn: DbConn) -> JsonResult {
    if !headers.is_setup_session() {
        err_code!("Not found", Status::NotFound.code)
    }
    let unmet = unmet(&headers.user.uuid, &[], &conn).await?;
    Ok(Json(json!({
        "email": headers.user.email,
        "requiredBy": requirer_names(&unmet),
        "hasMasterPassword": !headers.user.password_hash.is_empty(),
        "methods": {
            "authenticator": true,
            "webauthn": CONFIG.is_webauthn_2fa_supported(),
            "duo": true,
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
/// Business preset, and an MSP's default policies.
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
    OrgAdminTwoStep::set(org_id, required, conn).await?;
    let event = if required {
        EventType::KeykeeperAdminTwoStepOn
    } else {
        EventType::KeykeeperAdminTwoStepOff
    };
    log_event(event, org_id, org_id, actor, device_type, ip, conn).await;
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
#[put("/keykeeper/organizations/<org_id>/admin-two-step", data = "<data>")]
async fn put_org_setting(
    org_id: OrganizationId,
    headers: Headers,
    data: Json<OrgSettingData>,
    conn: DbConn,
) -> JsonResult {
    if !is_token_admin(&org_id, &headers.user.uuid, &conn).await {
        err_code!("Organization not found", Status::NotFound.code)
    }
    let required = data.into_inner().required;
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

/// Turns the MSP's requirement for its staff on or off. MSP admins only; the
/// change goes in the activity log (high for security tools).
#[put("/keykeeper/msp/<msp_id>/two-step", data = "<data>")]
async fn put_msp_setting(msp_id: MspId, headers: Headers, data: Json<MspSettingData>, conn: DbConn) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let caller = staff_member(&msp_id, &headers.user.uuid, &conn).await?;
    let required = data.into_inner().staff_required;
    if MspStaffTwoStep::required(&msp_id, &conn).await? != required {
        MspStaffTwoStep::set(&msp_id, required, &conn).await?;
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

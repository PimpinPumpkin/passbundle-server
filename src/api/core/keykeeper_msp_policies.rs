// Keykeeper: an MSP's default policies. Every client follows them: a new
// client starts with them, and changing a default changes every client whose
// policy still does what the old default did. A client whose policy does
// something else has its own setting, which a changed default leaves alone,
// until an MSP admin uses the default there again.
//
// Nothing records which clients follow, so that can't drift from the clients'
// real policies: a policy changed in a client's admin console, by anyone who
// may change it there, is simply that client's own. Defaults reach clients
// through set_policy, the body of upstream's policy endpoint, with the same
// checks and side effects. See DESIGN.md, "Default policies".
//
// One default isn't an upstream policy: two-step login for each client's
// admins (keykeeper_two_step), with an option to require it of everyone else
// too (`{"everyone": true}`). It's kept with the others under a type number
// upstream never uses (ADMIN_TWO_STEP), and a client's setting is its own row,
// never an upstream policy, since upstream's apps refuse every policy when one
// has a type they don't know.
//
// A default can also be required for every client: it reaches every client,
// those with their own setting too, and nobody can change that policy in a
// client's admin console until the MSP stops requiring it (refuse_if_required,
// called from every path that changes a client's policy). Stopping changes
// nothing in the clients: each keeps the setting, now following the default.
// The MSP keeps the ids of the clients that had their own setting when the
// requirement changed them (never what their policy was), so it can tell which
// ones might want to go back. See DESIGN.md, "Required for every client".

use std::collections::{HashMap, HashSet};

use num_traits::FromPrimitive;
use rocket::{Route, serde::json::Json};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult, JsonResult},
    auth::Headers,
    db::{
        DbConn,
        models::{
            Membership, MembershipType, Msp, MspClient, MspId, MspPolicy, MspRequiredHadOwn, OrgAdminTwoStep,
            OrgPolicy, OrgPolicyType, Organization, OrganizationId, TwoStepScope,
            keykeeper_roles::{self, Permission},
        },
    },
};

use super::{
    keykeeper_msp::{Audit, require_admin, staff_member},
    keykeeper_two_step::{self, SessionFacts},
    organizations::{PolicyData, set_policy},
};

pub fn routes() -> Vec<Route> {
    routes![get_policies, set_default, use_default, get_client_policies]
}

/// The type number of the default that isn't an upstream policy: two-step
/// login for each client's admins (keykeeper_two_step). Upstream's policy
/// types are small numbers; this one is never sent to the apps as a policy.
pub const ADMIN_TWO_STEP: i32 = 1000;

/// Two-step login for admins' one option, as its data: everyone else too.
/// Without it, the data is null, as it always was.
const EVERYONE: &str = r#"{"everyone":true}"#;

/// Whether two-step login for admins' options ask for everyone else too.
fn everyone_option(data: &str) -> bool {
    serde_json::from_str::<Value>(data).ok().and_then(|v| v.get("everyone").and_then(Value::as_bool)) == Some(true)
}

/// The level two-step login for admins' effect (kind_effect) sets.
fn admin_level(effect: Option<&Value>) -> TwoStepScope {
    match effect {
        None => TwoStepScope::Off,
        Some(options) => TwoStepScope::of(true, options.get("everyone").and_then(Value::as_bool) == Some(true)),
    }
}

/// What an MSP default sets in a client: an upstream policy, or two-step
/// login for its admins.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Policy(OrgPolicyType),
    AdminTwoStep,
}

impl Kind {
    fn from_i32(t: i32) -> Option<Self> {
        if t == ADMIN_TWO_STEP {
            return Some(Self::AdminTwoStep);
        }
        OrgPolicyType::from_i32(t).map(Self::Policy)
    }

    fn as_i32(self) -> i32 {
        match self {
            Self::Policy(t) => t as i32,
            Self::AdminTwoStep => ADMIN_TWO_STEP,
        }
    }
}

/// The policies an MSP can set defaults for: every upstream policy this server
/// supports, in the order the admin console lists them, with two-step login
/// for admins after upstream's two-step login.
const OFFERED: [Kind; 14] = [
    Kind::Policy(OrgPolicyType::TwoFactorAuthentication),
    Kind::AdminTwoStep,
    Kind::Policy(OrgPolicyType::MasterPassword),
    Kind::Policy(OrgPolicyType::RemoveUnlockWithPin),
    Kind::Policy(OrgPolicyType::MaximumVaultTimeout),
    Kind::Policy(OrgPolicyType::ResetPassword),
    Kind::Policy(OrgPolicyType::PasswordGenerator),
    Kind::Policy(OrgPolicyType::SingleOrg),
    Kind::Policy(OrgPolicyType::PersonalOwnership),
    Kind::Policy(OrgPolicyType::DisableSend),
    Kind::Policy(OrgPolicyType::SendOptions),
    Kind::Policy(OrgPolicyType::RestrictedItemTypes),
    Kind::Policy(OrgPolicyType::UriMatchDefaults),
    Kind::Policy(OrgPolicyType::OrganizationUserNotification),
];

/// The policies offered on this server. Account recovery needs email, since a
/// member must be told when an admin resets their password.
fn offered() -> Vec<Kind> {
    OFFERED.into_iter().filter(|t| *t != Kind::Policy(OrgPolicyType::ResetPassword) || CONFIG.mail_enabled()).collect()
}

fn offered_type(pol_type: i32) -> Result<Kind, crate::error::Error> {
    match Kind::from_i32(pol_type) {
        Some(t) if offered().contains(&t) => Ok(t),
        _ => err!("Invalid or unsupported policy type"),
    }
}

/// The policies a policy needs on in the same client: what this server's
/// policy code refuses to break. Account recovery needs single organization
/// where the server enforces it (ENFORCE_SINGLE_ORG_WITH_RESET_PW_POLICY, as
/// Bitwarden always does). Require single sign-on needs it too, but it's
/// never a default. While a policy is required for every client, what it needs
/// stays on: as the MSP's default, and in every client (refuse_if_required).
fn prerequisites(t: Kind) -> Vec<Kind> {
    prerequisites_where(t, CONFIG.enforce_single_org_with_reset_pw_policy())
}

fn prerequisites_where(t: Kind, single_org_for_recovery: bool) -> Vec<Kind> {
    match t {
        Kind::Policy(OrgPolicyType::ResetPassword) if single_org_for_recovery => {
            vec![Kind::Policy(OrgPolicyType::SingleOrg)]
        }
        _ => Vec::new(),
    }
}

/// A policy's name as the admin console shows it, for the audit log and a
/// client's owners.
fn policy_name(kind: Kind) -> &'static str {
    let Kind::Policy(t) = kind else {
        return "Two-step login for admins";
    };
    match t {
        OrgPolicyType::TwoFactorAuthentication => "Require two-step login",
        OrgPolicyType::MasterPassword => "Master password requirements",
        OrgPolicyType::PasswordGenerator => "Password generator",
        OrgPolicyType::SingleOrg => "Single organization",
        OrgPolicyType::PersonalOwnership => "Centralize organization ownership",
        OrgPolicyType::DisableSend => "Remove Send",
        OrgPolicyType::SendOptions => "Send options",
        OrgPolicyType::ResetPassword => "Account recovery administration",
        OrgPolicyType::RemoveUnlockWithPin => "Remove Unlock with PIN",
        OrgPolicyType::RestrictedItemTypes => "Remove card item type",
        OrgPolicyType::UriMatchDefaults => "Default URI match detection",
        OrgPolicyType::OrganizationUserNotification => "Vault banner",
        OrgPolicyType::MaximumVaultTimeout => "Vault lock",
        OrgPolicyType::RequireSso => "Require single sign-on",
        OrgPolicyType::AutotypeDefaultSetting => "Desktop Autotype default setting",
        OrgPolicyType::FillAssist => "Activate fill assist",
    }
}

/// The Business preset's policies, which a new MSP's defaults start as. See
/// DESIGN.md, "Defaults (Business preset)". The keykeeper_msp_policies and
/// keykeeper_msp_vault_lock migrations gave MSPs that already existed the same,
/// except two-step login for admins, which came after (there were no users).
fn business_policies() -> Vec<(Kind, Value)> {
    vec![
        // Account recovery, with automatic enrollment: a member who forgets
        // their master password can be let back in by an owner or admin.
        (Kind::Policy(OrgPolicyType::ResetPassword), json!({ "autoEnrollEnabled": true })),
        // Single organization: members can't also belong to another
        // organization with the same account. Recovery opens a member's whole
        // account, so without this a client's admins could recover their way
        // into a member's family organization. Personal items go in a separate
        // personal account. MSP staff are exempt (see
        // exempt_from_member_policies), so they still reach every client.
        (Kind::Policy(OrgPolicyType::SingleOrg), Value::Null),
        // A strong master password: at least 12 characters and a strength
        // score of 3 out of 4. Existing passwords aren't forced to change.
        (
            Kind::Policy(OrgPolicyType::MasterPassword),
            json!({
                "minComplexity": 3,
                "minLength": 12,
                "requireUpper": false,
                "requireLower": false,
                "requireNumbers": false,
                "requireSpecial": false,
                "enforceOnLogin": false,
            }),
        ),
        // Vault lock: vaults lock when the computer locks or sleeps, then
        // wait as each person chooses (docs/core.md, "Locking by policy").
        // The web vault, which can't see the computer lock, locks after 15
        // minutes without use instead, the default when webMinutes is missing.
        (
            Kind::Policy(OrgPolicyType::MaximumVaultTimeout),
            json!({ "type": "onSystemLock", "minutes": null, "action": "lock" }),
        ),
        // Two-step login for the client's owners, admins, and custom roles
        // that manage members, policies, or account recovery: an
        // authenticator app, a security key or passkey, or Duo (DESIGN.md,
        // "Two-step login for admins").
        (Kind::AdminTwoStep, Value::Null),
    ]
}

/// What a policy does: nothing when it's off, otherwise its options. An off
/// policy's options don't matter, and missing options, empty options, and an
/// option set to null all mean the same.
fn effect(enabled: bool, data: &str) -> Option<Value> {
    if !enabled {
        return None;
    }
    let mut options = serde_json::from_str::<Value>(data).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut options {
        map.retain(|_, v| !v.is_null());
    }
    Some(if options.is_null() {
        json!({})
    } else {
        options
    })
}

/// What one kind of default does (effect). Two-step login for admins has one
/// option, everyone else too, which only `true` turns on: anything else is
/// the same as none.
fn kind_effect(t: Kind, enabled: bool, data: &str) -> Option<Value> {
    if t != Kind::AdminTwoStep {
        return effect(enabled, data);
    }
    enabled.then(|| {
        if everyone_option(data) {
            json!({ "everyone": true })
        } else {
            json!({})
        }
    })
}

/// A policy as the console reads it: on or off, with its options.
fn policy_json(t: Kind, enabled: bool, data: Option<&str>) -> Value {
    json!({
        "type": t.as_i32(),
        "enabled": enabled,
        "data": data.and_then(|d| serde_json::from_str::<Value>(d).ok()).unwrap_or(Value::Null),
    })
}

/// An MSP's defaults by policy type. A type without one is off.
async fn defaults(msp_id: &MspId, conn: &DbConn) -> HashMap<i32, MspPolicy> {
    MspPolicy::find_by_msp(msp_id, conn).await.into_iter().map(|p| (p.atype, p)).collect()
}

fn default_effect(defaults: &HashMap<i32, MspPolicy>, t: Kind) -> Option<Value> {
    defaults.get(&t.as_i32()).and_then(|p| kind_effect(t, p.enabled, &p.data))
}

/// The defaults the MSP requires for every client, in the console's order.
fn required_kinds(defaults: &HashMap<i32, MspPolicy>) -> Vec<Kind> {
    OFFERED.into_iter().filter(|t| defaults.get(&t.as_i32()).is_some_and(|p| p.required)).collect()
}

/// A policy the MSP requires, or one a required policy needs, which nobody
/// changes in a client (refuse_if_required).
fn locked_kinds(defaults: &HashMap<i32, MspPolicy>) -> Vec<(Kind, Option<Kind>)> {
    let required = required_kinds(defaults);
    let mut locked: Vec<(Kind, Option<Kind>)> = required.iter().map(|t| (*t, None)).collect();
    for t in &required {
        for needed in prerequisites(*t) {
            if !locked.iter().any(|(l, _)| *l == needed) {
                locked.push((needed, Some(*t)));
            }
        }
    }
    locked
}

/// A client's MSP, if it requires any policy for every client, and its defaults.
struct Requirement {
    msp: Msp,
    defaults: HashMap<i32, MspPolicy>,
}

impl Requirement {
    async fn of(org_id: &OrganizationId, conn: &DbConn) -> Option<Self> {
        let client = MspClient::find_by_org(org_id, conn).await?;
        let defaults = defaults(&client.msp_uuid, conn).await;
        if !defaults.values().any(|p| p.required) {
            return None;
        }
        let msp = Msp::find_by_uuid(&client.msp_uuid, conn).await?;
        Some(Self {
            msp,
            defaults,
        })
    }
}

/// What a client's people, and the MSP's own staff working in the client's
/// admin console, hear when they change a policy its MSP requires.
fn required_refusal(msp_name: &str) -> String {
    format!("{msp_name} requires this policy for every client, so it can only be changed in {msp_name}'s console.")
}

/// Refuses changing a policy in a client whose MSP requires it for every
/// client, and turning off a policy that a required one needs, whoever asks:
/// the client's own owners, a point of contact with the policies permission,
/// or the MSP's own staff in the client's admin console. Only changing the
/// required default in the MSP's console changes it. Every path that changes
/// a client's policy calls this first (upstream's policy endpoint and the
/// client's two-step login for admins), except the MSP's own defaults. A
/// refusal is a 400, never a 401 or 403, which sign the web vault out.
pub async fn refuse_if_required(org_id: &OrganizationId, pol_type: i32, enabled: bool, conn: &DbConn) -> EmptyResult {
    let Some(t) = Kind::from_i32(pol_type) else {
        return Ok(());
    };
    let Some(requirement) = Requirement::of(org_id, conn).await else {
        return Ok(());
    };
    let name = &requirement.msp.name;
    let required = required_kinds(&requirement.defaults);
    if required.contains(&t) {
        err!(required_refusal(name))
    }
    if !enabled && let Some(needs) = required.iter().find(|r| prerequisites(**r).contains(&t)) {
        err!(format!(
            "{name} requires {} for every client, which needs this policy on, so it can only be changed in {name}'s console.",
            policy_name(*needs)
        ))
    }
    Ok(())
}

/// The name of the MSP that keeps a client's admin console from changing
/// this policy, if one does: it requires the policy for every client, or
/// requires one that needs it.
pub async fn locked_by(org_id: &OrganizationId, pol_type: i32, conn: &DbConn) -> Option<String> {
    let t = Kind::from_i32(pol_type)?;
    let requirement = Requirement::of(org_id, conn).await?;
    locked_kinds(&requirement.defaults).iter().any(|(l, _)| *l == t).then_some(requirement.msp.name)
}

/// Whether a client's admin console can't change this policy (locked_by).
/// Upstream's policy dialog reads this as canToggleState and doesn't let
/// anyone save it.
pub async fn is_locked(org_id: &OrganizationId, pol_type: i32, conn: &DbConn) -> bool {
    locked_by(org_id, pol_type, conn).await.is_some()
}

/// What a client has now for each kind of default: its upstream policies, and
/// whom it requires two-step login of (its admins, or everyone).
struct ClientPolicies {
    policies: Vec<OrgPolicy>,
    admin_two_step: TwoStepScope,
}

impl ClientPolicies {
    async fn of(org_id: &OrganizationId, conn: &DbConn) -> ApiResult<Self> {
        Ok(Self {
            policies: OrgPolicy::find_by_org(org_id, conn).await,
            admin_two_step: OrgAdminTwoStep::scope(org_id, conn).await?,
        })
    }

    /// On or off, with its options.
    fn state(&self, t: Kind) -> (bool, Option<&str>) {
        match t {
            Kind::Policy(t) => {
                self.policies.iter().find(|p| p.atype == t as i32).map_or((false, None), |p| (p.enabled, Some(&p.data)))
            }
            Kind::AdminTwoStep => (self.admin_two_step.required(), self.admin_two_step.everyone().then_some(EVERYONE)),
        }
    }

    fn effect(&self, t: Kind) -> Option<Value> {
        let (enabled, data) = self.state(t);
        kind_effect(t, enabled, data.unwrap_or("null"))
    }

    /// Whether this kind differs from the default: its own setting.
    fn is_own(&self, defaults: &HashMap<i32, MspPolicy>, t: Kind) -> bool {
        self.effect(t) != default_effect(defaults, t)
    }
}

/// The policies offered where a client has its own setting, with their names.
/// A required policy is never a client's own: where it differs, the client
/// isn't in step yet.
pub(super) async fn own_policies(msp_id: &MspId, org_id: &OrganizationId, conn: &DbConn) -> ApiResult<Vec<Value>> {
    let defaults = defaults(msp_id, conn).await;
    let current = ClientPolicies::of(org_id, conn).await?;
    let required = required_kinds(&defaults);
    Ok(offered()
        .into_iter()
        .filter(|t| !required.contains(t) && current.is_own(&defaults, *t))
        .map(|t| json!({ "type": t.as_i32(), "name": policy_name(t) }))
        .collect())
}

/// For whoever can open a client's Policies page (its owners and admins, and
/// custom roles that manage policies): its MSP, the policies the MSP requires
/// for every client and any they need on, which nobody changes there, and the
/// policies where the client has its own setting. Anyone else gets "not
/// found": upstream's web vault signs out on 403. Not a client of an MSP:
/// nothing.
#[get("/keykeeper/organizations/<org_id>/msp-policies")]
async fn get_client_policies(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(member) = Membership::find_confirmed_by_user_and_org(&headers.user.uuid, &org_id, &conn).await else {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    };
    let manages = member.atype == MembershipType::Owner as i32
        || member.atype == MembershipType::Admin as i32
        || keykeeper_roles::find(&member.uuid, &conn).await.is_some_and(|c| c.has(Permission::ManagePolicies));
    if !manages {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    }
    let nothing = json!({ "msp": null, "required": [], "own": [] });
    let Some(client) = MspClient::find_by_org(&org_id, &conn).await else {
        return Ok(Json(nothing));
    };
    let Some(msp) = Msp::find_by_uuid(&client.msp_uuid, &conn).await else {
        return Ok(Json(nothing));
    };
    let defaults = defaults(&msp.uuid, &conn).await;
    let required: Vec<Value> = locked_kinds(&defaults)
        .into_iter()
        .map(|(t, needed_by)| {
            json!({
                "type": t.as_i32(),
                "name": policy_name(t),
                // A policy that a required one needs, rather than one required itself.
                "neededBy": needed_by.map(policy_name),
            })
        })
        .collect();
    Ok(Json(json!({
        "msp": { "id": msp.uuid, "name": msp.name },
        "required": required,
        "own": own_policies(&msp.uuid, &org_id, &conn).await?,
    })))
}

async fn client_effect(org_id: &OrganizationId, t: Kind, conn: &DbConn) -> ApiResult<Option<Value>> {
    Ok(ClientPolicies::of(org_id, conn).await?.effect(t))
}

/// Sets one kind of default in a client: an upstream policy through
/// upstream's own policy code, as if the caller had saved it in the client's
/// admin console, or the client's two-step login for admins.
async fn set_in_client(
    org_id: &OrganizationId,
    t: Kind,
    data: PolicyData,
    headers: &Headers,
    conn: &DbConn,
) -> EmptyResult {
    match t {
        Kind::Policy(t) => {
            set_policy(org_id, t, data, &headers.user.uuid, headers.device.atype, &headers.ip.ip, conn).await?;
        }
        Kind::AdminTwoStep => {
            let everyone = data.data.as_ref().and_then(|d| d.get("everyone")).and_then(Value::as_bool) == Some(true);
            keykeeper_two_step::set_org_scope(
                org_id,
                TwoStepScope::of(data.enabled, everyone),
                &headers.user.uuid,
                headers.device.atype,
                &headers.ip.ip,
                conn,
            )
            .await?;
        }
    }
    Ok(())
}

/// Gives a client a default (off when there's none), as if the caller had
/// saved it in the client's admin console.
async fn apply(
    org_id: &OrganizationId,
    t: Kind,
    default: Option<&MspPolicy>,
    headers: &Headers,
    conn: &DbConn,
) -> EmptyResult {
    let data = PolicyData {
        enabled: default.is_some_and(|p| p.enabled),
        data: default.and_then(|p| serde_json::from_str::<Value>(&p.data).ok()),
    };
    set_in_client(org_id, t, data, headers, conn).await
}

fn client_json(org: &Organization) -> Value {
    json!({ "id": org.uuid, "name": org.name })
}

fn refused_json(org: &Organization, error: &crate::error::Error) -> Value {
    json!({ "id": org.uuid, "name": org.name, "error": error.message() })
}

fn clients_phrase(count: usize) -> String {
    if count == 1 {
        "1 client".to_owned()
    } else {
        format!("{count} clients")
    }
}

/// A new MSP's defaults: the Business preset.
pub(super) async fn seed_defaults(msp_id: &MspId, conn: &DbConn) -> EmptyResult {
    for (t, data) in business_policies() {
        MspPolicy::new(msp_id.clone(), t.as_i32(), true, data.to_string()).save(conn).await?;
    }
    Ok(())
}

/// Gives a new client the MSP's defaults that are on, or with `required_only`
/// (a client added without the default policies) only those the MSP requires
/// for every client and what they need. Single organization goes first, since
/// a server can require it before account recovery.
pub(super) async fn apply_defaults_to_new_client(
    msp_id: &MspId,
    org_id: &OrganizationId,
    required_only: bool,
    headers: &Headers,
    conn: &DbConn,
) -> EmptyResult {
    let defaults = defaults(msp_id, conn).await;
    let locked: Vec<i32> = locked_kinds(&defaults).into_iter().map(|(t, _)| t.as_i32()).collect();
    let mut on: Vec<MspPolicy> =
        defaults.into_values().filter(|p| p.enabled && (!required_only || locked.contains(&p.atype))).collect();
    on.sort_by_key(|p| (p.atype != OrgPolicyType::SingleOrg as i32, p.atype));
    for default in &on {
        if let Some(t) = Kind::from_i32(default.atype) {
            apply(org_id, t, Some(default), headers, conn).await?;
        }
    }
    Ok(())
}

/// Gives a company's own new organization the Business preset, through
/// upstream's own policy code, as if the caller had saved each policy in the
/// admin console. Single organization goes first, as for an MSP's client.
pub(super) async fn apply_business_preset(org_id: &OrganizationId, headers: &Headers, conn: &DbConn) -> EmptyResult {
    let mut preset = business_policies();
    preset.sort_by_key(|(t, _)| *t != Kind::Policy(OrgPolicyType::SingleOrg));
    for (t, options) in preset {
        let data = PolicyData {
            enabled: true,
            data: (!options.is_null()).then_some(options),
        };
        set_in_client(org_id, t, data, headers, conn).await?;
    }
    Ok(())
}

/// The MSP's defaults, which of them it requires for every client, and for
/// each client the caller reaches, the policies where it has its own setting,
/// and the required ones where it isn't in step (it refused the requirement).
/// For a required default, the clients the caller reaches that had their own
/// setting when it was required, and have the required setting now
/// (`hadOwn`).
#[get("/keykeeper/msp/<msp_id>/policies")]
async fn get_policies(msp_id: MspId, headers: Headers, conn: DbConn) -> JsonResult {
    let caller = staff_member(&msp_id, &headers.user.uuid, &conn).await?;
    let reach = caller.reach(&conn).await;
    let types = offered();
    let defaults = defaults(&msp_id, &conn).await;
    let required = required_kinds(&defaults);

    let mut orgs = Vec::new();
    for client in MspClient::find_by_msp(&msp_id, &conn).await {
        if reach.as_ref().is_some_and(|r| !r.contains(&client.org_uuid)) {
            continue;
        }
        if let Some(org) = Organization::find_by_uuid(&client.org_uuid, &conn).await {
            orgs.push(org);
        }
    }

    let mut clients = Vec::new();
    let mut behind = HashSet::new();
    for org in &orgs {
        let current = ClientPolicies::of(&org.uuid, &conn).await?;
        let (mut own, mut not_in_step) = (Vec::new(), Vec::new());
        for t in types.iter().filter(|t| current.is_own(&defaults, **t)) {
            let (enabled, data) = current.state(*t);
            if required.contains(t) {
                not_in_step.push(policy_json(*t, enabled, data));
                behind.insert((org.uuid.clone(), t.as_i32()));
            } else {
                own.push(policy_json(*t, enabled, data));
            }
        }
        clients.push(json!({ "id": org.uuid, "name": org.name, "own": own, "notInStep": not_in_step }));
    }

    let mut default_list = Vec::new();
    for t in &types {
        let default = defaults.get(&t.as_i32());
        let mut json = policy_json(*t, default.is_some_and(|p| p.enabled), default.map(|p| p.data.as_str()));
        json["required"] = json!(required.contains(t));
        if required.contains(t) {
            // A client that never took it still has its own setting: nothing to go back to.
            let had_own = MspRequiredHadOwn::find(&msp_id, t.as_i32(), &conn).await;
            json["hadOwn"] = orgs
                .iter()
                .filter(|o| had_own.contains(&o.uuid) && !behind.contains(&(o.uuid.clone(), t.as_i32())))
                .map(client_json)
                .collect();
        }
        default_list.push(json);
    }

    let prerequisites: Vec<Value> = types
        .iter()
        .filter_map(|t| {
            let needs = prerequisites(*t);
            (!needs.is_empty())
                .then(|| json!({ "type": t.as_i32(), "needs": needs.iter().map(|n| n.as_i32()).collect::<Vec<_>>() }))
        })
        .collect();

    Ok(Json(json!({
        "types": types.iter().map(|t| t.as_i32()).collect::<Vec<_>>(),
        "defaults": default_list,
        "prerequisites": prerequisites,
        "clients": clients,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DefaultPolicyData {
    enabled: bool,
    data: Option<Value>,
    /// Clients that follow the default but stay as they are this time; their
    /// policy then counts as their own setting. Never for a required default.
    #[serde(default)]
    keep: Vec<OrganizationId>,
    /// Required for every client, or a default clients follow unless one has
    /// its own setting. Left out, it stays as it is.
    required: Option<bool>,
}

fn had_own_phrase(count: usize) -> String {
    match count {
        0 => "no client had its own setting before".to_owned(),
        1 => "1 client had its own setting before".to_owned(),
        n => format!("{n} clients had their own setting before"),
    }
}

/// Changes one default, and with it every client that follows it, except
/// those the admin chose to keep as they are. Clients with their own setting
/// keep it. A client whose policy code refuses the change (for example a
/// server that needs single organization before account recovery) is named in
/// the response and keeps its policy, which then counts as its own setting.
///
/// A required default (`required`) reaches every client instead, those with
/// their own setting too, which are remembered as having had their own
/// setting (MspRequiredHadOwn). A client that refuses it is named, and shows
/// as not in step until it takes it (use_default tries again). It stays
/// required either way. Stopping requiring it changes no client: the
/// response lists the clients that had their own setting before and have the
/// required one now (`hadOwn`), and the MSP forgets them all.
#[put("/keykeeper/msp/<msp_id>/policies/<pol_type>", data = "<data>")]
async fn set_default(
    msp_id: MspId,
    pol_type: i32,
    headers: Headers,
    session: SessionFacts,
    data: Json<DefaultPolicyData>,
    conn: DbConn,
) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let t = offered_type(pol_type)?;
    let data = data.into_inner();
    let options = data.data.clone().unwrap_or(Value::Null);
    if !(options.is_null() || options.is_object()) {
        err!("Policy options must be an object")
    }
    // Two-step login for admins keeps its one option, and nothing else, so
    // its data stays null without it, as it always was.
    let options = if t == Kind::AdminTwoStep && everyone_option(&options.to_string()) {
        json!({ "everyone": true })
    } else if t == Kind::AdminTwoStep {
        Value::Null
    } else {
        options
    };
    // Only someone who meets two-step login for admins turns its default off,
    // or lowers it from everyone to admins.
    if t == Kind::AdminTwoStep {
        let was = admin_level(default_effect(&defaults(&msp_id, &conn).await, t).as_ref());
        let now = admin_level(kind_effect(t, data.enabled, &options.to_string()).as_ref());
        if !data.enabled || now < was {
            keykeeper_two_step::require_caller_meets(&headers.user, &session, &conn).await?;
        }
    }
    // Refused before it's kept, not by each client after.
    if t == Kind::Policy(OrgPolicyType::MaximumVaultTimeout) {
        super::keykeeper_vault_lock::check(&PolicyData {
            enabled: data.enabled,
            data: Some(options.clone()),
        })?;
    }
    let clients = MspClient::find_by_msp(&msp_id, &conn).await;
    if data.keep.iter().any(|org| !clients.iter().any(|c| &c.org_uuid == org)) {
        err!("Client not found")
    }

    let defaults = defaults(&msp_id, &conn).await;
    let was_required = defaults.get(&t.as_i32()).is_some_and(|p| p.required);
    let required = data.required.unwrap_or(was_required);
    if required {
        // Requiring a policy off would only stop clients from turning it on.
        if !data.enabled {
            err!("Only a policy that's on can be required for every client. Turn it on, or make it a default.")
        }
        if !data.keep.is_empty() {
            err!("A required policy reaches every client, so no client can keep what it has.")
        }
        // What it needs stays on in every client, so it must be on by default too.
        for needed in prerequisites(t) {
            if default_effect(&defaults, needed).is_none() {
                err!(format!(
                    "{} needs {}. Turn on the {} default first.",
                    policy_name(t),
                    policy_name(needed),
                    policy_name(needed)
                ))
            }
        }
    }
    if !data.enabled
        && let Some(needs) = required_kinds(&defaults).into_iter().find(|r| *r != t && prerequisites(*r).contains(&t))
    {
        err!(format!(
            "{} is required for every client and needs {}, so this default stays on.",
            policy_name(needs),
            policy_name(t)
        ))
    }

    let old = default_effect(&defaults, t);
    let mut default = MspPolicy::new(msp_id.clone(), t.as_i32(), data.enabled, options.to_string());
    default.required = required;
    let new = kind_effect(t, default.enabled, &default.data);
    default.save(&conn).await?;
    // Stopping requiring it: the clients that had their own setting before,
    // as the console listed them, and then they're forgotten.
    let had_own = if was_required && !required {
        let listed = MspRequiredHadOwn::find(&msp_id, t.as_i32(), &conn).await;
        MspRequiredHadOwn::clear(&msp_id, t.as_i32(), &conn).await?;
        Some(listed)
    } else {
        None
    };

    let (mut changed, mut kept, mut refused, mut listed) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for client in clients {
        let Some(org) = Organization::find_by_uuid(&client.org_uuid, &conn).await else {
            continue;
        };
        let current = client_effect(&org.uuid, t, &conn).await?;
        // Remembered as having had its own setting, and has the required one
        // now (one that never took it still has its own).
        if had_own.as_ref().is_some_and(|ids| ids.contains(&org.uuid)) && current == old {
            listed.push(client_json(&org));
        }
        if current == new {
            continue;
        }
        // Its own setting: or, while the default was required, a client that
        // isn't in step yet.
        let own = current != old;
        if !required && (own || data.keep.contains(&org.uuid)) {
            kept.push(client_json(&org));
            continue;
        }
        // Requiring it: the clients with their own setting are remembered,
        // whether they take it now or later, when it's tried again.
        if required && !was_required && own {
            MspRequiredHadOwn::record(&msp_id, t.as_i32(), &org.uuid, &conn).await?;
        }
        // Keykeeper: never in a client where the caller has no place of their
        // own, such as one that revoked them (keykeeper_offboarding.rs).
        if !super::keykeeper_offboarding::has_client_place(&org.uuid, &headers.user.uuid, true, &conn).await {
            refused.push(json!({
                "id": org.uuid,
                "name": org.name,
                "error": super::keykeeper_offboarding::client_place_refusal(&org.uuid, &conn).await,
            }));
            continue;
        }
        match apply(&org.uuid, t, Some(&default), &headers, &conn).await {
            Ok(()) => changed.push(client_json(&org)),
            Err(e) => refused.push(refused_json(&org, &e)),
        }
    }

    let mut outcome = vec![format!("{} changed", clients_phrase(changed.len()))];
    if !kept.is_empty() {
        outcome.push(if kept.len() == 1 {
            "1 client kept its own setting".to_owned()
        } else {
            format!("{} clients kept their own setting", kept.len())
        });
    }
    if !refused.is_empty() {
        outcome.push(format!("{} refused it", clients_phrase(refused.len())));
    }
    let outcome = outcome.join(", ");
    let name = policy_name(t);
    let stopped = was_required && !required;
    if required && !was_required {
        // High for security tools: it overrides what clients chose.
        Audit::by("default_policy_required", &headers)
            .detail(format!("{name} for every client: {outcome}"))
            .record(&msp_id, &conn)
            .await?;
    } else {
        if stopped {
            Audit::by("default_policy_unrequired", &headers)
                .detail(format!("{name} for every client: {}", had_own_phrase(listed.len())))
                .record(&msp_id, &conn)
                .await?;
        }
        // Stopping a requirement changes the default only if it changed too.
        if !stopped || old != new {
            let state = if !data.enabled {
                "off"
            } else if t == Kind::AdminTwoStep && admin_level(new.as_ref()).everyone() {
                "on for everyone"
            } else {
                "on"
            };
            // Two-step login for admins is a security setting, high for security tools.
            let action = if t == Kind::AdminTwoStep {
                "admin_two_step_default_set"
            } else {
                "default_policy_changed"
            };
            Audit::by(action, &headers).detail(format!("{name} to {state}: {outcome}")).record(&msp_id, &conn).await?;
        }
    }

    let mut result = json!({ "changed": changed, "kept": kept, "refused": refused });
    if had_own.is_some() {
        result["hadOwn"] = json!(listed);
    }
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UseDefaultData {
    clients: Vec<OrganizationId>,
}

/// Puts chosen clients back on the default for one policy, replacing their
/// own setting. For a required default, this tries again in clients that
/// aren't in step (they refused it).
#[post("/keykeeper/msp/<msp_id>/policies/<pol_type>/apply", data = "<data>")]
async fn use_default(
    msp_id: MspId,
    pol_type: i32,
    headers: Headers,
    session: SessionFacts,
    data: Json<UseDefaultData>,
    conn: DbConn,
) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let t = offered_type(pol_type)?;

    // Every client must be this MSP's before anything changes.
    let mut seen = HashSet::new();
    let mut orgs = Vec::new();
    for org_id in data.into_inner().clients {
        if !seen.insert(org_id.clone()) {
            continue;
        }
        let ours = MspClient::find_by_org(&org_id, &conn).await.is_some_and(|c| c.msp_uuid == msp_id);
        match Organization::find_by_uuid(&org_id, &conn).await {
            Some(org) if ours => orgs.push(org),
            _ => err!("Client not found"),
        }
    }
    if orgs.is_empty() {
        err!("Choose at least one client")
    }

    let defaults = defaults(&msp_id, &conn).await;
    let want = default_effect(&defaults, t);
    // Putting a client back on a default that lowers its two-step login for
    // admins (off, or admins only where it required everyone) takes someone
    // who meets it.
    if t == Kind::AdminTwoStep {
        let want_level = admin_level(want.as_ref());
        for org in &orgs {
            if OrgAdminTwoStep::scope(&org.uuid, &conn).await? > want_level {
                keykeeper_two_step::require_caller_meets(&headers.user, &session, &conn).await?;
                break;
            }
        }
    }
    let (mut changed, mut refused) = (Vec::new(), Vec::new());
    for org in &orgs {
        if client_effect(&org.uuid, t, &conn).await? == want {
            continue;
        }
        // Keykeeper: as in set_default.
        if !super::keykeeper_offboarding::has_client_place(&org.uuid, &headers.user.uuid, true, &conn).await {
            refused.push(json!({
                "id": org.uuid,
                "name": org.name,
                "error": super::keykeeper_offboarding::client_place_refusal(&org.uuid, &conn).await,
            }));
            continue;
        }
        match apply(&org.uuid, t, defaults.get(&t.as_i32()), &headers, &conn).await {
            Ok(()) => {
                Audit::by("client_policy_default", &headers)
                    .org(&org.uuid, &org.name)
                    .detail(policy_name(t))
                    .record(&msp_id, &conn)
                    .await?;
                changed.push(client_json(org));
            }
            Err(e) => refused.push(refused_json(org, &e)),
        }
    }

    Ok(Json(json!({ "changed": changed, "refused": refused })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{DbPool, models::MspRequiredHadOwn};

    async fn organization(name: &str, conn: &DbConn) -> Organization {
        let org = Organization::new(name.to_owned(), "billing@example.test", None, None);
        org.save(conn).await.unwrap();
        org
    }

    /// An MSP with one client, and a default for two-step login.
    async fn msp_with_client(required: bool, conn: &DbConn) -> (Msp, Organization) {
        let msp = Msp::new("Northwind IT".to_owned());
        msp.insert(conn).await.unwrap();
        let org = organization("Acme Dental", conn).await;
        // As keykeeper_offboarding's tests make one: MspClient::new seals an
        // install token with the server's keys, which tests don't load.
        MspClient {
            org_uuid: org.uuid.clone(),
            msp_uuid: msp.uuid.clone(),
            created_at: chrono::Utc::now().naive_utc(),
            preset: None,
            enrollment_token: None,
            enrollment_token_created_at: None,
            everyone_collection: None,
            templates_collection: None,
            enrollment_secret: None,
            enrollment_token_hash: None,
            client_seal: None,
        }
        .insert(conn)
        .await
        .unwrap();
        let mut default =
            MspPolicy::new(msp.uuid.clone(), OrgPolicyType::TwoFactorAuthentication as i32, true, "null".to_owned());
        default.required = required;
        default.save(conn).await.unwrap();
        (msp, org)
    }

    #[test]
    fn account_recovery_needs_single_organization_only_where_the_server_enforces_it() {
        let recovery = Kind::Policy(OrgPolicyType::ResetPassword);
        let single_org = Kind::Policy(OrgPolicyType::SingleOrg);
        assert!(prerequisites_where(recovery, true) == vec![single_org]);
        assert!(prerequisites_where(recovery, false).is_empty());
        for t in OFFERED.into_iter().filter(|t| *t != recovery) {
            assert!(prerequisites_where(t, true).is_empty(), "{}", t.as_i32());
        }
    }

    #[test]
    fn what_a_required_policy_needs_is_locked_too() {
        // Only where this server enforces it, which the tests' server doesn't.
        let mut defaults = HashMap::new();
        let mut recovery = MspPolicy::new(
            MspId::from("msp".to_owned()),
            OrgPolicyType::ResetPassword as i32,
            true,
            r#"{"autoEnrollEnabled":true}"#.to_owned(),
        );
        recovery.required = true;
        defaults.insert(recovery.atype, recovery);
        let locked = locked_kinds(&defaults);
        assert!(locked.iter().map(|(t, _)| *t).collect::<Vec<_>>() == required_kinds(&defaults));
        assert!(required_kinds(&defaults) == vec![Kind::Policy(OrgPolicyType::ResetPassword)]);
    }

    #[rocket::async_test]
    async fn a_required_policy_cant_be_changed_in_the_client_whoever_asks() {
        let conn = DbPool::for_test().await;
        let (msp, org) = msp_with_client(true, &conn).await;
        let two_step = OrgPolicyType::TwoFactorAuthentication as i32;

        // Turning it off or on again, as anyone in the client's admin console.
        for enabled in [false, true] {
            let refused = refuse_if_required(&org.uuid, two_step, enabled, &conn).await.unwrap_err();
            assert_eq!(
                refused.message(),
                "Northwind IT requires this policy for every client, so it can only be changed in Northwind IT's console."
            );
        }
        assert!(is_locked(&org.uuid, two_step, &conn).await);
        assert_eq!(locked_by(&org.uuid, two_step, &conn).await.as_deref(), Some(msp.name.as_str()));

        // Other policies, and organizations that aren't the MSP's clients.
        assert!(refuse_if_required(&org.uuid, OrgPolicyType::DisableSend as i32, true, &conn).await.is_ok());
        assert!(!is_locked(&org.uuid, OrgPolicyType::DisableSend as i32, &conn).await);
        let own = organization("Own Co", &conn).await;
        assert!(refuse_if_required(&own.uuid, two_step, false, &conn).await.is_ok());
        assert!(refuse_if_required(&org.uuid, 12_345, false, &conn).await.is_ok());
    }

    #[rocket::async_test]
    async fn a_default_that_isnt_required_leaves_the_client_free_to_change_it() {
        let conn = DbPool::for_test().await;
        let (_, org) = msp_with_client(false, &conn).await;
        let two_step = OrgPolicyType::TwoFactorAuthentication as i32;
        assert!(refuse_if_required(&org.uuid, two_step, false, &conn).await.is_ok());
        assert!(!is_locked(&org.uuid, two_step, &conn).await);
    }

    #[rocket::async_test]
    async fn a_client_that_leaves_its_msp_is_no_longer_bound_or_remembered() {
        let conn = DbPool::for_test().await;
        let (msp, org) = msp_with_client(true, &conn).await;
        let two_step = OrgPolicyType::TwoFactorAuthentication as i32;
        MspRequiredHadOwn::record(&msp.uuid, two_step, &org.uuid, &conn).await.unwrap();
        // Recording twice keeps one.
        MspRequiredHadOwn::record(&msp.uuid, two_step, &org.uuid, &conn).await.unwrap();
        assert_eq!(MspRequiredHadOwn::find(&msp.uuid, two_step, &conn).await, vec![org.uuid.clone()]);

        MspClient::find_by_org(&org.uuid, &conn).await.unwrap().delete(&conn).await.unwrap();
        assert!(refuse_if_required(&org.uuid, two_step, false, &conn).await.is_ok());
        assert!(MspRequiredHadOwn::find(&msp.uuid, two_step, &conn).await.is_empty());
    }

    #[rocket::async_test]
    async fn stopping_a_requirement_forgets_who_had_their_own_setting() {
        let conn = DbPool::for_test().await;
        let (msp, org) = msp_with_client(true, &conn).await;
        let two_step = OrgPolicyType::TwoFactorAuthentication as i32;
        MspRequiredHadOwn::record(&msp.uuid, two_step, &org.uuid, &conn).await.unwrap();
        MspRequiredHadOwn::record(&msp.uuid, OrgPolicyType::DisableSend as i32, &org.uuid, &conn).await.unwrap();
        MspRequiredHadOwn::clear(&msp.uuid, two_step, &conn).await.unwrap();
        assert!(MspRequiredHadOwn::find(&msp.uuid, two_step, &conn).await.is_empty());
        // Only for that policy.
        assert_eq!(MspRequiredHadOwn::find(&msp.uuid, OrgPolicyType::DisableSend as i32, &conn).await.len(), 1);
    }

    #[test]
    fn off_policies_do_the_same_whatever_their_options() {
        assert_eq!(effect(false, r#"{"minLength":12}"#), None);
        assert_eq!(effect(false, "null"), effect(false, "{}"));
    }

    #[test]
    fn missing_empty_and_null_options_are_the_same() {
        assert_eq!(effect(true, "null"), Some(json!({})));
        assert_eq!(effect(true, "{}"), Some(json!({})));
        assert_eq!(effect(true, "not json"), Some(json!({})));
        assert_eq!(effect(true, r#"{"minLength":12,"minComplexity":null}"#), effect(true, r#"{"minLength":12}"#));
    }

    #[test]
    fn on_and_off_or_different_options_differ() {
        assert_ne!(effect(true, "null"), effect(false, "null"));
        assert_ne!(effect(true, r#"{"minLength":12}"#), effect(true, r#"{"minLength":14}"#));
        assert_eq!(
            effect(true, r#"{"minLength":12,"requireUpper":false}"#),
            effect(true, r#"{"requireUpper":false,"minLength":12}"#)
        );
    }

    #[test]
    fn two_step_login_for_admins_has_one_option_everyone_else_too() {
        let t = Kind::AdminTwoStep;
        // Left out, false, null, or anything else: admins only.
        for data in ["null", "{}", r#"{"everyone":false}"#, r#"{"everyone":null}"#, r#"{"other":1}"#, "not json"] {
            assert_eq!(kind_effect(t, true, data), Some(json!({})), "{data}");
            assert_eq!(admin_level(kind_effect(t, true, data).as_ref()), TwoStepScope::Admins, "{data}");
        }
        assert_eq!(kind_effect(t, true, EVERYONE), Some(json!({ "everyone": true })));
        assert_eq!(admin_level(kind_effect(t, true, EVERYONE).as_ref()), TwoStepScope::Everyone);
        assert_ne!(kind_effect(t, true, EVERYONE), kind_effect(t, true, "null"));
        // Off is off, whatever it says.
        assert_eq!(kind_effect(t, false, EVERYONE), None);
        assert_eq!(admin_level(None), TwoStepScope::Off);
        // A client's setting reads as the default's would.
        let client = |scope| ClientPolicies {
            policies: Vec::new(),
            admin_two_step: scope,
        };
        assert_eq!(client(TwoStepScope::Everyone).effect(t), kind_effect(t, true, EVERYONE));
        assert_eq!(client(TwoStepScope::Admins).effect(t), kind_effect(t, true, "null"));
        assert_eq!(client(TwoStepScope::Admins).state(t), (true, None));
        assert_eq!(client(TwoStepScope::Off).effect(t), None);
        // Upstream's policies keep their own options as they are.
        let p = Kind::Policy(OrgPolicyType::MasterPassword);
        assert_eq!(kind_effect(p, true, r#"{"minLength":12}"#), effect(true, r#"{"minLength":12}"#));
    }

    #[test]
    fn the_business_preset_matches_the_migration() {
        // MSPs from before default policies got these from the migrations.
        let migrated = [
            (OrgPolicyType::ResetPassword, r#"{"autoEnrollEnabled":true}"#),
            (OrgPolicyType::SingleOrg, "null"),
            (
                OrgPolicyType::MasterPassword,
                r#"{"minComplexity":3,"minLength":12,"requireUpper":false,"requireLower":false,"requireNumbers":false,"requireSpecial":false,"enforceOnLogin":false}"#,
            ),
            // keykeeper_msp_vault_lock.
            (OrgPolicyType::MaximumVaultTimeout, r#"{"type":"onSystemLock","minutes":null,"action":"lock"}"#),
        ];
        // Every upstream policy in the preset is one the migrations gave, with
        // the same options. Two-step login for admins came after them, with
        // no MSPs to migrate, so it's the one thing they don't have.
        let preset = business_policies();
        let policies: Vec<_> = preset
            .iter()
            .filter_map(|(t, data)| match t {
                Kind::Policy(t) => Some((*t, data)),
                Kind::AdminTwoStep => None,
            })
            .collect();
        assert_eq!(policies.len(), migrated.len());
        for ((t, data), (mt, mdata)) in policies.iter().zip(migrated) {
            assert!(*t == mt);
            assert_eq!(effect(true, &data.to_string()), effect(true, mdata));
        }
        assert_eq!(preset.iter().filter(|(t, _)| *t == Kind::AdminTwoStep).count(), 1);
        assert_eq!(preset.len(), migrated.len() + 1);
    }

    #[test]
    fn two_step_login_for_admins_is_a_default_upstream_never_sees_as_a_policy() {
        assert!(OrgPolicyType::from_i32(ADMIN_TWO_STEP).is_none());
        assert!(Kind::from_i32(ADMIN_TWO_STEP) == Some(Kind::AdminTwoStep));
        assert_eq!(Kind::AdminTwoStep.as_i32(), ADMIN_TWO_STEP);
        assert!(offered().contains(&Kind::AdminTwoStep));
        assert!(Kind::from_i32(OrgPolicyType::SingleOrg as i32) == Some(Kind::Policy(OrgPolicyType::SingleOrg)));
        // On in the Business preset, so in every new MSP's defaults and every
        // new Business organization.
        assert!(business_policies().iter().any(|(t, _)| *t == Kind::AdminTwoStep));
        assert_eq!(policy_name(Kind::AdminTwoStep), "Two-step login for admins");
    }
}

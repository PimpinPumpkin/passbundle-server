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
// admins (keykeeper_two_step). It's kept with the others under a type number
// upstream never uses (ADMIN_TWO_STEP), and a client's setting is its own row,
// never an upstream policy, since upstream's apps refuse every policy when one
// has a type they don't know.

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
            MspClient, MspId, MspPolicy, OrgAdminTwoStep, OrgPolicy, OrgPolicyType, Organization, OrganizationId,
        },
    },
};

use super::{
    keykeeper_msp::{Audit, require_admin, staff_member},
    keykeeper_two_step,
    organizations::{PolicyData, set_policy},
};

pub fn routes() -> Vec<Route> {
    routes![get_policies, set_default, use_default]
}

/// The type number of the default that isn't an upstream policy: two-step
/// login for each client's admins (keykeeper_two_step). Upstream's policy
/// types are small numbers; this one is never sent to the apps as a policy.
pub const ADMIN_TWO_STEP: i32 = 1000;

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
    defaults.get(&t.as_i32()).and_then(|p| effect(p.enabled, &p.data))
}

/// What a client has now for each kind of default: its upstream policies, and
/// whether it requires two-step login of its admins.
struct ClientPolicies {
    policies: Vec<OrgPolicy>,
    admin_two_step: bool,
}

impl ClientPolicies {
    async fn of(org_id: &OrganizationId, conn: &DbConn) -> ApiResult<Self> {
        Ok(Self {
            policies: OrgPolicy::find_by_org(org_id, conn).await,
            admin_two_step: OrgAdminTwoStep::required(org_id, conn).await?,
        })
    }

    /// On or off, with its options.
    fn state(&self, t: Kind) -> (bool, Option<&str>) {
        match t {
            Kind::Policy(t) => {
                self.policies.iter().find(|p| p.atype == t as i32).map_or((false, None), |p| (p.enabled, Some(&p.data)))
            }
            Kind::AdminTwoStep => (self.admin_two_step, None),
        }
    }

    fn effect(&self, t: Kind) -> Option<Value> {
        let (enabled, data) = self.state(t);
        effect(enabled, data.unwrap_or("null"))
    }

    /// Whether this kind differs from the default: its own setting.
    fn is_own(&self, defaults: &HashMap<i32, MspPolicy>, t: Kind) -> bool {
        self.effect(t) != default_effect(defaults, t)
    }
}

/// The policies offered where a client has its own setting, with their names.
pub(super) async fn own_policies(msp_id: &MspId, org_id: &OrganizationId, conn: &DbConn) -> ApiResult<Vec<Value>> {
    let defaults = defaults(msp_id, conn).await;
    let current = ClientPolicies::of(org_id, conn).await?;
    Ok(offered()
        .into_iter()
        .filter(|t| current.is_own(&defaults, *t))
        .map(|t| json!({ "type": t.as_i32(), "name": policy_name(t) }))
        .collect())
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
            keykeeper_two_step::set_org_required(
                org_id,
                data.enabled,
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

/// Gives a new client the MSP's defaults that are on. Single organization goes
/// first, since a server can require it before account recovery.
pub(super) async fn apply_defaults_to_new_client(
    msp_id: &MspId,
    org_id: &OrganizationId,
    headers: &Headers,
    conn: &DbConn,
) -> EmptyResult {
    let mut on: Vec<MspPolicy> = MspPolicy::find_by_msp(msp_id, conn).await.into_iter().filter(|p| p.enabled).collect();
    on.sort_by_key(|p| p.atype != OrgPolicyType::SingleOrg as i32);
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

/// The MSP's defaults, and for each client the caller reaches, the policies
/// where it has its own setting.
#[get("/keykeeper/msp/<msp_id>/policies")]
async fn get_policies(msp_id: MspId, headers: Headers, conn: DbConn) -> JsonResult {
    let caller = staff_member(&msp_id, &headers.user.uuid, &conn).await?;
    let reach = caller.reach(&conn).await;
    let types = offered();
    let defaults = defaults(&msp_id, &conn).await;

    let default_list: Vec<Value> = types
        .iter()
        .map(|t| {
            let default = defaults.get(&t.as_i32());
            policy_json(*t, default.is_some_and(|p| p.enabled), default.map(|p| p.data.as_str()))
        })
        .collect();

    let mut clients = Vec::new();
    for client in MspClient::find_by_msp(&msp_id, &conn).await {
        if reach.as_ref().is_some_and(|r| !r.contains(&client.org_uuid)) {
            continue;
        }
        let Some(org) = Organization::find_by_uuid(&client.org_uuid, &conn).await else {
            continue;
        };
        let current = ClientPolicies::of(&org.uuid, &conn).await?;
        let mut own = Vec::new();
        for t in types.iter().filter(|t| current.is_own(&defaults, **t)) {
            let (enabled, data) = current.state(*t);
            own.push(policy_json(*t, enabled, data));
        }
        clients.push(json!({ "id": org.uuid, "name": org.name, "own": own }));
    }

    Ok(Json(json!({
        "types": types.iter().map(|t| t.as_i32()).collect::<Vec<_>>(),
        "defaults": default_list,
        "clients": clients,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DefaultPolicyData {
    enabled: bool,
    data: Option<Value>,
    /// Clients that follow the default but stay as they are this time; their
    /// policy then counts as their own setting.
    #[serde(default)]
    keep: Vec<OrganizationId>,
}

/// Changes one default, and with it every client that follows it, except
/// those the admin chose to keep as they are. Clients with their own setting
/// keep it. A client whose policy code refuses the change (for example a
/// server that needs single organization before account recovery) is named in
/// the response and keeps its policy, which then counts as its own setting.
#[put("/keykeeper/msp/<msp_id>/policies/<pol_type>", data = "<data>")]
async fn set_default(
    msp_id: MspId,
    pol_type: i32,
    headers: Headers,
    data: Json<DefaultPolicyData>,
    conn: DbConn,
) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let t = offered_type(pol_type)?;
    let data = data.into_inner();
    let options = data.data.unwrap_or(Value::Null);
    if !(options.is_null() || options.is_object()) {
        err!("Policy options must be an object")
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

    let old = default_effect(&defaults(&msp_id, &conn).await, t);
    let default = MspPolicy::new(msp_id.clone(), t.as_i32(), data.enabled, options.to_string());
    let new = effect(default.enabled, &default.data);
    default.save(&conn).await?;

    let (mut changed, mut kept, mut refused) = (Vec::new(), Vec::new(), Vec::new());
    for client in clients {
        let Some(org) = Organization::find_by_uuid(&client.org_uuid, &conn).await else {
            continue;
        };
        let current = client_effect(&org.uuid, t, &conn).await?;
        if current == new {
            continue;
        }
        if current != old || data.keep.contains(&org.uuid) {
            kept.push(client_json(&org));
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
    let state = if data.enabled {
        "on"
    } else {
        "off"
    };
    let detail = format!("{} to {state}: {}", policy_name(t), outcome.join(", "));
    // Two-step login for admins is a security setting, high for security tools.
    let action = if t == Kind::AdminTwoStep {
        "admin_two_step_default_set"
    } else {
        "default_policy_changed"
    };
    Audit::by(action, &headers).detail(detail).record(&msp_id, &conn).await?;

    Ok(Json(json!({ "changed": changed, "kept": kept, "refused": refused })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UseDefaultData {
    clients: Vec<OrganizationId>,
}

/// Puts chosen clients back on the default for one policy, replacing their
/// own setting.
#[post("/keykeeper/msp/<msp_id>/policies/<pol_type>/apply", data = "<data>")]
async fn use_default(
    msp_id: MspId,
    pol_type: i32,
    headers: Headers,
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
    let (mut changed, mut refused) = (Vec::new(), Vec::new());
    for org in &orgs {
        if client_effect(&org.uuid, t, &conn).await? == want {
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

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

use std::collections::{HashMap, HashSet};

use num_traits::FromPrimitive;
use rocket::{Route, serde::json::Json};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult},
    auth::Headers,
    db::{
        DbConn,
        models::{MspClient, MspId, MspPolicy, OrgPolicy, OrgPolicyType, Organization, OrganizationId},
    },
};

use super::{
    keykeeper_msp::{Audit, require_admin, staff_member},
    organizations::{PolicyData, set_policy},
};

pub fn routes() -> Vec<Route> {
    routes![get_policies, set_default, use_default]
}

/// The policies an MSP can set defaults for: every upstream policy this server
/// supports, in the order the admin console lists them.
const OFFERED: [OrgPolicyType; 13] = [
    OrgPolicyType::TwoFactorAuthentication,
    OrgPolicyType::MasterPassword,
    OrgPolicyType::RemoveUnlockWithPin,
    OrgPolicyType::MaximumVaultTimeout,
    OrgPolicyType::ResetPassword,
    OrgPolicyType::PasswordGenerator,
    OrgPolicyType::SingleOrg,
    OrgPolicyType::PersonalOwnership,
    OrgPolicyType::DisableSend,
    OrgPolicyType::SendOptions,
    OrgPolicyType::RestrictedItemTypes,
    OrgPolicyType::UriMatchDefaults,
    OrgPolicyType::OrganizationUserNotification,
];

/// The policies offered on this server. Account recovery needs email, since a
/// member must be told when an admin resets their password.
fn offered() -> Vec<OrgPolicyType> {
    OFFERED.into_iter().filter(|t| *t != OrgPolicyType::ResetPassword || CONFIG.mail_enabled()).collect()
}

fn offered_type(pol_type: i32) -> Result<OrgPolicyType, crate::error::Error> {
    match OrgPolicyType::from_i32(pol_type) {
        Some(t) if offered().contains(&t) => Ok(t),
        _ => err!("Invalid or unsupported policy type"),
    }
}

/// A policy's name as the admin console shows it, for the audit log and a
/// client's owners.
fn policy_name(t: OrgPolicyType) -> &'static str {
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
    }
}

/// The Business preset's policies, which a new MSP's defaults start as. See
/// DESIGN.md, "Defaults (Business preset)". The keykeeper_msp_policies and
/// keykeeper_msp_vault_lock migrations gave MSPs that already existed the same.
fn business_policies() -> Vec<(OrgPolicyType, Value)> {
    vec![
        // Account recovery, with automatic enrollment: a member who forgets
        // their master password can be let back in by an owner or admin.
        (OrgPolicyType::ResetPassword, json!({ "autoEnrollEnabled": true })),
        // Single organization: members can't also belong to another
        // organization with the same account. Recovery opens a member's whole
        // account, so without this a client's admins could recover their way
        // into a member's family organization. Personal items go in a separate
        // personal account. MSP staff are exempt (see
        // exempt_from_member_policies), so they still reach every client.
        (OrgPolicyType::SingleOrg, Value::Null),
        // A strong master password: at least 12 characters and a strength
        // score of 3 out of 4. Existing passwords aren't forced to change.
        (
            OrgPolicyType::MasterPassword,
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
        (OrgPolicyType::MaximumVaultTimeout, json!({ "type": "onSystemLock", "minutes": null, "action": "lock" })),
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
fn policy_json(t: OrgPolicyType, enabled: bool, data: Option<&str>) -> Value {
    json!({
        "type": t as i32,
        "enabled": enabled,
        "data": data.and_then(|d| serde_json::from_str::<Value>(d).ok()).unwrap_or(Value::Null),
    })
}

/// An MSP's defaults by policy type. A type without one is off.
async fn defaults(msp_id: &MspId, conn: &DbConn) -> HashMap<i32, MspPolicy> {
    MspPolicy::find_by_msp(msp_id, conn).await.into_iter().map(|p| (p.atype, p)).collect()
}

fn default_effect(defaults: &HashMap<i32, MspPolicy>, t: OrgPolicyType) -> Option<Value> {
    defaults.get(&(t as i32)).and_then(|p| effect(p.enabled, &p.data))
}

/// Whether a client's policy of one type differs from the default: its own setting.
fn is_own(policies: &[OrgPolicy], defaults: &HashMap<i32, MspPolicy>, t: OrgPolicyType) -> bool {
    let current = policies.iter().find(|p| p.atype == t as i32);
    current.and_then(|p| effect(p.enabled, &p.data)) != default_effect(defaults, t)
}

/// The policies offered where a client has its own setting, with their names.
pub(super) async fn own_policies(msp_id: &MspId, org_id: &OrganizationId, conn: &DbConn) -> Vec<Value> {
    let defaults = defaults(msp_id, conn).await;
    let policies = OrgPolicy::find_by_org(org_id, conn).await;
    offered()
        .into_iter()
        .filter(|t| is_own(&policies, &defaults, *t))
        .map(|t| json!({ "type": t as i32, "name": policy_name(t) }))
        .collect()
}

async fn client_effect(org_id: &OrganizationId, t: OrgPolicyType, conn: &DbConn) -> Option<Value> {
    OrgPolicy::find_by_org_and_type(org_id, t, conn).await.and_then(|p| effect(p.enabled, &p.data))
}

/// Gives a client a default (off when there's none) through upstream's own
/// policy code, as if the caller had saved it in the client's admin console.
async fn apply(
    org_id: &OrganizationId,
    t: OrgPolicyType,
    default: Option<&MspPolicy>,
    headers: &Headers,
    conn: &DbConn,
) -> EmptyResult {
    let data = PolicyData {
        enabled: default.is_some_and(|p| p.enabled),
        data: default.and_then(|p| serde_json::from_str::<Value>(&p.data).ok()),
    };
    set_policy(org_id, t, data, &headers.user.uuid, headers.device.atype, &headers.ip.ip, conn).await.map(|_| ())
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
        MspPolicy::new(msp_id.clone(), t as i32, true, data.to_string()).save(conn).await?;
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
        if let Some(t) = OrgPolicyType::from_i32(default.atype) {
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
    preset.sort_by_key(|(t, _)| *t != OrgPolicyType::SingleOrg);
    for (t, options) in preset {
        let data = PolicyData {
            enabled: true,
            data: (!options.is_null()).then_some(options),
        };
        set_policy(org_id, t, data, &headers.user.uuid, headers.device.atype, &headers.ip.ip, conn).await?;
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
            let default = defaults.get(&(*t as i32));
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
        let policies = OrgPolicy::find_by_org(&org.uuid, &conn).await;
        let mut own = Vec::new();
        for t in types.iter().filter(|t| is_own(&policies, &defaults, **t)) {
            let current = policies.iter().find(|p| p.atype == *t as i32);
            own.push(policy_json(*t, current.is_some_and(|p| p.enabled), current.map(|p| p.data.as_str())));
        }
        clients.push(json!({ "id": org.uuid, "name": org.name, "own": own }));
    }

    Ok(Json(json!({
        "types": types.iter().map(|t| *t as i32).collect::<Vec<_>>(),
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
    if t == OrgPolicyType::MaximumVaultTimeout {
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
    let default = MspPolicy::new(msp_id.clone(), t as i32, data.enabled, options.to_string());
    let new = effect(default.enabled, &default.data);
    default.save(&conn).await?;

    let (mut changed, mut kept, mut refused) = (Vec::new(), Vec::new(), Vec::new());
    for client in clients {
        let Some(org) = Organization::find_by_uuid(&client.org_uuid, &conn).await else {
            continue;
        };
        let current = client_effect(&org.uuid, t, &conn).await;
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
    Audit::by("default_policy_changed", &headers).detail(detail).record(&msp_id, &conn).await?;

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
        if client_effect(&org.uuid, t, &conn).await == want {
            continue;
        }
        match apply(&org.uuid, t, defaults.get(&(t as i32)), &headers, &conn).await {
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
        let preset = business_policies();
        assert_eq!(preset.len(), migrated.len());
        for ((t, data), (mt, mdata)) in preset.iter().zip(migrated) {
            assert!(*t == mt);
            assert_eq!(effect(true, &data.to_string()), effect(true, mdata));
        }
    }
}

// Keykeeper: the MSP API, under /api/keykeeper. An MSP's staff are ordinary
// members of each client organization (MSP admins as owners, technicians as
// admins), so client work uses the upstream organization endpoints. These
// endpoints only keep that membership in step with the MSP's staff and
// clients. The server never handles a key it could decrypt with: new
// memberships wait to be confirmed by a member who holds the org key, which the
// MSP console does automatically. See DESIGN.md, "MSP console".
//
// Callers who aren't staff of an MSP get "not found", so MSPs can't be probed.
//
// Technicians can be limited to chosen clients, to a custom role inside them,
// and away from install commands. One function, sync_staff_memberships, keeps
// a staff member's client memberships in step with their role and access, so
// every change applies to all of their clients at once.

use std::collections::{HashMap, HashSet};

use rocket::{Route, serde::json::Json};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        EmptyResult, JsonResult,
        core::{keykeeper_msp_policies, keykeeper_two_step},
    },
    auth::Headers,
    db::{
        DbConn,
        models::{
            Collection, CustomRole, Membership, MembershipId, MembershipStatus, MembershipType, Msp, MspClient,
            MspEvent, MspId, MspInvite, MspMembership, MspRole, MspStaff, OrgSetup, Organization, OrganizationId,
            TechnicianAccess, User, UserId, effective_joining,
            keykeeper_roles::{self, CustomPermissions, Permission},
        },
    },
};

pub fn routes() -> Vec<Route> {
    routes![
        list_msps,
        create_msp,
        get_msp,
        create_client,
        add_staff,
        change_staff_role,
        set_staff_access,
        remove_staff,
        pending_confirmations,
        list_events,
        cancel_invite,
        invite_info,
        accept_invite,
        get_organization_msp,
        remove_organization_msp,
    ]
}

const MAX_NAME_LENGTH: usize = 100;

pub(super) fn clean_name(name: &str) -> Result<String, crate::error::Error> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_LENGTH {
        err!(format!("Name must be 1 to {MAX_NAME_LENGTH} characters"))
    }
    // Names go into email subjects and logs.
    if name.chars().any(char::is_control) {
        err!("Names can't contain line breaks or other control characters")
    }
    Ok(name.to_owned())
}

/// The caller's staff record in an MSP. Anyone who isn't staff gets "not found".
pub(super) async fn staff_member(
    msp_id: &MspId,
    user_id: &UserId,
    conn: &DbConn,
) -> Result<MspStaff, crate::error::Error> {
    match MspStaff::find(msp_id, user_id, conn).await {
        Some(staff) if staff.role().is_some() => Ok(staff),
        _ => err_code!("MSP not found", rocket::http::Status::NotFound.code),
    }
}

/// The caller's role in an MSP. Anyone who isn't staff gets "not found".
pub(super) async fn staff_role(
    msp_id: &MspId,
    user_id: &UserId,
    conn: &DbConn,
) -> Result<MspRole, crate::error::Error> {
    let Some(role) = staff_member(msp_id, user_id, conn).await?.role() else {
        err_code!("MSP not found", rocket::http::Status::NotFound.code)
    };
    Ok(role)
}

pub(super) async fn require_admin(msp_id: &MspId, user_id: &UserId, conn: &DbConn) -> EmptyResult {
    match staff_role(msp_id, user_id, conn).await? {
        MspRole::Admin => Ok(()),
        MspRole::Technician => err_code!("Only MSP admins can do this", rocket::http::Status::Forbidden.code),
    }
}

/// Whether a membership came from an MSP. MSP staff are never part of a
/// client's account recovery: recovery lets the client's admins reset the
/// staff member's master password and take over their account, which can see
/// every other client of the MSP.
pub(super) async fn is_msp_membership(member_id: &MembershipId, conn: &DbConn) -> bool {
    MspMembership::find_by_membership(member_id, conn).await.is_some()
}

/// What an MSP's audit log records about one action. Names and emails are
/// copied in, so the entry stays readable after the account or organization
/// is deleted.
pub(super) struct Audit<'a> {
    pub event: &'static str,
    pub actor: Option<&'a User>,
    pub ip: Option<String>,
    pub org: Option<(&'a OrganizationId, &'a str)>,
    pub target_email: Option<&'a str>,
    pub detail: Option<String>,
}

impl<'a> Audit<'a> {
    pub fn by(event: &'static str, headers: &'a Headers) -> Self {
        Self {
            event,
            actor: Some(&headers.user),
            ip: Some(headers.ip.ip.to_string()),
            org: None,
            target_email: None,
            detail: None,
        }
    }

    pub fn org(mut self, id: &'a OrganizationId, name: &'a str) -> Self {
        self.org = Some((id, name));
        self
    }

    pub fn target(mut self, email: &'a str) -> Self {
        self.target_email = Some(email);
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub async fn record(self, msp_id: &MspId, conn: &DbConn) -> EmptyResult {
        let mut event = MspEvent::new(msp_id.clone(), self.event);
        event.actor_uuid = self.actor.map(|u| u.uuid.clone());
        event.actor_email = self.actor.map(|u| u.email.clone());
        event.ip = self.ip;
        event.org_uuid = self.org.map(|(id, _)| id.clone());
        event.org_name = self.org.map(|(_, name)| name.to_owned());
        event.target_email = self.target_email.map(str::to_owned);
        event.detail = self.detail;
        event.insert(conn).await
    }
}

/// Logs a confirmation in a client organization, called from upstream's
/// confirm. Nothing happens for organizations without an MSP.
pub(super) async fn record_member_confirmed(
    org_id: &OrganizationId,
    member_user_id: &UserId,
    headers_user: &User,
    ip: String,
    conn: &DbConn,
) -> EmptyResult {
    let Some(client) = MspClient::find_by_org(org_id, conn).await else {
        return Ok(());
    };
    let org_name = Organization::find_by_uuid(org_id, conn).await.map(|o| o.name).unwrap_or_default();
    let target = User::find_by_uuid(member_user_id, conn).await.map(|u| u.email).unwrap_or_default();
    Audit {
        event: "member_confirmed",
        actor: Some(headers_user),
        ip: Some(ip),
        org: Some((org_id, &org_name)),
        target_email: Some(&target),
        detail: None,
    }
    .record(&client.msp_uuid, conn)
    .await
}

/// The memberships this MSP created, as a set.
async fn msp_membership_ids(msp_id: &MspId, conn: &DbConn) -> HashSet<MembershipId> {
    MspMembership::find_by_msp(msp_id, conn).await.into_iter().map(|m| m.membership_uuid).collect()
}

/// What a staff member's membership looks like in each client they reach.
struct Grant {
    atype: MembershipType,
    /// Every vault item in the client.
    access_all: bool,
    custom: Option<CustomPermissions>,
}

impl Grant {
    /// MSP admins are owners. Technicians are admins, or regular members with
    /// their custom role and, if it includes them, every vault item.
    fn for_staff(staff: &MspStaff) -> Option<Self> {
        let role = staff.role()?;
        let custom = (role == MspRole::Technician).then(|| staff.custom_role()).flatten();
        Some(Self::with(role, custom))
    }

    /// The same, in one client: a technician's role there when it differs
    /// from their role in the rest (`roles`, from `MspStaff::client_roles`).
    fn for_staff_in(
        staff: &MspStaff,
        roles: &HashMap<OrganizationId, Option<CustomRole>>,
        client: &OrganizationId,
    ) -> Option<Self> {
        let role = staff.role()?;
        match roles.get(client) {
            Some(custom) if role == MspRole::Technician => Some(Self::with(role, custom.clone())),
            _ => Self::for_staff(staff),
        }
    }

    fn with(role: MspRole, custom: Option<CustomRole>) -> Self {
        match custom {
            None => Self {
                atype: role.membership_type(),
                access_all: true,
                custom: None,
            },
            Some(custom) => Self {
                atype: MembershipType::User,
                access_all: custom.vault_items,
                custom: Some(custom.permissions),
            },
        }
    }
}

/// Gives someone the MSP's access to one client: a new membership waiting to
/// be confirmed, recorded as the MSP's. Leaves any membership they already
/// have alone, since the client granted it.
async fn add_msp_membership(
    msp_id: &MspId,
    org_id: &OrganizationId,
    user_id: &UserId,
    grant: &Grant,
    invited_by: &str,
    conn: &DbConn,
) -> EmptyResult {
    if Membership::find_by_user_and_org(user_id, org_id, conn).await.is_some() {
        return Ok(());
    }
    let mut member = Membership::new(user_id.clone(), org_id.clone(), Some(invited_by.to_owned()));
    member.atype = grant.atype as i32;
    member.access_all = grant.access_all;
    member.status = MembershipStatus::Accepted as i32;
    member.save(conn).await?;
    MspMembership::new(member.uuid.clone(), msp_id.clone()).insert(conn).await?;
    if let Some(custom) = &grant.custom {
        keykeeper_roles::set(&member.uuid, Some(custom), conn).await?;
    }
    Ok(())
}

/// Brings someone's memberships in the MSP's clients in line with their role
/// and access, all at once: new memberships (waiting for the org key) in
/// clients they now reach, the right role and vault access in the rest, and
/// the MSP's memberships removed from clients they no longer reach.
/// Memberships a client granted itself are left alone.
async fn sync_staff_memberships(msp_id: &MspId, staff: &MspStaff, invited_by: &str, conn: &DbConn) -> EmptyResult {
    let reach = staff.reach(conn).await;
    let roles = staff.client_roles(conn).await?;
    let ours = msp_membership_ids(msp_id, conn).await;
    for client in MspClient::find_by_msp(msp_id, conn).await {
        let Some(grant) = Grant::for_staff_in(staff, &roles, &client.org_uuid) else {
            return Ok(());
        };
        let reached = reach.as_ref().is_none_or(|r| r.contains(&client.org_uuid));
        match Membership::find_by_user_and_org(&staff.user_uuid, &client.org_uuid, conn).await {
            None if reached => {
                add_msp_membership(msp_id, &client.org_uuid, &staff.user_uuid, &grant, invited_by, conn).await?;
            }
            Some(mut member) if ours.contains(&member.uuid) => {
                if reached {
                    member.atype = grant.atype as i32;
                    member.access_all = grant.access_all;
                    member.save(conn).await?;
                    keykeeper_roles::set(&member.uuid, grant.custom.as_ref(), conn).await?;
                } else {
                    member.delete(conn).await?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Confirmed owners of an organization, other than one membership.
async fn other_confirmed_owners(org_id: &OrganizationId, except: &MembershipId, conn: &DbConn) -> usize {
    Membership::find_by_org(org_id, conn)
        .await
        .iter()
        .filter(|m| {
            &m.uuid != except
                && m.atype == MembershipType::Owner as i32
                && m.status == MembershipStatus::Confirmed as i32
        })
        .count()
}

/// Someone's MSP memberships in this MSP's clients.
async fn staff_memberships(msp_id: &MspId, user_id: &UserId, conn: &DbConn) -> Vec<Membership> {
    let ours = msp_membership_ids(msp_id, conn).await;
    let mut result = Vec::new();
    for client in MspClient::find_by_msp(msp_id, conn).await {
        if let Some(member) = Membership::find_by_user_and_org(user_id, &client.org_uuid, conn).await
            && ours.contains(&member.uuid)
        {
            result.push(member);
        }
    }
    result
}

/// Refuses a change that would leave a client with no confirmed owner.
async fn ensure_owners_remain(memberships: &[Membership], conn: &DbConn) -> EmptyResult {
    for member in memberships {
        let is_confirmed_owner =
            member.atype == MembershipType::Owner as i32 && member.status == MembershipStatus::Confirmed as i32;
        if is_confirmed_owner && other_confirmed_owners(&member.org_uuid, &member.uuid, conn).await == 0 {
            let name = Organization::find_by_uuid(&member.org_uuid, conn).await.map(|o| o.name).unwrap_or_default();
            err!(format!("{name} would have no owner. Make someone else an owner there first."))
        }
    }
    Ok(())
}

#[get("/keykeeper/msp")]
async fn list_msps(headers: Headers, conn: DbConn) -> Json<Value> {
    let msps: Vec<Value> = Msp::find_by_staff_user(&headers.user.uuid, &conn)
        .await
        .into_iter()
        .filter_map(|(msp, staff)| {
            staff.role().map(|role| {
                json!({
                    "id": msp.uuid,
                    "name": msp.name,
                    "role": role.as_str(),
                })
            })
        })
        .collect();
    Json(json!({ "data": msps }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateMspData {
    name: String,
}

#[post("/keykeeper/msp", data = "<data>")]
async fn create_msp(headers: Headers, data: Json<CreateMspData>, conn: DbConn) -> JsonResult {
    if !CONFIG.msp_signups_allowed() {
        err_code!("This server doesn't allow creating MSPs", rocket::http::Status::Forbidden.code)
    }
    // Its staff come under two-step login for admins, on by default.
    let watch = keykeeper_two_step::Watch::user(&headers.user.uuid, &conn).await?;
    let msp = Msp::new(clean_name(&data.name)?);
    msp.insert(&conn).await?;
    MspStaff::new(msp.uuid.clone(), headers.user.uuid.clone(), MspRole::Admin).insert(&conn).await?;
    keykeeper_msp_policies::seed_defaults(&msp.uuid, &conn).await?;
    Audit::by("msp_created", &headers).detail(msp.name.clone()).record(&msp.uuid, &conn).await?;
    watch.settle(&conn).await?;
    Ok(Json(json!({ "id": msp.uuid, "name": msp.name, "role": MspRole::Admin.as_str() })))
}

/// The MSP, its staff, and its clients. A technician limited to chosen
/// clients sees only those. Only MSP admins see each technician's access;
/// technicians see their own.
#[get("/keykeeper/msp/<msp_id>")]
async fn get_msp(msp_id: MspId, headers: Headers, conn: DbConn) -> JsonResult {
    let caller = staff_member(&msp_id, &headers.user.uuid, &conn).await?;
    let role = caller.role().unwrap_or(MspRole::Technician);
    let is_admin = role == MspRole::Admin;
    let reach = caller.reach(&conn).await;
    let Some(msp) = Msp::find_by_uuid(&msp_id, &conn).await else {
        err_code!("MSP not found", rocket::http::Status::NotFound.code)
    };

    let mut staff = Vec::new();
    for member in MspStaff::find_by_msp(&msp_id, &conn).await {
        if let (Some(user), Some(member_role)) = (User::find_by_uuid(&member.user_uuid, &conn).await, member.role()) {
            let access = if is_admin && member_role == MspRole::Technician {
                json!(member.access(&conn).await?)
            } else {
                Value::Null
            };
            staff.push(json!({
                "userId": user.uuid,
                "email": user.email,
                "name": user.name,
                "role": member_role.as_str(),
                "access": access,
            }));
        }
    }

    // Member counts are the client's own people; the MSP's staff are left out.
    let ours = msp_membership_ids(&msp_id, &conn).await;
    let mut clients = Vec::new();
    for client in MspClient::find_by_msp(&msp_id, &conn).await {
        if reach.as_ref().is_some_and(|r| !r.contains(&client.org_uuid)) {
            continue;
        }
        let Some(org) = Organization::find_by_uuid(&client.org_uuid, &conn).await else {
            continue;
        };
        let (mut confirmed, mut accepted, mut invited, mut revoked) = (0, 0, 0, 0);
        let mut you = Value::Null;
        for member in Membership::find_by_org(&org.uuid, &conn).await {
            if member.user_uuid == headers.user.uuid {
                you = json!({
                    "memberId": member.uuid,
                    "status": member.status,
                    "type": member.atype,
                    "vaultItems": member.has_full_access(),
                });
            }
            if ours.contains(&member.uuid) {
                continue;
            }
            match member.status {
                s if s == MembershipStatus::Confirmed as i32 => confirmed += 1,
                s if s == MembershipStatus::Accepted as i32 => accepted += 1,
                s if s == MembershipStatus::Invited as i32 => invited += 1,
                _ => revoked += 1,
            }
        }
        clients.push(json!({
            "id": org.uuid,
            "name": org.name,
            "preset": client.preset,
            "createdAt": crate::util::format_date(&client.created_at),
            "members": { "confirmed": confirmed, "accepted": accepted, "invited": invited, "revoked": revoked },
            "you": you,
            // Keykeeper: whether the client provisions from Entra, and its last sync.
            "provisioning": crate::db::models::ScimToken::find(&org.uuid, &conn).await.map(|t| json!({
                "lastUsedAt": t.last_used_at.as_ref().map(crate::util::format_date),
            })),
        }));
    }

    let invites: Vec<Value> = MspInvite::find_by_msp(&msp_id, &conn)
        .await
        .into_iter()
        .map(|i| {
            json!({
                "id": i.uuid,
                "email": i.email,
                "role": i.role().map(MspRole::as_str),
                "access": if is_admin { json!(i.access()) } else { Value::Null },
                "createdAt": crate::util::format_date(&i.created_at),
            })
        })
        .collect();

    let access = if is_admin {
        Value::Null
    } else {
        json!(caller.access(&conn).await?)
    };
    Ok(Json(json!({
        "id": msp.uuid,
        "name": msp.name,
        "role": role.as_str(),
        "access": access,
        "staff": staff,
        "invites": invites,
        "clients": clients,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientKeys {
    encrypted_private_key: String,
    public_key: String,
}

/// The preset a client started with: "business" is the MSP's default policies
/// and the Everyone and Admins collections. See DESIGN.md, "Default policies".
const BUSINESS_PRESET: &str = "business";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateClientData {
    name: String,
    billing_email: Option<String>,
    /// The default collection's name, encrypted with the new org key. With the
    /// Business preset, this is the "Everyone" collection.
    collection_name: String,
    /// With the Business preset: the "Admins" collection's name, encrypted with
    /// the new org key.
    admins_collection_name: Option<String>,
    /// "business" for the Business preset, or none.
    preset: Option<String>,
    /// The new org key, encrypted for the caller.
    key: String,
    keys: ClientKeys,
}

/// Creates a client organization, owned by the caller, with every other staff
/// member added and waiting to be confirmed.
#[post("/keykeeper/msp/<msp_id>/clients", data = "<data>")]
async fn create_client(msp_id: MspId, headers: Headers, data: Json<CreateClientData>, conn: DbConn) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    // Upstream's own checks for creating an organization.
    if !CONFIG.is_org_creation_allowed(&headers.user.email) {
        err!("User not allowed to create organizations")
    }
    if crate::db::models::OrgPolicy::is_applicable_to_user(
        &headers.user.uuid,
        crate::db::models::OrgPolicyType::SingleOrg,
        None,
        &conn,
    )
    .await
    {
        err!(
            "You may not create an organization. You belong to an organization which has a policy that prohibits you from being a member of any other organization."
        )
    }
    let data = data.into_inner();
    let name = clean_name(&data.name)?;
    // The staff it reaches may come under two-step login for admins there.
    let staff_ids = MspStaff::find_by_msp(&msp_id, &conn).await.into_iter().map(|s| s.user_uuid);
    let watch = keykeeper_two_step::Watch::users(staff_ids, &conn).await?;
    let business = match data.preset.as_deref() {
        None | Some("none") => false,
        Some(BUSINESS_PRESET) => true,
        Some(_) => err!("Preset must be business or none"),
    };
    let admins_collection = match (business, data.admins_collection_name) {
        (true, Some(admins)) => Some(admins),
        (true, None) => err!("The Business preset needs the Admins collection's name"),
        (false, _) => None,
    };
    let billing_email = data.billing_email.filter(|e| !e.trim().is_empty()).unwrap_or(headers.user.email.clone());

    let org =
        Organization::new(name, &billing_email, Some(data.keys.encrypted_private_key), Some(data.keys.public_key));
    let mut owner = Membership::new(headers.user.uuid.clone(), org.uuid.clone(), None);
    owner.akey = data.key;
    owner.access_all = true;
    owner.atype = MembershipType::Owner as i32;
    owner.status = MembershipStatus::Confirmed as i32;
    let collection = Collection::new(org.uuid.clone(), data.collection_name, None);

    org.save(&conn).await?;
    owner.save(&conn).await?;
    collection.save(&conn).await?;
    if let Some(admins) = admins_collection {
        Collection::new(org.uuid.clone(), admins, None).save(&conn).await?;
    }
    if business {
        keykeeper_msp_policies::apply_defaults_to_new_client(&msp_id, &org.uuid, &headers, &conn).await?;
    }
    MspClient::new(
        org.uuid.clone(),
        msp_id.clone(),
        business.then(|| BUSINESS_PRESET.to_owned()),
        business.then(|| collection.uuid.clone()),
    )
    .insert(&conn)
    .await?;
    MspMembership::new(owner.uuid.clone(), msp_id.clone()).insert(&conn).await?;

    // New clients reach MSP admins and technicians with every client.
    for staff in MspStaff::find_by_msp(&msp_id, &conn).await {
        if staff.user_uuid == headers.user.uuid || staff.reach(&conn).await.is_some() {
            continue;
        }
        if let Some(grant) = Grant::for_staff(&staff) {
            add_msp_membership(&msp_id, &org.uuid, &staff.user_uuid, &grant, &headers.user.email, &conn).await?;
        }
    }

    Audit::by("client_created", &headers)
        .org(&org.uuid, &org.name)
        .detail(if business {
            "Default policies"
        } else {
            "No defaults"
        })
        .record(&msp_id, &conn)
        .await?;
    watch.settle(&conn).await?;
    Ok(Json(org.to_json()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddStaffData {
    email: String,
    role: String,
    /// For a technician: what they get in the MSP's clients. Without it,
    /// every client as admin, with install commands.
    access: Option<TechnicianAccess>,
}

/// Puts someone on the MSP's staff and adds them to the clients they reach,
/// waiting for the org key.
async fn add_to_staff(
    msp_id: &MspId,
    user: &User,
    role: MspRole,
    access: Option<&TechnicianAccess>,
    added_by: &str,
    conn: &DbConn,
) -> EmptyResult {
    // Joining the staff may bring them under two-step login for admins.
    let watch = keykeeper_two_step::Watch::user(&user.uuid, conn).await?;
    let mut staff = MspStaff::new(msp_id.clone(), user.uuid.clone(), role);
    staff.insert(conn).await?;
    // No organization may recover a staff account (DESIGN.md, "MSP staff and
    // account recovery"), so any enrollment they had ends now.
    for mut member in Membership::find_by_user(&user.uuid, conn).await {
        if member.reset_password_key.is_some() {
            member.reset_password_key = None;
            member.save(conn).await?;
        }
    }
    MspInvite::delete_by_msp_and_email(msp_id, &user.email, conn).await?;
    if role == MspRole::Technician
        && let Some(access) = access
    {
        staff.set_access(access, conn).await?;
    }
    sync_staff_memberships(msp_id, &staff, added_by, conn).await?;
    watch.settle(conn).await
}

/// Checks a technician's access before storing it: chosen clients must be the
/// MSP's own, and a custom role needs at least one permission.
async fn validate_access(
    msp_id: &MspId,
    mut access: TechnicianAccess,
    conn: &DbConn,
) -> Result<TechnicianAccess, crate::error::Error> {
    if access.all_clients {
        access.clients.clear();
    } else {
        let clients: HashSet<OrganizationId> =
            MspClient::find_by_msp(msp_id, conn).await.into_iter().map(|c| c.org_uuid).collect();
        let mut seen = HashSet::new();
        access.clients.retain(|c| seen.insert(c.clone()));
        if access.clients.iter().any(|c| !clients.contains(c)) {
            err!("Client not found")
        }
    }
    if access.custom.as_ref().is_some_and(|c| !c.permissions.any()) {
        err!("Choose at least one permission for the custom role")
    }
    if let Some(custom) = &access.custom {
        keykeeper_roles::ensure_export_needs_items(Some(&custom.permissions), custom.vault_items)?;
    }
    // A different role in some clients: each client once, one they reach,
    // and a custom role there follows the same rules.
    let mut seen = HashSet::new();
    let clients: HashSet<OrganizationId> =
        MspClient::find_by_msp(msp_id, conn).await.into_iter().map(|c| c.org_uuid).collect();
    for role in &access.client_roles {
        if !seen.insert(role.client.clone()) {
            err!("Each client can have only one role")
        }
        if !clients.contains(&role.client) {
            err!("Client not found")
        }
        if !access.all_clients && !access.clients.contains(&role.client) {
            err!("A role is only for a client the technician reaches")
        }
        if let Some(custom) = &role.custom {
            if !custom.permissions.any() {
                err!("Choose at least one permission for the custom role")
            }
            keykeeper_roles::ensure_export_needs_items(Some(&custom.permissions), custom.vault_items)?;
        }
    }
    Ok(access)
}

/// A technician's access in a few words, for the audit log, with client
/// names copied in.
async fn describe_access(access: &TechnicianAccess, conn: &DbConn) -> String {
    let clients = if access.all_clients {
        "every client".to_owned()
    } else {
        let mut names = Vec::new();
        for id in &access.clients {
            if let Some(org) = Organization::find_by_uuid(id, conn).await {
                names.push(org.name);
            }
        }
        names.sort();
        match names.as_slice() {
            [] => "no clients".to_owned(),
            [one] => one.clone(),
            [first, second] => format!("{first} and {second}"),
            [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
        }
    };
    let role = role_in_words(access.custom.as_ref());
    let install = if access.install_commands {
        "install commands"
    } else {
        "no install commands"
    };
    let mut words = format!("{clients}, {role}, {install}");
    let mut differing = Vec::new();
    for role in &access.client_roles {
        if let Some(org) = Organization::find_by_uuid(&role.client, conn).await {
            differing.push(format!("{}, {}", org.name, role_in_words(role.custom.as_ref())));
        }
    }
    differing.sort();
    if !differing.is_empty() {
        words.push_str("; in ");
        words.push_str(&differing.join("; in "));
    }
    words
}

/// A role in a few words: "as admin", or "custom role (...), no vault items".
fn role_in_words(custom: Option<&CustomRole>) -> String {
    match custom {
        None => "as admin".to_owned(),
        Some(custom) => {
            let permissions: Vec<&str> =
                Permission::ALL.iter().filter(|p| custom.permissions.has(**p)).map(|p| p.label()).collect();
            let items = if custom.vault_items {
                "with vault items"
            } else {
                "no vault items"
            };
            format!("custom role ({}), {items}", permissions.join(", "))
        }
    }
}

fn invite_url(token: &str) -> String {
    format!("{}/#/msp?invite={token}", CONFIG.domain())
}

/// Invites someone to the MSP's staff: emailed a link when the server sends
/// email, and the link is returned so the admin can pass it on. They join the
/// staff, and every client they reach, when they accept it.
#[post("/keykeeper/msp/<msp_id>/staff", data = "<data>")]
async fn add_staff(msp_id: MspId, headers: Headers, data: Json<AddStaffData>, conn: DbConn) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let data = data.into_inner();
    let Some(role) = MspRole::from_str(&data.role) else {
        err!("Role must be admin or technician")
    };
    // MSP admins are owners of every client, so access applies to technicians only.
    let access = match (role, data.access) {
        (MspRole::Technician, Some(access)) => Some(validate_access(&msp_id, access, &conn).await?),
        _ => None,
    };
    let email = data.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        err!("Enter an email address")
    }

    // Everyone gets an invitation they accept themselves, whether or not they
    // have an account yet, and the answer is the same either way: adding
    // someone straight to the staff would make them an owner of every client
    // without asking, and would tell anyone which emails have accounts.
    if let Some(user) = User::find_by_mail(&email, &conn).await
        && MspStaff::find(&msp_id, &user.uuid, &conn).await.is_some()
    {
        err!("They're already on your staff")
    }
    if MspInvite::find_by_msp_and_email(&msp_id, &email, &conn).await.is_some() {
        err!("They're already invited. Cancel the invitation to send a new one.")
    }
    let Some(msp) = Msp::find_by_uuid(&msp_id, &conn).await else {
        err_code!("MSP not found", rocket::http::Status::NotFound.code)
    };
    let invite = MspInvite::new(msp_id.clone(), &email, role, access.as_ref(), &headers.user.email);
    invite.insert(&conn).await?;
    let url = invite_url(&invite.token);
    let emailed = CONFIG.mail_enabled();
    if emailed {
        let role_name = if role == MspRole::Admin {
            "an admin"
        } else {
            "a technician"
        };
        crate::mail::send_msp_invite(&email, &msp.name, role_name, &headers.user.email, &url).await?;
    }
    Audit::by("staff_invited", &headers).target(&email).detail(role.as_str()).record(&msp_id, &conn).await?;
    if let Some(access) = &access {
        let detail = describe_access(access, &conn).await;
        Audit::by("staff_access_changed", &headers).target(&email).detail(detail).record(&msp_id, &conn).await?;
    }
    Ok(Json(json!({
        "invited": true,
        "inviteId": invite.uuid,
        "email": email,
        "role": role.as_str(),
        "inviteUrl": url,
        "emailed": emailed,
    })))
}

/// Cancels an invitation. MSP admins only.
#[delete("/keykeeper/msp/<msp_id>/invites/<invite_id>")]
async fn cancel_invite(msp_id: MspId, invite_id: &str, headers: Headers, conn: DbConn) -> EmptyResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let Some(invite) = MspInvite::find_by_msp_and_uuid(&msp_id, invite_id, &conn).await else {
        err_code!("Invitation not found", rocket::http::Status::NotFound.code)
    };
    let email = invite.email.clone();
    invite.delete(&conn).await?;
    Audit::by("staff_invite_cancelled", &headers).target(&email).record(&msp_id, &conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteTokenData {
    token: String,
}

const INVALID_INVITE: &str = "This invitation isn't valid anymore. Ask the MSP for a new one.";

/// What an invitation is for, before accepting it.
#[post("/keykeeper/msp/invites/info", data = "<data>")]
async fn invite_info(data: Json<InviteTokenData>, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(invite) = MspInvite::find_by_token(&data.token, &conn).await.filter(|i| !i.expired()) else {
        err_code!(INVALID_INVITE, rocket::http::Status::NotFound.code)
    };
    let Some(msp) = Msp::find_by_uuid(&invite.msp_uuid, &conn).await else {
        err_code!(INVALID_INVITE, rocket::http::Status::NotFound.code)
    };
    Ok(Json(json!({
        "mspName": msp.name,
        "role": invite.role().map(MspRole::as_str),
        "email": invite.email,
        "invitedBy": invite.invited_by_email,
        "forYou": invite.email == headers.user.email.to_lowercase(),
    })))
}

/// Accepts an invitation: needs its token and an account with the invited
/// email address, so neither a leaked link nor a look-alike account is enough.
#[post("/keykeeper/msp/invites/accept", data = "<data>")]
async fn accept_invite(data: Json<InviteTokenData>, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(invite) = MspInvite::find_by_token(&data.token, &conn).await else {
        err_code!(INVALID_INVITE, rocket::http::Status::NotFound.code)
    };
    if invite.expired() {
        invite.delete(&conn).await?;
        err_code!(INVALID_INVITE, rocket::http::Status::NotFound.code)
    }
    if invite.email != headers.user.email.to_lowercase() {
        err!(format!("This invitation is for {}. Sign in with that account to accept it.", invite.email))
    }
    // Where the server sends email, only someone who proved the address can
    // take an invitation to it.
    if CONFIG.mail_enabled() && headers.user.verified_at.is_none() {
        err!("Verify your email address first: Settings, then My account, sends the email.")
    }
    let Some(role) = invite.role() else {
        err_code!(INVALID_INVITE, rocket::http::Status::NotFound.code)
    };
    let msp_id = invite.msp_uuid.clone();
    if MspStaff::find(&msp_id, &headers.user.uuid, &conn).await.is_none() {
        // Clients removed since the invitation drop out of its access, and
        // so do roles in them (or in clients it no longer reaches).
        let mut access = invite.access();
        if let Some(access) = &mut access {
            let clients: HashSet<OrganizationId> =
                MspClient::find_by_msp(&msp_id, &conn).await.into_iter().map(|c| c.org_uuid).collect();
            access.clients.retain(|c| clients.contains(c));
            let reached = access.clients.clone();
            let all_clients = access.all_clients;
            access.client_roles.retain(|r| clients.contains(&r.client) && (all_clients || reached.contains(&r.client)));
        }
        add_to_staff(&msp_id, &headers.user, role, access.as_ref(), &invite.invited_by_email, &conn).await?;
        Audit::by("staff_invite_accepted", &headers)
            .target(&headers.user.email)
            .detail(role.as_str())
            .record(&msp_id, &conn)
            .await?;
    }
    invite.delete(&conn).await?;
    Ok(Json(json!({ "mspId": msp_id, "role": role.as_str() })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeStaffRoleData {
    role: String,
}

/// Changes a staff member's role, and their role in every client with it. A
/// technician made an admin becomes an owner of every client; an admin made a
/// technician gets the access stored for them, every client as admin if none.
#[put("/keykeeper/msp/<msp_id>/staff/<user_id>", data = "<data>")]
async fn change_staff_role(
    msp_id: MspId,
    user_id: UserId,
    headers: Headers,
    data: Json<ChangeStaffRoleData>,
    conn: DbConn,
) -> EmptyResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let Some(role) = MspRole::from_str(&data.role) else {
        err!("Role must be admin or technician")
    };
    let Some(mut staff) = MspStaff::find(&msp_id, &user_id, &conn).await else {
        err_code!("Staff member not found", rocket::http::Status::NotFound.code)
    };
    if staff.role() == Some(role) {
        return Ok(());
    }
    if role == MspRole::Technician {
        ensure_another_admin(&msp_id, &user_id, &conn).await?;
    }
    if role == MspRole::Technician {
        ensure_owners_remain(&staff_memberships(&msp_id, &user_id, &conn).await, &conn).await?;
    }
    let watch = keykeeper_two_step::Watch::user(&user_id, &conn).await?;
    staff.set_role(role, &conn).await?;
    sync_staff_memberships(&msp_id, &staff, &headers.user.email, &conn).await?;
    watch.settle(&conn).await?;
    let email = User::find_by_uuid(&user_id, &conn).await.map(|u| u.email).unwrap_or_default();
    Audit::by("staff_role_changed", &headers).target(&email).detail(role.as_str()).record(&msp_id, &conn).await
}

/// Sets which clients a technician reaches, their role inside them, and
/// whether they see install commands, and applies it to all of their client
/// memberships at once. MSP admins only, and only for technicians: MSP admins
/// are owners of every client.
#[put("/keykeeper/msp/<msp_id>/staff/<user_id>/access", data = "<data>")]
async fn set_staff_access(
    msp_id: MspId,
    user_id: UserId,
    headers: Headers,
    data: Json<TechnicianAccess>,
    conn: DbConn,
) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let Some(mut staff) = MspStaff::find(&msp_id, &user_id, &conn).await else {
        err_code!("Staff member not found", rocket::http::Status::NotFound.code)
    };
    if staff.role() != Some(MspRole::Technician) {
        err!("MSP admins are owners of every client. Make them a technician to limit their access.")
    }
    let access = validate_access(&msp_id, data.into_inner(), &conn).await?;
    let watch = keykeeper_two_step::Watch::user(&user_id, &conn).await?;
    staff.set_access(&access, &conn).await?;
    sync_staff_memberships(&msp_id, &staff, &headers.user.email, &conn).await?;
    watch.settle(&conn).await?;
    let email = User::find_by_uuid(&user_id, &conn).await.map(|u| u.email).unwrap_or_default();
    // Clients they no longer reach lose their staff seal there too.
    if let Some(reach) = staff.reach(&conn).await {
        let unreached = MspClient::find_by_msp(&msp_id, &conn)
            .await
            .into_iter()
            .map(|c| c.org_uuid)
            .filter(|org| !reach.contains(org))
            .collect();
        crate::db::models::JoinSeal::delete_staff(unreached, &email, &conn).await?;
    }
    let detail = describe_access(&access, &conn).await;
    Audit::by("staff_access_changed", &headers).target(&email).detail(detail).record(&msp_id, &conn).await?;
    Ok(Json(json!(access)))
}

async fn ensure_another_admin(msp_id: &MspId, user_id: &UserId, conn: &DbConn) -> EmptyResult {
    let other_admins = MspStaff::find_by_msp(msp_id, conn)
        .await
        .iter()
        .filter(|s| &s.user_uuid != user_id && s.role() == Some(MspRole::Admin))
        .count();
    if other_admins == 0 {
        err!("An MSP needs at least one admin")
    }
    Ok(())
}

/// Removes someone from the MSP and from every client, at once.
#[delete("/keykeeper/msp/<msp_id>/staff/<user_id>")]
async fn remove_staff(msp_id: MspId, user_id: UserId, headers: Headers, conn: DbConn) -> EmptyResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let Some(staff) = MspStaff::find(&msp_id, &user_id, &conn).await else {
        err_code!("Staff member not found", rocket::http::Status::NotFound.code)
    };
    if staff.role() == Some(MspRole::Admin) {
        ensure_another_admin(&msp_id, &user_id, &conn).await?;
    }
    let memberships = staff_memberships(&msp_id, &user_id, &conn).await;
    ensure_owners_remain(&memberships, &conn).await?;
    for member in memberships {
        member.delete(&conn).await?;
    }
    staff.delete(&conn).await?;
    let email = User::find_by_uuid(&user_id, &conn).await.map(|u| u.email).unwrap_or_default();
    // An old invitation link mustn't bring them back, nor an old seal vouch for them.
    MspInvite::delete_by_msp_and_email(&msp_id, &email, &conn).await?;
    let clients = MspClient::find_by_msp(&msp_id, &conn).await.into_iter().map(|c| c.org_uuid).collect();
    crate::db::models::JoinSeal::delete_staff(clients, &email, &conn).await?;
    Audit::by("staff_removed", &headers).target(&email).record(&msp_id, &conn).await
}

/// Memberships waiting for the org key in clients where the caller can give
/// it: the caller is a confirmed owner or admin there. The console confirms
/// them with the upstream confirm endpoint.
#[get("/keykeeper/msp/<msp_id>/pending")]
async fn pending_confirmations(msp_id: MspId, headers: Headers, conn: DbConn) -> JsonResult {
    staff_role(&msp_id, &headers.user.uuid, &conn).await?;
    let ours = msp_membership_ids(&msp_id, &conn).await;
    let mut pending = Vec::new();
    for client in MspClient::find_by_msp(&msp_id, &conn).await {
        let Some(caller) = Membership::find_by_user_and_org(&headers.user.uuid, &client.org_uuid, &conn)
            .await
            .filter(|m| m.status == MembershipStatus::Confirmed as i32)
        else {
            continue;
        };
        let is_owner = caller.atype == MembershipType::Owner as i32;
        if !is_owner && caller.atype != MembershipType::Admin as i32 {
            continue;
        }
        // Background work skips clients that want an admin to approve joiners;
        // the console's Confirm button still offers them.
        let auto_confirm = effective_joining(&client.org_uuid, &conn).await.0.auto_confirm;
        for member in Membership::find_by_org(&client.org_uuid, &conn).await {
            // Upstream lets only owners confirm admins and owners, so a
            // technician (an admin) gets just the regular members.
            if member.status != MembershipStatus::Accepted as i32
                || (!is_owner && member.atype != MembershipType::User as i32)
            {
                continue;
            }
            let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
                continue;
            };
            let Some(public_key) = user.public_key.clone() else {
                continue;
            };
            let from_msp = ours.contains(&member.uuid);
            let mut entry = json!({
                "organizationId": client.org_uuid,
                "memberId": member.uuid,
                "userId": user.uuid,
                "email": user.email,
                "name": user.name,
                "publicKey": public_key,
                "fromMsp": from_msp,
                "autoConfirm": crate::db::models::confirms_automatically(auto_confirm, &member, &conn).await,
                "needsTwoStep": crate::db::models::OrgPolicy::waits_for_two_step(&member, &conn).await,
            });
            super::keykeeper_joining::extend(
                &mut entry,
                super::keykeeper_joining::vouching(&client.org_uuid, &member, &user.email, from_msp, &conn).await,
            );
            pending.push(entry);
        }
    }
    Ok(Json(json!({ "data": pending })))
}

const MAX_EVENTS: i64 = 500;

fn parse_before(before: Option<&str>) -> Result<Option<chrono::NaiveDateTime>, crate::error::Error> {
    let Some(before) = before.filter(|b| !b.is_empty()) else {
        return Ok(None);
    };
    let Ok(time) = chrono::DateTime::parse_from_rfc3339(before) else {
        err!("before must be a date and time like 2026-10-16T09:30:00Z")
    };
    Ok(Some(time.naive_utc()))
}

/// The MSP's audit log, newest first. Any of its staff, though a technician
/// limited to chosen clients doesn't see entries about other clients. Pages
/// with `before`, the time of the oldest entry already shown.
#[get("/keykeeper/msp/<msp_id>/events?<before>&<limit>")]
async fn list_events(
    msp_id: MspId,
    before: Option<String>,
    limit: Option<i64>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let caller = staff_member(&msp_id, &headers.user.uuid, &conn).await?;
    let only = caller.reach(&conn).await.map(|r| r.into_iter().collect());
    let before_time = parse_before(before.as_deref())?;
    let limit = limit.unwrap_or(100).clamp(1, MAX_EVENTS);
    // Technicians see their clients' activity without where it came from,
    // and of the MSP's own changes to its staff, only their own.
    let technician = caller.role() != Some(MspRole::Admin);
    let events: Vec<Value> = MspEvent::find_by_msp(&msp_id, before_time, only, limit, &conn)
        .await
        .into_iter()
        .filter(|e| {
            !technician
                || !e.event.starts_with("staff_")
                || e.target_email.as_deref().is_some_and(|t| t.eq_ignore_ascii_case(&headers.user.email))
        })
        .map(|e| {
            json!({
                "id": e.uuid,
                "date": crate::util::format_date(&e.created_at),
                "event": e.event,
                "actorEmail": e.actor_email,
                "organizationId": e.org_uuid,
                "organizationName": e.org_name,
                "targetEmail": e.target_email,
                "detail": e.detail,
                "ip": if technician { None } else { e.ip },
            })
        })
        .collect();
    Ok(Json(json!({ "data": events })))
}

/// For a client's own owners and admins: which MSP manages the organization,
/// its staff there with the role each has (owner, admin, a custom role and its
/// permissions, or a regular member) and whether they see vault items, and the
/// policies where the organization has its own setting rather than the MSP's
/// default.
#[get("/keykeeper/organizations/<org_id>/msp")]
async fn get_organization_msp(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(caller) = Membership::find_confirmed_by_user_and_org(&headers.user.uuid, &org_id, &conn).await else {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    };
    if caller.atype != MembershipType::Owner as i32 && caller.atype != MembershipType::Admin as i32 {
        err_code!("Only owners and admins can see this", rocket::http::Status::Forbidden.code)
    }
    let Some(client) = MspClient::find_by_org(&org_id, &conn).await else {
        return Ok(Json(json!({ "msp": null, "staff": [] })));
    };
    let Some(msp) = Msp::find_by_uuid(&client.msp_uuid, &conn).await else {
        return Ok(Json(json!({ "msp": null, "staff": [] })));
    };
    let ours = msp_membership_ids(&msp.uuid, &conn).await;
    let mut staff = Vec::new();
    for member in Membership::find_by_org(&org_id, &conn).await {
        if !ours.contains(&member.uuid) {
            continue;
        }
        if let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await {
            let custom = keykeeper_roles::find(&member.uuid, &conn).await;
            let (role, vault_items) = if member.atype == MembershipType::Owner as i32 {
                ("owner", true)
            } else if member.atype == MembershipType::Admin as i32 {
                ("admin", true)
            } else if custom.is_some() {
                ("custom", member.access_all)
            } else {
                ("member", member.access_all)
            };
            let permissions: Vec<&str> = custom
                .map(|c| Permission::ALL.iter().filter(|p| c.has(**p)).map(|p| p.key()).collect())
                .unwrap_or_default();
            staff.push(json!({
                "memberId": member.uuid,
                "email": user.email,
                "name": user.name,
                "type": member.atype,
                "status": member.status,
                "role": role,
                "permissions": permissions,
                "vaultItems": vault_items,
            }));
        }
    }
    Ok(Json(json!({
        "msp": { "id": msp.uuid, "name": msp.name },
        "staff": staff,
        "ownPolicies": keykeeper_msp_policies::own_policies(&msp.uuid, &org_id, &conn).await?,
    })))
}

/// For a client's own owners: removes the MSP and all of its staff from the
/// organization in one step. The MSP's own staff can't do this.
#[delete("/keykeeper/organizations/<org_id>/msp")]
async fn remove_organization_msp(org_id: OrganizationId, headers: Headers, conn: DbConn) -> EmptyResult {
    let Some(caller) = Membership::find_confirmed_by_user_and_org(&headers.user.uuid, &org_id, &conn).await else {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    };
    let Some(client) = MspClient::find_by_org(&org_id, &conn).await else {
        err_code!("This organization has no MSP", rocket::http::Status::NotFound.code)
    };
    let caller_is_msp = MspMembership::find_by_membership(&caller.uuid, &conn).await.is_some();
    if caller.atype != MembershipType::Owner as i32 || caller_is_msp {
        err_code!("Only the organization's own owners can remove its MSP", rocket::http::Status::Forbidden.code)
    }
    // Fails closed: if the MSP's memberships can't be read, nothing changes
    // and the owner can try again.
    let ours: HashSet<MembershipId> =
        MspMembership::try_find_by_msp(&client.msp_uuid, &conn).await?.into_iter().map(|m| m.membership_uuid).collect();
    for member in Membership::find_by_org(&org_id, &conn).await {
        if ours.contains(&member.uuid) {
            member.delete(&conn).await?;
        }
    }
    // How people join stays as it was: a client that followed its MSP's
    // default keeps it as its own, rather than falling back to the server's.
    let (joining, _) = effective_joining(&org_id, &conn).await;
    if crate::db::models::OrgJoining::find(&org_id, &conn).await.is_none() {
        crate::db::models::OrgJoining::new(org_id.clone(), joining).save(&conn).await?;
    }
    let msp_id = client.msp_uuid.clone();
    // The organization keeps its preset and the collection people who join
    // get, as a company's own. Not the install command: its token was the
    // MSP's, so the owners make a new one in the admin console.
    if OrgSetup::find_by_org(&org_id, &conn).await.is_none() {
        OrgSetup::new(org_id.clone(), client.preset.clone(), client.everyone_collection.clone(), false)
            .insert(&conn)
            .await?;
    }
    client.delete(&conn).await?;
    // A staff change that ran at the same moment may have added one back.
    let ours: HashSet<MembershipId> =
        MspMembership::try_find_by_msp(&msp_id, &conn).await?.into_iter().map(|m| m.membership_uuid).collect();
    for member in Membership::find_by_org(&org_id, &conn).await {
        if ours.contains(&member.uuid) {
            member.delete(&conn).await?;
        }
    }
    // The MSP keeps a record that the client removed it.
    let org_name = Organization::find_by_uuid(&org_id, &conn).await.map(|o| o.name).unwrap_or_default();
    Audit::by("client_removed_msp", &headers).org(&org_id, &org_name).record(&msp_id, &conn).await
}

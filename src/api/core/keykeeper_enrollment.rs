// Keykeeper: joining a client organization through the RMM install command.
// The command gives the browser extension the client's enrollment token. After
// the person signs in and unlocks, the extension asks which organization the
// token belongs to, encrypts the person's user key to that organization's
// public key for account recovery (upstream's own enrollment code), and joins.
//
// A join goes through upstream's invite acceptance, so it gets exactly the
// checks an emailed invite gets: single organization in both directions,
// two-step login, and the account recovery key. It never includes the org
// key: the member waits to be confirmed, which the MSP console does. A client
// can limit the command to accounts at its email domains, and its own owners
// get an email about each join. See DESIGN.md, "Onboarding through the RMM".
//
// A company with its own IT has the same install command for its own
// organization, managed by its owners and admins in the admin console. An
// MSP's client's command stays in the MSP's console, where technicians' access
// to it is decided. See DESIGN.md, "A company's own IT".

use rocket::{Route, serde::json::Json};

use super::{
    keykeeper_msp::{Audit, require_admin, staff_member},
    keykeeper_offboarding::require_client_place,
};
use crate::{
    CONFIG,
    api::JsonResult,
    auth::Headers,
    db::{
        DbConn,
        models::{
            CollectionId, CollectionUser, EnrollmentDomains, JoiningSeal, Membership, MembershipStatus, MembershipType,
            Msp, MspClient, MspEnrollmentJoin, MspId, MspMembership, MspRole, OrgPolicy, OrgSetup, Organization,
            OrganizationId, RemovedMember, ScimUser, User, effective_joining, email_in_domains,
            parse_enrollment_domains, valid_encrypted_secret, valid_seal,
        },
    },
    mail,
};

pub fn routes() -> Vec<Route> {
    routes![
        get_enrollment,
        replace_enrollment,
        set_enrollment_domains,
        get_org_enrollment,
        replace_org_enrollment,
        set_org_enrollment_domains,
        enrollment_info,
        join
    ]
}

const INVALID_TOKEN: &str = "This install link isn't valid anymore. Ask your IT team for a new one.";

/// One of this MSP's clients, or "not found".
async fn msp_client(msp_id: &MspId, org_id: &OrganizationId, conn: &DbConn) -> Result<MspClient, crate::error::Error> {
    match MspClient::find_by_org(org_id, conn).await {
        Some(client) if &client.msp_uuid == msp_id => Ok(client),
        _ => err_code!("Client not found", rocket::http::Status::NotFound.code),
    }
}

async fn enrollment_json(client: &MspClient, conn: &DbConn) -> serde_json::Value {
    install_json(
        &client.org_uuid,
        client.enrollment_token.as_ref(),
        client.enrollment_token_created_at.as_ref(),
        client.enrollment_secret.as_ref(),
        conn,
    )
    .await
}

async fn setup_json(setup: &OrgSetup, conn: &DbConn) -> serde_json::Value {
    install_json(
        &setup.org_uuid,
        setup.enrollment_token.as_ref(),
        setup.enrollment_token_created_at.as_ref(),
        setup.enrollment_secret.as_ref(),
        conn,
    )
    .await
}

/// The install command's parts: the token, the join secret (encrypted with the
/// organization's key, for the browser to show in the command), the email
/// domains, how many joined with it, and how many people the organization
/// removed since the token was made: each may still have the command, so the
/// apps offer to replace it (DESIGN.md, "Offboarding").
async fn install_json(
    org_id: &OrganizationId,
    token: Option<&String>,
    created_at: Option<&chrono::NaiveDateTime>,
    secret: Option<&String>,
    conn: &DbConn,
) -> serde_json::Value {
    json!({
        "token": token,
        "secret": secret,
        "createdAt": created_at.map(crate::util::format_date),
        "joins": MspEnrollmentJoin::count_by_org(org_id, conn).await,
        "domains": EnrollmentDomains::for_org(org_id, conn).await,
        "removedSinceToken": removed_since(org_id, token, created_at, conn).await,
    })
}

/// How many people the organization removed since its install command's token
/// was made; none without a token.
async fn removed_since(
    org_id: &OrganizationId,
    token: Option<&String>,
    created_at: Option<&chrono::NaiveDateTime>,
    conn: &DbConn,
) -> i64 {
    if token.is_none() {
        return 0;
    }
    RemovedMember::count_since(org_id, created_at.copied(), conn).await
}

/// A seal from an app, checked to look like one. None when there isn't one.
pub(super) fn checked_seal(seal: Option<&String>) -> Result<Option<&str>, crate::error::Error> {
    match seal {
        Some(seal) if !valid_seal(seal) => err!("That seal isn't one"),
        seal => Ok(seal.map(String::as_str)),
    }
}

/// A join secret from the browser, checked to look like an encrypted one.
pub(super) fn checked_secret(secret: Option<&String>) -> Result<Option<String>, crate::error::Error> {
    match secret {
        Some(secret) if !valid_encrypted_secret(secret) => err!("That join secret isn't an encrypted one"),
        secret => Ok(secret.cloned()),
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReplaceData {
    /// The new command's join secret, encrypted with the organization's key.
    secret: Option<String>,
}

/// Saves a list of email domains for an organization's install command, or
/// clears it. The limit trusts an account's email only once it's verified, so
/// it needs a server that sends email.
///
/// The seal, from the app that saved them, covers the joining setting and the
/// domains together; a change without one means joins need approval.
async fn save_domains(
    org_id: &OrganizationId,
    data: &DomainsData,
    conn: &DbConn,
) -> Result<Vec<String>, crate::error::Error> {
    let seal = checked_seal(data.seal.as_ref())?;
    let domains = match parse_enrollment_domains(&data.domains) {
        Ok(domains) => domains,
        Err(e) => err!(e),
    };
    if !domains.is_empty() && !CONFIG.mail_enabled() {
        err!("Limiting the install command to email domains needs verified emails, and this server can't send email")
    }
    EnrollmentDomains::set(org_id, &domains, conn).await?;
    JoiningSeal::set(org_id, seal, conn).await?;
    Ok(domains)
}

/// A client's enrollment token, for its install command. MSP admins, and
/// technicians who reach the client and are allowed install commands.
#[get("/keykeeper/msp/<msp_id>/clients/<org_id>/enrollment")]
async fn get_enrollment(msp_id: MspId, org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    let staff = staff_member(&msp_id, &headers.user.uuid, &conn).await?;
    let client = msp_client(&msp_id, &org_id, &conn).await?;
    let technician = staff.role() == Some(MspRole::Technician);
    if technician {
        if staff.reach(&conn).await.is_some_and(|r| !r.contains(&org_id)) {
            err_code!("Client not found", rocket::http::Status::NotFound.code)
        }
        if !staff.install_commands {
            err_code!("Your MSP's admins haven't given you install commands", rocket::http::Status::Forbidden.code)
        }
    }
    // Keykeeper: only someone with a place of their own in the client, which
    // a client that revoked them takes away (keykeeper_offboarding.rs). A
    // technician's role there is the MSP's choice.
    require_client_place(&org_id, &headers.user.uuid, !technician, &conn).await?;
    Ok(Json(enrollment_json(&client, &conn).await))
}

/// Replaces a client's enrollment token. MSP admins only: install commands with
/// the old token stop letting new people join.
#[post("/keykeeper/msp/<msp_id>/clients/<org_id>/enrollment", data = "<data>")]
async fn replace_enrollment(
    msp_id: MspId,
    org_id: OrganizationId,
    data: Option<Json<ReplaceData>>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let secret = checked_secret(data.map(Json::into_inner).unwrap_or_default().secret.as_ref())?;
    let mut client = msp_client(&msp_id, &org_id, &conn).await?;
    require_client_place(&org_id, &headers.user.uuid, true, &conn).await?;
    client.replace_enrollment_token(secret, &conn).await?;
    let org_name = Organization::find_by_uuid(&org_id, &conn).await.map(|o| o.name).unwrap_or_default();
    Audit::by("install_token_replaced", &headers).org(&org_id, &org_name).record(&msp_id, &conn).await?;
    Ok(Json(enrollment_json(&client, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DomainsData {
    domains: Vec<String>,
    /// The seal over the joining setting and these domains.
    seal: Option<String>,
}

/// Limits a client's install command to accounts at these email domains, or
/// with none, lets anyone with the command join again. MSP admins only. The
/// limit trusts an account's email only once it's verified, so it needs a
/// server that sends email.
#[put("/keykeeper/msp/<msp_id>/clients/<org_id>/enrollment/domains", data = "<data>")]
async fn set_enrollment_domains(
    msp_id: MspId,
    org_id: OrganizationId,
    data: Json<DomainsData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let client = msp_client(&msp_id, &org_id, &conn).await?;
    require_client_place(&org_id, &headers.user.uuid, true, &conn).await?;
    let domains = save_domains(&org_id, &data, &conn).await?;
    let org_name = Organization::find_by_uuid(&org_id, &conn).await.map(|o| o.name).unwrap_or_default();
    Audit::by("install_domains_set", &headers)
        .org(&org_id, &org_name)
        .detail(domains.join(" "))
        .record(&msp_id, &conn)
        .await?;
    Ok(Json(enrollment_json(&client, &conn).await))
}

/// An owner or admin of a company's own organization, managing its install
/// command. An MSP's client's command is in the MSP's console instead, so its
/// technicians' access to it holds: they're admins in the client too.
async fn own_org_admin(
    org_id: &OrganizationId,
    headers: &Headers,
    conn: &DbConn,
) -> Result<OrgSetupOrNew, crate::error::Error> {
    let Some(caller) = Membership::find_confirmed_by_user_and_org(&headers.user.uuid, org_id, conn).await else {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    };
    if caller.atype != MembershipType::Owner as i32 && caller.atype != MembershipType::Admin as i32 {
        err_code!("Only owners and admins can manage the install command", rocket::http::Status::Forbidden.code)
    }
    if MspClient::find_by_org(org_id, conn).await.is_some() {
        err_code!(
            "This organization's IT provider manages its install command, in their MSP console",
            rocket::http::Status::Forbidden.code
        )
    }
    Ok(match OrgSetup::find_by_org(org_id, conn).await {
        Some(setup) => OrgSetupOrNew::Saved(setup),
        None => OrgSetupOrNew::New(OrgSetup::new(org_id.clone(), None, None, false)),
    })
}

/// An organization's setup, or a new one not saved yet: an organization made
/// before PassBundle kept setups, or without a preset, has none until its
/// first install command.
enum OrgSetupOrNew {
    Saved(OrgSetup),
    New(OrgSetup),
}

impl OrgSetupOrNew {
    fn setup(&self) -> &OrgSetup {
        match self {
            Self::Saved(setup) | Self::New(setup) => setup,
        }
    }
}

/// A company's own organization's install command, for its owners and admins.
/// For an MSP's client, only who manages it. The web vault reads this on every
/// Settings page and signs out on 403, so refusals here are "not found", and an
/// MSP's client gets an answer rather than a refusal.
#[get("/keykeeper/organizations/<org_id>/enrollment")]
async fn get_org_enrollment(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    let caller = Membership::find_confirmed_by_user_and_org(&headers.user.uuid, &org_id, &conn).await;
    if !caller.is_some_and(|c| c.atype == MembershipType::Owner as i32 || c.atype == MembershipType::Admin as i32) {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    }
    if let Some(client) = MspClient::find_by_org(&org_id, &conn).await {
        let provider = Msp::find_by_uuid(&client.msp_uuid, &conn).await.map(|m| m.name).unwrap_or_default();
        // Keykeeper: so the Members page can ask the provider to replace it.
        let removed = removed_since(
            &org_id,
            client.enrollment_token.as_ref(),
            client.enrollment_token_created_at.as_ref(),
            &conn,
        )
        .await;
        return Ok(Json(json!({ "provider": provider, "removedSinceToken": removed })));
    }
    let setup = OrgSetup::find_by_org(&org_id, &conn).await;
    let setup = setup.as_ref();
    Ok(Json(
        install_json(
            &org_id,
            setup.and_then(|s| s.enrollment_token.as_ref()),
            setup.and_then(|s| s.enrollment_token_created_at.as_ref()),
            setup.and_then(|s| s.enrollment_secret.as_ref()),
            &conn,
        )
        .await,
    ))
}

/// Makes a company's own organization's install command, or replaces it:
/// commands with the old token stop letting new people join. Owners and admins.
#[post("/keykeeper/organizations/<org_id>/enrollment", data = "<data>")]
async fn replace_org_enrollment(
    org_id: OrganizationId,
    data: Option<Json<ReplaceData>>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let secret = checked_secret(data.map(Json::into_inner).unwrap_or_default().secret.as_ref())?;
    let setup = match own_org_admin(&org_id, &headers, &conn).await? {
        OrgSetupOrNew::Saved(mut setup) => {
            setup.replace_enrollment_token(secret, &conn).await?;
            setup
        }
        OrgSetupOrNew::New(_) => {
            let mut setup = OrgSetup::new(org_id.clone(), None, None, true);
            setup.enrollment_secret = secret;
            setup.insert(&conn).await?;
            setup
        }
    };
    Ok(Json(setup_json(&setup, &conn).await))
}

/// Limits a company's own organization's install command to accounts at these
/// email domains, or with none, lets anyone with the command join again.
/// Owners and admins.
#[put("/keykeeper/organizations/<org_id>/enrollment/domains", data = "<data>")]
async fn set_org_enrollment_domains(
    org_id: OrganizationId,
    data: Json<DomainsData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let found = own_org_admin(&org_id, &headers, &conn).await?;
    save_domains(&org_id, &data, &conn).await?;
    Ok(Json(setup_json(found.setup(), &conn).await))
}

/// What an install command joins: one of an MSP's clients, or a company's own
/// organization.
struct Target {
    org_uuid: OrganizationId,
    everyone_collection: Option<CollectionId>,
    msp_uuid: Option<MspId>,
}

async fn target_by_token(token: &str, conn: &DbConn) -> Option<Target> {
    if let Some(client) = MspClient::find_by_enrollment_token(token, conn).await {
        return Some(Target {
            org_uuid: client.org_uuid,
            everyone_collection: client.everyone_collection,
            msp_uuid: Some(client.msp_uuid),
        });
    }
    OrgSetup::find_by_enrollment_token(token, conn).await.map(|setup| Target {
        org_uuid: setup.org_uuid,
        everyone_collection: setup.everyone_collection,
        msp_uuid: None,
    })
}

/// Refuses an account outside a client's email domains, or one whose email
/// isn't verified, when the client has domains. The message is what the
/// person sees in the extension.
fn check_domains(user: &User, org: &Organization, domains: &[String]) -> crate::api::EmptyResult {
    if domains.is_empty() {
        return Ok(());
    }
    let listed = match domains {
        [one] => one.clone(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
        [] => unreachable!(),
    };
    if !email_in_domains(&user.email, domains) {
        err!(format!(
            "{}'s install link is for {listed} accounts, and you're signed in as {}. Ask its admins to invite you.",
            org.name, user.email
        ))
    }
    if user.verified_at.is_none() {
        err!(format!(
            "Verify your email address first: {}'s install link is for verified {listed} accounts. Settings, then My account, sends the email.",
            org.name
        ))
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentTokenData {
    token: String,
}

/// Which organization a token joins, and what's needed to join it. The
/// public key is for account recovery enrollment.
#[post("/keykeeper/enrollment/info", data = "<data>")]
async fn enrollment_info(data: Json<EnrollmentTokenData>, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(target) = target_by_token(&data.token, &conn).await else {
        err_code!(INVALID_TOKEN, rocket::http::Status::NotFound.code)
    };
    let Some(org) = Organization::find_by_uuid(&target.org_uuid, &conn).await else {
        err_code!(INVALID_TOKEN, rocket::http::Status::NotFound.code)
    };
    // Said here too, so the extension says why before it does any work.
    // Keykeeper: an invitation only the directory chose (provisioning) isn't
    // an admin's choice, so the command's domains still apply to it.
    let invited = match Membership::find_by_user_and_org(&headers.user.uuid, &org.uuid, &conn).await {
        Some(member) => !ScimUser::invited_unvouched(&member, &headers.user.email, &conn).await,
        None => false,
    };
    if !invited {
        check_domains(&headers.user, &org, &EnrollmentDomains::for_org(&org.uuid, &conn).await)?;
    }
    Ok(Json(json!({
        "organizationId": org.uuid,
        "organizationName": org.name,
        "publicKey": org.public_key,
        "accountRecovery": OrgPolicy::org_is_reset_password_auto_enroll(&org.uuid, &conn).await,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinData {
    token: String,
    /// The person's user key encrypted to the organization's public key, when
    /// the organization enrolls members in account recovery automatically.
    reset_password_key: Option<String>,
    /// That the extension knew the command's join secret, bound to the
    /// person's public key, for the apps that confirm. See DESIGN.md, "Joins a
    /// hacked server can't forge".
    proof: Option<String>,
}

/// Joins the organization a token belongs to, as a regular member waiting to
/// be confirmed. Joining again is harmless.
#[post("/keykeeper/enrollment/join", data = "<data>")]
async fn join(data: Json<JoinData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data = data.into_inner();
    let proof = checked_seal(data.proof.as_ref())?.map(str::to_owned);
    let Some(target) = target_by_token(&data.token, &conn).await else {
        err_code!(INVALID_TOKEN, rocket::http::Status::NotFound.code)
    };
    let Some(org) = Organization::find_by_uuid(&target.org_uuid, &conn).await else {
        err_code!(INVALID_TOKEN, rocket::http::Status::NotFound.code)
    };
    let joined =
        |status: i32| Json(json!({ "organizationId": org.uuid, "organizationName": org.name, "status": status }));

    let existing = Membership::find_by_user_and_org(&headers.user.uuid, &org.uuid, &conn).await;
    let member = match existing {
        // Already in: nothing to do.
        Some(member) if member.status >= MembershipStatus::Accepted as i32 => return Ok(joined(member.status)),
        Some(member) if member.status < MembershipStatus::Invited as i32 => {
            err!(format!("Your access to {} was turned off. Ask its admins.", org.name))
        }
        // Invited by email, joining through the install command instead. An
        // admin chose them, so the client's domains don't apply. Only a
        // regular invitation, and from a verified address where the server
        // sends email: otherwise anyone with the command could register an
        // invited address and take its invitation, an admin's included.
        Some(member) => {
            if member.atype != MembershipType::User as i32
                || member.access_all
                || crate::db::models::keykeeper_roles::find(&member.uuid, &conn).await.is_some()
            {
                err!(format!("Accept your emailed invitation to {} instead.", org.name))
            }
            if CONFIG.mail_enabled() && headers.user.verified_at.is_none() {
                err!(format!(
                    "Verify your email address first, then join {}. Settings, then My account, sends the email.",
                    org.name
                ))
            }
            // Invited by the directory alone (provisioning), with no owner's
            // or admin's app vouching for the address: the command's domains
            // apply, or a stolen provisioning token plus a copied command
            // would let any address in. See DESIGN.md, "Provisioning from
            // Entra ID".
            if ScimUser::invited_unvouched(&member, &headers.user.email, &conn).await {
                check_domains(&headers.user, &org, &EnrollmentDomains::for_org(&org.uuid, &conn).await)?;
            }
            member
        }
        None => {
            check_domains(&headers.user, &org, &EnrollmentDomains::for_org(&org.uuid, &conn).await)?;
            let mut member = Membership::new(headers.user.uuid.clone(), org.uuid.clone(), None);
            member.status = MembershipStatus::Invited as i32;
            member.atype = MembershipType::User as i32;
            member.access_all = false;
            member
        }
    };

    let reset_password_key = match OrgPolicy::org_is_reset_password_auto_enroll(&org.uuid, &conn).await {
        true if data.reset_password_key.as_deref().is_none_or(str::is_empty) => {
            err!(format!("Joining {} needs account recovery enrollment", org.name))
        }
        true => data.reset_password_key,
        false => None,
    };

    let member_id = member.uuid.clone();
    let invited_by = member.invited_by_email.clone();
    super::accept_org_invite(&headers.user, member, reset_password_key, false, &conn).await?;

    if let Some(collection) = &target.everyone_collection
        // An invitation's own grant there stays as the admin set it: Can
        // edit would widen a narrower one.
        && CollectionUser::find_by_collection_and_user(collection, &headers.user.uuid, &conn).await.is_none()
    {
        // Can edit, as a preset grant (keykeeper_folder_permissions.rs).
        crate::db::models::keykeeper_folder_permissions::save_user(
            &headers.user.uuid,
            collection,
            &crate::db::models::keykeeper_folder_permissions::Grid::preset(false, false, false),
            &conn,
        )
        .await?;
    }
    MspEnrollmentJoin::new(member_id, org.uuid.clone(), proof).insert(&conn).await?;
    if let Some(msp_id) = &target.msp_uuid {
        Audit::by("joined_with_install_command", &headers)
            .org(&org.uuid, &org.name)
            .target(&headers.user.email)
            .record(msp_id, &conn)
            .await?;
    }
    tell_owners(&headers.user, &org, invited_by, target.msp_uuid.is_some(), &conn).await;

    Ok(joined(MembershipStatus::Accepted as i32))
}

/// Emails a client's own owners that someone joined with the install command:
/// with nobody clicking Confirm by default, this is how they hear of it. Its
/// MSP's people aren't emailed, since a rollout would mean one email per
/// machine; the console's Activity has every join. Someone who was invited by
/// email is the inviter's to hear about, as for any invitation. `provider`
/// says the command was an MSP's rather than the company's own.
async fn tell_owners(user: &User, org: &Organization, invited_by: Option<String>, provider: bool, conn: &DbConn) {
    if !CONFIG.mail_enabled() {
        return;
    }
    let auto = effective_joining(&org.uuid, conn).await.0.auto_confirm;
    let approve = match Membership::find_by_user_and_org(&user.uuid, &org.uuid, conn).await {
        Some(member) => !crate::db::models::confirms_automatically(auto, &member, conn).await,
        None => !auto,
    };
    let mut to: Vec<String> = Vec::new();
    if let Some(inviter) = invited_by {
        to.push(inviter);
    } else {
        for owner in Membership::find_by_org_and_type(&org.uuid, MembershipType::Owner, conn).await {
            if owner.status != MembershipStatus::Confirmed as i32
                || owner.user_uuid == user.uuid
                || MspMembership::find_by_membership(&owner.uuid, conn).await.is_some()
            {
                continue;
            }
            if let Some(owner) = User::find_by_uuid(&owner.user_uuid, conn).await {
                to.push(owner.email);
            }
        }
    }
    for address in to {
        if let Err(e) =
            mail::send_member_joined(&address, &user.email, &org.name, &org.uuid, true, provider, approve).await
        {
            error!("Error sending the join email for {}: {e:#?}", org.name);
        }
    }
}

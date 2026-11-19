// Keykeeper: an organization that already uses PassBundle joins an MSP, or
// moves from one MSP to another, with a one-time code the MSP gives its owner
// (DESIGN.md, "An organization that already uses PassBundle", in the meta
// repo). The organization's own owner says yes; an MSP alone never can.
//
// Nothing here touches a key. The MSP's staff join the organization waiting
// for its key, as they join a client the console makes, and the
// organization's own owner gives it to them by hand on the Members page,
// after comparing fingerprint phrases. Nothing on the organization's side
// confirms them on its own.
//
// Every refusal is "not found" or a plain 400, never 403 (which signs the web
// vault out), and none says anything about another organization or another
// MSP's codes.

use std::collections::HashSet;

use chrono::Utc;
use rocket::{Route, serde::json::Json};
use serde_json::Value;

use super::{
    keykeeper_msp::{Audit, Grant, StaffChange, add_msp_membership, detach_msp, staff_member},
    keykeeper_plan_limits::{company_features_on, refuse_if_ended, refuse_if_pool_ended},
    keykeeper_two_step,
};
use crate::{
    api::{EmptyResult, JsonResult},
    auth::Headers,
    db::{
        DbConn,
        models::{
            MAX_OPEN_LINK_CODES, Membership, MembershipId, MembershipType, Msp, MspClient, MspId, MspLinkCode,
            MspMembership, MspRole, MspStaff, OrgJoining, OrgSetup, Organization, OrganizationId, RemovedMember, User,
            UserId, begin_write, commit_write, effective_joining, find_link_code, rollback_write, shown_link_code,
        },
    },
};

pub fn routes() -> Vec<Route> {
    routes![list_codes, make_code, revoke_code, preview, link]
}

/// The one answer to every code that doesn't work, however it doesn't.
const INVALID_CODE: &str = "That code isn't valid. A code works once, for 7 days: ask your MSP for a new one.";

/// The answer to a member who may not join the organization to an MSP.
const OWNERS_ONLY: &str = "Only this organization's own owners can join it to an MSP.";

/// How long "who it's for" may be.
const MAX_LABEL: usize = 100;

/// One of the MSP's admins. Everyone else, its technicians included, gets
/// "not found", never 403.
async fn require_msp_admin(msp_id: &MspId, user_id: &UserId, conn: &DbConn) -> EmptyResult {
    if staff_member(msp_id, user_id, conn).await?.role() != Some(MspRole::Admin) {
        err_code!("MSP not found", rocket::http::Status::NotFound.code)
    }
    Ok(())
}

/// An open code as the console lists it. Never the code.
fn code_json(code: &MspLinkCode) -> Value {
    json!({
        "id": code.uuid,
        "label": code.label,
        "createdBy": code.created_by_email,
        "createdAt": crate::util::format_date(&code.created_at),
        "expiresAt": crate::util::format_date(&code.expires_at),
    })
}

/// Who a code is for, as the admin typed it: none if blank.
fn clean_label(label: Option<&str>) -> Result<Option<String>, crate::error::Error> {
    let Some(label) = label.map(str::trim).filter(|l| !l.is_empty()) else {
        return Ok(None);
    };
    if label.chars().count() > MAX_LABEL {
        err!(format!("Who it's for can be at most {MAX_LABEL} characters"))
    }
    // It goes into the activity log and the event stream.
    if label.chars().any(char::is_control) {
        err!("Who it's for can't contain line breaks or other control characters")
    }
    Ok(Some(label.to_owned()))
}

/// The MSP's codes that haven't been used, revoked, or ended. MSP admins only.
#[get("/keykeeper/msp/<msp_id>/link-codes")]
async fn list_codes(msp_id: MspId, headers: Headers, conn: DbConn) -> JsonResult {
    require_msp_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let codes = MspLinkCode::open_for_msp(&msp_id, Utc::now().naive_utc(), &conn).await?;
    Ok(Json(json!({ "data": codes.iter().map(code_json).collect::<Vec<_>>() })))
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MakeCodeData {
    label: Option<String>,
}

/// Makes a code for an organization's owner to join it to the MSP. The answer
/// has the code, the only time it's ever shown. MSP admins only.
#[post("/keykeeper/msp/<msp_id>/link-codes", data = "<data>")]
async fn make_code(msp_id: MspId, data: Option<Json<MakeCodeData>>, headers: Headers, conn: DbConn) -> JsonResult {
    require_msp_admin(&msp_id, &headers.user.uuid, &conn).await?;
    // An MSP whose plan has ended takes on no new clients.
    refuse_if_pool_ended(&msp_id, &conn).await?;
    let label = clean_label(data.as_ref().and_then(|d| d.label.as_deref()))?;
    let now = Utc::now().naive_utc();
    let open = MspLinkCode::open_for_msp(&msp_id, now, &conn).await?;
    if i64::try_from(open.len()).unwrap_or(i64::MAX) >= MAX_OPEN_LINK_CODES {
        err!(format!("Your MSP has {MAX_OPEN_LINK_CODES} codes nobody has used yet. Revoke one first."))
    }
    // A new code whose first 8 characters another open code has (one in a
    // trillion) isn't saved; another is made.
    for _ in 0..3 {
        let (row, code) = MspLinkCode::new(msp_id.clone(), label.clone(), &headers.user, now);
        if row.insert(&conn).await? {
            let mut audit = Audit::by("link_code_created", &headers);
            audit.detail = label.clone();
            audit.record(&msp_id, &conn).await?;
            let mut answer = code_json(&row);
            answer["code"] = json!(shown_link_code(&code));
            return Ok(Json(answer));
        }
    }
    err!("Couldn't make a code. Try again.")
}

/// Revokes a code nobody has used: it stops working at once. MSP admins only;
/// another MSP's code is "not found".
#[delete("/keykeeper/msp/<msp_id>/link-codes/<code_id>")]
async fn revoke_code(msp_id: MspId, code_id: &str, headers: Headers, conn: DbConn) -> EmptyResult {
    require_msp_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let Some(code) = MspLinkCode::find(&msp_id, code_id, &conn).await else {
        err_code!("Code not found", rocket::http::Status::NotFound.code)
    };
    if !code.delete(&conn).await? {
        err_code!("Code not found", rocket::http::Status::NotFound.code)
    }
    let mut audit = Audit::by("link_code_revoked", &headers).target(&code.created_by_email);
    audit.detail = code.label.clone();
    audit.record(&msp_id, &conn).await
}

/// Who may join an organization to an MSP: one of its confirmed owners whose
/// place is the organization's own, not one an MSP made. Anyone who isn't a
/// confirmed member gets "not found"; a member who isn't such an owner, a
/// plain 400. A database error reading whether the place is an MSP's is an
/// error, never a yes.
async fn require_own_owner(org_id: &OrganizationId, user_id: &UserId, conn: &DbConn) -> EmptyResult {
    let Some(member) = Membership::find_confirmed_by_user_and_org(user_id, org_id, conn).await else {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    };
    if member.atype != MembershipType::Owner as i32 || MspMembership::try_is_msp_membership(&member.uuid, conn).await? {
        err!(OWNERS_ONLY)
    }
    Ok(())
}

/// A code checked for an organization, as joining checks it.
struct Checked {
    code: MspLinkCode,
    msp: Msp,
    org: Organization,
    /// Its MSP now, for a move.
    current: Option<(MspClient, Msp)>,
}

/// Everything joining checks before anything changes, in this order, so
/// nobody learns anything about a code they may not use: the caller is one
/// of the organization's own owners; the code works; the organization isn't
/// a family, and neither its plan nor the MSP's has ended (where plans are
/// enforced); and it isn't the MSP's client already.
async fn check(
    org_id: &OrganizationId,
    typed: &str,
    user: &User,
    conn: &DbConn,
) -> Result<Checked, crate::error::Error> {
    require_own_owner(org_id, &user.uuid, conn).await?;
    let Some(code) = find_link_code(typed, Utc::now().naive_utc(), conn).await else {
        err_code!(INVALID_CODE, rocket::http::Status::NotFound.code)
    };
    let Some(msp) = Msp::find_by_uuid(&code.msp_uuid, conn).await else {
        err_code!(INVALID_CODE, rocket::http::Status::NotFound.code)
    };
    let Some(org) = Organization::find_by_uuid(org_id, conn).await else {
        err_code!("Organization not found", rocket::http::Status::NotFound.code)
    };
    let current = match MspClient::find_by_org(org_id, conn).await {
        Some(client) if client.msp_uuid == msp.uuid => {
            err!(format!("{} is already {}'s client.", org.name, msp.name))
        }
        Some(client) => {
            let Some(current) = Msp::find_by_uuid(&client.msp_uuid, conn).await else {
                err!("This organization's MSP can't be read now. Try again.")
            };
            Some((client, current))
        }
        None => None,
    };
    // A family's plan has no company features, and an MSP's clients are
    // businesses.
    if !company_features_on(org_id, conn).await? {
        err!("A family organization can't join an MSP: an MSP's clients are businesses.")
    }
    // Its own plan, unless an MSP's pool covers it now: a move takes it out
    // of that pool first, with the time any client leaving its MSP gets.
    if current.as_ref().is_none_or(|(client, _)| client.joined_with_code) {
        refuse_if_ended(org_id, conn).await?;
    }
    refuse_if_pool_ended(&msp.uuid, conn).await?;
    Ok(Checked {
        code,
        msp,
        org,
        current,
    })
}

/// One of the MSP's people who joins the organization, and as what.
struct Joiner {
    user: User,
    grant: Grant,
}

/// Who joining adds, and who stays out: the MSP's staff who reach every
/// client (its admins, and technicians with every client), as a client the
/// console makes gets them. Someone with a place in the organization of
/// their own keeps it, and isn't added. Someone the organization removed or
/// revoked itself stays out; someone it took out only by removing an MSP
/// doesn't. `leaving` are memberships a move takes out first (its current
/// MSP's), counted as already gone.
async fn who_joins(
    msp_id: &MspId,
    org_id: &OrganizationId,
    leaving: &HashSet<MembershipId>,
    conn: &DbConn,
) -> Result<(Vec<Joiner>, Vec<User>), crate::error::Error> {
    let (mut adding, mut staying_out) = (Vec::new(), Vec::new());
    for staff in MspStaff::find_by_msp(msp_id, conn).await {
        if staff.reach(conn).await.is_some() {
            continue;
        }
        let (Some(grant), Some(user)) = (Grant::for_staff(&staff), User::find_by_uuid(&staff.user_uuid, conn).await)
        else {
            continue;
        };
        if Membership::find_by_user_and_org(&user.uuid, org_id, conn).await.is_some_and(|m| !leaving.contains(&m.uuid))
        {
            continue;
        }
        match RemovedMember::try_find(org_id, &user.uuid, conn).await? {
            Some(removal) if !removal.with_msp => staying_out.push(user),
            _ => adding.push(Joiner {
                user,
                grant,
            }),
        }
    }
    Ok((adding, staying_out))
}

fn person_json(user: &User) -> Value {
    json!({ "email": user.email, "name": user.name })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CodeData {
    code: String,
    /// The owner saw that the organization's MSP now is removed first.
    #[serde(default, rename = "move")]
    moving: bool,
}

/// What joining with a code would do, before anything changes: which MSP it
/// is, the MSP the organization has now (for a move), who would be added and
/// as what, and who stays out. The organization's own owners only, with the
/// checks joining makes.
#[post("/keykeeper/organizations/<org_id>/msp/link/preview", data = "<data>")]
async fn preview(org_id: OrganizationId, data: Json<CodeData>, headers: Headers, conn: DbConn) -> JsonResult {
    let checked = check(&org_id, &data.code, &headers.user, &conn).await?;
    let leaving: HashSet<MembershipId> = match &checked.current {
        Some((client, _)) => MspMembership::try_find_by_msp(&client.msp_uuid, &conn)
            .await?
            .into_iter()
            .map(|m| m.membership_uuid)
            .collect(),
        None => HashSet::new(),
    };
    let (adding, staying_out) = who_joins(&checked.msp.uuid, &org_id, &leaving, &conn).await?;
    Ok(Json(json!({
        "msp": { "id": checked.msp.uuid, "name": checked.msp.name },
        "current": checked.current.as_ref().map(|(_, msp)| json!({ "id": msp.uuid, "name": msp.name })),
        "adding": adding.iter().map(|j| {
            let mut person = person_json(&j.user);
            person["role"] = json!(j.grant.in_words());
            person
        }).collect::<Vec<_>>(),
        "stayingOut": staying_out.iter().map(person_json).collect::<Vec<_>>(),
    })))
}

/// Joins the organization to the MSP whose code its owner entered, or, with
/// `move`, moves it there from the MSP it has now. One transaction: if
/// anything fails, nothing changes and the code still works.
#[post("/keykeeper/organizations/<org_id>/msp/link", data = "<data>")]
async fn link(org_id: OrganizationId, data: Json<CodeData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data = data.into_inner();
    let checked = check(&org_id, &data.code, &headers.user, &conn).await?;
    if let Some((_, current)) = &checked.current
        && !data.moving
    {
        err!(format!(
            "{} is {}'s client now. Moving to {} removes {} and all of its staff from it first: confirm the move to go on.",
            checked.org.name, current.name, checked.msp.name, current.name
        ))
    }
    // The staff it reaches may come under two-step login for admins there.
    let staff_ids = MspStaff::find_by_msp(&checked.msp.uuid, &conn).await.into_iter().map(|s| s.user_uuid);
    let watch = keykeeper_two_step::Watch::users(staff_ids, &conn).await?;
    begin_write(&org_id, &conn).await?;
    let answer = match join(&org_id, &checked, &headers, &conn).await {
        Ok(answer) => answer,
        Err(e) => {
            rollback_write(&conn).await;
            return Err(e);
        }
    };
    if let Err(e) = commit_write(&conn).await {
        rollback_write(&conn).await;
        return Err(e);
    }
    watch.settle(&conn).await?;
    Ok(Json(answer))
}

/// The organization's msp_clients row as it joins: its own install command,
/// if it has one, moves to the MSP with its token and join secret, so
/// commands already run keep working, along with its preset and the
/// collection people who join get. Without one, the MSP gets a new command,
/// as for a client the console makes.
async fn new_client(org_id: &OrganizationId, msp_id: &MspId, conn: &DbConn) -> Result<MspClient, crate::error::Error> {
    let setup = OrgSetup::find_by_org(org_id, conn).await;
    let preset = setup.as_ref().and_then(|s| s.preset.clone());
    let everyone = setup.as_ref().and_then(|s| s.everyone_collection.clone());
    let mut client = match setup {
        Some(mut setup) if setup.enrollment_token.is_some() => {
            let client = MspClient {
                org_uuid: org_id.clone(),
                msp_uuid: msp_id.clone(),
                created_at: Utc::now().naive_utc(),
                preset,
                enrollment_token: setup.enrollment_token.clone(),
                enrollment_token_created_at: setup.enrollment_token_created_at,
                everyone_collection: everyone,
                templates_collection: None,
                enrollment_secret: setup.enrollment_secret.clone(),
                enrollment_token_hash: setup.enrollment_token_hash.clone(),
                client_seal: None,
                joined_with_code: true,
            };
            setup.hand_over_enrollment_token(conn).await?;
            client
        }
        _ => MspClient::new(org_id.clone(), msp_id.clone(), preset, everyone)?,
    };
    client.joined_with_code = true;
    Ok(client)
}

/// Joining itself, inside the transaction `link` holds.
async fn join(
    org_id: &OrganizationId,
    checked: &Checked,
    headers: &Headers,
    conn: &DbConn,
) -> Result<Value, crate::error::Error> {
    // The code is used up here, once: a second request with it, at the same
    // moment or later, finds nothing to use.
    if !checked.code.delete(conn).await? {
        err_code!(INVALID_CODE, rocket::http::Status::NotFound.code)
    }
    // The organization's MSP is still the one the owner was shown.
    let current = MspClient::find_by_org(org_id, conn).await;
    if current.as_ref().map(|c| &c.msp_uuid) != checked.current.as_ref().map(|(c, _)| &c.msp_uuid) {
        err!("This organization's MSP changed in the meantime. Enter the code again to see what it would do now.")
    }
    // A move takes the current MSP out first, as removing it does.
    let moved = match current {
        Some(client) => Some(detach_msp(org_id, client, headers, "client_moved_away", conn).await?),
        None => None,
    };
    // How people join stays as it was, as the organization's own setting,
    // until an MSP admin uses the MSP's default there.
    let (joining, _) = effective_joining(org_id, conn).await;
    if OrgJoining::find(org_id, conn).await.is_none() {
        OrgJoining::new(org_id.clone(), joining).save(conn).await?;
    }
    let msp_id = &checked.msp.uuid;
    new_client(org_id, msp_id, conn).await?.insert(conn).await?;

    let org_name = checked.org.name.as_str();
    let mut used = Audit::by("link_code_used", headers).org(org_id, org_name).target(&checked.code.created_by_email);
    used.detail = checked.code.label.clone();
    used.record(msp_id, conn).await?;
    let mut joined = Audit::by("client_joined", headers).org(org_id, org_name);
    joined.detail = moved.is_some().then(|| "move".to_owned());
    joined.record(msp_id, conn).await?;

    // Anyone on its staff the organization took out only by removing an MSP
    // isn't kept out any more: the owner chose this MSP, and saw them listed.
    // Its later staff changes reach them as in any client. Whom the
    // organization removed or revoked itself stays out.
    for staff in MspStaff::find_by_msp(msp_id, conn).await {
        if RemovedMember::try_find(org_id, &staff.user_uuid, conn).await?.is_some_and(|r| r.with_msp) {
            RemovedMember::clear(org_id, &staff.user_uuid, conn).await?;
        }
    }
    // Its staff who reach every client join it, waiting for its key, which
    // its own owner gives them on the Members page.
    let (adding, _) = who_joins(msp_id, org_id, &HashSet::new(), conn).await?;
    let mut added = 0;
    for joiner in adding {
        if add_msp_membership(msp_id, org_id, &joiner.user.uuid, &joiner.grant, &headers.user.email, conn).await? {
            StaffChange {
                msp_id,
                actor: Some(&headers.user.uuid),
                actor_email: &headers.user.email,
                target_email: &joiner.user.email,
            }
            .record("client_staff_added", org_id, Some(joiner.grant.in_words().to_owned()), conn)
            .await?;
            added += 1;
        }
    }
    Ok(json!({
        "msp": { "id": checked.msp.uuid, "name": checked.msp.name },
        "added": added,
        "moved": moved,
    }))
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;

    use super::*;
    use crate::{
        auth::ClientIp,
        db::{
            DbPool,
            models::{
                CustomRole, Device, DeviceId, MembershipStatus, MspEvent, TechnicianAccess, init_install_token_key,
                keykeeper_roles::{self, CustomPermissions},
                token_hash,
            },
        },
    };

    async fn person(name: &str, conn: &DbConn) -> User {
        let mut user = User::new(&format!("{name}@example.test"), None);
        user.public_key = Some(format!("public-key-{name}"));
        user.save(conn).await.unwrap();
        user
    }

    async fn headers(user: &User, conn: &DbConn) -> Headers {
        Headers {
            host: "https://127.0.0.1".to_owned(),
            device: Device::new(
                DeviceId::from(format!("device-{}", user.uuid)),
                user.uuid.clone(),
                "test".to_owned(),
                9,
            ),
            user: User::find_by_uuid(&user.uuid, conn).await.unwrap(),
            ip: ClientIp {
                ip: "127.0.0.1".parse().unwrap(),
            },
        }
    }

    async fn organization(name: &str, conn: &DbConn) -> Organization {
        let org = Organization::new(name.to_owned(), "billing@example.test", None, None);
        org.save(conn).await.unwrap();
        org
    }

    async fn join_as(
        user: &User,
        org: &Organization,
        atype: MembershipType,
        status: MembershipStatus,
        conn: &DbConn,
    ) -> Membership {
        let mut member = Membership::new(user.uuid.clone(), org.uuid.clone(), None);
        member.atype = atype as i32;
        member.status = status as i32;
        member.access_all = atype != MembershipType::User;
        member.save(conn).await.unwrap();
        member
    }

    /// An organization of its own, with a confirmed owner.
    async fn own_org(name: &str, owner: &User, conn: &DbConn) -> Organization {
        let org = organization(name, conn).await;
        join_as(owner, &org, MembershipType::Owner, MembershipStatus::Confirmed, conn).await;
        org
    }

    async fn msp(name: &str, admin: &User, conn: &DbConn) -> MspId {
        let msp = Msp::new(name.to_owned());
        msp.insert(conn).await.unwrap();
        MspStaff::new(msp.uuid.clone(), admin.uuid.clone(), MspRole::Admin).insert(conn).await.unwrap();
        msp.uuid
    }

    async fn technician(msp: &MspId, user: &User, access: Option<TechnicianAccess>, conn: &DbConn) {
        let mut staff = MspStaff::new(msp.clone(), user.uuid.clone(), MspRole::Technician);
        staff.insert(conn).await.unwrap();
        if let Some(access) = access {
            staff.set_access(&access, conn).await.unwrap();
        }
    }

    /// A client the MSP made, with its admin there as the MSP's owner. As the
    /// other tests make one: MspClient::new seals an install token.
    async fn made_client(name: &str, msp: &MspId, admin: &User, conn: &DbConn) -> Organization {
        let org = organization(name, conn).await;
        MspClient {
            org_uuid: org.uuid.clone(),
            msp_uuid: msp.clone(),
            created_at: Utc::now().naive_utc(),
            preset: None,
            enrollment_token: None,
            enrollment_token_created_at: None,
            everyone_collection: None,
            templates_collection: None,
            enrollment_secret: None,
            enrollment_token_hash: None,
            client_seal: None,
            joined_with_code: false,
        }
        .insert(conn)
        .await
        .unwrap();
        let member = join_as(admin, &org, MembershipType::Owner, MembershipStatus::Confirmed, conn).await;
        MspMembership::new(member.uuid.clone(), msp.clone()).insert(conn).await.unwrap();
        org
    }

    /// A code one of the MSP's admins made at `at`.
    async fn code_at(msp: &MspId, admin: &User, at: chrono::NaiveDateTime, conn: &DbConn) -> String {
        let (row, code) = MspLinkCode::new(msp.clone(), Some("Acme Dental".to_owned()), admin, at);
        assert!(row.insert(conn).await.unwrap());
        shown_link_code(&code)
    }

    async fn code(msp: &MspId, admin: &User, conn: &DbConn) -> String {
        code_at(msp, admin, Utc::now().naive_utc(), conn).await
    }

    fn status_of<T>(result: Result<T, crate::error::Error>) -> (u16, String) {
        match result {
            Ok(_) => (200, String::new()),
            Err(e) => (e.status_code(), e.message().to_owned()),
        }
    }

    async fn checked(org: &Organization, typed: &str, user: &User, conn: &DbConn) -> (u16, String) {
        status_of(check(&org.uuid, typed, user, conn).await)
    }

    fn data(code: &str, moving: bool) -> Json<CodeData> {
        Json(CodeData {
            code: code.to_owned(),
            moving,
        })
    }

    async fn link_as(pool: &DbPool, org: &Organization, code: &str, moving: bool, user: &User) -> JsonResult {
        let conn = pool.get().await.unwrap();
        let headers = headers(user, &conn).await;
        link(org.uuid.clone(), data(code, moving), headers, conn).await
    }

    async fn membership(user: &User, org: &Organization, conn: &DbConn) -> Option<Membership> {
        Membership::find_by_user_and_org(&user.uuid, &org.uuid, conn).await
    }

    async fn msp_events(msp: &MspId, conn: &DbConn) -> Vec<String> {
        MspEvent::find_by_msp(msp, None, None, Vec::new(), 100, conn).await.into_iter().map(|e| e.event).collect()
    }

    #[rocket::async_test]
    async fn only_the_organizations_own_confirmed_owners_may_use_a_code() {
        let conn = DbPool::for_test().await;
        let msp_admin = person("msp-admin", &conn).await;
        let msp_id = msp("Northwind IT", &msp_admin, &conn).await;
        let code = code(&msp_id, &msp_admin, &conn).await;
        let owner = person("owner", &conn).await;
        let acme = own_org("Acme Dental", &owner, &conn).await;
        assert_eq!(checked(&acme, &code, &owner, &conn).await, (200, String::new()));

        // Members who aren't owners: a plain 400, whatever the code.
        for (name, atype) in
            [("admin", MembershipType::Admin), ("user", MembershipType::User), ("manager", MembershipType::Manager)]
        {
            let member = person(name, &conn).await;
            join_as(&member, &acme, atype, MembershipStatus::Confirmed, &conn).await;
            assert_eq!(checked(&acme, &code, &member, &conn).await, (400, OWNERS_ONLY.to_owned()), "{name}");
            assert_eq!(checked(&acme, "nonsense", &member, &conn).await, (400, OWNERS_ONLY.to_owned()), "{name}");
        }
        // A custom role, even one that manages members.
        let contact = person("contact", &conn).await;
        let custom = join_as(&contact, &acme, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        let permissions = CustomPermissions {
            manage_users: true,
            ..Default::default()
        };
        keykeeper_roles::set(&custom.uuid, Some(&permissions), &conn).await.unwrap();
        assert_eq!(checked(&acme, &code, &contact, &conn).await.0, 400);

        // Owners who aren't confirmed, or were revoked, and strangers: not found.
        for (name, status) in [
            ("invited", MembershipStatus::Invited),
            ("accepted", MembershipStatus::Accepted),
            ("revoked", MembershipStatus::Revoked),
        ] {
            let member = person(name, &conn).await;
            join_as(&member, &acme, MembershipType::Owner, status, &conn).await;
            assert_eq!(
                checked(&acme, &code, &member, &conn).await,
                (404, "Organization not found".to_owned()),
                "{name}"
            );
        }
        let stranger = person("stranger", &conn).await;
        assert_eq!(checked(&acme, &code, &stranger, &conn).await, (404, "Organization not found".to_owned()));
        // The MSP's own admin, who isn't in the organization.
        assert_eq!(checked(&acme, &code, &msp_admin, &conn).await.0, 404);
    }

    #[rocket::async_test]
    async fn an_owner_or_technician_whose_place_came_through_an_msp_may_not() {
        let conn = DbPool::for_test().await;
        let msp_admin = person("msp-admin", &conn).await;
        let msp_id = msp("Northwind IT", &msp_admin, &conn).await;
        let other_admin = person("other-admin", &conn).await;
        let other_msp = msp("Contoso IT", &other_admin, &conn).await;
        let code = code(&msp_id, &msp_admin, &conn).await;

        // A client of another MSP: its admin is an owner there through the
        // MSP, and its technician an admin through it. Neither may move it.
        let fabrikam = made_client("Fabrikam", &other_msp, &other_admin, &conn).await;
        assert_eq!(checked(&fabrikam, &code, &other_admin, &conn).await, (400, OWNERS_ONLY.to_owned()));
        let tech = person("tech", &conn).await;
        technician(&other_msp, &tech, None, &conn).await;
        let tech_member = join_as(&tech, &fabrikam, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        MspMembership::new(tech_member.uuid.clone(), other_msp.clone()).insert(&conn).await.unwrap();
        assert_eq!(checked(&fabrikam, &code, &tech, &conn).await, (400, OWNERS_ONLY.to_owned()));
        // Nor may the joining MSP's own technician, in an organization where
        // it isn't an owner.
        let ours = person("our-tech", &conn).await;
        technician(&msp_id, &ours, None, &conn).await;
        join_as(&ours, &fabrikam, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        assert_eq!(checked(&fabrikam, &code, &ours, &conn).await, (400, OWNERS_ONLY.to_owned()));

        // An owner whose place is the client's own may, with the move said.
        let owner = person("owner", &conn).await;
        join_as(&owner, &fabrikam, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        assert_eq!(checked(&fabrikam, &code, &owner, &conn).await.0, 200);
        // Someone on an MSP's staff who owns an organization of their own may
        // use a code there.
        let own = own_org("Tech's Own", &tech, &conn).await;
        assert_eq!(checked(&own, &code, &tech, &conn).await.0, 200);
    }

    #[rocket::async_test]
    async fn a_code_that_doesnt_work_is_not_found_whatever_is_wrong() {
        let pool = DbPool::for_test_pool();
        let conn = pool.get().await.unwrap();
        init_install_token_key(b"keykeeper msp link tests");
        let msp_admin = person("msp-admin", &conn).await;
        let msp_id = msp("Northwind IT", &msp_admin, &conn).await;
        let owner = person("owner", &conn).await;
        let acme = own_org("Acme Dental", &owner, &conn).await;
        let not_valid = (404, INVALID_CODE.to_owned());

        // Malformed, and made up.
        for typed in ["", "nonsense", "7KQ2-MXP4-ZT9W", "7KQ2-MXP4-ZT9W-HN3R-VB8C-J5DF"] {
            assert_eq!(checked(&acme, typed, &owner, &conn).await, not_valid, "{typed}");
        }
        // Guessed: a real code's first 8 characters, the rest wrong.
        let real = code(&msp_id, &msp_admin, &conn).await;
        let mut guess = real.clone().into_bytes();
        let last = guess.len() - 1;
        guess[last] = if guess[last] == b'0' {
            b'1'
        } else {
            b'0'
        };
        assert_eq!(checked(&acme, &String::from_utf8(guess).unwrap(), &owner, &conn).await, not_valid);
        assert_eq!(checked(&acme, &real, &owner, &conn).await.0, 200);
        // Typed in lower case, without dashes: the same code.
        assert_eq!(checked(&acme, &real.replace('-', "").to_lowercase(), &owner, &conn).await.0, 200);

        // Ended: made more than 7 days ago.
        let old = code_at(&msp_id, &msp_admin, Utc::now().naive_utc() - TimeDelta::days(8), &conn).await;
        assert_eq!(checked(&acme, &old, &owner, &conn).await, not_valid);

        // Revoked.
        let revoked = code(&msp_id, &msp_admin, &conn).await;
        let id = MspLinkCode::open_for_msp(&msp_id, Utc::now().naive_utc(), &conn)
            .await
            .unwrap()
            .into_iter()
            .find(|c| revoked.replace('-', "").starts_with(&c.selector))
            .unwrap()
            .uuid;
        drop(conn);
        let conn = pool.get().await.unwrap();
        let admin_headers = headers(&msp_admin, &conn).await;
        revoke_code(msp_id.clone(), &id, admin_headers, conn).await.unwrap();
        let conn = pool.get().await.unwrap();
        assert_eq!(checked(&acme, &revoked, &owner, &conn).await, not_valid);
        drop(conn);

        // Used: it works once.
        link_as(&pool, &acme, &real, false, &owner).await.unwrap();
        let other_owner = person_in(&pool, "other-owner").await;
        let other = {
            let conn = pool.get().await.unwrap();
            own_org("Baker Law", &other_owner, &conn).await
        };
        let conn = pool.get().await.unwrap();
        assert_eq!(checked(&other, &real, &other_owner, &conn).await, not_valid);
        drop(conn);
        assert_eq!(status_of(link_as(&pool, &other, &real, false, &other_owner).await), not_valid);
        let conn = pool.get().await.unwrap();
        assert!(MspClient::find_by_org(&other.uuid, &conn).await.is_none());
    }

    async fn as_(pool: &DbPool, user: &User) -> (Headers, DbConn) {
        let conn = pool.get().await.unwrap();
        (headers(user, &conn).await, conn)
    }

    async fn person_in(pool: &DbPool, name: &str) -> User {
        let conn = pool.get().await.unwrap();
        person(name, &conn).await
    }

    #[rocket::async_test]
    async fn the_database_keeps_a_hash_and_the_first_8_characters_never_the_code() {
        let conn = DbPool::for_test().await;
        let msp_admin = person("msp-admin", &conn).await;
        let msp_id = msp("Northwind IT", &msp_admin, &conn).await;
        let shown = code(&msp_id, &msp_admin, &conn).await;
        let code = shown.replace('-', "");
        let row = MspLinkCode::find_by_selector(&code[..8], &conn).await.unwrap();
        assert_eq!(row.code_hash, token_hash(&code));
        assert!(!row.code_hash.contains(&code[8..]));
        assert_eq!(row.selector.len(), 8);
        assert_eq!(row.created_by_email, msp_admin.email);
        assert_eq!(row.expires_at - row.created_at, TimeDelta::days(7));
    }

    #[rocket::async_test]
    async fn only_the_msps_admins_make_list_and_revoke_codes() {
        let pool = DbPool::for_test_pool();
        let conn = pool.get().await.unwrap();
        let admin = person("msp-admin", &conn).await;
        let msp_id = msp("Northwind IT", &admin, &conn).await;
        let tech = person("tech", &conn).await;
        technician(&msp_id, &tech, None, &conn).await;
        let other_admin = person("other-admin", &conn).await;
        let other_msp = msp("Contoso IT", &other_admin, &conn).await;
        let stranger = person("stranger", &conn).await;
        drop(conn);

        let made = {
            let (h, conn) = as_(&pool, &admin).await;
            make_code(
                msp_id.clone(),
                Some(Json(MakeCodeData {
                    label: Some(" Acme Dental ".to_owned()),
                })),
                h,
                conn,
            )
            .await
            .unwrap()
            .into_inner()
        };
        assert_eq!(made["label"], "Acme Dental");
        assert_eq!(made["code"].as_str().unwrap().len(), 29);
        let id = made["id"].as_str().unwrap().to_owned();
        let (h, conn) = as_(&pool, &admin).await;
        let listed = list_codes(msp_id.clone(), h, conn).await.unwrap().into_inner();
        assert_eq!(listed["data"].as_array().unwrap().len(), 1);
        assert!(listed["data"][0].get("code").is_none());

        for caller in [&tech, &other_admin, &stranger] {
            let (h, conn) = as_(&pool, caller).await;
            assert_eq!(status_of(list_codes(msp_id.clone(), h, conn).await).0, 404, "{}", caller.email);
            let (h, conn) = as_(&pool, caller).await;
            assert_eq!(status_of(make_code(msp_id.clone(), None, h, conn).await).0, 404, "{}", caller.email);
            let (h, conn) = as_(&pool, caller).await;
            assert_eq!(status_of(revoke_code(msp_id.clone(), &id, h, conn).await).0, 404, "{}", caller.email);
        }
        // Another MSP's admin can't revoke it through their own MSP either.
        let (h, conn) = as_(&pool, &other_admin).await;
        assert_eq!(status_of(revoke_code(other_msp.clone(), &id, h, conn).await).0, 404);
        let (h, conn) = as_(&pool, &admin).await;
        assert_eq!(
            list_codes(msp_id.clone(), h, conn).await.unwrap().into_inner()["data"].as_array().unwrap().len(),
            1
        );

        // Who it's for: plain text, not too long.
        let (h, conn) = as_(&pool, &admin).await;
        let refused = make_code(
            msp_id.clone(),
            Some(Json(MakeCodeData {
                label: Some("a\nb".to_owned()),
            })),
            h,
            conn,
        )
        .await;
        assert_eq!(status_of(refused).0, 400);
        let (h, conn) = as_(&pool, &admin).await;
        let refused = make_code(
            msp_id.clone(),
            Some(Json(MakeCodeData {
                label: Some("x".repeat(101)),
            })),
            h,
            conn,
        )
        .await;
        assert_eq!(status_of(refused).0, 400);

        // At most 25 open at once.
        for _ in 1..MAX_OPEN_LINK_CODES {
            let (h, conn) = as_(&pool, &admin).await;
            make_code(msp_id.clone(), None, h, conn).await.unwrap();
        }
        let (h, conn) = as_(&pool, &admin).await;
        assert_eq!(status_of(make_code(msp_id.clone(), None, h, conn).await).0, 400);
        let (h, conn) = as_(&pool, &admin).await;
        revoke_code(msp_id.clone(), &id, h, conn).await.unwrap();
        let (h, conn) = as_(&pool, &admin).await;
        make_code(msp_id.clone(), None, h, conn).await.unwrap();

        let conn = pool.get().await.unwrap();
        let events = msp_events(&msp_id, &conn).await;
        assert_eq!(events.iter().filter(|e| *e == "link_code_created").count(), 26);
        assert_eq!(events.iter().filter(|e| *e == "link_code_revoked").count(), 1);
    }

    #[rocket::async_test]
    async fn joining_adds_the_staff_who_reach_every_client_waiting_for_the_key() {
        let pool = DbPool::for_test_pool();
        let conn = pool.get().await.unwrap();
        init_install_token_key(b"keykeeper msp link tests");
        let admin = person("msp-admin", &conn).await;
        let msp_id = msp("Northwind IT", &admin, &conn).await;
        let tech = person("tech", &conn).await;
        technician(&msp_id, &tech, None, &conn).await;
        let helpdesk = person("helpdesk", &conn).await;
        let custom = TechnicianAccess {
            all_clients: true,
            clients: Vec::new(),
            custom: Some(CustomRole {
                permissions: CustomPermissions {
                    manage_users: true,
                    ..Default::default()
                },
                vault_items: false,
            }),
            install_commands: false,
            script_access: false,
            client_roles: Vec::new(),
        };
        technician(&msp_id, &helpdesk, Some(custom), &conn).await;
        let chosen = person("chosen", &conn).await;
        let other_client = made_client("Baker Law", &msp_id, &admin, &conn).await;
        technician(
            &msp_id,
            &chosen,
            Some(TechnicianAccess {
                all_clients: false,
                clients: vec![other_client.uuid.clone()],
                custom: None,
                install_commands: true,
                script_access: false,
                client_roles: Vec::new(),
            }),
            &conn,
        )
        .await;
        // Two the organization took out before: one it removed itself, one
        // only when it removed an earlier MSP.
        let removed = person("removed", &conn).await;
        technician(&msp_id, &removed, None, &conn).await;
        let with_msp = person("with-msp", &conn).await;
        technician(&msp_id, &with_msp, None, &conn).await;
        let owner = person("owner", &conn).await;
        let acme = own_org("Acme Dental", &owner, &conn).await;
        RemovedMember::record(&acme.uuid, &removed.uuid, None, false, &conn).await.unwrap();
        RemovedMember::record_with_msp(&acme.uuid, &with_msp.uuid, &msp_id, &conn).await.unwrap();
        // And one already there with a place of their own.
        let own = person("own", &conn).await;
        technician(&msp_id, &own, None, &conn).await;
        let own_member = join_as(&own, &acme, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        let code = code(&msp_id, &admin, &conn).await;
        drop(conn);

        // The preview says who joins, as what, and who stays out.
        let conn = pool.get().await.unwrap();
        let h = headers(&owner, &conn).await;
        let preview = preview(acme.uuid.clone(), data(&code, false), h, conn).await.unwrap().into_inner();
        assert_eq!(preview["msp"]["name"], "Northwind IT");
        assert_eq!(preview["current"], Value::Null);
        let roles: Vec<(String, String)> = preview["adding"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (p["email"].as_str().unwrap().to_owned(), p["role"].as_str().unwrap().to_owned()))
            .collect();
        assert_eq!(
            roles,
            vec![
                (admin.email.clone(), "owner".to_owned()),
                (tech.email.clone(), "admin".to_owned()),
                (helpdesk.email.clone(), "custom".to_owned()),
                (with_msp.email.clone(), "admin".to_owned()),
            ]
        );
        assert_eq!(preview["stayingOut"][0]["email"], removed.email.as_str());
        assert_eq!(preview["stayingOut"].as_array().unwrap().len(), 1);
        // Looking changed nothing.
        let conn = pool.get().await.unwrap();
        assert!(MspClient::find_by_org(&acme.uuid, &conn).await.is_none());
        assert!(find_link_code(&code, Utc::now().naive_utc(), &conn).await.is_some());
        drop(conn);

        let answer = link_as(&pool, &acme, &code, false, &owner).await.unwrap().into_inner();
        assert_eq!(answer["added"], 4);
        assert_eq!(answer["moved"], Value::Null);
        let conn = pool.get().await.unwrap();
        let client = MspClient::find_by_org(&acme.uuid, &conn).await.unwrap();
        assert_eq!(client.msp_uuid, msp_id);
        assert!(client.joined_with_code);
        assert!(client.client_seal.is_none());
        assert!(client.enrollment_token_hash.is_some());
        for (user, atype) in [
            (&admin, MembershipType::Owner),
            (&tech, MembershipType::Admin),
            (&helpdesk, MembershipType::User),
            (&with_msp, MembershipType::Admin),
        ] {
            let member = membership(user, &acme, &conn).await.unwrap_or_else(|| panic!("{} added", user.email));
            // Waiting for the organization's key: nobody gave it to them.
            assert_eq!(member.status, MembershipStatus::Accepted as i32, "{}", user.email);
            assert_eq!(member.akey, "", "{}", user.email);
            assert_eq!(member.atype, atype as i32, "{}", user.email);
            assert!(MspMembership::find_by_membership(&member.uuid, &conn).await.is_some(), "{}", user.email);
        }
        assert!(keykeeper_roles::find(&membership(&helpdesk, &acme, &conn).await.unwrap().uuid, &conn).await.is_some());
        assert!(membership(&chosen, &acme, &conn).await.is_none());
        assert!(membership(&removed, &acme, &conn).await.is_none());
        assert!(RemovedMember::exists(&acme.uuid, &removed.uuid, &conn).await);
        assert!(!RemovedMember::exists(&acme.uuid, &with_msp.uuid, &conn).await);
        // A place of their own stays theirs.
        let kept = membership(&own, &acme, &conn).await.unwrap();
        assert_eq!(kept.uuid, own_member.uuid);
        assert!(MspMembership::find_by_membership(&kept.uuid, &conn).await.is_none());
        // How people join is kept as the organization's own.
        assert!(OrgJoining::find(&acme.uuid, &conn).await.is_some());
        // The code is used up.
        assert!(find_link_code(&code, Utc::now().naive_utc(), &conn).await.is_none());

        // What the MSP's Activity says, and the client's own view.
        let events = msp_events(&msp_id, &conn).await;
        assert!(events.contains(&"link_code_used".to_owned()), "{events:?}");
        assert!(events.contains(&"client_joined".to_owned()), "{events:?}");
        let seen: Vec<MspEvent> = MspEvent::find_by_client(
            &msp_id,
            &acme.uuid,
            super::super::keykeeper_msp_activity::CLIENT_KINDS,
            None,
            100,
            &conn,
        )
        .await;
        assert_eq!(seen.iter().filter(|e| e.event == "client_staff_added").count(), 4);
        let joined = seen.iter().find(|e| e.event == "client_joined").unwrap();
        assert_eq!(joined.actor_email.as_deref(), Some(owner.email.as_str()));
        assert!(joined.detail.is_none());
        assert!(!seen.iter().any(|e| e.event == "link_code_used"));
    }

    #[rocket::async_test]
    async fn the_organizations_own_install_command_moves_to_the_msp() {
        let pool = DbPool::for_test_pool();
        let conn = pool.get().await.unwrap();
        let admin = person("msp-admin", &conn).await;
        let msp_id = msp("Northwind IT", &admin, &conn).await;
        let owner = person("owner", &conn).await;
        let acme = own_org("Acme Dental", &owner, &conn).await;
        let mut setup = OrgSetup::new(acme.uuid.clone(), Some("business".to_owned()), None, false).unwrap();
        setup.enrollment_token = Some("sealed-token".to_owned());
        setup.enrollment_token_hash = Some(token_hash("the-token"));
        setup.enrollment_token_created_at = Some(Utc::now().naive_utc());
        setup.enrollment_secret = Some("2.secret".to_owned());
        setup.insert(&conn).await.unwrap();
        let code = code(&msp_id, &admin, &conn).await;
        drop(conn);

        link_as(&pool, &acme, &code, false, &owner).await.unwrap();
        let conn = pool.get().await.unwrap();
        let client = MspClient::find_by_enrollment_token("the-token", &conn).await.unwrap();
        assert_eq!(client.org_uuid, acme.uuid);
        assert_eq!(client.enrollment_secret.as_deref(), Some("2.secret"));
        assert_eq!(client.preset.as_deref(), Some("business"));
        assert!(OrgSetup::find_by_enrollment_token("the-token", &conn).await.is_none());
        let setup = OrgSetup::find_by_org(&acme.uuid, &conn).await.unwrap();
        assert!(setup.enrollment_token.is_none() && setup.enrollment_secret.is_none());
        assert_eq!(setup.preset.as_deref(), Some("business"));
    }

    #[rocket::async_test]
    async fn an_msps_client_already_needs_the_move_said() {
        let pool = DbPool::for_test_pool();
        let conn = pool.get().await.unwrap();
        init_install_token_key(b"keykeeper msp link tests");
        let old_admin = person("old-admin", &conn).await;
        let old_msp = msp("Contoso IT", &old_admin, &conn).await;
        let new_admin = person("new-admin", &conn).await;
        let new_msp = msp("Northwind IT", &new_admin, &conn).await;
        let acme = made_client("Acme Dental", &old_msp, &old_admin, &conn).await;
        let owner = person("owner", &conn).await;
        join_as(&owner, &acme, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;

        // The MSP it has already: nothing to do.
        let same = code(&old_msp, &old_admin, &conn).await;
        assert_eq!(
            checked(&acme, &same, &owner, &conn).await,
            (400, "Acme Dental is already Contoso IT's client.".to_owned())
        );
        let code = code(&new_msp, &new_admin, &conn).await;
        drop(conn);

        // The preview names its MSP now.
        let conn = pool.get().await.unwrap();
        let h = headers(&owner, &conn).await;
        let seen = preview(acme.uuid.clone(), data(&code, false), h, conn).await.unwrap().into_inner();
        assert_eq!(seen["current"]["name"], "Contoso IT");
        assert_eq!(seen["msp"]["name"], "Northwind IT");

        // Without the move said, nothing changes and the code still works.
        let (status, message) = status_of(link_as(&pool, &acme, &code, false, &owner).await);
        assert_eq!(status, 400);
        assert!(message.contains("Contoso IT") && message.contains("confirm the move"), "{message}");
        let conn = pool.get().await.unwrap();
        assert_eq!(MspClient::find_by_org(&acme.uuid, &conn).await.unwrap().msp_uuid, old_msp);
        assert!(find_link_code(&code, Utc::now().naive_utc(), &conn).await.is_some());
    }

    #[rocket::async_test]
    async fn a_move_takes_the_old_msp_out_and_brings_the_new_one_in() {
        let pool = DbPool::for_test_pool();
        let conn = pool.get().await.unwrap();
        init_install_token_key(b"keykeeper msp link tests");
        let old_admin = person("old-admin", &conn).await;
        let old_msp = msp("Contoso IT", &old_admin, &conn).await;
        let old_tech = person("old-tech", &conn).await;
        technician(&old_msp, &old_tech, None, &conn).await;
        let new_admin = person("new-admin", &conn).await;
        let new_msp = msp("Northwind IT", &new_admin, &conn).await;
        // Someone on both MSPs' staff.
        let both = person("both", &conn).await;
        technician(&new_msp, &both, None, &conn).await;
        technician(&old_msp, &both, None, &conn).await;
        let acme = made_client("Acme Dental", &old_msp, &old_admin, &conn).await;
        for tech in [&old_tech, &both] {
            let member = join_as(tech, &acme, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
            MspMembership::new(member.uuid.clone(), old_msp.clone()).insert(&conn).await.unwrap();
        }
        let owner = person("owner", &conn).await;
        join_as(&owner, &acme, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        let code = code(&new_msp, &new_admin, &conn).await;
        drop(conn);

        let answer = link_as(&pool, &acme, &code, true, &owner).await.unwrap().into_inner();
        assert_eq!(answer["moved"]["msp"]["name"], "Contoso IT");
        assert_eq!(answer["moved"]["peopleRemoved"], 3);
        assert_eq!(answer["added"], 2);
        let conn = pool.get().await.unwrap();
        let client = MspClient::find_by_org(&acme.uuid, &conn).await.unwrap();
        assert_eq!(client.msp_uuid, new_msp);
        assert!(client.joined_with_code);
        // The old MSP's people are out, remembered as taken out with it.
        for user in [&old_admin, &old_tech] {
            assert!(membership(user, &acme, &conn).await.is_none(), "{}", user.email);
            assert!(RemovedMember::try_find(&acme.uuid, &user.uuid, &conn).await.unwrap().unwrap().with_msp);
        }
        // The new one's are in, waiting: someone on both staffs too.
        for user in [&new_admin, &both] {
            let member = membership(user, &acme, &conn).await.unwrap();
            assert_eq!(member.status, MembershipStatus::Accepted as i32, "{}", user.email);
            assert!(!RemovedMember::exists(&acme.uuid, &user.uuid, &conn).await);
        }
        assert_eq!(membership(&owner, &acme, &conn).await.unwrap().status, MembershipStatus::Confirmed as i32);
        // Each MSP's Activity says so, the old one without naming the new.
        assert!(msp_events(&old_msp, &conn).await.contains(&"client_moved_away".to_owned()));
        assert!(!msp_events(&old_msp, &conn).await.contains(&"client_removed_msp".to_owned()));
        let joined = MspEvent::find_by_msp(&new_msp, None, None, Vec::new(), 100, &conn)
            .await
            .into_iter()
            .find(|e| e.event == "client_joined")
            .unwrap();
        assert_eq!(joined.detail.as_deref(), Some("move"));
        let moved_away = MspEvent::find_by_msp(&old_msp, None, None, Vec::new(), 100, &conn)
            .await
            .into_iter()
            .find(|e| e.event == "client_moved_away")
            .unwrap();
        assert!(!format!("{:?}{:?}", moved_away.detail, moved_away.target_email).contains("Northwind"));
    }

    #[rocket::async_test]
    async fn a_move_that_fails_partway_changes_nothing() {
        let pool = DbPool::for_test_pool();
        let conn = pool.get().await.unwrap();
        let old_admin = person("old-admin", &conn).await;
        let old_msp = msp("Contoso IT", &old_admin, &conn).await;
        let new_admin = person("new-admin", &conn).await;
        let new_msp = msp("Northwind IT", &new_admin, &conn).await;
        let acme = made_client("Acme Dental", &old_msp, &old_admin, &conn).await;
        let owner = person("owner", &conn).await;
        join_as(&owner, &acme, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        let typed = code(&new_msp, &new_admin, &conn).await;
        let found = check(&acme.uuid, &typed, &owner, &conn).await.unwrap();
        let h = headers(&owner, &conn).await;

        // The transaction link holds, with the code used and the old MSP
        // taken out, and then a failure.
        begin_write(&acme.uuid, &conn).await.unwrap();
        assert!(found.code.delete(&conn).await.unwrap());
        let client = MspClient::find_by_org(&acme.uuid, &conn).await.unwrap();
        detach_msp(&acme.uuid, client, &h, "client_moved_away", &conn).await.unwrap();
        assert!(MspClient::find_by_org(&acme.uuid, &conn).await.is_none());
        rollback_write(&conn).await;

        // Nothing happened: the old MSP and its admin are there, the code
        // still works, and no activity was recorded.
        assert_eq!(MspClient::find_by_org(&acme.uuid, &conn).await.unwrap().msp_uuid, old_msp);
        let admin_place = membership(&old_admin, &acme, &conn).await.unwrap();
        assert_eq!(admin_place.status, MembershipStatus::Confirmed as i32);
        assert!(!RemovedMember::exists(&acme.uuid, &old_admin.uuid, &conn).await);
        assert!(find_link_code(&typed, Utc::now().naive_utc(), &conn).await.is_some());
        assert!(!msp_events(&old_msp, &conn).await.contains(&"client_moved_away".to_owned()));
        // And the connection works as before, outside any transaction.
        drop(conn);
        init_install_token_key(b"keykeeper msp link tests");
        link_as(&pool, &acme, &typed, true, &owner).await.unwrap();
        let conn = pool.get().await.unwrap();
        assert_eq!(MspClient::find_by_org(&acme.uuid, &conn).await.unwrap().msp_uuid, new_msp);
    }

    #[rocket::async_test]
    async fn a_code_used_in_the_meantime_joins_nothing() {
        let pool = DbPool::for_test_pool();
        let conn = pool.get().await.unwrap();
        init_install_token_key(b"keykeeper msp link tests");
        let admin = person("msp-admin", &conn).await;
        let msp_id = msp("Northwind IT", &admin, &conn).await;
        let owner = person("owner", &conn).await;
        let acme = own_org("Acme Dental", &owner, &conn).await;
        let typed = code(&msp_id, &admin, &conn).await;
        let found = check(&acme.uuid, &typed, &owner, &conn).await.unwrap();
        // Another request used it between the check and the join.
        assert!(found.code.delete(&conn).await.unwrap());
        let h = headers(&owner, &conn).await;
        begin_write(&acme.uuid, &conn).await.unwrap();
        let joined = join(&acme.uuid, &found, &h, &conn).await;
        rollback_write(&conn).await;
        assert_eq!(status_of(joined), (404, INVALID_CODE.to_owned()));
        assert!(MspClient::find_by_org(&acme.uuid, &conn).await.is_none());
        assert!(membership(&admin, &acme, &conn).await.is_none());
    }
}

// Keykeeper: a family's invite link (DESIGN.md, "A family's invite link", in
// the meta repo). Someone with the link opens the web vault's join page, signs
// in or makes an account with any email address, and joins as a member
// waiting for the family's key, counted against the family's people limit
// under the same lock as every other way in. An owner or admin then confirms
// them with one tap, or, where the owner chose automatic, an owner's or
// admin's unlocked web vault or extension lets them in with the install
// command's background work, after checking what the server can't forge.
//
// The server keeps only the SHA-256 of the link's token and never sees its
// join secret. Joining gives it nothing that decrypts anything: the family's
// key reaches a new member only through upstream's confirm.
//
// Only for families: an organization whose plan is Families, on a server that
// enforces plans, that isn't an MSP's client. Only its owners and admins see
// or change the link; anyone else, and any other organization, gets "not
// found", since the web vault signs out on 403.
//
// Also the suggestion to add a legacy contact that a family's owners get.

use chrono::{NaiveDateTime, Utc};
use rocket::{Route, serde::json::Json};
use serde_json::{Value, json};

use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult, JsonResult},
    auth::Headers,
    db::{
        DbConn,
        models::{
            Collection, CollectionId, CollectionUser, EmergencyAccess, FAMILY_LINK_DAYS, FamilyLink, FamilyLinkJoin,
            FamilyWithin, LegacyContactSuggestion, Membership, MembershipStatus, MembershipType, MspClient,
            Organization, OrganizationId, PlanOwner, User, UserId, plan_at, valid_family_link_token,
            valid_sealed_settings,
        },
    },
    mail,
};

pub fn routes() -> Vec<Route> {
    routes![
        get_link,
        make_link,
        set_approval,
        turn_off,
        link_info,
        join,
        legacy_contact_suggestion,
        dismiss_legacy_contact_suggestion
    ]
}

/// The one answer for every link that doesn't work, whatever the reason.
const LINK_DOESNT_WORK: &str = "This invite link doesn't work. Ask whoever sent it for a new one.";

fn not_found() -> crate::error::Error {
    crate::error::Error::new_msg("Organization not found").with_code(rocket::http::Status::NotFound.code)
}

fn doesnt_work() -> crate::error::Error {
    crate::error::Error::new_msg(LINK_DOESNT_WORK).with_code(rocket::http::Status::NotFound.code)
}

/// How many people the organization's Family preset covers, or None for an
/// organization without it: a Business organization, an MSP's client, any
/// organization on a server that doesn't enforce plans (`enforced`), and one
/// whose plan isn't Families.
async fn family_limit(enforced: bool, org: &OrganizationId, conn: &DbConn) -> ApiResult<Option<i64>> {
    if !enforced || MspClient::find_by_org(org, conn).await.is_some() {
        return Ok(None);
    }
    let plan = plan_at(&PlanOwner::Organization(org.clone()), None, Utc::now().naive_utc(), conn).await?;
    Ok(if plan.is_family() {
        plan.people_limit()
    } else {
        None
    })
}

/// Whether this person is a confirmed owner or admin of the organization.
async fn owner_or_admin(org: &OrganizationId, user: &UserId, conn: &DbConn) -> Option<Membership> {
    Membership::find_confirmed_by_user_and_org(user, org, conn)
        .await
        .filter(|m| m.atype == MembershipType::Owner as i32 || m.atype == MembershipType::Admin as i32)
}

/// The caller, if they may see and change this organization's link: one of
/// the owners or admins of a family. Everyone else, and every organization
/// that isn't a family, gets "not found", never 403.
async fn manager(org: &OrganizationId, user: &UserId, enforced: bool, conn: &DbConn) -> ApiResult<Membership> {
    let Some(member) = owner_or_admin(org, user, conn).await else {
        return Err(not_found());
    };
    if family_limit(enforced, org, conn).await?.is_none() {
        return Err(not_found());
    }
    Ok(member)
}

/// The family's live link that `token` is, made by someone who's still one of
/// its owners or admins, in an organization that's still a family; or the one
/// answer, the same for a wrong, replaced, ended, or turned-off link, one whose
/// maker left, and one that isn't a family's. The token is compared in
/// constant time (FamilyLink::live_for_token), and whether the organization is
/// a family is looked up whatever the token, so the work doesn't depend on
/// it either.
async fn usable_link(
    org: &OrganizationId,
    token: &str,
    enforced: bool,
    now: NaiveDateTime,
    conn: &DbConn,
) -> ApiResult<(FamilyLink, i64)> {
    let limit = family_limit(enforced, org, conn).await?;
    let link = FamilyLink::live_for_token(org, token, now, conn).await;
    let maker_manages = match link.as_ref().and_then(|l| l.made_by.as_ref()) {
        Some(maker) => owner_or_admin(org, maker, conn).await.is_some(),
        None => false,
    };
    match (link, limit) {
        (Some(link), Some(limit)) if maker_manages => Ok((link, limit)),
        _ => Err(doesnt_work()),
    }
}

/// The link's card on the family's Joining and security page: whether it's
/// on, its approval and end, its sealed settings (for the browser to show the
/// link again), and who joined with it.
async fn link_view(org: &OrganizationId, conn: &DbConn) -> Value {
    let now = Utc::now().naive_utc();
    let link = FamilyLink::find(org, conn).await;
    let made_by = match link.as_ref().and_then(|l| l.made_by.as_ref()) {
        Some(maker) => User::find_by_uuid(maker, conn).await.map(|u| u.email),
        None => None,
    };
    let mut joins = Vec::new();
    for join in FamilyLinkJoin::for_org(org, conn).await {
        let Some(member) = Membership::find_by_uuid_and_org(&join.membership_uuid, org, conn).await else {
            continue;
        };
        let Some(user) = User::find_by_uuid(&member.user_uuid, conn).await else {
            continue;
        };
        joins.push(json!({
            "memberId": member.uuid,
            "email": user.email,
            "name": user.name,
            "joinedAt": crate::util::format_date(&join.joined_at),
            "automatic": join.automatic,
            "status": member.status,
        }));
    }
    json!({
        "on": link.as_ref().is_some_and(|l| l.token_hash.is_some()),
        "live": link.as_ref().is_some_and(|l| l.is_live(now)),
        "automatic": link.as_ref().is_some_and(|l| l.automatic),
        "expiresAt": link.as_ref().and_then(|l| l.expires_at.as_ref()).map(crate::util::format_date),
        "madeAt": link.as_ref().map(|l| crate::util::format_date(&l.made_at)),
        "madeBy": made_by,
        "collectionId": link.as_ref().and_then(|l| l.collection_uuid.clone()),
        "sealed": link.as_ref().map(|l| l.sealed.clone()),
        "joins": joins,
    })
}

/// Settings sealed by the browser, checked to look encrypted.
fn checked_sealed(sealed: &str) -> EmptyResult {
    if !valid_sealed_settings(sealed) {
        err!("The link's settings must be encrypted with the family's key")
    }
    Ok(())
}

#[get("/keykeeper/organizations/<org_id>/family-link")]
async fn get_link(org_id: OrganizationId, headers: Headers, conn: DbConn) -> JsonResult {
    manager(&org_id, &headers.user.uuid, CONFIG.plans_enforced(), &conn).await?;
    Ok(Json(link_view(&org_id, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MakeData {
    /// The new link's token, made by the browser: 32 random bytes. Kept only
    /// as its hash.
    token: String,
    /// The link's settings, encrypted with the family's key.
    sealed: String,
    automatic: bool,
    /// How long it works: 1, 7, or 30 days.
    days: i64,
    /// The shared folder people who join get, Can edit.
    collection_id: Option<CollectionId>,
}

/// Makes the family's link, or replaces it: the old one stops working at once.
#[put("/keykeeper/organizations/<org_id>/family-link", data = "<data>")]
async fn make_link(org_id: OrganizationId, data: Json<MakeData>, headers: Headers, conn: DbConn) -> JsonResult {
    manager(&org_id, &headers.user.uuid, CONFIG.plans_enforced(), &conn).await?;
    let data = data.into_inner();
    if !valid_family_link_token(&data.token) {
        err!("That invite link's token isn't one")
    }
    checked_sealed(&data.sealed)?;
    if !FAMILY_LINK_DAYS.contains(&data.days) {
        err!("An invite link works for 1, 7, or 30 days")
    }
    if let Some(collection) = &data.collection_id
        && Collection::find_by_uuid_and_org(collection, &org_id, &conn).await.is_none()
    {
        err!("That shared folder isn't this family's")
    }
    FamilyLink::new(
        org_id.clone(),
        &data.token,
        data.sealed,
        data.automatic,
        data.days,
        headers.user.uuid.clone(),
        data.collection_id,
        Utc::now().naive_utc(),
    )
    .save(&conn)
    .await?;
    Ok(Json(link_view(&org_id, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalData {
    automatic: bool,
    /// The link's settings with the new approval, encrypted with the family's key.
    sealed: String,
}

/// One tap or automatic, for the link that's on. The link and when it ends
/// stay as they are.
#[put("/keykeeper/organizations/<org_id>/family-link/approval", data = "<data>")]
async fn set_approval(org_id: OrganizationId, data: Json<ApprovalData>, headers: Headers, conn: DbConn) -> JsonResult {
    manager(&org_id, &headers.user.uuid, CONFIG.plans_enforced(), &conn).await?;
    let data = data.into_inner();
    checked_sealed(&data.sealed)?;
    let Some(mut link) = FamilyLink::find(&org_id, &conn).await.filter(|l| l.token_hash.is_some()) else {
        err!("Make an invite link first")
    };
    link.automatic = data.automatic;
    link.sealed = data.sealed;
    link.save(&conn).await?;
    Ok(Json(link_view(&org_id, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OffData {
    /// Settings that say the link is off, encrypted with the family's key.
    sealed: String,
}

/// Turns the link off: no token works until someone makes a new link.
#[delete("/keykeeper/organizations/<org_id>/family-link", data = "<data>")]
async fn turn_off(org_id: OrganizationId, data: Json<OffData>, headers: Headers, conn: DbConn) -> JsonResult {
    let caller = manager(&org_id, &headers.user.uuid, CONFIG.plans_enforced(), &conn).await?;
    let data = data.into_inner();
    checked_sealed(&data.sealed)?;
    let mut link = match FamilyLink::find(&org_id, &conn).await {
        Some(link) => link,
        // Never made: kept off, so the apps learn the newest settings.
        None => FamilyLink {
            org_uuid: org_id.clone(),
            token_hash: None,
            sealed: String::new(),
            automatic: false,
            expires_at: None,
            made_by: Some(caller.user_uuid.clone()),
            made_at: Utc::now().naive_utc(),
            collection_uuid: None,
        },
    };
    link.turn_off(data.sealed);
    link.save(&conn).await?;
    Ok(Json(link_view(&org_id, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkData {
    organization_id: OrganizationId,
    /// The link's token. In the request's body, never its address, so it
    /// isn't in any log.
    token: String,
}

/// What the join page shows before anyone signs in: the family's name and who
/// made the link, and nothing else. Every link that doesn't work gets the
/// same answer.
#[post("/keykeeper/family-link/info", data = "<data>")]
async fn link_info(data: Json<LinkData>, conn: DbConn) -> JsonResult {
    let data = data.into_inner();
    let now = Utc::now().naive_utc();
    let (link, _) = usable_link(&data.organization_id, &data.token, CONFIG.plans_enforced(), now, &conn).await?;
    let Some(org) = Organization::find_by_uuid(&data.organization_id, &conn).await else {
        return Err(doesnt_work());
    };
    let invited_by = match &link.made_by {
        Some(maker) => User::find_by_uuid(maker, &conn).await.map(|u| {
            if u.name.trim().is_empty() {
                u.email
            } else {
                u.name
            }
        }),
        None => None,
    };
    Ok(Json(json!({ "organizationName": org.name, "invitedBy": invited_by })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinData {
    organization_id: OrganizationId,
    token: String,
    /// That the joining browser knew the link's join secret, bound to the
    /// person's public key (the install command's join proof).
    proof: Option<String>,
}

/// Joins the family a link is for, as a member waiting for its key.
#[post("/keykeeper/family-link/join", data = "<data>")]
async fn join(data: Json<JoinData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data = data.into_inner();
    let proof = super::keykeeper_enrollment::checked_seal(data.proof.as_ref())?.map(str::to_owned);
    let now = Utc::now().naive_utc();
    let (link, limit) = usable_link(&data.organization_id, &data.token, CONFIG.plans_enforced(), now, &conn).await?;
    let Some(org) = Organization::find_by_uuid(&data.organization_id, &conn).await else {
        return Err(doesnt_work());
    };
    let status = join_family(&headers.user, &org, &link, limit, proof, now, &conn).await?;
    if status == Joined::New {
        tell_owners(&headers.user, &org, link.automatic, &conn).await;
    }
    let member = Membership::find_by_user_and_org(&headers.user.uuid, &org.uuid, &conn).await;
    Ok(Json(json!({
        "organizationId": org.uuid,
        "organizationName": org.name,
        "status": member.map(|m| m.status),
        "automatic": link.automatic,
    })))
}

/// What a join did.
#[derive(Debug, PartialEq, Eq)]
enum Joined {
    /// A new member, waiting for the family's key.
    New,
    /// Already in, waiting or confirmed: nothing changed.
    Already,
}

/// Joins `user` to the family `link` is for: through upstream's invite
/// acceptance, as a regular member waiting for the family's key, counted
/// against its people limit (`limit`) in the same locked transaction as every
/// other way in. With Can edit in the link's shared folder, and the join
/// recorded with its proof and whether approval was automatic.
async fn join_family(
    user: &User,
    org: &Organization,
    link: &FamilyLink,
    limit: i64,
    proof: Option<String>,
    now: NaiveDateTime,
    conn: &DbConn,
) -> ApiResult<Joined> {
    match Membership::find_by_user_and_org(&user.uuid, &org.uuid, conn).await {
        Some(member) if member.status >= MembershipStatus::Accepted as i32 => return Ok(Joined::Already),
        Some(member) if member.status < MembershipStatus::Invited as i32 => {
            err!(format!("Your access to {} was turned off. Ask its owners.", org.name))
        }
        // An emailed invitation stays the inviter's: accepting it is how in.
        Some(_) => err!(format!("You have an emailed invitation to {}. Accept it from the email instead.", org.name)),
        None => {}
    }
    // Nobody joins an organization whose plan has ended.
    super::keykeeper_plan_limits::refuse_if_ended(&org.uuid, conn).await?;

    let mut member = Membership::new(user.uuid.clone(), org.uuid.clone(), None);
    member.atype = MembershipType::User as i32;
    member.access_all = false;
    member.status = MembershipStatus::Invited as i32;
    // The place is taken here, under the lock, or refused with the plan's
    // sentence; accepting it below adds nobody.
    if let FamilyWithin::Full {
        has,
    } = member.save_within(limit, conn).await?
    {
        err!(super::keykeeper_plan_limits::family_full(limit, has))
    }
    // Upstream's acceptance and its checks (single organization among them).
    // If it refuses, the place goes back.
    let member_id = member.uuid.clone();
    if let Err(e) = super::accept_org_invite(user, member, None, false, conn).await {
        if let Some(taken) = Membership::find_by_uuid(&member_id, conn).await {
            taken.delete(conn).await?;
        }
        return Err(e);
    }

    if let Some(collection) = &link.collection_uuid
        && Collection::find_by_uuid_and_org(collection, &org.uuid, conn).await.is_some()
        && CollectionUser::find_by_collection_and_user(collection, &user.uuid, conn).await.is_none()
    {
        // Can edit, as the install command gives Everyone (keykeeper_folder_permissions.rs).
        crate::db::models::keykeeper_folder_permissions::save_user(
            &user.uuid,
            collection,
            &crate::db::models::keykeeper_folder_permissions::Grid::preset(false, false, false),
            conn,
        )
        .await?;
    }
    FamilyLinkJoin {
        membership_uuid: member_id,
        org_uuid: org.uuid.clone(),
        proof,
        automatic: link.automatic,
        joined_at: now,
    }
    .insert(conn)
    .await?;
    Ok(Joined::New)
}

/// Emails the family's owners that someone joined with the link, or waits
/// for them to approve. Not the person who joined.
async fn tell_owners(user: &User, org: &Organization, automatic: bool, conn: &DbConn) {
    if !CONFIG.mail_enabled() {
        return;
    }
    for owner in Membership::find_by_org_and_type(&org.uuid, MembershipType::Owner, conn).await {
        if owner.status != MembershipStatus::Confirmed as i32 || owner.user_uuid == user.uuid {
            continue;
        }
        let Some(owner) = User::find_by_uuid(&owner.user_uuid, conn).await else {
            continue;
        };
        if let Err(e) = mail::send_member_joined(
            &owner.email,
            &user.email,
            &org.name,
            &org.uuid,
            mail::JoinedWith::InviteLink,
            !automatic,
        )
        .await
        {
            error!("Error sending the invite link's join email for {}: {e:#?}", org.name);
        }
    }
}

/// For the list of who's waiting (keykeeper_joining.rs): a member who joined
/// with the family's link, with what an app checks before letting them in on
/// its own (the link's sealed settings and the join's proof), and whether the
/// server lets them in automatically: the family's link is live with approval
/// automatic, and was when they joined. None for anyone who didn't join with
/// the link.
pub(super) async fn link_join_entry(member: &Membership, conn: &DbConn) -> Option<(Value, bool)> {
    link_join_entry_on(CONFIG.plans_enforced(), member, Utc::now().naive_utc(), conn).await
}

async fn link_join_entry_on(
    enforced: bool,
    member: &Membership,
    now: NaiveDateTime,
    conn: &DbConn,
) -> Option<(Value, bool)> {
    let join = FamilyLinkJoin::find(&member.uuid, conn).await?;
    let link = FamilyLink::find(&member.org_uuid, conn).await;
    let family = family_limit(enforced, &member.org_uuid, conn).await.ok().flatten().is_some();
    let automatic = family && join.automatic && link.as_ref().is_some_and(|l| l.automatic && l.is_live(now));
    Some((json!({ "sealed": link.map(|l| l.sealed), "joinProof": join.proof }), automatic))
}

/// The family's link's sealed settings, for an owner's or admin's apps to
/// remember the newest they've seen. None without one.
pub(super) async fn sealed_settings(org: &OrganizationId, conn: &DbConn) -> Option<String> {
    FamilyLink::find(org, conn).await.map(|l| l.sealed)
}

/// Whether to suggest a legacy contact: to an owner of a family who has named
/// none and hasn't said No thanks.
async fn suggest_legacy_contact(user: &UserId, enforced: bool, conn: &DbConn) -> ApiResult<bool> {
    if !enforced
        || LegacyContactSuggestion::dismissed(user, conn).await
        || !EmergencyAccess::find_all_by_grantor_uuid(user, conn).await.is_empty()
    {
        return Ok(false);
    }
    for member in Membership::find_confirmed_by_user(user, conn).await {
        if member.atype == MembershipType::Owner as i32
            && family_limit(enforced, &member.org_uuid, conn).await?.is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[get("/keykeeper/legacy-contact-suggestion")]
async fn legacy_contact_suggestion(headers: Headers, conn: DbConn) -> JsonResult {
    let show = suggest_legacy_contact(&headers.user.uuid, CONFIG.plans_enforced(), &conn).await?;
    Ok(Json(json!({ "show": show })))
}

/// "No thanks": it doesn't come back, on any device.
#[post("/keykeeper/legacy-contact-suggestion/dismiss")]
async fn dismiss_legacy_contact_suggestion(headers: Headers, conn: DbConn) -> JsonResult {
    LegacyContactSuggestion::dismiss(&headers.user.uuid, Utc::now().naive_utc(), &conn).await?;
    Ok(Json(json!({ "show": false })))
}

#[cfg(all(test, sqlite))]
mod tests {
    use chrono::TimeDelta;

    use super::*;
    use crate::db::{
        DbPool,
        models::{Billed, Msp, MspId, Plan, PlanName, PlanWrite, SetBy, Standing},
    };

    const TOKEN: &str = "dGhpcnR5LXR3byBieXRlcyBvZiBhIHRlc3QgdG9rZW4";
    const OTHER: &str = "YW5vdGhlciB0aGlydHktdHdvLWJ5dGUgdG9rZW4uLi4";
    const SEALED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|c2VhbGVk|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const PROOF: &str = "cHJvb2YtcHJvb2YtcHJvb2YtcHJvb2YtcHJvb2YtcHI=";

    fn now() -> NaiveDateTime {
        Utc::now().naive_utc()
    }

    async fn person(name: &str, conn: &DbConn) -> User {
        let local = name.to_lowercase().replace(|c: char| !c.is_ascii_alphanumeric(), "-");
        let mut user = User::new(&format!("{local}-{}@example.test", crate::util::get_uuid()), None);
        user.name = name.to_owned();
        user.save(conn).await.unwrap();
        user
    }

    async fn organization(name: &str, conn: &DbConn) -> Organization {
        let org = Organization::new(name.to_owned(), "billing@example.test", None, None);
        org.save(conn).await.unwrap();
        org
    }

    async fn set_plan(org: &Organization, plan: PlanName, conn: &DbConn) {
        let write = PlanWrite {
            plan,
            free_until: None,
            free_why: None,
            standing: Standing::Until,
            until: Some(now() + TimeDelta::days(30)),
            renews: false,
            billed: Billed::ByHand,
        };
        Plan::set(&PlanOwner::Organization(org.uuid.clone()), write, SetBy::Operator, conn).await.unwrap().unwrap();
    }

    async fn member(user: &User, org: &Organization, atype: MembershipType, status: MembershipStatus, conn: &DbConn) {
        let mut member = Membership::new(user.uuid.clone(), org.uuid.clone(), None);
        member.atype = atype as i32;
        member.status = status as i32;
        member.save(conn).await.unwrap();
    }

    /// A family on Families with its owner, and a live link the owner made.
    async fn family(automatic: bool, conn: &DbConn) -> (Organization, User) {
        let org = organization("Rivera family", conn).await;
        set_plan(&org, PlanName::Families, conn).await;
        let owner = person("Ana Rivera", conn).await;
        member(&owner, &org, MembershipType::Owner, MembershipStatus::Confirmed, conn).await;
        FamilyLink::new(org.uuid.clone(), TOKEN, SEALED.to_owned(), automatic, 7, owner.uuid.clone(), None, now())
            .save(conn)
            .await
            .unwrap();
        (org, owner)
    }

    /// Makes `org` an MSP's client, as the plans' tests do: MspClient::new
    /// seals an install token with the server's keys, which tests don't load.
    async fn take_on(org: &Organization, conn: &DbConn) -> MspId {
        let msp = Msp::new("Northwind IT".to_owned());
        msp.insert(conn).await.unwrap();
        MspClient {
            org_uuid: org.uuid.clone(),
            msp_uuid: msp.uuid.clone(),
            created_at: now(),
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
        msp.uuid
    }

    #[rocket::async_test]
    async fn only_a_family_has_a_link() {
        let conn = DbPool::for_test().await;
        let no_plan = organization("No plan", &conn).await;
        let business = organization("Acme", &conn).await;
        set_plan(&business, PlanName::Business, &conn).await;
        let family = organization("Rivera family", &conn).await;
        set_plan(&family, PlanName::Families, &conn).await;
        let client = organization("A client", &conn).await;
        set_plan(&client, PlanName::Families, &conn).await;
        take_on(&client, &conn).await;

        assert_eq!(family_limit(true, &family.uuid, &conn).await.unwrap(), Some(6));
        for org in [&no_plan, &business, &client] {
            assert_eq!(family_limit(true, &org.uuid, &conn).await.unwrap(), None, "{}", org.name);
        }
        // A server that doesn't enforce plans has no families.
        assert_eq!(family_limit(false, &family.uuid, &conn).await.unwrap(), None);
    }

    #[rocket::async_test]
    async fn only_a_familys_owners_and_admins_manage_it_and_everyone_else_gets_not_found() {
        let conn = DbPool::for_test().await;
        let (org, owner) = family(false, &conn).await;
        let admin = person("admin", &conn).await;
        member(&admin, &org, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        assert!(manager(&org.uuid, &owner.uuid, true, &conn).await.is_ok());
        assert!(manager(&org.uuid, &admin.uuid, true, &conn).await.is_ok());

        let mut refused = Vec::new();
        for (name, atype, status) in [
            ("member", MembershipType::User, MembershipStatus::Confirmed),
            ("manager", MembershipType::Manager, MembershipStatus::Confirmed),
            ("invited-owner", MembershipType::Owner, MembershipStatus::Invited),
            ("accepted-admin", MembershipType::Admin, MembershipStatus::Accepted),
            ("revoked-owner", MembershipType::Owner, MembershipStatus::Revoked),
        ] {
            let user = person(name, &conn).await;
            member(&user, &org, atype, status, &conn).await;
            refused.push((name, user));
        }
        refused.push(("outsider", person("outsider", &conn).await));
        // Not a family: the owner of a Business organization, and an MSP's
        // admin who is an owner in a client on Families.
        let business = organization("Acme", &conn).await;
        set_plan(&business, PlanName::Business, &conn).await;
        let business_owner = person("business-owner", &conn).await;
        member(&business_owner, &business, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        let client = organization("A client", &conn).await;
        set_plan(&client, PlanName::Families, &conn).await;
        take_on(&client, &conn).await;
        let msp_admin = person("msp-admin", &conn).await;
        member(&msp_admin, &client, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;

        for (name, user) in &refused {
            let e = manager(&org.uuid, &user.uuid, true, &conn).await.err().unwrap();
            assert_eq!((e.status_code(), e.message()), (404, "Organization not found"), "{name}");
        }
        for (org_id, user) in [(&business.uuid, &business_owner), (&client.uuid, &msp_admin)] {
            let e = manager(org_id, &user.uuid, true, &conn).await.err().unwrap();
            assert_eq!((e.status_code(), e.message()), (404, "Organization not found"));
        }
        // And nobody on a server that doesn't enforce plans.
        let e = manager(&org.uuid, &owner.uuid, false, &conn).await.err().unwrap();
        assert_eq!(e.status_code(), 404);
    }

    /// What the join page is told about a link that doesn't work.
    async fn answer(
        org: &OrganizationId,
        token: &str,
        enforced: bool,
        at: NaiveDateTime,
        conn: &DbConn,
    ) -> (u16, String) {
        let e = usable_link(org, token, enforced, at, conn).await.unwrap_err();
        (e.status_code(), e.message().to_owned())
    }

    /// A wrong, replaced, ended, or turned-off link, one whose maker left,
    /// one for an organization that's no longer a family or on a server that
    /// doesn't enforce plans, and one for an organization with no link: the
    /// same answer, every time.
    #[rocket::async_test]
    async fn the_join_page_has_one_answer_for_every_link_that_doesnt_work() {
        let conn = DbPool::for_test().await;
        let (org, owner) = family(false, &conn).await;
        let (_, other_owner) = family(false, &conn).await;
        let no_link = organization("No link", &conn).await;
        set_plan(&no_link, PlanName::Families, &conn).await;
        let remake = async |maker: &User| {
            FamilyLink::new(org.uuid.clone(), TOKEN, SEALED.to_owned(), false, 7, maker.uuid.clone(), None, now())
                .save(&conn)
                .await
                .unwrap();
        };
        let mut answers = Vec::new();

        assert!(usable_link(&org.uuid, TOKEN, true, now(), &conn).await.is_ok());
        answers.push(answer(&org.uuid, OTHER, true, now(), &conn).await);
        answers.push(answer(&org.uuid, "", true, now(), &conn).await);
        answers.push(answer(&no_link.uuid, TOKEN, true, now(), &conn).await);
        answers.push(answer(&org.uuid, TOKEN, true, now() + TimeDelta::days(8), &conn).await);
        // Replaced.
        FamilyLink::new(org.uuid.clone(), OTHER, SEALED.to_owned(), false, 7, owner.uuid.clone(), None, now())
            .save(&conn)
            .await
            .unwrap();
        answers.push(answer(&org.uuid, TOKEN, true, now(), &conn).await);
        // Made by someone who's no longer an owner or admin here.
        remake(&other_owner).await;
        answers.push(answer(&org.uuid, TOKEN, true, now(), &conn).await);
        // Off.
        let mut link = FamilyLink::find(&org.uuid, &conn).await.unwrap();
        link.turn_off(SEALED.to_owned());
        link.save(&conn).await.unwrap();
        answers.push(answer(&org.uuid, TOKEN, true, now(), &conn).await);
        // On a server that doesn't enforce plans, and no longer a family.
        remake(&owner).await;
        assert!(usable_link(&org.uuid, TOKEN, true, now(), &conn).await.is_ok());
        answers.push(answer(&org.uuid, TOKEN, false, now(), &conn).await);
        set_plan(&org, PlanName::Business, &conn).await;
        answers.push(answer(&org.uuid, TOKEN, true, now(), &conn).await);

        assert_eq!(answers.len(), 9);
        assert!(answers.iter().all(|a| a == &(404, LINK_DOESNT_WORK.to_owned())), "{answers:?}");
    }

    #[rocket::async_test]
    async fn joining_waits_for_the_familys_key_and_is_recorded() {
        let conn = DbPool::for_test().await;
        let (org, _) = family(true, &conn).await;
        let collection = Collection::new(org.uuid.clone(), "2.family".to_owned(), None);
        collection.save(&conn).await.unwrap();
        let mut link = FamilyLink::find(&org.uuid, &conn).await.unwrap();
        link.collection_uuid = Some(collection.uuid.clone());
        link.save(&conn).await.unwrap();

        let ben = person("Ben", &conn).await;
        let joined = join_family(&ben, &org, &link, 6, Some(PROOF.to_owned()), now(), &conn).await.unwrap();
        assert_eq!(joined, Joined::New);
        let in_family = Membership::find_by_user_and_org(&ben.uuid, &org.uuid, &conn).await.unwrap();
        assert_eq!(in_family.status, MembershipStatus::Accepted as i32, "waiting for the family's key");
        assert_eq!(in_family.atype, MembershipType::User as i32);
        assert!(!in_family.access_all);
        assert!(in_family.akey.is_empty(), "no key from the server");
        let recorded = FamilyLinkJoin::find(&in_family.uuid, &conn).await.unwrap();
        assert_eq!((recorded.proof.as_deref(), recorded.automatic), (Some(PROOF), true));
        assert!(CollectionUser::find_by_collection_and_user(&collection.uuid, &ben.uuid, &conn).await.is_some());

        // The list of who's waiting lets them in only while the link is live
        // and automatic, on a server that enforces plans.
        let (entry, automatic) = link_join_entry_on(true, &in_family, now(), &conn).await.unwrap();
        assert!(automatic);
        assert_eq!(entry["joinProof"], PROOF);
        assert_eq!(entry["sealed"], SEALED);
        assert!(!link_join_entry_on(true, &in_family, now() + TimeDelta::days(8), &conn).await.unwrap().1);
        assert!(!link_join_entry_on(false, &in_family, now(), &conn).await.unwrap().1);
        link.automatic = false;
        link.save(&conn).await.unwrap();
        assert!(!link_join_entry_on(true, &in_family, now(), &conn).await.unwrap().1);

        // Someone who joined while approval was one tap waits, even once it's automatic.
        let cleo = person("Cleo", &conn).await;
        join_family(&cleo, &org, &link, 6, Some(PROOF.to_owned()), now(), &conn).await.unwrap();
        link.automatic = true;
        link.save(&conn).await.unwrap();
        let cleo_member = Membership::find_by_user_and_org(&cleo.uuid, &org.uuid, &conn).await.unwrap();
        assert!(!link_join_entry_on(true, &cleo_member, now(), &conn).await.unwrap().1);
        // Nobody who didn't join with the link has an entry.
        let invited = person("Dee", &conn).await;
        member(&invited, &org, MembershipType::User, MembershipStatus::Accepted, &conn).await;
        let invited_member = Membership::find_by_user_and_org(&invited.uuid, &org.uuid, &conn).await.unwrap();
        assert!(link_join_entry_on(true, &invited_member, now(), &conn).await.is_none());

        // Joining again changes nothing.
        assert_eq!(join_family(&ben, &org, &link, 6, None, now(), &conn).await.unwrap(), Joined::Already);
    }

    #[rocket::async_test]
    async fn an_invitation_a_revoked_member_and_a_full_family_are_refused() {
        let conn = DbPool::for_test().await;
        let (org, _) = family(false, &conn).await;
        let link = FamilyLink::find(&org.uuid, &conn).await.unwrap();

        let invited = person("invited", &conn).await;
        member(&invited, &org, MembershipType::User, MembershipStatus::Invited, &conn).await;
        let e = join_family(&invited, &org, &link, 6, None, now(), &conn).await.unwrap_err();
        assert_eq!(e.message(), "You have an emailed invitation to Rivera family. Accept it from the email instead.");

        let revoked = person("revoked", &conn).await;
        member(&revoked, &org, MembershipType::User, MembershipStatus::Revoked, &conn).await;
        let e = join_family(&revoked, &org, &link, 6, None, now(), &conn).await.unwrap_err();
        assert_eq!(e.message(), "Your access to Rivera family was turned off. Ask its owners.");

        // The owner and the invitation count: four more fit in six.
        for n in 0..4 {
            let joiner = person(&format!("joiner{n}"), &conn).await;
            join_family(&joiner, &org, &link, 6, None, now(), &conn).await.unwrap();
        }
        let seventh = person("seventh", &conn).await;
        let e = join_family(&seventh, &org, &link, 6, None, now(), &conn).await.unwrap_err();
        assert_eq!(e.message(), "A Families plan covers 6 people, and this one has 6. Remove someone first.");
        assert!(Membership::find_by_user_and_org(&seventh.uuid, &org.uuid, &conn).await.is_none());
    }

    /// Eight people join at once for the one place left, each on its own
    /// connection to the same database: exactly one gets in, the rest get
    /// the plan's sentence, and the family ends with six.
    #[rocket::async_test]
    async fn joins_at_once_for_the_last_place_let_one_in() {
        const AT_ONCE: u32 = 8;
        let pool = std::sync::Arc::new(DbPool::for_test_pool_of(AT_ONCE));
        let conn = pool.get().await.unwrap();
        let (org, _) = family(false, &conn).await;
        for n in 1..=4 {
            let user = person(&format!("member{n}"), &conn).await;
            member(&user, &org, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        }
        let link = FamilyLink::find(&org.uuid, &conn).await.unwrap();
        let mut joiners = Vec::new();
        for n in 0..AT_ONCE {
            joiners.push(person(&format!("joiner{n}"), &conn).await);
        }
        drop(conn);

        let start = std::sync::Arc::new(tokio::sync::Barrier::new(joiners.len()));
        let mut tasks = Vec::new();
        for joiner in joiners {
            let (pool, start, org, link) =
                (std::sync::Arc::clone(&pool), std::sync::Arc::clone(&start), org.uuid.clone(), link.clone());
            tasks.push(tokio::spawn(async move {
                let conn = pool.get().await.unwrap();
                let org = Organization::find_by_uuid(&org, &conn).await.unwrap();
                start.wait().await;
                join_family(&joiner, &org, &link, 6, None, now(), &conn).await.map_err(|e| e.message().to_owned())
            }));
        }
        let mut joined = 0;
        for task in tasks {
            match task.await.unwrap() {
                Ok(Joined::New) => joined += 1,
                Ok(other) => panic!("{other:?}"),
                Err(e) => {
                    assert_eq!(e, "A Families plan covers 6 people, and this one has 6. Remove someone first.");
                }
            }
        }
        assert_eq!(joined, 1);
        let conn = pool.get().await.unwrap();
        assert_eq!(Membership::people_counted(&org.uuid, &conn).await.unwrap(), 6);
        assert_eq!(FamilyLinkJoin::for_org(&org.uuid, &conn).await.len(), 1);
    }

    #[rocket::async_test]
    async fn a_familys_owners_are_offered_a_legacy_contact_until_they_name_one_or_say_no_thanks() {
        let conn = DbPool::for_test().await;
        let (org, owner) = family(false, &conn).await;
        assert!(suggest_legacy_contact(&owner.uuid, true, &conn).await.unwrap());
        assert!(!suggest_legacy_contact(&owner.uuid, false, &conn).await.unwrap(), "no families without plans");

        // Not an admin, a member, or the owner of a Business organization.
        let admin = person("admin", &conn).await;
        member(&admin, &org, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        let business = organization("Acme", &conn).await;
        set_plan(&business, PlanName::Business, &conn).await;
        let business_owner = person("business-owner", &conn).await;
        member(&business_owner, &business, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        for user in [&admin, &business_owner] {
            assert!(!suggest_legacy_contact(&user.uuid, true, &conn).await.unwrap());
        }

        // No thanks keeps it away.
        LegacyContactSuggestion::dismiss(&owner.uuid, now(), &conn).await.unwrap();
        assert!(!suggest_legacy_contact(&owner.uuid, true, &conn).await.unwrap());

        // Naming a legacy contact ends it too.
        let other = person("Ana's sister", &conn).await;
        let (other_family, _) = family(false, &conn).await;
        member(&other, &other_family, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        assert!(suggest_legacy_contact(&other.uuid, true, &conn).await.unwrap());
        let mut contact = EmergencyAccess::new(other.uuid.clone(), "friend@example.test".to_owned(), 0, 0, 7);
        contact.save(&conn).await.unwrap();
        assert!(!suggest_legacy_contact(&other.uuid, true, &conn).await.unwrap());
    }
}

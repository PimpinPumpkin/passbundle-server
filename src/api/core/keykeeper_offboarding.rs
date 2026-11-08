// Keykeeper: offboarding that holds. Removing someone, or a client removing
// its MSP, cuts what they could still use and stays done:
//
// - Someone an organization removed can ask to join again with an install
//   command they kept, but an admin approves them; nothing confirms them on
//   its own. A new invitation from the organization's own people clears it.
// - An MSP's person the client itself removed or revoked stays out: the
//   MSP's staff changes never add, re-role, or confirm them there again, and
//   their staff seal goes, so no app vouches for them. The MSP's console
//   shows them as removed by the client.
// - The client's own people decide its MSP's people's roles by removing or
//   revoking them, never by changing their role, which the MSP's console
//   would set back; and an MSP's people never remove, revoke, demote, or
//   recover the client's own owners, or delete the client while it has any.
// - MSP-console actions on a client need the caller's own confirmed place
//   there, so a client that revoked an MSP admin is out of their reach.
// - Removing an MSP revokes the script and provisioning tokens its people
//   made, deletes the event destinations they set up and their staff seals,
//   and tells the client's owner what went, and what to review.
// - Leaving on one's own is remembered as a removal is, so rejoining with a
//   kept install command waits for an admin.
// - Once a client has an owner of its own, only its own owners invite or make
//   owners, so an MSP's people can't add a second account of their own as one.
// - An event destination sends only while whoever set it up still has access
//   to the organization the event came from, checked on every delivery, as
//   tokens are.
// - A client's removal or revocation of an MSP admin holds against the MSP's
//   staff changes: the staff that admin brings in afterward stay out of that
//   client too, and the admin no longer sees that client's activity.
//
// See DESIGN.md, "Offboarding", in the meta repo.

use std::collections::HashSet;

use serde_json::{Value, json};

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        models::{
            EventDestination, JoinSeal, Membership, MembershipStatus, MembershipType, MspClient, MspId, MspMembership,
            MspRole, Organization, OrganizationId, RemovedMember, ScimToken, ScriptToken, SealKind, SsoConfig, User,
            UserId,
        },
    },
    util::format_date,
};

use super::keykeeper_msp::Audit;

/// Who changed someone's place in an organization.
#[derive(Clone, Copy)]
pub(super) enum By<'a> {
    /// A member, through the organization's own routes.
    Member(&'a User),
    /// The organization's directory (provisioning) or its API key's import.
    Directory,
}

/// Whether someone's membership in an organization is one its MSP made: then
/// what they do there is the MSP's doing, not the client's own.
pub(super) async fn is_msp_caller(org_id: &OrganizationId, user_id: &UserId, conn: &DbConn) -> bool {
    match Membership::find_by_user_and_org(user_id, org_id, conn).await {
        Some(member) => MspMembership::find_by_membership(&member.uuid, conn).await.is_some(),
        None => false,
    }
}

async fn msp_side(org_id: &OrganizationId, by: By<'_>, conn: &DbConn) -> bool {
    match by {
        By::Member(user) => is_msp_caller(org_id, &user.uuid, conn).await,
        By::Directory => false,
    }
}

/// One of the organization's own owners: a confirmed owner its MSP didn't add.
pub(super) async fn is_own_owner(member: &Membership, conn: &DbConn) -> bool {
    member.atype == MembershipType::Owner as i32
        && member.status == MembershipStatus::Confirmed as i32
        && MspMembership::find_by_membership(&member.uuid, conn).await.is_none()
}

/// An MSP's people may not remove, revoke, demote, or recover the client's own
/// owners: the client stays in control, and can always remove its MSP. A
/// client with no owners of its own is the MSP's to run.
pub(super) async fn protect_own_owner(target: &Membership, caller: &User, what: &str, conn: &DbConn) -> EmptyResult {
    if is_own_owner(target, conn).await && is_msp_caller(&target.org_uuid, &caller.uuid, conn).await {
        err!(format!("Only the organization's own owners can {what} one of its owners, not its IT provider's staff."))
    }
    Ok(())
}

/// Whether the organization has an owner of its own (`is_own_owner`).
async fn has_own_owner(org_id: &OrganizationId, conn: &DbConn) -> bool {
    for owner in Membership::find_by_org_and_type(org_id, MembershipType::Owner, conn).await {
        if is_own_owner(&owner, conn).await {
            return true;
        }
    }
    false
}

/// Once an organization has an owner of its own, only its own owners invite
/// owners or make someone one. Otherwise an MSP's person could add a second
/// account of their own as an owner the MSP didn't add, which the client's
/// protections would then cover, and remove or demote the client's real
/// owners with it. A client with no owners of its own is the MSP's to run.
pub(super) async fn check_owner_grant(org_id: &OrganizationId, caller: &User, conn: &DbConn) -> EmptyResult {
    if is_msp_caller(org_id, &caller.uuid, conn).await && has_own_owner(org_id, conn).await {
        err!("Only the organization's own owners can make someone an owner here, not its IT provider's staff.")
    }
    Ok(())
}

/// Deleting an organization needs one of its own owners while it has any.
pub(super) async fn ensure_may_delete_org(org_id: &OrganizationId, caller: &User, conn: &DbConn) -> EmptyResult {
    if !is_msp_caller(org_id, &caller.uuid, conn).await {
        return Ok(());
    }
    for owner in Membership::find_by_org_and_type(org_id, MembershipType::Owner, conn).await {
        if is_own_owner(&owner, conn).await {
            err!("Only the organization's own owners can delete it. Ask one of them.")
        }
    }
    Ok(())
}

/// A change to the role of someone the MSP added, from the client's side, is
/// refused: the MSP's console would set it back. The client removes or
/// revokes them instead, which holds, or removes its MSP. An MSP's people
/// may not demote the client's own owners.
pub(super) async fn check_role_change(
    target: &Membership,
    new_type: MembershipType,
    access_all: bool,
    custom: Option<&crate::db::models::keykeeper_roles::CustomPermissions>,
    caller: &User,
    conn: &DbConn,
) -> EmptyResult {
    if new_type != MembershipType::Owner {
        protect_own_owner(target, caller, "change the role of", conn).await?;
    } else if target.atype != MembershipType::Owner as i32 {
        check_owner_grant(&target.org_uuid, caller, conn).await?;
    }
    // Keykeeper: and a role two-step login for admins covers waits for its
    // person to accept their place, where the server accepted it for them.
    let elevated = super::keykeeper_two_step::elevated_role(new_type, custom);
    super::keykeeper_two_step::require_accepted_to_promote(target, elevated, conn).await?;
    if MspMembership::find_by_membership(&target.uuid, conn).await.is_none()
        || is_msp_caller(&target.org_uuid, &caller.uuid, conn).await
    {
        return Ok(());
    }
    let current = crate::db::models::keykeeper_roles::find(&target.uuid, conn).await;
    if target.atype != new_type as i32 || target.access_all != access_all || current.as_ref() != custom {
        err!(
            "Your IT provider sets the roles of its own people here. Remove or revoke them instead, which holds, or remove your IT provider (Remove MSP, on the Members page)."
        )
    }
    Ok(())
}

async fn email_of(user_id: &UserId, conn: &DbConn) -> Option<String> {
    User::find_by_uuid(user_id, conn).await.map(|u| u.email)
}

/// Tells the MSP's activity log that a client took one of its people out.
async fn tell_msp(
    msp: &MspId,
    event: &'static str,
    org_id: &OrganizationId,
    target: Option<&str>,
    by: By<'_>,
    conn: &DbConn,
) -> EmptyResult {
    let name = Organization::find_by_uuid(org_id, conn).await.map(|o| o.name).unwrap_or_default();
    Audit {
        event,
        actor: match by {
            By::Member(user) => Some(user),
            By::Directory => None,
        },
        ip: None,
        org: Some((org_id, &name)),
        target_email: target,
        detail: None,
    }
    .record(msp, conn)
    .await
}

/// Before the organization's own people (or its directory) remove someone:
/// their invitation and staff seals go, so no app vouches for them again,
/// and the organization remembers it. For one of its MSP's people, the event
/// destinations they set up for it go too, and the MSP hears of it. When the
/// MSP's own people remove one of theirs, nothing is remembered: its console
/// manages its people.
pub(super) async fn before_removal(member: &Membership, by: By<'_>, conn: &DbConn) -> EmptyResult {
    let org = &member.org_uuid;
    let email = email_of(&member.user_uuid, conn).await;
    if let Some(email) = &email {
        JoinSeal::set(org, email, SealKind::Invite, None, conn).await?;
        JoinSeal::set(org, email, SealKind::Staff, None, conn).await?;
    }
    match MspMembership::find_by_membership(&member.uuid, conn).await {
        Some(_) if msp_side(org, by, conn).await => Ok(()),
        Some(ours) => {
            RemovedMember::record(org, &member.user_uuid, Some(&ours.msp_uuid), false, conn).await?;
            delete_destinations(org, &HashSet::from([member.user_uuid.clone()]), conn).await?;
            tell_msp(&ours.msp_uuid, "client_removed_staff", org, email.as_deref(), by, conn).await
        }
        None => RemovedMember::record(org, &member.user_uuid, None, false, conn).await,
    }
}

/// Before someone leaves an organization on their own: it remembers them as
/// it remembers someone it removed, so an install command they kept only
/// lets them ask to join again, and an admin approves them; and their
/// invitation and staff seals go. One of its MSP's people who leaves stays out
/// until someone there invites them again: the MSP's staff changes don't add
/// them back.
pub(super) async fn before_leaving(member: &Membership, conn: &DbConn) -> EmptyResult {
    let org = &member.org_uuid;
    if let Some(email) = email_of(&member.user_uuid, conn).await {
        JoinSeal::set(org, &email, SealKind::Invite, None, conn).await?;
        JoinSeal::set(org, &email, SealKind::Staff, None, conn).await?;
    }
    RemovedMember::record(org, &member.user_uuid, None, false, conn).await
}

/// Before the organization's own people revoke one of its MSP's people: the
/// staff seal goes, and the organization remembers it, so the MSP's console
/// never brings them back. Revoking anyone else needs nothing more: a revoked
/// member can't join again until restored.
pub(super) async fn before_revoke(member: &Membership, by: By<'_>, conn: &DbConn) -> EmptyResult {
    let Some(ours) = MspMembership::find_by_membership(&member.uuid, conn).await else {
        return Ok(());
    };
    let org = &member.org_uuid;
    let email = email_of(&member.user_uuid, conn).await;
    if let Some(email) = &email {
        JoinSeal::set(org, email, SealKind::Staff, None, conn).await?;
    }
    if msp_side(org, by, conn).await {
        return Ok(());
    }
    RemovedMember::record(org, &member.user_uuid, Some(&ours.msp_uuid), true, conn).await?;
    tell_msp(&ours.msp_uuid, "client_revoked_staff", org, email.as_deref(), by, conn).await
}

/// Only the organization's own people restore one of its MSP's people they
/// revoked.
pub(super) async fn check_restore(member: &Membership, by: By<'_>, conn: &DbConn) -> EmptyResult {
    let record = RemovedMember::try_find(&member.org_uuid, &member.user_uuid, conn).await?;
    if record.is_some_and(|r| r.msp_uuid.is_some()) && msp_side(&member.org_uuid, by, conn).await {
        err!("The organization's own people revoked them, so only they can restore them.")
    }
    Ok(())
}

/// After the organization's own people restored someone: the record goes.
pub(super) async fn after_restore(member: &Membership, by: By<'_>, conn: &DbConn) -> EmptyResult {
    if msp_side(&member.org_uuid, by, conn).await {
        return Ok(());
    }
    RemovedMember::clear(&member.org_uuid, &member.user_uuid, conn).await
}

/// A new invitation clears a removal. Someone the client itself took off its
/// MSP's staff there can be invited again only by the client's own people.
pub(super) async fn on_invite(org_id: &OrganizationId, user: &User, inviter: &User, conn: &DbConn) -> EmptyResult {
    let Some(record) = RemovedMember::try_find(org_id, &user.uuid, conn).await? else {
        return Ok(());
    };
    if record.msp_uuid.is_some() && is_msp_caller(org_id, &inviter.uuid, conn).await {
        err!(format!(
            "The organization's own people removed {}, so only they can invite them again.",
            user.email.escape_debug()
        ))
    }
    RemovedMember::clear(org_id, &user.uuid, conn).await
}

/// After someone is confirmed: an admin approved them, so an earlier removal
/// is settled, and the invitation's seal has done its work.
pub(super) async fn after_confirm(member: &Membership, conn: &DbConn) -> EmptyResult {
    if let Some(email) = email_of(&member.user_uuid, conn).await {
        JoinSeal::set(&member.org_uuid, &email, SealKind::Invite, None, conn).await?;
    }
    match RemovedMember::try_find(&member.org_uuid, &member.user_uuid, conn).await? {
        Some(record) if record.msp_uuid.is_none() => {
            RemovedMember::clear(&member.org_uuid, &member.user_uuid, conn).await
        }
        _ => Ok(()),
    }
}

/// The caller's own place in a client: a confirmed membership (so never
/// revoked), as an owner or admin when `manages`.
pub(super) async fn has_client_place(org_id: &OrganizationId, user_id: &UserId, manages: bool, conn: &DbConn) -> bool {
    Membership::find_by_user_and_org(user_id, org_id, conn).await.is_some_and(|m| {
        m.status == MembershipStatus::Confirmed as i32
            && (!manages || m.atype == MembershipType::Owner as i32 || m.atype == MembershipType::Admin as i32)
    })
}

/// Refuses an MSP-console action on a client where the caller has no place
/// of their own (see `has_client_place`), such as one that revoked them.
pub(super) async fn require_client_place(
    org_id: &OrganizationId,
    user_id: &UserId,
    manages: bool,
    conn: &DbConn,
) -> EmptyResult {
    if !has_client_place(org_id, user_id, manages, conn).await {
        err!(client_place_refusal(org_id, conn).await)
    }
    Ok(())
}

/// Why the caller can't act in a client from the MSP console.
pub(super) async fn client_place_refusal(org_id: &OrganizationId, conn: &DbConn) -> String {
    let name = Organization::find_by_uuid(org_id, conn).await.map(|o| o.name).unwrap_or_default();
    format!(
        "You don't have access to {name} yourself (it may have removed or revoked you, or not confirmed you yet), so you can't do this for it."
    )
}

/// Whether an event destination may send an event that came from this
/// organization (`source`; none for an MSP's own activity): only while
/// whoever set it up still has access to it, checked on every delivery, as
/// tokens are. An organization's destination needs its maker still a
/// confirmed owner or admin there (for an MSP's person, still an admin of the
/// MSP), as only they set one up; an MSP's needs its maker still one of the
/// MSP's admins, and sends a client's events only while that client hasn't
/// removed or revoked them. Their account must be on; once it's deleted, the
/// destination sends nothing. A database error counts as no.
pub async fn destination_may_send(destination: &EventDestination, source: Option<&str>, conn: &DbConn) -> bool {
    let Some(maker) = &destination.created_by else {
        return false;
    };
    if let Some(org) = &destination.org_uuid {
        return source.is_none_or(|s| s == org.as_ref())
            && super::keykeeper_script_access::creator_has_access(org, maker, conn).await;
    }
    let Some(msp) = &destination.msp_uuid else {
        return false;
    };
    if !User::find_by_uuid(maker, conn).await.is_some_and(|u| u.enabled)
        || !matches!(super::keykeeper_msp::staff_role(msp, maker, conn).await, Ok(MspRole::Admin))
    {
        return false;
    }
    match source {
        None => true,
        Some(org) => !closed_to(&OrganizationId::from(org.to_owned()), msp, maker, conn).await,
    }
}

/// Whether a client removed or revoked one of its MSP's people itself. A
/// database error counts as yes.
async fn closed_to(org_id: &OrganizationId, msp: &MspId, user_id: &UserId, conn: &DbConn) -> bool {
    match RemovedMember::try_find(org_id, user_id, conn).await {
        Ok(record) => record.is_some_and(|r| r.msp_uuid.as_ref() == Some(msp)),
        Err(_) => true,
    }
}

/// The MSP's clients that removed or revoked this person themselves: their
/// activity is no longer theirs to read in the MSP's log. A client that
/// removed its MSP isn't one of its clients any more, and the MSP keeps its
/// history of it.
pub(super) async fn clients_closed_to(msp: &MspId, user_id: &UserId, conn: &DbConn) -> HashSet<OrganizationId> {
    let clients: HashSet<OrganizationId> =
        MspClient::find_by_msp(msp, conn).await.into_iter().map(|c| c.org_uuid).collect();
    RemovedMember::find_by_msp(msp, conn)
        .await
        .into_iter()
        .filter(|r| &r.user_uuid == user_id && clients.contains(&r.org_uuid))
        .map(|r| r.org_uuid)
        .collect()
}

/// When someone joins an MSP's staff: each client that removed or revoked
/// whoever invited them keeps them out too, as removed by the client. A
/// client's revocation of an MSP admin would otherwise give way: the admin
/// invites a second account of their own, which joins only the clients where
/// the admin has a place, but the next staff change another admin makes for
/// it would add it everywhere. Only the client's own people can invite them
/// there. A client where they already have a membership of their own is left
/// alone.
pub(super) async fn carry_client_removals(
    msp: &MspId,
    inviter: &UserId,
    joining: &UserId,
    conn: &DbConn,
) -> EmptyResult {
    for removal in RemovedMember::find_by_msp(msp, conn).await {
        if &removal.user_uuid == inviter
            && Membership::find_by_user_and_org(joining, &removal.org_uuid, conn).await.is_none()
        {
            RemovedMember::record(&removal.org_uuid, joining, Some(msp), false, conn).await?;
        }
    }
    Ok(())
}

/// Deletes the organization's event destinations these people set up.
async fn delete_destinations(
    org_id: &OrganizationId,
    people: &HashSet<UserId>,
    conn: &DbConn,
) -> Result<Vec<Value>, crate::error::Error> {
    let mut deleted = Vec::new();
    for destination in EventDestination::find_by_org(org_id, conn).await {
        if destination.created_by.as_ref().is_some_and(|by| people.contains(by)) {
            destination.delete(conn).await?;
            deleted.push(json!({ "id": destination.uuid, "name": destination.name }));
        }
    }
    Ok(deleted)
}

/// What removing an MSP takes out of a client besides its people: the script
/// and provisioning tokens they made and the event destinations they set up,
/// and every staff seal. Says what went, and the single sign-on settings for
/// the owner to review, since an MSP may have set them up.
pub(super) async fn cut_msp_out(
    org_id: &OrganizationId,
    msp_id: &MspId,
    people: &HashSet<UserId>,
    conn: &DbConn,
) -> Result<Value, crate::error::Error> {
    let mut emails = HashSet::new();
    for person in people {
        if let Some(email) = email_of(person, conn).await {
            emails.insert(email.to_lowercase());
        }
    }

    let mut script_tokens = Vec::new();
    for mut token in ScriptToken::find_by_org(org_id, conn).await {
        if token.revoked_at.is_none() && people.contains(&token.created_by) {
            token.revoke(conn).await?;
            script_tokens.push(json!({
                "id": token.uuid,
                "name": token.name,
                "createdBy": email_of(&token.created_by, conn).await,
            }));
        }
    }

    let provisioning_token = match ScimToken::find(org_id, conn).await {
        Some(token)
            if token.created_by_user.as_ref().is_some_and(|by| people.contains(by))
                || emails.contains(&token.created_by.to_lowercase()) =>
        {
            ScimToken::delete(org_id, conn).await?;
            Some(json!({ "createdBy": token.created_by }))
        }
        _ => None,
    };

    let destinations = delete_destinations(org_id, people, conn).await?;
    let staff_seals = JoinSeal::delete_kind(org_id, SealKind::Staff, conn).await?;

    for person in people {
        RemovedMember::record(org_id, person, Some(msp_id), false, conn).await?;
    }

    let sso = SsoConfig::find(org_id, conn).await.map(|config| {
        json!({
            "enabled": config.enabled,
            "updatedBy": config.updated_by,
            "updatedByProvider": emails.contains(&config.updated_by.to_lowercase()),
            "updatedAt": format_date(&config.updated_at),
        })
    });

    Ok(json!({
        "scriptTokensRevoked": script_tokens,
        "provisioningTokenRevoked": provisioning_token,
        "eventDestinationsDeleted": destinations,
        "staffSealsDeleted": staff_seals,
        "singleSignOn": sso,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::keykeeper_two_step::{
        require_accepted_to_confirm, require_accepted_to_promote, require_accepted_to_restore, restore_waits_for_them,
        set_org_scope,
    };
    use super::*;
    use crate::db::{
        DbPool,
        models::{
            EventKind, Msp, MspRole, MspStaff, OrgAdminTwoStep, RevokedUntilAccepted, TwoStepScope,
            UnacceptedMembership, confirms_automatically,
        },
    };

    async fn person(name: &str, conn: &DbConn) -> User {
        let mut user = User::new(&format!("{name}@example.test"), None);
        user.save(conn).await.unwrap();
        user
    }

    async fn organization(name: &str, conn: &DbConn) -> Organization {
        let org = Organization::new(name.to_owned(), "billing@example.test", None, None);
        org.save(conn).await.unwrap();
        org
    }

    async fn join(user: &User, org: &Organization, atype: MembershipType, conn: &DbConn) -> Membership {
        let mut member = Membership::new(user.uuid.clone(), org.uuid.clone(), None);
        member.atype = atype as i32;
        member.status = MembershipStatus::Confirmed as i32;
        member.access_all = atype != MembershipType::User;
        member.save(conn).await.unwrap();
        member
    }

    /// An MSP, with these people as its admins.
    async fn msp(admins: &[&User], conn: &DbConn) -> MspId {
        let msp = Msp::new("Northwind IT".to_owned());
        msp.insert(conn).await.unwrap();
        for admin in admins {
            MspStaff::new(msp.uuid.clone(), admin.uuid.clone(), MspRole::Admin).insert(conn).await.unwrap();
        }
        msp.uuid
    }

    /// A client of the MSP, with its admins in it as the MSP's owners.
    async fn client(name: &str, msp: &MspId, admins: &[&User], conn: &DbConn) -> Organization {
        let org = organization(name, conn).await;
        MspClient {
            org_uuid: org.uuid.clone(),
            msp_uuid: msp.clone(),
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
        for admin in admins {
            let member = join(admin, &org, MembershipType::Owner, conn).await;
            MspMembership::new(member.uuid.clone(), msp.clone()).insert(conn).await.unwrap();
        }
        org
    }

    #[rocket::async_test]
    async fn leaving_is_remembered_so_rejoining_waits_for_an_admin() {
        let conn = DbPool::for_test().await;
        let org = organization("Contoso", &conn).await;
        let ana = person("ana", &conn).await;
        let member = join(&ana, &org, MembershipType::User, &conn).await;
        JoinSeal::set(&org.uuid, &ana.email, SealKind::Invite, Some("seal"), &conn).await.unwrap();

        before_leaving(&member, &conn).await.unwrap();
        member.delete(&conn).await.unwrap();
        assert!(RemovedMember::exists(&org.uuid, &ana.uuid, &conn).await);
        assert_eq!(JoinSeal::find(&org.uuid, &ana.email, SealKind::Invite, &conn).await, None);

        // She asks to join again, with the install command she kept: an admin
        // approves her, however the organization lets people in.
        let mut again = Membership::new(ana.uuid.clone(), org.uuid.clone(), None);
        again.status = MembershipStatus::Accepted as i32;
        again.save(&conn).await.unwrap();
        assert!(!confirms_automatically(true, &again, &conn).await);
    }

    #[rocket::async_test]
    async fn an_msp_admin_cant_make_another_account_an_owner_once_the_client_has_its_own() {
        let conn = DbPool::for_test().await;
        let mia = person("mia", &conn).await;
        let msp = msp(&[&mia], &conn).await;
        let acme = client("Acme Dental", &msp, &[&mia], &conn).await;
        let own = person("owner", &conn).await;
        join(&own, &acme, MembershipType::Owner, &conn).await;

        // Inviting an owner, or making someone one: only the client's own owners.
        assert!(check_owner_grant(&acme.uuid, &mia, &conn).await.is_err());
        assert!(check_owner_grant(&acme.uuid, &own, &conn).await.is_ok());
        let second = person("mia-again", &conn).await;
        let admin = join(&second, &acme, MembershipType::Admin, &conn).await;
        assert!(check_role_change(&admin, MembershipType::Owner, true, None, &mia, &conn).await.is_err());
        assert!(check_role_change(&admin, MembershipType::Owner, true, None, &own, &conn).await.is_ok());

        // A client with no owners of its own is the MSP's to run.
        let solo = client("Solo Law", &msp, &[&mia], &conn).await;
        assert!(check_owner_grant(&solo.uuid, &mia, &conn).await.is_ok());
    }

    #[rocket::async_test]
    async fn an_event_destination_sends_only_while_its_maker_has_access() {
        let conn = DbPool::for_test().await;
        let org = organization("Contoso", &conn).await;
        let owner = person("owner", &conn).await;
        join(&owner, &org, MembershipType::Owner, &conn).await;
        let maker = person("maker", &conn).await;
        let mut member = join(&maker, &org, MembershipType::Admin, &conn).await;
        let destination = EventDestination::new(
            Some(org.uuid.clone()),
            None,
            "SIEM".to_owned(),
            EventKind::Webhook,
            maker.uuid.clone(),
        );
        let source = org.uuid.to_string();
        assert!(destination_may_send(&destination, Some(&source), &conn).await);
        // Another organization's events never go there.
        assert!(!destination_may_send(&destination, Some("another-org"), &conn).await);

        member.atype = MembershipType::User as i32;
        member.save(&conn).await.unwrap();
        assert!(!destination_may_send(&destination, Some(&source), &conn).await);
        member.atype = MembershipType::Admin as i32;
        member.save(&conn).await.unwrap();
        assert!(destination_may_send(&destination, Some(&source), &conn).await);
        member.delete(&conn).await.unwrap();
        assert!(!destination_may_send(&destination, Some(&source), &conn).await);

        // An MSP's: while its maker is an admin of the MSP, and not for a
        // client that removed or revoked them.
        let mia = person("mia", &conn).await;
        let msp = msp(&[&mia], &conn).await;
        let acme = client("Acme Dental", &msp, &[&mia], &conn).await;
        let bayside = client("Bayside Law", &msp, &[&mia], &conn).await;
        let feed =
            EventDestination::new(None, Some(msp.clone()), "MDR".to_owned(), EventKind::Syslog, mia.uuid.clone());
        assert!(destination_may_send(&feed, Some(&acme.uuid.to_string()), &conn).await);
        RemovedMember::record(&acme.uuid, &mia.uuid, Some(&msp), true, &conn).await.unwrap();
        assert!(!destination_may_send(&feed, Some(&acme.uuid.to_string()), &conn).await);
        assert!(destination_may_send(&feed, Some(&bayside.uuid.to_string()), &conn).await);
        assert!(destination_may_send(&feed, None, &conn).await);
        MspStaff::find(&msp, &mia.uuid, &conn).await.unwrap().delete(&conn).await.unwrap();
        assert!(!destination_may_send(&feed, Some(&bayside.uuid.to_string()), &conn).await);
        assert!(!destination_may_send(&feed, None, &conn).await);
    }

    #[rocket::async_test]
    async fn a_clients_revocation_of_an_msp_admin_holds_against_staff_changes_and_its_log() {
        let conn = DbPool::for_test().await;
        let mia = person("mia", &conn).await;
        let bob = person("bob", &conn).await;
        let msp = msp(&[&mia, &bob], &conn).await;
        let acme = client("Acme Dental", &msp, &[&mia, &bob], &conn).await;
        let bayside = client("Bayside Law", &msp, &[&mia, &bob], &conn).await;

        // Acme revokes Mia.
        let mut revoked = Membership::find_by_user_and_org(&mia.uuid, &acme.uuid, &conn).await.unwrap();
        revoked.status = MembershipStatus::Revoked as i32;
        revoked.save(&conn).await.unwrap();
        RemovedMember::record(&acme.uuid, &mia.uuid, Some(&msp), true, &conn).await.unwrap();

        // She invites a second account of hers; it joins Bayside only.
        let second = person("mia-again", &conn).await;
        super::super::keykeeper_msp::add_to_staff(&msp, &second, MspRole::Admin, None, &mia.email, &conn)
            .await
            .unwrap();
        assert!(Membership::find_by_user_and_org(&second.uuid, &acme.uuid, &conn).await.is_none());
        assert!(Membership::find_by_user_and_org(&second.uuid, &bayside.uuid, &conn).await.is_some());

        // Bob's next change to it doesn't add it to Acme either.
        let staff = MspStaff::find(&msp, &second.uuid, &conn).await.unwrap();
        super::super::keykeeper_msp::sync_staff_memberships(&msp, &staff, Some(&bob.uuid), &bob.email, &conn)
            .await
            .unwrap();
        assert!(Membership::find_by_user_and_org(&second.uuid, &acme.uuid, &conn).await.is_none());

        // And Mia no longer reads Acme's activity; Bob does.
        assert_eq!(clients_closed_to(&msp, &mia.uuid, &conn).await, HashSet::from([acme.uuid.clone()]));
        assert!(clients_closed_to(&msp, &bob.uuid, &conn).await.is_empty());
    }

    #[rocket::async_test]
    async fn a_role_the_server_accepted_for_someone_waits_for_them_to_accept_it() {
        let conn = DbPool::for_test().await;
        let org = organization("Contoso", &conn).await;
        OrgAdminTwoStep::set(&org.uuid, TwoStepScope::Admins, &conn).await.unwrap();
        let ana = person("ana", &conn).await;
        let mut admin = join(&ana, &org, MembershipType::Admin, &conn).await;
        admin.status = MembershipStatus::Accepted as i32;
        admin.save(&conn).await.unwrap();
        UnacceptedMembership::mark(vec![admin.uuid.clone()], &conn).await.unwrap();
        assert!(require_accepted_to_confirm(&admin, &conn).await.is_err());

        // A regular member the server accepted for them isn't made an admin either.
        let ben = person("ben", &conn).await;
        let member = join(&ben, &org, MembershipType::User, &conn).await;
        UnacceptedMembership::mark(vec![member.uuid.clone()], &conn).await.unwrap();
        assert!(require_accepted_to_promote(&member, true, &conn).await.is_err());
        assert!(require_accepted_to_promote(&member, false, &conn).await.is_ok());

        // Once they accept, or where the organization doesn't require it, it goes ahead.
        UnacceptedMembership::accept(&admin.uuid, &conn).await.unwrap();
        assert!(require_accepted_to_confirm(&admin, &conn).await.is_ok());
        OrgAdminTwoStep::set(&org.uuid, TwoStepScope::Off, &conn).await.unwrap();
        assert!(require_accepted_to_promote(&member, true, &conn).await.is_ok());
    }

    #[rocket::async_test]
    async fn a_role_confirmed_before_the_rule_is_revoked_until_its_person_accepts_it() {
        let conn = DbPool::for_test().await;
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let org = organization("Contoso", &conn).await;
        let olivia = person("olivia", &conn).await;
        join(&olivia, &org, MembershipType::Owner, &conn).await;
        // Confirmed while the rule was off, in roles the server accepted for
        // their person: an admin, a regular member, and the admin who turns it on.
        let ana = person("ana", &conn).await;
        let admin = join(&ana, &org, MembershipType::Admin, &conn).await;
        let ben = person("ben", &conn).await;
        let member = join(&ben, &org, MembershipType::User, &conn).await;
        let cy = person("cy", &conn).await;
        let actor = join(&cy, &org, MembershipType::Admin, &conn).await;
        UnacceptedMembership::mark(vec![admin.uuid.clone(), member.uuid.clone(), actor.uuid.clone()], &conn)
            .await
            .unwrap();

        assert!(set_org_scope(&org.uuid, TwoStepScope::Admins, &cy.uuid, 0, &ip, &conn).await.unwrap());

        // The admin is revoked until they accept it.
        let admin = Membership::find_by_uuid(&admin.uuid, &conn).await.unwrap();
        assert!(admin.status < MembershipStatus::Invited as i32);
        assert_eq!(admin.get_unrevoked_status(), MembershipStatus::Confirmed as i32);
        assert!(RevokedUntilAccepted::is(&admin.uuid, &conn).await);
        assert!(UnacceptedMembership::is(&admin.uuid, &conn).await);
        // A regular member's role isn't one the rule covers.
        let member = Membership::find_by_uuid(&member.uuid, &conn).await.unwrap();
        assert_eq!(member.status, MembershipStatus::Confirmed as i32);
        assert!(!RevokedUntilAccepted::is(&member.uuid, &conn).await);
        // Whoever turned it on accepted their own role by doing so.
        let actor = Membership::find_by_uuid(&actor.uuid, &conn).await.unwrap();
        assert_eq!(actor.status, MembershipStatus::Confirmed as i32);
        assert!(!UnacceptedMembership::is(&actor.uuid, &conn).await);

        // An owner's restore waits for them, and says so; once they accept,
        // nothing holds it.
        assert!(require_accepted_to_restore(&admin, &conn).await.is_err());
        assert!(RevokedUntilAccepted::is(&admin.uuid, &conn).await);
        UnacceptedMembership::accept(&admin.uuid, &conn).await.unwrap();
        assert!(!restore_waits_for_them(&admin, &conn).await.unwrap());
        // Nor where the organization doesn't require it.
        OrgAdminTwoStep::set(&org.uuid, TwoStepScope::Off, &conn).await.unwrap();
        UnacceptedMembership::mark(vec![admin.uuid.clone()], &conn).await.unwrap();
        assert!(!restore_waits_for_them(&admin, &conn).await.unwrap());
    }

    #[rocket::async_test]
    async fn the_rule_never_revokes_an_organizations_last_confirmed_owner() {
        let conn = DbPool::for_test().await;
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let org = organization("Fabrikam", &conn).await;
        let olivia = person("olivia", &conn).await;
        let owner = join(&olivia, &org, MembershipType::Owner, &conn).await;
        UnacceptedMembership::mark(vec![owner.uuid.clone()], &conn).await.unwrap();
        let cy = person("cy", &conn).await;
        join(&cy, &org, MembershipType::Admin, &conn).await;

        set_org_scope(&org.uuid, TwoStepScope::Admins, &cy.uuid, 0, &ip, &conn).await.unwrap();

        let owner = Membership::find_by_uuid(&owner.uuid, &conn).await.unwrap();
        assert_eq!(owner.status, MembershipStatus::Confirmed as i32);
        assert!(!RevokedUntilAccepted::is(&owner.uuid, &conn).await);
    }
}

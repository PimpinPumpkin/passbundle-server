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
//
// See DESIGN.md, "Offboarding", in the meta repo.

use std::collections::HashSet;

use serde_json::{Value, json};

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        models::{
            EventDestination, JoinSeal, Membership, MembershipStatus, MembershipType, MspId, MspMembership,
            Organization, OrganizationId, RemovedMember, ScimToken, ScriptToken, SealKind, SsoConfig, User, UserId,
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
    }
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

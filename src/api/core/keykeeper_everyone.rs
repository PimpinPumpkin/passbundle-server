// Keykeeper: the "Everyone" collection the Business preset makes (an MSP's
// client's, or a company's own). People who join with the install command get
// it when they join, people provisioning invites when they're invited, and
// everyone else who joins as a member when an owner's or admin's app confirms
// them, the moment they get the organization's key: an emailed invitation
// included, whatever collections it named. See DESIGN.md, "Defaults
// (Business preset)", in the meta repo.
//
// A grant here is what an owner or admin adding them by hand gives (Can edit),
// nothing about keys: the organization's key reaches them only through the
// confirmation itself.

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        models::{
            Collection, CollectionUser, Membership, MembershipStatus, MembershipType, MspClient, MspMembership,
            OrgSetup, OrganizationId,
        },
    },
};

/// The organization's Everyone collection, found as the install command finds
/// it: by the id kept with its install command (an MSP's client's, or a
/// company's own), never by a name, which the server can't read. None for an
/// organization without one (a family, or one made before the preset), or one
/// whose Everyone was deleted.
pub async fn everyone_collection(org: &OrganizationId, conn: &DbConn) -> Option<Collection> {
    let id = match MspClient::find_by_org(org, conn).await {
        Some(client) => client.everyone_collection,
        None => OrgSetup::find_by_org(org, conn).await.and_then(|s| s.everyone_collection),
    }?;
    Collection::find_by_uuid_and_org(&id, org, conn).await
}

/// Gives a member who was just confirmed the organization's Everyone
/// collection, Can edit, as joining with the install command does. Nothing
/// for an MSP's staff, who reach a client through the MSP rather than as its
/// members; for owners, admins, and anyone with access to every item, who
/// reach it already; or for someone with a grant there already, which stays
/// as it is (Can edit would widen a narrower one).
pub async fn give_everyone(member: &Membership, conn: &DbConn) -> EmptyResult {
    if member.status != MembershipStatus::Confirmed as i32
        || member.atype >= MembershipType::Admin
        || member.access_all
        || MspMembership::find_by_membership(&member.uuid, conn).await.is_some()
    {
        return Ok(());
    }
    let Some(collection) = everyone_collection(&member.org_uuid, conn).await else {
        return Ok(());
    };
    if CollectionUser::find_by_collection_and_user(&collection.uuid, &member.user_uuid, conn).await.is_some() {
        return Ok(());
    }
    // Can edit, as a preset grant (keykeeper_folder_permissions.rs).
    crate::db::models::keykeeper_folder_permissions::save_user(
        &member.user_uuid,
        &collection.uuid,
        &crate::db::models::keykeeper_folder_permissions::Grid::preset(false, false, false),
        conn,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{WS_USERS, core::organizations::confirm_invite_impl},
        auth::{AdminHeaders, ClientIp},
        db::{
            DbPool,
            models::{
                Device, DeviceId, Msp, MspRole, MspStaff, Organization, ScimUser, User,
                keykeeper_folder_permissions::Grid,
            },
        },
    };

    async fn person(name: &str, conn: &DbConn) -> User {
        let mut user = User::new(&format!("{name}@example.test"), None);
        user.save(conn).await.unwrap();
        user
    }

    async fn member(
        user: &User,
        org: &Organization,
        atype: MembershipType,
        status: MembershipStatus,
        conn: &DbConn,
    ) -> Membership {
        let mut member = Membership::new(user.uuid.clone(), org.uuid.clone(), Some("owner@example.test".to_owned()));
        member.atype = atype as i32;
        member.status = status as i32;
        member.access_all = atype >= MembershipType::Admin;
        member.save(conn).await.unwrap();
        member
    }

    /// A company's own organization with the Business preset: an owner, and
    /// an Everyone collection kept with its install command, unless `everyone`
    /// is false (a family, or an organization made before the preset).
    async fn business(name: &str, everyone: bool, conn: &DbConn) -> (Organization, User, Option<Collection>) {
        let org = Organization::new(name.to_owned(), "billing@example.test", None, None);
        org.save(conn).await.unwrap();
        let owner = person(&format!("owner-{}", org.uuid), conn).await;
        member(&owner, &org, MembershipType::Owner, MembershipStatus::Confirmed, conn).await;
        let collection = if everyone {
            let collection = Collection::new(org.uuid.clone(), "2.everyone|ct|mac".to_owned(), None);
            collection.save(conn).await.unwrap();
            Some(collection)
        } else {
            None
        };
        OrgSetup::new(
            org.uuid.clone(),
            Some("business".to_owned()),
            collection.as_ref().map(|c| c.uuid.clone()),
            false,
        )
        .unwrap()
        .insert(conn)
        .await
        .unwrap();
        (org, owner, collection)
    }

    async fn headers(user: &User, org: &Organization, conn: &DbConn) -> AdminHeaders {
        AdminHeaders {
            host: "https://127.0.0.1".to_owned(),
            device: Device::new(
                DeviceId::from(format!("device-{}", user.uuid)),
                user.uuid.clone(),
                "test".to_owned(),
                9,
            ),
            user: User::find_by_uuid(&user.uuid, conn).await.unwrap(),
            membership_type: MembershipType::Owner,
            ip: ClientIp {
                ip: "127.0.0.1".parse().unwrap(),
            },
            org_id: org.uuid.clone(),
            custom_permissions: None,
        }
    }

    /// The owner's app confirms them, with the upstream route's own code.
    async fn confirm(owner: &User, org: &Organization, member: &Membership, conn: &DbConn) {
        let nt: crate::api::Notify<'_> = (&*WS_USERS).into();
        confirm_invite_impl(&org.uuid, &member.uuid, "2.org-key|ct|mac", &headers(owner, org, conn).await, conn, &nt)
            .await
            .unwrap();
        let confirmed = Membership::find_by_uuid(&member.uuid, conn).await.unwrap();
        assert_eq!(confirmed.status, MembershipStatus::Confirmed as i32);
    }

    async fn grants(collection: &Collection, conn: &DbConn) -> Vec<CollectionUser> {
        CollectionUser::find_by_collection(&collection.uuid, conn).await
    }

    async fn grid_of(user: &User, collection: &Collection, conn: &DbConn) -> Option<(bool, bool, bool)> {
        CollectionUser::find_by_collection_and_user(&collection.uuid, &user.uuid, conn)
            .await
            .map(|g| (g.read_only, g.hide_passwords, g.manage))
    }

    #[rocket::async_test]
    async fn someone_invited_by_email_gets_everyone_when_confirmed() {
        let conn = DbPool::for_test().await;
        let (org, owner, everyone) = business("Harbor Dental", true, &conn).await;
        let everyone = everyone.unwrap();
        let ana = person("ana", &conn).await;
        // Invited by email and accepted: nothing until the org key reaches her.
        let invited = member(&ana, &org, MembershipType::User, MembershipStatus::Accepted, &conn).await;
        assert_eq!(grid_of(&ana, &everyone, &conn).await, None);

        confirm(&owner, &org, &invited, &conn).await;
        // Can edit, as joining with the install command gives.
        assert_eq!(grid_of(&ana, &everyone, &conn).await, Some((false, false, false)));
        assert_eq!(Grid::preset(false, false, false).upstream(), (false, false, false));
        assert_eq!(grants(&everyone, &conn).await.len(), 1);
    }

    #[rocket::async_test]
    async fn an_invitation_that_named_collections_still_gets_everyone_and_keeps_its_grants() {
        let conn = DbPool::for_test().await;
        let (org, owner, everyone) = business("Harbor Dental", true, &conn).await;
        let everyone = everyone.unwrap();
        let front_desk = Collection::new(org.uuid.clone(), "2.front-desk|ct|mac".to_owned(), None);
        front_desk.save(&conn).await.unwrap();
        let bo = person("bo", &conn).await;
        let invited = member(&bo, &org, MembershipType::User, MembershipStatus::Accepted, &conn).await;
        // The invitation gave Front desk, read-only.
        crate::db::models::keykeeper_folder_permissions::save_user(
            &bo.uuid,
            &front_desk.uuid,
            &Grid::preset(true, false, false),
            &conn,
        )
        .await
        .unwrap();

        confirm(&owner, &org, &invited, &conn).await;
        assert_eq!(grid_of(&bo, &everyone, &conn).await, Some((false, false, false)));
        assert_eq!(grid_of(&bo, &front_desk, &conn).await, Some((true, false, false)));
    }

    #[rocket::async_test]
    async fn a_grant_there_already_stays_as_it_is_with_no_duplicate() {
        let conn = DbPool::for_test().await;
        let (org, owner, everyone) = business("Harbor Dental", true, &conn).await;
        let everyone = everyone.unwrap();
        let cy = person("cy", &conn).await;
        let invited = member(&cy, &org, MembershipType::User, MembershipStatus::Accepted, &conn).await;
        // The invitation gave Everyone itself, read-only: Can edit would widen it.
        crate::db::models::keykeeper_folder_permissions::save_user(
            &cy.uuid,
            &everyone.uuid,
            &Grid::preset(true, false, false),
            &conn,
        )
        .await
        .unwrap();

        confirm(&owner, &org, &invited, &conn).await;
        assert_eq!(grid_of(&cy, &everyone, &conn).await, Some((true, false, false)));
        assert_eq!(grants(&everyone, &conn).await.len(), 1);
        // Asked again, still one grant, still read-only.
        let confirmed = Membership::find_by_uuid(&invited.uuid, &conn).await.unwrap();
        give_everyone(&confirmed, &conn).await.unwrap();
        assert_eq!(grants(&everyone, &conn).await.len(), 1);
        assert_eq!(grid_of(&cy, &everyone, &conn).await, Some((true, false, false)));
    }

    #[rocket::async_test]
    async fn without_everyone_nothing_happens() {
        let conn = DbPool::for_test().await;
        // No Everyone kept with the organization (a family, or made before the preset).
        let (org, owner, _) = business("Rivera Family", false, &conn).await;
        let other = Collection::new(org.uuid.clone(), "2.default|ct|mac".to_owned(), None);
        other.save(&conn).await.unwrap();
        let di = person("di", &conn).await;
        let invited = member(&di, &org, MembershipType::User, MembershipStatus::Accepted, &conn).await;
        confirm(&owner, &org, &invited, &conn).await;
        assert_eq!(grid_of(&di, &other, &conn).await, None);

        // An organization with no setup at all: nothing either.
        let plain = Organization::new("Upstream Org".to_owned(), "billing@example.test", None, None);
        plain.save(&conn).await.unwrap();
        let plain_owner = person("plain-owner", &conn).await;
        member(&plain_owner, &plain, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        let plain_default = Collection::new(plain.uuid.clone(), "2.default|ct|mac".to_owned(), None);
        plain_default.save(&conn).await.unwrap();
        let ed = person("ed", &conn).await;
        let invited = member(&ed, &plain, MembershipType::User, MembershipStatus::Accepted, &conn).await;
        confirm(&plain_owner, &plain, &invited, &conn).await;
        assert_eq!(grid_of(&ed, &plain_default, &conn).await, None);
    }

    #[rocket::async_test]
    async fn a_deleted_everyone_is_never_given_and_confirming_still_works() {
        let conn = DbPool::for_test().await;
        let (org, owner, everyone) = business("Harbor Dental", true, &conn).await;
        let everyone = everyone.unwrap();
        let everyone_id = everyone.uuid.clone();
        everyone.delete(&conn).await.unwrap();
        assert!(everyone_collection(&org.uuid, &conn).await.is_none());

        let fay = person("fay", &conn).await;
        let invited = member(&fay, &org, MembershipType::User, MembershipStatus::Accepted, &conn).await;
        confirm(&owner, &org, &invited, &conn).await;
        assert!(CollectionUser::find_by_collection_and_user(&everyone_id, &fay.uuid, &conn).await.is_none());
    }

    #[rocket::async_test]
    async fn an_msps_staff_in_a_client_never_get_everyone() {
        let conn = DbPool::for_test().await;
        let org = Organization::new("Acme Dental".to_owned(), "billing@example.test", None, None);
        org.save(&conn).await.unwrap();
        let everyone = Collection::new(org.uuid.clone(), "2.everyone|ct|mac".to_owned(), None);
        everyone.save(&conn).await.unwrap();
        let msp = Msp::new("Northwind IT".to_owned());
        msp.insert(&conn).await.unwrap();
        MspClient {
            org_uuid: org.uuid.clone(),
            msp_uuid: msp.uuid.clone(),
            created_at: chrono::Utc::now().naive_utc(),
            preset: Some("business".to_owned()),
            enrollment_token: None,
            enrollment_token_created_at: None,
            everyone_collection: Some(everyone.uuid.clone()),
            templates_collection: None,
            enrollment_secret: None,
            enrollment_token_hash: None,
            client_seal: None,
            joined_with_code: false,
        }
        .insert(&conn)
        .await
        .unwrap();
        // The MSP's admin, the client's owner through the MSP.
        let mia = person("mia", &conn).await;
        MspStaff::new(msp.uuid.clone(), mia.uuid.clone(), MspRole::Admin).insert(&conn).await.unwrap();
        let owner = member(&mia, &org, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        MspMembership::new(owner.uuid.clone(), msp.uuid.clone()).insert(&conn).await.unwrap();
        // A technician the MSP brought in as a regular member, waiting for the key.
        let tom = person("tom", &conn).await;
        MspStaff::new(msp.uuid.clone(), tom.uuid.clone(), MspRole::Technician).insert(&conn).await.unwrap();
        let tech = member(&tom, &org, MembershipType::User, MembershipStatus::Accepted, &conn).await;
        MspMembership::new(tech.uuid.clone(), msp.uuid.clone()).insert(&conn).await.unwrap();
        // And one of the client's own people, invited by email.
        let gus = person("gus", &conn).await;
        let own = member(&gus, &org, MembershipType::User, MembershipStatus::Accepted, &conn).await;

        confirm(&mia, &org, &tech, &conn).await;
        confirm(&mia, &org, &own, &conn).await;
        assert_eq!(grid_of(&tom, &everyone, &conn).await, None);
        assert_eq!(grid_of(&gus, &everyone, &conn).await, Some((false, false, false)));
        // Its admin is never added either.
        assert_eq!(grid_of(&mia, &everyone, &conn).await, None);
    }

    #[rocket::async_test]
    async fn owners_admins_and_access_to_every_item_reach_it_already() {
        let conn = DbPool::for_test().await;
        let (org, owner, everyone) = business("Harbor Dental", true, &conn).await;
        let everyone = everyone.unwrap();
        let hal = person("hal", &conn).await;
        let admin = member(&hal, &org, MembershipType::Admin, MembershipStatus::Accepted, &conn).await;
        confirm(&owner, &org, &admin, &conn).await;
        assert_eq!(grid_of(&hal, &everyone, &conn).await, None);

        let ivy = person("ivy", &conn).await;
        let mut all = member(&ivy, &org, MembershipType::Manager, MembershipStatus::Accepted, &conn).await;
        all.access_all = true;
        all.save(&conn).await.unwrap();
        confirm(&owner, &org, &all, &conn).await;
        assert_eq!(grid_of(&ivy, &everyone, &conn).await, None);

        // A manager with chosen folders is a member like any other here.
        let jo = person("jo", &conn).await;
        let manager = member(&jo, &org, MembershipType::Manager, MembershipStatus::Accepted, &conn).await;
        confirm(&owner, &org, &manager, &conn).await;
        assert_eq!(grid_of(&jo, &everyone, &conn).await, Some((false, false, false)));
    }

    #[rocket::async_test]
    async fn someone_provisioning_invited_gets_everyone_when_confirmed() {
        let conn = DbPool::for_test().await;
        let (org, owner, everyone) = business("Harbor Dental", true, &conn).await;
        let everyone = everyone.unwrap();
        let kim = person("kim", &conn).await;
        // Invited by the directory: no inviter, and kept as provisioned. Their
        // grant from the invitation is gone (say, Everyone came after them).
        let mut invited = Membership::new(kim.uuid.clone(), org.uuid.clone(), None);
        invited.status = MembershipStatus::Accepted as i32;
        invited.save(&conn).await.unwrap();
        let mut scim = ScimUser::new(invited.uuid.clone(), org.uuid.clone(), true);
        scim.set_user_name("kim@contoso.onmicrosoft.com");
        scim.save(&conn).await.unwrap();
        assert_eq!(grid_of(&kim, &everyone, &conn).await, None);

        confirm(&owner, &org, &invited, &conn).await;
        assert_eq!(grid_of(&kim, &everyone, &conn).await, Some((false, false, false)));
        assert_eq!(grants(&everyone, &conn).await.len(), 1);
    }

    #[rocket::async_test]
    async fn members_still_waiting_or_turned_off_get_nothing() {
        let conn = DbPool::for_test().await;
        let (org, _, everyone) = business("Harbor Dental", true, &conn).await;
        let everyone = everyone.unwrap();
        for (name, status) in [
            ("invited", MembershipStatus::Invited),
            ("accepted", MembershipStatus::Accepted),
            ("revoked", MembershipStatus::Revoked),
        ] {
            let user = person(name, &conn).await;
            let waiting = member(&user, &org, MembershipType::User, status, &conn).await;
            give_everyone(&waiting, &conn).await.unwrap();
            assert_eq!(grid_of(&user, &everyone, &conn).await, None);
        }
    }
}

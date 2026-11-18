// Keykeeper: a client organization's own view of what its MSP did there
// (DESIGN.md, "MSP console", "The client sees its MSP's actions"). The MSP's
// audit log already records each action with the client it touched. A
// client's own owners and admins read the entries about their organization,
// of the kinds below, and nothing else of the MSP's: no other client's entry,
// no MSP-wide entry, never the MSP's list of clients, and never the address
// an action came from. The MSP's people, who have Activity in their console,
// get "not found" here, as does everyone else who isn't one of the client's
// own owners or admins.

use rocket::{Route, serde::json::Json};
use serde_json::Value;

use crate::{
    api::JsonResult,
    auth::Headers,
    db::{
        DbConn,
        models::{Membership, MembershipType, Msp, MspClient, MspEvent, MspId, MspMembership, OrganizationId, UserId},
    },
};

pub fn routes() -> Vec<Route> {
    routes![client_activity]
}

/// The kinds of the MSP's entries a client sees about itself: the MSP's people
/// added to it, given another role there, or removed from it; members
/// confirmed in it; its install command replaced or limited to email domains,
/// and people joining it with that command; the MSP's default policies
/// reaching it, required of it, or put back; and the MSP's templates sent to
/// it, with the collection they go in. Plus the entry for the MSP making it a
/// client, or for its own owner joining it to the MSP with a code. A kind left out here (single sign-on, provisioning, script tokens,
/// and anything added later) stays the MSP's until someone decides the client
/// should see it.
pub(super) const CLIENT_KINDS: &[&str] = &[
    "client_created",
    "client_joined",
    "client_staff_added",
    "client_staff_role_changed",
    "client_staff_removed",
    "member_confirmed",
    "install_token_replaced",
    "install_domains_set",
    "joined_with_install_command",
    "client_policy_pushed",
    "client_policy_required",
    "client_policy_default",
    "client_template_sent",
    "templates_collection_set",
];

/// Whether someone may read an organization's view of its MSP's actions.
pub(super) enum ClientView {
    /// A confirmed owner or admin there whose place is the client's own:
    /// the entries of the client's MSP.
    Shown(MspId),
    /// The same, in an organization no MSP manages: nothing to show.
    NoMsp,
    /// Anyone else: a regular member, a custom role, someone invited or
    /// revoked, the MSP's own people there, and people of other
    /// organizations. The route answers "not found", never 403, which would
    /// sign the web vault out (the Members page shows to custom roles and to
    /// the MSP's people too).
    Refused,
}

/// Who reads a client's view of its MSP's actions: a confirmed owner or admin
/// of the organization whose membership the MSP didn't make. A database error
/// reading whether it did is an error, never a yes.
pub(super) async fn client_view(
    org_id: &OrganizationId,
    user_id: &UserId,
    conn: &DbConn,
) -> Result<ClientView, crate::error::Error> {
    let Some(member) = Membership::find_confirmed_by_user_and_org(user_id, org_id, conn).await else {
        return Ok(ClientView::Refused);
    };
    if member.atype != MembershipType::Owner as i32 && member.atype != MembershipType::Admin as i32 {
        return Ok(ClientView::Refused);
    }
    if MspMembership::try_is_msp_membership(&member.uuid, conn).await? {
        return Ok(ClientView::Refused);
    }
    Ok(match MspClient::find_by_org(org_id, conn).await {
        Some(client) => ClientView::Shown(client.msp_uuid),
        None => ClientView::NoMsp,
    })
}

const MAX_ENTRIES: i64 = 500;

/// One entry as the client sees it: what happened, when, who did it, and to
/// whom, without where it came from.
fn entry_json(e: &MspEvent) -> Value {
    json!({
        "id": e.uuid,
        "date": crate::util::format_date(&e.created_at),
        "event": e.event,
        "actorEmail": e.actor_email,
        "targetEmail": e.target_email,
        "detail": e.detail,
    })
}

/// For a client's own owners and admins: what its MSP did in the
/// organization, newest first, `limit` at a time (100 by default), older
/// than `before` (the date of the oldest entry already shown). An
/// organization without an MSP has nothing to show, which isn't an error.
#[get("/keykeeper/organizations/<org_id>/msp/activity?<before>&<limit>")]
async fn client_activity(
    org_id: OrganizationId,
    before: Option<String>,
    limit: Option<i64>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let msp_id = match client_view(&org_id, &headers.user.uuid, &conn).await? {
        ClientView::Shown(msp_id) => msp_id,
        ClientView::NoMsp => return Ok(Json(json!({ "msp": null, "data": [] }))),
        ClientView::Refused => {
            err_code!("Organization not found", rocket::http::Status::NotFound.code)
        }
    };
    let before = super::keykeeper_msp::parse_before(before.as_deref())?;
    let limit = limit.unwrap_or(100).clamp(1, MAX_ENTRIES);
    let msp = Msp::find_by_uuid(&msp_id, &conn).await;
    let entries: Vec<Value> = MspEvent::find_by_client(&msp_id, &org_id, CLIENT_KINDS, before, limit, &conn)
        .await
        .iter()
        .map(entry_json)
        .collect();
    Ok(Json(json!({
        "msp": msp.map(|m| json!({ "id": m.uuid, "name": m.name })),
        "data": entries,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        DbPool,
        models::{
            CustomRole, MembershipStatus, MspRole, MspStaff, Organization, TechnicianAccess, User, keykeeper_roles,
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

    async fn join(
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

    async fn msp(admin: &User, conn: &DbConn) -> MspId {
        let msp = Msp::new("Northwind IT".to_owned());
        msp.insert(conn).await.unwrap();
        MspStaff::new(msp.uuid.clone(), admin.uuid.clone(), MspRole::Admin).insert(conn).await.unwrap();
        msp.uuid
    }

    /// A client of the MSP, with the MSP's admin in it as the MSP's owner.
    async fn client(name: &str, msp: &MspId, admin: &User, conn: &DbConn) -> Organization {
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
            joined_with_code: false,
        }
        .insert(conn)
        .await
        .unwrap();
        let member = join(admin, &org, MembershipType::Owner, MembershipStatus::Confirmed, conn).await;
        MspMembership::new(member.uuid.clone(), msp.clone()).insert(conn).await.unwrap();
        org
    }

    async fn shown(org: &Organization, user: &User, conn: &DbConn) -> bool {
        matches!(client_view(&org.uuid, &user.uuid, conn).await.unwrap(), ClientView::Shown(_))
    }

    async fn refused(org: &Organization, user: &User, conn: &DbConn) -> bool {
        matches!(client_view(&org.uuid, &user.uuid, conn).await.unwrap(), ClientView::Refused)
    }

    #[rocket::async_test]
    async fn the_clients_own_owners_and_admins_see_it_and_nobody_else() {
        let conn = DbPool::for_test().await;
        let msp_admin = person("msp-admin", &conn).await;
        let msp_id = msp(&msp_admin, &conn).await;
        let acme = client("Acme Dental", &msp_id, &msp_admin, &conn).await;

        let owner = person("owner", &conn).await;
        join(&owner, &acme, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        let admin = person("admin", &conn).await;
        join(&admin, &acme, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        assert!(shown(&acme, &owner, &conn).await);
        assert!(shown(&acme, &admin, &conn).await);

        // A regular member, and one with a custom role.
        let user = person("user", &conn).await;
        join(&user, &acme, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        assert!(refused(&acme, &user, &conn).await);
        let contact = person("contact", &conn).await;
        let custom = join(&contact, &acme, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        let permissions = keykeeper_roles::CustomPermissions {
            manage_users: true,
            access_event_logs: true,
            ..Default::default()
        };
        keykeeper_roles::set(&custom.uuid, Some(&permissions), &conn).await.unwrap();
        assert!(refused(&acme, &contact, &conn).await);

        // An owner who hasn't been confirmed yet, or was revoked.
        let waiting = person("waiting", &conn).await;
        join(&waiting, &acme, MembershipType::Owner, MembershipStatus::Accepted, &conn).await;
        assert!(refused(&acme, &waiting, &conn).await);
        let revoked = person("revoked", &conn).await;
        join(&revoked, &acme, MembershipType::Owner, MembershipStatus::Revoked, &conn).await;
        assert!(refused(&acme, &revoked, &conn).await);

        // The MSP's own people there: its admin, an owner through the MSP,
        // and a technician, an admin through the MSP.
        assert!(refused(&acme, &msp_admin, &conn).await);
        let tech = person("tech", &conn).await;
        MspStaff::new(msp_id.clone(), tech.uuid.clone(), MspRole::Technician).insert(&conn).await.unwrap();
        let tech_member = join(&tech, &acme, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        MspMembership::new(tech_member.uuid.clone(), msp_id.clone()).insert(&conn).await.unwrap();
        assert!(refused(&acme, &tech, &conn).await);

        // Another MSP's staff, an owner of another client of the same MSP,
        // and someone with no place anywhere.
        let other_admin = person("other-msp-admin", &conn).await;
        let other_msp = msp(&other_admin, &conn).await;
        client("Fabrikam", &other_msp, &other_admin, &conn).await;
        assert!(refused(&acme, &other_admin, &conn).await);
        let baker = client("Baker Law", &msp_id, &msp_admin, &conn).await;
        let baker_owner = person("baker-owner", &conn).await;
        join(&baker_owner, &baker, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        assert!(shown(&baker, &baker_owner, &conn).await);
        assert!(refused(&acme, &baker_owner, &conn).await);
        let stranger = person("stranger", &conn).await;
        assert!(refused(&acme, &stranger, &conn).await);
    }

    #[rocket::async_test]
    async fn a_member_of_the_msp_staff_whose_place_in_the_client_is_its_own_sees_it() {
        // Someone the client made an owner before they joined the MSP's
        // staff: their place there is the client's, not the MSP's.
        let conn = DbPool::for_test().await;
        let msp_admin = person("msp-admin", &conn).await;
        let msp_id = msp(&msp_admin, &conn).await;
        let acme = client("Acme Dental", &msp_id, &msp_admin, &conn).await;
        let owner = person("owner", &conn).await;
        join(&owner, &acme, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        MspStaff::new(msp_id.clone(), owner.uuid.clone(), MspRole::Technician).insert(&conn).await.unwrap();
        assert!(shown(&acme, &owner, &conn).await);
    }

    #[rocket::async_test]
    async fn an_organization_without_an_msp_has_nothing_to_show_to_its_owners_only() {
        let conn = DbPool::for_test().await;
        let own = organization("Contoso", &conn).await;
        let owner = person("owner", &conn).await;
        join(&owner, &own, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        assert!(matches!(client_view(&own.uuid, &owner.uuid, &conn).await.unwrap(), ClientView::NoMsp));
        let user = person("user", &conn).await;
        join(&user, &own, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        assert!(refused(&own, &user, &conn).await);
    }

    fn event(msp: &MspId, kind: &str, org: Option<&Organization>, at: i64) -> MspEvent {
        let mut e = MspEvent::new(msp.clone(), kind);
        e.created_at = chrono::DateTime::from_timestamp(1_790_000_000 + at, 0).unwrap().naive_utc();
        e.org_uuid = org.map(|o| o.uuid.clone());
        e.org_name = org.map(|o| o.name.clone());
        e.target_email = Some(format!("{kind}@example.test"));
        e.ip = Some("192.0.2.1".to_owned());
        e
    }

    #[rocket::async_test]
    async fn a_client_reads_only_its_own_entries_of_the_kinds_it_sees_newest_first() {
        let conn = DbPool::for_test().await;
        let msp_admin = person("msp-admin", &conn).await;
        let msp_id = msp(&msp_admin, &conn).await;
        let acme = client("Acme Dental", &msp_id, &msp_admin, &conn).await;
        let baker = client("Baker Law", &msp_id, &msp_admin, &conn).await;
        for e in [
            event(&msp_id, "client_created", Some(&acme), 1),
            // MSP-wide: someone joined the staff, a default changed.
            event(&msp_id, "staff_invite_accepted", None, 2),
            event(&msp_id, "default_policy_changed", None, 3),
            event(&msp_id, "client_staff_added", Some(&acme), 4),
            event(&msp_id, "client_staff_added", Some(&baker), 5),
            event(&msp_id, "member_confirmed", Some(&acme), 6),
            // About Acme, but a kind the client doesn't see.
            event(&msp_id, "script_token_new_address", Some(&acme), 7),
            event(&msp_id, "client_policy_pushed", Some(&acme), 8),
            event(&msp_id, "install_token_replaced", Some(&baker), 9),
        ] {
            e.insert(&conn).await.unwrap();
        }
        let kinds = |events: Vec<MspEvent>| events.into_iter().map(|e| e.event).collect::<Vec<_>>();
        let acme_entries = MspEvent::find_by_client(&msp_id, &acme.uuid, CLIENT_KINDS, None, 100, &conn).await;
        assert!(acme_entries.iter().all(|e| e.org_uuid.as_ref() == Some(&acme.uuid)));
        assert_eq!(
            kinds(acme_entries),
            ["client_policy_pushed", "member_confirmed", "client_staff_added", "client_created"]
        );
        assert_eq!(
            kinds(MspEvent::find_by_client(&msp_id, &baker.uuid, CLIENT_KINDS, None, 100, &conn).await),
            ["install_token_replaced", "client_staff_added"]
        );
        // Pages, older than the oldest already shown.
        let first = MspEvent::find_by_client(&msp_id, &acme.uuid, CLIENT_KINDS, None, 2, &conn).await;
        let before = Some(first[1].created_at);
        assert_eq!(
            kinds(MspEvent::find_by_client(&msp_id, &acme.uuid, CLIENT_KINDS, before, 2, &conn).await),
            ["client_staff_added", "client_created"]
        );
        // What a client sees never says where it came from.
        let shown = entry_json(&MspEvent::find_by_client(&msp_id, &acme.uuid, CLIENT_KINDS, None, 1, &conn).await[0]);
        assert!(shown.get("ip").is_none() && shown.get("organizationId").is_none(), "{shown}");

        // The MSP's own Activity leaves out each client's share of a change.
        assert_eq!(
            kinds(MspEvent::find_by_msp(&msp_id, None, None, Vec::new(), 100, &conn).await),
            [
                "install_token_replaced",
                "script_token_new_address",
                "member_confirmed",
                "default_policy_changed",
                "staff_invite_accepted",
                "client_created"
            ]
        );
    }

    /// A client's entries, oldest first: what, about whom, by whom, and how.
    async fn entries(msp: &MspId, org: &Organization, conn: &DbConn) -> Vec<(String, String, String, String)> {
        let mut found: Vec<_> = MspEvent::find_by_client(msp, &org.uuid, CLIENT_KINDS, None, 100, conn)
            .await
            .into_iter()
            .map(|e| {
                (
                    e.event,
                    e.target_email.unwrap_or_default(),
                    e.actor_email.unwrap_or_default(),
                    e.detail.unwrap_or_default(),
                )
            })
            .collect();
        found.reverse();
        found
    }

    /// What every staff change ends in: their memberships brought in line, by an MSP admin.
    async fn sync_by(admin: &User, staff: &MspStaff, conn: &DbConn) {
        super::super::keykeeper_msp::sync_staff_memberships(
            &staff.msp_uuid,
            staff,
            Some(&admin.uuid),
            &admin.email,
            conn,
        )
        .await
        .unwrap();
    }

    #[rocket::async_test]
    async fn each_client_a_staff_change_touches_gets_its_share_and_no_other_does() {
        let conn = DbPool::for_test().await;
        let msp_admin = person("msp-admin", &conn).await;
        let msp_id = msp(&msp_admin, &conn).await;
        let acme = client("Acme Dental", &msp_id, &msp_admin, &conn).await;
        let baker = client("Baker Law", &msp_id, &msp_admin, &conn).await;
        let tech = person("tech", &conn).await;
        let mut staff = MspStaff::new(msp_id.clone(), tech.uuid.clone(), MspRole::Technician);
        staff.insert(&conn).await.unwrap();
        let only_acme = TechnicianAccess {
            all_clients: false,
            clients: vec![acme.uuid.clone()],
            ..Default::default()
        };
        staff.set_access(&only_acme, &conn).await.unwrap();
        sync_by(&msp_admin, &staff, &conn).await;
        let added = |detail: &str| {
            ("client_staff_added".to_owned(), tech.email.clone(), msp_admin.email.clone(), detail.to_owned())
        };
        assert_eq!(entries(&msp_id, &acme, &conn).await, [added("admin")]);
        assert_eq!(entries(&msp_id, &baker, &conn).await, []);

        // Nothing changed for them: nothing more.
        sync_by(&msp_admin, &staff, &conn).await;
        assert_eq!(entries(&msp_id, &acme, &conn).await.len(), 1);

        // Both clients, with a custom role: Acme's role changes, Baker gets them.
        let custom = CustomRole {
            permissions: keykeeper_roles::CustomPermissions {
                manage_users: true,
                ..Default::default()
            },
            vault_items: false,
        };
        let both = TechnicianAccess {
            all_clients: true,
            custom: Some(custom),
            ..Default::default()
        };
        staff.set_access(&both, &conn).await.unwrap();
        sync_by(&msp_admin, &staff, &conn).await;
        let changed =
            ("client_staff_role_changed".to_owned(), tech.email.clone(), msp_admin.email.clone(), "custom".to_owned());
        assert_eq!(entries(&msp_id, &acme, &conn).await, [added("admin"), changed.clone()]);
        assert_eq!(entries(&msp_id, &baker, &conn).await, [added("custom")]);

        // Back to Baker only: Acme loses them.
        let only_baker = TechnicianAccess {
            all_clients: false,
            clients: vec![baker.uuid.clone()],
            ..Default::default()
        };
        staff.set_access(&only_baker, &conn).await.unwrap();
        sync_by(&msp_admin, &staff, &conn).await;
        let removed = ("client_staff_removed".to_owned(), tech.email.clone(), msp_admin.email.clone(), String::new());
        assert_eq!(entries(&msp_id, &acme, &conn).await, [added("admin"), changed, removed]);
        let baker_entries = entries(&msp_id, &baker, &conn).await;
        assert_eq!(baker_entries.len(), 2, "{baker_entries:?}");
        assert_eq!(baker_entries[1].0, "client_staff_role_changed");
        assert_eq!(baker_entries[1].3, "admin");

        // None of it is in the MSP's own Activity, which has its own entries.
        assert!(MspEvent::find_by_msp(&msp_id, None, None, Vec::new(), 100, &conn).await.is_empty());
    }

    #[test]
    fn every_entry_only_for_a_client_is_one_a_client_sees() {
        for kind in crate::db::models::CLIENT_ONLY_EVENTS {
            assert!(CLIENT_KINDS.contains(kind), "{kind}");
        }
    }
}

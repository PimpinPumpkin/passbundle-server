// Keykeeper: item templates an MSP sends to its clients. A template is an
// encrypted item, so the console does the sending: it writes a copy into each
// client's Templates collection, encrypted with that client's key. The server
// only records which item is the source, which clients get it, each client's
// copy, and the version of the source each copy was made from, so the console
// can tell which clients are behind. It never sees a template's name or
// fields. A client's own members get its Templates collection, read-only, so
// they can use the templates. See DESIGN.md, "MSP templates".

use std::collections::HashSet;

use chrono::Utc;
use rocket::{Route, serde::json::Json};

use crate::{
    api::{EmptyResult, JsonResult},
    auth::Headers,
    db::{
        DbConn,
        models::{
            Cipher, CipherId, Collection, CollectionId, CollectionUser, Membership, MembershipStatus, MembershipType,
            MspClient, MspId, MspMembership, MspTemplate, MspTemplateCopy, OrganizationId,
        },
    },
};

use super::keykeeper_msp::{Audit, require_admin, staff_member};

pub fn routes() -> Vec<Route> {
    routes![get_templates, set_template, stop_template, record_copies, set_templates_collection]
}

/// Template ids are the ones custom templates get: letters, digits, and
/// dashes, as in a UUID.
fn check_template_id(template_id: &str) -> EmptyResult {
    if template_id.is_empty()
        || template_id.len() > 64
        || !template_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        err!("Invalid template id")
    }
    Ok(())
}

/// The MSP's client organizations.
async fn client_ids(msp_id: &MspId, conn: &DbConn) -> HashSet<OrganizationId> {
    MspClient::find_by_msp(msp_id, conn).await.into_iter().map(|c| c.org_uuid).collect()
}

/// Clients in a few words, for the audit log.
fn clients_phrase(count: usize) -> String {
    if count == 1 {
        "1 client".to_owned()
    } else {
        format!("{count} clients")
    }
}

/// The MSP's templates, which clients get each, and the copies and Templates
/// collections in the clients the caller reaches. A technician limited to
/// chosen clients sees only templates that reach them, and only their clients.
#[get("/keykeeper/msp/<msp_id>/templates")]
async fn get_templates(msp_id: MspId, headers: Headers, conn: DbConn) -> JsonResult {
    let caller = staff_member(&msp_id, &headers.user.uuid, &conn).await?;
    let reach = caller.reach(&conn).await;
    let reached = |org: &OrganizationId| reach.as_ref().is_none_or(|r| r.contains(org));

    let mut templates = Vec::new();
    for template in MspTemplate::find_by_msp(&msp_id, &conn).await {
        let chosen: Vec<OrganizationId> =
            template.chosen_clients(&conn).await.into_iter().filter(|org| reached(org)).collect();
        if !template.all_clients && chosen.is_empty() {
            continue;
        }
        templates.push(json!({
            "templateId": template.template_id,
            "sourceCipherId": template.source_cipher_uuid,
            "allClients": template.all_clients,
            "clients": chosen,
            "createdAt": crate::util::format_date(&template.created_at),
        }));
    }

    let mut copies = Vec::new();
    let mut collections = serde_json::Map::new();
    for client in MspClient::find_by_msp(&msp_id, &conn).await {
        if !reached(&client.org_uuid) {
            continue;
        }
        for copy in MspTemplateCopy::find_by_org(&client.org_uuid, &conn).await {
            copies.push(json!({
                "organizationId": copy.org_uuid,
                "templateId": copy.template_id,
                "cipherId": copy.cipher_uuid,
                "sourceRevision": copy.source_revision,
            }));
        }
        collections.insert(client.org_uuid.to_string(), json!(client.templates_collection));
    }

    Ok(Json(json!({
        "templates": templates,
        "copies": copies,
        "collections": collections,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TemplateData {
    source_cipher_id: CipherId,
    all_clients: bool,
    #[serde(default)]
    clients: Vec<OrganizationId>,
}

/// Adds a template, or changes its source or which clients get it. The source
/// must be an item the caller can see, and not one of the MSP's clients'
/// copies.
#[put("/keykeeper/msp/<msp_id>/templates/<template_id>", data = "<data>")]
async fn set_template(
    msp_id: MspId,
    template_id: &str,
    headers: Headers,
    data: Json<TemplateData>,
    conn: DbConn,
) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    check_template_id(template_id)?;
    let data = data.into_inner();
    let ours = client_ids(&msp_id, &conn).await;

    let source = match Cipher::find_by_uuid(&data.source_cipher_id, &conn).await {
        Some(c) if c.deleted_at.is_none() && c.is_accessible_to_user(&headers.user.uuid, &conn).await => c,
        _ => err!("Template not found"),
    };
    if source.organization_uuid.as_ref().is_some_and(|org| ours.contains(org)) {
        err!("That's a copy in one of your clients. Choose the original template.")
    }

    let mut clients = Vec::new();
    if !data.all_clients {
        let mut seen = HashSet::new();
        for org in data.clients {
            if !ours.contains(&org) {
                err!("Client not found")
            }
            if seen.insert(org.clone()) {
                clients.push(org);
            }
        }
        if clients.is_empty() {
            err!("Choose at least one client")
        }
    }

    let existing = MspTemplate::find(&msp_id, template_id, &conn).await;
    let template = MspTemplate {
        msp_uuid: msp_id.clone(),
        template_id: template_id.to_owned(),
        source_cipher_uuid: source.uuid.clone(),
        all_clients: data.all_clients,
        created_at: existing.as_ref().map_or_else(|| Utc::now().naive_utc(), |t| t.created_at),
    };
    template.save(&clients, &conn).await?;

    let target = if template.all_clients {
        "every client".to_owned()
    } else {
        clients_phrase(clients.len())
    };
    Audit::by(
        if existing.is_some() {
            "template_changed"
        } else {
            "template_added"
        },
        &headers,
    )
    .detail(format!("{template_id}:{target}"))
    .record(&msp_id, &conn)
    .await?;

    Ok(Json(json!({ "templateId": template.template_id, "allClients": template.all_clients, "clients": clients })))
}

/// Stops sending a template. Its copies stay in the clients unless the console
/// removed them first.
#[delete("/keykeeper/msp/<msp_id>/templates/<template_id>")]
async fn stop_template(msp_id: MspId, template_id: &str, headers: Headers, conn: DbConn) -> EmptyResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let Some(template) = MspTemplate::find(&msp_id, template_id, &conn).await else {
        err_code!("Template not found", rocket::http::Status::NotFound.code)
    };
    template.delete(client_ids(&msp_id, &conn).await.into_iter().collect(), &conn).await?;
    Audit::by("template_stopped", &headers).detail(template_id).record(&msp_id, &conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CopyData {
    organization_id: OrganizationId,
    cipher_id: CipherId,
    source_revision: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CopiesData {
    copies: Vec<CopyData>,
}

/// Records the copies the console wrote: each must be an item in that client,
/// one of the MSP's. Nothing is recorded unless all of them check out.
#[post("/keykeeper/msp/<msp_id>/templates/<template_id>/copies", data = "<data>")]
async fn record_copies(
    msp_id: MspId,
    template_id: &str,
    headers: Headers,
    data: Json<CopiesData>,
    conn: DbConn,
) -> EmptyResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    if MspTemplate::find(&msp_id, template_id, &conn).await.is_none() {
        err_code!("Template not found", rocket::http::Status::NotFound.code)
    }
    let ours = client_ids(&msp_id, &conn).await;
    let copies = data.into_inner().copies;
    if copies.is_empty() {
        err!("No copies to record")
    }
    let mut seen = HashSet::new();
    for copy in &copies {
        if !ours.contains(&copy.organization_id) || !seen.insert(copy.organization_id.clone()) {
            err!("Client not found")
        }
        let in_client = Cipher::find_by_uuid_and_org(&copy.cipher_id, &copy.organization_id, &conn)
            .await
            .is_some_and(|c| c.deleted_at.is_none());
        if !in_client {
            err!("Copy not found")
        }
        if copy.source_revision.is_empty() || copy.source_revision.len() > 64 {
            err!("Invalid source revision")
        }
    }
    for copy in &copies {
        MspTemplateCopy {
            org_uuid: copy.organization_id.clone(),
            template_id: template_id.to_owned(),
            cipher_uuid: copy.cipher_id.clone(),
            source_revision: copy.source_revision.clone(),
        }
        .save(&conn)
        .await?;
    }

    let mut audit =
        Audit::by("template_sent", &headers).detail(format!("{template_id}:{}", clients_phrase(copies.len())));
    let only = (copies.len() == 1).then(|| copies[0].organization_id.clone());
    let name = match &only {
        Some(org) => crate::db::models::Organization::find_by_uuid(org, &conn).await.map(|o| o.name),
        None => None,
    };
    if let (Some(org), Some(name)) = (&only, &name) {
        audit = audit.org(org, name);
    }
    audit.record(&msp_id, &conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionData {
    collection_id: CollectionId,
}

/// Records the client's Templates collection, which the console creates the
/// first time it sends that client a template.
#[put("/keykeeper/msp/<msp_id>/clients/<org_id>/templates-collection", data = "<data>")]
async fn set_templates_collection(
    msp_id: MspId,
    org_id: OrganizationId,
    headers: Headers,
    data: Json<CollectionData>,
    conn: DbConn,
) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let mut client = match MspClient::find_by_org(&org_id, &conn).await {
        Some(c) if c.msp_uuid == msp_id => c,
        _ => err!("Client not found"),
    };
    let collection_id = data.into_inner().collection_id;
    let Some(collection) = Collection::find_by_uuid_and_org(&collection_id, &org_id, &conn).await else {
        err!("Collection not found")
    };
    // Set once: every regular member of the client gets to read it, so it
    // can't later be pointed at a collection they shouldn't see.
    if client.templates_collection.as_ref().is_some_and(|c| c != &collection_id) {
        err!("This client already has its Templates collection")
    }
    client.set_templates_collection(collection_id.clone(), &conn).await?;
    let org_name =
        crate::db::models::Organization::find_by_uuid(&org_id, &conn).await.map(|o| o.name).unwrap_or_default();
    Audit::by("templates_collection_set", &headers)
        .org(&org_id, &org_name)
        .detail(collection.uuid.to_string())
        .record(&msp_id, &conn)
        .await?;
    for member in Membership::find_by_org(&org_id, &conn).await {
        give_templates(&member, &client, &conn).await?;
    }
    Ok(Json(json!({ "collectionId": collection_id })))
}

/// Gives one of a client's own members its Templates collection, read-only:
/// they use the templates, and the MSP keeps them. Owners and admins see every
/// collection already, the MSP's people reach it through the MSP, and a member
/// who already has the collection keeps what they have, such as edit access an
/// admin gave them.
pub async fn give_templates(member: &Membership, client: &MspClient, conn: &DbConn) -> EmptyResult {
    let Some(collection) = &client.templates_collection else {
        return Ok(());
    };
    // Members still joining get it when they're confirmed.
    if member.status != MembershipStatus::Confirmed as i32
        || member.atype >= MembershipType::Admin
        || member.access_all
        || MspMembership::find_by_membership(&member.uuid, conn).await.is_some()
        || CollectionUser::find_by_collection_and_user(collection, &member.user_uuid, conn).await.is_some()
    {
        return Ok(());
    }
    CollectionUser::save(&member.user_uuid, collection, true, false, false, conn).await
}

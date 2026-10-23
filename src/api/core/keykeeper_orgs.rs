// Keykeeper: a company's own organization, set up without an MSP. "New
// organization" can start one with the Business preset, which an MSP's client
// gets from the MSP's default policies: account recovery, single
// organization, master password requirements, and the Everyone and Admins
// collections, plus an install command for rolling it out. All in one call, so
// a closed browser tab can't leave it half set up. See DESIGN.md, "A company's
// own IT".

use rocket::{Route, serde::json::Json};

use super::{keykeeper_msp, keykeeper_msp_policies};
use crate::{
    CONFIG,
    api::JsonResult,
    auth::Headers,
    db::{
        DbConn,
        models::{
            Collection, Membership, MembershipStatus, MembershipType, OrgPolicy, OrgPolicyType, OrgSetup, Organization,
        },
    },
};

pub fn routes() -> Vec<Route> {
    routes![create_organization]
}

const BUSINESS_PRESET: &str = "business";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgKeys {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateOrgData {
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
    keys: OrgKeys,
}

/// Creates an organization owned by the caller, as upstream's does, with the
/// Business preset when asked for.
#[post("/keykeeper/organizations", data = "<data>")]
async fn create_organization(headers: Headers, data: Json<CreateOrgData>, conn: DbConn) -> JsonResult {
    // Upstream's own checks for creating an organization.
    if !CONFIG.is_org_creation_allowed(&headers.user.email) {
        err!("User not allowed to create organizations")
    }
    if OrgPolicy::is_applicable_to_user(&headers.user.uuid, OrgPolicyType::SingleOrg, None, &conn).await {
        err!(
            "You may not create an organization. You belong to an organization which has a policy that prohibits you from being a member of any other organization."
        )
    }

    let data = data.into_inner();
    let name = keykeeper_msp::clean_name(&data.name)?;
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
    if business {
        if let Some(admins) = admins_collection {
            Collection::new(org.uuid.clone(), admins, None).save(&conn).await?;
        }
        keykeeper_msp_policies::apply_business_preset(&org.uuid, &headers, &conn).await?;
        OrgSetup::new(org.uuid.clone(), Some(BUSINESS_PRESET.to_owned()), Some(collection.uuid.clone()), true)
            .insert(&conn)
            .await?;
    }
    Ok(Json(org.to_json()))
}

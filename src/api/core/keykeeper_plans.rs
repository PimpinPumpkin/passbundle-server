// Keykeeper: what a signed-in person may ask about a plan (DESIGN.md, "Plans
// and billing", in the meta repo). One route, and it only reads: no request
// from a signed-in person, an owner, or an admin ever writes a plan. Plans
// are written by the operator, through the admin page (`src/api/admin.rs`).

use chrono::Utc;
use rocket::{Route, http::Status, serde::json::Json};

use crate::{
    CONFIG,
    api::{JsonResult, Notify, UpdateType},
    auth::Headers,
    db::{
        DbConn,
        models::{PlanOwner, Terms, User, may_manage_plan, not_enforced_json, people_a_plan_reaches, plan_at},
    },
};

pub fn routes() -> Vec<Route> {
    routes![get_plan]
}

/// What the sync carries as `keykeeperPlan`, freshly worked out.
///
/// - With no query, the caller's own plan.
/// - With `organization` or `msp`, that organization's plan or that MSP's
///   pool, for the people who may manage it: the organization's owners, or
///   the MSP's admins (who also manage what covers each of their clients).
///   Everyone else gets 404, the same answer as for an id that doesn't
///   exist, and never 403, which would sign the web vault out.
///
/// Who may manage a plan is decided in one place, `may_manage` in
/// `src/db/models/keykeeper_plans.rs`, and it's checked before anything about
/// the plan is read.
#[get("/keykeeper/plan?<organization>&<msp>")]
async fn get_plan(organization: Option<String>, msp: Option<String>, headers: Headers, conn: DbConn) -> JsonResult {
    let asker = &headers.user.uuid;
    let whose = match (organization, msp) {
        (None, None) => PlanOwner::User(asker.clone()),
        (Some(id), None) => PlanOwner::Organization(id.into()),
        (None, Some(id)) => PlanOwner::Msp(id.into()),
        (Some(_), Some(_)) => err!("Ask about an organization or an MSP, not both"),
    };
    if !may_manage_plan(asker, &whose, &conn).await? {
        err_code!("Plan not found", Status::NotFound.code)
    }
    if !CONFIG.plans_enforced() {
        return Ok(Json(not_enforced_json()));
    }
    let plan = plan_at(&whose, Some(asker), Utc::now().naive_utc(), &conn).await?;
    Ok(Json(plan.to_json(&Terms::from_config())))
}

/// When a plan changes, the people it reaches are sent the sync notice
/// clients already act on, so the change shows within seconds on a device
/// that's open. A device that misses it learns at its next sync. Where plans
/// aren't enforced a plan changes nothing anyone sees, so nobody is told.
pub async fn plan_changed(whose: &PlanOwner, conn: &DbConn, nt: Notify<'_>) {
    if !CONFIG.plans_enforced() {
        return;
    }
    let people = match people_a_plan_reaches(whose, conn).await {
        Ok(people) => people,
        Err(e) => {
            warn!("Couldn't tell people that the plan of {whose} changed: {e:#?}");
            return;
        }
    };
    for uuid in people {
        User::update_uuid_revision(&uuid, conn).await;
        if let Some(user) = User::find_by_uuid(&uuid, conn).await {
            nt.send_user_update(UpdateType::SyncVault, &user, None, conn).await;
        }
    }
}

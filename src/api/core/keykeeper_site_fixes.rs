// Keykeeper: site fixes and problem reports from the extension, for people
// who chose to share, and MSPs' site rules. A fix applies to everyone on the
// server once SITE_FIX_REPORTERS different people sent it; an MSP's admin can
// apply one to every client at once. Apps download the whole list and match
// it on the device, so asking doesn't say which sites someone visits. See
// DESIGN.md, "Site fixes (opt-in)".

use std::collections::HashSet;

use rocket::{Route, serde::json::Json};
use serde_json::{Value, json};

use super::keykeeper_msp::{Audit, require_admin};
use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult},
    auth::Headers,
    db::{
        DbConn,
        models::{
            Fix, FixField, Membership, MspClient, MspId, MspSiteFixReport, MspSiteRule, MspStaff, ProblemField,
            SiteFix, SiteProblem,
        },
    },
};

pub fn routes() -> Vec<Route> {
    routes![share_fix, list_fixes, report_problem, get_msp_site_fixes, add_msp_site_rule, remove_msp_site_rule]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixData {
    host: String,
    field: FixField,
    fill: String,
}

impl FixData {
    fn checked(&self) -> Result<Fix, crate::error::Error> {
        Fix::checked(&self.host, &self.field, &self.fill).map_err(crate::error::Error::new_msg)
    }
}

/// Someone shares a fix they made with the fill picker. Counted once per
/// person; their MSPs' consoles see it with who sent it.
#[post("/keykeeper/site-fixes", data = "<data>")]
async fn share_fix(data: Json<FixData>, headers: Headers, conn: DbConn) -> JsonResult {
    let fix = data.checked()?;
    let reporters = SiteFix::record(&fix, &headers.user.uuid, &conn).await?;
    for staff in MspStaff::find_by_user(&headers.user.uuid, &conn).await {
        MspSiteFixReport::record(&staff.msp_uuid, &fix, &headers.user.email, &conn).await?;
    }
    let threshold = i32::try_from(CONFIG.site_fix_reporters()).unwrap_or(i32::MAX);
    Ok(Json(json!({ "applies": reporters >= threshold })))
}

/// The MSPs whose site rules reach someone: the ones they're staff of, and
/// the ones that run an organization they're a member of.
async fn msps_of(headers: &Headers, conn: &DbConn) -> Vec<MspId> {
    let mut msps: Vec<MspId> = Vec::new();
    for staff in MspStaff::find_by_user(&headers.user.uuid, conn).await {
        msps.push(staff.msp_uuid);
    }
    for member in Membership::find_confirmed_by_user(&headers.user.uuid, conn).await {
        if let Some(client) = MspClient::find_by_org(&member.org_uuid, conn).await {
            msps.push(client.msp_uuid);
        }
    }
    let mut seen = HashSet::new();
    msps.retain(|m| seen.insert(m.clone()));
    msps
}

/// Every fix that applies to the caller: the ones enough people sent, and
/// their MSPs' rules. The whole list, to match on the device.
#[get("/keykeeper/site-fixes")]
async fn list_fixes(headers: Headers, conn: DbConn) -> Json<Value> {
    let threshold = i32::try_from(CONFIG.site_fix_reporters()).unwrap_or(i32::MAX);
    let confirmed: Vec<Value> = SiteFix::confirmed(threshold, &conn).await.iter().map(Fix::to_json).collect();
    let mut rules = Vec::new();
    for msp in msps_of(&headers, &conn).await {
        rules.extend(MspSiteRule::find_by_msp(&msp, &conn).await.iter().map(|r| r.fix().to_json()));
    }
    Json(json!({ "fixes": confirmed, "rules": rules }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProblemData {
    host: String,
    #[serde(default)]
    fields: Vec<ProblemField>,
    note: Option<String>,
}

/// "Report a problem with this site": the host and the shape of its sign-in
/// fields, with an optional note. Kept without an account.
#[post("/keykeeper/site-problems", data = "<data>")]
async fn report_problem(data: Json<ProblemData>, _headers: Headers, conn: DbConn) -> JsonResult {
    let data = data.into_inner();
    let report =
        SiteProblem::checked(&data.host, &data.fields, data.note.as_deref()).map_err(crate::error::Error::new_msg)?;
    let kept = report.save(&conn).await?;
    Ok(Json(json!({ "kept": kept })))
}

/// An MSP's site rules and the fixes its staff shared. MSP admins.
#[get("/keykeeper/msp/<msp_id>/site-fixes")]
async fn get_msp_site_fixes(msp_id: MspId, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let rules: Vec<Value> = MspSiteRule::find_by_msp(&msp_id, &conn).await.iter().map(MspSiteRule::to_json).collect();
    Ok(Json(json!({ "rules": rules, "shared": MspSiteFixReport::find_by_msp(&msp_id, &conn).await })))
}

/// Applies a fix to every client of the MSP at once. MSP admins.
#[post("/keykeeper/msp/<msp_id>/site-rules", data = "<data>")]
async fn add_msp_site_rule(msp_id: MspId, data: Json<FixData>, headers: Headers, conn: DbConn) -> JsonResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let fix = data.checked()?;
    let rule = MspSiteRule::add(&msp_id, &fix, &conn).await?;
    Audit::by("site_rule_added", &headers).detail(describe(&fix)).record(&msp_id, &conn).await?;
    Ok(Json(rule.to_json()))
}

#[delete("/keykeeper/msp/<msp_id>/site-rules/<rule_id>")]
async fn remove_msp_site_rule(msp_id: MspId, rule_id: &str, headers: Headers, conn: DbConn) -> EmptyResult {
    require_admin(&msp_id, &headers.user.uuid, &conn).await?;
    let Some(rule) = MspSiteRule::find(&msp_id, rule_id, &conn).await else {
        err_code!("Site rule not found", rocket::http::Status::NotFound.code)
    };
    let detail = describe(&rule.fix());
    rule.delete(&conn).await?;
    Audit::by("site_rule_removed", &headers).detail(detail).record(&msp_id, &conn).await
}

/// A fix in a few words, for the MSP's activity log.
fn describe(fix: &Fix) -> String {
    let field = [&fix.field.id, &fix.field.name, &fix.field.label]
        .into_iter()
        .find(|p| !p.is_empty())
        .cloned()
        .unwrap_or_default();
    format!("{} {} {}", fix.host, field, fix.fill)
}

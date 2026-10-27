// Keykeeper: provisioning from Microsoft Entra ID, or any SCIM 2.0 client
// (RFC 7643, RFC 7644, and Microsoft's public documentation for SCIM
// endpoints). Mounted at /scim, outside /api: these requests carry no user
// session, only an organization's provisioning token, and every one is scoped
// to the organization in its URL, /scim/v2/<organization id>/....
//
// What the directory can do here: invite people as regular members, turn
// regular members off (revoke) and back on, remove them, and keep the members
// of groups it made in step. It never gets or gives a key, never sees a vault
// item, and never changes owners, admins, custom roles, anyone with access to
// every item, or an MSP's staff. See DESIGN.md, "Provisioning from Entra ID",
// in the meta repo.

pub mod filter;
pub mod patch;

use std::{
    net::IpAddr,
    num::NonZeroU32,
    sync::{
        LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use chrono::Utc;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use rocket::{
    Catcher, Request, Response, Route,
    data::{Data, ToByteUnit},
    http::{ContentType, Header, Status},
    request::{FromRequest, Outcome},
    response::{self, Responder},
};
use serde_json::{Map, Value, json};

use self::{
    filter::{ENTERPRISE_USER_SCHEMA, Filter, GROUP_SCHEMA, USER_SCHEMA, get_key},
    patch::{Kind, Refusal, as_bool, without_nulls},
};
use super::events::log_scim_event;
use crate::{
    CONFIG,
    api::{Notify, UpdateType},
    auth::ClientIp,
    db::{
        DbConn,
        models::{
            Collection, CollectionUser, EventType, Group, GroupId, GroupUser, Invitation, JoinSeal, Membership,
            MembershipId, MembershipStatus, MspClient, OrgPolicy, OrgSetup, Organization, OrganizationId, ScimGroup,
            ScimPerson, ScimToken, ScimUser, SealKind, User, invite_hours, looks_like_scim_token, remove_group_member,
        },
    },
    mail,
    util::format_date,
};

pub fn routes() -> Vec<Route> {
    routes![list, get_one, create, replace, update, remove]
}

pub fn catchers() -> Vec<Catcher> {
    catchers![refused]
}

const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
/// A page of results: 100 unless the directory asks for fewer, at most 200.
const DEFAULT_COUNT: usize = 100;
const MAX_COUNT: usize = 200;
/// A request body, and what's kept of a person's attributes.
const MAX_BODY_MIB: u64 = 1;
const MAX_ATTRIBUTES: usize = 16 * 1024;
const MAX_NAME: usize = 256;
/// Group names, as upstream's groups table allows.
const MAX_GROUP_NAME: usize = 100;

/// Requests per organization's token a minute, people invited a minute and a
/// day (each sends an email, so a stolen token can't make the server a source
/// of spam), and refused tokens per address a minute.
const REQUESTS_PER_MINUTE: u32 = 600;
const CREATES_PER_MINUTE: u32 = 200;
const CREATES_PER_DAY: u32 = 2000;
const FAILURES_PER_MINUTE: u32 = 60;

type Limiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

fn limiter(per_minute: u32) -> Limiter {
    RateLimiter::keyed(Quota::per_minute(NonZeroU32::new(per_minute).expect("A non-zero limit")))
}

static REQUESTS: LazyLock<Limiter> = LazyLock::new(|| limiter(REQUESTS_PER_MINUTE));
static CREATES: LazyLock<Limiter> = LazyLock::new(|| limiter(CREATES_PER_MINUTE));
/// A day's invitations at once, refilling evenly over the day.
static CREATES_TODAY: LazyLock<Limiter> = LazyLock::new(|| {
    let period = std::time::Duration::from_secs(86_400 / u64::from(CREATES_PER_DAY));
    RateLimiter::keyed(
        Quota::with_period(period)
            .expect("A non-zero period")
            .allow_burst(NonZeroU32::new(CREATES_PER_DAY).expect("A non-zero limit")),
    )
});
static FAILURES: LazyLock<Limiter> = LazyLock::new(|| limiter(FAILURES_PER_MINUTE));

/// How many requests the limiters have seen, and how often they forget keys
/// whose limits have filled back up. Refused tokens are keyed by address, so
/// without this, requests from many addresses would grow it without bound.
static CHECKS: AtomicUsize = AtomicUsize::new(0);
const PRUNE_EVERY: usize = 1024;

/// Every `every` calls, forgets the keys whose limits have filled back up, as
/// the login limiters do (src/ratelimit.rs). Returns whether it did.
fn prune_now_and_then(checks: &AtomicUsize, every: usize, limiters: &[&Limiter]) -> bool {
    if checks.fetch_add(1, Ordering::Relaxed) % every != every - 1 {
        return false;
    }
    for limiter in limiters {
        limiter.retain_recent();
        limiter.shrink_to_fit();
    }
    true
}

fn scim_json() -> ContentType {
    ContentType::new("application", "scim+json")
}

/// A SCIM error (RFC 7644, section 3.12): the status as a string, a
/// `scimType` where one applies, and a sentence for whoever reads the
/// directory's provisioning log.
#[derive(Debug)]
pub struct ScimError {
    status: Status,
    scim_type: Option<&'static str>,
    detail: String,
}

impl ScimError {
    fn new(status: Status, scim_type: Option<&'static str>, detail: impl Into<String>) -> Self {
        Self {
            status,
            scim_type,
            detail: detail.into(),
        }
    }

    fn bad(scim_type: &'static str, detail: impl Into<String>) -> Self {
        Self::new(Status::BadRequest, Some(scim_type), detail)
    }

    fn not_found(what: &str) -> Self {
        Self::new(Status::NotFound, None, format!("{what} not found"))
    }

    fn conflict(detail: impl Into<String>) -> Self {
        Self::new(Status::Conflict, Some("uniqueness"), detail)
    }

    fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(Status::Forbidden, None, detail)
    }
}

impl From<Refusal> for ScimError {
    fn from(r: Refusal) -> Self {
        Self::bad(r.scim_type, r.detail)
    }
}

/// A database or mail failure: logged here, and said plainly to the
/// directory, which tries again later.
impl From<crate::error::Error> for ScimError {
    fn from(e: crate::error::Error) -> Self {
        error!("Provisioning request failed: {e:?}");
        Self::new(Status::InternalServerError, None, "PassBundle couldn't finish that; it will be tried again")
    }
}

fn respond(status: Status, body: Option<&Value>, location: Option<String>, retry_after: bool) -> Response<'static> {
    let mut response = Response::build();
    response.status(status);
    if let Some(body) = body {
        let text = body.to_string();
        response.header(scim_json()).sized_body(text.len(), std::io::Cursor::new(text));
    }
    if let Some(location) = location {
        response.header(Header::new("Location", location));
    }
    if retry_after {
        response.header(Header::new("Retry-After", "60"));
    }
    if status == Status::Unauthorized {
        response.header(Header::new("WWW-Authenticate", "Bearer"));
    }
    response.finalize()
}

impl<'r> Responder<'r, 'static> for ScimError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let mut body = json!({
            "schemas": [ERROR_SCHEMA],
            "status": self.status.code.to_string(),
            "detail": self.detail,
        });
        if let Some(scim_type) = self.scim_type {
            body["scimType"] = json!(scim_type);
        }
        Ok(respond(self.status, Some(&body), None, self.status == Status::TooManyRequests))
    }
}

/// A SCIM answer: a status, maybe a resource, and where a new one lives.
pub struct ScimResponse {
    status: Status,
    body: Option<Value>,
    location: Option<String>,
}

impl ScimResponse {
    fn ok(body: Value) -> Self {
        Self {
            status: Status::Ok,
            body: Some(body),
            location: None,
        }
    }

    fn no_content() -> Self {
        Self {
            status: Status::NoContent,
            body: None,
            location: None,
        }
    }

    fn created(body: Value) -> Self {
        let location = body["meta"]["location"].as_str().map(str::to_owned);
        Self {
            status: Status::Created,
            body: Some(body),
            location,
        }
    }
}

impl<'r> Responder<'r, 'static> for ScimResponse {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        Ok(respond(self.status, self.body.as_ref(), self.location, false))
    }
}

type ScimResult = Result<ScimResponse, ScimError>;

/// Whatever went wrong before a route ran (no token, a refused token, too many
/// requests, a path that isn't one), as a SCIM error. The same 401 for every
/// token problem, so the answer never says whether an organization exists.
#[catch(default)]
fn refused(status: Status, _: &Request<'_>) -> ScimError {
    let detail = match status.code {
        401 => {
            "That provisioning token doesn't work for this organization. Make a new one on its Provisioning page in PassBundle."
        }
        429 => "Too many requests; try again in a minute.",
        404 => "Not found",
        413 => "The request is too large",
        _ => "The request couldn't be handled",
    };
    ScimError::new(status, None, detail)
}

/// A request from the directory: its organization's token was presented,
/// matched in constant time, and is within its limits. Every request is
/// scoped to that one organization: the one in the URL, whose token it is.
pub struct ScimCaller {
    org: Organization,
    ip: IpAddr,
    /// This organization's SCIM URL, for resources' `meta.location`.
    base: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ScimCaller {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let ip = match ClientIp::from_request(request).await {
            Outcome::Success(client) => client.ip,
            _ => return Outcome::Error((Status::BadRequest, "No client address")),
        };
        prune_now_and_then(&CHECKS, PRUNE_EVERY, &[&*FAILURES, &*REQUESTS, &*CREATES, &*CREATES_TODAY]);
        let refused = || {
            if FAILURES.check_key(&ip.to_string()).is_err() {
                Outcome::Error((Status::TooManyRequests, "Too many refused tokens"))
            } else {
                Outcome::Error((Status::Unauthorized, "That token doesn't work here"))
            }
        };
        // The organization in the URL picks the token: a token never reaches
        // another organization's data, whatever it is.
        let Some(org_id) = request.routed_segment(1).filter(|s| uuid::Uuid::parse_str(s).is_ok()) else {
            return refused();
        };
        let org_id = OrganizationId::from(org_id.to_owned());
        let presented = request.headers().get_one("Authorization").and_then(|value| {
            let (scheme, token) = value.trim().split_once(' ')?;
            scheme.eq_ignore_ascii_case("Bearer").then(|| token.trim())
        });
        let Some(presented) = presented.filter(|t| looks_like_scim_token(t)) else {
            return refused();
        };
        let Outcome::Success(conn) = DbConn::from_request(request).await else {
            return Outcome::Error((Status::ServiceUnavailable, "No database"));
        };
        // With or without a token for this organization, the same work: a
        // hash and a constant-time compare, so timing doesn't say which.
        let Some(token) = ScimToken::find(&org_id, &conn).await else {
            ScimToken::matches_none(presented);
            return refused();
        };
        if !token.matches(presented) {
            return refused();
        }
        if REQUESTS.check_key(org_id.as_ref()).is_err() {
            return Outcome::Error((Status::TooManyRequests, "Too many requests"));
        }
        let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
            return refused();
        };
        // Keykeeper: a token works only while whoever made it still manages
        // the organization, checked on every request (DESIGN.md, "Offboarding").
        if !super::keykeeper_provisioning::token_maker_has_access(&token, &conn).await {
            return refused();
        }
        if let Err(e) = token.mark_used(&ip.to_string(), &conn).await {
            warn!("Couldn't record a provisioning request: {e:?}");
        }
        let base = format!("{}/scim/v2/{}", CONFIG.domain(), org.uuid);
        Outcome::Success(Self {
            org,
            ip,
            base,
        })
    }
}

/// The query parameters a list takes, read without regard to their case.
/// Others, such as Entra's `aadOptscim062020`, are ignored.
#[derive(Default)]
pub struct ScimQuery {
    filter: Option<String>,
    start_index: Option<i64>,
    count: Option<i64>,
    attributes: Vec<String>,
    excluded: Vec<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ScimQuery {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let mut query = Self::default();
        let Some(raw) = request.uri().query() else {
            return Outcome::Success(query);
        };
        let list = |v: &str| v.split(',').map(|a| a.trim().to_owned()).filter(|a| !a.is_empty()).collect();
        for (key, value) in url::form_urlencoded::parse(raw.as_str().as_bytes()) {
            match key.to_ascii_lowercase().as_str() {
                "filter" => query.filter = Some(value.into_owned()),
                "startindex" => match value.trim().parse() {
                    Ok(n) => query.start_index = Some(n),
                    Err(_) => return Outcome::Error((Status::BadRequest, "startIndex is a number")),
                },
                "count" => match value.trim().parse() {
                    Ok(n) => query.count = Some(n),
                    Err(_) => return Outcome::Error((Status::BadRequest, "count is a number")),
                },
                "attributes" => query.attributes = list(&value),
                "excludedattributes" => query.excluded = list(&value),
                _ => {}
            }
        }
        Outcome::Success(query)
    }
}

impl ScimQuery {
    fn filter(&self) -> Result<Option<Filter>, ScimError> {
        match &self.filter {
            None => Ok(None),
            Some(text) => filter::parse(text).map(Some).map_err(|e| ScimError::bad("invalidFilter", e)),
        }
    }

    /// Keeps only the asked-for attributes, or drops the excluded ones; `id`
    /// and `schemas` always stay.
    fn project(&self, resource: &mut Value) {
        let Some(object) = resource.as_object_mut() else {
            return;
        };
        let always = |k: &str| k == "id" || k == "schemas";
        // "name.givenName" keeps "name".
        let top = |a: &String| a.rsplit(':').next().unwrap_or(a).split('.').next().unwrap_or(a).to_owned();
        if !self.attributes.is_empty() {
            let keep: Vec<String> = self.attributes.iter().map(top).collect();
            object.retain(|k, _| always(k) || keep.iter().any(|a| a.eq_ignore_ascii_case(k)));
        }
        if !self.excluded.is_empty() {
            let drop: Vec<String> = self.excluded.iter().map(top).collect();
            object.retain(|k, _| always(k) || !drop.iter().any(|a| a.eq_ignore_ascii_case(k)));
        }
    }

    /// A ListResponse page (startIndex counts from 1; count 0 gives only the total).
    fn page(&self, mut resources: Vec<Value>) -> Value {
        let total = resources.len();
        let start = usize::try_from(self.start_index.unwrap_or(1).max(1)).unwrap_or(1);
        let count = self.count.map_or(DEFAULT_COUNT, |c| usize::try_from(c.max(0)).unwrap_or(0)).min(MAX_COUNT);
        let mut page: Vec<Value> = resources.drain(..).skip(start - 1).take(count).collect();
        for resource in &mut page {
            self.project(resource);
        }
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": page.len(),
            "Resources": page,
        })
    }
}

/// Which endpoint a request is for, from its path, in any case.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    Users,
    Groups,
    Schemas,
    ResourceTypes,
    ServiceProviderConfig,
}

impl Endpoint {
    fn parse(segment: &str) -> Result<Self, ScimError> {
        Ok(match segment.to_ascii_lowercase().as_str() {
            "users" => Self::Users,
            "groups" => Self::Groups,
            "schemas" => Self::Schemas,
            "resourcetypes" => Self::ResourceTypes,
            "serviceproviderconfig" | "serviceproviderconfigs" => Self::ServiceProviderConfig,
            _ => return Err(ScimError::not_found("That endpoint was")),
        })
    }
}

/// Reads a JSON body of at most 1 MiB.
async fn read_body(data: Data<'_>) -> Result<Value, ScimError> {
    let text = data
        .open(MAX_BODY_MIB.mebibytes())
        .into_string()
        .await
        .map_err(|_| ScimError::bad("invalidSyntax", "The request body couldn't be read"))?;
    if !text.is_complete() {
        return Err(ScimError::new(Status::PayloadTooLarge, None, "The request is larger than 1 MiB"));
    }
    serde_json::from_str(&text.into_inner()).map_err(|_| ScimError::bad("invalidSyntax", "The request body isn't JSON"))
}

fn groups_enabled() -> Result<(), ScimError> {
    if CONFIG.org_groups_enabled() {
        Ok(())
    } else {
        Err(ScimError::forbidden("Groups are turned off on this PassBundle server (ORG_GROUPS_ENABLED)"))
    }
}

#[get("/v2/<org_id>/<resource>")]
async fn list(org_id: &str, resource: &str, caller: ScimCaller, query: ScimQuery, conn: DbConn) -> ScimResult {
    let _ = org_id;
    match Endpoint::parse(resource)? {
        Endpoint::Users => list_users(&caller, &query, &conn).await,
        Endpoint::Groups => list_groups(&caller, &query, &conn).await,
        Endpoint::Schemas => Ok(ScimResponse::ok(query.page(schemas(&caller.base)))),
        Endpoint::ResourceTypes => Ok(ScimResponse::ok(query.page(resource_types(&caller.base)))),
        Endpoint::ServiceProviderConfig => Ok(ScimResponse::ok(service_provider_config(&caller.base))),
    }
}

#[get("/v2/<org_id>/<resource>/<id>")]
async fn get_one(
    org_id: &str,
    resource: &str,
    id: &str,
    caller: ScimCaller,
    query: ScimQuery,
    conn: DbConn,
) -> ScimResult {
    let _ = org_id;
    let mut found = match Endpoint::parse(resource)? {
        Endpoint::Users => user_json(&person(&caller, id, &conn).await?, &caller.base),
        Endpoint::Groups => {
            groups_enabled()?;
            let group = scim_group(&caller, id, &conn).await?;
            group_json(&group, Some(&group_members(&group, &conn).await), &caller.base)
        }
        Endpoint::Schemas => schemas(&caller.base)
            .into_iter()
            .find(|s| s["id"].as_str().is_some_and(|s| s.eq_ignore_ascii_case(id)))
            .ok_or_else(|| ScimError::not_found("That schema was"))?,
        Endpoint::ResourceTypes => resource_types(&caller.base)
            .into_iter()
            .find(|s| s["id"].as_str().is_some_and(|s| s.eq_ignore_ascii_case(id)))
            .ok_or_else(|| ScimError::not_found("That resource type was"))?,
        Endpoint::ServiceProviderConfig => return Err(ScimError::not_found("That endpoint was")),
    };
    query.project(&mut found);
    Ok(ScimResponse::ok(found))
}

#[post("/v2/<org_id>/<resource>", data = "<data>")]
async fn create(org_id: &str, resource: &str, data: Data<'_>, caller: ScimCaller, conn: DbConn) -> ScimResult {
    let _ = org_id;
    let resource = Endpoint::parse(resource)?;
    let body = read_body(data).await?;
    match resource {
        Endpoint::Users => create_user(&caller, body, &conn).await,
        Endpoint::Groups => create_group(&caller, body, &conn).await,
        _ => Err(ScimError::new(Status::MethodNotAllowed, None, "That endpoint is read-only")),
    }
}

#[put("/v2/<org_id>/<resource>/<id>", data = "<data>")]
async fn replace(
    org_id: &str,
    resource: &str,
    id: &str,
    data: Data<'_>,
    caller: ScimCaller,
    conn: DbConn,
) -> ScimResult {
    let _ = org_id;
    let resource = Endpoint::parse(resource)?;
    let body = read_body(data).await?;
    match resource {
        Endpoint::Users => put_user(&caller, id, body, &conn).await,
        Endpoint::Groups => put_group(&caller, id, body, &conn).await,
        _ => Err(ScimError::new(Status::MethodNotAllowed, None, "That endpoint is read-only")),
    }
}

#[patch("/v2/<org_id>/<resource>/<id>", data = "<data>")]
async fn update(
    org_id: &str,
    resource: &str,
    id: &str,
    data: Data<'_>,
    caller: ScimCaller,
    conn: DbConn,
) -> ScimResult {
    let _ = org_id;
    let resource = Endpoint::parse(resource)?;
    let body = read_body(data).await?;
    let operations = patch::parse_request(&body)?;
    match resource {
        Endpoint::Users => patch_user(&caller, id, &operations, &conn).await,
        Endpoint::Groups => patch_group(&caller, id, &operations, &conn).await,
        _ => Err(ScimError::new(Status::MethodNotAllowed, None, "That endpoint is read-only")),
    }
}

#[delete("/v2/<org_id>/<resource>/<id>")]
async fn remove(
    org_id: &str,
    resource: &str,
    id: &str,
    caller: ScimCaller,
    conn: DbConn,
    nt: Notify<'_>,
) -> ScimResult {
    let _ = org_id;
    match Endpoint::parse(resource)? {
        Endpoint::Users => delete_user(&caller, id, &conn, &nt).await,
        Endpoint::Groups => delete_group(&caller, id, &conn).await,
        _ => Err(ScimError::new(Status::MethodNotAllowed, None, "That endpoint is read-only")),
    }
}

// Users

/// Attributes the server keeps elsewhere, makes itself, or never keeps:
/// provisioning makes regular members only, so roles aren't kept, and a
/// password is never accepted.
const NOT_KEPT: &[&str] =
    &["id", "meta", "schemas", "userName", "externalId", "active", "password", "groups", "roles", "entitlements"];

const PROTECTED: &str = "PassBundle doesn't change owners, admins, custom roles, people who see every item, or your IT provider's staff from Microsoft Entra ID. An owner or admin can, in PassBundle; its Provisioning page lists who Entra turned off.";

fn date(at: &chrono::NaiveDateTime) -> String {
    format_date(at)
}

/// A member as a SCIM User: what the directory sent, as it sent it, with the
/// account's email where it sent none, and whether their membership is on.
fn user_json(person: &ScimPerson, base: &str) -> Value {
    let mut out = match &person.scim {
        Some(scim) => serde_json::from_str::<Map<String, Value>>(&scim.attributes).unwrap_or_default(),
        None => Map::new(),
    };
    let mut schemas = vec![json!(USER_SCHEMA)];
    for key in out.keys() {
        if key.len() > 4 && key[..4].eq_ignore_ascii_case("urn:") {
            schemas.push(json!(key));
        }
    }
    out.insert("schemas".into(), Value::Array(schemas));
    out.insert("id".into(), json!(person.member.uuid));
    match &person.scim {
        Some(scim) => {
            out.insert("userName".into(), json!(scim.user_name));
            if let Some(external_id) = &scim.external_id {
                out.insert("externalId".into(), json!(external_id));
            }
        }
        None => {
            out.insert("userName".into(), json!(person.user.email));
        }
    }
    if get_key(&Value::Object(out.clone()), "emails").is_none() {
        out.insert("emails".into(), json!([{ "value": person.user.email, "type": "work", "primary": true }]));
    }
    out.insert("active".into(), json!(person.member.status > MembershipStatus::Revoked as i32));
    let mut meta = json!({ "resourceType": "User", "location": format!("{base}/Users/{}", person.member.uuid) });
    if let Some(scim) = &person.scim {
        meta["created"] = json!(date(&scim.created_at));
        meta["lastModified"] = json!(date(&scim.updated_at));
    }
    out.insert("meta".into(), meta);
    Value::Object(out)
}

async fn person(caller: &ScimCaller, id: &str, conn: &DbConn) -> Result<ScimPerson, ScimError> {
    let member = Membership::find_by_uuid_and_org(&MembershipId::from(id.to_owned()), &caller.org.uuid, conn)
        .await
        .ok_or_else(|| ScimError::not_found("That user was"))?;
    ScimPerson::load(member, conn).await.ok_or_else(|| ScimError::not_found("That user was"))
}

async fn list_users(caller: &ScimCaller, query: &ScimQuery, conn: &DbConn) -> ScimResult {
    let filter = query.filter()?;
    let mut people = ScimPerson::load_org(&caller.org.uuid, conn).await;
    // Entra asks about one person at a time; narrow before checking it all.
    if let Some(f) = &filter {
        if let Some(name) = filter::required_equal(f, "userName") {
            let name = name.to_lowercase();
            people.retain(|p| match &p.scim {
                Some(s) => s.user_name_key == name,
                None => p.user.email == name,
            });
        } else if let Some(id) = filter::required_equal(f, "id") {
            people.retain(|p| *p.member.uuid == *id);
        }
    }
    let mut found = Vec::new();
    for p in &people {
        let user = user_json(p, &caller.base);
        if filter.as_ref().is_none_or(|f| filter::matches(f, &user)) {
            found.push(user);
        }
    }
    Ok(ScimResponse::ok(query.page(found)))
}

/// Whether text is an email address the server can invite.
fn email_address(text: &str) -> Option<String> {
    let text = text.trim();
    (text.len() <= 254 && text.parse::<lettre::Address>().is_ok()).then(|| text.to_lowercase())
}

/// Who to invite: the work email the directory sent (Entra's default maps
/// `mail` there), else the primary or first one, else the userName if it's an
/// email address (Entra's default maps the user principal name there).
fn invite_address(attributes: &Map<String, Value>, user_name: &str) -> Option<String> {
    let emails: Vec<&Value> = attributes
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("emails"))
        .and_then(|(_, v)| v.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let is = |e: &&Value, key: &str, want: &Value| {
        get_key(e, key).is_some_and(|v| match (v, want) {
            (Value::String(a), Value::String(b)) => a.eq_ignore_ascii_case(b),
            (a, b) => as_bool(a).is_some() && as_bool(a) == as_bool(b),
        })
    };
    let chosen = emails
        .iter()
        .find(|e| is(e, "type", &json!("work")))
        .or_else(|| emails.iter().find(|e| is(e, "primary", &json!(true))))
        .or_else(|| emails.first());
    chosen
        .and_then(|e| get_key(e, "value"))
        .and_then(Value::as_str)
        .and_then(email_address)
        .or_else(|| email_address(user_name))
}

/// A user resource the directory sent (a POST or PUT body, or the result of a
/// PATCH): its userName, externalId, active, and what's kept of the rest.
struct UserFields {
    user_name: String,
    external_id: Option<String>,
    active: Option<bool>,
    attributes: Map<String, Value>,
}

fn user_fields(mut resource: Map<String, Value>) -> Result<UserFields, ScimError> {
    without_nulls(&mut resource);
    let resource_value = Value::Object(resource.clone());
    let user_name = match get_key(&resource_value, "userName") {
        Some(Value::String(s)) if !s.trim().is_empty() && s.len() <= MAX_NAME => s.clone(),
        Some(Value::String(s)) if s.len() > MAX_NAME => {
            return Err(ScimError::bad("invalidValue", "userName is at most 256 characters"));
        }
        _ => return Err(ScimError::bad("invalidValue", "A user needs a userName")),
    };
    let external_id = match get_key(&resource_value, "externalId") {
        None => None,
        Some(Value::String(s)) if s.len() <= MAX_NAME => Some(s.clone()).filter(|s| !s.is_empty()),
        Some(_) => return Err(ScimError::bad("invalidValue", "externalId is a string of at most 256 characters")),
    };
    let active = match get_key(&resource_value, "active") {
        None => None,
        Some(v) => Some(as_bool(v).ok_or_else(|| ScimError::bad("invalidValue", "active is true or false"))?),
    };
    resource.retain(|k, _| !NOT_KEPT.iter().any(|n| n.eq_ignore_ascii_case(k)));
    if serde_json::to_string(&resource).map_or(0, |s| s.len()) > MAX_ATTRIBUTES {
        return Err(ScimError::bad("invalidValue", "A user's attributes are at most 16 KiB"));
    }
    Ok(UserFields {
        user_name,
        external_id,
        active,
        attributes: resource,
    })
}

fn keep(scim: &mut ScimUser, fields: &UserFields) {
    scim.set_user_name(&fields.user_name);
    scim.external_id.clone_from(&fields.external_id);
    scim.attributes = serde_json::to_string(&fields.attributes).unwrap_or_else(|_| "{}".into());
}

/// The collection everyone who joins gets (the Business preset's "Everyone"),
/// if the organization has one: an MSP's client's, or a company's own.
async fn everyone_collection(org: &OrganizationId, conn: &DbConn) -> Option<Collection> {
    let id = match MspClient::find_by_org(org, conn).await {
        Some(client) => client.everyone_collection,
        None => OrgSetup::find_by_org(org, conn).await.and_then(|s| s.everyone_collection),
    }?;
    Collection::find_by_uuid_and_org(&id, org, conn).await
}

/// Invites someone as a regular member, exactly as the Members page's invite
/// does on this server (its email, or without email, its no-mail rules), but
/// with no invitation seal: no owner's or admin's browser chose this address.
async fn invite(caller: &ScimCaller, email: &str, conn: &DbConn) -> Result<Membership, ScimError> {
    let org = &caller.org;
    let mut status = MembershipStatus::Invited as i32;
    let mut created = None;
    let user = match User::find_by_mail(email, conn).await {
        None => {
            if !CONFIG.invitations_allowed() {
                return Err(ScimError::forbidden("This PassBundle server doesn't allow invitations"));
            }
            if !CONFIG.is_email_domain_allowed(email) {
                return Err(ScimError::bad(
                    "invalidValue",
                    "This PassBundle server doesn't allow invitations to that email domain",
                ));
            }
            if !CONFIG.mail_enabled() {
                Invitation::new(email).save(conn).await?;
            }
            let mut user = User::new(email, None);
            user.save(conn).await?;
            created = Some(user.uuid.clone());
            user
        }
        Some(user) => {
            if !CONFIG.mail_enabled() {
                if user.password_hash.is_empty() {
                    Invitation::new(email).save(conn).await?;
                } else {
                    // Upstream's rule without email: an account joins at once,
                    // waiting for the organization's key.
                    status = MembershipStatus::Accepted as i32;
                }
            }
            user
        }
    };
    let mut member = Membership::new(user.uuid.clone(), org.uuid.clone(), None);
    member.status = status;
    member.save(conn).await?;
    // Joined at once without email, so not by them (two-step login for admins).
    if status == MembershipStatus::Accepted as i32 {
        crate::api::core::keykeeper_two_step::accepted_without_them(vec![member.uuid.clone()], conn).await?;
    }
    // No seal: an earlier one for this address never vouches for this.
    JoinSeal::set(&org.uuid, email, SealKind::Invite, None, conn).await?;
    if CONFIG.mail_enabled() {
        let hours = invite_hours(&org.uuid, conn).await;
        if let Err(e) = mail::send_invite(&user, org.uuid.clone(), member.uuid.clone(), &org.name, None, hours).await {
            error!("Couldn't send a provisioning invitation: {e:?}");
            if created.is_some() {
                user.delete(conn).await?;
            } else {
                member.delete(conn).await?;
            }
            return Err(ScimError::new(
                Status::InternalServerError,
                None,
                "PassBundle couldn't send the invitation email; it will be tried again",
            ));
        }
    }
    log_scim_event(EventType::OrganizationUserInvited, &member.uuid, &org.uuid, &caller.ip, conn).await;
    if let Some(collection) = everyone_collection(&org.uuid, conn).await
        // A grant there already stays as it is: Can edit would widen a
        // narrower one, as for joins with the install command.
        && CollectionUser::find_by_collection_and_user(&collection.uuid, &member.user_uuid, conn).await.is_none()
    {
        // Can edit, as a preset grant, as for people who join with the
        // install command (keykeeper_folder_permissions.rs).
        crate::db::models::keykeeper_folder_permissions::save_user(
            &member.user_uuid,
            &collection.uuid,
            &crate::db::models::keykeeper_folder_permissions::Grid::preset(false, false, false),
            conn,
        )
        .await?;
    }
    Ok(member)
}

async fn create_user(caller: &ScimCaller, body: Value, conn: &DbConn) -> ScimResult {
    let Value::Object(body) = body else {
        return Err(ScimError::bad("invalidSyntax", "A user is a JSON object"));
    };
    let fields = user_fields(body)?;
    let Some(email) = invite_address(&fields.attributes, &fields.user_name) else {
        return Err(ScimError::bad(
            "invalidValue",
            "PassBundle invites people by email: send a work email, or an email address as the userName",
        ));
    };
    let org = &caller.org.uuid;
    if ScimUser::find_by_user_name(org, &fields.user_name, conn).await.is_some() {
        return Err(ScimError::conflict(format!("A user with the userName {} exists", fields.user_name)));
    }
    let existing = Membership::find_by_email_and_org(&email, org, conn).await;
    check_user_name_slot(org, &fields.user_name, existing.as_ref().map(|m| &m.uuid), conn).await?;

    // Someone already in the organization: matched, never changed. The
    // directory gets their id and manages them from now on, if they're a
    // regular member. People provisioning never changes aren't linked: the
    // directory writes nothing about them.
    if let Some(member) = existing {
        if let Some(scim) = ScimUser::find(&member.uuid, conn).await {
            return Err(ScimError::conflict(format!("{email} is already provisioned as {}", scim.user_name)));
        }
        let mut person = ScimPerson::load(member, conn).await.ok_or_else(|| ScimError::not_found("That user was"))?;
        if person.protected {
            return Err(ScimError::conflict(format!(
                "{email} is already in this organization, and provisioning doesn't change owners, admins, custom roles, people who see every item, or your IT provider's staff. Match them by their email as userName, or leave them out of provisioning."
            )));
        }
        let mut scim = ScimUser::new(person.member.uuid.clone(), org.clone(), false);
        keep(&mut scim, &fields);
        scim.save(conn).await?;
        person.scim = Some(scim);
        return Ok(ScimResponse::created(user_json(&person, &caller.base)));
    }

    if CREATES.check_key(org.as_ref()).is_err() {
        return Err(ScimError::new(Status::TooManyRequests, None, "Too many new people this minute; try again soon"));
    }
    if CREATES_TODAY.check_key(org.as_ref()).is_err() {
        return Err(ScimError::new(Status::TooManyRequests, None, "Too many new people today; try again later"));
    }
    let mut member = invite(caller, &email, conn).await?;
    let mut scim = ScimUser::new(member.uuid.clone(), org.clone(), true);
    keep(&mut scim, &fields);
    // Microsoft doesn't provision someone who's turned off, but if a client
    // does, they start off.
    if fields.active == Some(false) {
        member.revoke();
        member.save(conn).await?;
        scim.turned_off = true;
        log_scim_event(EventType::OrganizationUserRevoked, &member.uuid, org, &caller.ip, conn).await;
    }
    scim.save(conn).await?;
    let person = ScimPerson::load(member, conn).await.ok_or_else(|| ScimError::not_found("That user was"))?;
    Ok(ScimResponse::created(user_json(&person, &caller.base)))
}

/// The user's attributes as a PATCH starts from: what the directory sent
/// before (never the account's email in its place), with userName,
/// externalId, and active.
fn editable(person: &ScimPerson) -> Map<String, Value> {
    let mut resource = match &person.scim {
        Some(scim) => serde_json::from_str::<Map<String, Value>>(&scim.attributes).unwrap_or_default(),
        None => Map::new(),
    };
    let (user_name, external_id) = match &person.scim {
        Some(scim) => (scim.user_name.clone(), scim.external_id.clone()),
        None => (person.user.email.clone(), None),
    };
    resource.insert("userName".into(), json!(user_name));
    if let Some(external_id) = external_id {
        resource.insert("externalId".into(), json!(external_id));
    }
    // For someone provisioning never changes, what the directory last asked
    // for, so a PATCH of other attributes doesn't read as turning them on.
    let active = match &person.scim {
        Some(scim) if person.protected && scim.refused_off_at.is_some() => false,
        _ => person.member.status > MembershipStatus::Revoked as i32,
    };
    resource.insert("active".into(), json!(active));
    resource
}

async fn patch_user(caller: &ScimCaller, id: &str, operations: &[patch::Operation], conn: &DbConn) -> ScimResult {
    let person = person(caller, id, conn).await?;
    let mut resource = editable(&person);
    patch::apply(&mut resource, operations)?;
    let fields = user_fields(resource)?;
    update_user(caller, person, fields, conn).await
}

async fn put_user(caller: &ScimCaller, id: &str, body: Value, conn: &DbConn) -> ScimResult {
    let Value::Object(body) = body else {
        return Err(ScimError::bad("invalidSyntax", "A user is a JSON object"));
    };
    let person = person(caller, id, conn).await?;
    let fields = user_fields(body)?;
    update_user(caller, person, fields, conn).await
}

/// Keeps what the directory sent, and turns a regular member off or on when
/// `active` changes. Everything is checked before anything changes.
async fn update_user(caller: &ScimCaller, mut person: ScimPerson, fields: UserFields, conn: &DbConn) -> ScimResult {
    let org = &caller.org.uuid;
    // People provisioning never changes are read-only: nothing the directory
    // sends about them is kept. What's noted is only whether it asked to turn
    // them off, for the Provisioning page.
    if person.protected {
        note_protected(&person, org, fields.active, conn).await?;
        return Err(ScimError::forbidden(PROTECTED));
    }
    let mut scim = person.scim.clone().unwrap_or_else(|| ScimUser::new(person.member.uuid.clone(), org.clone(), false));
    if let Some(other) = ScimUser::find_by_user_name(org, &fields.user_name, conn).await
        && other.membership_uuid != person.member.uuid
    {
        return Err(ScimError::conflict(format!("A user with the userName {} exists", fields.user_name)));
    }
    check_user_name_slot(org, &fields.user_name, Some(&person.member.uuid), conn).await?;
    let active_now = person.member.status > MembershipStatus::Revoked as i32;
    let active = fields.active.unwrap_or(active_now);

    if active != active_now {
        if active {
            if !scim.turned_off {
                return Err(ScimError::forbidden(
                    "An owner or admin turned this person off in PassBundle; they turn them back on there.",
                ));
            }
            // Restored, they may come under two-step login for admins.
            let watch = crate::api::core::keykeeper_two_step::Watch::user(&person.member.user_uuid, conn).await?;
            person.member.restore();
            // Upstream's checks for restoring someone: single organization,
            // two-step login.
            if let Err(e) = OrgPolicy::check_user_allowed(&person.member, "restore", conn).await {
                return Err(ScimError::new(Status::Conflict, None, e.message().to_owned()));
            }
            person.member.save(conn).await?;
            watch.settle(conn).await?;
            scim.turned_off = false;
            log_scim_event(EventType::OrganizationUserRestored, &person.member.uuid, org, &caller.ip, conn).await;
        } else {
            person.member.revoke();
            person.member.save(conn).await?;
            scim.turned_off = true;
            log_scim_event(EventType::OrganizationUserRevoked, &person.member.uuid, org, &caller.ip, conn).await;
        }
    }
    keep(&mut scim, &fields);
    scim.save(conn).await?;
    person.scim = Some(scim);
    Ok(ScimResponse::ok(user_json(&person, &caller.base)))
}

/// Notes that the directory asked to turn off (or remove) someone provisioning
/// never changes, or turned them back on, so the Provisioning page lists whom
/// to remove by hand. Nothing the directory sent is kept: a new note is keyed
/// by the person's own account email, never a userName the directory chose.
async fn note_protected(
    person: &ScimPerson,
    org: &OrganizationId,
    active: Option<bool>,
    conn: &DbConn,
) -> Result<(), ScimError> {
    let Some(active) = active else {
        return Ok(());
    };
    let mut scim = match &person.scim {
        Some(scim) => scim.clone(),
        None if active => return Ok(()),
        None => {
            let mut scim = ScimUser::new(person.member.uuid.clone(), org.clone(), false);
            scim.set_user_name(&person.user.email);
            scim
        }
    };
    let off = (!active).then(|| Utc::now().naive_utc());
    if scim.refused_off_at.is_some() == off.is_some() {
        return Ok(());
    }
    scim.refused_off_at = off;
    scim.save(conn).await?;
    Ok(())
}

/// A userName may not be another member's account email: the directory
/// can't take the name a member is matched by, an owner's included.
async fn check_user_name_slot(
    org: &OrganizationId,
    user_name: &str,
    own: Option<&MembershipId>,
    conn: &DbConn,
) -> Result<(), ScimError> {
    if let Some(other) = Membership::find_by_email_and_org(user_name, org, conn).await
        && Some(&other.uuid) != own
    {
        return Err(ScimError::conflict(format!(
            "{user_name} is another member's email, so it can't be this user's userName"
        )));
    }
    Ok(())
}

/// Removes a regular member, as the Members page's Remove: the organization's
/// items stay with it, and their own vault stays theirs.
async fn delete_user(caller: &ScimCaller, id: &str, conn: &DbConn, nt: &Notify<'_>) -> ScimResult {
    let person = person(caller, id, conn).await?;
    let org = &caller.org.uuid;
    if person.protected {
        note_protected(&person, org, Some(false), conn).await?;
        return Err(ScimError::forbidden(PROTECTED));
    }
    log_scim_event(EventType::OrganizationUserRemoved, &person.member.uuid, org, &caller.ip, conn).await;
    // Keykeeper: a removal holds (DESIGN.md, "Offboarding").
    super::keykeeper_offboarding::before_removal(&person.member, super::keykeeper_offboarding::By::Directory, conn)
        .await?;
    nt.send_user_update(UpdateType::SyncOrgKeys, &person.user, None, conn).await;
    if !CONFIG.mail_enabled()
        && !Membership::find_invited_by_user(&person.user.uuid, conn)
            .await
            .into_iter()
            .any(|m| m.uuid != person.member.uuid)
    {
        Invitation::take(&person.user.email, conn).await;
    }
    person.member.delete(conn).await?;
    Ok(ScimResponse::no_content())
}

// Groups

fn group_json(group: &Group, members: Option<&[MembershipId]>, base: &str) -> Value {
    let mut out = json!({
        "schemas": [GROUP_SCHEMA],
        "id": group.uuid,
        "displayName": group.name,
        "meta": {
            "resourceType": "Group",
            "created": date(&group.creation_date),
            "lastModified": date(&group.revision_date),
            "location": format!("{base}/Groups/{}", group.uuid),
        },
    });
    if let Some(external_id) = &group.external_id {
        out["externalId"] = json!(external_id);
    }
    if let Some(members) = members {
        out["members"] = members
            .iter()
            .map(|m| json!({ "value": m, "$ref": format!("{base}/Users/{m}") }))
            .collect::<Vec<_>>()
            .into();
    }
    out
}

/// A group provisioning made in this organization; groups made in PassBundle
/// aren't the directory's.
async fn scim_group(caller: &ScimCaller, id: &str, conn: &DbConn) -> Result<Group, ScimError> {
    let id = GroupId::from(id.to_owned());
    if ScimGroup::find(&id, &caller.org.uuid, conn).await.is_none() {
        return Err(ScimError::not_found("That group was"));
    }
    Group::find_by_uuid_and_org(&id, &caller.org.uuid, conn).await.ok_or_else(|| ScimError::not_found("That group was"))
}

async fn group_members(group: &Group, conn: &DbConn) -> Vec<MembershipId> {
    GroupUser::find_by_group(&group.uuid, &group.organizations_uuid, conn)
        .await
        .into_iter()
        .map(|g| g.users_organizations_uuid)
        .collect()
}

async fn list_groups(caller: &ScimCaller, query: &ScimQuery, conn: &DbConn) -> ScimResult {
    groups_enabled()?;
    let filter = query.filter()?;
    let mut found = Vec::new();
    for scim in ScimGroup::find_by_org(&caller.org.uuid, conn).await {
        let Some(group) = Group::find_by_uuid_and_org(&scim.group_uuid, &caller.org.uuid, conn).await else {
            continue;
        };
        let members = group_members(&group, conn).await;
        let resource = group_json(&group, Some(&members), &caller.base);
        if filter.as_ref().is_none_or(|f| filter::matches(f, &resource)) {
            found.push(resource);
        }
    }
    Ok(ScimResponse::ok(query.page(found)))
}

/// A group name nobody else in the organization has, in any case: Entra
/// matches groups by name.
async fn check_group_name(
    caller: &ScimCaller,
    name: &str,
    except: Option<&GroupId>,
    conn: &DbConn,
) -> Result<(), ScimError> {
    if name.trim().is_empty() || name.chars().count() > MAX_GROUP_NAME || name.chars().any(char::is_control) {
        return Err(ScimError::bad("invalidValue", "A group's displayName is 1 to 100 characters"));
    }
    let taken = Group::find_by_organization(&caller.org.uuid, conn)
        .await
        .into_iter()
        .any(|g| Some(&g.uuid) != except && g.name.trim().eq_ignore_ascii_case(name.trim()));
    if taken {
        return Err(ScimError::conflict(format!("This organization already has a group named {name}")));
    }
    Ok(())
}

/// The member ids in a list of `{ "value": id }`.
fn member_values(value: &Value) -> Result<Vec<MembershipId>, ScimError> {
    let items = match value {
        Value::Array(items) => items.iter().collect::<Vec<_>>(),
        Value::Object(_) => vec![value],
        _ => return Err(ScimError::bad("invalidValue", "members is a list of { \"value\": id }")),
    };
    items
        .into_iter()
        .map(|item| match get_key(item, "value") {
            Some(Value::String(id)) => Ok(MembershipId::from(id.clone())),
            _ => Err(ScimError::bad("invalidValue", "Each member is { \"value\": id }")),
        })
        .collect()
}

/// Brings a group's members to what the directory wants, leaving people
/// provisioning never changes as they are. Every id the directory adds must be
/// a member of this organization.
async fn set_members(
    caller: &ScimCaller,
    group: &Group,
    wanted: &[MembershipId],
    conn: &DbConn,
) -> Result<(), ScimError> {
    let people = ScimPerson::load_org(&caller.org.uuid, conn).await;
    let current = group_members(group, conn).await;
    for id in wanted {
        if !people.iter().any(|p| &p.member.uuid == id) {
            return Err(ScimError::bad("invalidValue", format!("No user with the id {id} is in this organization")));
        }
    }
    let mut changed = false;
    for p in people.iter().filter(|p| !p.protected) {
        let id = &p.member.uuid;
        let want = wanted.contains(id);
        let has = current.contains(id);
        if want && !has {
            GroupUser::new(group.uuid.clone(), id.clone()).save(conn).await?;
        } else if has && !want {
            remove_group_member(&group.uuid, &p.member, conn).await?;
        } else {
            continue;
        }
        changed = true;
        log_scim_event(EventType::OrganizationUserUpdatedGroups, id, &caller.org.uuid, &caller.ip, conn).await;
    }
    if changed {
        Group::update_revision(&group.uuid, conn).await;
    }
    Ok(())
}

fn string_field(resource: &Value, name: &str) -> Result<Option<String>, ScimError> {
    match get_key(resource, name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.len() <= MAX_NAME => Ok(Some(s.clone())),
        Some(_) => Err(ScimError::bad("invalidValue", format!("{name} is a string of at most 256 characters"))),
    }
}

async fn create_group(caller: &ScimCaller, body: Value, conn: &DbConn) -> ScimResult {
    groups_enabled()?;
    let Some(name) = string_field(&body, "displayName")? else {
        return Err(ScimError::bad("invalidValue", "A group needs a displayName"));
    };
    check_group_name(caller, &name, None, conn).await?;
    let external_id = string_field(&body, "externalId")?;
    let members = match get_key(&body, "members") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => member_values(v)?,
    };
    // No access to any shared folder: an admin gives the group its folders
    // in PassBundle.
    let mut group = Group::new(caller.org.uuid.clone(), name, false, external_id);
    group.save(conn).await?;
    ScimGroup::new(group.uuid.clone(), caller.org.uuid.clone()).insert(conn).await?;
    log_scim_event(EventType::GroupCreated, &group.uuid, &caller.org.uuid, &caller.ip, conn).await;
    if !members.is_empty() {
        set_members(caller, &group, &members, conn).await?;
    }
    let group = scim_group(caller, &group.uuid, conn).await?;
    Ok(ScimResponse::created(group_json(&group, Some(&group_members(&group, conn).await), &caller.base)))
}

async fn put_group(caller: &ScimCaller, id: &str, body: Value, conn: &DbConn) -> ScimResult {
    groups_enabled()?;
    let mut group = scim_group(caller, id, conn).await?;
    let Some(name) = string_field(&body, "displayName")? else {
        return Err(ScimError::bad("invalidValue", "A group needs a displayName"));
    };
    let external_id = string_field(&body, "externalId")?;
    let members = match get_key(&body, "members") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => member_values(v)?,
    };
    save_group(caller, &mut group, name, external_id, conn).await?;
    set_members(caller, &group, &members, conn).await?;
    let group = scim_group(caller, id, conn).await?;
    Ok(ScimResponse::ok(group_json(&group, Some(&group_members(&group, conn).await), &caller.base)))
}

async fn save_group(
    caller: &ScimCaller,
    group: &mut Group,
    name: String,
    external_id: Option<String>,
    conn: &DbConn,
) -> Result<(), ScimError> {
    if name == group.name && external_id == group.external_id {
        return Ok(());
    }
    if name != group.name {
        check_group_name(caller, &name, Some(&group.uuid), conn).await?;
    }
    group.name = name;
    group.set_external_id(external_id);
    group.save(conn).await?;
    log_scim_event(EventType::GroupUpdated, &group.uuid, &caller.org.uuid, &caller.ip, conn).await;
    Ok(())
}

/// A group's PATCH: its name, its externalId, and its members, in the shapes
/// Entra sends (add and remove with `path: "members"` and a list of values,
/// or remove with `members[value eq "..."]`). Other attributes are ignored.
async fn patch_group(caller: &ScimCaller, id: &str, operations: &[patch::Operation], conn: &DbConn) -> ScimResult {
    groups_enabled()?;
    let mut group = scim_group(caller, id, conn).await?;
    let mut name = group.name.clone();
    let mut external_id = group.external_id.clone();
    let mut members = group_members(&group, conn).await;
    let mut touched_members = false;

    for op in operations {
        // Without a path, the value's attributes are each an operation.
        let steps: Vec<(Option<patch::PatchPath>, Option<Value>)> = match &op.path {
            Some(path) => vec![(Some(path.clone()), op.value.clone())],
            None => match &op.value {
                Some(Value::Object(values)) => values
                    .iter()
                    .map(|(k, v)| patch::parse_path(k).map(|p| (Some(p), Some(v.clone()))))
                    .collect::<Result<_, _>>()?,
                _ => return Err(ScimError::bad("invalidValue", "Without a path, the value is an object")),
            },
        };
        for (path, value) in steps {
            let Some(path) = path else {
                continue;
            };
            let attr = &path.attr;
            if attr.is("displayName") {
                match (op.kind, value) {
                    (Kind::Remove, _) => {
                        return Err(ScimError::bad("mutability", "A group's displayName can't be removed"));
                    }
                    (_, Some(Value::String(s))) => name = s,
                    _ => return Err(ScimError::bad("invalidValue", "displayName is a string")),
                }
            } else if attr.is("externalId") {
                match (op.kind, value) {
                    (Kind::Remove, _) | (_, Some(Value::Null)) => external_id = None,
                    (_, Some(Value::String(s))) if s.len() <= MAX_NAME => external_id = Some(s),
                    _ => return Err(ScimError::bad("invalidValue", "externalId is a string")),
                }
            } else if attr.schema.is_none() && attr.attr.eq_ignore_ascii_case("members") && attr.sub.is_none() {
                touched_members = true;
                match (&path.filter, op.kind) {
                    (Some(f), Kind::Remove) => {
                        members.retain(|m| !filter::matches(f, &json!({ "value": m })));
                    }
                    (Some(_), _) => {
                        return Err(ScimError::bad("invalidPath", "Add and replace members with a list of values"));
                    }
                    (None, Kind::Add) => {
                        for m in member_values(&value.unwrap_or(Value::Null))? {
                            if !members.contains(&m) {
                                members.push(m);
                            }
                        }
                    }
                    (None, Kind::Replace) => members = member_values(&value.unwrap_or(Value::Null))?,
                    (None, Kind::Remove) => match value {
                        None | Some(Value::Null) => members.clear(),
                        Some(v) => {
                            let gone = member_values(&v)?;
                            members.retain(|m| !gone.contains(m));
                        }
                    },
                }
            }
        }
    }

    // Check the members the directory adds before changing anything.
    if touched_members {
        let people = ScimPerson::load_org(&caller.org.uuid, conn).await;
        let current = group_members(&group, conn).await;
        if let Some(stranger) =
            members.iter().find(|m| !current.contains(m) && !people.iter().any(|p| &p.member.uuid == *m))
        {
            return Err(ScimError::bad(
                "invalidValue",
                format!("No user with the id {stranger} is in this organization"),
            ));
        }
    }
    save_group(caller, &mut group, name, external_id, conn).await?;
    if touched_members {
        // Ids no longer in the organization drop out on their own.
        let people = ScimPerson::load_org(&caller.org.uuid, conn).await;
        members.retain(|m| people.iter().any(|p| &p.member.uuid == m));
        set_members(caller, &group, &members, conn).await?;
    }
    Ok(ScimResponse::no_content())
}

async fn delete_group(caller: &ScimCaller, id: &str, conn: &DbConn) -> ScimResult {
    groups_enabled()?;
    let group = scim_group(caller, id, conn).await?;
    log_scim_event(EventType::GroupDeleted, &group.uuid, &caller.org.uuid, &caller.ip, conn).await;
    group.delete(&caller.org.uuid, conn).await?;
    Ok(ScimResponse::no_content())
}

// Discovery (RFC 7643, sections 5 to 7)

fn service_provider_config(base: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://passbundle.com/help/",
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": MAX_COUNT },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "Provisioning token",
            "description": "The token from the organization's Provisioning page in PassBundle, as a bearer token.",
            "primary": true,
        }],
        "meta": { "resourceType": "ServiceProviderConfig", "location": format!("{base}/ServiceProviderConfig") },
    })
}

fn resource_types(base: &str) -> Vec<Value> {
    let mut types = vec![json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "description": "A member of the organization",
        "schema": USER_SCHEMA,
        "schemaExtensions": [{ "schema": ENTERPRISE_USER_SCHEMA, "required": false }],
        "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/User") },
    })];
    if CONFIG.org_groups_enabled() {
        types.push(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "A group of members; its access to shared folders is set in PassBundle",
            "schema": GROUP_SCHEMA,
            "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/Group") },
        }));
    }
    types
}

fn attribute(name: &str, kind: &str, multi: bool, required: bool, unique: bool) -> Value {
    json!({
        "name": name,
        "type": kind,
        "multiValued": multi,
        "required": required,
        "caseExact": false,
        "mutability": "readWrite",
        "returned": "default",
        "uniqueness": if unique { "server" } else { "none" },
    })
}

fn complex(name: &str, multi: bool, sub: Vec<Value>) -> Value {
    let mut a = attribute(name, "complex", multi, false, false);
    a["subAttributes"] = Value::Array(sub);
    a
}

fn schemas(base: &str) -> Vec<Value> {
    let schema = |id: &str, name: &str, description: &str, attributes: Vec<Value>| {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
            "id": id,
            "name": name,
            "description": description,
            "attributes": attributes,
            "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{id}") },
        })
    };
    let s = |n: &str| attribute(n, "string", false, false, false);
    let typed = || vec![s("value"), s("type"), attribute("primary", "boolean", false, false, false)];
    let mut list = vec![
        schema(
            USER_SCHEMA,
            "User",
            "A member of the organization. PassBundle invites the work email, or the userName when it's an email address.",
            vec![
                attribute("userName", "string", false, true, true),
                complex(
                    "name",
                    false,
                    vec![
                        s("formatted"),
                        s("familyName"),
                        s("givenName"),
                        s("middleName"),
                        s("honorificPrefix"),
                        s("honorificSuffix"),
                    ],
                ),
                s("displayName"),
                s("nickName"),
                s("title"),
                s("preferredLanguage"),
                attribute("active", "boolean", false, false, false),
                complex("emails", true, typed()),
                complex("phoneNumbers", true, typed()),
            ],
        ),
        schema(
            ENTERPRISE_USER_SCHEMA,
            "EnterpriseUser",
            "Kept as sent; PassBundle doesn't act on it",
            vec![
                s("employeeNumber"),
                s("costCenter"),
                s("organization"),
                s("division"),
                s("department"),
                complex("manager", false, vec![s("value"), attribute("$ref", "reference", false, false, false)]),
            ],
        ),
    ];
    if CONFIG.org_groups_enabled() {
        list.push(schema(
            GROUP_SCHEMA,
            "Group",
            "A group of members",
            vec![
                attribute("displayName", "string", false, true, true),
                complex("members", true, vec![s("value"), attribute("$ref", "reference", false, false, false)]),
            ],
        ));
    }
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn invites_the_work_email_then_the_user_name() {
        // Entra's defaults: userName is the user principal name, and the work
        // email is the mailbox.
        let a = attrs(json!({ "emails": [
            { "type": "other", "value": "alias@contoso.test" },
            { "primary": true, "type": "work", "value": "Ana@Contoso.test" }
        ] }));
        assert_eq!(invite_address(&a, "ana@contoso.onmicrosoft.com").as_deref(), Some("ana@contoso.test"));
        let a = attrs(json!({ "emails": [{ "primary": "True", "value": "b@contoso.test" }] }));
        assert_eq!(invite_address(&a, "x").as_deref(), Some("b@contoso.test"));
        let a = attrs(json!({}));
        assert_eq!(invite_address(&a, "Cy@contoso.test").as_deref(), Some("cy@contoso.test"));
        assert_eq!(invite_address(&a, "Test_User_00aa00aa"), None);
        let a = attrs(json!({ "emails": [{ "type": "work", "value": "not an address" }] }));
        assert_eq!(invite_address(&a, "d@contoso.test").as_deref(), Some("d@contoso.test"));
    }

    #[test]
    fn keeps_what_was_sent_but_never_roles_or_passwords() {
        let fields = user_fields(attrs(json!({
            "schemas": [USER_SCHEMA],
            "externalId": "jyoung",
            "userName": "jyoung@testuser.com",
            "active": "True",
            "addresses": null,
            "displayName": "Joy Young",
            "password": "hunter2",
            "roles": [{ "value": "Admin" }],
            "name": { "familyName": "Young", "givenName": "Joy" },
            "meta": { "resourceType": "User" }
        })))
        .unwrap();
        assert_eq!(fields.user_name, "jyoung@testuser.com");
        assert_eq!(fields.external_id.as_deref(), Some("jyoung"));
        assert_eq!(fields.active, Some(true));
        assert_eq!(
            Value::Object(fields.attributes),
            json!({ "displayName": "Joy Young", "name": { "familyName": "Young", "givenName": "Joy" } })
        );
    }

    #[test]
    fn refuses_users_without_a_user_name_or_with_a_bad_active() {
        assert!(user_fields(attrs(json!({ "userName": "  " }))).is_err());
        assert!(user_fields(attrs(json!({ "displayName": "x" }))).is_err());
        assert!(user_fields(attrs(json!({ "userName": "a", "active": "maybe" }))).is_err());
        assert!(user_fields(attrs(json!({ "userName": "a", "externalId": 5 }))).is_err());
        assert!(user_fields(attrs(json!({ "userName": "a".repeat(257) }))).is_err());
        assert!(user_fields(attrs(json!({ "userName": "a", "title": "x".repeat(MAX_ATTRIBUTES) }))).is_err());
    }

    #[test]
    fn pages_count_from_one() {
        let items: Vec<Value> = (1..=5).map(|i| json!({ "id": i.to_string() })).collect();
        let query = ScimQuery {
            start_index: Some(2),
            count: Some(2),
            ..ScimQuery::default()
        };
        let page = query.page(items.clone());
        assert_eq!(page["totalResults"], 5);
        assert_eq!(page["startIndex"], 2);
        assert_eq!(page["itemsPerPage"], 2);
        assert_eq!(page["Resources"], json!([{ "id": "2" }, { "id": "3" }]));
        let query = ScimQuery {
            start_index: Some(0),
            count: Some(0),
            ..ScimQuery::default()
        };
        let page = query.page(items.clone());
        assert_eq!(page["startIndex"], 1);
        assert_eq!(page["Resources"], json!([]));
        let page = ScimQuery::default().page(items);
        assert_eq!(page["itemsPerPage"], 5);
    }

    #[test]
    fn excluded_and_chosen_attributes() {
        let query = ScimQuery {
            excluded: vec!["members".into()],
            ..ScimQuery::default()
        };
        let mut group = json!({ "schemas": [GROUP_SCHEMA], "id": "g", "displayName": "x", "members": [] });
        query.project(&mut group);
        assert_eq!(group, json!({ "schemas": [GROUP_SCHEMA], "id": "g", "displayName": "x" }));
        let query = ScimQuery {
            attributes: vec!["name.givenName".into()],
            ..ScimQuery::default()
        };
        let mut user = json!({ "schemas": [], "id": "u", "userName": "a", "name": { "givenName": "A" } });
        query.project(&mut user);
        assert_eq!(user, json!({ "schemas": [], "id": "u", "name": { "givenName": "A" } }));
    }

    #[test]
    fn the_limiters_forget_filled_keys_now_and_then() {
        let limiter: Limiter = RateLimiter::keyed(Quota::per_second(NonZeroU32::new(1000).unwrap()));
        for i in 0..200 {
            assert!(limiter.check_key(&format!("203.0.113.{i}")).is_ok());
        }
        assert_eq!(limiter.len(), 200);
        // Long enough for every key's limit to fill back up.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let checks = AtomicUsize::new(0);
        for _ in 0..9 {
            assert!(!prune_now_and_then(&checks, 10, &[&limiter]));
        }
        assert_eq!(limiter.len(), 200, "not before the tenth check");
        assert!(prune_now_and_then(&checks, 10, &[&limiter]));
        assert_eq!(limiter.len(), 0);
        assert!(!prune_now_and_then(&checks, 10, &[&limiter]));
    }

    #[test]
    fn discovery_documents_the_supported_features() {
        let config = service_provider_config("https://x/scim/v2/o");
        assert_eq!(config["patch"]["supported"], true);
        assert_eq!(config["bulk"]["supported"], false);
        assert_eq!(config["filter"]["maxResults"], 200);
        assert_eq!(config["authenticationSchemes"][0]["type"], "oauthbearertoken");
        assert!(resource_types("b").iter().any(|t| t["id"] == "User"));
        assert!(schemas("b").iter().any(|s| s["id"] == USER_SCHEMA));
    }
}

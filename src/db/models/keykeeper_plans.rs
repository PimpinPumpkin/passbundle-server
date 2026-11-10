// Keykeeper: plans (DESIGN.md, "Plans and billing", in the meta repo). A plan
// belongs to a person (Premium), an organization (Families or Business), or an
// MSP (its pool, which covers each of its clients). The `plans` table holds at
// most one row for each. What a person gets is never stored: `what_a_person_gets`
// works it out from the rows, the memberships, and a time it's handed, and
// every sync calls it.
//
// Plans are looked at only where PLANS_ENFORCED is set. With it off, a server
// gives everyone everything, as it always has, and nothing here runs.
//
// Nothing here refuses anything, takes a payment, or talks to a provider, and
// no request from a signed-in person ever writes a plan. Rows are written by
// the operator through the admin page (`src/api/admin.rs`).

use std::collections::{HashMap, HashSet};

use chrono::{NaiveDateTime, TimeDelta, Utc};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    CONFIG,
    api::ApiResult,
    db::{
        DbConn, DbConnInner,
        keykeeper_schema::{msp_clients, msp_staff, msps, plans},
        schema::{organizations, users, users_organizations},
    },
    error::MapResult,
    util::format_date,
};

use super::{MembershipStatus, MembershipType, MspId, MspRole, OrganizationId, UserId};

/// Whose plan it is.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PlanOwner {
    User(UserId),
    Organization(OrganizationId),
    Msp(MspId),
}

impl PlanOwner {
    /// From the operator's route: `users`, `organizations`, or `msps`, and an id.
    pub fn parse(kind: &str, id: &str) -> Option<Self> {
        match kind {
            "users" => Some(Self::User(id.to_owned().into())),
            "organizations" => Some(Self::Organization(id.to_owned().into())),
            "msps" => Some(Self::Msp(id.to_owned().into())),
            _ => None,
        }
    }
}

impl std::fmt::Display for PlanOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User(id) => write!(f, "user {id}"),
            Self::Organization(id) => write!(f, "organization {id}"),
            Self::Msp(id) => write!(f, "MSP {id}"),
        }
    }
}

/// Which plan. A person with no plan is on Free, which has no row and no name here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanName {
    Premium,
    Families,
    Business,
    Msp,
}

impl PlanName {
    /// Its name in the database, in the sync, and in the operator's route.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Premium => "premium",
            Self::Families => "families",
            Self::Business => "business",
            Self::Msp => "msp",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "premium" => Some(Self::Premium),
            "families" => Some(Self::Families),
            "business" => Some(Self::Business),
            "msp" => Some(Self::Msp),
            _ => None,
        }
    }

    /// Premium is a person's, Families and Business are an organization's,
    /// and the pool is an MSP's.
    pub fn fits(self, whose: &PlanOwner) -> bool {
        matches!(
            (self, whose),
            (Self::Premium, PlanOwner::User(_))
                | (Self::Families | Self::Business, PlanOwner::Organization(_))
                | (Self::Msp, PlanOwner::Msp(_))
        )
    }
}

/// Why nothing has to be paid before `free_until`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreeWhy {
    Trial,
    Offer,
}

impl FreeWhy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trial => "trial",
            Self::Offer => "offer",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "trial" => Some(Self::Trial),
            "offer" => Some(Self::Offer),
            _ => None,
        }
    }
}

/// A plan's standing. "No end" is its own value, not an empty date, so a row
/// nobody ever paid for can't be read as one that never ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Never paid, or over.
    None,
    /// Good through the moment in `until`.
    Until,
    /// Good with no end set: a pool with a card on file and nothing unpaid.
    Open,
}

impl Standing {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Until => "until",
            Self::Open => "open",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "until" => Some(Self::Until),
            "open" => Some(Self::Open),
            _ => None,
        }
    }
}

/// How a plan is billed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Billed {
    Prepaid,
    ByTheDay,
    ByHand,
}

impl Billed {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepaid => "prepaid",
            Self::ByTheDay => "by_the_day",
            Self::ByHand => "by_hand",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "prepaid" => Some(Self::Prepaid),
            "by_the_day" => Some(Self::ByTheDay),
            "by_hand" => Some(Self::ByHand),
            _ => None,
        }
    }
}

/// Who last set a plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetBy {
    Server,
    Provider,
    Operator,
}

impl SetBy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Provider => "provider",
            Self::Operator => "operator",
        }
    }
}

/// What a client is told about a plan at one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanState {
    /// Before `free_until`, with nothing paid: a trial or an offer.
    Trial,
    /// In good standing.
    Active,
    /// In grace after a payment that didn't arrive. Still in effect.
    PaymentDue,
    /// Past all three. The plan gives nothing more.
    Ended,
}

impl PlanState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trial => "trial",
            Self::Active => "active",
            Self::PaymentDue => "paymentDue",
            Self::Ended => "ended",
        }
    }

    /// Every state but the last gives what the plan gives.
    pub fn in_effect(self) -> bool {
        self != Self::Ended
    }
}

/// One row of `plans`. Exactly one of `user_uuid`, `org_uuid`, and `msp_uuid`
/// is set (the table checks it), and each is unique, so an owner has at most
/// one row. The row goes when its owner is deleted.
#[derive(Clone, Debug, PartialEq, Eq, Identifiable, Queryable, Insertable)]
#[diesel(table_name = plans)]
#[diesel(primary_key(uuid))]
pub struct Plan {
    pub uuid: String,
    pub user_uuid: Option<UserId>,
    pub org_uuid: Option<OrganizationId>,
    pub msp_uuid: Option<MspId>,
    pub plan: String,
    pub free_until: Option<NaiveDateTime>,
    pub free_why: Option<String>,
    pub standing: String,
    pub until: Option<NaiveDateTime>,
    pub renews: bool,
    pub billed: String,
    pub set_by: String,
    /// The provider's name and its ids for the customer and the subscription,
    /// where a provider set the plan. They mean nothing outside the provider.
    pub provider: Option<String>,
    pub provider_customer: Option<String>,
    pub provider_subscription: Option<String>,
    /// When the provider was last asked.
    pub checked_at: Option<NaiveDateTime>,
    pub updated_at: NaiveDateTime,
}

impl Plan {
    pub fn name(&self) -> Option<PlanName> {
        PlanName::parse(&self.plan)
    }

    /// A value this code doesn't know reads as never paid.
    pub fn standing(&self) -> Standing {
        Standing::parse(&self.standing).unwrap_or(Standing::None)
    }

    pub fn free_why(&self) -> Option<FreeWhy> {
        self.free_why.as_deref().and_then(FreeWhy::parse)
    }

    /// The plan's state at `at`, with `grace_days` of grace (PLAN_GRACE_DAYS).
    ///
    /// - In good standing (`open`, or `until` with `at` no later than the
    ///   moment in `until`): active. A plan that's paid is active even while a
    ///   free period still runs.
    /// - Otherwise, before `free_until`: a trial or an offer. Nothing has to
    ///   be paid before then.
    /// - Otherwise, for a plan that was set to renew, up to `grace_days` past
    ///   `until`: payment due, and still in effect. A plan someone canceled
    ///   (`renews` false) gets no grace, and a free period has none after it.
    /// - Past all three: ended.
    pub fn state_at(&self, at: NaiveDateTime, grace_days: i64) -> PlanState {
        let standing = self.standing();
        let good = match standing {
            Standing::Open => true,
            Standing::Until => self.until.is_some_and(|until| at <= until),
            Standing::None => false,
        };
        if good {
            return PlanState::Active;
        }
        if self.free_until.is_some_and(|free_until| at < free_until) {
            return PlanState::Trial;
        }
        let grace_ends = match (standing, self.renews, self.until, TimeDelta::try_days(grace_days)) {
            (Standing::Until, true, Some(until), Some(grace)) => until.checked_add_signed(grace),
            _ => None,
        };
        if grace_ends.is_some_and(|ends| at <= ends) {
            PlanState::PaymentDue
        } else {
            PlanState::Ended
        }
    }
}

/// The plans' figures, which are settings whose defaults are the site's
/// proposals.
#[derive(Clone, Copy, Debug)]
pub struct Terms {
    /// PLAN_GRACE_DAYS
    pub grace_days: i64,
    /// PLAN_PREMIUM_STORAGE_GB
    pub premium_storage_gb: i64,
    /// PLAN_FAMILIES_PEOPLE
    pub families_people: i64,
    /// PLAN_ORG_STORAGE_GB_PER_PERSON
    pub org_storage_gb_per_person: i64,
    /// PLAN_ORG_STORAGE_MIN_GB
    pub org_storage_min_gb: i64,
}

impl Terms {
    pub fn from_config() -> Self {
        Self {
            grace_days: CONFIG.plan_grace_days(),
            premium_storage_gb: CONFIG.plan_premium_storage_gb(),
            families_people: CONFIG.plan_families_people(),
            org_storage_gb_per_person: CONFIG.plan_org_storage_gb_per_person(),
            org_storage_min_gb: CONFIG.plan_org_storage_min_gb(),
        }
    }

    /// An organization's attachments, pooled: so much a seat, and never less
    /// than the minimum.
    fn org_storage_gb(&self, seats: i64) -> i64 {
        seats.saturating_mul(self.org_storage_gb_per_person).max(self.org_storage_min_gb)
    }
}

/// What a plan gives while it's in effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gives {
    /// Attachments, in whole GB.
    pub storage_gb: i64,
    /// How many people it covers. None: no limit.
    pub people: Option<i64>,
    /// Policies, account recovery, the install command, provisioning, single
    /// sign-on, custom roles, groups, and the event log: one switch.
    pub company_features: bool,
}

impl PlanName {
    /// What each plan gives: the one table of it, because it's the product.
    /// Every plan gives Premium's features to the people it covers (the
    /// person, every member, and for a pool the MSP's staff too), so that
    /// isn't a column here. `seats` is the organization's, and a person's
    /// plan doesn't look at it.
    pub fn gives(self, seats: i64, terms: &Terms) -> Gives {
        match self {
            Self::Premium => Gives {
                storage_gb: terms.premium_storage_gb,
                people: None,
                company_features: false,
            },
            Self::Families => Gives {
                storage_gb: terms.org_storage_gb(seats),
                people: Some(terms.families_people),
                company_features: false,
            },
            Self::Business | Self::Msp => Gives {
                storage_gb: terms.org_storage_gb(seats),
                people: None,
                company_features: true,
            },
        }
    }
}

/// One owner's plan as it stands at the time asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanNow {
    pub whose: PlanOwner,
    /// The row that applies. None for a person on Free and for an organization
    /// or an MSP with no plan. For an MSP's client it's the MSP's row.
    pub row: Option<Plan>,
    /// None when no row applies.
    pub state: Option<PlanState>,
    /// What the plan gives, whatever its state. None when no row applies.
    pub gives: Option<Gives>,
    /// The MSP whose pool covers this organization, and its name.
    pub covered_by: Option<(MspId, String)>,
    /// Whether the person asking may manage it (`may_manage`). False when
    /// nobody is asking.
    pub may_manage: bool,
    /// A person only: Premium's features come through an organization or an
    /// MSP, whatever their own plan says.
    pub through_organization: bool,
}

impl PlanNow {
    /// Whether the plan gives what it gives at the time asked.
    pub fn in_effect(&self) -> bool {
        self.state.is_some_and(PlanState::in_effect)
    }

    /// An organization on Families: six people, and no company features.
    pub fn is_family(&self) -> bool {
        self.row.as_ref().and_then(Plan::name) == Some(PlanName::Families)
    }

    /// Attachments, in whole GB: the plan's figure while it's in effect, and
    /// none after. A person covered by an organization or an MSP gets
    /// Premium's for their own vault. None for a pool, which has no storage of
    /// its own: each client has.
    pub fn storage_gb(&self, terms: &Terms) -> Option<i64> {
        match self.whose {
            PlanOwner::Msp(_) => None,
            PlanOwner::User(_) if self.through_organization || self.in_effect() => Some(terms.premium_storage_gb),
            PlanOwner::Organization(_) if self.in_effect() => Some(self.gives.map_or(0, |gives| gives.storage_gb)),
            _ => Some(0),
        }
    }
}

/// What a person gets at the time asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersonGets {
    /// Their own plan. No row: Free.
    pub own: PlanNow,
    /// Their own plan is in effect (the profile's `premium`).
    pub premium: bool,
    /// They hold a seat in an organization whose plan is in effect, or
    /// they're on the staff of an MSP whose plan is in effect (the profile's
    /// `premiumFromOrganization`).
    pub premium_from_organization: bool,
    /// Each organization they've joined, with its plan.
    pub organizations: HashMap<OrganizationId, PlanNow>,
}

type Query<T> = Result<T, diesel::result::Error>;

/// An MSP's staff: its admins and its technicians.
const STAFF_ROLES: [i32; 2] = [MspRole::Admin as i32, MspRole::Technician as i32];

/// Holding a seat: accepted or confirmed. Invited people haven't joined, and
/// revoked ones keep a negative status.
const JOINED: [i32; 2] = [MembershipStatus::Accepted as i32, MembershipStatus::Confirmed as i32];

fn find_row(conn: &mut DbConnInner, whose: &PlanOwner) -> Query<Option<Plan>> {
    match whose {
        PlanOwner::User(id) => plans::table.filter(plans::user_uuid.eq(id)).first::<Plan>(conn).optional(),
        PlanOwner::Organization(id) => plans::table.filter(plans::org_uuid.eq(id)).first::<Plan>(conn).optional(),
        PlanOwner::Msp(id) => plans::table.filter(plans::msp_uuid.eq(id)).first::<Plan>(conn).optional(),
    }
}

/// The MSP an organization is a client of now, and the MSP's name.
fn covering_msp(conn: &mut DbConnInner, org: &OrganizationId) -> Query<Option<(MspId, String)>> {
    let msp = msp_clients::table
        .filter(msp_clients::org_uuid.eq(org))
        .select(msp_clients::msp_uuid)
        .first::<MspId>(conn)
        .optional()?;
    let Some(msp) = msp else {
        return Ok(None);
    };
    let name = msps::table.filter(msps::uuid.eq(&msp)).select(msps::name).first::<String>(conn)?;
    Ok(Some((msp, name)))
}

/// A confirmed owner of the organization.
fn is_owner(conn: &mut DbConnInner, user: &UserId, org: &OrganizationId) -> Query<bool> {
    let found = users_organizations::table
        .filter(users_organizations::org_uuid.eq(org))
        .filter(users_organizations::user_uuid.eq(user))
        .filter(users_organizations::atype.eq(MembershipType::Owner as i32))
        .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
        .count()
        .get_result::<i64>(conn)?;
    Ok(found > 0)
}

/// On the MSP's staff as an admin.
fn is_msp_admin(conn: &mut DbConnInner, user: &UserId, msp: &MspId) -> Query<bool> {
    let found = msp_staff::table
        .filter(msp_staff::msp_uuid.eq(msp))
        .filter(msp_staff::user_uuid.eq(user))
        .filter(msp_staff::role.eq(MspRole::Admin as i32))
        .count()
        .get_result::<i64>(conn)?;
    Ok(found > 0)
}

/// Who may manage a plan. This is the only place that decides it: the sync's
/// `canManage`, and every route that answers about a plan to a signed-in
/// person, ask here.
///
/// - A person manages their own plan, and nobody else's.
/// - An organization's confirmed owners manage its plan.
/// - An MSP's admins manage its pool. A client is covered by the pool, so its
///   plan is the MSP's admins' to manage too, and not its own owners'.
///
/// Managing never writes a plan. No signed-in person can.
fn may_manage(conn: &mut DbConnInner, asker: &UserId, whose: &PlanOwner) -> Query<bool> {
    match whose {
        PlanOwner::User(user) => Ok(user == asker),
        PlanOwner::Msp(msp) => is_msp_admin(conn, asker, msp),
        PlanOwner::Organization(org) => match covering_msp(conn, org)? {
            Some((msp, _)) => is_msp_admin(conn, asker, &msp),
            None => is_owner(conn, asker, org),
        },
    }
}

/// An organization's seats: members who have joined (accepted or confirmed),
/// aren't revoked, and aren't on the staff of the MSP that covers it. The
/// rule in "Seats by client".
fn seats(conn: &mut DbConnInner, org: &OrganizationId, msp: Option<&MspId>) -> Query<i64> {
    let members = users_organizations::table
        .filter(users_organizations::org_uuid.eq(org))
        .filter(users_organizations::status.eq_any(JOINED))
        .select(users_organizations::user_uuid)
        .load::<UserId>(conn)?;
    let staff: HashSet<UserId> = match msp {
        Some(msp) => msp_staff::table
            .filter(msp_staff::msp_uuid.eq(msp))
            .filter(msp_staff::role.eq_any(STAFF_ROLES))
            .select(msp_staff::user_uuid)
            .load::<UserId>(conn)?
            .into_iter()
            .collect(),
        None => HashSet::new(),
    };
    let seats = members.iter().filter(|member| !staff.contains(member)).count();
    Ok(i64::try_from(seats).unwrap_or(i64::MAX))
}

/// One owner's plan at `at`. An MSP's pool covers its clients: a client's
/// plan is its MSP's, found through `msp_clients` when it's asked for, and a
/// row of the client's own is ignored while it's a client.
fn plan_now(
    conn: &mut DbConnInner,
    whose: &PlanOwner,
    asker: Option<&UserId>,
    at: NaiveDateTime,
    terms: &Terms,
) -> Query<PlanNow> {
    let covered_by = match whose {
        PlanOwner::Organization(org) => covering_msp(conn, org)?,
        _ => None,
    };
    let row = match &covered_by {
        Some((msp, _)) => find_row(conn, &PlanOwner::Msp(msp.clone()))?,
        None => find_row(conn, whose)?,
    };
    let state = row.as_ref().map(|row| row.state_at(at, terms.grace_days));
    let gives = match (row.as_ref().and_then(Plan::name), whose) {
        (Some(name), PlanOwner::Organization(org)) => {
            let seats = seats(conn, org, covered_by.as_ref().map(|(msp, _)| msp))?;
            Some(name.gives(seats, terms))
        }
        (Some(name), _) => Some(name.gives(0, terms)),
        (None, _) => None,
    };
    let may_manage = match asker {
        Some(asker) => may_manage(conn, asker, whose)?,
        None => false,
    };
    Ok(PlanNow {
        whose: whose.clone(),
        row,
        state,
        gives,
        covered_by,
        may_manage,
        through_organization: false,
    })
}

/// The one function, on a connection. A person has Premium's features when
/// their own plan is in effect, or they hold a seat (joined and not revoked)
/// in an organization whose plan is in effect, or they're on the staff of an
/// MSP whose plan is in effect.
fn person_gets(conn: &mut DbConnInner, user: &UserId, at: NaiveDateTime, terms: &Terms) -> Query<PersonGets> {
    let mut own = plan_now(conn, &PlanOwner::User(user.clone()), Some(user), at, terms)?;
    let premium = own.in_effect();
    let mut premium_from_organization = false;

    let staff_of = msp_staff::table
        .filter(msp_staff::user_uuid.eq(user))
        .filter(msp_staff::role.eq_any(STAFF_ROLES))
        .select(msp_staff::msp_uuid)
        .load::<MspId>(conn)?;
    for msp in staff_of {
        let pool = find_row(conn, &PlanOwner::Msp(msp))?;
        if pool.is_some_and(|row| row.state_at(at, terms.grace_days).in_effect()) {
            premium_from_organization = true;
        }
    }

    let member_of = users_organizations::table
        .filter(users_organizations::user_uuid.eq(user))
        .filter(users_organizations::status.eq_any(JOINED))
        .select(users_organizations::org_uuid)
        .load::<OrganizationId>(conn)?;
    let mut organizations = HashMap::new();
    for org in member_of {
        let plan = plan_now(conn, &PlanOwner::Organization(org.clone()), Some(user), at, terms)?;
        if plan.in_effect() {
            premium_from_organization = true;
        }
        organizations.insert(org, plan);
    }

    own.through_organization = premium_from_organization;
    Ok(PersonGets {
        own,
        premium,
        premium_from_organization,
        organizations,
    })
}

/// What a person gets at `at`: the one function. Worked out from the rows,
/// the memberships, and the time it's handed, and never stored, so nothing
/// keeps a copy that could go stale. Every check and every sync calls it.
pub async fn what_a_person_gets(user: &UserId, at: NaiveDateTime, conn: &DbConn) -> ApiResult<PersonGets> {
    let terms = Terms::from_config();
    conn.run(move |conn| person_gets(conn, user, at, &terms).map_res("Error working out what a person's plans give"))
        .await
}

/// One owner's plan at `at`, for `asker` (nobody, when the operator asks).
pub async fn plan_at(
    whose: &PlanOwner,
    asker: Option<&UserId>,
    at: NaiveDateTime,
    conn: &DbConn,
) -> ApiResult<PlanNow> {
    let terms = Terms::from_config();
    conn.run(move |conn| plan_now(conn, whose, asker, at, &terms).map_res("Error working out a plan")).await
}

/// Whether `asker` may manage `whose` plan. See `may_manage`.
pub async fn may_manage_plan(asker: &UserId, whose: &PlanOwner, conn: &DbConn) -> ApiResult<bool> {
    conn.run(move |conn| may_manage(conn, asker, whose).map_res("Error checking who manages a plan")).await
}

/// `keykeeperPlan` on a server that doesn't enforce plans: everyone gets
/// everything, and no plan is looked up.
pub fn not_enforced_json() -> Value {
    json!({ "enforced": false })
}

impl PlanNow {
    /// `keykeeperPlan`, as the sync and `GET /api/keykeeper/plan` carry it on
    /// a server that enforces plans. Clients show it. Nothing is enforced
    /// from it.
    ///
    /// The dates, whether it renews, and a payment that's due are for whoever
    /// manages the plan. Everyone else is told only what they get: a plan in
    /// grace reads as active to them, since grace changes nothing for them.
    pub fn to_json(&self, terms: &Terms) -> Value {
        let plan = match (&self.row, &self.whose) {
            (Some(row), _) => Value::from(row.plan.as_str()),
            (None, PlanOwner::User(_)) => Value::from("free"),
            (None, _) => Value::Null,
        };
        let state = match self.state {
            Some(PlanState::PaymentDue) if !self.may_manage => Some(PlanState::Active),
            state => state,
        };
        let row = self.row.as_ref().filter(|_| self.may_manage);
        json!({
            "enforced": true,
            "plan": plan,
            "state": state.map(PlanState::as_str),
            "freeUntil": row.and_then(|row| row.free_until).map(|date| format_date(&date)),
            "freeWhy": row.and_then(Plan::free_why).map(FreeWhy::as_str),
            "until": row.and_then(|row| row.until).map(|date| format_date(&date)),
            "renews": row.map(|row| row.renews),
            "storageGb": self.storage_gb(terms),
            "people": self.gives.and_then(|gives| gives.people),
            "coveredBy": self.covered_by.as_ref().map(|(id, name)| json!({ "id": id, "name": name })),
            "canManage": self.may_manage,
        })
    }
}

/// The fields of an organization in a profile that say it has the company
/// features. A family doesn't, so the admin console hides them.
const COMPANY_FEATURE_FIELDS: [&str; 8] = [
    "usePolicies",
    "useGroups",
    "useEvents",
    "useSso",
    "useScim",
    "useResetPassword",
    "useCustomPermissions",
    "useApi",
];

/// Puts an organization's plan in its entry in a profile. `enabled` is never
/// touched: a plan never suspends an organization.
fn put_in_organization(org: &mut Value, plan: &PlanNow, terms: &Terms) {
    org["usersGetPremium"] = plan.in_effect().into();
    org["maxStorageGb"] = plan.storage_gb(terms).unwrap_or(0).clamp(0, i64::from(i16::MAX)).into();
    if plan.is_family() {
        // Upstream's Families, where the invite form stops at the seats left.
        org["seats"] = plan.gives.and_then(|gives| gives.people).into();
        org["productTierType"] = 1.into();
    } else {
        org["seats"] = Value::Null;
        org["productTierType"] = 3.into();
    }
    if plan.gives.is_some_and(|gives| !gives.company_features) {
        for field in COMPANY_FEATURE_FIELDS {
            org[field] = false.into();
        }
    }
    org["keykeeperPlan"] = plan.to_json(terms);
}

/// Puts a person's plans in their profile, which every sync carries
/// (`User::to_json`).
///
/// With PLANS_ENFORCED off, every field keeps the value it has always had,
/// no plan is looked up, and `keykeeperPlan` says this server doesn't enforce
/// plans. With it on, the fields the vault format already has get true
/// values, and `keykeeperPlan` is added to the profile and to each
/// organization in it.
pub async fn put_in_profile(profile: &mut Value, user: &UserId, conn: &DbConn) {
    const LISTS: [&str; 2] = ["organizations", "organizationsNew"];
    if !CONFIG.plans_enforced() {
        profile["keykeeperPlan"] = not_enforced_json();
        for list in LISTS {
            for org in profile[list].as_array_mut().into_iter().flatten() {
                org["keykeeperPlan"] = not_enforced_json();
            }
        }
        return;
    }

    let gets = match what_a_person_gets(user, Utc::now().naive_utc(), conn).await {
        Ok(gets) => gets,
        Err(e) => {
            // A plan never ends on a guess: when the plans can't be read, the
            // profile says what it has always said.
            error!("Plans couldn't be read for a profile, so it was left as it is: {e:#?}");
            return;
        }
    };
    let terms = Terms::from_config();
    profile["premium"] = gets.premium.into();
    profile["premiumFromOrganization"] = gets.premium_from_organization.into();
    profile["keykeeperPlan"] = gets.own.to_json(&terms);
    for list in LISTS {
        for org in profile[list].as_array_mut().into_iter().flatten() {
            let id = org["id"].as_str().map(|id| OrganizationId::from(id.to_owned()));
            if let Some(plan) = id.and_then(|id| gets.organizations.get(&id)) {
                put_in_organization(org, plan, &terms);
            }
        }
    }
}

/// What the operator sets on a plan. Everything else in the row is the
/// server's or a provider's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanWrite {
    pub plan: PlanName,
    pub free_until: Option<NaiveDateTime>,
    pub free_why: Option<FreeWhy>,
    pub standing: Standing,
    pub until: Option<NaiveDateTime>,
    pub renews: bool,
    pub billed: Billed,
}

impl PlanWrite {
    /// Why this can't be `whose` plan, if it can't.
    pub fn refusal(&self, whose: &PlanOwner) -> Option<&'static str> {
        if !self.plan.fits(whose) {
            return Some(
                "That plan doesn't fit: premium is a person's, families and business are an organization's, and msp is an MSP's",
            );
        }
        if self.free_until.is_some() != self.free_why.is_some() {
            return Some("freeUntil and freeWhy go together");
        }
        if (self.standing == Standing::Until) != self.until.is_some() {
            return Some("until is given when standing is until, and only then");
        }
        None
    }
}

fn owner_exists(conn: &mut DbConnInner, whose: &PlanOwner) -> Query<bool> {
    let found = match whose {
        PlanOwner::User(id) => users::table.filter(users::uuid.eq(id)).count().get_result::<i64>(conn)?,
        PlanOwner::Organization(id) => {
            organizations::table.filter(organizations::uuid.eq(id)).count().get_result::<i64>(conn)?
        }
        PlanOwner::Msp(id) => msps::table.filter(msps::uuid.eq(id)).count().get_result::<i64>(conn)?,
    };
    Ok(found > 0)
}

impl Plan {
    /// The row itself, for the operator.
    pub fn to_json(&self) -> Value {
        json!({
            "plan": self.plan,
            "freeUntil": self.free_until.map(|date| format_date(&date)),
            "freeWhy": self.free_why,
            "standing": self.standing,
            "until": self.until.map(|date| format_date(&date)),
            "renews": self.renews,
            "billed": self.billed,
            "setBy": self.set_by,
            "provider": self.provider,
            "providerCustomer": self.provider_customer,
            "providerSubscription": self.provider_subscription,
            "checkedAt": self.checked_at.map(|date| format_date(&date)),
            "updatedAt": format_date(&self.updated_at),
        })
    }

    /// Whether there's such a person, organization, or MSP.
    pub async fn owner_exists(whose: &PlanOwner, conn: &DbConn) -> ApiResult<bool> {
        conn.run(move |conn| owner_exists(conn, whose).map_res("Error looking for a plan's owner")).await
    }

    /// `whose` own row, if it has one. A client's own row is found here even
    /// while its MSP's pool covers it.
    pub async fn find(whose: &PlanOwner, conn: &DbConn) -> ApiResult<Option<Self>> {
        conn.run(move |conn| find_row(conn, whose).map_res("Error loading a plan")).await
    }

    /// Writes `whose` plan, in place of the row it had. Answers the row
    /// before and the row now, or nothing when there's no such person,
    /// organization, or MSP. What a provider recorded on the row stays.
    ///
    /// Only the server calls this: for the operator, from the admin page. No
    /// route a signed-in person can reach does.
    pub async fn set(
        whose: &PlanOwner,
        write: PlanWrite,
        set_by: SetBy,
        conn: &DbConn,
    ) -> ApiResult<Option<(Option<Self>, Self)>> {
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            conn.transaction(|conn| {
                if !owner_exists(conn, whose)? {
                    return Ok(None);
                }
                let old = find_row(conn, whose)?;
                let (user_uuid, org_uuid, msp_uuid) = match whose {
                    PlanOwner::User(id) => (Some(id.clone()), None, None),
                    PlanOwner::Organization(id) => (None, Some(id.clone()), None),
                    PlanOwner::Msp(id) => (None, None, Some(id.clone())),
                };
                let new = Self {
                    uuid: old.as_ref().map_or_else(crate::util::get_uuid, |old| old.uuid.clone()),
                    user_uuid,
                    org_uuid,
                    msp_uuid,
                    plan: write.plan.as_str().to_owned(),
                    free_until: write.free_until,
                    free_why: write.free_why.map(|why| why.as_str().to_owned()),
                    standing: write.standing.as_str().to_owned(),
                    until: write.until,
                    renews: write.renews,
                    billed: write.billed.as_str().to_owned(),
                    set_by: set_by.as_str().to_owned(),
                    provider: old.as_ref().and_then(|old| old.provider.clone()),
                    provider_customer: old.as_ref().and_then(|old| old.provider_customer.clone()),
                    provider_subscription: old.as_ref().and_then(|old| old.provider_subscription.clone()),
                    checked_at: old.as_ref().and_then(|old| old.checked_at),
                    updated_at: now,
                };
                if let Some(old) = &old {
                    diesel::delete(plans::table.filter(plans::uuid.eq(&old.uuid))).execute(conn)?;
                }
                diesel::insert_into(plans::table).values(&new).execute(conn)?;
                Ok::<_, diesel::result::Error>(Some((old, new)))
            })
            .map_res("Error saving a plan")
        })
        .await
    }

    /// Removes `whose` row, and answers it if there was one. A person is then
    /// on Free, and an organization or an MSP has no plan.
    pub async fn remove(whose: &PlanOwner, conn: &DbConn) -> ApiResult<Option<Self>> {
        conn.run(move |conn| {
            conn.transaction(|conn| {
                let old = find_row(conn, whose)?;
                if let Some(old) = &old {
                    diesel::delete(plans::table.filter(plans::uuid.eq(&old.uuid))).execute(conn)?;
                }
                Ok::<_, diesel::result::Error>(old)
            })
            .map_res("Error removing a plan")
        })
        .await
    }
}

/// The people a change to `whose` plan reaches, who are sent the sync notice:
/// the person; an organization's members who have joined; an MSP's staff and
/// the members of each of its clients.
pub async fn people_a_plan_reaches(whose: &PlanOwner, conn: &DbConn) -> ApiResult<Vec<UserId>> {
    fn members(conn: &mut DbConnInner, org: &OrganizationId) -> Query<Vec<UserId>> {
        users_organizations::table
            .filter(users_organizations::org_uuid.eq(org))
            .filter(users_organizations::status.eq_any(JOINED))
            .select(users_organizations::user_uuid)
            .load::<UserId>(conn)
    }
    fn reached(conn: &mut DbConnInner, whose: &PlanOwner) -> Query<HashSet<UserId>> {
        Ok(match whose {
            PlanOwner::User(user) => HashSet::from([user.clone()]),
            PlanOwner::Organization(org) => members(conn, org)?.into_iter().collect(),
            PlanOwner::Msp(msp) => {
                let mut people: HashSet<UserId> = msp_staff::table
                    .filter(msp_staff::msp_uuid.eq(msp))
                    .filter(msp_staff::role.eq_any(STAFF_ROLES))
                    .select(msp_staff::user_uuid)
                    .load::<UserId>(conn)?
                    .into_iter()
                    .collect();
                let clients = msp_clients::table
                    .filter(msp_clients::msp_uuid.eq(msp))
                    .select(msp_clients::org_uuid)
                    .load::<OrganizationId>(conn)?;
                for client in clients {
                    people.extend(members(conn, &client)?);
                }
                people
            }
        })
    }
    conn.run(move |conn| {
        reached(conn, whose).map(|people| people.into_iter().collect()).map_res("Error loading who a plan reaches")
    })
    .await
}

#[cfg(all(test, sqlite))]
mod tests {
    use super::*;
    use crate::db::{
        DbPool,
        models::{Membership, Msp, MspClient, MspStaff, Organization, User},
    };

    /// Noon on March 1, 2027: the moment the plans below turn on.
    fn noon() -> NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2027, 3, 1).unwrap().and_hms_opt(12, 0, 0).unwrap()
    }

    fn second() -> TimeDelta {
        TimeDelta::seconds(1)
    }

    fn grace() -> TimeDelta {
        TimeDelta::days(CONFIG.plan_grace_days())
    }

    /// A row nobody has paid for and nobody was given free time on.
    fn row(plan: PlanName) -> Plan {
        Plan {
            uuid: crate::util::get_uuid(),
            user_uuid: None,
            org_uuid: None,
            msp_uuid: None,
            plan: plan.as_str().to_owned(),
            free_until: None,
            free_why: None,
            standing: Standing::None.as_str().to_owned(),
            until: None,
            renews: false,
            billed: Billed::ByHand.as_str().to_owned(),
            set_by: SetBy::Operator.as_str().to_owned(),
            provider: None,
            provider_customer: None,
            provider_subscription: None,
            checked_at: None,
            updated_at: noon(),
        }
    }

    fn nothing(plan: PlanName) -> PlanWrite {
        PlanWrite {
            plan,
            free_until: None,
            free_why: None,
            standing: Standing::None,
            until: None,
            renews: false,
            billed: Billed::ByHand,
        }
    }

    /// Free until `free_until`, and never paid.
    fn free(plan: PlanName, free_until: NaiveDateTime, why: FreeWhy) -> PlanWrite {
        PlanWrite {
            free_until: Some(free_until),
            free_why: Some(why),
            ..nothing(plan)
        }
    }

    /// Paid through `until`.
    fn paid(plan: PlanName, until: NaiveDateTime, renews: bool) -> PlanWrite {
        PlanWrite {
            standing: Standing::Until,
            until: Some(until),
            renews,
            ..nothing(plan)
        }
    }

    /// Good with no end set.
    fn open(plan: PlanName) -> PlanWrite {
        PlanWrite {
            standing: Standing::Open,
            renews: true,
            billed: Billed::ByTheDay,
            ..nothing(plan)
        }
    }

    #[test]
    fn a_plans_state_at_a_time() {
        let days = 14;
        let end = noon();

        // Nobody paid, and no free time: over from the start.
        assert_eq!(row(PlanName::Business).state_at(end, days), PlanState::Ended);

        // A trial runs up to, and not including, the moment in free_until,
        // and has no grace after it.
        let trial = Plan {
            free_until: Some(end),
            free_why: Some("trial".to_owned()),
            ..row(PlanName::Business)
        };
        assert_eq!(trial.state_at(end - second(), days), PlanState::Trial);
        assert_eq!(trial.state_at(end, days), PlanState::Ended);
        assert_eq!(trial.state_at(end + second(), days), PlanState::Ended);

        // Good through the moment in until, then grace for a plan set to
        // renew: from the next second through the last of the grace days.
        let renewing = Plan {
            standing: "until".to_owned(),
            until: Some(end),
            renews: true,
            ..row(PlanName::Premium)
        };
        assert_eq!(renewing.state_at(end - TimeDelta::days(300), days), PlanState::Active);
        assert_eq!(renewing.state_at(end, days), PlanState::Active);
        assert_eq!(renewing.state_at(end + second(), days), PlanState::PaymentDue);
        assert_eq!(renewing.state_at(end + TimeDelta::days(days), days), PlanState::PaymentDue);
        assert_eq!(renewing.state_at(end + TimeDelta::days(days) + second(), days), PlanState::Ended);
        // The grace is the setting's, and none is none.
        assert_eq!(renewing.state_at(end + second(), 0), PlanState::Ended);
        assert_eq!(renewing.state_at(end + TimeDelta::days(7), 7), PlanState::PaymentDue);
        assert_eq!(renewing.state_at(end + TimeDelta::days(7) + second(), 7), PlanState::Ended);

        // A plan someone canceled ends at until, as they chose.
        let canceled = Plan {
            renews: false,
            ..renewing.clone()
        };
        assert_eq!(canceled.state_at(end, days), PlanState::Active);
        assert_eq!(canceled.state_at(end + second(), days), PlanState::Ended);

        // Good with no end set.
        let pool = Plan {
            standing: "open".to_owned(),
            renews: true,
            ..row(PlanName::Msp)
        };
        assert_eq!(pool.state_at(end + TimeDelta::days(3650), days), PlanState::Active);

        // Paid during a trial: active. A payment that didn't arrive while
        // free time still runs: nothing is due before free_until.
        let paid_early = Plan {
            free_until: Some(end + TimeDelta::days(20)),
            free_why: Some("trial".to_owned()),
            ..renewing.clone()
        };
        assert_eq!(paid_early.state_at(end, days), PlanState::Active);
        assert_eq!(paid_early.state_at(end + TimeDelta::days(15), days), PlanState::Trial);
        assert_eq!(paid_early.state_at(end + TimeDelta::days(20), days), PlanState::Ended);

        // A standing this code doesn't know is never read as paid, and an
        // "until" with no date isn't either.
        let unknown = Plan {
            standing: "forever".to_owned(),
            ..row(PlanName::Premium)
        };
        assert_eq!(unknown.state_at(end, days), PlanState::Ended);
        let no_date = Plan {
            standing: "until".to_owned(),
            renews: true,
            ..row(PlanName::Premium)
        };
        assert_eq!(no_date.state_at(end, days), PlanState::Ended);
    }

    /// The site's proposals, which are the settings' defaults.
    fn site_terms() -> Terms {
        Terms {
            grace_days: 14,
            premium_storage_gb: 5,
            families_people: 6,
            org_storage_gb_per_person: 1,
            org_storage_min_gb: 5,
        }
    }

    #[test]
    fn what_each_plan_gives() {
        let terms = site_terms();
        let premium = PlanName::Premium.gives(0, &terms);
        assert_eq!((premium.storage_gb, premium.people, premium.company_features), (5, None, false));
        let family = PlanName::Families.gives(6, &terms);
        assert_eq!((family.storage_gb, family.people, family.company_features), (6, Some(6), false));
        // Pooled at 1 GB a person, and never less than 5 GB.
        let small = PlanName::Business.gives(3, &terms);
        assert_eq!((small.storage_gb, small.people, small.company_features), (5, None, true));
        assert_eq!(PlanName::Business.gives(40, &terms).storage_gb, 40);
        assert_eq!(PlanName::Msp.gives(40, &terms), PlanName::Business.gives(40, &terms));
    }

    #[test]
    fn a_plan_fits_only_its_kind_of_owner() {
        let person = PlanOwner::User("u".to_owned().into());
        let org = PlanOwner::Organization("o".to_owned().into());
        let msp = PlanOwner::Msp("m".to_owned().into());
        for (plan, fits) in [
            (PlanName::Premium, [true, false, false]),
            (PlanName::Families, [false, true, false]),
            (PlanName::Business, [false, true, false]),
            (PlanName::Msp, [false, false, true]),
        ] {
            assert_eq!([plan.fits(&person), plan.fits(&org), plan.fits(&msp)], fits, "{plan:?}");
            assert_eq!(nothing(plan).refusal(&person).is_none(), fits[0], "{plan:?}");
        }
        // The dates and their reasons go together.
        let mut write = free(PlanName::Premium, noon(), FreeWhy::Trial);
        assert!(write.refusal(&person).is_none());
        write.free_why = None;
        assert!(write.refusal(&person).is_some());
        let mut write = paid(PlanName::Premium, noon(), true);
        assert!(write.refusal(&person).is_none());
        write.until = None;
        assert!(write.refusal(&person).is_some());
        let mut write = open(PlanName::Premium);
        write.until = Some(noon());
        assert!(write.refusal(&person).is_some());
        assert_eq!(PlanOwner::parse("users", "u"), Some(person));
        assert_eq!(PlanOwner::parse("people", "u"), None);
    }

    // With a database: the one function, handed a time.

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
        member.save(conn).await.unwrap();
        member
    }

    async fn msp(name: &str, conn: &DbConn) -> Msp {
        let msp = Msp::new(name.to_owned());
        msp.insert(conn).await.unwrap();
        msp
    }

    async fn staff(msp: &Msp, user: &User, role: MspRole, conn: &DbConn) {
        MspStaff::new(msp.uuid.clone(), user.uuid.clone(), role).insert(conn).await.unwrap();
    }

    /// Makes `org` a client of `msp`. As keykeeper_offboarding's tests make
    /// one: MspClient::new seals an install token with the server's keys,
    /// which tests don't load.
    async fn take_on(msp: &Msp, org: &Organization, conn: &DbConn) {
        MspClient {
            org_uuid: org.uuid.clone(),
            msp_uuid: msp.uuid.clone(),
            created_at: Utc::now().naive_utc(),
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
    }

    /// The client leaves its MSP.
    async fn leave(org: &Organization, conn: &DbConn) {
        MspClient::find_by_org(&org.uuid, conn).await.unwrap().delete(conn).await.unwrap();
    }

    fn of(user: &User) -> PlanOwner {
        PlanOwner::User(user.uuid.clone())
    }

    fn of_org(org: &Organization) -> PlanOwner {
        PlanOwner::Organization(org.uuid.clone())
    }

    fn of_msp(msp: &Msp) -> PlanOwner {
        PlanOwner::Msp(msp.uuid.clone())
    }

    /// Writes a plan as the operator does.
    async fn set(whose: &PlanOwner, write: PlanWrite, conn: &DbConn) -> Plan {
        Plan::set(whose, write, SetBy::Operator, conn).await.unwrap().expect("the owner exists").1
    }

    async fn gets_at(user: &User, at: NaiveDateTime, conn: &DbConn) -> PersonGets {
        what_a_person_gets(&user.uuid, at, conn).await.unwrap()
    }

    /// Whether the person has Premium's features of their own, and through
    /// an organization or an MSP.
    async fn premium(user: &User, at: NaiveDateTime, conn: &DbConn) -> (bool, bool) {
        let gets = gets_at(user, at, conn).await;
        (gets.premium, gets.premium_from_organization)
    }

    fn state_in(gets: &PersonGets, org: &Organization) -> Option<PlanState> {
        gets.organizations[&org.uuid].state
    }

    #[rocket::async_test]
    async fn no_row_is_free() {
        let conn = DbPool::for_test().await;
        let ana = person("ana", &conn).await;

        let gets = gets_at(&ana, noon(), &conn).await;
        assert!(!gets.premium && !gets.premium_from_organization);
        assert_eq!(gets.own.row, None);
        assert_eq!(gets.own.state, None);
        assert_eq!(gets.own.gives, None);
        assert!(!gets.own.in_effect());
        assert!(gets.organizations.is_empty());
        // Their own plan is theirs to manage, and Free has no attachments.
        assert!(gets.own.may_manage);
        assert_eq!(gets.own.storage_gb(&Terms::from_config()), Some(0));

        // Someone who doesn't exist gets nothing either.
        let nobody = UserId::from("nobody".to_owned());
        let gets = what_a_person_gets(&nobody, noon(), &conn).await.unwrap();
        assert!(!gets.premium && !gets.premium_from_organization);
    }

    #[rocket::async_test]
    async fn a_trial_the_second_before_and_the_second_after_it_ends() {
        let conn = DbPool::for_test().await;
        let ana = person("ana", &conn).await;
        let ends = noon();
        set(&of(&ana), free(PlanName::Premium, ends, FreeWhy::Trial), &conn).await;

        let before = gets_at(&ana, ends - second(), &conn).await;
        assert!(before.premium);
        assert_eq!(before.own.state, Some(PlanState::Trial));
        assert_eq!(before.own.storage_gb(&Terms::from_config()), Some(CONFIG.plan_premium_storage_gb()));

        // The moment in free_until is the first moment it's over, and a
        // trial has no grace after it.
        for at in [ends, ends + second()] {
            let after = gets_at(&ana, at, &conn).await;
            assert!(!after.premium, "{at}");
            assert_eq!(after.own.state, Some(PlanState::Ended), "{at}");
            assert_eq!(after.own.storage_gb(&Terms::from_config()), Some(0), "{at}");
        }
        // The row is still there, and says what it was.
        assert_eq!(gets_at(&ana, ends + second(), &conn).await.own.row.unwrap().plan, "premium");
    }

    #[rocket::async_test]
    async fn good_standing_then_grace_from_its_first_moment_to_its_last() {
        let conn = DbPool::for_test().await;
        let ana = person("ana", &conn).await;
        let until = noon();
        set(&of(&ana), paid(PlanName::Premium, until, true), &conn).await;

        // Good standing, through the moment in until.
        for at in [until - TimeDelta::days(364), until - second(), until] {
            let gets = gets_at(&ana, at, &conn).await;
            assert!(gets.premium, "{at}");
            assert_eq!(gets.own.state, Some(PlanState::Active), "{at}");
        }
        // Grace: its first moment and its last. Still in effect.
        for at in [until + second(), until + grace()] {
            let gets = gets_at(&ana, at, &conn).await;
            assert!(gets.premium, "{at}");
            assert_eq!(gets.own.state, Some(PlanState::PaymentDue), "{at}");
        }
        // And the second after its last.
        let gets = gets_at(&ana, until + grace() + second(), &conn).await;
        assert!(!gets.premium);
        assert_eq!(gets.own.state, Some(PlanState::Ended));
    }

    #[rocket::async_test]
    async fn a_canceled_plan_gets_no_grace() {
        let conn = DbPool::for_test().await;
        let ana = person("ana", &conn).await;
        let until = noon();
        set(&of(&ana), paid(PlanName::Premium, until, false), &conn).await;

        assert_eq!(premium(&ana, until, &conn).await, (true, false));
        let gets = gets_at(&ana, until + second(), &conn).await;
        assert!(!gets.premium);
        assert_eq!(gets.own.state, Some(PlanState::Ended));
    }

    #[rocket::async_test]
    async fn a_client_is_covered_by_its_msp_until_the_moment_it_leaves() {
        let conn = DbPool::for_test().await;
        let northwind = msp("Northwind IT", &conn).await;
        let clinic = organization("Lakeside Clinic", &conn).await;
        let owner = person("owner", &conn).await;
        join(&owner, &clinic, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        take_on(&northwind, &clinic, &conn).await;

        // The client's own row ended long ago, and the pool has no end.
        set(&of_org(&clinic), paid(PlanName::Business, noon() - TimeDelta::days(400), false), &conn).await;
        let pool = set(&of_msp(&northwind), open(PlanName::Msp), &conn).await;

        let covered = gets_at(&owner, noon(), &conn).await;
        assert!(!covered.premium && covered.premium_from_organization);
        let plan = &covered.organizations[&clinic.uuid];
        assert_eq!(plan.state, Some(PlanState::Active));
        // The row that applies is the pool's, and the client's own is ignored.
        assert_eq!(plan.row.as_ref(), Some(&pool));
        assert_eq!(plan.covered_by, Some((northwind.uuid.clone(), "Northwind IT".to_owned())));
        assert!(plan.gives.unwrap().company_features);
        // Covered by: the pool is the MSP's admins' to manage, not the owner's.
        assert!(!plan.may_manage);

        // The pool ends, and so does what the client gets, whatever its own row says.
        set(&of_org(&clinic), open(PlanName::Business), &conn).await;
        set(&of_msp(&northwind), paid(PlanName::Msp, noon() - second(), false), &conn).await;
        let ended = gets_at(&owner, noon(), &conn).await;
        assert!(!ended.premium_from_organization);
        assert_eq!(state_in(&ended, &clinic), Some(PlanState::Ended));
        assert_eq!(ended.organizations[&clinic.uuid].storage_gb(&Terms::from_config()), Some(0));

        // The moment it leaves, its own row is the one that counts: here, an
        // ended one, at the same time and with the pool in effect again.
        set(&of_org(&clinic), paid(PlanName::Business, noon() - TimeDelta::days(400), false), &conn).await;
        set(&of_msp(&northwind), open(PlanName::Msp), &conn).await;
        assert_eq!(premium(&owner, noon(), &conn).await, (false, true));
        leave(&clinic, &conn).await;
        let left = gets_at(&owner, noon(), &conn).await;
        assert!(!left.premium_from_organization);
        let plan = &left.organizations[&clinic.uuid];
        assert_eq!(plan.state, Some(PlanState::Ended));
        assert_eq!(plan.row.as_ref().map(|row| row.plan.as_str()), Some("business"));
        assert_eq!(plan.covered_by, None);
        assert!(plan.may_manage);
    }

    #[rocket::async_test]
    async fn a_client_with_no_row_of_its_own_has_no_plan_once_it_leaves() {
        let conn = DbPool::for_test().await;
        let northwind = msp("Northwind IT", &conn).await;
        let clinic = organization("Lakeside Clinic", &conn).await;
        let member = person("member", &conn).await;
        join(&member, &clinic, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        take_on(&northwind, &clinic, &conn).await;
        set(&of_msp(&northwind), open(PlanName::Msp), &conn).await;

        assert_eq!(premium(&member, noon(), &conn).await, (false, true));
        leave(&clinic, &conn).await;
        let left = gets_at(&member, noon(), &conn).await;
        assert!(!left.premium_from_organization);
        assert_eq!(left.organizations[&clinic.uuid].row, None);
        assert_eq!(state_in(&left, &clinic), None);
    }

    #[rocket::async_test]
    async fn an_msps_staff_are_covered_while_its_pool_is_in_effect() {
        let conn = DbPool::for_test().await;
        let northwind = msp("Northwind IT", &conn).await;
        let admin = person("admin", &conn).await;
        let tech = person("tech", &conn).await;
        let stranger = person("stranger", &conn).await;
        staff(&northwind, &admin, MspRole::Admin, &conn).await;
        staff(&northwind, &tech, MspRole::Technician, &conn).await;

        // No pool yet: nothing.
        for user in [&admin, &tech, &stranger] {
            assert_eq!(premium(user, noon(), &conn).await, (false, false), "{}", user.email);
        }

        // Admins and technicians both, in no client at all; nobody else.
        let until = noon();
        set(&of_msp(&northwind), paid(PlanName::Msp, until, true), &conn).await;
        for at in [until, until + grace()] {
            assert_eq!(premium(&admin, at, &conn).await, (false, true), "{at}");
            assert_eq!(premium(&tech, at, &conn).await, (false, true), "{at}");
            assert_eq!(premium(&stranger, at, &conn).await, (false, false), "{at}");
        }
        // Covered people get Premium's storage for their own vault.
        let covered = gets_at(&tech, until, &conn).await;
        assert_eq!(covered.own.storage_gb(&Terms::from_config()), Some(CONFIG.plan_premium_storage_gb()));
        assert_eq!(covered.own.row, None);

        // It ends for them when the pool ends.
        let after = until + grace() + second();
        assert_eq!(premium(&admin, after, &conn).await, (false, false));
        assert_eq!(premium(&tech, after, &conn).await, (false, false));
        assert_eq!(gets_at(&tech, after, &conn).await.own.storage_gb(&Terms::from_config()), Some(0));

        // And when they leave the staff.
        MspStaff::find(&northwind.uuid, &tech.uuid, &conn).await.unwrap().delete(&conn).await.unwrap();
        assert_eq!(premium(&tech, until, &conn).await, (false, false));
        assert_eq!(premium(&admin, until, &conn).await, (false, true));
    }

    #[rocket::async_test]
    async fn someone_in_two_organizations_one_ended_and_one_not() {
        let conn = DbPool::for_test().await;
        let ana = person("ana", &conn).await;
        let ended = organization("Old Co", &conn).await;
        let running = organization("New Co", &conn).await;
        join(&ana, &ended, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        join(&ana, &running, MembershipType::User, MembershipStatus::Accepted, &conn).await;
        let until = noon();
        set(&of_org(&ended), paid(PlanName::Business, until - TimeDelta::days(30), false), &conn).await;
        set(&of_org(&running), paid(PlanName::Business, until, false), &conn).await;

        let gets = gets_at(&ana, until, &conn).await;
        assert!(!gets.premium && gets.premium_from_organization);
        assert_eq!(state_in(&gets, &ended), Some(PlanState::Ended));
        assert_eq!(state_in(&gets, &running), Some(PlanState::Active));
        // Each organization's own figures: the ended one gives nothing more.
        let terms = Terms::from_config();
        assert_eq!(gets.organizations[&ended.uuid].storage_gb(&terms), Some(0));
        assert_eq!(gets.organizations[&running.uuid].storage_gb(&terms), Some(CONFIG.plan_org_storage_min_gb()));
        // She manages the one she owns, and not the one she's a member of.
        assert!(gets.organizations[&ended.uuid].may_manage);
        assert!(!gets.organizations[&running.uuid].may_manage);

        // Once the second has ended too, nothing covers her.
        let gets = gets_at(&ana, until + second(), &conn).await;
        assert!(!gets.premium && !gets.premium_from_organization);
        assert_eq!(state_in(&gets, &running), Some(PlanState::Ended));
        assert_eq!(gets.own.storage_gb(&terms), Some(0));
    }

    #[rocket::async_test]
    async fn an_offers_free_months() {
        let conn = DbPool::for_test().await;
        let northwind = msp("Northwind IT", &conn).await;
        let admin = person("admin", &conn).await;
        staff(&northwind, &admin, MspRole::Admin, &conn).await;
        let clinic = organization("Lakeside Clinic", &conn).await;
        let member = person("member", &conn).await;
        join(&member, &clinic, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        take_on(&northwind, &clinic, &conn).await;

        // Six months free, and nothing paid.
        let free_until = chrono::NaiveDate::from_ymd_opt(2027, 9, 1).unwrap().and_hms_opt(12, 0, 0).unwrap();
        let pool = set(&of_msp(&northwind), free(PlanName::Msp, free_until, FreeWhy::Offer), &conn).await;
        assert_eq!(pool.free_why(), Some(FreeWhy::Offer));

        for at in [noon(), free_until - second()] {
            assert_eq!(premium(&admin, at, &conn).await, (false, true), "{at}");
            let gets = gets_at(&member, at, &conn).await;
            assert!(gets.premium_from_organization, "{at}");
            assert_eq!(state_in(&gets, &clinic), Some(PlanState::Trial), "{at}");
        }
        // When the months are over, with nothing paid, so is the plan.
        assert_eq!(premium(&admin, free_until, &conn).await, (false, false));
        let gets = gets_at(&member, free_until, &conn).await;
        assert!(!gets.premium_from_organization);
        assert_eq!(state_in(&gets, &clinic), Some(PlanState::Ended));

        // A pool that started paying during the offer carries on after it.
        let mut paying = free(PlanName::Msp, free_until, FreeWhy::Offer);
        paying.standing = Standing::Open;
        paying.renews = true;
        set(&of_msp(&northwind), paying, &conn).await;
        assert_eq!(premium(&admin, free_until, &conn).await, (false, true));
        assert_eq!(state_in(&gets_at(&member, free_until, &conn).await, &clinic), Some(PlanState::Active));
    }

    #[rocket::async_test]
    async fn only_people_who_have_joined_hold_a_seat() {
        let conn = DbPool::for_test().await;
        let acme = organization("Acme", &conn).await;
        set(&of_org(&acme), open(PlanName::Business), &conn).await;
        let invited = person("invited", &conn).await;
        let accepted = person("accepted", &conn).await;
        let confirmed = person("confirmed", &conn).await;
        let revoked = person("revoked", &conn).await;
        join(&invited, &acme, MembershipType::User, MembershipStatus::Invited, &conn).await;
        join(&accepted, &acme, MembershipType::User, MembershipStatus::Accepted, &conn).await;
        join(&confirmed, &acme, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        let mut gone = join(&revoked, &acme, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        assert!(gone.revoke());
        gone.save(&conn).await.unwrap();

        assert_eq!(premium(&accepted, noon(), &conn).await, (false, true));
        assert_eq!(premium(&confirmed, noon(), &conn).await, (false, true));
        for user in [&invited, &revoked] {
            let gets = gets_at(user, noon(), &conn).await;
            assert!(!gets.premium_from_organization, "{}", user.email);
            assert!(gets.organizations.is_empty(), "{}", user.email);
        }
        assert_eq!(seats_of(&acme, None, &conn).await, 2);

        // Restored, they hold their seat again.
        assert!(gone.restore());
        gone.save(&conn).await.unwrap();
        assert_eq!(premium(&revoked, noon(), &conn).await, (false, true));
        assert_eq!(seats_of(&acme, None, &conn).await, 3);
    }

    async fn seats_of(org: &Organization, msp: Option<&Msp>, conn: &DbConn) -> i64 {
        conn.run(move |conn| seats(conn, &org.uuid, msp.map(|msp| &msp.uuid))).await.unwrap()
    }

    #[rocket::async_test]
    async fn a_clients_storage_counts_its_people_and_not_the_msps_staff() {
        let conn = DbPool::for_test().await;
        let northwind = msp("Northwind IT", &conn).await;
        let clinic = organization("Lakeside Clinic", &conn).await;
        take_on(&northwind, &clinic, &conn).await;
        set(&of_msp(&northwind), open(PlanName::Msp), &conn).await;
        for name in ["one", "two", "three"] {
            let user = person(name, &conn).await;
            join(&user, &clinic, MembershipType::User, MembershipStatus::Confirmed, &conn).await;
        }
        let admin = person("admin", &conn).await;
        let tech = person("tech", &conn).await;
        staff(&northwind, &admin, MspRole::Admin, &conn).await;
        staff(&northwind, &tech, MspRole::Technician, &conn).await;
        join(&admin, &clinic, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        join(&tech, &clinic, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;

        assert_eq!(seats_of(&clinic, Some(&northwind), &conn).await, 3);
        assert_eq!(seats_of(&clinic, None, &conn).await, 5);

        // 2 GB a seat here, so the figure shows which seats were counted.
        let terms = Terms {
            org_storage_gb_per_person: 2,
            org_storage_min_gb: 1,
            ..site_terms()
        };
        let whose = of_org(&clinic);
        let plan = conn.run(|conn| plan_now(conn, &whose, None, noon(), &terms)).await.unwrap();
        assert_eq!(plan.storage_gb(&terms), Some(6));
        assert!(!plan.may_manage);

        // Once it leaves with a plan of its own, the same people are all its own.
        leave(&clinic, &conn).await;
        set(&whose, open(PlanName::Business), &conn).await;
        let plan = conn.run(|conn| plan_now(conn, &whose, None, noon(), &terms)).await.unwrap();
        assert_eq!(plan.storage_gb(&terms), Some(10));
    }

    #[rocket::async_test]
    async fn who_may_manage_a_plan() {
        let conn = DbPool::for_test().await;
        let acme = organization("Acme", &conn).await;
        let owner = person("owner", &conn).await;
        let owner_to_be = person("owner-to-be", &conn).await;
        let admin = person("admin", &conn).await;
        let member = person("member", &conn).await;
        let stranger = person("stranger", &conn).await;
        join(&owner, &acme, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        join(&owner_to_be, &acme, MembershipType::Owner, MembershipStatus::Accepted, &conn).await;
        join(&admin, &acme, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        join(&member, &acme, MembershipType::User, MembershipStatus::Confirmed, &conn).await;

        let northwind = msp("Northwind IT", &conn).await;
        let other_msp = msp("Fabrikam IT", &conn).await;
        let msp_admin = person("msp-admin", &conn).await;
        let tech = person("tech", &conn).await;
        let other_admin = person("other-admin", &conn).await;
        staff(&northwind, &msp_admin, MspRole::Admin, &conn).await;
        staff(&northwind, &tech, MspRole::Technician, &conn).await;
        staff(&other_msp, &other_admin, MspRole::Admin, &conn).await;
        let clinic = organization("Lakeside Clinic", &conn).await;
        let clinic_owner = person("clinic-owner", &conn).await;
        join(&clinic_owner, &clinic, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        // The MSP's people are members of the client too, as owners even.
        join(&msp_admin, &clinic, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        join(&tech, &clinic, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;
        take_on(&northwind, &clinic, &conn).await;

        let everyone =
            [&owner, &owner_to_be, &admin, &member, &stranger, &msp_admin, &tech, &other_admin, &clinic_owner];
        // Whose plan, and the only people who may manage it.
        let cases = [
            // A person's own, and nobody else's.
            (of(&member), vec![&member]),
            // An organization's confirmed owners.
            (of_org(&acme), vec![&owner]),
            // An MSP's admins, for its pool.
            (of_msp(&northwind), vec![&msp_admin]),
            (of_msp(&other_msp), vec![&other_admin]),
            // A client is covered by the pool, so the MSP's admins, and not
            // its own owners, nor a technician who is an owner there.
            (of_org(&clinic), vec![&msp_admin]),
            // Nothing that doesn't exist.
            (PlanOwner::Organization("no-such-organization".to_owned().into()), vec![]),
            (PlanOwner::Msp("no-such-msp".to_owned().into()), vec![]),
        ];
        for (whose, managers) in &cases {
            for user in everyone {
                let may = may_manage_plan(&user.uuid, whose, &conn).await.unwrap();
                let expected = managers.iter().any(|manager| manager.uuid == user.uuid);
                assert_eq!(may, expected, "{} managing the plan of {whose}", user.email);
                // What the sync says is the same answer.
                let plan = plan_at(whose, Some(&user.uuid), noon(), &conn).await.unwrap();
                assert_eq!(plan.may_manage, expected, "{} in the sync for {whose}", user.email);
            }
        }

        // Once the client leaves, its plan is its own owners' again.
        leave(&clinic, &conn).await;
        assert!(may_manage_plan(&clinic_owner.uuid, &of_org(&clinic), &conn).await.unwrap());
        assert!(!may_manage_plan(&other_admin.uuid, &of_org(&clinic), &conn).await.unwrap());
    }

    #[rocket::async_test]
    async fn an_owner_has_one_row_which_the_operator_replaces() {
        let conn = DbPool::for_test().await;
        let ana = person("ana", &conn).await;
        let whose = of(&ana);
        assert_eq!(Plan::find(&whose, &conn).await.unwrap(), None);

        // Nobody to give a plan to.
        let nobody = PlanOwner::User("nobody".to_owned().into());
        assert!(!Plan::owner_exists(&nobody, &conn).await.unwrap());
        let write = free(PlanName::Premium, noon(), FreeWhy::Trial);
        assert_eq!(Plan::set(&nobody, write.clone(), SetBy::Operator, &conn).await.unwrap(), None);
        assert_eq!(Plan::find(&nobody, &conn).await.unwrap(), None);

        // The first write has nothing before it.
        let (before, first) = Plan::set(&whose, write, SetBy::Operator, &conn).await.unwrap().unwrap();
        assert_eq!(before, None);
        assert_eq!(first.user_uuid.as_ref(), Some(&ana.uuid));
        assert_eq!((first.org_uuid.as_ref(), first.msp_uuid.as_ref()), (None, None));
        assert_eq!(
            (first.plan.as_str(), first.standing.as_str(), first.set_by.as_str()),
            ("premium", "none", "operator")
        );
        assert_eq!((first.free_until, first.free_why.as_deref()), (Some(noon()), Some("trial")));
        assert_eq!(first.billed, "by_hand");

        // What a provider recorded on the row stays through the operator's write.
        let checked = noon() - TimeDelta::days(1);
        let id = first.uuid.clone();
        conn.run(move |conn| {
            diesel::update(plans::table.filter(plans::uuid.eq(&id)))
                .set((
                    plans::provider.eq("stand-in"),
                    plans::provider_customer.eq("customer-1"),
                    plans::provider_subscription.eq("subscription-1"),
                    plans::checked_at.eq(checked),
                ))
                .execute(conn)
        })
        .await
        .unwrap();

        // The second replaces it: the same row, with the old one handed back.
        let mut write = paid(PlanName::Premium, noon(), true);
        write.billed = Billed::Prepaid;
        let (before, after) = Plan::set(&whose, write, SetBy::Operator, &conn).await.unwrap().unwrap();
        let before = before.unwrap();
        assert_eq!(before.uuid, first.uuid);
        assert_eq!(before.free_until, Some(noon()));
        assert_eq!(after.uuid, first.uuid);
        assert_eq!((after.free_until, after.free_why.as_deref()), (None, None));
        assert_eq!((after.standing.as_str(), after.until, after.renews), ("until", Some(noon()), true));
        assert_eq!(after.billed, "prepaid");
        assert_eq!(after.provider.as_deref(), Some("stand-in"));
        assert_eq!(after.provider_customer.as_deref(), Some("customer-1"));
        assert_eq!(after.provider_subscription.as_deref(), Some("subscription-1"));
        assert_eq!(after.checked_at, Some(checked));
        assert_eq!(Plan::find(&whose, &conn).await.unwrap(), Some(after.clone()));
        let rows = conn.run(|conn| plans::table.count().get_result::<i64>(conn)).await.unwrap();
        assert_eq!(rows, 1);

        // Removed, the person is on Free again, and there's nothing more to remove.
        assert_eq!(Plan::remove(&whose, &conn).await.unwrap(), Some(after));
        assert_eq!(Plan::remove(&whose, &conn).await.unwrap(), None);
        assert_eq!(premium(&ana, noon() - second(), &conn).await, (false, false));
    }

    #[rocket::async_test]
    async fn a_plan_goes_with_its_owner() {
        let conn = DbPool::for_test().await;
        let ana = person("ana", &conn).await;
        let acme = organization("Acme", &conn).await;
        set(&of(&ana), open(PlanName::Premium), &conn).await;
        set(&of_org(&acme), open(PlanName::Business), &conn).await;
        let (hers, its) = (of(&ana), of_org(&acme));

        acme.delete(&conn).await.unwrap();
        assert_eq!(Plan::find(&its, &conn).await.unwrap(), None);
        assert!(Plan::find(&hers, &conn).await.unwrap().is_some());
        ana.delete(&conn).await.unwrap();
        assert_eq!(Plan::find(&hers, &conn).await.unwrap(), None);
    }

    #[rocket::async_test]
    async fn the_people_a_plan_reaches() {
        let conn = DbPool::for_test().await;
        let northwind = msp("Northwind IT", &conn).await;
        let admin = person("admin", &conn).await;
        let tech = person("tech", &conn).await;
        staff(&northwind, &admin, MspRole::Admin, &conn).await;
        staff(&northwind, &tech, MspRole::Technician, &conn).await;
        let clinic = organization("Lakeside Clinic", &conn).await;
        let nurse = person("nurse", &conn).await;
        let invited = person("invited", &conn).await;
        join(&nurse, &clinic, MembershipType::User, MembershipStatus::Accepted, &conn).await;
        join(&invited, &clinic, MembershipType::User, MembershipStatus::Invited, &conn).await;
        join(&tech, &clinic, MembershipType::Admin, MembershipStatus::Confirmed, &conn).await;
        take_on(&northwind, &clinic, &conn).await;
        let other = organization("Own Co", &conn).await;
        let boss = person("boss", &conn).await;
        join(&boss, &other, MembershipType::Owner, MembershipStatus::Confirmed, &conn).await;

        let reached = async |whose: PlanOwner| {
            let mut people = people_a_plan_reaches(&whose, &conn).await.unwrap();
            people.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
            people
        };
        let these = |users: &[&User]| {
            let mut people: Vec<UserId> = users.iter().map(|user| user.uuid.clone()).collect();
            people.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
            people
        };
        assert_eq!(reached(of(&nurse)).await, these(&[&nurse]));
        assert_eq!(reached(of_org(&clinic)).await, these(&[&nurse, &tech]));
        assert_eq!(reached(of_org(&other)).await, these(&[&boss]));
        // The pool: the staff, and everyone in each client, each of them once.
        assert_eq!(reached(of_msp(&northwind)).await, these(&[&admin, &tech, &nurse]));
    }

    // What the sync is told.

    /// A plan as the sync has it, for someone who may or may not manage it.
    fn as_it_stands(whose: PlanOwner, row: Option<Plan>, at: NaiveDateTime, seats: i64, may_manage: bool) -> PlanNow {
        let terms = site_terms();
        PlanNow {
            state: row.as_ref().map(|row| row.state_at(at, terms.grace_days)),
            gives: row.as_ref().and_then(Plan::name).map(|name| name.gives(seats, &terms)),
            whose,
            row,
            covered_by: None,
            may_manage,
            through_organization: false,
        }
    }

    /// An organization in a profile, as the server sends it today.
    fn org_today() -> Value {
        json!({
            "id": "acme",
            "enabled": true,
            "usersGetPremium": true,
            "maxStorageGb": i16::MAX,
            "seats": 20,
            "productTierType": 3,
            "maxCollections": null,
            "useTotp": true,
            "usePolicies": true,
            "useGroups": true,
            "useEvents": true,
            "useSso": false,
            "useScim": false,
            "useResetPassword": true,
            "useCustomPermissions": true,
            "useApi": true,
            "planType": 6,
            "selfHost": true,
        })
    }

    #[test]
    fn free_in_the_sync() {
        let me = PlanOwner::User("ana".to_owned().into());
        let plan = as_it_stands(me, None, noon(), 0, true);
        assert_eq!(
            plan.to_json(&site_terms()),
            json!({
                "enforced": true,
                "plan": "free",
                "state": null,
                "freeUntil": null,
                "freeWhy": null,
                "until": null,
                "renews": null,
                "storageGb": 0,
                "people": null,
                "coveredBy": null,
                "canManage": true,
            })
        );
        assert_eq!(not_enforced_json(), json!({ "enforced": false }));
    }

    #[test]
    fn the_dates_and_a_payment_due_are_only_for_whoever_manages_the_plan() {
        let acme = PlanOwner::Organization("acme".to_owned().into());
        let until = noon();
        let row = Plan {
            org_uuid: Some("acme".to_owned().into()),
            free_until: Some(until - TimeDelta::days(350)),
            free_why: Some("trial".to_owned()),
            standing: "until".to_owned(),
            until: Some(until),
            renews: true,
            ..row(PlanName::Business)
        };
        let in_grace = until + second();

        let owner = as_it_stands(acme.clone(), Some(row.clone()), in_grace, 12, true).to_json(&site_terms());
        assert_eq!(
            owner,
            json!({
                "enforced": true,
                "plan": "business",
                "state": "paymentDue",
                "freeUntil": format_date(&(until - TimeDelta::days(350))),
                "freeWhy": "trial",
                "until": format_date(&until),
                "renews": true,
                "storageGb": 12,
                "people": null,
                "coveredBy": null,
                "canManage": true,
            })
        );

        // A member is told what they get, which grace doesn't change.
        let member = as_it_stands(acme.clone(), Some(row.clone()), in_grace, 12, false).to_json(&site_terms());
        assert_eq!(
            member,
            json!({
                "enforced": true,
                "plan": "business",
                "state": "active",
                "freeUntil": null,
                "freeWhy": null,
                "until": null,
                "renews": null,
                "storageGb": 12,
                "people": null,
                "coveredBy": null,
                "canManage": false,
            })
        );
        // Ended is ended for everyone.
        let after = until + TimeDelta::days(15);
        let member = as_it_stands(acme, Some(row), after, 12, false).to_json(&site_terms());
        assert_eq!(member["state"], "ended");
        assert_eq!(member["storageGb"], 0);
    }

    #[test]
    fn a_covered_client_says_who_covers_it() {
        let clinic = PlanOwner::Organization("clinic".to_owned().into());
        let pool = Plan {
            msp_uuid: Some("northwind".to_owned().into()),
            standing: "open".to_owned(),
            renews: true,
            ..row(PlanName::Msp)
        };
        let mut plan = as_it_stands(clinic, Some(pool), noon(), 8, false);
        plan.covered_by = Some(("northwind".to_owned().into(), "Northwind IT".to_owned()));
        let json = plan.to_json(&site_terms());
        assert_eq!(json["plan"], "msp");
        assert_eq!(json["state"], "active");
        assert_eq!(json["coveredBy"], json!({ "id": "northwind", "name": "Northwind IT" }));
        assert_eq!(json["canManage"], false);
        assert_eq!(json["storageGb"], 8);

        // A pool has no storage of its own.
        let msp = PlanOwner::Msp("northwind".to_owned().into());
        let pool = plan.row.clone();
        assert_eq!(as_it_stands(msp, pool, noon(), 0, true).to_json(&site_terms())["storageGb"], Value::Null);
    }

    #[test]
    fn an_organizations_fields_in_a_profile() {
        let terms = site_terms();
        let acme = PlanOwner::Organization("acme".to_owned().into());
        let good = |plan: PlanName| Plan {
            org_uuid: Some("acme".to_owned().into()),
            standing: "until".to_owned(),
            until: Some(noon()),
            ..row(plan)
        };

        // Business, in effect: the company features as they are today.
        let mut org = org_today();
        put_in_organization(
            &mut org,
            &as_it_stands(acme.clone(), Some(good(PlanName::Business)), noon(), 12, true),
            &terms,
        );
        let mut expected = org_today();
        expected["maxStorageGb"] = 12.into();
        expected["seats"] = Value::Null;
        expected["keykeeperPlan"] = org["keykeeperPlan"].clone();
        assert_eq!(org, expected);
        assert_eq!(org["keykeeperPlan"]["plan"], "business");

        // Ended: nothing more from the plan, and the organization still enabled.
        let mut org = org_today();
        let ended = as_it_stands(acme.clone(), Some(good(PlanName::Business)), noon() + second(), 12, true);
        put_in_organization(&mut org, &ended, &terms);
        let mut expected = org_today();
        expected["usersGetPremium"] = false.into();
        expected["maxStorageGb"] = 0.into();
        expected["seats"] = Value::Null;
        expected["keykeeperPlan"] = org["keykeeperPlan"].clone();
        assert_eq!(org, expected);
        assert_eq!(org["enabled"], true);
        assert_eq!(org["keykeeperPlan"]["state"], "ended");

        // A family: six people, and no company features, in effect or not.
        for at in [noon(), noon() + second()] {
            let mut org = org_today();
            let family = as_it_stands(acme.clone(), Some(good(PlanName::Families)), at, 4, true);
            put_in_organization(&mut org, &family, &terms);
            assert_eq!(org["seats"], 6, "{at}");
            assert_eq!(org["productTierType"], 1, "{at}");
            for field in COMPANY_FEATURE_FIELDS {
                assert_eq!(org[field], false, "{field} at {at}");
            }
            assert_eq!(org["usersGetPremium"], at == noon(), "{at}");
            assert_eq!(
                org["maxStorageGb"],
                if at == noon() {
                    5
                } else {
                    0
                },
                "{at}"
            );
            assert_eq!(org["keykeeperPlan"]["people"], 6, "{at}");
            for field in ["enabled", "useTotp"] {
                assert_eq!(org[field], true, "{field} at {at}");
            }
            assert_eq!(org["maxCollections"], Value::Null, "{at}");
            assert_eq!((&org["planType"], &org["selfHost"]), (&json!(6), &json!(true)), "{at}");
        }

        // No row at all: no plan, with the company features as they are today.
        let mut org = org_today();
        put_in_organization(&mut org, &as_it_stands(acme, None, noon(), 3, false), &terms);
        let mut expected = org_today();
        expected["usersGetPremium"] = false.into();
        expected["maxStorageGb"] = 0.into();
        expected["seats"] = Value::Null;
        expected["keykeeperPlan"] = org["keykeeperPlan"].clone();
        assert_eq!(org, expected);
        assert_eq!(org["keykeeperPlan"]["plan"], Value::Null);
        assert_eq!(org["keykeeperPlan"]["state"], Value::Null);
    }
}

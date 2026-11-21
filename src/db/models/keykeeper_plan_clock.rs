// Keykeeper: the trial clock, and what the clock does to a plan by itself
// (DESIGN.md, "Plans and billing": "The trial clock" and "What happens when
// payment stops", in the meta repo).
//
// - The server writes a trial (`free_until` PLAN_TRIAL_DAYS out, reason
//   `trial`) for a new organization, a new MSP's pool, a client the moment it
//   leaves its MSP, and an organization or an MSP found with no row. Every
//   new organization starts as Business: there's no Family preset yet.
// - The reminders: a trial's 7 and 1 days before `free_until`, and for a plan
//   set to renew, 3 days before its grace ends and when it has. Which one is
//   due is worked out from a row and a time (`reminder_due`), and
//   `plan_notices` keeps each from going twice.
// - When the clock moves a plan into another state, the people it reaches
//   are sent the sync notice once (`clock_changes`).
//
// All of it only where plans are enforced: the callers check, and with
// PLANS_ENFORCED off nothing here is called. Nothing here takes a payment or
// talks to a provider, and no request from a signed-in person writes a plan.

use std::collections::HashSet;

use chrono::{NaiveDateTime, TimeDelta, Utc};
use diesel::prelude::*;

use crate::{
    CONFIG,
    api::ApiResult,
    db::{
        DbConn, DbConnInner,
        keykeeper_schema::{msp_clients, msp_staff, msps, plan_notices, plans},
        schema::{organizations, users, users_organizations},
    },
    error::MapResult,
};

use super::{
    MembershipStatus, MembershipType, MspId, MspRole, OrganizationId, UserId,
    keykeeper_plans::{
        Billed, FreeWhy, Plan, PlanName, PlanOwner, PlanState, SetBy, Standing, find_row, owner_exists, writing_plan,
    },
};

type Query<T> = Result<T, diesel::result::Error>;

/// Runs `insert` in a savepoint of its own and answers whether it wrote
/// anything: false when a row with the same key was there already (written
/// by another request or job at the same moment), which isn't an error.
fn insert_once(conn: &mut DbConnInner, insert: impl FnOnce(&mut DbConnInner) -> Query<usize>) -> Query<bool> {
    match conn.transaction(insert) {
        Ok(written) => Ok(written > 0),
        Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// The trial the server writes for an organization or an MSP: `days` from
/// `at`, nothing paid. A person gets none: Free is how a person tries
/// PassBundle. Every organization is Business, since there's no Family
/// preset yet.
fn trial_row(whose: &PlanOwner, at: NaiveDateTime, days: i64) -> Option<Plan> {
    let (org_uuid, msp_uuid, plan) = match whose {
        PlanOwner::Organization(id) => (Some(id.clone()), None, PlanName::Business),
        PlanOwner::Msp(id) => (None, Some(id.clone()), PlanName::Msp),
        PlanOwner::User(_) => return None,
    };
    Some(Plan {
        uuid: crate::util::get_uuid(),
        user_uuid: None,
        org_uuid,
        msp_uuid,
        plan: plan.as_str().to_owned(),
        free_until: at.checked_add_signed(TimeDelta::try_days(days)?),
        free_why: Some(FreeWhy::Trial.as_str().to_owned()),
        standing: Standing::None.as_str().to_owned(),
        until: None,
        renews: false,
        billed: Billed::ByTheDay.as_str().to_owned(),
        set_by: SetBy::Server.as_str().to_owned(),
        provider: None,
        provider_customer: None,
        provider_subscription: None,
        checked_at: None,
        updated_at: at,
    })
}

/// Gives an organization or an MSP with no row a trial from `at`, and
/// answers the row it has then. A row that's already there is left as it is,
/// and so is a person, who gets no trial, and an owner that doesn't exist.
/// The row is looked for again with the plan's lock held (`writing_plan`),
/// so an operator's save at the same moment is never written over, nor fails.
pub(super) fn start_trial(
    conn: &mut DbConnInner,
    whose: &PlanOwner,
    at: NaiveDateTime,
    days: i64,
) -> Query<Option<Plan>> {
    if let Some(row) = find_row(conn, whose)? {
        return Ok(Some(row));
    }
    let Some(trial) = trial_row(whose, at, days) else {
        return Ok(None);
    };
    writing_plan(conn, whose, |conn| {
        if let Some(row) = find_row(conn, whose)? {
            return Ok(Some(row));
        }
        if !owner_exists(conn, whose)? {
            return Ok(None);
        }
        insert_once(conn, |conn| diesel::insert_into(plans::table).values(&trial).execute(conn))?;
        find_row(conn, whose)
    })
}

/// The organization or the MSP was just created: its trial starts now
/// (PLAN_TRIAL_DAYS). Only where plans are enforced.
pub async fn start_trial_now(whose: &PlanOwner, conn: &DbConn) -> ApiResult<()> {
    if !CONFIG.plans_enforced() {
        return Ok(());
    }
    let (at, days) = (Utc::now().naive_utc(), CONFIG.plan_trial_days());
    conn.run(move |conn| start_trial(conn, whose, at, days).map(|_| ()).map_res("Error starting a trial")).await
}

/// A client that leaves its MSP gets `days` from `at` to make its own
/// arrangement: its own row's `free_until` moves out to then, unless it was
/// later already, and it gets a trial if it has no row. A plan of its own
/// that's paid for stays paid for.
pub(super) fn left_msp(conn: &mut DbConnInner, org: &OrganizationId, at: NaiveDateTime, days: i64) -> Query<()> {
    let whose = PlanOwner::Organization(org.clone());
    let Some(until) = TimeDelta::try_days(days).and_then(|days| at.checked_add_signed(days)) else {
        return Ok(());
    };
    writing_plan(conn, &whose, |conn| match find_row(conn, &whose)? {
        Some(row) if row.free_until.is_some_and(|free_until| free_until >= until) => Ok(()),
        Some(row) => diesel::update(plans::table.filter(plans::uuid.eq(&row.uuid)))
            .set((
                plans::free_until.eq(Some(until)),
                plans::free_why.eq(Some(FreeWhy::Trial.as_str())),
                plans::set_by.eq(SetBy::Server.as_str()),
                plans::updated_at.eq(at),
            ))
            .execute(conn)
            .map(|_| ()),
        None => start_trial(conn, &whose, at, days).map(|_| ()),
    })
}

/// The organization just left its MSP. Only where plans are enforced.
pub async fn after_leaving_msp(org: &OrganizationId, conn: &DbConn) -> ApiResult<()> {
    if !CONFIG.plans_enforced() {
        return Ok(());
    }
    let (at, days) = (Utc::now().naive_utc(), CONFIG.plan_trial_days());
    conn.run(move |conn| {
        left_msp(conn, org, at, days).map_res("Error starting a trial for an organization that left its MSP")
    })
    .await
}

/// Every organization that isn't an MSP's client, and every MSP, with no row
/// gets a trial from `at`: the job finds them, so the clock starts for an
/// organization nobody has opened since enforcement was turned on. A client
/// that joined with a code keeps its own plan (pool_clients), so it counts as
/// an organization here.
fn start_missing_trials(conn: &mut DbConnInner, at: NaiveDateTime, days: i64) -> Query<usize> {
    let with_rows: HashSet<String> = plans::table
        .select((plans::org_uuid, plans::msp_uuid))
        .load::<(Option<OrganizationId>, Option<MspId>)>(conn)?
        .into_iter()
        .flat_map(|(org, msp)| [org.map(|id| id.to_string()), msp.map(|id| id.to_string())])
        .flatten()
        .collect();
    let clients = pool_clients(conn)?;
    let mut missing: Vec<PlanOwner> = organizations::table
        .select(organizations::uuid)
        .load::<OrganizationId>(conn)?
        .into_iter()
        .filter(|org| !clients.contains(org) && !with_rows.contains(org.as_ref()))
        .map(PlanOwner::Organization)
        .collect();
    missing.extend(
        msps::table
            .select(msps::uuid)
            .load::<MspId>(conn)?
            .into_iter()
            .filter(|msp| !with_rows.contains(msp.as_ref()))
            .map(PlanOwner::Msp),
    );
    for whose in &missing {
        start_trial(conn, whose, at, days)?;
    }
    Ok(missing.len())
}

/// The reminder emails ("What happens when payment stops"). "At the
/// failure" waits for a payment provider (pieces 8 and 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reminder {
    /// A trial or an offer that ends in 7 days or less, with nothing paid.
    TrialSevenDays,
    /// The same, in a day or less.
    TrialOneDay,
    /// A plan set to renew, in grace, whose grace ends in 3 days or less.
    GraceThreeDays,
    /// The same plan, whose grace has ended.
    GraceEnded,
}

/// A trial's reminders, in days before it ends.
const TRIAL_FIRST: i64 = 7;
const TRIAL_LAST: i64 = 1;
/// Grace's reminder, in days before it ends.
const GRACE_LAST: i64 = 3;
/// How long after grace ends its email may still go, for a job that didn't
/// run then. Past it, the email would be news to nobody.
const ENDED_LATE: i64 = 7;

impl Reminder {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TrialSevenDays => "trial_7_days",
            Self::TrialOneDay => "trial_1_day",
            Self::GraceThreeDays => "grace_3_days",
            Self::GraceEnded => "grace_ended",
        }
    }
}

/// Which reminder is due for `row` at `at`, if any, and the moment it's
/// about: when the free time ends, or the grace. At most one is due at a
/// time, so a job that runs late sends the one that's true now and not the
/// ones it missed.
///
/// - A trial's, while it's a trial that ends with nothing to follow it: not
///   once it's paid for, nor when grace would follow it.
/// - Grace's, while payment is due, for a plan that was set to renew.
/// - Grace's end, for such a plan once its grace has ended, unless free time
///   ran on past it.
pub fn reminder_due(row: &Plan, at: NaiveDateTime, grace_days: i64) -> Option<(Reminder, NaiveDateTime)> {
    match row.state_at(at, grace_days) {
        PlanState::Trial => {
            let free_until = row.free_until?;
            if row.state_at(free_until, grace_days) != PlanState::Ended {
                return None;
            }
            let left = free_until - at;
            if left <= TimeDelta::days(TRIAL_LAST) {
                Some((Reminder::TrialOneDay, free_until))
            } else if left <= TimeDelta::days(TRIAL_FIRST) {
                Some((Reminder::TrialSevenDays, free_until))
            } else {
                None
            }
        }
        PlanState::PaymentDue => {
            let ends = row.grace_ends(grace_days)?;
            (ends - at <= TimeDelta::days(GRACE_LAST)).then_some((Reminder::GraceThreeDays, ends))
        }
        PlanState::Ended => {
            let ends = row.grace_ends(grace_days)?;
            let ended_by_grace = row.ends_at(grace_days) == Some(ends);
            (ended_by_grace && at - ends <= TimeDelta::days(ENDED_LATE)).then_some((Reminder::GraceEnded, ends))
        }
        PlanState::Active => None,
    }
}

/// What the plans' clock has already done (`plan_notices`).
#[derive(Clone, Debug, PartialEq, Eq, Identifiable, Queryable, Insertable)]
#[diesel(table_name = plan_notices)]
#[diesel(primary_key(plan_uuid, notice, about))]
pub struct PlanNotice {
    pub plan_uuid: String,
    pub notice: String,
    pub about: NaiveDateTime,
    pub sent_at: NaiveDateTime,
}

/// Notes that `notice` about `about` went for the plan, and answers whether
/// it's the first time.
fn note(conn: &mut DbConnInner, plan: &str, notice: &str, about: NaiveDateTime, at: NaiveDateTime) -> Query<bool> {
    let row = PlanNotice {
        plan_uuid: plan.to_owned(),
        notice: notice.to_owned(),
        about,
        sent_at: at,
    };
    insert_once(conn, |conn| diesel::insert_into(plan_notices::table).values(&row).execute(conn))
}

/// A plan's owner, from its row.
fn owner_of(row: &Plan) -> Option<PlanOwner> {
    match (&row.user_uuid, &row.org_uuid, &row.msp_uuid) {
        (Some(user), None, None) => Some(PlanOwner::User(user.clone())),
        (None, Some(org), None) => Some(PlanOwner::Organization(org.clone())),
        (None, None, Some(msp)) => Some(PlanOwner::Msp(msp.clone())),
        _ => None,
    }
}

/// The clients an MSP's pool covers: every MSP's client except those that
/// joined with a code, which keep their own plan until the owner decides who
/// pays (DESIGN.md, "Plans and billing", decision 14).
fn pool_clients(conn: &mut DbConnInner) -> Query<HashSet<OrganizationId>> {
    Ok(msp_clients::table
        .filter(msp_clients::joined_with_code.eq(false))
        .select(msp_clients::org_uuid)
        .load::<OrganizationId>(conn)?
        .into_iter()
        .collect())
}

/// The rows the clock looks at: every one but a client's own, which is
/// ignored while its MSP's pool covers it.
fn rows_in_force(conn: &mut DbConnInner) -> Query<Vec<(Plan, PlanOwner)>> {
    let clients = pool_clients(conn)?;
    Ok(plans::table
        .load::<Plan>(conn)?
        .into_iter()
        .filter_map(|row| owner_of(&row).map(|whose| (row, whose)))
        .filter(|(_, whose)| !matches!(whose, PlanOwner::Organization(org) if clients.contains(org)))
        .collect())
}

/// The plans whose state the clock has moved since they were written, each
/// answered once for each state it moves into, for the sync notice. A plan's
/// state at the moment it was written is what its writer already told
/// people (the operator's route sends the notice), so only a state that
/// differs from it counts.
fn clock_changes_at(conn: &mut DbConnInner, at: NaiveDateTime, grace_days: i64) -> Query<Vec<PlanOwner>> {
    let mut changed = Vec::new();
    for (row, whose) in rows_in_force(conn)? {
        let now = row.state_at(at, grace_days);
        if now == row.state_at(row.updated_at, grace_days) {
            continue;
        }
        if note(conn, &row.uuid, &format!("state_{}", now.as_str()), row.updated_at, at)? {
            changed.push(whose);
        }
    }
    Ok(changed)
}

/// A reminder to send: whose plan it is, what for, and to whom.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DueReminder {
    pub plan_uuid: String,
    pub whose: PlanOwner,
    pub reminder: Reminder,
    /// The moment it's about: when the free time ends, or the grace.
    pub about: NaiveDateTime,
    /// The plan as it stands, for the dates in the email.
    pub row: Plan,
    /// The organization's or the MSP's name. None for a person.
    pub name: Option<String>,
    /// How many clients an MSP's pool covers.
    pub clients: usize,
    /// Whoever manages the plan: the person, an organization's confirmed
    /// owners, or an MSP's admins.
    pub to: Vec<String>,
}

/// The email addresses of whoever manages a plan (the rule in `may_manage`,
/// keykeeper_plans.rs, for a plan that isn't a covered client's).
fn managers(conn: &mut DbConnInner, whose: &PlanOwner) -> Query<Vec<String>> {
    let people: Vec<UserId> = match whose {
        PlanOwner::User(user) => vec![user.clone()],
        PlanOwner::Organization(org) => users_organizations::table
            .filter(users_organizations::org_uuid.eq(org))
            .filter(users_organizations::atype.eq(MembershipType::Owner as i32))
            .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
            .select(users_organizations::user_uuid)
            .load::<UserId>(conn)?,
        PlanOwner::Msp(msp) => msp_staff::table
            .filter(msp_staff::msp_uuid.eq(msp))
            .filter(msp_staff::role.eq(MspRole::Admin as i32))
            .select(msp_staff::user_uuid)
            .load::<UserId>(conn)?,
    };
    let mut emails = users::table.filter(users::uuid.eq_any(people)).select(users::email).load::<String>(conn)?;
    emails.sort();
    Ok(emails)
}

/// The reminders due at `at`, each noted as sent before it's answered, so
/// none goes twice. A reminder that couldn't be sent to anyone is forgotten
/// again (`PlanNotice::forget`), and tried at the next run while it's due.
fn due_reminders_at(conn: &mut DbConnInner, at: NaiveDateTime, grace_days: i64) -> Query<Vec<DueReminder>> {
    let mut due = Vec::new();
    for (row, whose) in rows_in_force(conn)? {
        let Some((reminder, about)) = reminder_due(&row, at, grace_days) else {
            continue;
        };
        let to = managers(conn, &whose)?;
        if to.is_empty() || !note(conn, &row.uuid, reminder.as_str(), about, at)? {
            continue;
        }
        let (name, clients) = match &whose {
            PlanOwner::User(_) => (None, 0),
            PlanOwner::Organization(org) => (
                organizations::table
                    .filter(organizations::uuid.eq(org))
                    .select(organizations::name)
                    .first::<String>(conn)
                    .optional()?,
                0,
            ),
            PlanOwner::Msp(msp) => {
                let name =
                    msps::table.filter(msps::uuid.eq(msp)).select(msps::name).first::<String>(conn).optional()?;
                let clients = msp_clients::table
                    .filter(msp_clients::msp_uuid.eq(msp))
                    .filter(msp_clients::joined_with_code.eq(false))
                    .count()
                    .get_result::<i64>(conn)?;
                (name, usize::try_from(clients).unwrap_or(0))
            }
        };
        due.push(DueReminder {
            plan_uuid: row.uuid.clone(),
            whose,
            reminder,
            about,
            row,
            name,
            clients,
            to,
        });
    }
    Ok(due)
}

/// Removes what the clock noted about rows that are gone (their owner was
/// deleted, or the operator removed the row), in one statement: it looks at
/// the plans as it deletes, so a plan written and noted by another run of the
/// clock at the same moment keeps its notes, where looking first and
/// deleting after forgot them as a gone plan's.
fn forget_gone(conn: &mut DbConnInner) -> Query<usize> {
    diesel::delete(plan_notices::table.filter(plan_notices::plan_uuid.ne_all(plans::table.select(plans::uuid))))
        .execute(conn)
}

/// One run of the plans' clock, handed a time: trials for whatever has no
/// row, then the plans the clock moved (for the sync notice), then the
/// reminders due (for the emails), each noted so none goes twice.
pub async fn run_clock(at: NaiveDateTime, conn: &DbConn) -> ApiResult<(Vec<PlanOwner>, Vec<DueReminder>)> {
    let (grace_days, trial_days) = (CONFIG.plan_grace_days(), CONFIG.plan_trial_days());
    let mail = CONFIG.mail_enabled();
    conn.run(move |conn| clock_at(conn, at, grace_days, trial_days, mail).map_res("Error running the plans' clock"))
        .await
}

fn clock_at(
    conn: &mut DbConnInner,
    at: NaiveDateTime,
    grace_days: i64,
    trial_days: i64,
    mail: bool,
) -> Query<(Vec<PlanOwner>, Vec<DueReminder>)> {
    start_missing_trials(conn, at, trial_days)?;
    forget_gone(conn)?;
    let changed = clock_changes_at(conn, at, grace_days)?;
    let due = if mail {
        due_reminders_at(conn, at, grace_days)?
    } else {
        Vec::new()
    };
    Ok((changed, due))
}

impl PlanNotice {
    /// Forgets a reminder that reached nobody, so it's tried again.
    pub async fn forget(plan_uuid: &str, reminder: Reminder, about: NaiveDateTime, conn: &DbConn) -> ApiResult<()> {
        conn.run(move |conn| {
            diesel::delete(
                plan_notices::table
                    .filter(plan_notices::plan_uuid.eq(plan_uuid))
                    .filter(plan_notices::notice.eq(reminder.as_str()))
                    .filter(plan_notices::about.eq(about)),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error forgetting a reminder")
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Noon on March 1, 2027.
    fn noon() -> NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2027, 3, 1).unwrap().and_hms_opt(12, 0, 0).unwrap()
    }

    fn second() -> TimeDelta {
        TimeDelta::seconds(1)
    }

    fn days(n: i64) -> TimeDelta {
        TimeDelta::days(n)
    }

    const GRACE: i64 = 14;

    fn trial(ends: NaiveDateTime) -> Plan {
        trial_row(&PlanOwner::Organization("acme".to_owned().into()), ends - days(30), 30).unwrap()
    }

    fn paid(until: NaiveDateTime, renews: bool) -> Plan {
        Plan {
            free_until: None,
            free_why: None,
            standing: Standing::Until.as_str().to_owned(),
            until: Some(until),
            renews,
            ..trial(noon())
        }
    }

    #[test]
    fn the_server_writes_a_business_trial_for_an_organization_and_a_pool_and_none_for_a_person() {
        let org = trial_row(&PlanOwner::Organization("acme".to_owned().into()), noon(), 30).unwrap();
        assert_eq!(org.org_uuid.as_ref().map(ToString::to_string).as_deref(), Some("acme"));
        assert_eq!((org.user_uuid.as_ref(), org.msp_uuid.as_ref()), (None, None));
        assert_eq!(org.plan, "business");
        assert_eq!(org.free_until, Some(noon() + days(30)));
        assert_eq!(org.free_why.as_deref(), Some("trial"));
        assert_eq!((org.standing.as_str(), org.until, org.renews), ("none", None, false));
        assert_eq!((org.set_by.as_str(), org.updated_at), ("server", noon()));
        assert_eq!(org.state_at(noon(), GRACE), PlanState::Trial);
        assert_eq!(org.state_at(noon() + days(30) - second(), GRACE), PlanState::Trial);
        // No grace after a trial.
        assert_eq!(org.state_at(noon() + days(30), GRACE), PlanState::Ended);

        let pool = trial_row(&PlanOwner::Msp("northwind".to_owned().into()), noon(), 30).unwrap();
        assert_eq!(pool.plan, "msp");
        assert_eq!(pool.msp_uuid.as_ref().map(ToString::to_string).as_deref(), Some("northwind"));
        assert_eq!(pool.free_until, Some(noon() + days(30)));

        assert_eq!(trial_row(&PlanOwner::User("ana".to_owned().into()), noon(), 30), None);
        // The setting's length, and a length too long to add is no trial.
        assert_eq!(
            trial_row(&PlanOwner::Organization("acme".to_owned().into()), noon(), 7).unwrap().free_until,
            Some(noon() + days(7))
        );
        assert_eq!(trial_row(&PlanOwner::Organization("acme".to_owned().into()), noon(), i64::MAX), None);
    }

    #[test]
    fn a_trials_reminders_come_7_days_and_1_day_before_it_ends() {
        let ends = noon();
        let row = trial(ends);
        let due = |at: NaiveDateTime| reminder_due(&row, at, GRACE);

        assert_eq!(due(ends - days(30)), None);
        assert_eq!(due(ends - days(7) - second()), None);
        assert_eq!(due(ends - days(7)), Some((Reminder::TrialSevenDays, ends)));
        assert_eq!(due(ends - days(1) - second()), Some((Reminder::TrialSevenDays, ends)));
        assert_eq!(due(ends - days(1)), Some((Reminder::TrialOneDay, ends)));
        assert_eq!(due(ends - second()), Some((Reminder::TrialOneDay, ends)));
        // At its end and after, nothing: a trial ends with no email of its own.
        assert_eq!(due(ends), None);
        assert_eq!(due(ends + days(1)), None);

        // An offer's free months get the same reminders.
        let offer = Plan {
            free_why: Some("offer".to_owned()),
            ..row.clone()
        };
        assert_eq!(reminder_due(&offer, ends - days(3), GRACE), Some((Reminder::TrialSevenDays, ends)));

        // Paid for during the trial: no reminder, since nothing stops.
        let paying = Plan {
            standing: "open".to_owned(),
            renews: true,
            ..row.clone()
        };
        assert_eq!(reminder_due(&paying, ends - days(3), GRACE), None);
        let paid_past_it = Plan {
            standing: "until".to_owned(),
            until: Some(ends + days(300)),
            ..row.clone()
        };
        assert_eq!(reminder_due(&paid_past_it, ends - second(), GRACE), None);
        // Free time over a payment that's due, where grace runs on past it:
        // nothing stops at its end either, so no trial reminder.
        let grace_after = Plan {
            standing: "until".to_owned(),
            until: Some(ends - days(5)),
            renews: true,
            ..row
        };
        assert_eq!(grace_after.state_at(ends - days(3), GRACE), PlanState::Trial);
        assert_eq!(reminder_due(&grace_after, ends - days(3), GRACE), None);
    }

    #[test]
    fn grace_has_its_reminder_3_days_before_it_ends_and_one_when_it_has() {
        let until = noon();
        let row = paid(until, true);
        let grace_ends = until + days(GRACE);
        let due = |at: NaiveDateTime| reminder_due(&row, at, GRACE);

        assert_eq!(due(until), None);
        assert_eq!(due(until + second()), None);
        assert_eq!(due(grace_ends - days(3) - second()), None);
        assert_eq!(due(grace_ends - days(3)), Some((Reminder::GraceThreeDays, grace_ends)));
        assert_eq!(due(grace_ends), Some((Reminder::GraceThreeDays, grace_ends)));
        assert_eq!(due(grace_ends + second()), Some((Reminder::GraceEnded, grace_ends)));
        assert_eq!(due(grace_ends + days(7)), Some((Reminder::GraceEnded, grace_ends)));
        // A week late, it would be news to nobody.
        assert_eq!(due(grace_ends + days(7) + second()), None);

        // The grace is the setting's.
        assert_eq!(reminder_due(&row, until + days(5), 7), Some((Reminder::GraceThreeDays, until + days(7))));
        // With none, the plan ends at until, and that email goes.
        assert_eq!(reminder_due(&row, until + second(), 0), Some((Reminder::GraceEnded, until)));

        // A plan someone canceled ends as they chose, with no email.
        let canceled = paid(until, false);
        for at in [until - days(2), until + second(), until + days(2)] {
            assert_eq!(reminder_due(&canceled, at, GRACE), None, "{at}");
        }
        // Good with no end: nothing.
        let open = Plan {
            standing: "open".to_owned(),
            until: None,
            ..row.clone()
        };
        assert_eq!(reminder_due(&open, until + days(400), GRACE), None);
        // Free time that runs past grace ends it, not grace: no grace email.
        let free_later = Plan {
            free_until: Some(grace_ends + days(10)),
            free_why: Some("offer".to_owned()),
            ..row
        };
        assert_eq!(reminder_due(&free_later, grace_ends + second(), GRACE), None);
        assert_eq!(
            reminder_due(&free_later, grace_ends + days(4), GRACE),
            Some((Reminder::TrialSevenDays, grace_ends + days(10)))
        );
        assert_eq!(reminder_due(&free_later, grace_ends + days(10) + second(), GRACE), None);
    }
}

// With a database: the trial clock's writes, and what the clock finds due.
#[cfg(all(test, sqlite))]
mod database_tests {
    use super::*;
    use crate::db::{
        DbPool,
        models::{Membership, Msp, MspClient, MspStaff, Organization, PlanWrite, User},
    };

    /// Noon on March 1, 2027.
    fn noon() -> NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2027, 3, 1).unwrap().and_hms_opt(12, 0, 0).unwrap()
    }

    fn second() -> TimeDelta {
        TimeDelta::seconds(1)
    }

    fn days(n: i64) -> TimeDelta {
        TimeDelta::days(n)
    }

    const GRACE: i64 = 14;

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

    async fn owner_of_org(user: &User, org: &Organization, conn: &DbConn) {
        let mut member = Membership::new(user.uuid.clone(), org.uuid.clone(), None);
        member.atype = MembershipType::Owner as i32;
        member.status = MembershipStatus::Confirmed as i32;
        member.save(conn).await.unwrap();
    }

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
            joined_with_code: false,
        }
        .insert(conn)
        .await
        .unwrap();
    }

    fn of_org(org: &Organization) -> PlanOwner {
        PlanOwner::Organization(org.uuid.clone())
    }

    async fn row_of(whose: &PlanOwner, conn: &DbConn) -> Option<Plan> {
        Plan::find(whose, conn).await.unwrap()
    }

    async fn clock(at: NaiveDateTime, conn: &DbConn) -> (Vec<PlanOwner>, Vec<DueReminder>) {
        conn.run(move |conn| clock_at(conn, at, GRACE, 30, true)).await.unwrap()
    }

    #[rocket::async_test]
    async fn a_trial_starts_once_and_never_over_a_row_thats_there() {
        let conn = DbPool::for_test().await;
        let acme = organization("Acme", &conn).await;
        let whose = of_org(&acme);

        let first = conn.run(|conn| start_trial(conn, &whose, noon(), 30)).await.unwrap().unwrap();
        assert_eq!(first.free_until, Some(noon() + days(30)));
        // Found again later: the same trial, not a new one.
        let again = conn.run(|conn| start_trial(conn, &whose, noon() + days(10), 30)).await.unwrap().unwrap();
        assert_eq!(again, first);
        // An owner that doesn't exist, and a person, get none.
        let nobody = PlanOwner::Organization("nobody".to_owned().into());
        assert_eq!(conn.run(move |conn| start_trial(conn, &nobody, noon(), 30)).await.unwrap(), None);
        let ana = person("ana", &conn).await;
        let hers = PlanOwner::User(ana.uuid.clone());
        assert_eq!(conn.run(move |conn| start_trial(conn, &hers, noon(), 30)).await.unwrap(), None);
    }

    #[rocket::async_test]
    async fn a_client_that_leaves_its_msp_gets_30_days_from_that_moment() {
        let conn = DbPool::for_test().await;
        let left = noon();
        let bare = organization("Bare", &conn).await;
        let ended = organization("Ended", &conn).await;
        let paying = organization("Paying", &conn).await;
        let offered = organization("Offered", &conn).await;
        let until = left + days(30);

        // No row of its own: a trial, from the moment it leaves.
        let id = bare.uuid.clone();
        conn.run(move |conn| left_msp(conn, &id, left, 30)).await.unwrap();
        let row = row_of(&of_org(&bare), &conn).await.unwrap();
        assert_eq!(
            (row.plan.as_str(), row.free_until, row.free_why.as_deref()),
            ("business", Some(until), Some("trial"))
        );
        assert_eq!(row.state_at(until - second(), GRACE), PlanState::Trial);
        assert_eq!(row.state_at(until, GRACE), PlanState::Ended);

        // A row of its own that ended long ago: 30 days on it.
        let old = PlanWrite {
            plan: PlanName::Business,
            free_until: None,
            free_why: None,
            standing: Standing::Until,
            until: Some(left - days(400)),
            renews: false,
            billed: Billed::ByHand,
        };
        Plan::set(&of_org(&ended), old.clone(), SetBy::Operator, &conn).await.unwrap();
        let id = ended.uuid.clone();
        conn.run(move |conn| left_msp(conn, &id, left, 30)).await.unwrap();
        let row = row_of(&of_org(&ended), &conn).await.unwrap();
        assert_eq!(
            (row.free_until, row.free_why.as_deref(), row.set_by.as_str()),
            (Some(until), Some("trial"), "server")
        );
        assert_eq!(row.until, Some(left - days(400)));
        assert_eq!(row.state_at(left, GRACE), PlanState::Trial);

        // One that's paid stays paid, with the 30 days beside it.
        let paid_for = PlanWrite {
            standing: Standing::Open,
            until: None,
            renews: true,
            ..old.clone()
        };
        Plan::set(&of_org(&paying), paid_for, SetBy::Operator, &conn).await.unwrap();
        let id = paying.uuid.clone();
        conn.run(move |conn| left_msp(conn, &id, left, 30)).await.unwrap();
        assert_eq!(
            row_of(&of_org(&paying), &conn).await.unwrap().state_at(until + days(100), GRACE),
            PlanState::Active
        );

        // Free time that runs later already is left as it is.
        let later = PlanWrite {
            free_until: Some(left + days(90)),
            free_why: Some(FreeWhy::Offer),
            standing: Standing::None,
            until: None,
            ..old
        };
        let written = Plan::set(&of_org(&offered), later, SetBy::Operator, &conn).await.unwrap().unwrap().1;
        let id = offered.uuid.clone();
        conn.run(move |conn| left_msp(conn, &id, left, 30)).await.unwrap();
        assert_eq!(row_of(&of_org(&offered), &conn).await.unwrap(), written);
    }

    /// A client leaving its MSP has its 30 days written in a transaction that
    /// waits for a write in progress elsewhere instead of failing, with a row
    /// of its own or without one. Inside a transaction the caller holds (a
    /// move to another MSP is one), it's part of that transaction: undone
    /// with it, and kept with it.
    #[rocket::async_test]
    async fn leaving_waits_for_a_write_in_progress_and_is_part_of_a_move() {
        let pool = DbPool::for_test_pool_of(2);
        let conn = pool.get().await.unwrap();
        let left = noon();
        let ended = organization("Ended", &conn).await;
        let old = PlanWrite {
            plan: PlanName::Business,
            free_until: None,
            free_why: None,
            standing: Standing::Until,
            until: Some(left - days(400)),
            renews: false,
            billed: Billed::ByHand,
        };
        Plan::set(&of_org(&ended), old, SetBy::Operator, &conn).await.unwrap();
        let bare = organization("Bare", &conn).await;
        for org in [&ended, &bare] {
            let released = pool.hold_write_lock(std::time::Duration::from_millis(300)).await;
            let id = org.uuid.clone();
            let written = conn.run(move |conn| left_msp(conn, &id, left, 30)).await;
            released.await.unwrap();
            written.expect("leaving waits for the other write, and is written");
            let row = row_of(&of_org(org), &conn).await.unwrap();
            assert_eq!((row.free_until, row.free_why.as_deref()), (Some(left + days(30)), Some("trial")));
        }

        let moved = organization("Moved", &conn).await;
        let id = moved.uuid.clone();
        let undone = conn
            .run(move |conn| {
                conn.transaction(|conn| {
                    left_msp(conn, &id, left, 30)?;
                    Err::<(), _>(diesel::result::Error::RollbackTransaction)
                })
            })
            .await;
        assert!(matches!(undone, Err(diesel::result::Error::RollbackTransaction)));
        assert_eq!(row_of(&of_org(&moved), &conn).await, None);
        let id = moved.uuid.clone();
        conn.run(move |conn| conn.transaction(|conn| left_msp(conn, &id, left, 30))).await.unwrap();
        assert_eq!(row_of(&of_org(&moved), &conn).await.unwrap().free_until, Some(left + days(30)));
    }

    #[rocket::async_test]
    async fn the_clock_finds_whatever_has_no_row_and_leaves_clients_to_their_msp() {
        let conn = DbPool::for_test().await;
        let acme = organization("Acme", &conn).await;
        let clinic = organization("Clinic", &conn).await;
        let northwind = Msp::new("Northwind IT".to_owned());
        northwind.insert(&conn).await.unwrap();
        take_on(&northwind, &clinic, &conn).await;

        clock(noon(), &conn).await;
        assert_eq!(row_of(&of_org(&acme), &conn).await.unwrap().free_until, Some(noon() + days(30)));
        let pool = row_of(&PlanOwner::Msp(northwind.uuid.clone()), &conn).await.unwrap();
        assert_eq!((pool.plan.as_str(), pool.free_until), ("msp", Some(noon() + days(30))));
        // A client is covered by its MSP's pool, and gets no row of its own.
        assert_eq!(row_of(&of_org(&clinic), &conn).await, None);
    }

    #[rocket::async_test]
    async fn each_reminder_goes_once_to_whoever_manages_the_plan() {
        let conn = DbPool::for_test().await;
        let acme = organization("Acme", &conn).await;
        let owner = person("owner", &conn).await;
        let other_owner = person("other-owner", &conn).await;
        let member = person("member", &conn).await;
        owner_of_org(&owner, &acme, &conn).await;
        owner_of_org(&other_owner, &acme, &conn).await;
        let mut plain = Membership::new(member.uuid.clone(), acme.uuid.clone(), None);
        plain.status = MembershipStatus::Confirmed as i32;
        plain.save(&conn).await.unwrap();
        let northwind = Msp::new("Northwind IT".to_owned());
        northwind.insert(&conn).await.unwrap();
        let admin = person("msp-admin", &conn).await;
        let tech = person("msp-tech", &conn).await;
        MspStaff::new(northwind.uuid.clone(), admin.uuid.clone(), MspRole::Admin).insert(&conn).await.unwrap();
        MspStaff::new(northwind.uuid.clone(), tech.uuid.clone(), MspRole::Technician).insert(&conn).await.unwrap();
        let clinic = organization("Clinic", &conn).await;
        take_on(&northwind, &clinic, &conn).await;

        // Both trials end at noon, started 30 days before.
        let started = noon() - days(30);
        clock(started, &conn).await;
        assert!(clock(started + days(1), &conn).await.1.is_empty());

        // Seven days out: one reminder each, to the owners and to the MSP's admins.
        let (_, due) = clock(noon() - days(7), &conn).await;
        let mut sent: Vec<(Reminder, Option<String>, Vec<String>, usize)> =
            due.iter().map(|d| (d.reminder, d.name.clone(), d.to.clone(), d.clients)).collect();
        sent.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(
            sent,
            vec![
                (
                    Reminder::TrialSevenDays,
                    Some("Acme".to_owned()),
                    vec!["other-owner@example.test".to_owned(), "owner@example.test".to_owned()],
                    0
                ),
                (
                    Reminder::TrialSevenDays,
                    Some("Northwind IT".to_owned()),
                    vec!["msp-admin@example.test".to_owned()],
                    1
                ),
            ]
        );
        assert!(due.iter().all(|d| d.about == noon()));
        // The next run, and the next day's: nothing, since each went once.
        assert!(clock(noon() - days(7) + TimeDelta::hours(1), &conn).await.1.is_empty());
        assert!(clock(noon() - days(2), &conn).await.1.is_empty());
        // The day before: the last one, once.
        let (_, due) = clock(noon() - days(1), &conn).await;
        assert_eq!(due.iter().map(|d| d.reminder).collect::<Vec<_>>(), vec![Reminder::TrialOneDay; 2]);
        assert!(clock(noon() - TimeDelta::hours(1), &conn).await.1.is_empty());

        // The operator gives Acme new dates: its reminders can go again, for them.
        let more = PlanWrite {
            plan: PlanName::Business,
            free_until: Some(noon() + days(10)),
            free_why: Some(FreeWhy::Trial),
            standing: Standing::None,
            until: None,
            renews: false,
            billed: Billed::ByTheDay,
        };
        Plan::set(&of_org(&acme), more, SetBy::Operator, &conn).await.unwrap();
        let (_, due) = clock(noon() + days(3), &conn).await;
        assert_eq!(due.len(), 1);
        assert_eq!((due[0].reminder, due[0].about), (Reminder::TrialSevenDays, noon() + days(10)));

        // A reminder that reached nobody is forgotten, and goes at the next run.
        PlanNotice::forget(&due[0].plan_uuid, due[0].reminder, due[0].about, &conn).await.unwrap();
        assert_eq!(clock(noon() + days(3), &conn).await.1.len(), 1);
        assert!(clock(noon() + days(3), &conn).await.1.is_empty());

        // Without email, nothing is due and nothing is noted.
        let (_, due) =
            conn.run(|conn| clock_at(conn, noon() + days(9) + TimeDelta::hours(13), GRACE, 30, false)).await.unwrap();
        assert!(due.is_empty());
        assert_eq!(clock(noon() + days(9) + TimeDelta::hours(13), &conn).await.1.len(), 1);
    }

    #[rocket::async_test]
    async fn the_clock_tells_people_to_sync_once_for_each_state_it_moves_a_plan_into() {
        let conn = DbPool::for_test().await;
        let acme = organization("Acme", &conn).await;
        let ana = person("ana", &conn).await;
        let hers = PlanOwner::User(ana.uuid.clone());
        let until = noon();
        let renewing = PlanWrite {
            plan: PlanName::Premium,
            free_until: None,
            free_why: None,
            standing: Standing::Until,
            until: Some(until),
            renews: true,
            billed: Billed::Prepaid,
        };
        Plan::set(&hers, renewing, SetBy::Operator, &conn).await.unwrap();
        // The row was written now, and is good through noon: nothing changed yet.
        let written = row_of(&hers, &conn).await.unwrap().updated_at;
        assert!(written < until, "the row is written before its date");
        let changed = |list: &[PlanOwner]| list.iter().filter(|w| **w == hers).count();

        let (first, _) = clock(written.max(until - days(1)), &conn).await;
        assert_eq!(changed(&first), 0);
        // Into grace: once.
        assert_eq!(changed(&clock(until + second(), &conn).await.0), 1);
        assert_eq!(changed(&clock(until + days(1), &conn).await.0), 0);
        // Grace's end: once.
        assert_eq!(changed(&clock(until + days(GRACE) + second(), &conn).await.0), 1);
        assert_eq!(changed(&clock(until + days(GRACE + 1), &conn).await.0), 0);

        // The organization's trial, which the clock wrote itself, ends: once.
        let trial_ends = row_of(&of_org(&acme), &conn).await.unwrap().free_until.unwrap();
        let theirs = of_org(&acme);
        let ended = clock(trial_ends, &conn).await.0;
        assert_eq!(ended.iter().filter(|w| **w == theirs).count(), 1);
        assert_eq!(clock(trial_ends + days(1), &conn).await.0.iter().filter(|w| **w == theirs).count(), 0);

        // A row that's gone takes what was noted about it with it.
        let uuid = row_of(&hers, &conn).await.unwrap().uuid;
        Plan::remove(&hers, &conn).await.unwrap();
        clock(until + days(GRACE + 2), &conn).await;
        let left = conn
            .run(move |conn| {
                plan_notices::table.filter(plan_notices::plan_uuid.eq(uuid)).count().get_result::<i64>(conn)
            })
            .await
            .unwrap();
        assert_eq!(left, 0);
    }
}

/// The clock forgetting what it noted while another run of it writes.
#[cfg(test)]
mod race_tests {
    use super::*;
    use crate::db::{DbPool, models::Organization};

    /// How long the other run takes to commit: far longer than forgetting
    /// takes, and far less than SQLite's busy timeout (5 seconds).
    const ANOTHER_RUN: std::time::Duration = std::time::Duration::from_millis(300);

    /// Two runs of the clock at once (a run that outlasts the schedule, or
    /// two servers on one database): one writes an organization's trial and
    /// notes its reminder, and hasn't committed yet when the other forgets
    /// what was noted about plans that are gone. That plan isn't gone, and
    /// its note stays, so the reminder doesn't go twice. On SQLite the
    /// forgetting waits for the other run's write: it looked at the plans
    /// first, and then forgot the new plan's note as a gone plan's. On
    /// PostgreSQL it doesn't wait, and can't see what isn't committed yet.
    async fn forgetting_keeps_what_another_run_just_noted(pool: DbPool) {
        let conn = pool.get().await.unwrap();
        let acme = Organization::new("Acme".to_owned(), "billing@example.test", None, None);
        acme.save(&conn).await.unwrap();
        let whose = PlanOwner::Organization(acme.uuid.clone());
        let at = Utc::now().naive_utc();

        let other = pool.another_request().await;
        let plan = other
            .run(move |conn| {
                let trial = start_trial(conn, &whose, at, 7)?.expect("Acme's trial");
                let ends = trial.free_until.expect("its end");
                note(conn, &trial.uuid, Reminder::TrialSevenDays.as_str(), ends, at)?;
                Ok::<_, diesel::result::Error>(trial.uuid)
            })
            .await
            .unwrap();
        let committed = other.commit_after(ANOTHER_RUN);
        let forgot = conn.run(forget_gone).await;
        committed.await.unwrap();
        assert_eq!(forgot.unwrap(), 0, "no plan is gone");
        let notes = conn
            .run(move |conn| {
                plan_notices::table.filter(plan_notices::plan_uuid.eq(plan)).count().get_result::<i64>(conn)
            })
            .await
            .unwrap();
        assert_eq!(notes, 1, "the reminder's note stays");
    }

    crate::on_each_database!(forgetting_during_another_run, 2, forgetting_keeps_what_another_run_just_noted);
}

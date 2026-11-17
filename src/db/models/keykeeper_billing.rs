// Keykeeper: what the server keeps to learn who has paid (DESIGN.md, "Plans
// and billing", "Learning who has paid"): the ids of the provider's webhooks,
// whose plan each of the provider's customers pays for, and the provider's
// answers, written to `plans`. Only `src/keykeeper_billing` calls this, and
// only where PLANS_ENFORCED and BILLING_PROVIDER are both set.

use chrono::NaiveDateTime;
use diesel::prelude::*;

use crate::{
    api::ApiResult,
    db::{
        DbConn, DbConnInner,
        keykeeper_schema::{billing_customers, billing_events, plans},
    },
    error::MapResult,
    keykeeper_billing::plain_id,
};

use super::{
    Billed, MspId, OrganizationId, Plan, PlanName, PlanOwner, SetBy, Standing, UserId, keykeeper_plans::find_row,
};

type Query<T> = Result<T, diesel::result::Error>;

/// What a provider says about a customer now (the fifth call), checked to fit
/// together before it's anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderAnswer {
    pub plan: PlanName,
    pub standing: Standing,
    /// Good through this moment, with `standing` `until`, and only then.
    pub until: Option<NaiveDateTime>,
    pub renews: bool,
    pub billed: Billed,
    /// The provider's id for what's paid, which means nothing outside it.
    pub subscription: Option<String>,
}

impl ProviderAnswer {
    /// None when the parts don't fit together, as the operator's route refuses
    /// a plan that doesn't (`PlanWrite::refusal`).
    pub fn new(
        plan: PlanName,
        standing: Standing,
        until: Option<NaiveDateTime>,
        renews: bool,
        billed: Billed,
        subscription: Option<String>,
    ) -> Option<Self> {
        if (standing == Standing::Until) != until.is_some() {
            return None;
        }
        if subscription.as_deref().is_some_and(|id| !plain_id(id)) {
            return None;
        }
        Some(Self {
            plan,
            standing,
            until,
            renews,
            billed,
            subscription,
        })
    }
}

/// The ids of the provider's webhooks, so a repeat is dropped.
pub struct BillingEvent;

impl BillingEvent {
    /// Records a webhook's id, with the customer a look is owed for, if any.
    /// False when the id was there already: a repeat, which is dropped.
    pub async fn record(
        provider: &str,
        event_id: &str,
        pending_customer: Option<&str>,
        received_at: NaiveDateTime,
        conn: &DbConn,
    ) -> ApiResult<bool> {
        conn.run(move |conn| {
            let inserted = diesel::insert_into(billing_events::table)
                .values((
                    billing_events::provider.eq(provider),
                    billing_events::event_id.eq(event_id),
                    billing_events::pending_customer.eq(pending_customer),
                    billing_events::received_at.eq(received_at),
                ))
                .execute(conn);
            match inserted {
                Ok(_) => Ok(true),
                Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _)) => {
                    Ok(false)
                }
                Err(e) => Err(e),
            }
            .map_res("Error recording a billing event")
        })
        .await
    }

    /// The customers a look is still owed for, each with when the first of
    /// their webhooks came.
    pub async fn pending(provider: &str, conn: &DbConn) -> ApiResult<Vec<(String, NaiveDateTime)>> {
        let rows = conn
            .run(move |conn| {
                billing_events::table
                    .filter(billing_events::provider.eq(provider))
                    .filter(billing_events::pending_customer.is_not_null())
                    .select((billing_events::pending_customer.assume_not_null(), billing_events::received_at))
                    .load::<(String, NaiveDateTime)>(conn)
                    .map_res("Error loading the billing events owed a look")
            })
            .await?;
        let mut first: std::collections::BTreeMap<String, NaiveDateTime> = std::collections::BTreeMap::new();
        for (customer, received_at) in rows {
            first.entry(customer).and_modify(|since| *since = (*since).min(received_at)).or_insert(received_at);
        }
        Ok(first.into_iter().collect())
    }

    /// Whether webhook `event_id` is still owed a look: no look about its
    /// customer has asked the provider since it came.
    pub async fn owed(provider: &str, event_id: &str, conn: &DbConn) -> ApiResult<bool> {
        conn.run(move |conn| {
            diesel::select(diesel::dsl::exists(
                billing_events::table
                    .filter(billing_events::provider.eq(provider))
                    .filter(billing_events::event_id.eq(event_id))
                    .filter(billing_events::pending_customer.is_not_null()),
            ))
            .get_result(conn)
            .map_res("Error reading whether a billing event is owed a look")
        })
        .await
    }

    /// The provider was asked about `customer` at `asked_at` and answered: no
    /// look is owed for the webhooks about them that came by then. One that
    /// came later is still owed one, since the answer may be from before
    /// what it says changed.
    pub async fn answered(provider: &str, customer: &str, asked_at: NaiveDateTime, conn: &DbConn) -> ApiResult<()> {
        conn.run(move |conn| {
            diesel::update(
                billing_events::table
                    .filter(billing_events::provider.eq(provider))
                    .filter(billing_events::pending_customer.eq(customer))
                    .filter(billing_events::received_at.le(asked_at)),
            )
            .set(billing_events::pending_customer.eq(None::<String>))
            .execute(conn)
            .map(|_| ())
            .map_res("Error noting a billing event's look")
        })
        .await
    }

    /// Clears the ids of webhooks that came before `before`.
    pub async fn clear_before(before: NaiveDateTime, conn: &DbConn) -> ApiResult<usize> {
        conn.run(move |conn| {
            diesel::delete(billing_events::table.filter(billing_events::received_at.lt(before)))
                .execute(conn)
                .map_res("Error clearing old billing events")
        })
        .await
    }
}

/// Whose plan each of the provider's customers pays for. The server's own
/// record: written when it first asks the provider for a page to pay, and
/// never from what a provider or a webhook says.
pub struct BillingCustomer;

type OwnerColumns = (Option<UserId>, Option<OrganizationId>, Option<MspId>);

fn owner_columns(whose: &PlanOwner) -> OwnerColumns {
    match whose {
        PlanOwner::User(id) => (Some(id.clone()), None, None),
        PlanOwner::Organization(id) => (None, Some(id.clone()), None),
        PlanOwner::Msp(id) => (None, None, Some(id.clone())),
    }
}

fn customer_of(conn: &mut DbConnInner, provider: &str, whose: &PlanOwner) -> Query<Option<String>> {
    let mine = billing_customers::table.filter(billing_customers::provider.eq(provider));
    match whose {
        PlanOwner::User(id) => {
            mine.filter(billing_customers::user_uuid.eq(id)).select(billing_customers::customer).first::<String>(conn)
        }
        PlanOwner::Organization(id) => {
            mine.filter(billing_customers::org_uuid.eq(id)).select(billing_customers::customer).first::<String>(conn)
        }
        PlanOwner::Msp(id) => {
            mine.filter(billing_customers::msp_uuid.eq(id)).select(billing_customers::customer).first::<String>(conn)
        }
    }
    .optional()
}

impl BillingCustomer {
    /// The provider's customer for `whose` plan, if it has one.
    pub async fn of(provider: &str, whose: &PlanOwner, conn: &DbConn) -> ApiResult<Option<String>> {
        conn.run(move |conn| customer_of(conn, provider, whose).map_res("Error loading a billing customer")).await
    }

    /// Whose plan `customer` pays for. None: nobody this server knows.
    pub async fn whose(provider: &str, customer: &str, conn: &DbConn) -> ApiResult<Option<PlanOwner>> {
        conn.run(move |conn| {
            billing_customers::table
                .filter(billing_customers::provider.eq(provider))
                .filter(billing_customers::customer.eq(customer))
                .select((billing_customers::user_uuid, billing_customers::org_uuid, billing_customers::msp_uuid))
                .first::<OwnerColumns>(conn)
                .optional()
                .map(|found| {
                    found.and_then(|owner| match owner {
                        (Some(user), None, None) => Some(PlanOwner::User(user)),
                        (None, Some(org), None) => Some(PlanOwner::Organization(org)),
                        (None, None, Some(msp)) => Some(PlanOwner::Msp(msp)),
                        _ => None,
                    })
                })
                .map_res("Error loading whose plan a billing customer pays for")
        })
        .await
    }

    /// Records that `customer` pays for `whose` plan. False when either is
    /// taken already: the customer pays for another plan, or the plan has
    /// another customer.
    pub async fn record(
        provider: &str,
        customer: &str,
        whose: &PlanOwner,
        created_at: NaiveDateTime,
        conn: &DbConn,
    ) -> ApiResult<bool> {
        let (user_uuid, org_uuid, msp_uuid) = owner_columns(whose);
        conn.run(move |conn| {
            let inserted = diesel::insert_into(billing_customers::table)
                .values((
                    billing_customers::provider.eq(provider),
                    billing_customers::customer.eq(customer),
                    billing_customers::user_uuid.eq(user_uuid),
                    billing_customers::org_uuid.eq(org_uuid),
                    billing_customers::msp_uuid.eq(msp_uuid),
                    billing_customers::created_at.eq(created_at),
                ))
                .execute(conn);
            match inserted {
                Ok(_) => Ok(true),
                Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _)) => {
                    Ok(false)
                }
                Err(e) => Err(e),
            }
            .map_res("Error recording a billing customer")
        })
        .await
    }
}

/// Writes a provider's answer about `customer` to `whose` plan, as asked at
/// `at`, and says whether what the plan gives changed.
///
/// - An answer that something is or was paid (a standing of `until` or
///   `open`) is the plan now: its name, standing, date, whether it renews, and
///   how it's billed, set by the provider, with the provider's ids. A free
///   period the server or the operator gave stays.
/// - An answer that nothing is paid (no answer, or a standing of `none`)
///   ends only a plan the provider set. A trial the server gave, or a plan the
///   operator set by hand, stands, and a person or an organization with no
///   plan still has none.
///
/// Either way `checked_at` says when the provider last answered.
fn write_answer(
    conn: &mut DbConnInner,
    whose: &PlanOwner,
    provider: &str,
    customer: &str,
    answer: Option<&ProviderAnswer>,
    at: NaiveDateTime,
) -> Query<bool> {
    conn.transaction(|conn| {
        let old = find_row(conn, whose)?;
        let paid = answer.filter(|answer| answer.standing != Standing::None);
        let provider_set = |row: &Plan| row.set_by == SetBy::Provider.as_str();
        let (plan, standing, until, renews, billed, subscription) = match (paid, &old) {
            (Some(answer), _) => (
                answer.plan.as_str().to_owned(),
                answer.standing,
                answer.until,
                answer.renews,
                answer.billed.as_str().to_owned(),
                answer.subscription.clone(),
            ),
            (None, Some(row)) if provider_set(row) => (
                answer.map_or_else(|| row.plan.clone(), |answer| answer.plan.as_str().to_owned()),
                Standing::None,
                None,
                false,
                answer.map_or_else(|| row.billed.clone(), |answer| answer.billed.as_str().to_owned()),
                answer.and_then(|answer| answer.subscription.clone()),
            ),
            (None, Some(row)) => {
                diesel::update(plans::table.filter(plans::uuid.eq(&row.uuid)))
                    .set(plans::checked_at.eq(at))
                    .execute(conn)?;
                return Ok(false);
            }
            (None, None) => return Ok(false),
        };
        let Some(row) = old else {
            let (user_uuid, org_uuid, msp_uuid) = owner_columns(whose);
            diesel::insert_into(plans::table)
                .values((
                    plans::uuid.eq(crate::util::get_uuid()),
                    plans::user_uuid.eq(user_uuid),
                    plans::org_uuid.eq(org_uuid),
                    plans::msp_uuid.eq(msp_uuid),
                    plans::plan.eq(&plan),
                    plans::free_until.eq(None::<NaiveDateTime>),
                    plans::free_why.eq(None::<String>),
                    plans::standing.eq(standing.as_str()),
                    plans::until.eq(until),
                    plans::renews.eq(renews),
                    plans::billed.eq(&billed),
                    plans::set_by.eq(SetBy::Provider.as_str()),
                    plans::provider.eq(provider),
                    plans::provider_customer.eq(customer),
                    plans::provider_subscription.eq(&subscription),
                    plans::checked_at.eq(at),
                    plans::updated_at.eq(at),
                ))
                .execute(conn)?;
            return Ok(true);
        };
        let changed = row.plan != plan
            || row.standing() != standing
            || row.until != until
            || row.renews != renews
            || row.billed != billed;
        diesel::update(plans::table.filter(plans::uuid.eq(&row.uuid)))
            .set((
                plans::plan.eq(&plan),
                plans::standing.eq(standing.as_str()),
                plans::until.eq(until),
                plans::renews.eq(renews),
                plans::billed.eq(&billed),
                plans::set_by.eq(SetBy::Provider.as_str()),
                plans::provider.eq(provider),
                plans::provider_customer.eq(customer),
                plans::provider_subscription.eq(&subscription),
                plans::checked_at.eq(at),
            ))
            .execute(conn)?;
        if changed || row.set_by != SetBy::Provider.as_str() {
            diesel::update(plans::table.filter(plans::uuid.eq(&row.uuid)))
                .set(plans::updated_at.eq(at))
                .execute(conn)?;
        }
        Ok(changed)
    })
}

/// See `write_answer`. Only the server calls this, with what the provider
/// answered when it asked: no request writes a plan from what it says.
pub async fn write_provider_answer(
    whose: &PlanOwner,
    provider: &str,
    customer: &str,
    answer: Option<&ProviderAnswer>,
    at: NaiveDateTime,
    conn: &DbConn,
) -> ApiResult<bool> {
    conn.run(move |conn| {
        write_answer(conn, whose, provider, customer, answer, at).map_res("Error writing a provider's answer")
    })
    .await
}

/// Every plan `provider` set, with its customer, when the provider last
/// answered about it, and when it's good through: what the billing job
/// decides whether to look at again from.
pub async fn plans_a_provider_set(
    provider: &str,
    conn: &DbConn,
) -> ApiResult<Vec<(PlanOwner, String, Option<NaiveDateTime>, Option<NaiveDateTime>)>> {
    conn.run(move |conn| {
        plans::table
            .filter(plans::set_by.eq(SetBy::Provider.as_str()))
            .filter(plans::provider.eq(provider))
            .filter(plans::provider_customer.is_not_null())
            .load::<Plan>(conn)
            .map(|rows| {
                rows.into_iter()
                    .filter_map(|row| {
                        let whose = match (row.user_uuid, row.org_uuid, row.msp_uuid) {
                            (Some(user), None, None) => PlanOwner::User(user),
                            (None, Some(org), None) => PlanOwner::Organization(org),
                            (None, None, Some(msp)) => PlanOwner::Msp(msp),
                            _ => return None,
                        };
                        Some((whose, row.provider_customer?, row.checked_at, row.until))
                    })
                    .collect()
            })
            .map_res("Error loading the plans a provider set")
    })
    .await
}

#[cfg(all(test, sqlite))]
mod tests {
    use chrono::TimeDelta;

    use super::*;
    use crate::db::{
        DbPool,
        models::{FreeWhy, Organization, PlanWrite, User},
    };

    fn noon() -> NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2027, 3, 1).unwrap().and_hms_opt(12, 0, 0).unwrap()
    }

    fn paid(plan: PlanName, until: NaiveDateTime, renews: bool) -> ProviderAnswer {
        ProviderAnswer::new(plan, Standing::Until, Some(until), renews, Billed::Prepaid, Some("sub_1".to_owned()))
            .unwrap()
    }

    fn over(plan: PlanName) -> ProviderAnswer {
        ProviderAnswer::new(plan, Standing::None, None, false, Billed::Prepaid, None).unwrap()
    }

    async fn person(conn: &DbConn) -> PlanOwner {
        let mut user = User::new(&format!("{}@example.test", crate::util::get_uuid()), None);
        user.save(conn).await.unwrap();
        PlanOwner::User(user.uuid)
    }

    async fn write(whose: &PlanOwner, answer: Option<&ProviderAnswer>, at: NaiveDateTime, conn: &DbConn) -> bool {
        write_provider_answer(whose, "standin", "cus_1", answer, at, conn).await.unwrap()
    }

    #[test]
    fn an_answer_fits_together_or_isnt_one() {
        assert!(ProviderAnswer::new(PlanName::Premium, Standing::Until, None, true, Billed::Prepaid, None).is_none());
        assert!(
            ProviderAnswer::new(PlanName::Msp, Standing::Open, Some(noon()), true, Billed::ByTheDay, None).is_none()
        );
        assert!(ProviderAnswer::new(PlanName::Msp, Standing::Open, None, true, Billed::ByTheDay, None).is_some());
        assert!(
            ProviderAnswer::new(
                PlanName::Premium,
                Standing::None,
                None,
                false,
                Billed::Prepaid,
                Some("../x".to_owned())
            )
            .is_none()
        );
    }

    #[rocket::async_test]
    async fn the_providers_word_is_the_plan_it_set() {
        let conn = DbPool::for_test().await;
        let ana = person(&conn).await;
        let year = noon() + TimeDelta::days(365);

        // Nothing paid, and no plan: still none.
        assert!(!write(&ana, None, noon(), &conn).await);
        assert!(!write(&ana, Some(&over(PlanName::Premium)), noon(), &conn).await);
        assert_eq!(Plan::find(&ana, &conn).await.unwrap(), None);

        // Paid: the plan, set by the provider, with its ids and when it answered.
        assert!(write(&ana, Some(&paid(PlanName::Premium, year, true)), noon(), &conn).await);
        let row = Plan::find(&ana, &conn).await.unwrap().unwrap();
        assert_eq!(
            (row.plan.as_str(), row.standing(), row.until, row.renews),
            ("premium", Standing::Until, Some(year), true)
        );
        assert_eq!((row.set_by.as_str(), row.provider.as_deref()), ("provider", Some("standin")));
        assert_eq!(
            (row.provider_customer.as_deref(), row.provider_subscription.as_deref()),
            (Some("cus_1"), Some("sub_1"))
        );
        assert_eq!((row.checked_at, row.updated_at), (Some(noon()), noon()));

        // The same answer later changes nothing but when it was asked.
        let later = noon() + TimeDelta::hours(5);
        assert!(!write(&ana, Some(&paid(PlanName::Premium, year, true)), later, &conn).await);
        let row = Plan::find(&ana, &conn).await.unwrap().unwrap();
        assert_eq!((row.checked_at, row.updated_at), (Some(later), noon()));

        // Canceled, then over: the provider's plan ends when it says so.
        assert!(write(&ana, Some(&paid(PlanName::Premium, year, false)), later, &conn).await);
        assert!(write(&ana, None, later, &conn).await);
        let row = Plan::find(&ana, &conn).await.unwrap().unwrap();
        assert_eq!(
            (row.plan.as_str(), row.standing(), row.until, row.renews),
            ("premium", Standing::None, None, false)
        );
        assert_eq!(row.provider_subscription, None);
    }

    #[rocket::async_test]
    async fn nothing_paid_never_ends_a_trial_or_the_operators_plan() {
        let conn = DbPool::for_test().await;
        let acme = Organization::new("Acme".to_owned(), "billing@example.test", None, None);
        acme.save(&conn).await.unwrap();
        let acme = PlanOwner::Organization(acme.uuid);
        let trial_ends = noon() + TimeDelta::days(30);
        let trial = PlanWrite {
            plan: PlanName::Business,
            free_until: Some(trial_ends),
            free_why: Some(FreeWhy::Trial),
            standing: Standing::None,
            until: None,
            renews: false,
            billed: Billed::ByHand,
        };
        Plan::set(&acme, trial.clone(), SetBy::Server, &conn).await.unwrap();

        // The provider has nothing: the trial stands, and it was asked.
        assert!(!write(&acme, None, noon(), &conn).await);
        assert!(!write(&acme, Some(&over(PlanName::Business)), noon(), &conn).await);
        let row = Plan::find(&acme, &conn).await.unwrap().unwrap();
        assert_eq!((row.set_by.as_str(), row.free_until, row.checked_at), ("server", Some(trial_ends), Some(noon())));

        // Paid during the trial: the provider's plan, and the trial's days stay.
        let year = noon() + TimeDelta::days(365);
        assert!(write(&acme, Some(&paid(PlanName::Business, year, true)), noon(), &conn).await);
        let row = Plan::find(&acme, &conn).await.unwrap().unwrap();
        assert_eq!(
            (row.set_by.as_str(), row.standing(), row.free_until),
            ("provider", Standing::Until, Some(trial_ends))
        );

        // The operator's plan, set by hand, stands when the provider has nothing.
        let by_hand = PlanWrite {
            standing: Standing::Until,
            until: Some(year),
            renews: false,
            ..trial
        };
        Plan::set(&acme, by_hand, SetBy::Operator, &conn).await.unwrap();
        assert!(!write(&acme, None, noon(), &conn).await);
        let row = Plan::find(&acme, &conn).await.unwrap().unwrap();
        assert_eq!((row.set_by.as_str(), row.standing(), row.until), ("operator", Standing::Until, Some(year)));
    }

    #[rocket::async_test]
    async fn webhooks_once_each_and_the_looks_they_owe() {
        let conn = DbPool::for_test().await;
        let at = noon();
        assert!(BillingEvent::record("standin", "evt_1", Some("cus_1"), at, &conn).await.unwrap());
        // A repeat, at any time, is dropped.
        assert!(
            !BillingEvent::record("standin", "evt_1", Some("cus_1"), at + TimeDelta::days(3), &conn).await.unwrap()
        );
        assert!(!BillingEvent::record("standin", "evt_1", None, at, &conn).await.unwrap());
        // Another provider's id is its own.
        assert!(BillingEvent::record("other", "evt_1", None, at, &conn).await.unwrap());
        assert!(
            BillingEvent::record("standin", "evt_2", Some("cus_1"), at + TimeDelta::hours(1), &conn).await.unwrap()
        );
        assert!(
            BillingEvent::record("standin", "evt_3", Some("cus_2"), at + TimeDelta::hours(2), &conn).await.unwrap()
        );
        assert!(BillingEvent::record("standin", "evt_4", None, at, &conn).await.unwrap());

        let mut pending = BillingEvent::pending("standin", &conn).await.unwrap();
        pending.sort();
        assert_eq!(pending, vec![("cus_1".to_owned(), at), ("cus_2".to_owned(), at + TimeDelta::hours(2))]);
        assert!(BillingEvent::owed("standin", "evt_1", &conn).await.unwrap());
        assert!(!BillingEvent::owed("standin", "evt_4", &conn).await.unwrap());
        assert!(!BillingEvent::owed("standin", "evt_nobody", &conn).await.unwrap());
        // A look that asked between evt_1 and evt_2 answers evt_1 only: evt_2
        // came while it waited, and may say something its answer doesn't.
        BillingEvent::answered("standin", "cus_1", at + TimeDelta::minutes(30), &conn).await.unwrap();
        assert!(!BillingEvent::owed("standin", "evt_1", &conn).await.unwrap());
        assert!(BillingEvent::owed("standin", "evt_2", &conn).await.unwrap());
        let mut pending = BillingEvent::pending("standin", &conn).await.unwrap();
        pending.sort();
        assert_eq!(
            pending,
            vec![("cus_1".to_owned(), at + TimeDelta::hours(1)), ("cus_2".to_owned(), at + TimeDelta::hours(2))]
        );
        // One that asked as evt_2 came answers it too, and nobody else's.
        BillingEvent::answered("standin", "cus_1", at + TimeDelta::hours(1), &conn).await.unwrap();
        assert!(!BillingEvent::owed("standin", "evt_2", &conn).await.unwrap());
        assert!(BillingEvent::owed("standin", "evt_3", &conn).await.unwrap());
        assert_eq!(
            BillingEvent::pending("standin", &conn).await.unwrap(),
            vec![("cus_2".to_owned(), at + TimeDelta::hours(2))]
        );
        // Answered isn't forgotten: the id still drops a repeat.
        assert!(!BillingEvent::record("standin", "evt_2", Some("cus_1"), at, &conn).await.unwrap());

        // Kept 35 days: cleared by when they came.
        assert_eq!(BillingEvent::clear_before(at + TimeDelta::minutes(30), &conn).await.unwrap(), 3);
        assert!(BillingEvent::record("standin", "evt_1", None, at, &conn).await.unwrap());
        assert!(!BillingEvent::record("standin", "evt_2", None, at, &conn).await.unwrap());
    }

    #[rocket::async_test]
    async fn a_customer_pays_for_one_plan() {
        let conn = DbPool::for_test().await;
        let ana = person(&conn).await;
        let bo = person(&conn).await;
        assert_eq!(BillingCustomer::of("standin", &ana, &conn).await.unwrap(), None);
        assert!(BillingCustomer::record("standin", "cus_a", &ana, noon(), &conn).await.unwrap());
        assert_eq!(BillingCustomer::of("standin", &ana, &conn).await.unwrap().as_deref(), Some("cus_a"));
        assert_eq!(BillingCustomer::whose("standin", "cus_a", &conn).await.unwrap(), Some(ana.clone()));
        assert_eq!(BillingCustomer::whose("standin", "cus_nobody", &conn).await.unwrap(), None);
        // Neither the customer nor the plan takes a second.
        assert!(!BillingCustomer::record("standin", "cus_a", &bo, noon(), &conn).await.unwrap());
        assert!(!BillingCustomer::record("standin", "cus_b", &ana, noon(), &conn).await.unwrap());
        // At another provider, a plan has a customer of its own.
        assert!(BillingCustomer::record("other", "cus_a", &bo, noon(), &conn).await.unwrap());
        assert_eq!(BillingCustomer::whose("standin", "cus_a", &conn).await.unwrap(), Some(ana));
    }
}

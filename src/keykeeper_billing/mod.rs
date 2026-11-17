// Keykeeper: learning who has paid (DESIGN.md, "Plans and billing", "Learning
// who has paid" and "Self-hosted servers", in the meta repo).
//
// Everything specific to a payment provider sits behind five calls (`Provider`)
// and the rest of the server knows only their answers:
//
//   1. a page to pay, or to put a card on file, for a plan and whose it is;
//   2. a page to manage it: the card, past invoices, canceling;
//   3. invoice a customer for some lines, once, for a month;
//   4. whether a webhook is really the provider's, and which customer it's about;
//   5. a customer's standing now: which plan, good through when, renewing or not;
//
// and one more, for when an account or an organization is deleted: cancel at
// once whatever the provider bills that customer for (`cancel_at_provider`).
//
// A webhook only ever causes a look: the server never writes a plan from what a
// webhook's body says. It asks the provider (call 5) and writes that answer
// (`look`). So an event that comes twice, late, out of order, or replayed can
// only cause one more look at the truth. A plan never ends on a guess: when the
// provider can't be asked, the last answer stands and the look is tried again.
//
// All of it is a second switch, BILLING_PROVIDER, which does nothing unless
// PLANS_ENFORCED is on. Without both, `billing()` is None: no route here
// exists, no job runs, and nothing is asked of anyone. Billing by the day
// after each month, for an MSP's pool and a Business organization with no
// MSP (`invoices.rs`), is on where BILLING_INVOICE_SCHEDULE isn't blank too,
// with a seat's prices from the environment (`by_the_day()`).
//
// The provider's secrets come from the environment only (`init`). They're
// never in CONFIG, so the admin page, its diagnostics, and the config file
// never see them, and `Secret` can't be printed, so no log or error can carry one.

mod invoices;
mod signature;
mod standin;
mod stripe;

pub use invoices::{ByTheDay, invoice_month_job};

use std::{
    collections::{BTreeMap, HashMap},
    sync::{LazyLock, Mutex, OnceLock, PoisonError},
    time::{Duration, Instant},
};

use chrono::{NaiveDateTime, TimeDelta, Utc};

use crate::{
    CONFIG,
    api::{ApiResult, Notify, WS_USERS, core::keykeeper_plans::plan_changed},
    db::{
        DbConn, DbPool,
        models::{
            BillingCustomer, BillingEvent, Plan, PlanName, PlanOwner, PlanState, ProviderAnswer, SetBy, Standing,
            plans_a_provider_set, write_provider_answer,
        },
    },
};

/// A secret from the environment. It has no Debug or Display, so it can't
/// reach a log, an error, or a page by accident.
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// The provider couldn't be asked, or its answer couldn't be read. It says
/// nothing more on purpose: what went wrong is logged where it happened,
/// without a secret or a body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unreachable;

/// Call 1's answer: the page, and the provider's customer it's for.
pub struct PayPage {
    pub url: String,
    pub customer: String,
}

/// One line of a month's invoice (call 3), in `invoices::CURRENCY`.
pub struct InvoiceLine {
    pub description: String,
    pub amount_cents: i64,
}

/// What call 4 takes from a webhook whose signature checked out: its id, its
/// mode, and the customer it's about, and nothing else.
#[derive(Debug)]
pub struct Event {
    pub id: String,
    /// The provider's live mode, not a test one.
    pub live: bool,
    pub customer: Option<String>,
}

/// What the rest of the server asks a payment provider. An adapter for each
/// provider implements it; `Adapter` picks the one BILLING_PROVIDER names.
pub trait Provider {
    /// Whether this server's account at the provider is its live one. An
    /// event for the other mode is dropped.
    fn live(&self) -> bool;

    /// The request header a webhook's signature comes in.
    fn signature_header(&self) -> &'static str;

    /// Whether people can pay for `plan` on the provider's pages yet.
    fn takes(&self, plan: PlanName) -> bool;

    /// Call 1: a page on the provider's site to pay for `plan`, or for a pool to
    /// put a card on file, for `whose` plan, as `customer` when the provider
    /// already has one for it. `back` is where the provider sends them after.
    async fn pay_page(
        &self,
        whose: &PlanOwner,
        plan: PlanName,
        customer: Option<&str>,
        back: &str,
    ) -> Result<PayPage, Unreachable>;

    /// Call 2: a page on the provider's site to manage what `customer` pays for.
    async fn manage_page(&self, customer: &str, back: &str) -> Result<String, Unreachable>;

    /// Call 3: invoice `customer` for `lines`, once for `month` ("2027-01"),
    /// whatever happens: `key` is the same every time it's asked for that
    /// plan and month, and asking again with it finds what the first asking
    /// made. The invoice collects from the card on file by itself. Answers the
    /// provider's id for the invoice.
    async fn invoice(
        &self,
        customer: &str,
        month: &str,
        lines: &[InvoiceLine],
        key: &str,
    ) -> Result<String, Unreachable>;

    /// Call 4: whether a webhook is really the provider's (its signature, against
    /// each secret in use, and its timestamp), and if so its id, mode, and
    /// customer. Nothing in the body is read until the signature checks out.
    fn event(&self, signature: Option<&str>, body: &[u8], now: i64) -> Result<Event, &'static str>;

    /// Call 5: `customer`'s standing now, as the customer that pays for
    /// `whose` plan (the server's own record says whose). None when the
    /// provider has nothing for them: never paid, or nothing started.
    async fn standing(&self, customer: &str, whose: &PlanOwner) -> Result<Option<ProviderAnswer>, Unreachable>;

    /// When the account or organization `customer` pays for is deleted: cancel
    /// at once everything the provider bills them for. Answers how many things
    /// it canceled.
    async fn cancel(&self, customer: &str) -> Result<usize, Unreachable>;
}

/// The provider BILLING_PROVIDER names.
pub enum Adapter {
    /// `standin`: the test stand-in in the meta repo's e2e/, which only talks
    /// to a loopback address.
    Standin(standin::Standin),
    /// `stripe`: Stripe, for Premium and Families.
    Stripe(stripe::Stripe),
}

impl Provider for Adapter {
    fn live(&self) -> bool {
        match self {
            Self::Standin(p) => p.live(),
            Self::Stripe(p) => p.live(),
        }
    }

    fn signature_header(&self) -> &'static str {
        match self {
            Self::Standin(p) => p.signature_header(),
            Self::Stripe(p) => p.signature_header(),
        }
    }

    fn takes(&self, plan: PlanName) -> bool {
        match self {
            Self::Standin(p) => p.takes(plan),
            Self::Stripe(p) => p.takes(plan),
        }
    }

    async fn pay_page(
        &self,
        whose: &PlanOwner,
        plan: PlanName,
        customer: Option<&str>,
        back: &str,
    ) -> Result<PayPage, Unreachable> {
        match self {
            Self::Standin(p) => p.pay_page(whose, plan, customer, back).await,
            Self::Stripe(p) => p.pay_page(whose, plan, customer, back).await,
        }
    }

    async fn manage_page(&self, customer: &str, back: &str) -> Result<String, Unreachable> {
        match self {
            Self::Standin(p) => p.manage_page(customer, back).await,
            Self::Stripe(p) => p.manage_page(customer, back).await,
        }
    }

    async fn invoice(
        &self,
        customer: &str,
        month: &str,
        lines: &[InvoiceLine],
        key: &str,
    ) -> Result<String, Unreachable> {
        match self {
            Self::Standin(p) => p.invoice(customer, month, lines, key).await,
            Self::Stripe(p) => p.invoice(customer, month, lines, key).await,
        }
    }

    fn event(&self, signature: Option<&str>, body: &[u8], now: i64) -> Result<Event, &'static str> {
        match self {
            Self::Standin(p) => p.event(signature, body, now),
            Self::Stripe(p) => p.event(signature, body, now),
        }
    }

    async fn standing(&self, customer: &str, whose: &PlanOwner) -> Result<Option<ProviderAnswer>, Unreachable> {
        match self {
            Self::Standin(p) => p.standing(customer, whose).await,
            Self::Stripe(p) => p.standing(customer, whose).await,
        }
    }

    async fn cancel(&self, customer: &str) -> Result<usize, Unreachable> {
        match self {
            Self::Standin(p) => p.cancel(customer).await,
            Self::Stripe(p) => p.cancel(customer).await,
        }
    }
}

/// The provider this server learns from, where PLANS_ENFORCED and
/// BILLING_PROVIDER are both set.
pub struct Billing {
    /// BILLING_PROVIDER, which names the webhook route and is written on
    /// the plans it sets.
    pub name: &'static str,
    adapter: Adapter,
    /// Billing by the day: a seat's prices, where BILLING_INVOICE_SCHEDULE
    /// isn't blank. None: no month is invoiced, and Stripe doesn't take a
    /// card for Business or a pool.
    by_the_day: Option<ByTheDay>,
}

impl Billing {
    pub fn provider(&self) -> &Adapter {
        &self.adapter
    }
}

/// The settings and secrets, as read from the environment once at start.
static BILLING: OnceLock<Option<Billing>> = OnceLock::new();

/// The provider, where PLANS_ENFORCED and BILLING_PROVIDER are both set, and
/// None everywhere else.
pub fn billing() -> Option<&'static Billing> {
    BILLING.get().and_then(Option::as_ref)
}

/// Billing by the day after each month, and its prices: where PLANS_ENFORCED
/// and BILLING_PROVIDER are both set and BILLING_INVOICE_SCHEDULE isn't blank.
pub fn by_the_day() -> Option<(&'static Billing, &'static ByTheDay)> {
    billing().and_then(|billing| billing.by_the_day.as_ref().map(|prices| (billing, prices)))
}

/// Whether people can be sent to a provider's pages: plans are enforced and
/// a provider is set. `Terms::payments`, and through it the sync's `canPay`
/// and the payment routes, ask here.
pub fn payments_on() -> bool {
    billing().is_some()
}

/// A provider's secrets, by the names the server reads them under.
const API_KEY: &str = "BILLING_API_KEY";
const WEBHOOK_SECRET: &str = "BILLING_WEBHOOK_SECRET";
const WEBHOOK_SECRET_OLD: &str = "BILLING_WEBHOOK_SECRET_OLD";
/// Stripe's prices for Premium and Families. They aren't secrets, and are
/// read from the environment beside them.
const PRICE_PREMIUM: &str = "BILLING_PRICE_PREMIUM";
const PRICE_FAMILIES: &str = "BILLING_PRICE_FAMILIES";

/// An http or https address on this machine, written as one: a name could be
/// made to point anywhere. The only address BILLING_API_BASE may be.
pub(super) fn loopback_url(api_base: &str) -> Option<url::Url> {
    let url = url::Url::parse(api_base).ok()?;
    let ip = match url.host()? {
        url::Host::Ipv4(ip) => std::net::IpAddr::V4(ip),
        url::Host::Ipv6(ip) => std::net::IpAddr::V6(ip),
        url::Host::Domain(_) => return None,
    };
    (ip.is_loopback() && matches!(url.scheme(), "http" | "https")).then_some(url)
}

/// Works out the provider from the settings and the environment. Pure, so
/// each way a server can be set up is tested. The problems name settings
/// and never hold a value. `invoicing` is whether BILLING_INVOICE_SCHEDULE
/// isn't blank: then a seat's prices are needed, whichever the provider.
fn from_settings(
    enforced: bool,
    provider: &str,
    api_base: &str,
    invoicing: bool,
    env: &dyn Fn(&'static str) -> Option<String>,
) -> Result<Option<Billing>, String> {
    if provider.is_empty() || !enforced {
        return Ok(None);
    }
    let by_the_day = if invoicing {
        Some(ByTheDay::from_env(env)?)
    } else {
        None
    };
    let secret = |name| env(name).filter(|value| !value.is_empty()).map(Secret::new);
    let api_key = secret(API_KEY).ok_or("`BILLING_PROVIDER` needs `BILLING_API_KEY` in the environment")?;
    let mut webhook_secrets =
        vec![secret(WEBHOOK_SECRET).ok_or("`BILLING_PROVIDER` needs `BILLING_WEBHOOK_SECRET` in the environment")?];
    webhook_secrets.extend(secret(WEBHOOK_SECRET_OLD));
    let (name, adapter) = match provider {
        "standin" => ("standin", Adapter::Standin(standin::Standin::new(api_base, api_key, webhook_secrets)?)),
        "stripe" => {
            let prices = stripe::Prices {
                premium: env(PRICE_PREMIUM).unwrap_or_default(),
                families: env(PRICE_FAMILIES).unwrap_or_default(),
            };
            let stripe = stripe::Stripe::new(api_base, api_key, webhook_secrets, prices, by_the_day.is_some())?;
            ("stripe", Adapter::Stripe(stripe))
        }
        _ => {
            return Err(
                "`BILLING_PROVIDER` names a provider this server doesn't have: leave it empty, set `stripe`, or set `standin` for tests".to_owned(),
            );
        }
    };
    Ok(Some(Billing {
        name,
        adapter,
        by_the_day,
    }))
}

/// Reads the provider's settings and secrets, once, before any route is
/// mounted or job scheduled. A server set up wrong doesn't start.
pub fn init() {
    let provider = CONFIG.billing_provider();
    let invoicing = !CONFIG.billing_invoice_schedule().is_empty();
    match from_settings(
        CONFIG.plans_enforced(),
        &provider,
        &CONFIG.billing_api_base(),
        invoicing,
        &crate::util::get_env_str_value,
    ) {
        Ok(found) => {
            match &found {
                Some(billing) if billing.by_the_day.is_some() => info!(
                    "Plans are paid for through the payment provider `{}`, and Business and MSPs' pools by the day after each month.",
                    billing.name
                ),
                Some(billing) => info!("Plans are paid for through the payment provider `{}`.", billing.name),
                None if !provider.is_empty() => warn!("BILLING_PROVIDER does nothing while PLANS_ENFORCED is off."),
                None => {}
            }
            BILLING.get_or_init(|| found);
        }
        Err(problem) => {
            error!("{problem}");
            std::process::exit(1);
        }
    }
}

/// What the provider answered about something the server gave it, checked
/// before it's written: ids short and plain, so they're safe to keep and
/// put in a path.
pub fn plain_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 255 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// One look, or one new customer, at a time: so the answer written last is
/// the one fetched last, and an owner never gets two customers at once.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What a look came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Looked {
    /// The provider answered, and its answer is written.
    Answered,
    /// The provider couldn't be asked, or answered something that can't be
    /// written. The last answer stands, and the look is tried again.
    Failed,
}

/// Asks the provider about `customer`, who pays for `whose` plan, and writes
/// its answer to `plans`, with when it was asked and that the provider set
/// it. The people a change reaches are told to sync. Every webhook it was
/// owed for is then answered.
pub async fn look(billing: &Billing, whose: &PlanOwner, customer: &str, conn: &DbConn) -> Looked {
    let _one = ONE_AT_A_TIME.lock().await;
    look_held(billing, whose, customer, conn).await
}

/// The billing job's look, decided on at `since`: none if the provider has
/// answered about the plan since then, which a webhook's look or an earlier
/// run of the job still going may have done while this one waited its turn.
/// The schedule starts a run on each tick without waiting for the last.
async fn look_unless_answered_since(
    billing: &Billing,
    whose: &PlanOwner,
    customer: &str,
    since: NaiveDateTime,
    conn: &DbConn,
) -> Looked {
    let _one = ONE_AT_A_TIME.lock().await;
    if let Ok(Some(row)) = Plan::find(whose, conn).await
        && answered_since(row.checked_at, since)
    {
        return Looked::Answered;
    }
    look_held(billing, whose, customer, conn).await
}

/// Whether the provider's last answer, at `checked_at`, came at or after
/// `since`.
fn answered_since(checked_at: Option<NaiveDateTime>, since: NaiveDateTime) -> bool {
    checked_at.is_some_and(|checked_at| checked_at >= since)
}

/// `look`, with `ONE_AT_A_TIME` held.
async fn look_held(billing: &Billing, whose: &PlanOwner, customer: &str, conn: &DbConn) -> Looked {
    let Ok(answer) = billing.provider().standing(customer, whose).await else {
        warn!(
            "The payment provider couldn't be asked about the plan of {whose}. Its last answer stands, and it'll be asked again."
        );
        return Looked::Failed;
    };
    if let Some(answer) = &answer
        && !answer.plan.fits(whose)
    {
        error!(
            "The payment provider answered a `{}` plan for {whose}, which that plan can't be. Nothing was written, and it'll be asked again.",
            answer.plan.as_str()
        );
        return Looked::Failed;
    }
    let now = Utc::now().naive_utc();
    let changed = match write_provider_answer(whose, billing.name, customer, answer.as_ref(), now, conn).await {
        Ok(changed) => changed,
        Err(e) => {
            error!("The payment provider's answer about the plan of {whose} couldn't be written: {e:#?}");
            return Looked::Failed;
        }
    };
    if let Err(e) = BillingEvent::answered(billing.name, customer, conn).await {
        warn!("Couldn't note that the webhooks about the plan of {whose} were answered: {e:#?}");
    }
    if changed {
        info!("The payment provider's answer changed the plan of {whose}.");
        let nt: Notify<'_> = (&*WS_USERS).into();
        plan_changed(whose, conn, nt).await;
    }
    Looked::Answered
}

/// The look a webhook asked for, about `customer`. A customer the server
/// never gave the provider is nobody it knows: the webhook is dropped.
pub async fn look_at_customer(billing: &Billing, customer: &str, conn: &DbConn) -> Looked {
    match BillingCustomer::whose(billing.name, customer, conn).await {
        Ok(Some(whose)) => look(billing, &whose, customer, conn).await,
        Ok(None) => {
            info!(
                "A webhook from the payment provider was about a customer this server doesn't know, and was dropped."
            );
            if let Err(e) = BillingEvent::answered(billing.name, customer, conn).await {
                warn!("Couldn't drop the webhooks about a customer this server doesn't know: {e:#?}");
            }
            Looked::Answered
        }
        Err(e) => {
            warn!("Couldn't find whose plan a webhook was about, so it'll be looked at again: {e:#?}");
            Looked::Failed
        }
    }
}

/// How long a provider may go without answering about a plan before the
/// operator is told.
const TELL_THE_OPERATOR_AFTER: TimeDelta = TimeDelta::days(1);

/// How long a webhook's id is kept: longer than a provider resends one.
const KEEP_EVENTS_FOR: TimeDelta = TimeDelta::days(35);

/// Whether the provider is asked again about a plan it set, last answered at
/// `checked_at` and good through `until`, at `now`: once its last answer is a
/// day old, and once `until` has passed since that answer.
pub fn due_a_look(checked_at: Option<NaiveDateTime>, until: Option<NaiveDateTime>, now: NaiveDateTime) -> bool {
    let Some(checked_at) = checked_at else {
        return true;
    };
    checked_at <= now - TimeDelta::days(1) || until.is_some_and(|until| until < now && checked_at <= until)
}

/// The billing job (BILLING_LOOK_SCHEDULE): asks the provider again about
/// each plan it set that's due a look (`due_a_look`) and about each customer
/// a webhook asked about whose look got no answer, and clears webhooks' ids
/// after 35 days. A plan whose provider hasn't answered for a day is the
/// operator's to know about: one error in the log for each run, with how
/// many, while the plans' `checkedAt` on the admin page says since when.
pub async fn look_again_job(pool: DbPool) {
    let Some(billing) = billing() else {
        return;
    };
    let Ok(conn) = pool.get().await else {
        error!("Failed to get DB connection while asking the payment provider again");
        return;
    };
    let now = Utc::now().naive_utc();
    if let Err(e) = BillingEvent::clear_before(now - KEEP_EVENTS_FOR, &conn).await {
        warn!("Couldn't clear old webhooks' ids: {e:#?}");
    }

    // Each customer once, with whose plan it pays for and since when the
    // provider's word about it has been owed.
    let mut asking: BTreeMap<String, (PlanOwner, NaiveDateTime)> = BTreeMap::new();
    match plans_a_provider_set(billing.name, &conn).await {
        Ok(plans) => {
            for (whose, customer, checked_at, until) in plans {
                if due_a_look(checked_at, until, now) {
                    asking.insert(customer, (whose, checked_at.unwrap_or(now)));
                }
            }
        }
        Err(e) => error!("Couldn't load the plans to ask the payment provider about: {e:#?}"),
    }
    match BillingEvent::pending(billing.name, &conn).await {
        Ok(pending) => {
            for (customer, since) in pending {
                match BillingCustomer::whose(billing.name, &customer, &conn).await {
                    Ok(Some(whose)) => {
                        let entry = asking.entry(customer).or_insert((whose, since));
                        entry.1 = entry.1.min(since);
                    }
                    Ok(None) => {
                        look_at_customer(billing, &customer, &conn).await;
                    }
                    Err(e) => warn!("Couldn't find whose plan a webhook was about: {e:#?}"),
                }
            }
        }
        Err(e) => error!("Couldn't load the webhooks still owed a look: {e:#?}"),
    }

    let mut unanswered_for_a_day = 0_usize;
    for (customer, (whose, since)) in asking {
        if look_unless_answered_since(billing, &whose, &customer, now, &conn).await == Looked::Failed
            && since <= now - TELL_THE_OPERATOR_AFTER
        {
            unanswered_for_a_day += 1;
        }
    }
    if unanswered_for_a_day > 0 {
        error!(
            "The payment provider `{}` hasn't answered about {unanswered_for_a_day} plan(s) for more than a day. Their last answers stand, and the server keeps asking (BILLING_LOOK_SCHEDULE). Each plan's checkedAt on the admin page says when it last answered.",
            billing.name
        );
    }
}

/// When each plan was last looked at because someone asked, so it's at most
/// once a minute for each.
static ASKED: LazyLock<Mutex<HashMap<PlanOwner, Instant>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

const ASK_AT_MOST_EVERY: Duration = Duration::from_secs(60);

/// Whether someone who manages `whose` plan may have it looked at now: at
/// most once a minute for each plan.
pub fn may_look_now(whose: &PlanOwner) -> bool {
    let now = Instant::now();
    let mut asked = ASKED.lock().unwrap_or_else(PoisonError::into_inner);
    asked.retain(|_, at| now.duration_since(*at) < ASK_AT_MOST_EVERY);
    if asked.contains_key(whose) {
        return false;
    }
    asked.insert(whose.clone(), now);
    true
}

/// What a person reads when the provider can't be reached for a page.
pub const PROVIDER_UNREACHABLE: &str = "The payment provider can't be reached right now. Try again in a few minutes.";

/// What a person reads when they ask to pay for a plan the provider can't
/// take: with Stripe, a pool's card on file and Business, while billing by
/// the day is off (BILLING_INVOICE_SCHEDULE blank).
pub fn not_yet(plan: PlanName) -> &'static str {
    match plan {
        PlanName::Msp => "An MSP's plan can't be paid for online yet.",
        PlanName::Business => "Business can't be paid for online yet.",
        PlanName::Premium | PlanName::Families => "This plan can't be paid for online yet.",
    }
}

/// Whether `row` is a plan `provider` set that's paid for and still in effect
/// at `at`: in good standing, or in grace while a payment is retried. Someone
/// with such a plan already pays for it, so asking to pay again gets the page
/// to manage it, never a second subscription.
fn paid_through_provider(row: &Plan, provider: &str, at: NaiveDateTime, grace_days: i64) -> bool {
    row.set_by == SetBy::Provider.as_str()
        && row.provider.as_deref() == Some(provider)
        && row.standing() != Standing::None
        && matches!(row.state_at(at, grace_days), PlanState::Active | PlanState::PaymentDue)
}

/// The page to manage `whose` plan, when a provider already bills them for
/// one that's in effect. The provider is asked first, so a payment whose
/// webhook hasn't come yet counts too; when it can't be asked, its last
/// answer is what counts.
async fn already_paid(billing: &Billing, whose: &PlanOwner, back: &str, conn: &DbConn) -> ApiResult<Option<String>> {
    let Some(customer) = BillingCustomer::of(billing.name, whose, conn).await? else {
        return Ok(None);
    };
    look(billing, whose, &customer, conn).await;
    let grace_days = CONFIG.plan_grace_days();
    let now = Utc::now().naive_utc();
    let paid =
        Plan::find(whose, conn).await?.is_some_and(|row| paid_through_provider(&row, billing.name, now, grace_days));
    if !paid {
        return Ok(None);
    }
    info!("The plan of {whose} is paid for already, so asking to pay again gets the page to manage it.");
    manage_page(billing, whose, back, conn).await
}

/// A page to pay for `plan` (call 1), for `whose` plan. The provider's
/// customer for it is recorded the first time, and the same one is used
/// after, so a payment's webhooks are about someone the server knows.
///
/// Someone the provider already bills for a plan that's in effect gets the
/// page to manage it instead, whatever the button they pressed said: the
/// server checks, so nobody pays twice.
pub async fn pay_page(
    billing: &Billing,
    whose: &PlanOwner,
    plan: PlanName,
    back: &str,
    conn: &DbConn,
) -> ApiResult<String> {
    if let Some(url) = already_paid(billing, whose, back, conn).await? {
        return Ok(url);
    }
    if !billing.provider().takes(plan) {
        err!(not_yet(plan))
    }
    let _one = ONE_AT_A_TIME.lock().await;
    let known = BillingCustomer::of(billing.name, whose, conn).await?;
    let Ok(page) = billing.provider().pay_page(whose, plan, known.as_deref(), back).await else {
        err!(PROVIDER_UNREACHABLE)
    };
    if !plain_id(&page.customer) || !web_page(&page.url) {
        error!("The payment provider's page to pay for the plan of {whose} couldn't be used.");
        err!(PROVIDER_UNREACHABLE)
    }
    match known {
        Some(known) if known != page.customer => {
            error!("The payment provider answered another customer for the plan of {whose}, so its page wasn't used.");
            err!(PROVIDER_UNREACHABLE)
        }
        Some(_) => {}
        None => {
            if !BillingCustomer::record(billing.name, &page.customer, whose, Utc::now().naive_utc(), conn).await? {
                error!("The payment provider answered a customer that pays for another plan, so its page wasn't used.");
                err!(PROVIDER_UNREACHABLE)
            }
        }
    }
    Ok(page.url)
}

/// A page to manage `whose` plan (call 2): its card, past invoices, and
/// canceling. None when nothing has been paid for it at this provider.
pub async fn manage_page(billing: &Billing, whose: &PlanOwner, back: &str, conn: &DbConn) -> ApiResult<Option<String>> {
    let Some(customer) = BillingCustomer::of(billing.name, whose, conn).await? else {
        return Ok(None);
    };
    match billing.provider().manage_page(&customer, back).await {
        Ok(url) if web_page(&url) => Ok(Some(url)),
        Ok(_) => {
            error!("The payment provider's page to manage the plan of {whose} couldn't be used.");
            err!(PROVIDER_UNREACHABLE)
        }
        Err(Unreachable) => err!(PROVIDER_UNREACHABLE),
    }
}

/// Before an account or an organization is deleted: asks the provider to
/// cancel at once whatever it bills `whose` customer for, so nobody is
/// charged for something that's gone. Whoever has a customer at the provider
/// is asked about, whatever their plan says now, since the server's record of
/// who is a customer is what says who could be billed.
///
/// It never stops the deletion: when the provider can't be reached, or the
/// customer can't be looked up, the operator is told in the log, with the
/// provider's id for the customer so it can be canceled in the provider's
/// dashboard, and the deletion goes ahead. Where PLANS_ENFORCED or
/// BILLING_PROVIDER is off, it does nothing and reads nothing.
pub async fn cancel_at_provider(whose: &PlanOwner, conn: &DbConn) {
    let Some(billing) = billing() else {
        return;
    };
    let customer = match BillingCustomer::of(billing.name, whose, conn).await {
        Ok(Some(customer)) => customer,
        Ok(None) => return,
        Err(e) => {
            error!(
                "{whose} is being deleted, and whether the payment provider `{}` bills it for anything couldn't be read: {e:#?}. The deletion goes ahead: look for it in the provider's dashboard.",
                billing.name
            );
            return;
        }
    };
    match billing.provider().cancel(&customer).await {
        Ok(0) => {}
        Ok(canceled) => info!(
            "{whose} is being deleted, so the payment provider `{}` canceled {canceled} subscription(s) of its customer {customer}.",
            billing.name
        ),
        Err(Unreachable) => error!(
            "{whose} is being deleted, and the payment provider `{}` couldn't be asked to cancel what its customer {customer} pays for. The deletion goes ahead: cancel it in the provider's dashboard.",
            billing.name
        ),
    }
}

/// A page a person's browser can open.
fn web_page(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|url| matches!(url.scheme(), "https" | "http") && url.host().is_some())
}

/// Where the provider sends someone after its page: the web vault's Plan
/// page for that plan, a person's in their settings, an organization's in its
/// admin console, and a pool's in the MSP console.
pub fn back_to_plan(whose: &PlanOwner) -> String {
    let domain = CONFIG.domain();
    match whose {
        PlanOwner::User(_) => format!("{domain}/#/settings/plan"),
        PlanOwner::Organization(id) => format!("{domain}/#/organizations/{id}/plan"),
        PlanOwner::Msp(_) => format!("{domain}/#/msp"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::{PlanNow, Terms, not_enforced_json};

    fn env<'a>(values: &'a [(&'static str, &'static str)]) -> impl Fn(&'static str) -> Option<String> + 'a {
        move |name| values.iter().find(|(n, _)| *n == name).map(|(_, v)| (*v).to_owned())
    }

    const SECRETS: [(&str, &str); 2] =
        [("BILLING_API_KEY", "sk_test_standin"), ("BILLING_WEBHOOK_SECRET", "whsec_standin")];

    /// Stripe's settings, every value made up.
    const STRIPE: [(&str, &str); 4] = [
        ("BILLING_API_KEY", "rk_test_made_up"),
        ("BILLING_WEBHOOK_SECRET", "whsec_made_up"),
        ("BILLING_PRICE_PREMIUM", "price_premium_made_up"),
        ("BILLING_PRICE_FAMILIES", "price_families_made_up"),
    ];

    /// Stripe's settings with one changed, or without it when `value` is None.
    fn stripe_with(name: &'static str, value: Option<&'static str>) -> Vec<(&'static str, &'static str)> {
        let mut values: Vec<_> = STRIPE.iter().copied().filter(|(n, _)| *n != name).collect();
        if let Some(value) = value {
            values.push((name, value));
        }
        values
    }

    #[test]
    fn stripe_starts_only_with_a_restricted_key_its_signing_secret_and_both_prices() {
        let started = |base: &str, values: &[(&'static str, &'static str)]| {
            from_settings(true, "stripe", base, false, &env(values))
        };
        // Stripe's own address, with BILLING_API_BASE empty, in either mode.
        let test = started("", &STRIPE).unwrap().unwrap();
        assert_eq!(test.name, "stripe");
        assert!(!test.provider().live());
        assert_eq!(test.provider().signature_header(), "Stripe-Signature");
        let live = started("", &stripe_with("BILLING_API_KEY", Some("rk_live_made_up"))).unwrap().unwrap();
        assert!(live.provider().live());
        // The stand-in on this machine, with a test key.
        assert!(started("http://127.0.0.1:8128", &STRIPE).unwrap().is_some());
        // Nothing without PLANS_ENFORCED, and nothing is checked.
        assert!(from_settings(false, "stripe", "https://api.example.com", false, &env(&[])).unwrap().is_none());

        let refused = |base: &str, values: Vec<(&'static str, &'static str)>| {
            started(base, &values).err().unwrap_or_else(|| "it was taken".to_owned())
        };
        // A live key is only ever sent to Stripe: never beside BILLING_API_BASE.
        assert!(
            refused("http://127.0.0.1:8128", stripe_with("BILLING_API_KEY", Some("rk_live_made_up"))).contains("live")
        );
        // BILLING_API_BASE is only an address on this machine.
        for base in ["https://api.example.com", "http://localhost:8128", "http://192.0.2.10:8128"] {
            assert!(refused(base, STRIPE.to_vec()).contains("BILLING_API_BASE"), "{base}");
        }
        // The account's full secret key, in either mode, for a restricted one.
        for key in ["sk_live_made_up", "sk_test_made_up"] {
            assert!(refused("", stripe_with("BILLING_API_KEY", Some(key))).contains("restricted key"), "{key}");
        }
        assert!(refused("", stripe_with("BILLING_API_KEY", Some("pk_live_made_up"))).contains("restricted key"));
        // Each setting is needed.
        assert!(refused("", stripe_with("BILLING_API_KEY", None)).contains("BILLING_API_KEY"));
        assert!(refused("", stripe_with("BILLING_WEBHOOK_SECRET", None)).contains("BILLING_WEBHOOK_SECRET"));
        for price in ["BILLING_PRICE_PREMIUM", "BILLING_PRICE_FAMILIES"] {
            assert!(refused("", stripe_with(price, None)).contains(price), "{price}");
            assert!(refused("", stripe_with(price, Some(""))).contains(price), "{price}");
            assert!(refused("", stripe_with(price, Some("prod_made_up"))).contains(price), "{price}");
        }
        // A signing secret that isn't one.
        assert!(refused("", stripe_with("BILLING_WEBHOOK_SECRET", Some("rk_test_made_up"))).contains("whsec_"));
        let mut old = STRIPE.to_vec();
        old.push(("BILLING_WEBHOOK_SECRET_OLD", "not_a_secret"));
        assert!(refused("", old).contains("BILLING_WEBHOOK_SECRET_OLD"));
        // No problem holds a value.
        for values in [
            stripe_with("BILLING_API_KEY", Some("sk_live_made_up")),
            stripe_with("BILLING_API_KEY", Some("rk_live_made_up")),
            stripe_with("BILLING_PRICE_PREMIUM", Some("prod_made_up")),
        ] {
            let problem = refused("http://127.0.0.1:8128", values);
            assert!(!problem.contains("made_up"), "{problem}");
        }
    }

    /// Billing by the day: on where BILLING_INVOICE_SCHEDULE isn't blank, and
    /// then a seat's prices are needed and checked at start, with Stripe or
    /// the stand-in. Off, nothing about them is read.
    #[test]
    fn billing_by_the_day_needs_a_seats_prices_and_then_stripe_takes_a_card() {
        let with_prices = |msp: Option<&'static str>, business: Option<&'static str>| {
            let mut values = STRIPE.to_vec();
            values.extend(msp.map(|value| ("BILLING_SEAT_PRICES_MSP", value)));
            values.extend(business.map(|value| ("BILLING_SEAT_PRICES_BUSINESS", value)));
            values
        };
        let prices = with_prices(Some("1:1.50,500:1.25,2500:1.00"), Some("1:2.00,250:1.75"));
        let on = from_settings(true, "stripe", "", true, &env(&prices)).unwrap().unwrap();
        let by_the_day = on.by_the_day.as_ref().unwrap();
        assert_eq!(by_the_day.msp.price_for(50_000), 125);
        assert_eq!(by_the_day.business.price_for(24_900), 200);
        assert!(on.provider().takes(PlanName::Business) && on.provider().takes(PlanName::Msp));
        // Off: no prices needed, none read, and Business and a pool aren't taken.
        let off = from_settings(true, "stripe", "", false, &env(&prices)).unwrap().unwrap();
        assert!(off.by_the_day.is_none());
        assert!(!off.provider().takes(PlanName::Business) && !off.provider().takes(PlanName::Msp));
        assert!(from_settings(true, "stripe", "", false, &env(&STRIPE)).unwrap().unwrap().by_the_day.is_none());
        // On without both prices, or with one that doesn't read: no start.
        for (values, missing) in [
            (with_prices(None, Some("1:2.00")), "BILLING_SEAT_PRICES_MSP"),
            (with_prices(Some("1:1.50"), None), "BILLING_SEAT_PRICES_BUSINESS"),
            (with_prices(Some("1:1.50"), Some("2:2.00")), "BILLING_SEAT_PRICES_BUSINESS"),
            (with_prices(Some("1.50"), Some("1:2.00")), "BILLING_SEAT_PRICES_MSP"),
        ] {
            let problem = from_settings(true, "stripe", "", true, &env(&values)).err().unwrap();
            assert!(problem.contains(missing), "{problem}");
        }
        // The stand-in needs them too.
        assert!(from_settings(true, "standin", "http://127.0.0.1:1", true, &env(&SECRETS)).is_err());
        // Nothing without PLANS_ENFORCED or a provider.
        assert!(from_settings(false, "stripe", "", true, &env(&[])).unwrap().is_none());
        assert!(from_settings(true, "", "", true, &env(&[])).unwrap().is_none());
    }

    #[test]
    fn both_signing_secrets_while_stripes_is_rolled() {
        let mut two = STRIPE.to_vec();
        two.push(("BILLING_WEBHOOK_SECRET_OLD", "whsec_old_made_up"));
        let billing = from_settings(true, "stripe", "", false, &env(&two)).unwrap().unwrap();
        let Adapter::Stripe(stripe) = billing.provider() else {
            panic!("Stripe")
        };
        assert_eq!(stripe.webhook_secrets(), 2);
    }

    fn row(
        set_by: SetBy,
        provider: Option<&str>,
        standing: Standing,
        until: Option<NaiveDateTime>,
        renews: bool,
    ) -> Plan {
        Plan {
            uuid: "row".to_owned(),
            user_uuid: Some("ana".to_owned().into()),
            org_uuid: None,
            msp_uuid: None,
            plan: "premium".to_owned(),
            free_until: None,
            free_why: None,
            standing: standing.as_str().to_owned(),
            until,
            renews,
            billed: "prepaid".to_owned(),
            set_by: set_by.as_str().to_owned(),
            provider: provider.map(str::to_owned),
            provider_customer: provider.map(|_| "cus_1".to_owned()),
            provider_subscription: None,
            checked_at: None,
            updated_at: at(1, 0),
        }
    }

    /// Who gets the page to manage their plan instead of a second checkout.
    #[test]
    fn no_second_subscription() {
        let now = at(10, 12);
        let year = Some(now + TimeDelta::days(365));
        let grace = 14;
        let paid = |row: Plan| paid_through_provider(&row, "stripe", now, grace);
        // Paid through the provider and in good standing, renewing or canceled.
        assert!(paid(row(SetBy::Provider, Some("stripe"), Standing::Until, year, true)));
        assert!(paid(row(SetBy::Provider, Some("stripe"), Standing::Until, year, false)));
        assert!(paid(row(SetBy::Provider, Some("stripe"), Standing::Open, None, true)));
        // In grace while a payment is retried: they manage the card, not pay twice.
        let lapsed = Some(now - TimeDelta::days(3));
        assert!(paid(row(SetBy::Provider, Some("stripe"), Standing::Until, lapsed, true)));
        // Past grace, or canceled and past its date: a new checkout.
        assert!(!paid(row(SetBy::Provider, Some("stripe"), Standing::Until, Some(now - TimeDelta::days(15)), true)));
        assert!(!paid(row(SetBy::Provider, Some("stripe"), Standing::Until, lapsed, false)));
        // Over at the provider, even during a free period the server gave.
        let mut over = row(SetBy::Provider, Some("stripe"), Standing::None, None, false);
        assert!(!paid(over.clone()));
        over.free_until = Some(now + TimeDelta::days(10));
        assert!(!paid(over));
        // A plan the operator or the server set, or another provider's: the provider bills nothing for it.
        assert!(!paid(row(SetBy::Operator, Some("stripe"), Standing::Until, year, true)));
        assert!(!paid(row(SetBy::Operator, None, Standing::Until, year, true)));
        assert!(!paid(row(SetBy::Server, None, Standing::None, None, false)));
        assert!(!paid(row(SetBy::Provider, Some("standin"), Standing::Until, year, true)));
    }

    #[test]
    fn what_stripe_doesnt_take_yet_says_so() {
        assert_eq!(not_yet(PlanName::Business), "Business can't be paid for online yet.");
        assert_eq!(not_yet(PlanName::Msp), "An MSP's plan can't be paid for online yet.");
        let billing = from_settings(true, "stripe", "", false, &env(&STRIPE)).unwrap().unwrap();
        for (plan, takes) in
            [(PlanName::Premium, true), (PlanName::Families, true), (PlanName::Business, false), (PlanName::Msp, false)]
        {
            assert_eq!(billing.provider().takes(plan), takes, "{plan:?}");
        }
        // The stand-in takes every plan.
        let standin = from_settings(true, "standin", "http://127.0.0.1:1", false, &env(&SECRETS)).unwrap().unwrap();
        assert!(
            [PlanName::Premium, PlanName::Families, PlanName::Business, PlanName::Msp]
                .into_iter()
                .all(|plan| standin.provider().takes(plan))
        );
    }

    #[test]
    fn the_same_loopback_rule_for_every_provider() {
        for base in ["http://127.0.0.1:8128", "https://127.0.0.1", "http://127.8.9.10:1", "http://[::1]:8128/v1/"] {
            assert!(loopback_url(base).is_some(), "{base}");
        }
        for base in [
            "",
            "http://localhost:8128",
            "http://127.0.0.1.example.com",
            "http://[::ffff:127.0.0.1]:8128",
            "http://10.0.0.5",
            "ftp://127.0.0.1",
            "https://api.stripe.com",
        ] {
            assert!(loopback_url(base).is_none(), "{base}");
        }
    }

    #[test]
    fn the_provider_is_a_second_switch() {
        let secrets = env(&SECRETS);
        let loopback = "http://127.0.0.1:8124";
        // No provider: nothing, whatever else is set.
        assert!(from_settings(true, "", loopback, false, &secrets).unwrap().is_none());
        assert!(from_settings(false, "", loopback, false, &secrets).unwrap().is_none());
        // A provider does nothing without PLANS_ENFORCED, and nothing is checked.
        assert!(from_settings(false, "standin", loopback, false, &secrets).unwrap().is_none());
        assert!(from_settings(false, "standin", "https://api.example.com", false, &env(&[])).unwrap().is_none());
        // With both, there's a provider.
        let billing = from_settings(true, "standin", loopback, false, &secrets).unwrap().unwrap();
        assert_eq!(billing.name, "standin");
        assert!(!billing.provider().live());
    }

    #[test]
    fn a_server_set_up_wrong_doesnt_start() {
        let loopback = "http://127.0.0.1:8124";
        let refused = |provider, base, values: &[(&'static str, &'static str)]| {
            from_settings(true, provider, base, false, &env(values)).err().unwrap_or_else(|| "it was taken".to_owned())
        };
        // A provider this server doesn't have.
        assert!(refused("nonesuch", loopback, &SECRETS).contains("doesn't have"));
        assert!(refused("Standin", loopback, &SECRETS).contains("doesn't have"));
        assert!(refused("Stripe", loopback, &STRIPE).contains("doesn't have"));
        // Each secret is needed, and an empty one is none.
        assert!(refused("standin", loopback, &[SECRETS[1]]).contains("BILLING_API_KEY"));
        assert!(refused("standin", loopback, &[SECRETS[0]]).contains("BILLING_WEBHOOK_SECRET"));
        assert!(refused("standin", loopback, &[("BILLING_API_KEY", ""), SECRETS[1]]).contains("BILLING_API_KEY"));
        // The stand-in talks only to this machine.
        for base in [
            "",
            "https://api.example.com",
            "http://localhost:8124",
            "http://10.0.0.5:8124",
            "http://192.168.1.2",
            "http://[fd00::5]:8124",
            "http://0.0.0.0:8124",
            "ftp://127.0.0.1",
            "not a url",
        ] {
            assert!(refused("standin", base, &SECRETS).contains("BILLING_API_BASE"), "{base}");
        }
        for base in ["http://127.0.0.1:8124", "https://127.0.0.1", "http://127.8.9.10:1", "http://[::1]:8124/v1/"] {
            assert!(from_settings(true, "standin", base, false, &env(&SECRETS)).is_ok(), "{base}");
        }
        // A key that looks like a live one is never sent to the stand-in.
        let live = [("BILLING_API_KEY", "rk_live_123"), SECRETS[1]];
        assert!(refused("standin", loopback, &live).contains("live"));
        // No problem holds a value.
        for values in [&SECRETS[..1], &SECRETS[1..], &live[..]] {
            let problem = refused("standin", "https://api.example.com", values);
            assert!(!problem.contains("sk_test") && !problem.contains("whsec") && !problem.contains("rk_live"));
        }
    }

    #[test]
    fn both_webhook_secrets_while_one_is_replaced() {
        let one = from_settings(true, "standin", "http://127.0.0.1:1", false, &env(&SECRETS)).unwrap().unwrap();
        let Adapter::Standin(standin) = one.provider() else {
            panic!("the stand-in")
        };
        assert_eq!(standin.webhook_secrets(), 1);
        let two = [SECRETS[0], SECRETS[1], ("BILLING_WEBHOOK_SECRET_OLD", "whsec_old")];
        let two = from_settings(true, "standin", "http://127.0.0.1:1", false, &env(&two)).unwrap().unwrap();
        let Adapter::Standin(standin) = two.provider() else {
            panic!("the stand-in")
        };
        assert_eq!(standin.webhook_secrets(), 2);
        // An empty old one is none.
        let empty = [SECRETS[0], SECRETS[1], ("BILLING_WEBHOOK_SECRET_OLD", "")];
        let empty = from_settings(true, "standin", "http://127.0.0.1:1", false, &env(&empty)).unwrap().unwrap();
        let Adapter::Standin(standin) = empty.provider() else {
            panic!("the stand-in")
        };
        assert_eq!(standin.webhook_secrets(), 1);
    }

    fn at(day: u32, hour: u32) -> NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2027, 3, day).unwrap().and_hms_opt(hour, 0, 0).unwrap()
    }

    #[test]
    fn when_a_plan_a_provider_set_is_looked_at_again() {
        let now = at(10, 12);
        let second = TimeDelta::seconds(1);
        // Never answered.
        assert!(due_a_look(None, None, now));
        // Once a day.
        assert!(!due_a_look(Some(now - TimeDelta::hours(23)), None, now));
        assert!(!due_a_look(Some(now - TimeDelta::days(1) + second), None, now));
        assert!(due_a_look(Some(now - TimeDelta::days(1)), None, now));
        assert!(due_a_look(Some(now - TimeDelta::days(30)), Some(now + TimeDelta::days(300)), now));
        // When `until` has passed since the last answer, and not before.
        let checked = now - TimeDelta::hours(2);
        assert!(!due_a_look(Some(checked), Some(now), now));
        assert!(due_a_look(Some(checked), Some(now - second), now));
        assert!(due_a_look(Some(checked), Some(checked), now));
        // Answered since it passed: the answer already says what came after.
        assert!(!due_a_look(Some(checked), Some(checked - second), now));
        assert!(!due_a_look(Some(checked), Some(now + TimeDelta::days(30)), now));
    }

    #[test]
    fn the_job_leaves_a_plan_answered_after_it_began() {
        let began = chrono::NaiveDate::from_ymd_opt(2026, 11, 16).unwrap().and_hms_opt(12, 0, 0).unwrap();
        // A webhook's look, or another run's, answered while this run waited.
        assert!(answered_since(Some(began), began));
        assert!(answered_since(Some(began + TimeDelta::seconds(3)), began));
        // Answered before the run began, or never: the run asks.
        assert!(!answered_since(Some(began - TimeDelta::seconds(1)), began));
        assert!(!answered_since(None, began));
    }

    #[test]
    fn someone_may_have_a_plan_looked_at_once_a_minute() {
        let ana = PlanOwner::User("look-once-ana".to_owned().into());
        let acme = PlanOwner::Organization("look-once-acme".to_owned().into());
        assert!(may_look_now(&ana));
        assert!(!may_look_now(&ana));
        // Each plan has its own minute.
        assert!(may_look_now(&acme));
        assert!(!may_look_now(&acme));
        // A minute on, it may again.
        ASKED.lock().unwrap().insert(ana.clone(), Instant::now().checked_sub(ASK_AT_MOST_EVERY).unwrap());
        assert!(may_look_now(&ana));
        assert!(!may_look_now(&ana));
    }

    #[test]
    fn ids_are_short_and_plain() {
        for id in ["cus_123", "evt_1AbC-x", "a", &"x".repeat(255)] {
            assert!(plain_id(id), "{id}");
        }
        for id in ["", "cus 1", "cus/1", "../x", "cus_1\n", "cüs", &"x".repeat(256)] {
            assert!(!plain_id(id), "{id}");
        }
    }

    #[test]
    fn only_web_pages() {
        assert!(web_page("https://pay.example.com/c/1"));
        assert!(web_page("http://127.0.0.1:8124/pay/1"));
        for url in ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "/relative", "https://", ""] {
            assert!(!web_page(url), "{url}");
        }
    }

    /// `keykeeperPlan` as the sync and `GET /api/keykeeper/plan` carry it, on
    /// a server set up each way, for someone who manages the plan or not.
    fn keykeeper_plan(enforced: bool, provider: &str, may_manage: bool, covered: bool) -> serde_json::Value {
        let billing = from_settings(enforced, provider, "http://127.0.0.1:1", false, &env(&SECRETS)).unwrap();
        if !enforced {
            return not_enforced_json();
        }
        let terms = Terms {
            grace_days: 14,
            trial_days: 30,
            // As these tests ask only how a plan reads, never a trial started.
            starts_trials: false,
            premium_storage_gb: 5,
            families_people: 6,
            org_storage_gb_per_person: 1,
            org_storage_min_gb: 5,
            payments: billing.is_some(),
        };
        PlanNow {
            whose: PlanOwner::Organization("acme".to_owned().into()),
            row: None,
            state: None,
            gives: None,
            covered_by: covered.then(|| ("northwind".to_owned().into(), "Northwind IT".to_owned())),
            may_manage,
            through_organization: false,
        }
        .to_json(&terms)
    }

    #[test]
    fn can_pay_only_where_plans_are_enforced_a_provider_is_set_and_they_manage_the_plan() {
        for enforced in [false, true] {
            for provider in ["", "standin"] {
                for may_manage in [false, true] {
                    let plan = keykeeper_plan(enforced, provider, may_manage, false);
                    let case = format!("enforced {enforced}, provider {provider:?}, manages {may_manage}");
                    if enforced {
                        assert_eq!(plan["canManage"], may_manage, "{case}");
                        assert_eq!(plan["canPay"], may_manage && !provider.is_empty(), "{case}");
                    } else {
                        // Absent, as every plan field is.
                        assert_eq!(plan, not_enforced_json(), "{case}");
                        assert!(plan.get("canPay").is_none(), "{case}");
                    }
                }
            }
        }
        // A client's plan is paid for through its MSP: never here.
        assert_eq!(keykeeper_plan(true, "standin", true, true)["canPay"], false);
    }
}

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
//   5. a customer's standing now: which plan, good through when, renewing or not.
//
// A webhook only ever causes a look: the server never writes a plan from what a
// webhook's body says. It asks the provider (call 5) and writes that answer
// (`look`). So an event that comes twice, late, out of order, or replayed can
// only cause one more look at the truth. A plan never ends on a guess: when the
// provider can't be asked, the last answer stands and the look is tried again.
//
// All of it is a second switch, BILLING_PROVIDER, which does nothing unless
// PLANS_ENFORCED is on. Without both, `billing()` is None: no route here
// exists, no job runs, and nothing is asked of anyone.
//
// The provider's secrets come from the environment only (`init`). They're
// never in CONFIG, so the admin page, its diagnostics, and the config file
// never see them, and `Secret` can't be printed, so no log or error can carry one.

mod signature;
mod standin;

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
            BillingCustomer, BillingEvent, PlanName, PlanOwner, ProviderAnswer, plans_a_provider_set,
            write_provider_answer,
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

/// One line of a month's invoice (call 3).
#[expect(dead_code, reason = "the month's invoice job, piece 10 of the plans design's build order, makes the first")]
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
    /// plan and month. Answers the provider's id for the invoice.
    #[expect(
        dead_code,
        reason = "the month's invoice job, piece 10 of the plans design's build order, is the first to ask"
    )]
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

    /// Call 5: `customer`'s standing now. None when the provider has nothing for
    /// them: never paid, or nothing started.
    async fn standing(&self, customer: &str) -> Result<Option<ProviderAnswer>, Unreachable>;
}

/// The provider BILLING_PROVIDER names.
pub enum Adapter {
    /// `standin`: the test stand-in in the meta repo's e2e/, which only talks
    /// to a loopback address.
    Standin(standin::Standin),
}

impl Provider for Adapter {
    fn live(&self) -> bool {
        match self {
            Self::Standin(p) => p.live(),
        }
    }

    fn signature_header(&self) -> &'static str {
        match self {
            Self::Standin(p) => p.signature_header(),
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
        }
    }

    async fn manage_page(&self, customer: &str, back: &str) -> Result<String, Unreachable> {
        match self {
            Self::Standin(p) => p.manage_page(customer, back).await,
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
        }
    }

    fn event(&self, signature: Option<&str>, body: &[u8], now: i64) -> Result<Event, &'static str> {
        match self {
            Self::Standin(p) => p.event(signature, body, now),
        }
    }

    async fn standing(&self, customer: &str) -> Result<Option<ProviderAnswer>, Unreachable> {
        match self {
            Self::Standin(p) => p.standing(customer).await,
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

/// Works out the provider from the settings and the environment. Pure, so
/// each way a server can be set up is tested. The problems name settings
/// and never hold a value.
fn from_settings(
    enforced: bool,
    provider: &str,
    api_base: &str,
    env: &dyn Fn(&'static str) -> Option<String>,
) -> Result<Option<Billing>, &'static str> {
    if provider.is_empty() || !enforced {
        return Ok(None);
    }
    let secret = |name| env(name).filter(|value| !value.is_empty()).map(Secret::new);
    let api_key = secret(API_KEY).ok_or("`BILLING_PROVIDER` needs `BILLING_API_KEY` in the environment")?;
    let mut webhook_secrets =
        vec![secret(WEBHOOK_SECRET).ok_or("`BILLING_PROVIDER` needs `BILLING_WEBHOOK_SECRET` in the environment")?];
    webhook_secrets.extend(secret(WEBHOOK_SECRET_OLD));
    let (name, adapter) = match provider {
        "standin" => ("standin", Adapter::Standin(standin::Standin::new(api_base, api_key, webhook_secrets)?)),
        _ => {
            return Err(
                "`BILLING_PROVIDER` names a provider this server doesn't have: leave it empty, or set `standin` for tests",
            );
        }
    };
    Ok(Some(Billing {
        name,
        adapter,
    }))
}

/// Reads the provider's settings and secrets, once, before any route is
/// mounted or job scheduled. A server set up wrong doesn't start.
pub fn init() {
    let provider = CONFIG.billing_provider();
    match from_settings(CONFIG.plans_enforced(), &provider, &CONFIG.billing_api_base(), &crate::util::get_env_str_value)
    {
        Ok(found) => {
            match &found {
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
    let Ok(answer) = billing.provider().standing(customer).await else {
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
        if look(billing, &whose, &customer, &conn).await == Looked::Failed && since <= now - TELL_THE_OPERATOR_AFTER {
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

/// A page to pay for `plan` (call 1), for `whose` plan. The provider's
/// customer for it is recorded the first time, and the same one is used
/// after, so a payment's webhooks are about someone the server knows.
pub async fn pay_page(
    billing: &Billing,
    whose: &PlanOwner,
    plan: PlanName,
    back: &str,
    conn: &DbConn,
) -> ApiResult<String> {
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

    #[test]
    fn the_provider_is_a_second_switch() {
        let secrets = env(&SECRETS);
        let loopback = "http://127.0.0.1:8124";
        // No provider: nothing, whatever else is set.
        assert!(from_settings(true, "", loopback, &secrets).unwrap().is_none());
        assert!(from_settings(false, "", loopback, &secrets).unwrap().is_none());
        // A provider does nothing without PLANS_ENFORCED, and nothing is checked.
        assert!(from_settings(false, "standin", loopback, &secrets).unwrap().is_none());
        assert!(from_settings(false, "standin", "https://api.example.com", &env(&[])).unwrap().is_none());
        // With both, there's a provider.
        let billing = from_settings(true, "standin", loopback, &secrets).unwrap().unwrap();
        assert_eq!(billing.name, "standin");
        assert!(!billing.provider().live());
    }

    #[test]
    fn a_server_set_up_wrong_doesnt_start() {
        let loopback = "http://127.0.0.1:8124";
        let refused = |provider, base, values: &[(&'static str, &'static str)]| {
            from_settings(true, provider, base, &env(values)).err().unwrap_or("it was taken")
        };
        // A provider this server doesn't have.
        assert!(refused("stripe", loopback, &SECRETS).contains("doesn't have"));
        assert!(refused("Standin", loopback, &SECRETS).contains("doesn't have"));
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
            assert!(from_settings(true, "standin", base, &env(&SECRETS)).is_ok(), "{base}");
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
        let one = from_settings(true, "standin", "http://127.0.0.1:1", &env(&SECRETS)).unwrap().unwrap();
        let Adapter::Standin(standin) = one.provider();
        assert_eq!(standin.webhook_secrets(), 1);
        let two = [SECRETS[0], SECRETS[1], ("BILLING_WEBHOOK_SECRET_OLD", "whsec_old")];
        let two = from_settings(true, "standin", "http://127.0.0.1:1", &env(&two)).unwrap().unwrap();
        let Adapter::Standin(standin) = two.provider();
        assert_eq!(standin.webhook_secrets(), 2);
        // An empty old one is none.
        let empty = [SECRETS[0], SECRETS[1], ("BILLING_WEBHOOK_SECRET_OLD", "")];
        let empty = from_settings(true, "standin", "http://127.0.0.1:1", &env(&empty)).unwrap().unwrap();
        let Adapter::Standin(standin) = empty.provider();
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
        let billing = from_settings(enforced, provider, "http://127.0.0.1:1", &env(&SECRETS)).unwrap();
        if !enforced {
            return not_enforced_json();
        }
        let terms = Terms {
            grace_days: 14,
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

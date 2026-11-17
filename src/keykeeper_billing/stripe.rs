// Keykeeper: the adapter for Stripe (BILLING_PROVIDER=stripe), DESIGN.md,
// "Plans and billing", "Stripe, the first provider", in the meta repo.
// Written from Stripe's public API reference (docs.stripe.com, read November
// 16, 2026) for the version pinned in `VERSION`, and tested against the
// stand-in in the meta repo's e2e/stripe-standin.mjs. Nothing here was tried
// against Stripe itself.
//
// What it asks Stripe, each POST form-encoded as Stripe's API takes it, with
// the restricted key as a bearer token and the pinned version:
//
// - Pay, for Premium or Families: a customer the first time (`POST
//   /v1/customers`), then a Checkout Session in subscription mode with the
//   plan's price (`POST /v1/checkout/sessions`), which comes back to the Plan
//   page. Whose plan it is goes in `client_reference_id` and in the
//   subscription's metadata, for the owner to see in Stripe's dashboard; the
//   server's own record (`billing_customers`) is what decides whose plan an
//   answer is written to.
// - Manage: a customer portal session (`POST /v1/billing_portal/sessions`).
// - Standing: the customer's subscriptions (`GET /v1/subscriptions`), read by
//   DESIGN.md's table (`read_standing`).
// - Cancel, when the account or organization is deleted: each of the
//   customer's subscriptions that isn't over, at once (`DELETE
//   /v1/subscriptions/<id>`).
// - Webhooks: the `Stripe-Signature` header, checked by `signature.rs`, and
//   from the event only its id, its mode, and the customer.
//
// Billing by the day (piece 10 of the build order, where
// BILLING_INVOICE_SCHEDULE isn't blank), for an MSP's pool and a Business
// organization with no MSP:
//
// - A card on file: a customer the first time, then a Checkout Session in
//   setup mode (`POST /v1/checkout/sessions`, `mode=setup`), which comes back
//   to the Plan page. On the next look, a customer with no default card for
//   invoices gets the card that setup saved, while it's still the customer's
//   (`POST /v1/customers/<id>`, `invoice_settings[default_payment_method]`).
// - The month's invoice: an invoice item with the amount, the description,
//   and the month as its period (`POST /v1/invoiceitems`), then an invoice
//   that takes it and collects from the card on file by itself (`POST
//   /v1/invoices`, `auto_advance`), each with an idempotency key from the
//   server's row for the month, and each written with that key in its
//   metadata. Stripe keeps an idempotency key about a day, so before making
//   either the adapter looks for one it made with the key (`GET
//   /v1/invoices`, `GET /v1/invoiceitems?pending=true`): asked again a week
//   later, it still finds the first.
// - Standing for a pool, by DESIGN.md's table (`read_pool`): once a setup
//   has completed (`GET /v1/checkout/sessions`), a default card and no unpaid
//   invoice is good with no end, and an unpaid invoice of the server's is
//   good through its first failed attempt, when it was finalized, since
//   Stripe tries to collect as it finalizes one.
//
// No body, key, or header goes into a log or an error: a failure says which
// call it was and the status, and nothing more.

use std::{collections::HashMap, sync::LazyLock, time::Duration};

use chrono::{DateTime, NaiveDateTime};
use reqwest::{Client, Method, header};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use url::Url;

use super::{
    Event, InvoiceLine, PayPage, Provider, Secret, Unreachable,
    invoices::{CURRENCY, month_period},
    loopback_url, plain_id, signature,
};
use crate::{
    db::models::{Billed, PlanName, PlanOwner, ProviderAnswer, Standing},
    http_client::get_reqwest_client_builder,
};

/// The API version every request is made with (the `Stripe-Version` header):
/// the one current on docs.stripe.com on November 16, 2026. A change to the
/// account's default changes nothing the server reads. Whoever moves it
/// rereads the reference page of each call below first.
pub const VERSION: &str = "2026-10-28.endive";

/// Stripe's own address. BILLING_API_BASE changes it only for tests, and
/// never beside a live key.
const STRIPE_API: &str = "https://api.stripe.com";

/// Subscriptions are read 100 at a time, Stripe's most, and five pages at
/// most. A customer with more can't be read whole, which is no answer. The
/// same for a customer's Checkout Sessions, invoices, and invoice items.
const PAGE_SIZE: &str = "100";
const MAX_PAGES: usize = 5;

/// The metadata on an invoice and its item that says which of the server's
/// invoices it is: the key it was made with.
const INVOICE_KEY: &str = "invoice";

/// Made the first time Stripe is asked something. It follows no redirect, so
/// the key goes nowhere but the address it was set for, and gives up on a
/// call after ten seconds.
static CLIENT: LazyLock<Client> = LazyLock::new(|| {
    get_reqwest_client_builder(false)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to build Stripe's HTTP client")
});

/// The prices people pay for each plan, from BILLING_PRICE_PREMIUM and
/// BILLING_PRICE_FAMILIES.
pub struct Prices {
    pub premium: String,
    pub families: String,
}

/// A Stripe price's id.
fn price_id(id: &str) -> bool {
    id.starts_with("price_") && plain_id(id)
}

pub struct Stripe {
    base: Url,
    api_key: Secret,
    live: bool,
    webhook_secrets: Vec<Secret>,
    prices: Prices,
    /// Billing by the day is on: a card goes on file for Business and a pool.
    by_the_day: bool,
}

/// One request as the adapter makes it, before it's sent, so the tests can
/// read it whole.
#[derive(Debug, PartialEq, Eq)]
struct Call {
    method: Method,
    path: Vec<String>,
    /// The query, for a GET.
    query: Vec<(&'static str, String)>,
    /// The form-encoded body, for a POST.
    form: Vec<(&'static str, String)>,
    /// What the call is for, as the log says it.
    what: &'static str,
    /// The `Idempotency-Key` header, for a POST that must happen once.
    idempotency: Option<String>,
}

impl Call {
    fn new(method: Method, path: &[&str], what: &'static str) -> Self {
        Self {
            method,
            path: path.iter().map(|part| (*part).to_owned()).collect(),
            query: Vec::new(),
            form: Vec::new(),
            what,
            idempotency: None,
        }
    }
}

/// Whose plan, as Stripe's dashboard shows it in `client_reference_id` and
/// metadata: `user_<id>`, `organization_<id>`, or `msp_<id>`.
fn whose_ref(whose: &PlanOwner) -> String {
    match whose {
        PlanOwner::User(id) => format!("user_{id}"),
        PlanOwner::Organization(id) => format!("organization_{id}"),
        PlanOwner::Msp(id) => format!("msp_{id}"),
    }
}

impl Stripe {
    /// The adapter, from its settings, or the reason the server won't start.
    /// No reason holds a value.
    pub fn new(
        api_base: &str,
        api_key: Secret,
        webhook_secrets: Vec<Secret>,
        prices: Prices,
        by_the_day: bool,
    ) -> Result<Self, &'static str> {
        let key = api_key.expose();
        if key.starts_with("sk_") {
            return Err(
                "`BILLING_API_KEY` is a Stripe account's full secret key, which the server never takes: give it a restricted key (rk_live_ or rk_test_) that can do only what the server asks (deploy/README.md, \"Plans\")",
            );
        }
        let live = key.starts_with("rk_live_");
        if !live && !key.starts_with("rk_test_") {
            return Err("`BILLING_API_KEY` isn't a Stripe restricted key, which starts with rk_live_ or rk_test_");
        }
        let base = if api_base.is_empty() {
            Url::parse(STRIPE_API).map_err(|_| "Stripe's address couldn't be read")?
        } else if live {
            return Err(
                "`BILLING_API_BASE` is set beside a live Stripe key, which is only ever sent to Stripe itself: unset `BILLING_API_BASE`",
            );
        } else {
            loopback_url(api_base).ok_or(
                "`BILLING_API_BASE` is for tests only: it must be an http or https address on this machine, written as one, such as http://127.0.0.1:8128",
            )?
        };
        if webhook_secrets.iter().any(|secret| !secret.expose().starts_with("whsec_")) {
            return Err(
                "`BILLING_WEBHOOK_SECRET` and `BILLING_WEBHOOK_SECRET_OLD` are a Stripe endpoint's signing secrets, which start with whsec_",
            );
        }
        if !price_id(&prices.premium) || !price_id(&prices.families) {
            return Err(
                "`BILLING_PROVIDER=stripe` needs `BILLING_PRICE_PREMIUM` and `BILLING_PRICE_FAMILIES`, each the id of a Stripe price (price_...)",
            );
        }
        if prices.premium == prices.families {
            return Err("`BILLING_PRICE_PREMIUM` and `BILLING_PRICE_FAMILIES` must be two different prices");
        }
        Ok(Self {
            base,
            api_key,
            live,
            webhook_secrets,
            prices,
            by_the_day,
        })
    }

    #[cfg(test)]
    pub fn webhook_secrets(&self) -> usize {
        self.webhook_secrets.len()
    }

    /// The price someone pays for `plan`, for the plans Stripe takes here.
    fn price(&self, plan: PlanName) -> Option<&str> {
        match plan {
            PlanName::Premium => Some(&self.prices.premium),
            PlanName::Families => Some(&self.prices.families),
            PlanName::Business | PlanName::Msp => None,
        }
    }

    /// `POST /v1/customers`: a customer for whose plan it is, named in its
    /// metadata for the owner. Its email is asked on Stripe's page.
    fn new_customer(whose: &PlanOwner) -> Call {
        let mut call = Call::new(Method::POST, &["v1", "customers"], "making a customer");
        call.form.push(("metadata[whose]", whose_ref(whose)));
        call
    }

    /// `POST /v1/checkout/sessions`: Stripe's page to pay for `plan`, a year
    /// at a time as its price says, for `customer`, which comes back to `back`
    /// whether they paid or not; or, for Business and a pool while billing by
    /// the day is on, to put a card on file (`setup`). None for a plan Stripe
    /// doesn't take here.
    fn checkout(&self, whose: &PlanOwner, plan: PlanName, customer: &str, back: &str) -> Option<Call> {
        let Some(price) = self.price(plan) else {
            return self.setup(whose, plan, customer, back);
        };
        let whose = whose_ref(whose);
        let mut call = Call::new(Method::POST, &["v1", "checkout", "sessions"], "making a Checkout Session");
        call.form = vec![
            ("mode", "subscription".to_owned()),
            ("customer", customer.to_owned()),
            ("client_reference_id", whose.clone()),
            ("line_items[0][price]", price.to_owned()),
            ("line_items[0][quantity]", "1".to_owned()),
            ("subscription_data[metadata][whose]", whose),
            ("subscription_data[metadata][plan]", plan.as_str().to_owned()),
            ("success_url", back.to_owned()),
            ("cancel_url", back.to_owned()),
        ];
        Some(call)
    }

    /// `POST /v1/checkout/sessions` in setup mode: Stripe's page to put a card
    /// on file for `customer`, for a plan billed by the day after each month,
    /// which charges nothing and comes back to `back`. Setup mode needs the
    /// currency the card will be charged in. None while billing by the day is
    /// off, and for a plan that isn't billed that way.
    fn setup(&self, whose: &PlanOwner, plan: PlanName, customer: &str, back: &str) -> Option<Call> {
        if !self.by_the_day || !matches!(plan, PlanName::Business | PlanName::Msp) {
            return None;
        }
        let whose = whose_ref(whose);
        let mut call = Call::new(Method::POST, &["v1", "checkout", "sessions"], "making a Checkout Session for a card");
        call.form = vec![
            ("mode", "setup".to_owned()),
            ("currency", CURRENCY.to_owned()),
            ("customer", customer.to_owned()),
            ("client_reference_id", whose.clone()),
            ("metadata[whose]", whose.clone()),
            ("metadata[plan]", plan.as_str().to_owned()),
            ("setup_intent_data[metadata][whose]", whose),
            ("setup_intent_data[metadata][plan]", plan.as_str().to_owned()),
            ("success_url", back.to_owned()),
            ("cancel_url", back.to_owned()),
        ];
        Some(call)
    }

    /// `GET /v1/checkout/sessions`: one page of the customer's completed
    /// Checkout Sessions, each with its SetupIntent and that intent's card,
    /// so a card's owner can be checked before it's made the default.
    fn completed_sessions(customer: &str, after: Option<&str>) -> Call {
        let mut call =
            Call::new(Method::GET, &["v1", "checkout", "sessions"], "reading a customer's Checkout Sessions");
        call.query = vec![
            ("customer", customer.to_owned()),
            ("status", "complete".to_owned()),
            ("limit", PAGE_SIZE.to_owned()),
            ("expand[]", "data.setup_intent.payment_method".to_owned()),
        ];
        if let Some(after) = after {
            call.query.push(("starting_after", after.to_owned()));
        }
        call
    }

    /// `GET /v1/customers/<id>`: the customer, for its default card for invoices.
    fn customer(customer: &str) -> Call {
        Call::new(Method::GET, &["v1", "customers", customer], "reading a customer")
    }

    /// `POST /v1/customers/<id>`: `card` is the customer's default for invoices.
    fn make_default(customer: &str, card: &str) -> Call {
        let mut call =
            Call::new(Method::POST, &["v1", "customers", customer], "making a card the default for invoices");
        call.form = vec![("invoice_settings[default_payment_method]", card.to_owned())];
        call
    }

    /// `GET /v1/invoices`: one page of the customer's invoices, newest first.
    fn invoices(customer: &str, after: Option<&str>) -> Call {
        let mut call = Call::new(Method::GET, &["v1", "invoices"], "reading a customer's invoices");
        call.query = vec![("customer", customer.to_owned()), ("limit", PAGE_SIZE.to_owned())];
        if let Some(after) = after {
            call.query.push(("starting_after", after.to_owned()));
        }
        call
    }

    /// `GET /v1/invoiceitems`: one page of the customer's invoice items that
    /// no invoice has taken yet.
    fn pending_items(customer: &str, after: Option<&str>) -> Call {
        let mut call = Call::new(Method::GET, &["v1", "invoiceitems"], "reading a customer's invoice items");
        call.query =
            vec![("customer", customer.to_owned()), ("pending", "true".to_owned()), ("limit", PAGE_SIZE.to_owned())];
        if let Some(after) = after {
            call.query.push(("starting_after", after.to_owned()));
        }
        call
    }

    /// `POST /v1/invoiceitems`: the month's one line, its amount in cents, its
    /// description, and the month as its period, for the next invoice made
    /// for `customer`. None for a month that isn't `YYYY-MM`.
    fn invoice_item(customer: &str, month: &str, line: &InvoiceLine, key: &str) -> Option<Call> {
        let (start, end) = month_period(month)?;
        let mut call = Call::new(Method::POST, &["v1", "invoiceitems"], "making an invoice item");
        call.form = vec![
            ("customer", customer.to_owned()),
            ("amount", line.amount_cents.to_string()),
            ("currency", CURRENCY.to_owned()),
            ("description", line.description.clone()),
            ("period[start]", start.to_string()),
            ("period[end]", end.to_string()),
            ("metadata[invoice]", key.to_owned()),
            ("metadata[month]", month.to_owned()),
        ];
        call.idempotency = Some(format!("{key}-item"));
        Some(call)
    }

    /// `POST /v1/invoices`: the month's invoice for `customer`, taking the
    /// invoice item made for it, charged to the card on file, and advanced by
    /// Stripe itself: finalized, collected, and retried on Stripe's schedule.
    fn new_invoice(customer: &str, month: &str, key: &str) -> Call {
        let mut call = Call::new(Method::POST, &["v1", "invoices"], "making an invoice");
        call.form = vec![
            ("customer", customer.to_owned()),
            ("collection_method", "charge_automatically".to_owned()),
            ("auto_advance", "true".to_owned()),
            ("pending_invoice_items_behavior", "include".to_owned()),
            ("metadata[invoice]", key.to_owned()),
            ("metadata[month]", month.to_owned()),
        ];
        call.idempotency = Some(format!("{key}-invoice"));
        call
    }

    /// `POST /v1/billing_portal/sessions`: Stripe's customer portal for
    /// `customer`, which comes back to `back`.
    fn portal(customer: &str, back: &str) -> Call {
        let mut call = Call::new(Method::POST, &["v1", "billing_portal", "sessions"], "making a portal session");
        call.form = vec![("customer", customer.to_owned()), ("return_url", back.to_owned())];
        call
    }

    /// `GET /v1/subscriptions`: one page of the customer's subscriptions, in
    /// every status, after `after`.
    fn subscriptions(customer: &str, after: Option<&str>) -> Call {
        let mut call = Call::new(Method::GET, &["v1", "subscriptions"], "reading a customer's subscriptions");
        call.query =
            vec![("customer", customer.to_owned()), ("status", "all".to_owned()), ("limit", PAGE_SIZE.to_owned())];
        if let Some(after) = after {
            call.query.push(("starting_after", after.to_owned()));
        }
        call
    }

    /// `DELETE /v1/subscriptions/<id>`: canceled at once, with no final
    /// invoice and no proration, Stripe's defaults. Refunds are the owner's,
    /// by hand.
    fn cancel_subscription(id: &str) -> Call {
        Call::new(Method::DELETE, &["v1", "subscriptions", id], "canceling a subscription")
    }

    /// The request for `call`: its address on Stripe's API (or the test
    /// stand-in's), the key as a bearer token, the pinned version, and for a
    /// POST its form-encoded body.
    fn request(&self, call: &Call) -> Result<reqwest::RequestBuilder, Unreachable> {
        let mut url = self.base.clone();
        url.path_segments_mut().map_err(|()| Unreachable)?.pop_if_empty().extend(&call.path);
        if !call.query.is_empty() {
            url.query_pairs_mut().extend_pairs(&call.query);
        }
        let mut request = CLIENT
            .request(call.method.clone(), url)
            .bearer_auth(self.api_key.expose())
            .header("Stripe-Version", VERSION);
        if let Some(key) = &call.idempotency {
            request = request.header("Idempotency-Key", key);
        }
        if call.method == Method::POST {
            let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(&call.form).finish();
            request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(body);
        }
        Ok(request)
    }

    /// Makes one call and reads its answer. Anything but a 2xx with an answer
    /// that reads is a failure, logged with the call and its status only.
    async fn send<T: DeserializeOwned>(&self, call: &Call) -> Result<T, Unreachable> {
        let what = call.what;
        let response = self.request(call)?.send().await.map_err(|e| {
            warn!("Stripe couldn't be reached while {what}: {}", e.without_url());
            Unreachable
        })?;
        let status = response.status();
        if status.is_success() {
            return response.json::<T>().await.map_err(|_| {
                warn!("Stripe's answer while {what} couldn't be read.");
                Unreachable
            });
        }
        if matches!(status.as_u16(), 401 | 403) {
            error!(
                "Stripe refused the server's key ({status}) while {what}. Check BILLING_API_KEY and the permissions deploy/README.md (\"Plans\") lists for it."
            );
        } else {
            warn!("Stripe answered {status} while {what}.");
        }
        Err(Unreachable)
    }

    /// Every subscription the customer has, in every status.
    async fn all_subscriptions(&self, customer: &str) -> Result<Vec<Subscription>, Unreachable> {
        let mut all = Vec::new();
        let mut after: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let page: List<Subscription> = self.send(&Self::subscriptions(customer, after.as_deref())).await?;
            let last = page.data.last().map(|subscription| subscription.id.clone());
            all.extend(page.data);
            match (page.has_more, last) {
                (false, _) => {
                    if all.iter().any(|subscription| subscription.customer.as_str() != Some(customer)) {
                        warn!("Stripe answered subscriptions of another customer, so none was read.");
                        return Err(Unreachable);
                    }
                    return Ok(all);
                }
                (true, Some(last)) if plain_id(&last) => after = Some(last),
                (true, _) => {
                    warn!("Stripe's list of a customer's subscriptions couldn't be read to its end.");
                    return Err(Unreachable);
                }
            }
        }
        warn!("A Stripe customer has more subscriptions than the server reads, so its standing couldn't be read.");
        Err(Unreachable)
    }

    /// Every page of a list a call reads, `page` making the call for the page
    /// after an object's id.
    async fn all<T: DeserializeOwned + Listed>(
        &self,
        page: impl Fn(Option<&str>) -> Call,
    ) -> Result<Vec<T>, Unreachable> {
        let mut all = Vec::new();
        let mut after: Option<String> = None;
        let what = page(None).what;
        for _ in 0..MAX_PAGES {
            let found: List<T> = self.send(&page(after.as_deref())).await?;
            let next = found.data.last().map(|item| item.id().to_owned());
            all.extend(found.data);
            match (found.has_more, next) {
                (false, _) => return Ok(all),
                (true, Some(next)) if plain_id(&next) => after = Some(next),
                (true, _) => break,
            }
        }
        warn!("Stripe's list couldn't be read to its end while {what}.");
        Err(Unreachable)
    }

    /// A pool's standing (or a Business organization's, billed by the day the
    /// same way), as `plan`: None when no setup Checkout Session of this
    /// customer's has completed, so it isn't billed by the day at all.
    /// Before reading, a customer with no default card for invoices gets the
    /// card from its latest setup, while that card is still the customer's.
    async fn pool_standing(&self, customer: &str, plan: PlanName) -> Result<Option<ProviderAnswer>, Unreachable> {
        let sessions: Vec<SessionRead> = self.all(|after| Self::completed_sessions(customer, after)).await?;
        let saved = match setup_card(&sessions, customer) {
            Setup::None => return Ok(None),
            Setup::CardGone => None,
            Setup::Card(card) => Some(card),
        };
        let found: CustomerRead = self.send(&Self::customer(customer)).await?;
        if found.id != customer {
            warn!("Stripe answered another customer, so a pool's standing wasn't read.");
            return Err(Unreachable);
        }
        let mut card = if found.deleted {
            None
        } else {
            found.invoice_settings.and_then(|settings| id_of(&settings.default_payment_method))
        };
        if card.is_none()
            && !found.deleted
            && let Some(saved) = saved
        {
            let made: Made = self.send(&Self::make_default(customer, &saved)).await?;
            if made.id != customer {
                return Err(Unreachable);
            }
            info!("The card Stripe's customer {customer} put on file is now its default for invoices.");
            card = Some(saved);
        }
        let invoices: Vec<InvoiceRead> = self.all(|after| Self::invoices(customer, after)).await?;
        if invoices.iter().any(|invoice| id_of(&invoice.customer).as_deref() != Some(customer)) {
            warn!("Stripe answered invoices of another customer, so a pool's standing wasn't read.");
            return Err(Unreachable);
        }
        read_pool(plan, card.is_some(), &invoices).map(Some)
    }
}

/// Something a list holds, by its id.
trait Listed {
    fn id(&self) -> &str;
}

/// The id of an object Stripe sent as its id or expanded.
fn id_of(value: &Value) -> Option<String> {
    match value {
        Value::String(id) if plain_id(id) => Some(id.clone()),
        Value::Object(object) => object.get("id").and_then(Value::as_str).filter(|id| plain_id(id)).map(str::to_owned),
        _ => None,
    }
}

/// A Checkout Session as the adapter reads one for a card on file: its
/// mode, when it was made, and its SetupIntent, expanded with its card.
#[derive(Deserialize)]
struct SessionRead {
    id: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    created: i64,
    #[serde(default)]
    setup_intent: Value,
}

impl Listed for SessionRead {
    fn id(&self) -> &str {
        &self.id
    }
}

/// What a customer's setup Checkout Sessions come to.
#[derive(Debug, PartialEq, Eq)]
enum Setup {
    /// None completed: the customer isn't billed by the day at all.
    None,
    /// Completed, and none of their cards is the customer's anymore.
    CardGone,
    /// The card the latest successful one saved that's still the customer's.
    Card(String),
}

/// Whether the customer completed a setup Checkout Session, and the card the
/// latest successful one saved that's still the customer's.
fn setup_card(sessions: &[SessionRead], customer: &str) -> Setup {
    let mut setups: Vec<&SessionRead> = sessions
        .iter()
        .filter(|session| {
            session.mode == "setup" && session.status.as_deref().is_none_or(|status| status == "complete")
        })
        .collect();
    if setups.is_empty() {
        return Setup::None;
    }
    setups.sort_by_key(|session| std::cmp::Reverse(session.created));
    let saved = |session: &SessionRead| -> Option<String> {
        let intent = session.setup_intent.as_object()?;
        if intent.get("status").and_then(Value::as_str) != Some("succeeded") {
            return None;
        }
        let card = intent.get("payment_method")?.as_object()?;
        if card.get("customer").and_then(id_of).as_deref() != Some(customer) {
            return None;
        }
        card.get("id").and_then(Value::as_str).filter(|id| plain_id(id)).map(str::to_owned)
    };
    setups.into_iter().find_map(saved).map_or(Setup::CardGone, Setup::Card)
}

/// The parts of a customer the adapter reads.
#[derive(Deserialize)]
struct CustomerRead {
    id: String,
    #[serde(default)]
    deleted: bool,
    #[serde(default)]
    invoice_settings: Option<InvoiceSettings>,
}

#[derive(Deserialize)]
struct InvoiceSettings {
    #[serde(default)]
    default_payment_method: Value,
}

/// The parts of an invoice the adapter reads.
#[derive(Deserialize)]
struct InvoiceRead {
    id: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    attempted: bool,
    #[serde(default)]
    attempt_count: i64,
    #[serde(default)]
    created: i64,
    #[serde(default)]
    customer: Value,
    #[serde(default)]
    status_transitions: Option<Transitions>,
    #[serde(default)]
    metadata: HashMap<String, Value>,
}

impl Listed for InvoiceRead {
    fn id(&self) -> &str {
        &self.id
    }
}

impl InvoiceRead {
    /// Whether it's the server's invoice made with `key`, or with any key.
    fn key(&self) -> Option<&str> {
        self.metadata.get(INVOICE_KEY).and_then(Value::as_str)
    }
}

#[derive(Deserialize)]
struct Transitions {
    finalized_at: Option<i64>,
}

/// The parts of an invoice item the adapter reads.
#[derive(Deserialize)]
struct ItemRead {
    id: String,
    #[serde(default)]
    metadata: HashMap<String, Value>,
}

impl Listed for ItemRead {
    fn id(&self) -> &str {
        &self.id
    }
}

/// A pool's standing, as `plan`, by DESIGN.md's table, from whether it has a
/// default card for invoices and its invoices: an unpaid invoice of the
/// server's (open, or marked uncollectible, after a payment was tried) is
/// good through its first failed attempt, which is when it was finalized,
/// since Stripe tries to collect as it finalizes an invoice it charges
/// automatically; otherwise a default card is good with no end, and no card
/// is nothing. An invoice of the server's in a status this code doesn't know
/// is no answer, so the last one stands. Invoices the server didn't make
/// (a subscription's) aren't read here.
fn read_pool(plan: PlanName, card: bool, invoices: &[InvoiceRead]) -> Result<ProviderAnswer, Unreachable> {
    let mut first_failed: Option<i64> = None;
    for invoice in invoices.iter().filter(|invoice| invoice.key().is_some()) {
        let unpaid = match invoice.status.as_deref() {
            Some("open" | "uncollectible") => true,
            Some("draft" | "paid" | "void") => false,
            _ => {
                warn!(
                    "Stripe's invoice {} has a status the server doesn't know, so a pool's standing wasn't read.",
                    invoice.id
                );
                return Err(Unreachable);
            }
        };
        if unpaid && (invoice.attempted || invoice.attempt_count > 0) {
            let at = invoice.status_transitions.as_ref().and_then(|t| t.finalized_at).unwrap_or(invoice.created);
            first_failed = Some(first_failed.map_or(at, |first| first.min(at)));
        }
    }
    match first_failed {
        Some(at) => ProviderAnswer::new(plan, Standing::Until, Some(moment(Some(at))?), true, Billed::ByTheDay, None),
        None if card => ProviderAnswer::new(plan, Standing::Open, None, true, Billed::ByTheDay, None),
        None => ProviderAnswer::new(plan, Standing::None, None, false, Billed::ByTheDay, None),
    }
    .ok_or(Unreachable)
}

/// An object Stripe made, by its id.
#[derive(Deserialize)]
struct Made {
    id: String,
}

/// A Checkout Session or a portal session: the page to send someone to.
#[derive(Deserialize)]
struct Session {
    url: Option<String>,
}

/// One page of a list.
#[derive(Deserialize)]
struct List<T> {
    data: Vec<T>,
    #[serde(default)]
    has_more: bool,
}

/// The parts of a subscription the adapter reads. Anything else in it is
/// ignored.
#[derive(Deserialize)]
struct Subscription {
    id: String,
    status: String,
    #[serde(default)]
    customer: Value,
    #[serde(default)]
    cancel_at_period_end: bool,
    #[serde(default)]
    cancel_at: Option<i64>,
    #[serde(default)]
    created: i64,
    #[serde(default)]
    metadata: HashMap<String, Value>,
    items: List<Item>,
}

/// A subscription's item: its price, and its period, which is on the item
/// since Stripe's 2025-03-31 version.
#[derive(Deserialize)]
struct Item {
    price: Option<Price>,
    current_period_start: Option<i64>,
    current_period_end: Option<i64>,
}

#[derive(Deserialize)]
struct Price {
    id: String,
}

/// A subscription's status, as DESIGN.md's table reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    /// `active` or `trialing`: good through the current period's end.
    Good,
    /// `past_due`: good through the end of the last period that was paid,
    /// which is the current period's start, while Stripe retries.
    PastDue,
    /// `canceled`, `unpaid`, `incomplete_expired`, or `paused`: over.
    Over,
    /// `incomplete`: a first payment that never finished. Nothing yet.
    NothingYet,
}

impl Status {
    /// None for a status this code doesn't know, which is no answer: a plan
    /// never ends on a guess.
    fn parse(status: &str) -> Option<Self> {
        match status {
            "active" | "trialing" => Some(Self::Good),
            "past_due" => Some(Self::PastDue),
            "canceled" | "unpaid" | "incomplete_expired" | "paused" => Some(Self::Over),
            "incomplete" => Some(Self::NothingYet),
            _ => None,
        }
    }
}

/// What a customer's subscriptions come to.
#[derive(Debug, PartialEq, Eq)]
struct Read {
    answer: Option<ProviderAnswer>,
    /// How many subscriptions are in effect: more than one is someone paying twice.
    in_effect: usize,
}

/// Which plan a subscription is for, and the item that says so: by its
/// price, or, for a price the server isn't set to (as after the owner changes
/// a plan's price for new customers), by the plan the server wrote in its
/// metadata at checkout.
fn plan_of<'a>(subscription: &'a Subscription, prices: &Prices) -> Option<(PlanName, &'a Item)> {
    for item in &subscription.items.data {
        match item.price.as_ref().map(|price| price.id.as_str()) {
            Some(id) if id == prices.premium => return Some((PlanName::Premium, item)),
            Some(id) if id == prices.families => return Some((PlanName::Families, item)),
            _ => {}
        }
    }
    let plan = subscription
        .metadata
        .get("plan")
        .and_then(Value::as_str)
        .and_then(PlanName::parse)
        .filter(|plan| matches!(plan, PlanName::Premium | PlanName::Families))?;
    Some((plan, subscription.items.data.first()?))
}

fn moment(seconds: Option<i64>) -> Result<NaiveDateTime, Unreachable> {
    seconds.and_then(|seconds| DateTime::from_timestamp(seconds, 0)).map(|at| at.naive_utc()).ok_or(Unreachable)
}

/// A customer's standing, from their subscriptions, by DESIGN.md's table:
///
/// - `active` or `trialing` is good through the current period's end (or the
///   date it's set to cancel, if that's sooner), renewing unless it's set to
///   cancel;
/// - `past_due` was good through the end of the last period paid, the
///   current period's start, so grace runs from there while Stripe retries;
/// - `canceled`, `unpaid`, `incomplete_expired`, and `paused` are over;
/// - `incomplete` is nothing yet.
///
/// Of the subscriptions in effect, one in good standing comes before one past
/// due, and then the one paid furthest ahead. With none in effect, the latest
/// that's over says the plan is over. A status this code doesn't know, or a
/// subscription in effect for a plan it can't tell, is no answer at all, so
/// the last one stands.
fn read_standing(subscriptions: &[Subscription], prices: &Prices) -> Result<Read, Unreachable> {
    let mut best: Option<((bool, NaiveDateTime), ProviderAnswer)> = None;
    let mut in_effect = 0;
    let mut latest_over: Option<(i64, ProviderAnswer)> = None;
    for subscription in subscriptions {
        let Some(status) = Status::parse(&subscription.status) else {
            warn!(
                "Stripe's subscription {} has a status the server doesn't know, so the customer's standing wasn't read.",
                subscription.id
            );
            return Err(Unreachable);
        };
        match status {
            Status::NothingYet => {}
            Status::Good | Status::PastDue => {
                let Some((plan, item)) = plan_of(subscription, prices) else {
                    error!(
                        "Stripe's subscription {} is in effect for a price the server isn't set to (BILLING_PRICE_PREMIUM, BILLING_PRICE_FAMILIES), so the customer's standing wasn't read.",
                        subscription.id
                    );
                    return Err(Unreachable);
                };
                in_effect += 1;
                let renews = !subscription.cancel_at_period_end && subscription.cancel_at.is_none();
                let until = if status == Status::PastDue {
                    moment(item.current_period_start)?
                } else {
                    let end = item.current_period_end;
                    moment(match (end, subscription.cancel_at) {
                        (Some(end), Some(cancel_at)) => Some(end.min(cancel_at)),
                        (end, _) => end,
                    })?
                };
                let answer = ProviderAnswer::new(
                    plan,
                    Standing::Until,
                    Some(until),
                    renews,
                    Billed::Prepaid,
                    Some(subscription.id.clone()),
                )
                .ok_or(Unreachable)?;
                let rank = (status == Status::Good, until);
                if best.as_ref().is_none_or(|(best, _)| rank > *best) {
                    best = Some((rank, answer));
                }
            }
            Status::Over => {
                let Some((plan, _)) = plan_of(subscription, prices) else {
                    continue;
                };
                if latest_over.as_ref().is_none_or(|(created, _)| subscription.created > *created) {
                    let answer = ProviderAnswer::new(
                        plan,
                        Standing::None,
                        None,
                        false,
                        Billed::Prepaid,
                        Some(subscription.id.clone()),
                    )
                    .ok_or(Unreachable)?;
                    latest_over = Some((subscription.created, answer));
                }
            }
        }
    }
    Ok(Read {
        answer: best.map(|(_, answer)| answer).or(latest_over.map(|(_, answer)| answer)),
        in_effect,
    })
}

/// The parts of an event the adapter reads: its id, its mode, and the object
/// it's about, for the customer. Anything else in it is ignored.
#[derive(Deserialize)]
struct EventBody {
    id: String,
    object: String,
    livemode: bool,
    data: EventData,
}

#[derive(Deserialize)]
struct EventData {
    object: EventObject,
}

#[derive(Deserialize)]
struct EventObject {
    object: String,
    id: Option<String>,
    #[serde(default)]
    customer: Value,
}

impl EventObject {
    /// The customer it's about: a customer itself, or the customer of a
    /// Checkout Session, a subscription, an invoice, or a charge.
    fn customer(self) -> Option<String> {
        if self.object == "customer" {
            return self.id;
        }
        match self.customer {
            Value::String(id) => Some(id),
            Value::Object(object) => object.get("id").and_then(Value::as_str).map(str::to_owned),
            _ => None,
        }
    }
}

impl Provider for Stripe {
    fn live(&self) -> bool {
        self.live
    }

    fn signature_header(&self) -> &'static str {
        "Stripe-Signature"
    }

    fn takes(&self, plan: PlanName) -> bool {
        self.price(plan).is_some() || (self.by_the_day && matches!(plan, PlanName::Business | PlanName::Msp))
    }

    async fn pay_page(
        &self,
        whose: &PlanOwner,
        plan: PlanName,
        customer: Option<&str>,
        back: &str,
    ) -> Result<PayPage, Unreachable> {
        let customer = if let Some(customer) = customer {
            customer.to_owned()
        } else {
            let made: Made = self.send(&Self::new_customer(whose)).await?;
            made.id
        };
        if !plain_id(&customer) {
            warn!("Stripe's answer while making a customer had no usable id.");
            return Err(Unreachable);
        }
        let call = self.checkout(whose, plan, &customer, back).ok_or(Unreachable)?;
        let session: Session = self.send(&call).await?;
        Ok(PayPage {
            url: session.url.ok_or(Unreachable)?,
            customer,
        })
    }

    async fn manage_page(&self, customer: &str, back: &str) -> Result<String, Unreachable> {
        let session: Session = self.send(&Self::portal(customer, back)).await?;
        session.url.ok_or(Unreachable)
    }

    /// The month's invoice, made once whatever happens: the invoice made
    /// with `key` if there's one, or else the invoice item made with it (or
    /// a new one), then the invoice that takes it, each sent with an
    /// idempotency key from `key`.
    async fn invoice(
        &self,
        customer: &str,
        month: &str,
        lines: &[InvoiceLine],
        key: &str,
    ) -> Result<String, Unreachable> {
        let [line] = lines else {
            warn!("A month's invoice through Stripe has one line, and was asked for {}.", lines.len());
            return Err(Unreachable);
        };
        let invoices: Vec<InvoiceRead> = self.all(|after| Self::invoices(customer, after)).await?;
        if let Some(made) = invoices.iter().find(|invoice| invoice.key() == Some(key)) {
            return Ok(made.id.clone());
        }
        let items: Vec<ItemRead> = self.all(|after| Self::pending_items(customer, after)).await?;
        if !items.iter().any(|item| item.metadata.get(INVOICE_KEY).and_then(Value::as_str) == Some(key)) {
            let call = Self::invoice_item(customer, month, line, key).ok_or(Unreachable)?;
            let item: Made = self.send(&call).await?;
            if !plain_id(&item.id) {
                return Err(Unreachable);
            }
        }
        let made: Made = self.send(&Self::new_invoice(customer, month, key)).await?;
        Ok(made.id)
    }

    fn event(&self, signature: Option<&str>, body: &[u8], now: i64) -> Result<Event, &'static str> {
        signature::check(signature, body, &self.webhook_secrets, now).map_err(signature::Refused::as_str)?;
        let event: EventBody = serde_json::from_slice(body).map_err(|_| "its body isn't an event")?;
        if event.object != "event" {
            return Err("its body isn't a snapshot event, the only kind Stripe's endpoint here is set to send");
        }
        let customer = event.data.object.customer();
        if !plain_id(&event.id) || customer.as_deref().is_some_and(|customer| !plain_id(customer)) {
            return Err("its event's id or customer isn't one the server keeps");
        }
        Ok(Event {
            id: event.id,
            live: event.livemode,
            customer,
        })
    }

    /// A subscription in effect is the plan. Otherwise, for an MSP's pool or
    /// an organization, a card on file from a setup Checkout Session is a
    /// plan billed by the day; and otherwise the latest subscription that's
    /// over says the plan is over. A pool's card is read whether or not
    /// billing by the day is on now, so turning it off ends no plan.
    async fn standing(&self, customer: &str, whose: &PlanOwner) -> Result<Option<ProviderAnswer>, Unreachable> {
        let subscriptions = self.all_subscriptions(customer).await?;
        let read = read_standing(&subscriptions, &self.prices)?;
        if read.in_effect > 1 {
            warn!(
                "Stripe has {} subscriptions in effect for customer {customer}, so they may be paying twice. The one paid furthest ahead is the plan; see Stripe's dashboard.",
                read.in_effect
            );
        }
        let by_the_day = match whose {
            PlanOwner::Msp(_) => Some(PlanName::Msp),
            PlanOwner::Organization(_) => Some(PlanName::Business),
            PlanOwner::User(_) => None,
        };
        if read.in_effect == 0
            && let Some(plan) = by_the_day
            && let Some(answer) = self.pool_standing(customer, plan).await?
        {
            return Ok(Some(answer));
        }
        Ok(read.answer)
    }

    async fn cancel(&self, customer: &str) -> Result<usize, Unreachable> {
        let subscriptions = self.all_subscriptions(customer).await?;
        let mut canceled = 0;
        let mut failed = false;
        for subscription in subscriptions {
            if matches!(subscription.status.as_str(), "canceled" | "incomplete_expired") {
                continue;
            }
            if !plain_id(&subscription.id) {
                failed = true;
                continue;
            }
            match self.send::<Made>(&Self::cancel_subscription(&subscription.id)).await {
                Ok(_) => canceled += 1,
                Err(Unreachable) => failed = true,
            }
        }
        if failed {
            return Err(Unreachable);
        }
        Ok(canceled)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const PREMIUM: &str = "price_premium1";
    const FAMILIES: &str = "price_families1";

    fn prices() -> Prices {
        Prices {
            premium: PREMIUM.to_owned(),
            families: FAMILIES.to_owned(),
        }
    }

    fn stripe(base: &str, key: &str) -> Result<Stripe, &'static str> {
        Stripe::new(base, Secret::new(key.to_owned()), vec![Secret::new("whsec_made_up".to_owned())], prices(), false)
    }

    fn test_stripe() -> Stripe {
        stripe("http://127.0.0.1:8128", "rk_test_made_up").unwrap()
    }

    /// Stripe with billing by the day on.
    fn by_the_day() -> Stripe {
        Stripe::new(
            "http://127.0.0.1:8128",
            Secret::new("rk_test_made_up".to_owned()),
            vec![Secret::new("whsec_made_up".to_owned())],
            prices(),
            true,
        )
        .unwrap()
    }

    #[test]
    fn the_key_is_a_restricted_one_and_a_live_one_goes_only_to_stripe() {
        // A restricted key, in either mode, to Stripe's own address.
        let live = stripe("", "rk_live_made_up").unwrap();
        assert!(live.live);
        assert_eq!(live.base.as_str(), "https://api.stripe.com/");
        let test = stripe("", "rk_test_made_up").unwrap();
        assert!(!test.live);
        // A test key may go to the stand-in on this machine.
        for base in ["http://127.0.0.1:8128", "https://127.0.0.1", "http://[::1]:8128/"] {
            assert!(!stripe(base, "rk_test_made_up").unwrap().live, "{base}");
        }
        // Never a live key beside BILLING_API_BASE, wherever it points.
        for base in ["http://127.0.0.1:8128", "https://api.stripe.com", "https://stripe.example.com"] {
            let refused = stripe(base, "rk_live_made_up").err().unwrap();
            assert!(refused.contains("BILLING_API_BASE") && refused.contains("live"), "{base}: {refused}");
        }
        // BILLING_API_BASE is for this machine only.
        for base in ["https://api.stripe.com", "http://localhost:8128", "http://10.0.0.5", "ftp://127.0.0.1", "nope"] {
            let refused = stripe(base, "rk_test_made_up").err().unwrap();
            assert!(refused.contains("BILLING_API_BASE"), "{base}: {refused}");
        }
        // The account's full secret key, in either mode, is refused for a restricted one.
        for key in ["sk_live_made_up", "sk_test_made_up"] {
            assert!(stripe("", key).err().unwrap().contains("restricted key"), "{key}");
        }
        // Anything else isn't a key Stripe gave for this.
        for key in ["pk_live_made_up", "pk_test_made_up", "rk_made_up", "whsec_made_up", "made_up", "RK_TEST_X"] {
            assert!(stripe("", key).err().unwrap().contains("rk_live_ or rk_test_"), "{key}");
        }
    }

    #[test]
    fn the_signing_secrets_and_the_prices_are_stripes() {
        let with = |secrets: &[&str], premium: &str, families: &str| {
            Stripe::new(
                "",
                Secret::new("rk_test_made_up".to_owned()),
                secrets.iter().map(|s| Secret::new((*s).to_owned())).collect(),
                Prices {
                    premium: premium.to_owned(),
                    families: families.to_owned(),
                },
                false,
            )
        };
        assert!(with(&["whsec_a"], PREMIUM, FAMILIES).is_ok());
        assert_eq!(with(&["whsec_a", "whsec_old"], PREMIUM, FAMILIES).unwrap().webhook_secrets(), 2);
        for secrets in [&["rk_test_made_up"][..], &["whsec_a", "secret"][..]] {
            assert!(with(secrets, PREMIUM, FAMILIES).err().unwrap().contains("whsec_"), "{secrets:?}");
        }
        // Each is needed, and is a price's id: not a product's, and nothing a URL could carry.
        for (premium, families) in
            [("", FAMILIES), (PREMIUM, ""), ("prod_1", FAMILIES), (PREMIUM, "price_1 2"), (PREMIUM, "price_1/x")]
        {
            let refused = with(&["whsec_a"], premium, families).err().unwrap();
            assert!(refused.contains("BILLING_PRICE_PREMIUM") && refused.contains("BILLING_PRICE_FAMILIES"));
        }
        // One price can't be both plans, or a subscription couldn't say which it is.
        assert!(with(&["whsec_a"], PREMIUM, PREMIUM).err().unwrap().contains("two different prices"));
    }

    #[test]
    fn stripe_takes_business_and_a_pool_only_while_billing_by_the_day_is_on() {
        let s = test_stripe();
        assert!(s.takes(PlanName::Premium) && s.takes(PlanName::Families));
        assert!(!s.takes(PlanName::Business) && !s.takes(PlanName::Msp));
        let org = PlanOwner::Organization("acme".to_owned().into());
        let msp = PlanOwner::Msp("m".to_owned().into());
        assert!(s.checkout(&org, PlanName::Business, "cus_1", "https://vault.example.com/").is_none());
        assert!(s.checkout(&msp, PlanName::Msp, "cus_1", "x").is_none());
        let on = by_the_day();
        assert!(
            [PlanName::Premium, PlanName::Families, PlanName::Business, PlanName::Msp].iter().all(|p| on.takes(*p))
        );
        assert!(on.checkout(&org, PlanName::Business, "cus_1", "x").is_some());
        assert!(on.checkout(&msp, PlanName::Msp, "cus_1", "x").is_some());
        // A person's plan is never a card on file, and Families stays a subscription.
        assert!(on.setup(&PlanOwner::User("ana".to_owned().into()), PlanName::Premium, "cus_1", "x").is_none());
        assert!(on.setup(&org, PlanName::Families, "cus_1", "x").is_none());
        let families = on.checkout(&org, PlanName::Families, "cus_1", "x").unwrap();
        assert!(families.form.contains(&("mode", "subscription".to_owned())));
    }

    /// A card on file for a pool, and the month's invoice, as Stripe's
    /// reference names each call's fields.
    #[test]
    fn the_calls_for_billing_by_the_day() {
        let s = by_the_day();
        let msp = PlanOwner::Msp("9a1c5e7d-0b2f-4c3e-8d6a-1f2e3d4c5b6a".to_owned().into());
        let back = "https://vault.example.com/#/msp";
        let whose = "msp_9a1c5e7d-0b2f-4c3e-8d6a-1f2e3d4c5b6a".to_owned();
        let setup = s.checkout(&msp, PlanName::Msp, "cus_9", back).unwrap();
        assert_eq!((setup.method.clone(), setup.path.join("/")), (Method::POST, "v1/checkout/sessions".to_owned()));
        assert_eq!(
            setup.form,
            vec![
                ("mode", "setup".to_owned()),
                ("currency", "usd".to_owned()),
                ("customer", "cus_9".to_owned()),
                ("client_reference_id", whose.clone()),
                ("metadata[whose]", whose.clone()),
                ("metadata[plan]", "msp".to_owned()),
                ("setup_intent_data[metadata][whose]", whose),
                ("setup_intent_data[metadata][plan]", "msp".to_owned()),
                ("success_url", back.to_owned()),
                ("cancel_url", back.to_owned()),
            ]
        );
        assert_eq!(setup.idempotency, None);

        let sessions = Stripe::completed_sessions("cus_9", Some("cs_7"));
        assert_eq!(
            (sessions.method.clone(), sessions.path.join("/")),
            (Method::GET, "v1/checkout/sessions".to_owned())
        );
        assert_eq!(
            sessions.query,
            vec![
                ("customer", "cus_9".to_owned()),
                ("status", "complete".to_owned()),
                ("limit", "100".to_owned()),
                ("expand[]", "data.setup_intent.payment_method".to_owned()),
                ("starting_after", "cs_7".to_owned()),
            ]
        );
        let customer = Stripe::customer("cus_9");
        assert_eq!((customer.method.clone(), customer.path.join("/")), (Method::GET, "v1/customers/cus_9".to_owned()));
        let default = Stripe::make_default("cus_9", "pm_3");
        assert_eq!((default.method.clone(), default.path.join("/")), (Method::POST, "v1/customers/cus_9".to_owned()));
        assert_eq!(default.form, vec![("invoice_settings[default_payment_method]", "pm_3".to_owned())]);
        let invoices = Stripe::invoices("cus_9", None);
        assert_eq!((invoices.method.clone(), invoices.path.join("/")), (Method::GET, "v1/invoices".to_owned()));
        assert_eq!(invoices.query, vec![("customer", "cus_9".to_owned()), ("limit", "100".to_owned())]);
        let pending = Stripe::pending_items("cus_9", None);
        assert_eq!((pending.method.clone(), pending.path.join("/")), (Method::GET, "v1/invoiceitems".to_owned()));
        assert_eq!(
            pending.query,
            vec![("customer", "cus_9".to_owned()), ("pending", "true".to_owned()), ("limit", "100".to_owned())]
        );

        let key = "passbundle-invoice-msp-9a1c5e7d-0b2f-4c3e-8d6a-1f2e3d4c5b6a-2026-11";
        let line = InvoiceLine {
            description: "MSP seat pool, November 2026: 311 seat-days".to_owned(),
            amount_cents: 1556,
        };
        let item = Stripe::invoice_item("cus_9", "2026-11", &line, key).unwrap();
        assert_eq!((item.method.clone(), item.path.join("/")), (Method::POST, "v1/invoiceitems".to_owned()));
        assert_eq!(
            item.form,
            vec![
                ("customer", "cus_9".to_owned()),
                ("amount", "1556".to_owned()),
                ("currency", "usd".to_owned()),
                ("description", line.description.clone()),
                // November 2026, its first second to its last.
                ("period[start]", "1793491200".to_owned()),
                ("period[end]", "1796083199".to_owned()),
                ("metadata[invoice]", key.to_owned()),
                ("metadata[month]", "2026-11".to_owned()),
            ]
        );
        assert_eq!(item.idempotency.as_deref(), Some(&*format!("{key}-item")));
        assert!(Stripe::invoice_item("cus_9", "2026-13", &line, key).is_none());
        let invoice = Stripe::new_invoice("cus_9", "2026-11", key);
        assert_eq!((invoice.method.clone(), invoice.path.join("/")), (Method::POST, "v1/invoices".to_owned()));
        assert_eq!(
            invoice.form,
            vec![
                ("customer", "cus_9".to_owned()),
                ("collection_method", "charge_automatically".to_owned()),
                ("auto_advance", "true".to_owned()),
                ("pending_invoice_items_behavior", "include".to_owned()),
                ("metadata[invoice]", key.to_owned()),
                ("metadata[month]", "2026-11".to_owned()),
            ]
        );
        assert_eq!(invoice.idempotency.as_deref(), Some(&*format!("{key}-invoice")));
        // Stripe takes an idempotency key of up to 255 characters.
        assert!(format!("{key}-invoice").len() <= 255);
    }

    #[test]
    fn an_invoice_is_sent_with_its_idempotency_key() {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            drop(rustls::crypto::ring::default_provider().install_default());
        }
        let s = by_the_day();
        let call = Stripe::new_invoice("cus_9", "2026-11", "passbundle-invoice-msp-m-2026-11");
        let built = s.request(&call).unwrap().build().unwrap();
        assert_eq!(built.headers()["Idempotency-Key"], "passbundle-invoice-msp-m-2026-11-invoice");
        assert_eq!(built.headers()["Stripe-Version"], VERSION);
        // Reading sends none.
        let read = s.request(&Stripe::invoices("cus_9", None)).unwrap().build().unwrap();
        assert!(read.headers().get("Idempotency-Key").is_none());
        let list = s.request(&Stripe::completed_sessions("cus_9", None)).unwrap().build().unwrap();
        assert_eq!(
            list.url().as_str(),
            "http://127.0.0.1:8128/v1/checkout/sessions?customer=cus_9&status=complete&limit=100&expand%5B%5D=data.setup_intent.payment_method"
        );
    }

    fn stripe_invoice(id: &str, status: &str, attempted: bool, finalized: Option<i64>, ours: bool) -> Value {
        json!({
            "id": id,
            "object": "invoice",
            "customer": "cus_9",
            "status": status,
            "attempted": attempted,
            "attempt_count": if attempted { 1 } else { 0 },
            "created": NOW - 10 * DAY,
            "status_transitions": { "finalized_at": finalized, "paid_at": null },
            "metadata": if ours { json!({ "invoice": format!("key-{id}"), "month": "2026-11" }) } else { json!({}) },
        })
    }

    fn pool(card: bool, invoices: Vec<Value>) -> Result<ProviderAnswer, Unreachable> {
        let invoices: Vec<InvoiceRead> = serde_json::from_value(Value::Array(invoices)).unwrap();
        read_pool(PlanName::Msp, card, &invoices)
    }

    fn open() -> Option<ProviderAnswer> {
        ProviderAnswer::new(PlanName::Msp, Standing::Open, None, true, Billed::ByTheDay, None)
    }

    fn until(at_seconds: i64) -> Option<ProviderAnswer> {
        ProviderAnswer::new(PlanName::Msp, Standing::Until, Some(at(at_seconds)), true, Billed::ByTheDay, None)
    }

    /// Standing for a pool, by DESIGN.md's table: a default card and no
    /// unpaid invoice is good with no end; an unpaid invoice is good through
    /// its first failed attempt.
    #[test]
    fn standing_for_a_pool() {
        let finalized = NOW - 3 * DAY;
        // A card, and nothing unpaid: good with no end.
        assert_eq!(pool(true, vec![]).ok(), open());
        for status in ["paid", "void", "draft"] {
            assert_eq!(
                pool(true, vec![stripe_invoice("in_1", status, true, Some(finalized), true)]).ok(),
                open(),
                "{status}"
            );
        }
        // Finalized and not yet tried: nothing has failed.
        assert_eq!(pool(true, vec![stripe_invoice("in_1", "open", false, Some(finalized), true)]).ok(), open());
        // Tried and unpaid, or given up on: good through the first failed attempt.
        for status in ["open", "uncollectible"] {
            assert_eq!(
                pool(true, vec![stripe_invoice("in_1", status, true, Some(finalized), true)]).ok(),
                until(finalized),
                "{status}"
            );
        }
        // The earliest unpaid one counts, and with no card the same.
        assert_eq!(
            pool(
                false,
                vec![
                    stripe_invoice("in_2", "open", true, Some(finalized), true),
                    stripe_invoice("in_1", "open", true, Some(finalized - 30 * DAY), true),
                    stripe_invoice("in_0", "paid", true, Some(finalized - 60 * DAY), true),
                ]
            )
            .ok(),
            until(finalized - 30 * DAY)
        );
        // No finalized date: when it was made.
        assert_eq!(pool(true, vec![stripe_invoice("in_1", "open", true, None, true)]).ok(), until(NOW - 10 * DAY));
        // No card and nothing unpaid: nothing, which ends a plan the provider set.
        assert_eq!(
            pool(false, vec![]).ok(),
            ProviderAnswer::new(PlanName::Msp, Standing::None, None, false, Billed::ByTheDay, None)
        );
        // An invoice the server didn't make (a subscription's) isn't read here.
        assert_eq!(pool(true, vec![stripe_invoice("in_1", "open", true, Some(finalized), false)]).ok(), open());
        // A status this code doesn't know is no answer.
        assert_eq!(pool(true, vec![stripe_invoice("in_1", "deleted", true, Some(finalized), true)]), Err(Unreachable));
        // A Business organization reads the same, as Business.
        let invoices: Vec<InvoiceRead> = vec![];
        assert_eq!(
            read_pool(PlanName::Business, true, &invoices).ok(),
            ProviderAnswer::new(PlanName::Business, Standing::Open, None, true, Billed::ByTheDay, None)
        );
    }

    fn session(id: &str, created: i64, mode: &str, intent: Value) -> Value {
        json!({ "id": id, "object": "checkout.session", "mode": mode, "status": "complete", "created": created, "setup_intent": intent })
    }

    fn intent(status: &str, card: &str, owner: Value) -> Value {
        json!({ "id": "seti_1", "object": "setup_intent", "status": status, "payment_method": { "id": card, "object": "payment_method", "customer": owner } })
    }

    fn setups(sessions: Vec<Value>) -> Setup {
        let sessions: Vec<SessionRead> = serde_json::from_value(Value::Array(sessions)).unwrap();
        setup_card(&sessions, "cus_9")
    }

    #[test]
    fn the_card_a_setup_saved_while_its_still_the_customers() {
        // No setup: not billed by the day at all.
        assert_eq!(setups(vec![]), Setup::None);
        assert_eq!(setups(vec![session("cs_1", NOW, "subscription", Value::Null)]), Setup::None);
        // The latest setup's card, still the customer's.
        assert_eq!(
            setups(vec![
                session("cs_1", NOW - DAY, "setup", intent("succeeded", "pm_old", json!("cus_9"))),
                session("cs_2", NOW, "setup", intent("succeeded", "pm_new", json!({ "id": "cus_9" }))),
            ]),
            Setup::Card("pm_new".to_owned())
        );
        // Removed from the customer since: an older card that's still theirs, or none.
        assert_eq!(
            setups(vec![
                session("cs_1", NOW - DAY, "setup", intent("succeeded", "pm_old", json!("cus_9"))),
                session("cs_2", NOW, "setup", intent("succeeded", "pm_new", Value::Null)),
            ]),
            Setup::Card("pm_old".to_owned())
        );
        assert_eq!(
            setups(vec![session("cs_2", NOW, "setup", intent("succeeded", "pm_new", Value::Null))]),
            Setup::CardGone
        );
        // Another customer's card, or a setup that didn't succeed, isn't one.
        assert_eq!(
            setups(vec![session("cs_2", NOW, "setup", intent("succeeded", "pm_new", json!("cus_other")))]),
            Setup::CardGone
        );
        assert_eq!(
            setups(vec![session("cs_2", NOW, "setup", intent("requires_payment_method", "pm_new", json!("cus_9")))]),
            Setup::CardGone
        );
        // An intent that wasn't expanded can't say whose its card is.
        assert_eq!(setups(vec![session("cs_2", NOW, "setup", json!("seti_1"))]), Setup::CardGone);
    }

    /// The fields of each call, as Stripe's reference names them.
    #[test]
    fn the_calls_and_their_fields() {
        let s = test_stripe();
        let ana = PlanOwner::User("0b4a8e1c-6c0e-4a39-9f43-6d1d8e3f7a10".to_owned().into());
        let acme = PlanOwner::Organization("5d9f0c2e-1b7a-4f5e-8c3d-2a6b9e4f1c07".to_owned().into());
        let back = "https://vault.example.com/#/settings/plan";

        assert_eq!(
            Stripe::new_customer(&acme),
            Call {
                method: Method::POST,
                path: vec!["v1".into(), "customers".into()],
                query: vec![],
                form: vec![("metadata[whose]", "organization_5d9f0c2e-1b7a-4f5e-8c3d-2a6b9e4f1c07".into())],
                what: "making a customer",
                idempotency: None,
            }
        );
        let checkout = s.checkout(&ana, PlanName::Premium, "cus_9", back).unwrap();
        assert_eq!(
            (checkout.method.clone(), checkout.path.join("/")),
            (Method::POST, "v1/checkout/sessions".to_owned())
        );
        let whose = "user_0b4a8e1c-6c0e-4a39-9f43-6d1d8e3f7a10".to_owned();
        assert_eq!(
            checkout.form,
            vec![
                ("mode", "subscription".to_owned()),
                ("customer", "cus_9".to_owned()),
                ("client_reference_id", whose.clone()),
                ("line_items[0][price]", PREMIUM.to_owned()),
                ("line_items[0][quantity]", "1".to_owned()),
                ("subscription_data[metadata][whose]", whose),
                ("subscription_data[metadata][plan]", "premium".to_owned()),
                ("success_url", back.to_owned()),
                ("cancel_url", back.to_owned()),
            ]
        );
        // Families has its own price.
        let families = s.checkout(&acme, PlanName::Families, "cus_9", back).unwrap();
        assert!(families.form.contains(&("line_items[0][price]", FAMILIES.to_owned())));
        assert!(families.form.contains(&("subscription_data[metadata][plan]", "families".to_owned())));
        assert!(
            families
                .form
                .contains(&("client_reference_id", "organization_5d9f0c2e-1b7a-4f5e-8c3d-2a6b9e4f1c07".to_owned()))
        );
        // client_reference_id is at most 200 characters.
        assert!(families.form.iter().all(|(name, value)| *name != "client_reference_id" || value.len() <= 200));

        let portal = Stripe::portal("cus_9", back);
        assert_eq!(
            (portal.method.clone(), portal.path.join("/")),
            (Method::POST, "v1/billing_portal/sessions".to_owned())
        );
        assert_eq!(portal.form, vec![("customer", "cus_9".to_owned()), ("return_url", back.to_owned())]);

        let first = Stripe::subscriptions("cus_9", None);
        assert_eq!((first.method.clone(), first.path.join("/")), (Method::GET, "v1/subscriptions".to_owned()));
        assert_eq!(
            first.query,
            vec![("customer", "cus_9".to_owned()), ("status", "all".to_owned()), ("limit", "100".to_owned())]
        );
        assert!(first.form.is_empty());
        let next = Stripe::subscriptions("cus_9", Some("sub_7"));
        assert_eq!(next.query.last(), Some(&("starting_after", "sub_7".to_owned())));

        let cancel = Stripe::cancel_subscription("sub_7");
        assert_eq!(
            (cancel.method.clone(), cancel.path.join("/")),
            (Method::DELETE, "v1/subscriptions/sub_7".to_owned())
        );
        assert!(cancel.form.is_empty() && cancel.query.is_empty());
    }

    /// What goes over the wire: the address, the bearer, the pinned version,
    /// and a POST's body form-encoded.
    #[test]
    fn the_requests_as_sent() {
        // As main() does before any client is made. Another test may have done it first.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            drop(rustls::crypto::ring::default_provider().install_default());
        }
        let s = test_stripe();
        let back = "https://vault.example.com/#/organizations/a b/plan";
        let ana = PlanOwner::User("ana".to_owned().into());
        let built = s.request(&s.checkout(&ana, PlanName::Premium, "cus_9", back).unwrap()).unwrap().build().unwrap();
        assert_eq!(built.method(), Method::POST);
        assert_eq!(built.url().as_str(), "http://127.0.0.1:8128/v1/checkout/sessions");
        let headers = built.headers();
        assert_eq!(headers[header::AUTHORIZATION], "Bearer rk_test_made_up");
        assert!(headers[header::AUTHORIZATION].is_sensitive());
        assert_eq!(headers["Stripe-Version"], VERSION);
        assert_eq!(headers[header::CONTENT_TYPE], "application/x-www-form-urlencoded");
        let body = std::str::from_utf8(built.body().unwrap().as_bytes().unwrap()).unwrap();
        assert_eq!(
            body,
            "mode=subscription&customer=cus_9&client_reference_id=user_ana\
             &line_items%5B0%5D%5Bprice%5D=price_premium1&line_items%5B0%5D%5Bquantity%5D=1\
             &subscription_data%5Bmetadata%5D%5Bwhose%5D=user_ana&subscription_data%5Bmetadata%5D%5Bplan%5D=premium\
             &success_url=https%3A%2F%2Fvault.example.com%2F%23%2Forganizations%2Fa+b%2Fplan\
             &cancel_url=https%3A%2F%2Fvault.example.com%2F%23%2Forganizations%2Fa+b%2Fplan"
        );
        // Decoded, it's the same fields.
        let decoded: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes()).into_owned().collect();
        assert_eq!(decoded[3], ("line_items[0][price]".to_owned(), PREMIUM.to_owned()));
        assert_eq!(decoded[7].1, back);

        // A GET has its query and no body.
        let list = s.request(&Stripe::subscriptions("cus_9", Some("sub_7"))).unwrap().build().unwrap();
        assert_eq!(
            list.url().as_str(),
            "http://127.0.0.1:8128/v1/subscriptions?customer=cus_9&status=all&limit=100&starting_after=sub_7"
        );
        assert!(list.body().is_none());
        assert_eq!(list.headers()["Stripe-Version"], VERSION);
        assert!(list.headers().get(header::CONTENT_TYPE).is_none());

        // A DELETE, the same.
        let cancel = s.request(&Stripe::cancel_subscription("sub_7")).unwrap().build().unwrap();
        assert_eq!((cancel.method(), cancel.url().path()), (&Method::DELETE, "/v1/subscriptions/sub_7"));
        assert!(cancel.body().is_none());

        // To Stripe itself, with no BILLING_API_BASE.
        let live = stripe("", "rk_live_made_up").unwrap();
        let built = live.request(&Stripe::portal("cus_9", "https://vault.example.com/")).unwrap().build().unwrap();
        assert_eq!(built.url().as_str(), "https://api.stripe.com/v1/billing_portal/sessions");
        assert_eq!(built.headers()[header::AUTHORIZATION], "Bearer rk_live_made_up");
    }

    #[test]
    fn the_pinned_version_is_a_dated_release() {
        let (date, name) = VERSION.split_once('.').unwrap();
        assert!(chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok());
        assert!(!name.is_empty() && name != "preview" && name.bytes().all(|b| b.is_ascii_lowercase()));
    }

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn subscription(id: &str, status: &str, price: &str, start: i64, end: i64) -> Value {
        json!({
            "id": id,
            "object": "subscription",
            "customer": "cus_9",
            "status": status,
            "cancel_at": null,
            "cancel_at_period_end": false,
            "created": start,
            "metadata": { "whose": "user_ana", "plan": "premium" },
            "items": {
                "object": "list",
                "data": [{
                    "id": "si_1",
                    "object": "subscription_item",
                    "current_period_start": start,
                    "current_period_end": end,
                    "price": { "id": price, "object": "price" },
                    "quantity": 1,
                }],
                "has_more": false,
            },
        })
    }

    fn read(subscriptions: Vec<Value>) -> Result<Read, Unreachable> {
        let subscriptions: Vec<Subscription> = serde_json::from_value(Value::Array(subscriptions)).unwrap();
        read_standing(&subscriptions, &prices())
    }

    fn at(seconds: i64) -> NaiveDateTime {
        DateTime::from_timestamp(seconds, 0).unwrap().naive_utc()
    }

    fn paid(plan: PlanName, until: i64, renews: bool, id: &str) -> Option<ProviderAnswer> {
        ProviderAnswer::new(plan, Standing::Until, Some(at(until)), renews, Billed::Prepaid, Some(id.to_owned()))
    }

    fn over(plan: PlanName, id: &str) -> Option<ProviderAnswer> {
        ProviderAnswer::new(plan, Standing::None, None, false, Billed::Prepaid, Some(id.to_owned()))
    }

    /// Every status a subscription can have, by DESIGN.md's table.
    #[test]
    fn each_status_read_by_the_designs_table() {
        let start = NOW - 10 * DAY;
        let end = start + 365 * DAY;
        let one = |status: &str| read(vec![subscription("sub_1", status, PREMIUM, start, end)]);
        // Good through the current period's end, renewing.
        for status in ["active", "trialing"] {
            assert_eq!(
                one(status),
                Ok(Read {
                    answer: paid(PlanName::Premium, end, true, "sub_1"),
                    in_effect: 1
                }),
                "{status}"
            );
        }
        // Past due: good through the last period paid, which ended when this one started.
        assert_eq!(
            one("past_due"),
            Ok(Read {
                answer: paid(PlanName::Premium, start, true, "sub_1"),
                in_effect: 1
            })
        );
        // Over.
        for status in ["canceled", "unpaid", "incomplete_expired", "paused"] {
            assert_eq!(
                one(status),
                Ok(Read {
                    answer: over(PlanName::Premium, "sub_1"),
                    in_effect: 0
                }),
                "{status}"
            );
        }
        // A first payment that never finished: nothing yet.
        assert_eq!(
            one("incomplete"),
            Ok(Read {
                answer: None,
                in_effect: 0
            })
        );
        // No subscriptions at all: nothing.
        assert_eq!(
            read(vec![]),
            Ok(Read {
                answer: None,
                in_effect: 0
            })
        );
        // A status this code doesn't know is no answer, so the last one stands.
        for status in ["ended", "Active", "", "on_hold"] {
            assert_eq!(one(status), Err(Unreachable), "{status}");
        }
    }

    #[test]
    fn canceling_at_the_periods_end_or_on_a_date() {
        let start = NOW - 10 * DAY;
        let end = start + 365 * DAY;
        // Canceled in the portal: it ends at the period's end and doesn't renew.
        let mut at_end = subscription("sub_1", "active", PREMIUM, start, end);
        at_end["cancel_at_period_end"] = json!(true);
        assert_eq!(read(vec![at_end.clone()]).unwrap().answer, paid(PlanName::Premium, end, false, "sub_1"));
        // Set to cancel on a date: that date, when it's sooner.
        let mut on_a_date = subscription("sub_1", "active", PREMIUM, start, end);
        on_a_date["cancel_at"] = json!(NOW + 30 * DAY);
        assert_eq!(
            read(vec![on_a_date.clone()]).unwrap().answer,
            paid(PlanName::Premium, NOW + 30 * DAY, false, "sub_1")
        );
        on_a_date["cancel_at"] = json!(end + DAY);
        assert_eq!(read(vec![on_a_date]).unwrap().answer, paid(PlanName::Premium, end, false, "sub_1"));
        // Past due and canceled: through the last period paid, with no grace.
        at_end["status"] = json!("past_due");
        assert_eq!(read(vec![at_end]).unwrap().answer, paid(PlanName::Premium, start, false, "sub_1"));
    }

    #[test]
    fn which_plan_a_subscription_is_for() {
        let start = NOW - DAY;
        let end = start + 365 * DAY;
        // By its price.
        let mut families = subscription("sub_f", "active", FAMILIES, start, end);
        families["metadata"] = json!({});
        assert_eq!(read(vec![families]).unwrap().answer, paid(PlanName::Families, end, true, "sub_f"));
        // Another price, as after the owner changes a plan's price: the plan written at checkout.
        let mut renamed = subscription("sub_r", "active", "price_old_premium", start, end);
        assert_eq!(read(vec![renamed.clone()]).unwrap().answer, paid(PlanName::Premium, end, true, "sub_r"));
        // Neither, while it's in effect: no answer, so the last one stands.
        renamed["metadata"] = json!({ "plan": "business" });
        assert_eq!(read(vec![renamed.clone()]), Err(Unreachable));
        renamed["metadata"] = json!({});
        assert_eq!(read(vec![renamed.clone()]), Err(Unreachable));
        // Neither, and over: something else the account sells, which isn't read.
        renamed["status"] = json!("canceled");
        assert_eq!(
            read(vec![renamed]),
            Ok(Read {
                answer: None,
                in_effect: 0
            })
        );
        // An item with no period can't say how long it's paid for.
        let mut no_period = subscription("sub_n", "active", PREMIUM, start, end);
        no_period["items"]["data"][0]["current_period_end"] = Value::Null;
        assert_eq!(read(vec![no_period]), Err(Unreachable));
        // A subscription id the server won't keep.
        assert_eq!(read(vec![subscription("sub 1", "active", PREMIUM, start, end)]), Err(Unreachable));
    }

    #[test]
    fn several_subscriptions() {
        let start = NOW - 10 * DAY;
        let year = 365 * DAY;
        // One in good standing comes before one past due, whatever their dates.
        let both = read(vec![
            subscription("sub_due", "past_due", PREMIUM, start + 100 * DAY, start + 100 * DAY + year),
            subscription("sub_ok", "active", PREMIUM, start, start + year),
        ])
        .unwrap();
        assert_eq!(both.answer, paid(PlanName::Premium, start + year, true, "sub_ok"));
        assert_eq!(both.in_effect, 2);
        // Of two in good standing, the one paid furthest ahead.
        let two = read(vec![
            subscription("sub_a", "active", PREMIUM, start, start + year),
            subscription("sub_b", "active", PREMIUM, start + DAY, start + DAY + year),
        ])
        .unwrap();
        assert_eq!((two.answer, two.in_effect), (paid(PlanName::Premium, start + DAY + year, true, "sub_b"), 2));
        // One in effect beside ones that are over or never started: the one in effect.
        let mixed = read(vec![
            subscription("sub_old", "canceled", PREMIUM, start - year, start),
            subscription("sub_new", "incomplete", PREMIUM, NOW, NOW + year),
            subscription("sub_ok", "trialing", PREMIUM, start, start + 14 * DAY),
        ])
        .unwrap();
        assert_eq!((mixed.answer, mixed.in_effect), (paid(PlanName::Premium, start + 14 * DAY, true, "sub_ok"), 1));
        // None in effect: the latest that's over.
        let ended = read(vec![
            subscription("sub_first", "canceled", PREMIUM, start - 2 * year, start - year),
            subscription("sub_last", "unpaid", FAMILIES, start - year, start),
        ])
        .unwrap();
        assert_eq!(ended.answer, over(PlanName::Families, "sub_last"));
        // One status this code doesn't know spoils the lot.
        assert_eq!(
            read(vec![
                subscription("sub_ok", "active", PREMIUM, start, start + year),
                subscription("sub_odd", "frozen", PREMIUM, start, start + year),
            ]),
            Err(Unreachable)
        );
    }

    fn header(secret: &str, t: i64, body: &[u8]) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
        let mut message = t.to_string().into_bytes();
        message.push(b'.');
        message.extend_from_slice(body);
        let v1 = data_encoding::HEXLOWER.encode(ring::hmac::sign(&key, &message).as_ref());
        // As Stripe writes it for a sandbox event, with a fake v0 and its debugging entries.
        format!(
            "t={t},v1={v1},v0=6ffbb59b2300aae63f272406069a9788,secret=whsec_****PzVt,destination=we_1,payload=a25aefc6"
        )
    }

    #[test]
    fn from_an_event_only_its_id_its_mode_and_the_customer() {
        let s = test_stripe();
        assert_eq!(s.signature_header(), "Stripe-Signature");
        let event = |object: Value| {
            serde_json::to_vec(&json!({
                "id": "evt_1",
                "object": "event",
                "api_version": VERSION,
                "created": NOW,
                "data": { "object": object, "previous_attributes": { "status": "active" } },
                "livemode": false,
                "pending_webhooks": 1,
                "request": { "id": null, "idempotency_key": null },
                "type": "customer.subscription.updated",
            }))
            .unwrap()
        };
        let take = |body: &[u8]| s.event(Some(&header("whsec_made_up", NOW, body)), body, NOW);
        // A subscription's, a Checkout Session's, an invoice's: their customer.
        for object in [
            json!({ "id": "sub_1", "object": "subscription", "customer": "cus_9", "status": "active" }),
            json!({ "id": "cs_1", "object": "checkout.session", "customer": "cus_9", "mode": "subscription" }),
            json!({ "id": "in_1", "object": "invoice", "customer": { "id": "cus_9", "object": "customer" } }),
            json!({ "id": "cus_9", "object": "customer", "email": null }),
        ] {
            let taken = take(&event(object.clone())).unwrap();
            assert_eq!(
                (taken.id.as_str(), taken.live, taken.customer.as_deref()),
                ("evt_1", false, Some("cus_9")),
                "{object}"
            );
        }
        // One about no customer, as a dispute is.
        let nobody = take(&event(json!({ "id": "dp_1", "object": "dispute", "charge": "ch_1" }))).unwrap();
        assert_eq!(nobody.customer, None);
        // The live mode, as the event says it.
        let mut live: Value =
            serde_json::from_slice(&event(json!({ "id": "sub_1", "object": "subscription", "customer": "cus_9" })))
                .unwrap();
        live["livemode"] = json!(true);
        assert!(take(&serde_json::to_vec(&live).unwrap()).unwrap().live);
        // A thin event, which has no data.object and isn't what the endpoint is set to send.
        let thin = serde_json::to_vec(&json!({
            "id": "evt_2",
            "object": "v2.core.event",
            "type": "v1.customer.subscription.updated",
            "livemode": false,
            "related_object": { "id": "sub_1", "type": "subscription" },
            "data": { "object": { "object": "subscription", "customer": "cus_9" } },
        }))
        .unwrap();
        assert!(take(&thin).unwrap_err().contains("snapshot"));
        // Ids the server won't keep.
        let odd = event(json!({ "id": "sub_1", "object": "subscription", "customer": "cus 9" }));
        assert!(take(&odd).is_err());
        // A wrong secret, and a body changed after it was signed, before anything in it is read.
        let body = event(json!({ "id": "sub_1", "object": "subscription", "customer": "cus_9" }));
        assert!(s.event(Some(&header("whsec_other", NOW, &body)), &body, NOW).unwrap_err().contains("signing secret"));
        let mut changed = body.clone();
        changed[10] ^= 1;
        assert!(s.event(Some(&header("whsec_made_up", NOW, &body)), &changed, NOW).is_err());
        assert!(s.event(None, &body, NOW).is_err());
        // Six minutes old.
        assert!(
            s.event(Some(&header("whsec_made_up", NOW - 360, &body)), &body, NOW).unwrap_err().contains("five minutes")
        );
    }
}

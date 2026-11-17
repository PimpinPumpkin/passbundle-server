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
// A card on file for a pool, Business, and invoices are piece 10 of the build
// order: until then they answer that they aren't there yet.
//
// No body, key, or header goes into a log or an error: a failure says which
// call it was and the status, and nothing more.

use std::{collections::HashMap, sync::LazyLock, time::Duration};

use chrono::{DateTime, NaiveDateTime};
use reqwest::{Client, Method, header};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use url::Url;

use super::{Event, InvoiceLine, PayPage, Provider, Secret, Unreachable, loopback_url, plain_id, signature};
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
/// most. A customer with more can't be read whole, which is no answer.
const PAGE_SIZE: &str = "100";
const MAX_PAGES: usize = 5;

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
}

impl Call {
    fn new(method: Method, path: &[&str], what: &'static str) -> Self {
        Self {
            method,
            path: path.iter().map(|part| (*part).to_owned()).collect(),
            query: Vec::new(),
            form: Vec::new(),
            what,
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
    /// whether they paid or not. None for a plan Stripe doesn't take here.
    fn checkout(&self, whose: &PlanOwner, plan: PlanName, customer: &str, back: &str) -> Option<Call> {
        let price = self.price(plan)?;
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
        self.price(plan).is_some()
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

    fn invoice(
        &self,
        _customer: &str,
        _month: &str,
        _lines: &[InvoiceLine],
        _key: &str,
    ) -> impl Future<Output = Result<String, Unreachable>> {
        warn!("Invoicing a month through Stripe isn't built yet (piece 10 of the plans design's build order).");
        std::future::ready(Err(Unreachable))
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

    async fn standing(&self, customer: &str) -> Result<Option<ProviderAnswer>, Unreachable> {
        let subscriptions = self.all_subscriptions(customer).await?;
        let read = read_standing(&subscriptions, &self.prices)?;
        if read.in_effect > 1 {
            warn!(
                "Stripe has {} subscriptions in effect for customer {customer}, so they may be paying twice. The one paid furthest ahead is the plan; see Stripe's dashboard.",
                read.in_effect
            );
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
        Stripe::new(base, Secret::new(key.to_owned()), vec![Secret::new("whsec_made_up".to_owned())], prices())
    }

    fn test_stripe() -> Stripe {
        stripe("http://127.0.0.1:8128", "rk_test_made_up").unwrap()
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
    fn stripe_takes_premium_and_families_and_the_rest_waits_for_piece_10() {
        let s = test_stripe();
        assert!(s.takes(PlanName::Premium) && s.takes(PlanName::Families));
        assert!(!s.takes(PlanName::Business) && !s.takes(PlanName::Msp));
        let org = PlanOwner::Organization("acme".to_owned().into());
        assert!(s.checkout(&org, PlanName::Business, "cus_1", "https://vault.example.com/").is_none());
        assert!(s.checkout(&PlanOwner::Msp("m".to_owned().into()), PlanName::Msp, "cus_1", "x").is_none());
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

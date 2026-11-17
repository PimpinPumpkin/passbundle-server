// Keykeeper: the adapter for the test stand-in (BILLING_PROVIDER=standin),
// the small server in the meta repo's e2e/billing-standin.mjs. It answers the
// five calls the way a provider would, from what a test tells it, and signs
// its webhooks with Stripe's published scheme (`signature`), so the server's
// whole path from a webhook to a plan is tested without any real provider.
//
// It can't be used for real: it talks only to a loopback BILLING_API_BASE
// (the server won't start otherwise), never with a key that looks live, and
// it's never the provider's live mode, so a live event is dropped.

use std::sync::LazyLock;

use reqwest::{Client, Method, StatusCode, header};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

use super::{Event, InvoiceLine, PayPage, Provider, Secret, Unreachable, loopback_url, plain_id, signature};
use crate::{
    db::models::{Billed, PlanName, PlanOwner, ProviderAnswer, Standing},
    http_client::get_reqwest_client_builder,
};

pub struct Standin {
    base: Url,
    api_key: Secret,
    webhook_secrets: Vec<Secret>,
}

/// Made the first time the stand-in is asked something. It follows no
/// redirect, so the key goes nowhere but the address it was set for.
static CLIENT: LazyLock<Client> = LazyLock::new(|| {
    get_reqwest_client_builder(false)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build the stand-in payment provider's HTTP client")
});

/// Only an address on this machine, written as one: a name could be made to
/// point anywhere.
fn loopback(api_base: &str) -> Result<Url, &'static str> {
    loopback_url(api_base).ok_or(
        "The stand-in payment provider is for tests: `BILLING_API_BASE` must be an http or https address on this machine, written as one, such as http://127.0.0.1:8124",
    )
}

impl Standin {
    pub fn new(api_base: &str, api_key: Secret, webhook_secrets: Vec<Secret>) -> Result<Self, &'static str> {
        let base = loopback(api_base)?;
        if api_key.expose().contains("_live_") {
            return Err(
                "`BILLING_API_KEY` looks like a live key, which is never sent to the stand-in payment provider",
            );
        }
        Ok(Self {
            base,
            api_key,
            webhook_secrets,
        })
    }

    #[cfg(test)]
    pub fn webhook_secrets(&self) -> usize {
        self.webhook_secrets.len()
    }

    /// The stand-in's address for `path`, each part percent-encoded.
    fn url(&self, path: &[&str]) -> Result<Url, Unreachable> {
        let mut url = self.base.clone();
        url.path_segments_mut().map_err(|()| Unreachable)?.pop_if_empty().extend(path);
        Ok(url)
    }

    /// One call. None for a 404, which is the stand-in not knowing what was
    /// asked about. Anything but a 200 or a 404, or an answer that isn't
    /// JSON, is a failure, logged without the key.
    async fn call(&self, method: Method, path: &[&str], body: Option<Value>) -> Result<Option<Value>, Unreachable> {
        let mut request = CLIENT
            .request(method, self.url(path)?)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.api_key.expose()));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.map_err(|e| {
            warn!("The stand-in payment provider couldn't be reached: {}", e.without_url());
            Unreachable
        })?;
        match response.status() {
            StatusCode::OK => response.json::<Value>().await.map(Some).map_err(|_| {
                warn!("The stand-in payment provider's answer wasn't JSON.");
                Unreachable
            }),
            StatusCode::NOT_FOUND => Ok(None),
            status => {
                warn!("The stand-in payment provider answered {status}.");
                Err(Unreachable)
            }
        }
    }

    /// A string field of an answer, as an id.
    fn id(answer: &Value, field: &str) -> Result<String, Unreachable> {
        match answer[field].as_str() {
            Some(id) if plain_id(id) => Ok(id.to_owned()),
            _ => {
                warn!("The stand-in payment provider's answer had no usable `{field}`.");
                Err(Unreachable)
            }
        }
    }

    fn whose(whose: &PlanOwner) -> String {
        match whose {
            PlanOwner::User(id) => format!("user:{id}"),
            PlanOwner::Organization(id) => format!("organization:{id}"),
            PlanOwner::Msp(id) => format!("msp:{id}"),
        }
    }
}

/// A customer's standing, as the stand-in writes it. `plan` null is nothing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StandingBody {
    plan: Option<String>,
    standing: Option<String>,
    until: Option<String>,
    renews: Option<bool>,
    billed: Option<String>,
    subscription: Option<String>,
}

impl StandingBody {
    /// The answer, or Unreachable when it can't be read whole.
    fn answer(self) -> Result<Option<ProviderAnswer>, Unreachable> {
        let Some(plan) = self.plan else {
            return Ok(None);
        };
        let until = match self.until {
            Some(until) => Some(crate::util::parse_date(&until).ok_or(Unreachable)?),
            None => None,
        };
        let answer = ProviderAnswer::new(
            PlanName::parse(&plan).ok_or(Unreachable)?,
            Standing::parse(self.standing.as_deref().ok_or(Unreachable)?).ok_or(Unreachable)?,
            until,
            self.renews.ok_or(Unreachable)?,
            Billed::parse(self.billed.as_deref().ok_or(Unreachable)?).ok_or(Unreachable)?,
            self.subscription,
        )
        .ok_or(Unreachable)?;
        Ok(Some(answer))
    }
}

/// The fields of a webhook the adapter reads: its id, its mode, and the
/// customer. Anything else in it is ignored.
#[derive(Deserialize)]
struct EventBody {
    id: String,
    livemode: bool,
    customer: Option<String>,
}

impl Provider for Standin {
    fn live(&self) -> bool {
        false
    }

    fn signature_header(&self) -> &'static str {
        "Standin-Signature"
    }

    /// Every plan, so the server's whole path is tested for each.
    fn takes(&self, _plan: PlanName) -> bool {
        true
    }

    async fn pay_page(
        &self,
        whose: &PlanOwner,
        plan: PlanName,
        customer: Option<&str>,
        back: &str,
    ) -> Result<PayPage, Unreachable> {
        let body = json!({ "whose": Self::whose(whose), "plan": plan.as_str(), "customer": customer, "back": back });
        let answer = self.call(Method::POST, &["pay"], Some(body)).await?.ok_or(Unreachable)?;
        Ok(PayPage {
            url: answer["url"].as_str().ok_or(Unreachable)?.to_owned(),
            customer: Self::id(&answer, "customer")?,
        })
    }

    async fn manage_page(&self, customer: &str, back: &str) -> Result<String, Unreachable> {
        let body = json!({ "customer": customer, "back": back });
        let answer = self.call(Method::POST, &["manage"], Some(body)).await?.ok_or(Unreachable)?;
        Ok(answer["url"].as_str().ok_or(Unreachable)?.to_owned())
    }

    async fn invoice(
        &self,
        customer: &str,
        month: &str,
        lines: &[InvoiceLine],
        key: &str,
    ) -> Result<String, Unreachable> {
        let lines: Vec<Value> = lines
            .iter()
            .map(|line| json!({ "description": line.description, "amountCents": line.amount_cents }))
            .collect();
        let (start, end) = super::invoices::month_period(month).ok_or(Unreachable)?;
        let body = json!({
            "customer": customer,
            "month": month,
            "period": { "start": start, "end": end },
            "currency": super::invoices::CURRENCY,
            "lines": lines,
            "key": key,
        });
        let answer = self.call(Method::POST, &["invoices"], Some(body)).await?.ok_or(Unreachable)?;
        Self::id(&answer, "id")
    }

    fn event(&self, signature: Option<&str>, body: &[u8], now: i64) -> Result<Event, &'static str> {
        signature::check(signature, body, &self.webhook_secrets, now).map_err(signature::Refused::as_str)?;
        let event: EventBody = serde_json::from_slice(body).map_err(|_| "its body isn't an event")?;
        if !plain_id(&event.id) || event.customer.as_deref().is_some_and(|customer| !plain_id(customer)) {
            return Err("its event's id or customer isn't one the server keeps");
        }
        Ok(Event {
            id: event.id,
            live: event.livemode,
            customer: event.customer,
        })
    }

    /// Whatever the stand-in says, which a test sets, for anyone's plan.
    async fn standing(&self, customer: &str, _whose: &PlanOwner) -> Result<Option<ProviderAnswer>, Unreachable> {
        let Some(answer) = self.call(Method::GET, &["customers", customer], None).await? else {
            return Ok(None);
        };
        let read =
            serde_json::from_value::<StandingBody>(answer).map_err(|_| Unreachable).and_then(StandingBody::answer);
        if read.is_err() {
            warn!("The stand-in payment provider's standing couldn't be read.");
        }
        read
    }

    async fn cancel(&self, customer: &str) -> Result<usize, Unreachable> {
        let body = json!({ "customer": customer });
        let Some(answer) = self.call(Method::POST, &["cancel"], Some(body)).await? else {
            return Ok(0);
        };
        answer["canceled"].as_u64().and_then(|n| usize::try_from(n).ok()).ok_or(Unreachable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(text: &str) -> chrono::NaiveDateTime {
        crate::util::parse_date(text).unwrap()
    }

    fn standing(value: Value) -> Result<Option<ProviderAnswer>, Unreachable> {
        serde_json::from_value::<StandingBody>(value).map_err(|_| Unreachable).and_then(StandingBody::answer)
    }

    #[test]
    fn a_standing_is_read_whole_or_not_at_all() {
        assert_eq!(standing(json!({ "plan": null })), Ok(None));
        let paid = standing(json!({
            "plan": "premium",
            "standing": "until",
            "until": "2027-03-01T12:00:00Z",
            "renews": true,
            "billed": "prepaid",
            "subscription": "sub_1",
        }))
        .unwrap()
        .unwrap();
        assert_eq!(paid.plan, PlanName::Premium);
        assert_eq!(paid.standing, Standing::Until);
        assert_eq!(paid.until, Some(date("2027-03-01T12:00:00Z")));
        assert!(paid.renews);
        assert_eq!(paid.billed, Billed::Prepaid);
        assert_eq!(paid.subscription.as_deref(), Some("sub_1"));

        let good = json!({ "plan": "msp", "standing": "open", "renews": true, "billed": "by_the_day" });
        assert!(standing(good.clone()).unwrap().is_some());
        // Anything missing, unknown, or that doesn't fit together is no answer.
        for (field, value) in [
            ("plan", json!("enterprise")),
            ("standing", json!("forever")),
            ("standing", json!("until")),
            ("until", json!("tomorrow")),
            ("until", json!("2027-03-01T12:00:00Z")),
            ("renews", Value::Null),
            ("billed", json!("monthly")),
            ("subscription", json!("sub 1")),
            ("extra", json!(1)),
        ] {
            let mut bad = good.clone();
            bad[field] = value.clone();
            assert_eq!(standing(bad), Err(Unreachable), "{field}: {value}");
        }
    }

    #[test]
    fn only_a_loopback_address() {
        assert!(loopback("http://127.0.0.1:8124").is_ok());
        assert!(loopback("http://[::1]:8124").is_ok());
        assert!(loopback("http://localhost:8124").is_err());
        assert!(loopback("http://127.0.0.1.example.com").is_err());
        assert!(loopback("http://[::ffff:127.0.0.1]:8124").is_err());
    }

    fn standin(secrets: &[&str]) -> Standin {
        Standin::new(
            "http://127.0.0.1:1",
            Secret::new("sk_test_x".to_owned()),
            secrets.iter().map(|s| Secret::new((*s).to_owned())).collect(),
        )
        .unwrap()
    }

    fn header(secret: &str, t: i64, body: &[u8]) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
        let mut message = t.to_string().into_bytes();
        message.push(b'.');
        message.extend_from_slice(body);
        format!("t={t},v1={}", data_encoding::HEXLOWER.encode(ring::hmac::sign(&key, &message).as_ref()))
    }

    #[test]
    fn an_event_is_read_only_once_its_signature_checks_out() {
        let p = standin(&["whsec_a"]);
        let now = 1_800_000_000;
        let body = br#"{"id":"evt_1","livemode":false,"customer":"cus_1","type":"anything","data":{"x":1}}"#;
        let event = p.event(Some(&header("whsec_a", now, body)), body, now).unwrap();
        assert_eq!((event.id.as_str(), event.live, event.customer.as_deref()), ("evt_1", false, Some("cus_1")));
        // A wrong secret, before the body is read: even one that isn't JSON.
        assert!(p.event(Some(&header("whsec_b", now, body)), body, now).is_err());
        assert!(
            p.event(Some(&header("whsec_b", now, b"not json")), b"not json", now)
                .unwrap_err()
                .contains("signing secret")
        );
        // A good signature on something that isn't an event.
        assert_eq!(p.event(Some(&header("whsec_a", now, b"[]")), b"[]", now).err(), Some("its body isn't an event"));
        // Ids the server won't keep.
        let odd = br#"{"id":"evt 1","livemode":false,"customer":null}"#;
        assert!(p.event(Some(&header("whsec_a", now, odd)), odd, now).is_err());
        // No customer is an event about nobody.
        let nobody = br#"{"id":"evt_2","livemode":true,"customer":null}"#;
        let event = p.event(Some(&header("whsec_a", now, nobody)), nobody, now).unwrap();
        assert!(event.live && event.customer.is_none());
    }
}

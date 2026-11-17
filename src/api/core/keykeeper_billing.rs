// Keykeeper: the routes of learning who has paid (DESIGN.md, "Plans and
// billing", "Learning who has paid" and "How a plan reaches the clients", in
// the meta repo). They exist only where PLANS_ENFORCED and BILLING_PROVIDER
// are both set (`routes`): everywhere else each is the 404 of a path the
// server doesn't have.
//
// - `POST /api/keykeeper/billing/events/<provider>`: the provider's webhooks.
//   Nobody signs in; the provider's signature is the check, and a webhook
//   only ever causes a look at what the provider says.
// - `POST /api/keykeeper/plan/pay`, `.../manage`, and `.../look`: for whoever
//   may pay for and manage the plan (`PlanNow::can_pay`), and 404 for anyone
//   else, never 403, which would sign the web vault out. None writes a plan:
//   only the provider's answer, which the server fetches itself, does.

use chrono::Utc;
use rocket::{
    Request, Route, State,
    data::{Data, ToByteUnit},
    http::Status,
    request::{FromRequest, Outcome},
    response::{self, Responder, Response},
    serde::json::Json,
};

use super::keykeeper_plans::whose_plan;
use crate::{
    api::{ApiResult, JsonResult},
    auth::{ClientIp, Headers},
    db::{
        DbConn, DbPool,
        models::{
            BillingCustomer, BillingEvent, PlanName, PlanNow, PlanOwner, Terms, UserId, may_manage_plan, plan_at,
        },
    },
    keykeeper_billing::{
        Billing, Looked, Provider, back_to_plan, billing, look, look_for_webhook, manage_page, may_look_now, pay_page,
    },
};

/// The routes, where plans are enforced and a provider is set, and none
/// anywhere else.
pub fn routes() -> Vec<Route> {
    if billing().is_none() {
        return Vec::new();
    }
    routes![billing_event, pay, manage, look_now]
}

/// The most a webhook's body may be: 1 MiB.
const MAX_EVENT_BYTES: usize = 1024 * 1024;

/// A webhook's body, byte for byte, since the signature is over the bytes.
/// None when it's larger than 1 MiB or can't be read.
async fn raw_body(data: Data<'_>) -> Option<Vec<u8>> {
    let read = data.open(MAX_EVENT_BYTES.bytes()).into_bytes().await.ok()?;
    read.is_complete().then(|| read.into_inner())
}

/// The webhook's signature header, whichever the provider names. None when
/// it's missing or sent more than once.
struct Signature(Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Signature {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(billing) = billing() else {
            return Outcome::Success(Self(None));
        };
        let mut values = request.headers().get(billing.provider().signature_header());
        let one = match (values.next(), values.next()) {
            (Some(value), None) => Some(value.to_owned()),
            _ => None,
        };
        Outcome::Success(Self(one))
    }
}

/// What a webhook is answered. A refusal says nothing about why: the reason
/// is only in the server's log, which never has the body.
enum EventAnswer {
    /// 200, with nothing in it: taken, or dropped as a repeat, the other
    /// mode, or about no customer.
    Taken,
    /// 400, with nothing in it.
    Refused,
    /// 503, with nothing in it: the server couldn't record it, so the
    /// provider sends it again later.
    NotNow,
    /// The 404 of a path the server doesn't have.
    NoRoute,
}

impl<'r> Responder<'r, 'static> for EventAnswer {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        match self {
            Self::Taken => Response::build().status(Status::Ok).ok(),
            Self::Refused => Response::build().status(Status::BadRequest).ok(),
            Self::NotNow => Response::build().status(Status::ServiceUnavailable).ok(),
            Self::NoRoute => Err(Status::NotFound),
        }
    }
}

fn refused(why: &str, ip: &ClientIp) -> EventAnswer {
    warn!("A webhook to the billing route was refused: {why}. IP: {}.", ip.ip);
    EventAnswer::Refused
}

/// The provider's webhooks, checked in this order before anything in them is
/// believed: the route is the provider's that's set; the body is read raw, at
/// most 1 MiB; its signature, against each signing secret in use, and its
/// timestamp, within five minutes; its id goes into `billing_events`, and a
/// repeat is dropped; an event for the provider's other mode is dropped. Then
/// it's answered, and only after that does the server ask the provider about
/// the customer it names and write what the provider says.
#[post("/keykeeper/billing/events/<provider>", data = "<body>")]
async fn billing_event(
    provider: &str,
    signature: Signature,
    ip: ClientIp,
    body: Data<'_>,
    pool: &State<DbPool>,
) -> EventAnswer {
    let Some(billing) = billing() else {
        return EventAnswer::NoRoute;
    };
    if provider != billing.name {
        return EventAnswer::NoRoute;
    }
    let Some(body) = raw_body(body).await else {
        return refused("its body is larger than 1 MiB or couldn't be read", &ip);
    };
    let now = Utc::now();
    let event = match billing.provider().event(signature.0.as_deref(), &body, now.timestamp()) {
        Ok(event) => event,
        Err(why) => return refused(why, &ip),
    };
    let same_mode = event.live == billing.provider().live();
    let owed = event.customer.filter(|_| same_mode);
    let Ok(conn) = pool.get().await else {
        error!("A webhook from the payment provider couldn't be recorded, so it'll come again: no database connection");
        return EventAnswer::NotNow;
    };
    match BillingEvent::record(billing.name, &event.id, owed.as_deref(), now.naive_utc(), &conn).await {
        Ok(true) => {}
        Ok(false) => {
            info!("The payment provider sent webhook {} again, and it was dropped.", event.id);
            return EventAnswer::Taken;
        }
        Err(e) => {
            error!("A webhook from the payment provider couldn't be recorded, so it'll come again: {e:#?}");
            return EventAnswer::NotNow;
        }
    }
    if !same_mode {
        info!("Webhook {} was for the payment provider's other mode, and was dropped.", event.id);
        return EventAnswer::Taken;
    }
    if let Some(customer) = owed {
        let pool = pool.inner().clone();
        let event_id = event.id;
        tokio::spawn(async move {
            match pool.get().await {
                Ok(conn) => {
                    // A look that fails is owed still, and the billing job tries it again.
                    look_for_webhook(billing, &customer, &event_id, &conn).await;
                }
                Err(e) => warn!("The look a webhook asked for waits for the billing job: {e:#?}"),
            }
        });
    }
    EventAnswer::Taken
}

/// The one check every payment route makes: whether the person asking may
/// pay for and manage the plan (`PlanNow::can_pay`, which the sync's `canPay`
/// is too), and 404 everywhere else. Who manages a plan is checked before
/// anything about the plan is read.
async fn payable(asker: &UserId, whose: &PlanOwner, conn: &DbConn) -> ApiResult<&'static Billing> {
    if may_manage_plan(asker, whose, conn).await? {
        let plan: PlanNow = plan_at(whose, Some(asker), Utc::now().naive_utc(), conn).await?;
        if let Some(billing) = billing()
            && plan.can_pay(&Terms::from_config())
        {
            return Ok(billing);
        }
    }
    err_code!("Plan not found", Status::NotFound.code)
}

/// Whose plan, as the payment routes take it: `organization` or `msp`, or
/// neither for the person's own, as `GET /api/keykeeper/plan` names them.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WhoseData {
    organization: Option<String>,
    msp: Option<String>,
}

/// Whose plan, and which plan to pay for.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PayData {
    organization: Option<String>,
    msp: Option<String>,
    /// `premium` for a person, `families` or `business` for an organization,
    /// `msp` for an MSP's pool.
    plan: String,
}

/// A page on the provider's site to pay for a plan, or for a pool to put a
/// card on file: `{"url": ...}`.
#[post("/keykeeper/plan/pay", data = "<data>")]
async fn pay(data: Json<PayData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data = data.into_inner();
    let whose = whose_plan(&headers.user.uuid, data.organization, data.msp)?;
    let billing = payable(&headers.user.uuid, &whose, &conn).await?;
    let Some(plan) = PlanName::parse(&data.plan).filter(|plan| plan.fits(&whose)) else {
        err!(
            "Ask to pay for a plan this can have: premium for a person, families or business for an organization, msp for an MSP"
        )
    };
    let url = pay_page(billing, &whose, plan, &back_to_plan(&whose), &conn).await?;
    Ok(Json(json!({ "url": url })))
}

/// A page on the provider's site to manage the plan: its card, past
/// invoices, and canceling. `{"url": ...}`.
#[post("/keykeeper/plan/manage", data = "<data>")]
async fn manage(data: Json<WhoseData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data = data.into_inner();
    let whose = whose_plan(&headers.user.uuid, data.organization, data.msp)?;
    let billing = payable(&headers.user.uuid, &whose, &conn).await?;
    let Some(url) = manage_page(billing, &whose, &back_to_plan(&whose), &conn).await? else {
        err!("Nothing has been paid for this plan yet, so there's nothing to manage.")
    };
    Ok(Json(json!({ "url": url })))
}

/// Asks the provider about the plan now, for someone back from the
/// provider's page or opening the Plan page, so it shows before the webhook
/// lands: at most once a minute for each plan. Answers the plan as it then
/// stands, as `GET /api/keykeeper/plan` does, whether the provider was asked
/// or answered.
#[post("/keykeeper/plan/look", data = "<data>")]
async fn look_now(data: Json<WhoseData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data = data.into_inner();
    let asker = &headers.user.uuid;
    let whose = whose_plan(asker, data.organization, data.msp)?;
    let billing = payable(asker, &whose, &conn).await?;
    if may_look_now(&whose)
        && let Some(customer) = BillingCustomer::of(billing.name, &whose, &conn).await?
        && look(billing, &whose, &customer, &conn).await == Looked::Failed
    {
        info!("The plan of {whose} was asked about, and the payment provider couldn't be reached.");
    }
    let plan = plan_at(&whose, Some(asker), Utc::now().naive_utc(), &conn).await?;
    Ok(Json(plan.to_json(&Terms::from_config())))
}

#[cfg(test)]
mod tests {
    use rocket::local::asynchronous::Client;

    use super::*;

    #[post("/", data = "<data>")]
    async fn read(data: Data<'_>) -> String {
        raw_body(data).await.map_or_else(|| "refused".to_owned(), |body| body.len().to_string())
    }

    /// A body is read whole up to 1 MiB, and refused past it, whatever the
    /// request says its length is.
    #[rocket::async_test]
    async fn a_body_up_to_one_mib() {
        let client = Client::tracked(rocket::build().mount("/", routes![read])).await.unwrap();
        for (size, answer) in [
            (0, "0".to_owned()),
            (1000, "1000".to_owned()),
            (MAX_EVENT_BYTES, MAX_EVENT_BYTES.to_string()),
            (MAX_EVENT_BYTES + 1, "refused".to_owned()),
            (5 * MAX_EVENT_BYTES, "refused".to_owned()),
        ] {
            let response = client.post("/").body(vec![b'x'; size]).dispatch().await;
            assert_eq!(response.into_string().await.as_deref(), Some(answer.as_str()), "{size} bytes");
        }
        // A length header that understates the body changes nothing.
        let response = client
            .post("/")
            .header(rocket::http::Header::new("Content-Length", "10"))
            .body(vec![b'x'; MAX_EVENT_BYTES + 1])
            .dispatch()
            .await;
        assert_eq!(response.into_string().await.as_deref(), Some("refused"));
    }
}

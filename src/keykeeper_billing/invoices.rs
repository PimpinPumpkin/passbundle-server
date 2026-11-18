// Keykeeper: billing by the day, after each month (DESIGN.md, "Plans and
// billing", "Learning who has paid", in the meta repo), for an MSP's pool and
// for a Business organization with no MSP (decision 8).
//
// - Prices: a seat's price at each pool size where it changes, from the
//   hosted server's environment (`BILLING_SEAT_PRICES_MSP`,
//   `BILLING_SEAT_PRICES_BUSINESS`), never in the code. Which price a month
//   gets is decision 9 (`SeatPrices::price_for`): the month's prorated seats,
//   rounded up to whole seats, pick the tier, and every prorated seat is
//   billed at that tier's price. Monthly prices only: commitments wait until
//   after launch (decision 10).
// - The month job (BILLING_INVOICE_SCHEDULE): after each month ends, for each
//   plan billed by the day whose card the provider has had, the month's
//   figures from the same readings and the same arithmetic as the seat report
//   (`month_to_invoice` in keykeeper_msp_seats.rs), one `plan_invoices` row
//   written first, then the provider asked (call 3), then the row completed
//   with the provider's id. One invoice for each plan and month, ever: a crash
//   or a rerun at any step finds the row, sends what it says, with the same
//   key, and never makes a second.
//
// All of it only where PLANS_ENFORCED and BILLING_PROVIDER are both set and
// BILLING_INVOICE_SCHEDULE isn't blank (`super::by_the_day`).

use chrono::{NaiveDate, NaiveDateTime, Utc};

use super::{InvoiceLine, Provider, Unreachable, plain_id};
use crate::{
    api::core::keykeeper_msp_seats::{
        DayReading, InvoiceFigures, day_text, first_of_month, month_text, month_to_invoice, next_month, parse_month,
    },
    db::{
        DbConn, DbPool,
        models::{
            BillingCustomer, ClientSeats, OrgSeats, Plan, PlanInvoice, PlanName, PlanOwner, plans_billed_by_the_day,
        },
    },
};

/// What every invoice is in. Other currencies aren't built yet.
pub const CURRENCY: &str = "usd";

/// The settings that hold a seat's prices.
pub const MSP_PRICES: &str = "BILLING_SEAT_PRICES_MSP";
pub const BUSINESS_PRICES: &str = "BILLING_SEAT_PRICES_BUSINESS";

/// The most tiers a price setting may have, and the most a seat may cost a
/// month, in cents: far past anything the site sells, to catch a typo.
const MAX_TIERS: usize = 20;
const MAX_SEAT_CENTS: i64 = 100_000;

/// A seat's price a month at each pool size where it changes, in cents:
/// `(from, cents)`, the first from 1, each from more seats than the last.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeatPrices(Vec<(i64, i64)>);

/// A price as the settings write it: dollars, with up to two decimals.
fn parse_cents(text: &str) -> Option<i64> {
    let (dollars, cents) = text.split_once('.').unwrap_or((text, ""));
    if dollars.is_empty()
        || dollars.len() > 4
        || cents.len() > 2
        || !dollars.bytes().all(|b| b.is_ascii_digit())
        || !cents.bytes().all(|b| b.is_ascii_digit())
        || (text.contains('.') && cents.is_empty())
    {
        return None;
    }
    let cents = format!("{cents:0<2}");
    Some(dollars.parse::<i64>().ok()? * 100 + cents.parse::<i64>().ok()?)
}

impl SeatPrices {
    /// From a setting such as `1:1.50, 500:1.25, 2500:1.00`: from 1 seat, $1.50
    /// a seat; from 500, $1.25; from 2,500, $1.00. The problem names the
    /// setting and never holds its value.
    pub fn parse(setting: &'static str, text: &str) -> Result<Self, String> {
        let problem = || {
            format!(
                "`{setting}` is a seat's price a month at each pool size where it changes, such as 1:1.50,500:1.25,2500:1.00: the first from 1 seat, each from more seats than the last, each price in dollars and cents above 0"
            )
        };
        let mut tiers: Vec<(i64, i64)> = Vec::new();
        for part in text.split(',') {
            let (from, price) = part.trim().split_once(':').ok_or_else(problem)?;
            let from = from.trim();
            if from.is_empty() || from.len() > 9 || !from.bytes().all(|b| b.is_ascii_digit()) {
                return Err(problem());
            }
            let from: i64 = from.parse().map_err(|_| problem())?;
            let cents = parse_cents(price.trim()).ok_or_else(problem)?;
            let follows = tiers.last().map_or(from == 1, |(last, _)| from > *last);
            if !follows || cents <= 0 || cents > MAX_SEAT_CENTS {
                return Err(problem());
            }
            tiers.push((from, cents));
        }
        if tiers.is_empty() || tiers.len() > MAX_TIERS {
            return Err(problem());
        }
        Ok(Self(tiers))
    }

    /// Decision 9: the price a seat for a month whose prorated seats come to
    /// `prorated` hundredths. The prorated total, rounded up to whole seats,
    /// picks the tier; a month of less than one seat is in the first.
    pub fn price_for(&self, prorated: i64) -> i64 {
        let whole = prorated.saturating_add(99).div_euclid(100).max(1);
        self.0.iter().take_while(|(from, _)| *from <= whole).last().map_or(self.0[0].1, |(_, cents)| *cents)
    }
}

/// Every prorated seat at the tier's price: `prorated` hundredths of a seat
/// times `price` cents, to the cent, rounded half up. None if it's too much
/// to be a real month.
pub fn amount_cents(prorated: i64, price: i64) -> Option<i64> {
    prorated.checked_mul(price)?.checked_add(50).map(|sum| sum.div_euclid(100))
}

/// The prices for billing by the day, read at start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByTheDay {
    pub msp: SeatPrices,
    pub business: SeatPrices,
}

impl ByTheDay {
    /// Both settings, each needed.
    pub fn from_env(env: &dyn Fn(&'static str) -> Option<String>) -> Result<Self, String> {
        let read = |setting: &'static str| {
            let text = env(setting).unwrap_or_default();
            if text.trim().is_empty() {
                return Err(format!(
                    "Billing by the day (`BILLING_INVOICE_SCHEDULE`) needs `{setting}` in the environment, a seat's price a month at each pool size where it changes, such as 1:1.50,500:1.25,2500:1.00; or set `BILLING_INVOICE_SCHEDULE` blank to leave Business and MSPs' pools unbilled"
                ));
            }
            SeatPrices::parse(setting, &text)
        };
        Ok(Self {
            msp: read(MSP_PRICES)?,
            business: read(BUSINESS_PRICES)?,
        })
    }

    fn prices(&self, plan: PlanName) -> Option<&SeatPrices> {
        match plan {
            PlanName::Msp => Some(&self.msp),
            PlanName::Business => Some(&self.business),
            PlanName::Premium | PlanName::Families => None,
        }
    }
}

/// The month before the one `day` is in, as `YYYY-MM`: the month that has
/// just ended.
pub fn month_before(day: NaiveDate) -> String {
    let first = first_of_month(day);
    month_text(first.pred_opt().map_or(first, first_of_month))
}

/// A month's first and last seconds, as the provider takes a period (Unix
/// seconds, both inclusive).
pub fn month_period(month: &str) -> Option<(i64, i64)> {
    let first = parse_month(month)?;
    let start = first.and_hms_opt(0, 0, 0)?.and_utc().timestamp();
    let end = next_month(first).and_hms_opt(0, 0, 0)?.and_utc().timestamp() - 1;
    Some((start, end))
}

/// `$1.50`.
fn dollars(cents: i64) -> String {
    format!("${}.{:02}", cents / 100, cents % 100)
}

/// `November 2026`.
fn month_in_words(month: &str) -> String {
    parse_month(month).map_or_else(|| month.to_owned(), |first| first.format("%B %Y").to_string())
}

/// The invoice's one line, as the person paying reads it: the plan and the
/// month, the seat-days, the days in the month, the prorated seats to two
/// decimals, and the price a seat.
pub fn description(invoice: &PlanInvoice) -> String {
    let plan = if invoice.plan == PlanName::Msp.as_str() {
        "MSP seat pool"
    } else {
        "Business"
    };
    let free = match invoice.free_days {
        0 => String::new(),
        1 => " (its first day free)".to_owned(),
        days => format!(" (its first {days} days free)"),
    };
    format!(
        "{plan}, {}: {} seat-days over the month's {} days{free}, {}.{:02} seats at {} a seat",
        month_in_words(&invoice.month),
        invoice.seat_days,
        invoice.days_in_month,
        invoice.prorated / 100,
        invoice.prorated % 100,
        dollars(invoice.price_cents),
    )
}

/// What the month job came to for one plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invoiced {
    /// The provider has no customer for it: nobody to invoice.
    NoCustomer,
    /// The month had no seat-days to bill.
    Nothing,
    /// The provider has the month's invoice: made now, or before.
    Sent,
    /// The provider couldn't be asked, or the row couldn't be read or
    /// written. The row, if it was written, stays, and the next run sends it.
    Failed,
}

/// The readings a plan's month is worked out from: an MSP's clients', or an
/// organization's own.
async fn readings(whose: &PlanOwner, month: &str, conn: &DbConn) -> crate::api::ApiResult<Vec<DayReading>> {
    let Some(first) = parse_month(month) else {
        return Ok(Vec::new());
    };
    let (from, until) = (day_text(first), day_text(next_month(first)));
    Ok(match whose {
        PlanOwner::Msp(id) => {
            ClientSeats::find_between(id, &from, &until, conn).await?.iter().map(DayReading::from).collect()
        }
        PlanOwner::Organization(id) => {
            OrgSeats::find_between(id, &from, &until, conn).await?.iter().map(DayReading::from).collect()
        }
        PlanOwner::User(_) => Vec::new(),
    })
}

/// Asks the provider for the invoice a row says, with the row's own key, and
/// completes the row with the provider's id.
async fn send<P: Provider>(provider: &P, invoice: &PlanInvoice, now: NaiveDateTime, conn: &DbConn) -> Invoiced {
    let line = InvoiceLine {
        description: description(invoice),
        amount_cents: invoice.amount_cents,
    };
    let whose = invoice.whose().map_or_else(|| "nobody".to_owned(), |whose| whose.to_string());
    match provider.invoice(&invoice.provider_customer, &invoice.month, &[line], &invoice.key()).await {
        Ok(id) if plain_id(&id) => match invoice.complete(&id, now, conn).await {
            Ok(_) => {
                info!("The payment provider has the {} invoice of {whose}.", invoice.month);
                Invoiced::Sent
            }
            Err(e) => {
                error!(
                    "The payment provider made the {} invoice of {whose}, and it couldn't be noted. It'll be asked again with the same key, which finds it: {e:#?}",
                    invoice.month
                );
                Invoiced::Failed
            }
        },
        Ok(_) => {
            error!("The payment provider's id for the {} invoice of {whose} couldn't be kept.", invoice.month);
            Invoiced::Failed
        }
        Err(Unreachable) => {
            warn!(
                "The payment provider couldn't be asked for the {} invoice of {whose}. It's written down, and the next run sends it.",
                invoice.month
            );
            Invoiced::Failed
        }
    }
}

/// The month job for one plan billed by the day: first any month of its the
/// provider doesn't have yet, oldest first, then `month` (`YYYY-MM`, one that
/// has ended), worked out from the readings and the row's free days, written,
/// sent, and completed. Every step can be run again: the row is found, its
/// figures are sent as they were written, and the key is the same.
pub async fn invoice_plan<P: Provider>(
    provider_name: &str,
    provider: &P,
    prices: &ByTheDay,
    plan: &Plan,
    month: &str,
    now: NaiveDateTime,
    conn: &DbConn,
) -> Invoiced {
    let (whose, name) = match (&plan.org_uuid, &plan.msp_uuid, plan.name()) {
        (Some(org), None, Some(PlanName::Business)) => (PlanOwner::Organization(org.clone()), PlanName::Business),
        (None, Some(msp), Some(PlanName::Msp)) => (PlanOwner::Msp(msp.clone()), PlanName::Msp),
        _ => return Invoiced::Nothing,
    };
    let customer = match BillingCustomer::of(provider_name, &whose, conn).await {
        Ok(Some(customer)) => customer,
        Ok(None) => return Invoiced::NoCustomer,
        Err(e) => {
            error!("Couldn't find the payment provider's customer for {whose}: {e:#?}");
            return Invoiced::Failed;
        }
    };

    // A month written down and never sent goes first, so the provider gets
    // them in order.
    match PlanInvoice::unsent(&whose, conn).await {
        Ok(unsent) => {
            for invoice in unsent {
                if send(provider, &invoice, now, conn).await != Invoiced::Sent {
                    return Invoiced::Failed;
                }
            }
        }
        Err(e) => {
            error!("Couldn't load the invoices of {whose} still to send: {e:#?}");
            return Invoiced::Failed;
        }
    }
    match PlanInvoice::find(&whose, month, conn).await {
        Ok(Some(_)) => return Invoiced::Sent,
        Ok(None) => {}
        Err(e) => {
            error!("Couldn't load the {month} invoice of {whose}: {e:#?}");
            return Invoiced::Failed;
        }
    }

    let readings = match readings(&whose, month, conn).await {
        Ok(readings) => readings,
        Err(e) => {
            error!("Couldn't load the seats of {whose} for {month}: {e:#?}");
            return Invoiced::Failed;
        }
    };
    let Some(InvoiceFigures {
        days_in_month,
        seat_days,
        free_days,
        prorated,
    }) = month_to_invoice(month, &readings, plan.free_until)
    else {
        return Invoiced::Nothing;
    };
    if seat_days <= 0 {
        return Invoiced::Nothing;
    }
    let Some(price) = prices.prices(name).map(|prices| prices.price_for(prorated)) else {
        return Invoiced::Nothing;
    };
    let Some(amount) = amount_cents(prorated, price) else {
        error!("The {month} invoice of {whose} comes to more than the server can bill, so it wasn't sent.");
        return Invoiced::Failed;
    };
    let (org_uuid, msp_uuid) = match &whose {
        PlanOwner::Organization(id) => (Some(id.clone()), None),
        PlanOwner::Msp(id) => (None, Some(id.clone())),
        PlanOwner::User(_) => return Invoiced::Nothing,
    };
    let row = PlanInvoice {
        uuid: crate::util::get_uuid(),
        org_uuid,
        msp_uuid,
        month: month.to_owned(),
        plan: name.as_str().to_owned(),
        seat_days,
        free_days: i32::try_from(free_days).unwrap_or(0),
        days_in_month: i32::try_from(days_in_month).unwrap_or(0),
        prorated,
        price_cents: price,
        amount_cents: amount,
        currency: CURRENCY.to_owned(),
        provider: provider_name.to_owned(),
        provider_customer: customer,
        provider_invoice: None,
        created_at: now,
        sent_at: None,
    };
    // Written before the provider is asked: from here on, every run sends
    // this row and nothing else for the month.
    let row = match PlanInvoice::write_once(row, conn).await {
        Ok(row) => row,
        Err(e) => {
            error!("The {month} invoice of {whose} couldn't be written down, so it wasn't sent: {e:#?}");
            return Invoiced::Failed;
        }
    };
    if row.sent() {
        return Invoiced::Sent;
    }
    send(provider, &row, now, conn).await
}

/// One run of the month job at a time: a run that's still going when the
/// next is due lets it pass.
static INVOICING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The month job (BILLING_INVOICE_SCHEDULE): the month that has just ended,
/// for every plan billed by the day. A plan the provider couldn't be asked
/// about is tried again on the next run, and the operator is told in the log.
pub async fn invoice_month_job(pool: DbPool) {
    let Some((billing, prices)) = super::by_the_day() else {
        return;
    };
    let Ok(_one) = INVOICING.try_lock() else {
        return;
    };
    let Ok(conn) = pool.get().await else {
        error!("Failed to get DB connection while invoicing the month");
        return;
    };
    let now = Utc::now().naive_utc();
    let month = month_before(now.date());
    let plans = match plans_billed_by_the_day(billing.name, &conn).await {
        Ok(plans) => plans,
        Err(e) => {
            error!("Couldn't load the plans billed by the day: {e:#?}");
            return;
        }
    };
    let mut failed = 0_usize;
    for plan in &plans {
        if invoice_plan(billing.name, billing.provider(), prices, plan, &month, now, &conn).await == Invoiced::Failed {
            failed += 1;
        }
    }
    if failed > 0 {
        error!(
            "{failed} plan(s) billed by the day couldn't be invoiced for {month} through the payment provider `{}`. What was worked out is kept, and the next run of BILLING_INVOICE_SCHEDULE sends it.",
            billing.name
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use super::*;
    use crate::{
        db::models::{
            Billed, FreeWhy, Membership, MembershipStatus, Msp, MspClient, Organization, PlanWrite, ProviderAnswer,
            SetBy, Standing, User, write_provider_answer,
        },
        keykeeper_billing::{Event, PayPage},
    };

    fn prices(text: &str) -> SeatPrices {
        SeatPrices::parse("BILLING_SEAT_PRICES_MSP", text).unwrap()
    }

    #[test]
    fn seat_prices_are_read_from_one_setting_or_the_server_doesnt_start() {
        assert_eq!(prices("1:1.50,500:1.25,2500:1.00"), SeatPrices(vec![(1, 150), (500, 125), (2500, 100)]));
        assert_eq!(prices(" 1 : 2 , 250 : 1.75 "), SeatPrices(vec![(1, 200), (250, 175)]));
        assert_eq!(prices("1:0.85"), SeatPrices(vec![(1, 85)]));
        assert_eq!(prices("1:1.5"), SeatPrices(vec![(1, 150)]));
        for bad in [
            "",
            "1.50",
            "2:1.50",
            "0:1.50",
            "1:1.50,500:1.25,500:1.00",
            "1:1.50,500:1.25,400:1.00",
            "1:0",
            "1:0.00",
            "1:-1",
            "1:1.505",
            "1:1.",
            "1:.50",
            "1:$1.50",
            "1:1,50",
            "1:1.50;500:1.25",
            "1:1000.01",
            "one:1.50",
            "1:1.50,",
            "1:1.50,2,500:1.00",
        ] {
            let problem = SeatPrices::parse("BILLING_SEAT_PRICES_MSP", bad).unwrap_err();
            assert!(problem.contains("BILLING_SEAT_PRICES_MSP"), "{bad}: {problem}");
            // The same sentence whatever was set, so it never says the value back.
            assert_eq!(problem, SeatPrices::parse("BILLING_SEAT_PRICES_MSP", "x").unwrap_err(), "{bad}");
        }
        let many: Vec<String> = (0..21).map(|i| format!("{}:1.00", i * 10 + 1)).collect();
        assert!(SeatPrices::parse("BILLING_SEAT_PRICES_MSP", &many.join(",")).is_err());
    }

    #[test]
    fn both_settings_are_needed() {
        let env = |values: &'static [(&'static str, &'static str)]| {
            move |name: &'static str| values.iter().find(|(n, _)| *n == name).map(|(_, v)| (*v).to_owned())
        };
        let both = ByTheDay::from_env(&env(&[
            ("BILLING_SEAT_PRICES_MSP", "1:1.50,500:1.25,2500:1.00"),
            ("BILLING_SEAT_PRICES_BUSINESS", "1:2.00,250:1.75"),
        ]))
        .unwrap();
        assert_eq!(both.business, SeatPrices(vec![(1, 200), (250, 175)]));
        let missing = ByTheDay::from_env(&env(&[("BILLING_SEAT_PRICES_MSP", "1:1.50")])).unwrap_err();
        assert!(missing.contains("BILLING_SEAT_PRICES_BUSINESS") && missing.contains("BILLING_INVOICE_SCHEDULE"));
        let empty =
            ByTheDay::from_env(&env(&[("BILLING_SEAT_PRICES_MSP", " "), ("BILLING_SEAT_PRICES_BUSINESS", "1:2.00")]))
                .unwrap_err();
        assert!(empty.contains("BILLING_SEAT_PRICES_MSP"));
    }

    /// Decision 9 at its steps: the prorated total, rounded up to whole
    /// seats, picks the tier, and every prorated seat is billed at it, so 499
    /// seats cost more than 500.
    #[test]
    fn the_price_tiers_at_their_steps() {
        let msp = prices("1:1.50,500:1.25,2500:1.00");
        // 499.00 seats: the first tier.
        assert_eq!(msp.price_for(49_900), 150);
        assert_eq!(amount_cents(49_900, 150), Some(74_850));
        // 499.01 rounds up to 500: the second tier, for every seat.
        assert_eq!(msp.price_for(49_901), 125);
        assert_eq!(amount_cents(49_901, 125), Some(62_376));
        // 500.00: the second tier.
        assert_eq!(msp.price_for(50_000), 125);
        assert_eq!(amount_cents(50_000, 125), Some(62_500));
        assert!(amount_cents(49_900, 150) > amount_cents(50_000, 125));
        // 2,499 and 2,500.
        assert_eq!(msp.price_for(249_900), 125);
        assert_eq!(msp.price_for(249_901), 100);
        assert_eq!(msp.price_for(250_000), 100);
        // Less than a seat, and none, are in the first tier.
        assert_eq!(msp.price_for(1), 150);
        assert_eq!(msp.price_for(0), 150);
        // Business: 249 and 250 people.
        let business = SeatPrices::parse("BILLING_SEAT_PRICES_BUSINESS", "1:2.00,250:1.75").unwrap();
        assert_eq!(business.price_for(24_900), 200);
        assert_eq!(business.price_for(24_901), 175);
        assert_eq!(business.price_for(25_000), 175);
    }

    #[test]
    fn the_amount_is_to_the_cent_rounded_half_up() {
        // 10.37 seats at $1.50: $15.555, so $15.56.
        assert_eq!(amount_cents(1037, 150), Some(1556));
        // 10.37 at $1.25: $12.9625, so $12.96.
        assert_eq!(amount_cents(1037, 125), Some(1296));
        // 0.01 at $0.50: half a cent, so a cent.
        assert_eq!(amount_cents(1, 50), Some(1));
        assert_eq!(amount_cents(1, 49), Some(0));
        assert_eq!(amount_cents(0, 150), Some(0));
        assert_eq!(amount_cents(i64::MAX, 150), None);
    }

    #[test]
    fn the_month_just_ended_and_its_period() {
        let day = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
        assert_eq!(month_before(day(2026, 12, 1)), "2026-11");
        assert_eq!(month_before(day(2026, 12, 31)), "2026-11");
        assert_eq!(month_before(day(2027, 1, 1)), "2026-12");
        assert_eq!(month_before(day(2028, 3, 1)), "2028-02");
        // November 2026: from its first second to its last, both inclusive.
        let (start, end) = month_period("2026-11").unwrap();
        assert_eq!(start, day(2026, 11, 1).and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp());
        assert_eq!(end + 1, day(2026, 12, 1).and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp());
        assert_eq!((end + 1 - start) / 86_400, 30);
        assert_eq!(month_period("2026-13"), None);
    }

    fn invoice(month: &str, free_days: i32) -> PlanInvoice {
        PlanInvoice {
            uuid: "row".to_owned(),
            org_uuid: None,
            msp_uuid: Some("northwind".to_owned().into()),
            month: month.to_owned(),
            plan: "msp".to_owned(),
            seat_days: 311,
            free_days,
            days_in_month: 30,
            prorated: 1037,
            price_cents: 150,
            amount_cents: 1556,
            currency: CURRENCY.to_owned(),
            provider: "standin".to_owned(),
            provider_customer: "cus_1".to_owned(),
            provider_invoice: None,
            created_at: NaiveDate::from_ymd_opt(2026, 12, 1).unwrap().and_hms_opt(0, 35, 0).unwrap(),
            sent_at: None,
        }
    }

    #[test]
    fn the_line_says_what_its_amount_comes_from() {
        assert_eq!(
            description(&invoice("2026-11", 0)),
            "MSP seat pool, November 2026: 311 seat-days over the month's 30 days, 10.37 seats at $1.50 a seat"
        );
        assert_eq!(
            description(&invoice("2026-11", 12)),
            "MSP seat pool, November 2026: 311 seat-days over the month's 30 days (its first 12 days free), 10.37 seats at $1.50 a seat"
        );
        let mut business = invoice("2026-11", 1);
        business.plan = "business".to_owned();
        business.prorated = 7;
        business.price_cents = 200;
        assert_eq!(
            description(&business),
            "Business, November 2026: 311 seat-days over the month's 30 days (its first day free), 0.07 seats at $2.00 a seat"
        );
        // The key is whose plan and the month, the same every time.
        assert_eq!(invoice("2026-11", 0).key(), "passbundle-invoice-msp-northwind-2026-11");
    }

    /// A provider for the month job's tests: it makes an invoice once for
    /// each key, as Stripe's idempotency keys and the adapter's lookups do,
    /// and can fail before making it or after.
    #[derive(Default)]
    struct Fake {
        /// key -> (invoice id, customer, month, amount, description)
        made: Mutex<HashMap<String, (String, String, String, i64, String)>>,
        asked: AtomicUsize,
        /// Fail this many calls before making anything.
        fail_before: AtomicUsize,
        /// Make the invoice, then fail to answer, this many times.
        fail_after: AtomicUsize,
    }

    impl Fake {
        fn made(&self) -> usize {
            self.made.lock().unwrap().len()
        }
    }

    impl Provider for Fake {
        fn live(&self) -> bool {
            false
        }

        fn signature_header(&self) -> &'static str {
            "Fake-Signature"
        }

        fn takes(&self, _plan: PlanName) -> bool {
            true
        }

        async fn pay_page(
            &self,
            _whose: &PlanOwner,
            _plan: PlanName,
            _customer: Option<&str>,
            _back: &str,
        ) -> Result<PayPage, Unreachable> {
            Err(Unreachable)
        }

        async fn manage_page(&self, _customer: &str, _back: &str) -> Result<String, Unreachable> {
            Err(Unreachable)
        }

        async fn invoice(
            &self,
            customer: &str,
            month: &str,
            lines: &[InvoiceLine],
            key: &str,
        ) -> Result<String, Unreachable> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            if self.fail_before.load(Ordering::SeqCst) > 0 {
                self.fail_before.fetch_sub(1, Ordering::SeqCst);
                return Err(Unreachable);
            }
            let id = {
                let mut made = self.made.lock().unwrap();
                let next = made.len() + 1;
                let line = &lines[0];
                made.entry(key.to_owned())
                    .or_insert_with(|| {
                        (
                            format!("in_{next}"),
                            customer.to_owned(),
                            month.to_owned(),
                            line.amount_cents,
                            line.description.clone(),
                        )
                    })
                    .0
                    .clone()
            };
            if self.fail_after.load(Ordering::SeqCst) > 0 {
                self.fail_after.fetch_sub(1, Ordering::SeqCst);
                return Err(Unreachable);
            }
            Ok(id)
        }

        fn event(&self, _signature: Option<&str>, _body: &[u8], _now: i64) -> Result<Event, &'static str> {
            Err("no")
        }

        async fn standing(&self, _customer: &str, _whose: &PlanOwner) -> Result<Option<ProviderAnswer>, Unreachable> {
            Err(Unreachable)
        }

        async fn cancel(&self, _customer: &str) -> Result<usize, Unreachable> {
            Ok(0)
        }
    }

    fn by_the_day() -> ByTheDay {
        ByTheDay {
            msp: prices("1:1.50,500:1.25,2500:1.00"),
            business: SeatPrices::parse("BILLING_SEAT_PRICES_BUSINESS", "1:2.00,250:1.75").unwrap(),
        }
    }

    fn at(month: u32, day: u32, hour: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, month, day).unwrap().and_hms_opt(hour, 0, 0).unwrap()
    }

    async fn msp(conn: &DbConn) -> Msp {
        let msp = Msp::new("Northwind IT".to_owned());
        msp.insert(conn).await.unwrap();
        msp
    }

    /// Makes `org` a client of `msp`, as the plans' tests do: MspClient::new
    /// seals an install token with the server's keys, which tests don't load.
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

    /// An MSP with a client whose seats were read every day of November 2026
    /// (ten seats, eleven from the 20th), whose pool has a card on file at
    /// the stand-in and nothing free after `free_until`.
    async fn pool(conn: &DbConn, free_until: Option<NaiveDateTime>) -> (PlanOwner, Plan) {
        let msp = msp(conn).await;
        let client = Organization::new("Acme".to_owned(), "billing@example.test", None, None);
        client.save(conn).await.unwrap();
        take_on(&msp, &client, conn).await;
        let mut rows = Vec::new();
        for day in 1..=30 {
            rows.push(ClientSeats {
                msp_uuid: msp.uuid.clone(),
                org_uuid: client.uuid.clone(),
                day: format!("2026-11-{day:02}"),
                seats: if day < 20 {
                    10
                } else {
                    11
                },
                org_name: "Acme".to_owned(),
            });
        }
        ClientSeats::record(rows, conn).await.unwrap();
        let whose = PlanOwner::Msp(msp.uuid.clone());
        card_on_file(&whose, PlanName::Msp, free_until, conn).await
    }

    /// The plan an operator gave, and then the provider's word that a card
    /// is on file, as a look writes it.
    async fn card_on_file(
        whose: &PlanOwner,
        plan: PlanName,
        free_until: Option<NaiveDateTime>,
        conn: &DbConn,
    ) -> (PlanOwner, Plan) {
        let write = PlanWrite {
            plan,
            free_until,
            free_why: free_until.map(|_| FreeWhy::Offer),
            standing: Standing::None,
            until: None,
            renews: false,
            billed: Billed::ByTheDay,
        };
        Plan::set(whose, write, SetBy::Operator, conn).await.unwrap();
        assert!(BillingCustomer::record("standin", "cus_1", whose, at(11, 1, 0), conn).await.unwrap());
        let open = ProviderAnswer::new(plan, Standing::Open, None, true, Billed::ByTheDay, None).unwrap();
        write_provider_answer(whose, "standin", "cus_1", Some(&open), at(11, 1, 0), conn).await.unwrap();
        (whose.clone(), Plan::find(whose, conn).await.unwrap().unwrap())
    }

    async fn run(fake: &Fake, plan: &Plan, conn: &DbConn) -> Invoiced {
        invoice_plan("standin", fake, &by_the_day(), plan, "2026-11", at(12, 1, 0), conn).await
    }

    #[rocket::async_test]
    async fn a_month_is_invoiced_once_with_the_seat_reports_figures() {
        let conn = DbPool::for_test().await;
        let (whose, plan) = pool(&conn, None).await;
        let fake = Fake::default();
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Sent);
        let row = PlanInvoice::find(&whose, "2026-11", &conn).await.unwrap().unwrap();
        // 19 × 10 + 11 × 11 = 311 seat-days, 10.37 seats at $1.50: $15.56.
        assert_eq!(
            (row.seat_days, row.free_days, row.days_in_month, row.prorated, row.price_cents, row.amount_cents),
            (311, 0, 30, 1037, 150, 1556)
        );
        assert_eq!((row.provider_invoice.as_deref(), row.provider_customer.as_str()), (Some("in_1"), "cus_1"));
        assert_eq!(row.sent_at, Some(at(12, 1, 0)));
        let made = fake.made.lock().unwrap().get(&row.key()).cloned().unwrap();
        assert_eq!((made.1.as_str(), made.2.as_str(), made.3), ("cus_1", "2026-11", 1556));
        assert_eq!(made.4, description(&row));

        // Run again, and again: nothing more is asked or made.
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Sent);
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Sent);
        assert_eq!((fake.made(), fake.asked.load(Ordering::SeqCst)), (1, 1));
        assert_eq!(PlanInvoice::of(&whose, &conn).await.unwrap().len(), 1);
    }

    #[rocket::async_test]
    async fn free_days_arent_billed_and_the_rest_are_over_all_the_months_days() {
        let conn = DbPool::for_test().await;
        // Free until the 20th at noon: the 1st to the 20th are free.
        let (whose, plan) = pool(&conn, Some(at(11, 20, 12))).await;
        let fake = Fake::default();
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Sent);
        let row = PlanInvoice::find(&whose, "2026-11", &conn).await.unwrap().unwrap();
        // The 21st to the 30th, 10 × 11 = 110 seat-days, over 30 days: 3.67 seats.
        assert_eq!((row.seat_days, row.free_days, row.days_in_month, row.prorated), (110, 20, 30, 367));
        assert_eq!(row.amount_cents, 551);

        // Free through the whole month: nothing to bill, and nothing written.
        let conn = DbPool::for_test().await;
        let (whose, plan) = pool(&conn, Some(at(12, 1, 0))).await;
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Nothing);
        assert_eq!(PlanInvoice::find(&whose, "2026-11", &conn).await.unwrap(), None);
    }

    #[rocket::async_test]
    async fn the_provider_unreachable_before_it_makes_the_invoice_leaves_the_row_and_the_next_run_sends_it() {
        let conn = DbPool::for_test().await;
        let (whose, plan) = pool(&conn, None).await;
        let fake = Fake::default();
        fake.fail_before.store(2, Ordering::SeqCst);
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Failed);
        let row = PlanInvoice::find(&whose, "2026-11", &conn).await.unwrap().unwrap();
        assert!(!row.sent());
        assert_eq!(fake.made(), 0);
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Failed);
        // The seats change after the row was written: the row's figures are what's sent.
        ClientSeats::record(
            vec![ClientSeats {
                msp_uuid: row.msp_uuid.clone().unwrap(),
                org_uuid: ClientSeats::find_between(row.msp_uuid.as_ref().unwrap(), "2026-11-01", "2026-11-02", &conn)
                    .await
                    .unwrap()[0]
                    .org_uuid
                    .clone(),
                day: "2026-11-01".to_owned(),
                seats: 500,
                org_name: "Acme".to_owned(),
            }],
            &conn,
        )
        .await
        .unwrap();
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Sent);
        let sent = PlanInvoice::find(&whose, "2026-11", &conn).await.unwrap().unwrap();
        assert_eq!((sent.uuid, sent.amount_cents, sent.provider_invoice.as_deref()), (row.uuid, 1556, Some("in_1")));
        assert_eq!(fake.made.lock().unwrap().get(&sent_key(&whose)).unwrap().3, 1556);
        assert_eq!((fake.made(), fake.asked.load(Ordering::SeqCst)), (1, 3));
    }

    fn sent_key(whose: &PlanOwner) -> String {
        let mut row = invoice("2026-11", 0);
        row.msp_uuid = match whose {
            PlanOwner::Msp(id) => Some(id.clone()),
            _ => None,
        };
        row.key()
    }

    #[rocket::async_test]
    async fn a_crash_after_the_provider_made_it_finds_the_same_invoice_and_makes_no_second() {
        let conn = DbPool::for_test().await;
        let (whose, plan) = pool(&conn, None).await;
        let fake = Fake::default();
        // The provider made it, and its answer never came back.
        fake.fail_after.store(1, Ordering::SeqCst);
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Failed);
        assert!(!PlanInvoice::find(&whose, "2026-11", &conn).await.unwrap().unwrap().sent());
        assert_eq!(fake.made(), 1);
        // The next run asks with the same key and gets the same invoice.
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Sent);
        let row = PlanInvoice::find(&whose, "2026-11", &conn).await.unwrap().unwrap();
        assert_eq!(row.provider_invoice.as_deref(), Some("in_1"));
        assert_eq!((fake.made(), fake.asked.load(Ordering::SeqCst)), (1, 2));
    }

    #[rocket::async_test]
    async fn a_crash_between_the_row_and_the_provider_sends_the_row_as_written() {
        let conn = DbPool::for_test().await;
        let (whose, plan) = pool(&conn, None).await;
        // A row a run wrote before the server stopped, with figures of its own.
        let mut written = invoice("2026-11", 0);
        written.uuid = crate::util::get_uuid();
        written.msp_uuid = match &whose {
            PlanOwner::Msp(id) => Some(id.clone()),
            _ => None,
        };
        written.amount_cents = 1234;
        let written = PlanInvoice::write_once(written, &conn).await.unwrap();
        // Writing it again, as a second run at the same moment would, finds it.
        let mut again = written.clone();
        again.uuid = crate::util::get_uuid();
        again.amount_cents = 9999;
        assert_eq!(PlanInvoice::write_once(again, &conn).await.unwrap(), written);

        let fake = Fake::default();
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Sent);
        assert_eq!(fake.made.lock().unwrap().get(&written.key()).unwrap().3, 1234);
        assert_eq!(fake.made(), 1);
        let row = PlanInvoice::find(&whose, "2026-11", &conn).await.unwrap().unwrap();
        assert_eq!((row.uuid, row.provider_invoice.as_deref()), (written.uuid, Some("in_1")));
        // Completing it twice keeps the first id.
        let row = PlanInvoice::find(&whose, "2026-11", &conn).await.unwrap().unwrap();
        assert_eq!(
            row.complete("in_other", at(12, 2, 0), &conn).await.unwrap().provider_invoice.as_deref(),
            Some("in_1")
        );
    }

    #[rocket::async_test]
    async fn an_earlier_month_still_to_send_goes_first() {
        let conn = DbPool::for_test().await;
        let (whose, plan) = pool(&conn, None).await;
        let mut october = invoice("2026-10", 0);
        october.uuid = crate::util::get_uuid();
        october.msp_uuid = match &whose {
            PlanOwner::Msp(id) => Some(id.clone()),
            _ => None,
        };
        let october = PlanInvoice::write_once(october, &conn).await.unwrap();
        let fake = Fake::default();
        // October can't be sent: November waits for it.
        fake.fail_before.store(1, Ordering::SeqCst);
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Failed);
        assert_eq!(PlanInvoice::find(&whose, "2026-11", &conn).await.unwrap(), None);
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Sent);
        let sent = PlanInvoice::of(&whose, &conn).await.unwrap();
        assert_eq!(
            sent.iter().map(|row| (row.month.as_str(), row.sent())).collect::<Vec<_>>(),
            vec![("2026-11", true), ("2026-10", true)]
        );
        let made = fake.made.lock().unwrap();
        assert_eq!(made.get(&october.key()).unwrap().0, "in_1");
        assert_eq!(made.len(), 2);
    }

    #[rocket::async_test]
    async fn a_business_with_no_msp_is_billed_from_its_own_readings_and_never_for_days_it_was_a_client() {
        let conn = DbPool::for_test().await;
        let acme = Organization::new("Acme".to_owned(), "billing@example.test", None, None);
        acme.save(&conn).await.unwrap();
        let whose = PlanOwner::Organization(acme.uuid.clone());
        // Its own for the 1st to the 10th, an MSP's client (0 of its own) to the
        // 20th, and its own again after.
        let rows = (1..=30)
            .map(|day| OrgSeats {
                org_uuid: acme.uuid.clone(),
                day: format!("2026-11-{day:02}"),
                seats: if (11..=20).contains(&day) {
                    0
                } else {
                    3
                },
            })
            .collect();
        OrgSeats::record(rows, &conn).await.unwrap();
        let (_, plan) = card_on_file(&whose, PlanName::Business, None, &conn).await;
        let fake = Fake::default();
        assert_eq!(run(&fake, &plan, &conn).await, Invoiced::Sent);
        let row = PlanInvoice::find(&whose, "2026-11", &conn).await.unwrap().unwrap();
        // 20 days of 3 seats: 60 seat-days, 2.00 seats at Business's $2.00.
        assert_eq!((row.plan.as_str(), row.seat_days, row.prorated, row.price_cents), ("business", 60, 200, 200));
        assert_eq!(row.amount_cents, 400);
        assert!(description(&row).starts_with("Business, November 2026: 60 seat-days"));
    }

    #[rocket::async_test]
    async fn no_customer_no_invoice_and_the_seats_job_reads_organizations_billed_on_their_own() {
        let conn = DbPool::for_test().await;
        let msp = msp(&conn).await;
        let whose = PlanOwner::Msp(msp.uuid.clone());
        let write = PlanWrite {
            plan: PlanName::Msp,
            free_until: None,
            free_why: None,
            standing: Standing::Open,
            until: None,
            renews: true,
            billed: Billed::ByTheDay,
        };
        let (_, plan) = Plan::set(&whose, write, SetBy::Operator, &conn).await.unwrap().unwrap();
        assert_eq!(run(&Fake::default(), &plan, &conn).await, Invoiced::NoCustomer);

        // Who the seats job reads: a Business organization with a plan of its
        // own, its seats, and 0 while it's an MSP's client.
        let own = Organization::new("Own".to_owned(), "billing@example.test", None, None);
        own.save(&conn).await.unwrap();
        let mut ana = User::new("ana@example.test", None);
        ana.save(&conn).await.unwrap();
        let mut member = Membership::new(ana.uuid.clone(), own.uuid.clone(), None);
        member.status = MembershipStatus::Confirmed as i32;
        member.save(&conn).await.unwrap();
        let business = |free: NaiveDateTime| PlanWrite {
            plan: PlanName::Business,
            free_until: Some(free),
            free_why: Some(FreeWhy::Trial),
            standing: Standing::None,
            until: None,
            renews: false,
            billed: Billed::ByTheDay,
        };
        Plan::set(&PlanOwner::Organization(own.uuid.clone()), business(at(12, 1, 0)), SetBy::Server, &conn)
            .await
            .unwrap();
        let client = Organization::new("Client".to_owned(), "billing@example.test", None, None);
        client.save(&conn).await.unwrap();
        Plan::set(&PlanOwner::Organization(client.uuid.clone()), business(at(12, 1, 0)), SetBy::Server, &conn)
            .await
            .unwrap();
        take_on(&msp, &client, &conn).await;
        let mut read = crate::db::models::business_orgs_of_their_own(&conn).await.unwrap();
        read.sort_by_key(|(org, _)| org.to_string());
        let mut expected = vec![(own.uuid.clone(), false), (client.uuid.clone(), true)];
        expected.sort_by_key(|(org, _)| org.to_string());
        assert_eq!(read, expected);
        // An organization with no plan of its own, and a family, aren't read.
        assert_eq!(read.len(), 2);
    }
}

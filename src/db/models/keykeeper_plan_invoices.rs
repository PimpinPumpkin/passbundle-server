// Keykeeper: invoices by the day (DESIGN.md, "Plans and billing", "Learning
// who has paid", in the meta repo). Two tables:
//
// - `org_seats`: once a day, beside the MSP clients' readings
//   (`msp_client_seats`), the seats of each organization with a Business plan
//   of its own. While it's an MSP's client its seats are the MSP's, so its own
//   reading that day is 0: on any day an organization's seats are its MSP's
//   or its own, never both.
// - `plan_invoices`: one row for each plan billed by the day and each month,
//   ever. It's written, with the figures the server worked out, before the
//   provider is asked for the invoice, and completed with the provider's id
//   for it after, so a crash or a rerun finds the row and never makes a
//   second invoice.
//
// Only the seats job and `src/keykeeper_billing` call this, and only where
// PLANS_ENFORCED and BILLING_PROVIDER are both set.

use std::collections::HashSet;

use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    api::{ApiResult, EmptyResult},
    db::{
        DbConn,
        keykeeper_schema::{msp_clients, org_seats, plan_invoices, plans},
    },
    error::MapResult,
    util::format_date,
};

use super::{Billed, MspId, OrganizationId, Plan, PlanName, PlanOwner};

/// An organization's own seats on one day (UTC, `YYYY-MM-DD`).
#[derive(Clone, Debug, PartialEq, Eq, Identifiable, Queryable, Insertable)]
#[diesel(table_name = org_seats)]
#[diesel(primary_key(org_uuid, day))]
pub struct OrgSeats {
    pub org_uuid: OrganizationId,
    pub day: String,
    pub seats: i32,
}

impl OrgSeats {
    /// Records a day's readings, each replacing that organization's earlier
    /// reading of the same day, so a day keeps its last reading, as the MSP
    /// clients' readings do.
    pub async fn record(rows: Vec<Self>, conn: &DbConn) -> EmptyResult {
        if rows.is_empty() {
            return Ok(());
        }
        conn.run(move |conn| {
            conn.transaction(|conn| {
                for row in &rows {
                    diesel::delete(
                        org_seats::table
                            .filter(org_seats::org_uuid.eq(&row.org_uuid))
                            .filter(org_seats::day.eq(&row.day)),
                    )
                    .execute(conn)?;
                    diesel::insert_into(org_seats::table).values(row).execute(conn)?;
                }
                Ok::<(), diesel::result::Error>(())
            })
            .map_res("Error recording organizations' seats")
        })
        .await
    }

    /// An organization's readings from `from` up to, not including, `until`
    /// (both days).
    pub async fn find_between(org: &OrganizationId, from: &str, until: &str, conn: &DbConn) -> ApiResult<Vec<Self>> {
        let (from, until) = (from.to_owned(), until.to_owned());
        conn.run(move |conn| {
            org_seats::table
                .filter(org_seats::org_uuid.eq(org))
                .filter(org_seats::day.ge(from))
                .filter(org_seats::day.lt(until))
                .order(org_seats::day.asc())
                .load::<Self>(conn)
                .map_res("Error loading an organization's seats")
        })
        .await
    }
}

/// The organizations the seats job reads each day: each with a Business plan
/// of its own, and whether it's an MSP's client now, when its seats are the
/// MSP's and its own reading is 0.
pub async fn business_orgs_of_their_own(conn: &DbConn) -> ApiResult<Vec<(OrganizationId, bool)>> {
    conn.run(move |conn| {
        let orgs = plans::table
            .filter(plans::plan.eq(PlanName::Business.as_str()))
            .filter(plans::org_uuid.is_not_null())
            .select(plans::org_uuid.assume_not_null())
            .load::<OrganizationId>(conn)?;
        let clients: HashSet<OrganizationId> =
            msp_clients::table.select(msp_clients::org_uuid).load::<OrganizationId>(conn)?.into_iter().collect();
        Ok::<_, diesel::result::Error>(
            orgs.into_iter()
                .map(|org| {
                    let client = clients.contains(&org);
                    (org, client)
                })
                .collect(),
        )
    })
    .await
    .map_res("Error loading the organizations billed on their own")
}

/// The plans billed by the day through `provider`: an MSP's pool, or a
/// Business organization's own plan, billed by the day, which that provider
/// has set at some point (so a card was put on file there). A trial nobody
/// put a card on file for isn't one, and neither is a plan billed by hand.
pub async fn plans_billed_by_the_day(provider: &str, conn: &DbConn) -> ApiResult<Vec<Plan>> {
    let provider = provider.to_owned();
    conn.run(move |conn| {
        plans::table
            .filter(plans::billed.eq(Billed::ByTheDay.as_str()))
            .filter(plans::provider.eq(provider))
            .filter(
                plans::msp_uuid
                    .is_not_null()
                    .and(plans::plan.eq(PlanName::Msp.as_str()))
                    .or(plans::org_uuid.is_not_null().and(plans::plan.eq(PlanName::Business.as_str()))),
            )
            .load::<Plan>(conn)
            .map_res("Error loading the plans billed by the day")
    })
    .await
}

/// One month's invoice for one plan billed by the day: the figures the server
/// worked out, and, once the provider has it, the provider's id for it.
#[derive(Clone, Debug, PartialEq, Eq, Identifiable, Queryable, Insertable)]
#[diesel(table_name = plan_invoices)]
#[diesel(primary_key(uuid))]
pub struct PlanInvoice {
    pub uuid: String,
    pub org_uuid: Option<OrganizationId>,
    pub msp_uuid: Option<MspId>,
    /// `YYYY-MM`, UTC.
    pub month: String,
    /// `msp` or `business`.
    pub plan: String,
    /// The month's seat-days that are billed: days before `free_until` aren't.
    pub seat_days: i64,
    /// How many of the month's days weren't billed.
    pub free_days: i32,
    /// 28 to 31: what the seat-days are divided by, whatever was free.
    pub days_in_month: i32,
    /// Prorated seats in hundredths: seat-days over the days in the month,
    /// rounded half up, as the seat report rounds.
    pub prorated: i64,
    /// The price a seat for the month's tier, in cents.
    pub price_cents: i64,
    /// Prorated seats times the price, to the cent, rounded half up.
    pub amount_cents: i64,
    pub currency: String,
    pub provider: String,
    pub provider_customer: String,
    /// The provider's id for the invoice, once it has answered. Until then the
    /// invoice is still being sent.
    pub provider_invoice: Option<String>,
    pub created_at: NaiveDateTime,
    pub sent_at: Option<NaiveDateTime>,
}

fn owner_filter(whose: &PlanOwner) -> Option<(Option<OrganizationId>, Option<MspId>)> {
    match whose {
        PlanOwner::Organization(id) => Some((Some(id.clone()), None)),
        PlanOwner::Msp(id) => Some((None, Some(id.clone()))),
        PlanOwner::User(_) => None,
    }
}

type Query<T> = Result<T, diesel::result::Error>;

fn rows_of(conn: &mut crate::db::DbConnInner, whose: &PlanOwner) -> Query<Vec<PlanInvoice>> {
    match owner_filter(whose) {
        Some((Some(org), _)) => plan_invoices::table.filter(plan_invoices::org_uuid.eq(org)).load::<PlanInvoice>(conn),
        Some((_, Some(msp))) => plan_invoices::table.filter(plan_invoices::msp_uuid.eq(msp)).load::<PlanInvoice>(conn),
        _ => Ok(Vec::new()),
    }
}

impl PlanInvoice {
    /// Whose plan the invoice is for.
    pub fn whose(&self) -> Option<PlanOwner> {
        match (&self.org_uuid, &self.msp_uuid) {
            (Some(org), None) => Some(PlanOwner::Organization(org.clone())),
            (None, Some(msp)) => Some(PlanOwner::Msp(msp.clone())),
            _ => None,
        }
    }

    /// Whether the provider has it.
    pub fn sent(&self) -> bool {
        self.provider_invoice.is_some()
    }

    /// The key every call to the provider for this invoice is made with, and
    /// written on what it makes: from whose plan it is and the month, the
    /// same each time it's asked, so the provider never makes it twice.
    pub fn key(&self) -> String {
        let whose = match (&self.org_uuid, &self.msp_uuid) {
            (Some(org), _) => format!("organization-{org}"),
            (_, Some(msp)) => format!("msp-{msp}"),
            _ => "nobody".to_owned(),
        };
        format!("passbundle-invoice-{whose}-{}", self.month)
    }

    /// The invoice as the Plan page lists it. Prorated seats are a number
    /// with two decimals, as the seat report has them; money is in cents.
    pub fn to_json(&self) -> Value {
        json!({
            "month": self.month,
            "seatDays": self.seat_days,
            "freeDays": self.free_days,
            "daysInMonth": self.days_in_month,
            "prorated": crate::api::core::keykeeper_msp_seats::hundredths_value(self.prorated),
            "priceCents": self.price_cents,
            "amountCents": self.amount_cents,
            "currency": self.currency,
            "state": if self.sent() { "invoiced" } else { "pending" },
            "sentAt": self.sent_at.map(|at| format_date(&at)),
        })
    }

    /// `whose` invoice for `month`, if there's one.
    pub async fn find(whose: &PlanOwner, month: &str, conn: &DbConn) -> ApiResult<Option<Self>> {
        let month = month.to_owned();
        conn.run(move |conn| {
            rows_of(conn, whose)
                .map(|rows| rows.into_iter().find(|row| row.month == month))
                .map_res("Error loading a month's invoice")
        })
        .await
    }

    /// Every invoice of `whose` plan, the newest month first.
    pub async fn of(whose: &PlanOwner, conn: &DbConn) -> ApiResult<Vec<Self>> {
        conn.run(move |conn| {
            rows_of(conn, whose)
                .map(|mut rows| {
                    rows.sort_by(|a, b| b.month.cmp(&a.month));
                    rows
                })
                .map_res("Error loading a plan's invoices")
        })
        .await
    }

    /// The invoices of `whose` plan the provider doesn't have yet, the oldest
    /// month first.
    pub async fn unsent(whose: &PlanOwner, conn: &DbConn) -> ApiResult<Vec<Self>> {
        let mut rows = Self::of(whose, conn).await?;
        rows.retain(|row| !row.sent());
        rows.reverse();
        Ok(rows)
    }

    /// Writes `row`, unless that plan has a row for that month already, and
    /// answers the row there is then: one invoice for each plan and month,
    /// ever, whatever runs at the same moment.
    pub async fn write_once(row: Self, conn: &DbConn) -> ApiResult<Self> {
        let Some(whose) = row.whose() else {
            err!("An invoice is for an MSP's pool or an organization")
        };
        let month = row.month.clone();
        conn.run(move |conn| {
            let inserted =
                conn.transaction(|conn| diesel::insert_into(plan_invoices::table).values(&row).execute(conn));
            match inserted {
                Ok(_)
                | Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _)) => {}
                Err(e) => return Err(e),
            }
            rows_of(conn, &whose)?.into_iter().find(|found| found.month == month).ok_or(diesel::result::Error::NotFound)
        })
        .await
        .map_res("Error writing a month's invoice")
    }

    /// Completes the row with the provider's id for its invoice, unless it
    /// has one already. Answers the row as it is then.
    pub async fn complete(&self, provider_invoice: &str, at: NaiveDateTime, conn: &DbConn) -> ApiResult<Self> {
        let uuid = self.uuid.clone();
        let provider_invoice = provider_invoice.to_owned();
        conn.run(move |conn| {
            diesel::update(
                plan_invoices::table
                    .filter(plan_invoices::uuid.eq(&uuid))
                    .filter(plan_invoices::provider_invoice.is_null()),
            )
            .set((plan_invoices::provider_invoice.eq(Some(provider_invoice)), plan_invoices::sent_at.eq(Some(at))))
            .execute(conn)?;
            plan_invoices::table.filter(plan_invoices::uuid.eq(&uuid)).first::<Self>(conn)
        })
        .await
        .map_res("Error completing a month's invoice")
    }
}

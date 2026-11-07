// Keykeeper: seats by client, for MSPs that bill each client for its own.
// PassBundle bills an MSP for one pool of seats across all its clients; this
// gives the MSP the per-client breakdown. A seat is a member of a client who
// has joined (accepted or confirmed), isn't revoked, and isn't one of the
// MSP's staff: neither a membership the MSP made nor anyone on its staff now.
// Someone in two clients counts in each.
//
// The server records each client's seats once a day (the MSP_SEATS_SCHEDULE
// job; a reading counts for the UTC day it's taken on, and a later reading
// the same day replaces it), and counts today's live, as a reading taken now.
// For a month, each
// client gets its most seats on any day and its average over the days
// recorded for the MSP that month, a day it wasn't a client counting as none,
// so the column adds up to the total. This month's figures count today as it
// is now. MSP admins only; everyone else gets "not found", never 403, which
// would sign the web vault out. See DESIGN.md, "Seats by client".

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt::Write as _,
};

use chrono::{Datelike, NaiveDate, Utc};
use rocket::{
    Request, Route,
    http::{ContentType, Header, Status},
    response::{self, Responder},
    serde::json::Json,
};
use serde_json::Value;

use crate::{
    api::{ApiResult, EmptyResult},
    auth::Headers,
    db::{
        DbConn, DbPool,
        models::{
            ClientSeats, MembershipId, MspId, MspMembership, MspRole, OrganizationId,
            keykeeper_msp_seats::{all_msps, clients_now, joined_members, staff_users},
        },
    },
    error::Error,
};

use super::keykeeper_msp::staff_member;

pub fn routes() -> Vec<Route> {
    routes![seats]
}

/// A client's seats as they are now.
#[derive(Clone, Debug)]
struct Reading {
    org: OrganizationId,
    name: String,
    seats: i64,
}

/// Each of the MSP's clients now, with its seats. A database error is an
/// error, never a count of none.
async fn read_now(msp_id: &MspId, conn: &DbConn) -> ApiResult<Vec<Reading>> {
    let staff = staff_users(msp_id, conn).await?;
    let ours: HashSet<MembershipId> =
        MspMembership::try_find_by_msp(msp_id, conn).await?.into_iter().map(|m| m.membership_uuid).collect();
    let mut readings = Vec::new();
    for (org, name) in clients_now(msp_id, conn).await? {
        let joined = joined_members(&org, conn).await?;
        let seats = joined.iter().filter(|(member, user)| !ours.contains(member) && !staff.contains(user)).count();
        readings.push(Reading {
            org,
            name,
            seats: i64::try_from(seats).unwrap_or(i64::MAX),
        });
    }
    Ok(readings)
}

/// A day as the table keeps it.
fn day_text(day: NaiveDate) -> String {
    day.format("%Y-%m-%d").to_string()
}

/// A month as the API names it.
fn month_text(first: NaiveDate) -> String {
    first.format("%Y-%m").to_string()
}

fn first_of_month(day: NaiveDate) -> NaiveDate {
    day.with_day(1).unwrap_or(day)
}

fn next_month(first: NaiveDate) -> NaiveDate {
    let (year, month) = if first.month() == 12 {
        (first.year() + 1, 1)
    } else {
        (first.year(), first.month() + 1)
    };
    NaiveDate::from_ymd_opt(year, month, 1).unwrap_or(first)
}

/// `YYYY-MM`, and nothing else.
fn parse_month(text: &str) -> Option<NaiveDate> {
    let bytes = text.as_bytes();
    if bytes.len() != 7 || bytes[4] != b'-' || !bytes.iter().enumerate().all(|(i, b)| i == 4 || b.is_ascii_digit()) {
        return None;
    }
    NaiveDate::from_ymd_opt(text[..4].parse().ok()?, text[5..].parse().ok()?, 1)
}

/// Records every client's seats for one MSP, for today.
async fn record_msp(msp_id: &MspId, day: &str, conn: &DbConn) -> EmptyResult {
    let rows = read_now(msp_id, conn)
        .await?
        .into_iter()
        .map(|r| ClientSeats {
            msp_uuid: msp_id.clone(),
            org_uuid: r.org,
            day: day.to_owned(),
            seats: i32::try_from(r.seats).unwrap_or(i32::MAX),
            org_name: r.name,
        })
        .collect();
    ClientSeats::record(rows, conn).await
}

/// The daily job: records each MSP client's seats for today (UTC).
pub async fn record_client_seats_job(pool: DbPool) {
    debug!("Recording MSP clients' seats");
    let Ok(conn) = pool.get().await else {
        error!("Failed to get DB connection while recording MSP clients' seats");
        return;
    };
    let day = day_text(Utc::now().date_naive());
    let msps = match all_msps(&conn).await {
        Ok(msps) => msps,
        Err(e) => {
            error!("Couldn't record MSP clients' seats: {e:?}");
            return;
        }
    };
    for msp_id in msps {
        if let Err(e) = record_msp(&msp_id, &day, &conn).await {
            error!("Couldn't record the seats of MSP {msp_id}'s clients: {e:?}");
        }
    }
}

/// One client's line for a month.
#[derive(Debug, PartialEq, Eq)]
struct Line {
    id: OrganizationId,
    name: String,
    /// Whether it's a client now.
    current: bool,
    most: i64,
    /// The seats on each day the month counts, added up.
    sum: i64,
    /// This month only, and only for a client now.
    today: Option<i64>,
}

/// A month's seats, by client.
#[derive(Debug, PartialEq, Eq)]
struct Summary {
    /// The days the figures cover: those recorded for the MSP, and today in
    /// this month while it has clients.
    days: i64,
    lines: Vec<Line>,
}

impl Summary {
    fn most(&self) -> i64 {
        self.lines.iter().map(|l| l.most).sum()
    }

    fn sum(&self) -> i64 {
        self.lines.iter().map(|l| l.sum).sum()
    }

    fn today(&self) -> Option<i64> {
        let mut todays = self.lines.iter().filter_map(|l| l.today).peekable();
        todays.peek()?;
        Some(todays.sum())
    }
}

/// An average in tenths, rounded half up: `sum / days`, to one decimal.
fn tenths(sum: i64, days: i64) -> i64 {
    if days <= 0 {
        0
    } else {
        (20 * sum + days) / (2 * days)
    }
}

/// `4.7` for 47 tenths.
fn tenths_text(tenths: i64) -> String {
    format!("{}.{}", tenths / 10, tenths % 10)
}

fn tenths_value(tenths: i64) -> Value {
    // Exact for any count of seats a client has: tenths below 2^53.
    #[expect(clippy::cast_precision_loss, reason = "tenths of a seat count stay far below 2^53")]
    let value = tenths as f64 / 10.0;
    json!(value)
}

/// A month's lines from what the server recorded (`rows`) and the clients
/// now (`now`). `today` is today's date when the month is this month: a
/// client now then counts today as it is now, in place of a reading already
/// taken today, while one that left since keeps that reading.
fn summarize(rows: &[ClientSeats], now: &[Reading], today: Option<&str>) -> Summary {
    struct Client {
        id: OrganizationId,
        name: String,
        name_day: String,
        days: BTreeMap<String, i64>,
    }
    // By the organization's id.
    let mut clients: BTreeMap<String, Client> = BTreeMap::new();
    let mut days: BTreeSet<String> = BTreeSet::new();
    for row in rows {
        days.insert(row.day.clone());
        let client = clients.entry(row.org_uuid.to_string()).or_insert_with(|| Client {
            id: row.org_uuid.clone(),
            name: row.org_name.clone(),
            name_day: row.day.clone(),
            days: BTreeMap::new(),
        });
        if row.day >= client.name_day {
            client.name.clone_from(&row.org_name);
            client.name_day.clone_from(&row.day);
        }
        client.days.insert(row.day.clone(), i64::from(row.seats));
    }
    if let Some(today) = today {
        for reading in now {
            days.insert(today.to_owned());
            let client = clients.entry(reading.org.to_string()).or_insert_with(|| Client {
                id: reading.org.clone(),
                name: reading.name.clone(),
                name_day: today.to_owned(),
                days: BTreeMap::new(),
            });
            client.name.clone_from(&reading.name);
            today.clone_into(&mut client.name_day);
            client.days.insert(today.to_owned(), reading.seats);
        }
    }
    let current: HashSet<&OrganizationId> = now.iter().map(|r| &r.org).collect();
    let mut lines: Vec<Line> = clients
        .into_values()
        .map(|client| {
            let is_current = current.contains(&client.id);
            Line {
                most: client.days.values().copied().max().unwrap_or(0),
                sum: client.days.values().sum(),
                today: today.filter(|_| is_current).and_then(|t| client.days.get(t).copied()),
                current: is_current,
                name: client.name,
                id: client.id,
            }
        })
        .collect();
    lines.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then_with(|| (*a.id).cmp(&*b.id)));
    Summary {
        days: i64::try_from(days.len()).unwrap_or(i64::MAX),
        lines,
    }
}

/// A CSV field: quoted when it must be, and never read as a formula by a
/// spreadsheet (a client's own owners name it, so it could start with `=`).
fn csv_field(text: &str) -> String {
    let text = if text.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{text}")
    } else {
        text.to_owned()
    };
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text
    }
}

/// The month as CSV, with a byte order mark so spreadsheets read names with
/// accents right. Today's column is empty for earlier months.
fn csv(month: &str, summary: &Summary) -> String {
    let days = summary.days;
    let today = |t: Option<i64>| t.map(|n| n.to_string()).unwrap_or_default();
    let mut out = String::from("\u{feff}Month,Client,Most on any day,Average,Today\r\n");
    for line in &summary.lines {
        let _ = write!(
            out,
            "{month},{},{},{},{}\r\n",
            csv_field(&line.name),
            line.most,
            tenths_text(tenths(line.sum, days)),
            today(line.today),
        );
    }
    let _ = write!(
        out,
        "{month},Total,{},{},{}\r\n",
        summary.most(),
        tenths_text(tenths(summary.sum(), days)),
        today(summary.today()),
    );
    out
}

/// A CSV file to download.
struct Csv {
    body: String,
    filename: String,
}

impl<'r> Responder<'r, 'static> for Csv {
    fn respond_to(self, request: &'r Request<'_>) -> response::Result<'static> {
        let mut response = (ContentType::CSV, self.body).respond_to(request)?;
        response.set_header(Header::new("Content-Disposition", format!("attachment; filename=\"{}\"", self.filename)));
        response.set_header(Header::new("Cache-Control", "no-store"));
        Ok(response)
    }
}

#[derive(Responder)]
enum SeatsAnswer {
    Json(Json<Value>),
    Csv(Csv),
}

/// A month's seats by client: each client's most on any day, its average
/// (one decimal), and today's (this month only), with totals, and the months
/// there are figures for. `format=csv` gives the same as a CSV file.
#[get("/keykeeper/msp/<msp_id>/seats?<month>&<format>")]
async fn seats(
    msp_id: MspId,
    month: Option<&str>,
    format: Option<&str>,
    headers: Headers,
    conn: DbConn,
) -> Result<SeatsAnswer, Error> {
    // MSP admins only. Technicians, like anyone off the staff, get "not
    // found": the web vault signs out on 403.
    let caller = staff_member(&msp_id, &headers.user.uuid, &conn).await?;
    if caller.role() != Some(MspRole::Admin) {
        err_code!("MSP not found", Status::NotFound.code)
    }
    let as_csv = match format {
        None | Some("json") => false,
        Some("csv") => true,
        Some(_) => err!("The format is json or csv"),
    };
    let today = Utc::now().date_naive();
    let this_month = first_of_month(today);
    let first = match month.map(parse_month) {
        None => this_month,
        Some(Some(first)) => first,
        Some(None) => err!("Choose a month as YYYY-MM"),
    };
    if first > this_month {
        err!("That month hasn't started yet")
    }
    let is_this_month = first == this_month;

    let rows = ClientSeats::find_between(&msp_id, &day_text(first), &day_text(next_month(first)), &conn).await?;
    let now = read_now(&msp_id, &conn).await?;
    let today_text = day_text(today);
    let summary = summarize(&rows, &now, is_this_month.then_some(today_text.as_str()));
    let month_name = month_text(first);

    if as_csv {
        return Ok(SeatsAnswer::Csv(Csv {
            body: csv(&month_name, &summary),
            filename: format!("seats-{month_name}.csv"),
        }));
    }

    let this_month_text = month_text(this_month);
    let mut months: BTreeSet<String> = ClientSeats::days(&msp_id, &conn)
        .await?
        .iter()
        .filter_map(|day| day.get(..7).map(str::to_owned))
        .filter(|m| *m <= this_month_text)
        .collect();
    months.insert(this_month_text);

    let days = summary.days;
    let clients: Vec<Value> = summary
        .lines
        .iter()
        .map(|line| {
            json!({
                "id": line.id,
                "name": line.name,
                "current": line.current,
                "most": line.most,
                "average": tenths_value(tenths(line.sum, days)),
                "today": line.today,
            })
        })
        .collect();
    Ok(SeatsAnswer::Json(Json(json!({
        "month": month_name,
        "thisMonth": is_this_month,
        "months": months.into_iter().rev().collect::<Vec<_>>(),
        "days": days,
        "clients": clients,
        "totals": {
            "most": summary.most(),
            "average": tenths_value(tenths(summary.sum(), days)),
            "today": if is_this_month { Some(summary.today().unwrap_or(0)) } else { None },
        },
    }))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(org: &str, day: &str, seats: i32, name: &str) -> ClientSeats {
        ClientSeats {
            msp_uuid: MspId::from("msp".to_owned()),
            org_uuid: OrganizationId::from(org.to_owned()),
            day: day.to_owned(),
            seats,
            org_name: name.to_owned(),
        }
    }

    fn now(org: &str, name: &str, seats: i64) -> Reading {
        Reading {
            org: OrganizationId::from(org.to_owned()),
            name: name.to_owned(),
            seats,
        }
    }

    #[test]
    fn averages_round_half_up_to_one_decimal() {
        assert_eq!(tenths(14, 3), 47); // 4.666…
        assert_eq!(tenths(2, 3), 7); // 0.666…
        assert_eq!(tenths(1, 4), 3); // 0.25
        assert_eq!(tenths(12, 3), 40);
        assert_eq!(tenths(5, 0), 0);
        assert_eq!(tenths_text(47), "4.7");
        assert_eq!(tenths_text(40), "4.0");
        assert_eq!(tenths_text(3), "0.3");
        assert_eq!(tenths_value(47), json!(4.7));
    }

    #[test]
    fn a_past_month_has_each_clients_most_and_average_over_the_msps_days() {
        let rows = [
            row("a", "2026-10-01", 3, "Acme"),
            row("a", "2026-10-02", 5, "Acme"),
            row("a", "2026-10-03", 4, "Acme Dental"),
            // Left after one day: its other days count as none.
            row("b", "2026-10-01", 2, "Bolt"),
        ];
        let summary = summarize(&rows, &[now("a", "Acme Dental Group", 9)], None);
        assert_eq!(summary.days, 3);
        assert_eq!(
            summary.lines,
            vec![
                Line {
                    id: OrganizationId::from("a".to_owned()),
                    // The name on its last day that month, not today's.
                    name: "Acme Dental".to_owned(),
                    current: true,
                    most: 5,
                    sum: 12,
                    today: None,
                },
                Line {
                    id: OrganizationId::from("b".to_owned()),
                    name: "Bolt".to_owned(),
                    current: false,
                    most: 2,
                    sum: 2,
                    today: None,
                },
            ]
        );
        assert_eq!(tenths(summary.lines[0].sum, summary.days), 40);
        assert_eq!(tenths(summary.lines[1].sum, summary.days), 7);
        assert_eq!(summary.most(), 7);
        assert_eq!(tenths(summary.sum(), summary.days), 47);
        assert_eq!(summary.today(), None);
    }

    #[test]
    fn this_month_counts_today_as_it_is_now() {
        let rows = [
            row("a", "2026-11-01", 3, "Acme"),
            // Taken earlier today: today counts as it is now instead.
            row("a", "2026-11-02", 1, "Acme"),
            row("gone", "2026-11-01", 4, "Gone Ltd"),
            // Left after this morning's reading, which stays.
            row("gone", "2026-11-02", 5, "Gone Ltd"),
        ];
        let summary = summarize(&rows, &[now("a", "Acme 2", 6), now("new", "New Co", 2)], Some("2026-11-02"));
        assert_eq!(summary.days, 2);
        let names: Vec<_> =
            summary.lines.iter().map(|l| (l.name.as_str(), l.most, l.sum, l.today, l.current)).collect();
        assert_eq!(
            names,
            vec![("Acme 2", 6, 9, Some(6), true), ("Gone Ltd", 5, 9, None, false), ("New Co", 2, 2, Some(2), true)]
        );
        assert_eq!(summary.most(), 13);
        assert_eq!(summary.today(), Some(8));
    }

    #[test]
    fn a_month_with_nothing_has_no_days() {
        let summary = summarize(&[], &[], Some("2026-11-02"));
        assert_eq!(summary.days, 0);
        assert!(summary.lines.is_empty());
        assert_eq!(summary.today(), None);
        assert_eq!(tenths(summary.sum(), summary.days), 0);
    }

    #[test]
    fn months_are_exactly_year_dash_month() {
        assert_eq!(parse_month("2026-11"), NaiveDate::from_ymd_opt(2026, 11, 1));
        assert_eq!(parse_month("2026-01"), NaiveDate::from_ymd_opt(2026, 1, 1));
        for bad in ["2026-13", "2026-00", "2026-1", "2026/11", "26-11", "2026-11-01", "", "２０２６-11", "+026-11"]
        {
            assert_eq!(parse_month(bad), None, "{bad}");
        }
        let december = NaiveDate::from_ymd_opt(2026, 12, 1).unwrap();
        assert_eq!(next_month(december), NaiveDate::from_ymd_opt(2027, 1, 1).unwrap());
        assert_eq!(
            first_of_month(NaiveDate::from_ymd_opt(2026, 11, 30).unwrap()),
            NaiveDate::from_ymd_opt(2026, 11, 1).unwrap()
        );
    }

    #[test]
    fn csv_fields_are_quoted_and_never_formulas() {
        assert_eq!(csv_field("Acme Dental"), "Acme Dental");
        assert_eq!(csv_field("Smith, Jones & Co"), "\"Smith, Jones & Co\"");
        assert_eq!(csv_field("The \"Best\" Bakery"), "\"The \"\"Best\"\" Bakery\"");
        assert_eq!(csv_field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_field("+1 Plumbing"), "'+1 Plumbing");
        assert_eq!(csv_field("-dash"), "'-dash");
        assert_eq!(csv_field("@home"), "'@home");
        assert_eq!(csv_field("Line\nbreak"), "\"Line\nbreak\"");
        assert_eq!(csv_field("Café Rio"), "Café Rio");
    }

    #[test]
    fn the_csv_has_a_line_per_client_and_the_total() {
        let rows = [
            row("a", "2026-10-01", 3, "Acme"),
            row("a", "2026-10-02", 5, "Acme"),
            row("b", "2026-10-01", 2, "Bolt, Inc"),
        ];
        let summary = summarize(&rows, &[], None);
        assert_eq!(
            csv("2026-10", &summary),
            "\u{feff}Month,Client,Most on any day,Average,Today\r\n\
             2026-10,Acme,5,4.0,\r\n\
             2026-10,\"Bolt, Inc\",2,1.0,\r\n\
             2026-10,Total,7,5.0,\r\n"
        );
        let summary = summarize(&[], &[now("a", "Acme", 3)], Some("2026-11-06"));
        assert_eq!(
            csv("2026-11", &summary),
            "\u{feff}Month,Client,Most on any day,Average,Today\r\n2026-11,Acme,3,3.0,3\r\n2026-11,Total,3,3.0,3\r\n"
        );
    }
}

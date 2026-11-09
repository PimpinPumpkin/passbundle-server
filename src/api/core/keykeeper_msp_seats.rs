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
// Seats are billed by the day: a seat counts for each day it's there at that
// day's reading. For a month (in UTC), each client gets its seat-days (its
// seats on each day, added up), its prorated seats (seat-days divided by the
// days in the month, to two decimals), and its peak (most seats on any day),
// for reference. This month counts through today, as it is now. MSP admins
// only; everyone else gets "not found", never 403, which would sign the web
// vault out. See DESIGN.md, "Seats by client".

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

/// The month's last day.
fn last_of_month(first: NaiveDate) -> NaiveDate {
    next_month(first).pred_opt().unwrap_or(first)
}

/// 28 to 31: what a month's seat-days are divided by.
fn days_in_month(first: NaiveDate) -> i64 {
    (last_of_month(first) - first).num_days() + 1
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
    /// Its seats on each day the month counts, added up: what it's billed on.
    seat_days: i64,
    /// Its most seats on any day, for reference.
    most: i64,
    /// This month only, and only for a client now.
    today: Option<i64>,
}

/// A month's seats, by client.
#[derive(Debug, PartialEq, Eq)]
struct Summary {
    /// 28 to 31: what seat-days are divided by, even while the month runs.
    days_in_month: i64,
    /// The last day counted: today in this month, the month's last day before.
    through: NaiveDate,
    lines: Vec<Line>,
}

impl Summary {
    fn seat_days(&self) -> i64 {
        self.lines.iter().map(|l| l.seat_days).sum()
    }

    fn most(&self) -> i64 {
        self.lines.iter().map(|l| l.most).sum()
    }

    fn today(&self) -> Option<i64> {
        let mut todays = self.lines.iter().filter_map(|l| l.today).peekable();
        todays.peek()?;
        Some(todays.sum())
    }

    /// Prorated seats in hundredths: seat-days over the days in the month.
    fn prorated(&self, seat_days: i64) -> i64 {
        hundredths(seat_days, self.days_in_month)
    }
}

/// `sum / days` in hundredths, rounded half up: to two decimals.
fn hundredths(sum: i64, days: i64) -> i64 {
    if days <= 0 {
        0
    } else {
        (200 * sum + days) / (2 * days)
    }
}

/// `10.37` for 1037 hundredths.
fn hundredths_text(hundredths: i64) -> String {
    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

fn hundredths_value(hundredths: i64) -> Value {
    // The nearest double to two decimals, which JSON writes as those two
    // decimals, for any count of seats a client has.
    #[expect(clippy::cast_precision_loss, reason = "hundredths of seat-days stay far below 2^53")]
    let value = hundredths as f64 / 100.0;
    json!(value)
}

/// Where a day's seats come from.
enum Source {
    /// The day's reading: a client without one wasn't a client that day.
    Reading(String),
    /// No reading that day (the server was down at that time): each client
    /// counts the lower of its readings on the closest days either side.
    Between(String, String),
    /// No reading that day, and none before or after it that month.
    Nothing,
}

/// A month's lines from what the server recorded for the MSP (`rows`) and
/// its clients now (`now`). `today` is today's date when the month is this
/// month: a client now then counts today as it is now, in place of a reading
/// already taken today, while one that left since keeps that reading, and
/// the month counts through today.
fn summarize(first: NaiveDate, rows: &[ClientSeats], now: &[Reading], today: Option<NaiveDate>) -> Summary {
    struct Client {
        id: OrganizationId,
        name: String,
        name_day: String,
        days: BTreeMap<String, i64>,
    }
    let through = today.unwrap_or_else(|| last_of_month(first));
    let (first_text, through_text) = (day_text(first), day_text(through));
    let today_text = today.map(day_text);
    // By the organization's id.
    let mut clients: BTreeMap<String, Client> = BTreeMap::new();
    // The days with a reading. The job reads every client of an MSP at once,
    // so a day with none was missed, or had no clients. Only a client with
    // readings on both sides counts on it, and it never left in between: a
    // client that leaves its MSP can't be added back (add client always makes
    // a new organization).
    let mut read: BTreeSet<String> = BTreeSet::new();
    for row in rows.iter().filter(|r| r.day >= first_text && r.day <= through_text) {
        read.insert(row.day.clone());
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
    if let Some(today) = &today_text {
        read.insert(today.clone());
        for reading in now {
            let client = clients.entry(reading.org.to_string()).or_insert_with(|| Client {
                id: reading.org.clone(),
                name: reading.name.clone(),
                name_day: today.clone(),
                days: BTreeMap::new(),
            });
            client.name.clone_from(&reading.name);
            client.name_day.clone_from(today);
            client.days.insert(today.clone(), reading.seats);
        }
    }
    let sources: Vec<Source> = first
        .iter_days()
        .take_while(|day| *day <= through)
        .map(|day| {
            let day = day_text(day);
            if read.contains(&day) {
                return Source::Reading(day);
            }
            match (read.range(..day.clone()).next_back(), read.range(day..).next()) {
                (Some(before), Some(after)) => Source::Between(before.clone(), after.clone()),
                _ => Source::Nothing,
            }
        })
        .collect();
    let current: HashSet<&OrganizationId> = now.iter().map(|r| &r.org).collect();
    let mut lines: Vec<Line> = clients
        .into_values()
        .map(|client| {
            let on = |day: &String| client.days.get(day).copied().unwrap_or(0);
            let seat_days = sources
                .iter()
                .map(|source| match source {
                    Source::Reading(day) => on(day),
                    Source::Between(before, after) => on(before).min(on(after)),
                    Source::Nothing => 0,
                })
                .sum();
            let is_current = current.contains(&client.id);
            Line {
                seat_days,
                most: client.days.values().copied().max().unwrap_or(0),
                today: today_text.as_ref().filter(|_| is_current).and_then(|t| client.days.get(t).copied()),
                current: is_current,
                name: client.name,
                id: client.id,
            }
        })
        .collect();
    lines.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then_with(|| (*a.id).cmp(&*b.id)));
    Summary {
        days_in_month: days_in_month(first),
        through,
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
/// accents right. Each line has what its prorated seats come from (seat-days
/// and the days in the month) and the last day counted, so a file saved
/// partway through a month says so. Today's column is empty for earlier
/// months.
fn csv(month: &str, summary: &Summary) -> String {
    let through = day_text(summary.through);
    let days = summary.days_in_month;
    let today = |t: Option<i64>| t.map(|n| n.to_string()).unwrap_or_default();
    let mut out = String::from("\u{feff}Month,Through,Client,Seat-days,Days in month,Prorated seats,Peak,Today\r\n");
    for line in &summary.lines {
        let _ = write!(
            out,
            "{month},{through},{},{},{days},{},{},{}\r\n",
            csv_field(&line.name),
            line.seat_days,
            hundredths_text(summary.prorated(line.seat_days)),
            line.most,
            today(line.today),
        );
    }
    let _ = write!(
        out,
        "{month},{through},Total,{},{days},{},{},{}\r\n",
        summary.seat_days(),
        hundredths_text(summary.prorated(summary.seat_days())),
        summary.most(),
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

/// A month's seats by client: each client's seat-days, its prorated seats
/// (seat-days over the days in the month, two decimals), its peak (most on
/// any day), and today's (this month only), with totals, and the months
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
    let summary = summarize(first, &rows, &now, is_this_month.then_some(today));
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

    let prorated = |seat_days| hundredths_value(summary.prorated(seat_days));
    let clients: Vec<Value> = summary
        .lines
        .iter()
        .map(|line| {
            json!({
                "id": line.id,
                "name": line.name,
                "current": line.current,
                "seatDays": line.seat_days,
                "prorated": prorated(line.seat_days),
                "most": line.most,
                "today": line.today,
            })
        })
        .collect();
    Ok(SeatsAnswer::Json(Json(json!({
        "month": month_name,
        "thisMonth": is_this_month,
        "months": months.into_iter().rev().collect::<Vec<_>>(),
        "daysInMonth": summary.days_in_month,
        "through": day_text(summary.through),
        "clients": clients,
        "totals": {
            "seatDays": summary.seat_days(),
            "prorated": prorated(summary.seat_days()),
            "most": summary.most(),
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

    /// A client's readings on days `from` to `to` of `month` (`YYYY-MM`).
    fn readings(org: &str, month: &str, from: u32, to: u32, seats: i32, name: &str) -> Vec<ClientSeats> {
        (from..=to).map(|d| row(org, &format!("{month}-{d:02}"), seats, name)).collect()
    }

    fn now(org: &str, name: &str, seats: i64) -> Reading {
        Reading {
            org: OrganizationId::from(org.to_owned()),
            name: name.to_owned(),
            seats,
        }
    }

    fn month(text: &str) -> NaiveDate {
        parse_month(text).unwrap()
    }

    fn day(text: &str) -> NaiveDate {
        NaiveDate::parse_from_str(text, "%Y-%m-%d").unwrap()
    }

    /// A line as the report shows it: name, seat-days, prorated seats, peak,
    /// today, and whether it's a client now.
    type Figures<'a> = (&'a str, i64, String, i64, Option<i64>, bool);

    fn figures(summary: &Summary) -> Vec<Figures<'_>> {
        summary
            .lines
            .iter()
            .map(|l| {
                let prorated = hundredths_text(summary.prorated(l.seat_days));
                (l.name.as_str(), l.seat_days, prorated, l.most, l.today, l.current)
            })
            .collect()
    }

    #[test]
    fn months_have_their_own_number_of_days_and_leap_februaries_29() {
        assert_eq!(days_in_month(month("2026-02")), 28);
        assert_eq!(days_in_month(month("2028-02")), 29);
        assert_eq!(days_in_month(month("2000-02")), 29);
        assert_eq!(days_in_month(month("2100-02")), 28);
        assert_eq!(days_in_month(month("2026-04")), 30);
        assert_eq!(days_in_month(month("2026-11")), 30);
        assert_eq!(days_in_month(month("2026-12")), 31);
        assert_eq!(days_in_month(month("2027-01")), 31);
        assert_eq!(last_of_month(month("2026-12")), day("2026-12-31"));
        assert_eq!(last_of_month(month("2028-02")), day("2028-02-29"));
    }

    #[test]
    fn prorated_seats_round_half_up_to_two_decimals() {
        assert_eq!(hundredths(311, 30), 1037); // 10.366…
        assert_eq!(hundredths(1, 3), 33);
        assert_eq!(hundredths(2, 3), 67);
        assert_eq!(hundredths(1, 8), 13); // 0.125
        assert_eq!(hundredths(60, 30), 200);
        assert_eq!(hundredths(5, 0), 0);
        assert_eq!(hundredths_text(1037), "10.37");
        assert_eq!(hundredths_text(200), "2.00");
        assert_eq!(hundredths_text(7), "0.07");
        assert_eq!(hundredths_value(1037), json!(10.37));
        // JSON never writes more than the two decimals.
        for h in 0..=200_000 {
            let text = hundredths_value(h).to_string();
            assert!(text.split('.').nth(1).is_none_or(|d| d.len() <= 2), "{h}: {text}");
        }
    }

    #[test]
    fn a_seat_added_on_the_20th_of_a_30_day_month_pays_11_30ths() {
        // November 2026: ten seats, and an eleventh from the 20th.
        let mut rows = readings("a", "2026-11", 1, 19, 10, "Acme");
        rows.extend(readings("a", "2026-11", 20, 30, 11, "Acme"));
        let summary = summarize(month("2026-11"), &rows, &[now("a", "Acme", 11)], None);
        assert_eq!(summary.days_in_month, 30);
        assert_eq!(summary.through, day("2026-11-30"));
        // 19 × 10 + 11 × 11 = 311 seat-days: ten seats, and 11/30 of one.
        assert_eq!(figures(&summary), vec![("Acme", 311, "10.37".to_owned(), 11, None, true)]);
    }

    #[test]
    fn a_seat_removed_mid_month_stops_counting_on_its_day_in_a_31_day_month() {
        // December 2026: five seats, one removed on the 16th, before its reading.
        let mut rows = readings("a", "2026-12", 1, 15, 5, "Acme");
        rows.extend(readings("a", "2026-12", 16, 31, 4, "Acme"));
        let summary = summarize(month("2026-12"), &rows, &[], None);
        assert_eq!(summary.days_in_month, 31);
        // 15 × 5 + 16 × 4 = 139 seat-days over 31 days.
        assert_eq!(figures(&summary), vec![("Acme", 139, "4.48".to_owned(), 5, None, false)]);
    }

    #[test]
    fn a_client_added_mid_month_counts_from_its_first_day_in_a_28_day_month() {
        // February 2026: Acme all month, Bolt from the 15th.
        let mut rows = readings("a", "2026-02", 1, 28, 2, "Acme");
        rows.extend(readings("b", "2026-02", 15, 28, 3, "Bolt"));
        let summary = summarize(month("2026-02"), &rows, &[], None);
        assert_eq!(summary.days_in_month, 28);
        assert_eq!(
            figures(&summary),
            vec![("Acme", 56, "2.00".to_owned(), 2, None, false), ("Bolt", 42, "1.50".to_owned(), 3, None, false)]
        );
        assert_eq!(summary.seat_days(), 98);
        assert_eq!(summary.prorated(summary.seat_days()), 350);
        // The peaks added up, for reference.
        assert_eq!(summary.most(), 5);
    }

    #[test]
    fn a_leap_february_divides_by_29() {
        // February 2028: two seats, and a third on the 29th only.
        let mut rows = readings("a", "2028-02", 1, 28, 2, "Acme");
        rows.push(row("a", "2028-02-29", 3, "Acme"));
        let summary = summarize(month("2028-02"), &rows, &[], None);
        assert_eq!(summary.days_in_month, 29);
        assert_eq!(summary.through, day("2028-02-29"));
        // 28 × 2 + 3 = 59 seat-days, and 59 / 29 = 2.034…
        assert_eq!(figures(&summary), vec![("Acme", 59, "2.03".to_owned(), 3, None, false)]);
        // The same seats every day are exactly those seats.
        let summary = summarize(month("2028-02"), &readings("a", "2028-02", 1, 29, 4, "Acme"), &[], None);
        assert_eq!(figures(&summary), vec![("Acme", 116, "4.00".to_owned(), 4, None, false)]);
    }

    #[test]
    fn a_past_month_names_each_client_as_on_its_last_day_and_one_that_left_keeps_its_days() {
        let rows = [
            row("a", "2026-10-01", 3, "Acme"),
            row("a", "2026-10-02", 5, "Acme"),
            row("a", "2026-10-03", 4, "Acme Dental"),
            // Left after one day: its other days count as none.
            row("b", "2026-10-01", 2, "Bolt"),
        ];
        let summary = summarize(month("2026-10"), &rows, &[now("a", "Acme Dental Group", 9)], None);
        assert_eq!(
            summary.lines,
            vec![
                Line {
                    id: OrganizationId::from("a".to_owned()),
                    // The name on its last day that month, not today's.
                    name: "Acme Dental".to_owned(),
                    current: true,
                    seat_days: 12,
                    most: 5,
                    today: None,
                },
                Line {
                    id: OrganizationId::from("b".to_owned()),
                    name: "Bolt".to_owned(),
                    current: false,
                    seat_days: 2,
                    most: 2,
                    today: None,
                },
            ]
        );
        // Over October's 31 days, the days after the last reading counting
        // as none.
        assert_eq!(summary.days_in_month, 31);
        assert_eq!(summary.prorated(12), 39);
        assert_eq!(summary.prorated(2), 6);
        assert_eq!(summary.seat_days(), 14);
        assert_eq!(summary.prorated(summary.seat_days()), 45);
        assert_eq!(summary.most(), 7);
        assert_eq!(summary.today(), None);
    }

    #[test]
    fn a_day_with_no_reading_counts_the_lower_of_the_days_either_side() {
        // November 2026: the server missed the 10th and 11th, and the 29th
        // and 30th.
        let mut rows = readings("a", "2026-11", 1, 9, 4, "Acme");
        rows.extend(readings("a", "2026-11", 12, 28, 6, "Acme"));
        // Bolt left before the 12th's reading, and Cara joined by it.
        rows.extend(readings("b", "2026-11", 1, 9, 3, "Bolt"));
        rows.extend(readings("c", "2026-11", 12, 28, 1, "Cara"));
        let summary = summarize(month("2026-11"), &rows, &[], None);
        assert_eq!(
            figures(&summary),
            vec![
                // 9 × 4, the 10th and 11th at the lower 4, and 17 × 6: no
                // reading after the 28th, so nothing then.
                ("Acme", 146, "4.87".to_owned(), 6, None, false),
                ("Bolt", 27, "0.90".to_owned(), 3, None, false),
                ("Cara", 17, "0.57".to_owned(), 1, None, false),
            ]
        );
    }

    #[test]
    fn this_month_counts_through_today_as_it_is_now_over_all_its_days() {
        let rows = [
            // The MSP's first reading: nothing before it counts.
            row("a", "2026-11-03", 3, "Acme"),
            row("a", "2026-11-04", 3, "Acme"),
            // Taken earlier today: today counts as it is now instead.
            row("a", "2026-11-06", 1, "Acme"),
            row("gone", "2026-11-03", 4, "Gone Ltd"),
            // Left after this morning's reading, which stays.
            row("gone", "2026-11-06", 5, "Gone Ltd"),
        ];
        let summary = summarize(
            month("2026-11"),
            &rows,
            &[now("a", "Acme 2", 6), now("new", "New Co", 2)],
            Some(day("2026-11-06")),
        );
        assert_eq!(summary.days_in_month, 30);
        assert_eq!(summary.through, day("2026-11-06"));
        assert_eq!(
            figures(&summary),
            vec![
                // The 5th had no reading: the lower of the 4th's and today's.
                ("Acme 2", 15, "0.50".to_owned(), 6, Some(6), true),
                ("Gone Ltd", 9, "0.30".to_owned(), 5, None, false),
                ("New Co", 2, "0.07".to_owned(), 2, Some(2), true),
            ]
        );
        assert_eq!(summary.seat_days(), 26);
        assert_eq!(summary.prorated(summary.seat_days()), 87);
        assert_eq!(summary.most(), 13);
        assert_eq!(summary.today(), Some(8));
    }

    #[test]
    fn a_month_with_nothing_has_no_seat_days() {
        let summary = summarize(month("2026-11"), &[], &[], Some(day("2026-11-02")));
        assert_eq!(summary.days_in_month, 30);
        assert_eq!(summary.through, day("2026-11-02"));
        assert!(summary.lines.is_empty());
        assert_eq!(summary.today(), None);
        assert_eq!(summary.prorated(summary.seat_days()), 0);
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
        let summary = summarize(month("2026-10"), &rows, &[], None);
        assert_eq!(
            csv("2026-10", &summary),
            "\u{feff}Month,Through,Client,Seat-days,Days in month,Prorated seats,Peak,Today\r\n\
             2026-10,2026-10-31,Acme,8,31,0.26,5,\r\n\
             2026-10,2026-10-31,\"Bolt, Inc\",2,31,0.06,2,\r\n\
             2026-10,2026-10-31,Total,10,31,0.32,7,\r\n"
        );
        let summary = summarize(month("2026-11"), &[], &[now("a", "Acme", 3)], Some(day("2026-11-06")));
        assert_eq!(
            csv("2026-11", &summary),
            "\u{feff}Month,Through,Client,Seat-days,Days in month,Prorated seats,Peak,Today\r\n\
             2026-11,2026-11-06,Acme,3,30,0.10,3,3\r\n\
             2026-11,2026-11-06,Total,3,30,0.10,3,3\r\n"
        );
    }
}

// Keykeeper: the plans' clock (DESIGN.md, "Plans and billing", "What happens
// when payment stops", in the meta repo), a scheduled job
// (PLAN_REMINDERS_SCHEDULE) that does nothing unless PLANS_ENFORCED is on:
//
// - organizations and MSPs with no plan get a trial (`run_clock`);
// - when the clock moves a plan into another state (a trial ending, grace
//   starting or ending), the people it reaches are sent the sync notice the
//   apps already act on, once;
// - owners get the reminders, once each: a trial ending in 7 days and in 1
//   day, and for a renewing plan in grace, 3 days before grace ends and when
//   it has. An MSP's go to its admins, and a person's Premium to them.
//
// What's due, and that nothing goes twice, is worked out in
// `src/db/models/keykeeper_plan_clock.rs`. The words are here. "At the
// failure" of a payment needs a payment provider, and isn't sent yet.

use chrono::{NaiveDateTime, Utc};

use crate::{
    CONFIG,
    api::notifications::WebSocketUsers,
    db::{
        DbConn, DbPool,
        models::{DueReminder, FreeWhy, PlanNotice, PlanOwner, Reminder, run_clock},
    },
    mail,
};

use super::keykeeper_plans::tell_people_to_sync;

/// The job. Where plans aren't enforced it does nothing at all.
pub async fn plan_clock_job(pool: DbPool) {
    if !CONFIG.plans_enforced() {
        return;
    }
    let Ok(conn) = pool.get().await else {
        error!("Failed to get a database connection for the plans' clock");
        return;
    };
    run(Utc::now().naive_utc(), &conn, &crate::api::WS_USERS).await;
}

async fn run(at: NaiveDateTime, conn: &DbConn, ws: &WebSocketUsers) {
    let (changed, due) = match run_clock(at, conn).await {
        Ok(found) => found,
        Err(e) => {
            error!("The plans' clock couldn't run: {e:#?}");
            return;
        }
    };
    for whose in &changed {
        tell_people_to_sync(whose, conn, ws).await;
    }
    let grace_days = CONFIG.plan_grace_days();
    for reminder in due {
        let (subject, paragraphs) = words(&reminder, grace_days);
        let mut reached = false;
        for address in &reminder.to {
            match mail::send_plan_reminder(address, &subject, &paragraphs).await {
                Ok(()) => reached = true,
                Err(e) => warn!("A plan's reminder couldn't be sent to {address}: {e:#?}"),
            }
        }
        // Noted as sent before it went, so it never goes twice. One that
        // reached nobody is tried again at the next run while it's due.
        if !reached
            && let Err(e) = PlanNotice::forget(&reminder.plan_uuid, reminder.reminder, reminder.about, conn).await
        {
            error!("A plan's reminder that wasn't sent couldn't be forgotten, so it won't be tried again: {e:#?}");
        }
    }
}

/// A day, in words: "March 1, 2027".
fn day(date: &NaiveDateTime) -> String {
    date.format("%B %-d, %Y").to_string()
}

/// A moment, in words, in UTC: "Monday, March 1, 2027, at 12:00 PM UTC".
fn moment(date: &NaiveDateTime) -> String {
    date.format("%A, %B %-d, %Y, at %-I:%M %p UTC").to_string()
}

/// What stops for whose plan it is, said as of then (`after`) or of now.
fn what_stops(whose: &PlanOwner, name: &str, after: bool) -> String {
    let (nothing, now, have, stop) = if after {
        ("After that, nothing", "", "have", "stop too")
    } else {
        ("Nothing", " now", "had", "have stopped too")
    };
    match whose {
        PlanOwner::User(_) => format!(
            "{}our own plan no longer gives you attaching files, sending files, or the data breach report.",
            if after {
                "After that, y"
            } else {
                "Y"
            }
        ),
        PlanOwner::Organization(_) => format!(
            "{nothing} new can be added to {name}{now}: no new people, shared items, shared folders, groups, or attachments. Premium features its members {have} through {name} {stop}."
        ),
        PlanOwner::Msp(_) => format!(
            "{nothing} new can be added to {name}'s clients{now}: no new people, shared items, shared folders, groups, or attachments, and {name} can't take on new clients or invite staff. Premium features your staff and your clients' people {have} through {name} {stop}."
        ),
    }
}

/// What keeps working, which is everything that's there.
fn what_keeps(whose: &PlanOwner, name: &str) -> String {
    match whose {
        PlanOwner::User(_) => "Nothing is deleted. Your items and the files already attached to them stay, and you can still open, change, export, and delete all of it.".to_owned(),
        PlanOwner::Organization(_) => format!(
            "Nothing is deleted. Everyone in {name} can still sign in, and open, change, export, and delete everything in it."
        ),
        PlanOwner::Msp(_) => "Nothing is deleted. Everyone in your clients can still sign in, and open, change, export, and delete everything in them, and your staff keep the MSP console and their access to each client.".to_owned(),
    }
}

/// An MSP's clients, for its trial's email.
fn clients(count: usize) -> String {
    match count {
        0 => String::new(),
        1 => " It covers 1 client organization.".to_owned(),
        n => format!(" It covers {n} client organizations."),
    }
}

/// The subject and the paragraphs of a reminder. Plain: whose plan, the date
/// in words, what stops, and what keeps working.
fn words(due: &DueReminder, grace_days: i64) -> (String, Vec<String>) {
    let name = due.name.as_deref().unwrap_or("Your organization");
    let person = matches!(due.whose, PlanOwner::User(_));
    let offer = due.row.free_why() == Some(FreeWhy::Offer);
    let pool = if matches!(due.whose, PlanOwner::Msp(_)) {
        clients(due.clients)
    } else {
        String::new()
    };
    let ends = &due.about;
    match due.reminder {
        Reminder::TrialSevenDays | Reminder::TrialOneDay => {
            let (subject, first) = match (person, offer) {
                (true, false) => (
                    format!("Your PassBundle Premium trial ends on {}", day(ends)),
                    format!("Your free trial of Premium ends on {}.", moment(ends)),
                ),
                (true, true) => (
                    format!("Your free months of PassBundle Premium end on {}", day(ends)),
                    format!("Your free months of Premium end on {}.", moment(ends)),
                ),
                (false, false) => (
                    format!("The PassBundle trial for {name} ends on {}", day(ends)),
                    format!("The free trial for {name} ends on {}.{pool}", moment(ends)),
                ),
                (false, true) => (
                    format!("The free months of PassBundle for {name} end on {}", day(ends)),
                    format!("The free months for {name} end on {}.{pool}", moment(ends)),
                ),
            };
            (subject, vec![first, what_stops(&due.whose, name, true), what_keeps(&due.whose, name)])
        }
        Reminder::GraceThreeDays => {
            let paid = due.row.until.map(|until| moment(&until)).unwrap_or_default();
            let (subject, first) = if person {
                (
                    format!("Your PassBundle Premium ends on {} unless it's paid", day(ends)),
                    format!(
                        "The payment for your Premium hasn't come through. It was paid through {paid}, and it ends on {} unless it's paid by then.",
                        moment(ends)
                    ),
                )
            } else {
                (
                    format!("{name}'s PassBundle plan ends on {} unless it's paid", day(ends)),
                    format!(
                        "The payment for {name}'s PassBundle plan hasn't come through. It was paid through {paid}, and it ends on {} unless it's paid by then.",
                        moment(ends)
                    ),
                )
            };
            (subject, vec![first, what_stops(&due.whose, name, true), what_keeps(&due.whose, name)])
        }
        Reminder::GraceEnded => {
            let (subject, first) = if person {
                (
                    "Your PassBundle Premium has ended".to_owned(),
                    format!(
                        "Your Premium ended on {}, {grace_days} days after it was due, because its payment didn't come through.",
                        moment(ends)
                    ),
                )
            } else {
                (
                    format!("{name}'s PassBundle plan has ended"),
                    format!(
                        "{name}'s PassBundle plan ended on {}, {grace_days} days after it was due, because its payment didn't come through.",
                        moment(ends)
                    ),
                )
            };
            let mut keeps = what_keeps(&due.whose, name);
            keeps.push_str(" Once it's paid, everything works as it did.");
            (subject, vec![first, what_stops(&due.whose, name, false), keeps])
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;

    use super::*;
    use crate::db::models::{Billed, Plan, SetBy, Standing};

    fn noon() -> NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2027, 3, 1).unwrap().and_hms_opt(12, 0, 0).unwrap()
    }

    fn row(free_why: Option<&str>, until: Option<NaiveDateTime>) -> Plan {
        Plan {
            uuid: "plan".to_owned(),
            user_uuid: None,
            org_uuid: None,
            msp_uuid: None,
            plan: "business".to_owned(),
            free_until: free_why.map(|_| noon()),
            free_why: free_why.map(str::to_owned),
            standing: if until.is_some() {
                Standing::Until
            } else {
                Standing::None
            }
            .as_str()
            .to_owned(),
            until,
            renews: until.is_some(),
            billed: Billed::ByHand.as_str().to_owned(),
            set_by: SetBy::Operator.as_str().to_owned(),
            provider: None,
            provider_customer: None,
            provider_subscription: None,
            checked_at: None,
            updated_at: noon(),
        }
    }

    fn due(whose: PlanOwner, name: Option<&str>, reminder: Reminder, row: Plan) -> DueReminder {
        DueReminder {
            plan_uuid: row.uuid.clone(),
            about: match reminder {
                Reminder::TrialSevenDays | Reminder::TrialOneDay => row.free_until.unwrap(),
                _ => row.until.unwrap() + TimeDelta::days(14),
            },
            whose,
            reminder,
            row,
            name: name.map(str::to_owned),
            clients: 3,
            to: vec!["owner@example.test".to_owned()],
        }
    }

    fn acme() -> PlanOwner {
        PlanOwner::Organization("acme".to_owned().into())
    }

    #[test]
    fn dates_read_in_words_in_utc() {
        assert_eq!(day(&noon()), "March 1, 2027");
        assert_eq!(moment(&noon()), "Monday, March 1, 2027, at 12:00 PM UTC");
        let morning = noon() - TimeDelta::hours(3) - TimeDelta::minutes(55);
        assert_eq!(moment(&morning), "Monday, March 1, 2027, at 8:05 AM UTC");
    }

    #[test]
    fn a_trials_reminder_says_the_date_what_stops_and_that_nothing_is_deleted() {
        let (subject, paragraphs) =
            words(&due(acme(), Some("Acme"), Reminder::TrialSevenDays, row(Some("trial"), None)), 14);
        assert_eq!(subject, "The PassBundle trial for Acme ends on March 1, 2027");
        assert_eq!(
            paragraphs,
            vec![
                "The free trial for Acme ends on Monday, March 1, 2027, at 12:00 PM UTC.",
                "After that, nothing new can be added to Acme: no new people, shared items, shared folders, groups, or attachments. Premium features its members have through Acme stop too.",
                "Nothing is deleted. Everyone in Acme can still sign in, and open, change, export, and delete everything in it.",
            ]
        );
        // The day before says the same.
        assert_eq!(
            words(&due(acme(), Some("Acme"), Reminder::TrialOneDay, row(Some("trial"), None)), 14),
            (subject, paragraphs)
        );

        // An offer's free months.
        let (subject, paragraphs) =
            words(&due(acme(), Some("Acme"), Reminder::TrialOneDay, row(Some("offer"), None)), 14);
        assert_eq!(subject, "The free months of PassBundle for Acme end on March 1, 2027");
        assert_eq!(paragraphs[0], "The free months for Acme end on Monday, March 1, 2027, at 12:00 PM UTC.");

        // An MSP's pool, to its admins.
        let msp = PlanOwner::Msp("northwind".to_owned().into());
        let (subject, paragraphs) =
            words(&due(msp, Some("Northwind IT"), Reminder::TrialSevenDays, row(Some("trial"), None)), 14);
        assert_eq!(subject, "The PassBundle trial for Northwind IT ends on March 1, 2027");
        assert_eq!(
            paragraphs,
            vec![
                "The free trial for Northwind IT ends on Monday, March 1, 2027, at 12:00 PM UTC. It covers 3 client organizations.",
                "After that, nothing new can be added to Northwind IT's clients: no new people, shared items, shared folders, groups, or attachments, and Northwind IT can't take on new clients or invite staff. Premium features your staff and your clients' people have through Northwind IT stop too.",
                "Nothing is deleted. Everyone in your clients can still sign in, and open, change, export, and delete everything in them, and your staff keep the MSP console and their access to each client.",
            ]
        );

        // A person's Premium.
        let ana = PlanOwner::User("ana".to_owned().into());
        let (subject, paragraphs) = words(&due(ana, None, Reminder::TrialSevenDays, row(Some("trial"), None)), 14);
        assert_eq!(subject, "Your PassBundle Premium trial ends on March 1, 2027");
        assert_eq!(
            paragraphs,
            vec![
                "Your free trial of Premium ends on Monday, March 1, 2027, at 12:00 PM UTC.",
                "After that, your own plan no longer gives you attaching files, sending files, or the data breach report.",
                "Nothing is deleted. Your items and the files already attached to them stay, and you can still open, change, export, and delete all of it.",
            ]
        );
    }

    #[test]
    fn grace_says_when_it_ends_and_then_that_it_has() {
        let paid = row(None, Some(noon()));
        let (subject, paragraphs) = words(&due(acme(), Some("Acme"), Reminder::GraceThreeDays, paid.clone()), 14);
        assert_eq!(subject, "Acme's PassBundle plan ends on March 15, 2027 unless it's paid");
        assert_eq!(
            paragraphs,
            vec![
                "The payment for Acme's PassBundle plan hasn't come through. It was paid through Monday, March 1, 2027, at 12:00 PM UTC, and it ends on Monday, March 15, 2027, at 12:00 PM UTC unless it's paid by then.",
                "After that, nothing new can be added to Acme: no new people, shared items, shared folders, groups, or attachments. Premium features its members have through Acme stop too.",
                "Nothing is deleted. Everyone in Acme can still sign in, and open, change, export, and delete everything in it.",
            ]
        );

        let (subject, paragraphs) = words(&due(acme(), Some("Acme"), Reminder::GraceEnded, paid.clone()), 14);
        assert_eq!(subject, "Acme's PassBundle plan has ended");
        assert_eq!(
            paragraphs,
            vec![
                "Acme's PassBundle plan ended on Monday, March 15, 2027, at 12:00 PM UTC, 14 days after it was due, because its payment didn't come through.",
                "Nothing new can be added to Acme now: no new people, shared items, shared folders, groups, or attachments. Premium features its members had through Acme have stopped too.",
                "Nothing is deleted. Everyone in Acme can still sign in, and open, change, export, and delete everything in it. Once it's paid, everything works as it did.",
            ]
        );

        let ana = PlanOwner::User("ana".to_owned().into());
        let (subject, paragraphs) = words(&due(ana.clone(), None, Reminder::GraceThreeDays, paid.clone()), 14);
        assert_eq!(subject, "Your PassBundle Premium ends on March 15, 2027 unless it's paid");
        assert_eq!(
            paragraphs[0],
            "The payment for your Premium hasn't come through. It was paid through Monday, March 1, 2027, at 12:00 PM UTC, and it ends on Monday, March 15, 2027, at 12:00 PM UTC unless it's paid by then."
        );
        let (subject, paragraphs) = words(&due(ana, None, Reminder::GraceEnded, paid.clone()), 14);
        assert_eq!(subject, "Your PassBundle Premium has ended");
        assert_eq!(
            paragraphs[1],
            "Your own plan no longer gives you attaching files, sending files, or the data breach report."
        );

        let msp = PlanOwner::Msp("northwind".to_owned().into());
        let (subject, paragraphs) = words(&due(msp, Some("Northwind IT"), Reminder::GraceEnded, paid), 14);
        assert_eq!(subject, "Northwind IT's PassBundle plan has ended");
        assert_eq!(
            paragraphs[1],
            "Nothing new can be added to Northwind IT's clients now: no new people, shared items, shared folders, groups, or attachments, and Northwind IT can't take on new clients or invite staff. Premium features your staff and your clients' people had through Northwind IT have stopped too."
        );
    }
}

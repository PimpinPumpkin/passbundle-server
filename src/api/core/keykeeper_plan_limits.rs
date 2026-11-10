// Keykeeper: what a plan lets someone add, on a server that enforces plans
// (DESIGN.md, "Plans and billing", "What the server refuses", in the meta
// repo): attachments by the plan of whoever owns the item, file Sends, and
// the data breach report.
//
// Only adding is checked. Downloading and deleting never look at a plan, so
// nothing here is called from those routes: a file attached while a plan was
// in effect still downloads and can be removed after it, and storage that's
// over its limit refuses new uploads and nothing else.
//
// Who has Premium's features is decided in one place, `what_a_person_gets`
// in `src/db/models/keykeeper_plans.rs`, and an organization's plan in
// `plan_at` beside it. A plan that can't be read is the server's ordinary
// error, never Free and never Premium: every read below passes its error on.
//
// A refusal is the server's ordinary 400 with one sentence, which the web
// vault, the extension, and the apps show as it is. The sentences are here,
// written once.
//
// Where plans aren't enforced, nothing here looks anything up, and every
// answer is the one the server has always given.

use chrono::{NaiveDateTime, Utc};

use crate::{
    CONFIG,
    api::EmptyResult,
    db::{
        DbConn,
        models::{
            Attachment, Cipher, Organization, PersonGets, PlanOwner, PlanState, Terms, UserId, plan_at,
            what_a_person_gets,
        },
    },
};

const ATTACHING_IS_PREMIUM: &str = "Attaching files is part of Premium.";
const SENDING_FILES_IS_PREMIUM: &str = "Sending files is part of Premium. Sending text is free.";
const BREACH_REPORT_IS_PREMIUM: &str = "The data breach report is part of Premium.";
/// The design's sentence for anything added to an organization whose plan has
/// ended ("What happens when payment stops").
const ORGANIZATION_ENDED: &str = "This organization's plan has ended, so nothing new can be added. Everything in it can still be opened, changed, exported, and deleted.";
/// The server's own sentence where its operator turned attachments off for
/// everyone (a cap of 0), whatever anyone's plan.
const ATTACHMENTS_OFF: &str = "Attachments are disabled";

const KB: i64 = 1024;
const MB: i64 = 1024 * KB;
const GB: i64 = 1024 * MB;

/// What the plan of whoever owns an item gives for attachments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Allowance {
    /// A plan in effect, and its attachments in whole GB.
    Gb(i64),
    /// No plan in effect: a person on Free (who never had Premium, or whose
    /// Premium ended), or an organization nobody has set a plan for.
    NoPlan,
    /// An organization whose plan has ended.
    Ended,
}

/// Why a file can't be attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// The operator turned attachments off.
    Off,
    NoPlan,
    Ended,
    /// The plan is in effect and gives no storage: its figure is set to 0.
    NoneInPlan,
    /// No room for this file. Carries the limit, in bytes, so the sentence
    /// says the real figure.
    Full(i64),
}

/// The most an owner may keep, in bytes: what the plan gives, and never more
/// than a cap the operator set (in KB, as `USER_ATTACHMENT_LIMIT` and
/// `ORG_ATTACHMENT_LIMIT` are).
fn limit_bytes(plan_gb: i64, cap_kb: Option<i64>) -> i64 {
    let plan = plan_gb.saturating_mul(GB);
    match cap_kb {
        Some(cap_kb) => plan.min(cap_kb.saturating_mul(KB)),
        None => plan,
    }
}

/// Whether a file of `size` bytes may be added to what its owner already
/// keeps (`used` bytes). `credit` is what `used` already counts for this same
/// file: the record the v2 upload made before the data arrived.
fn fits(allowance: Allowance, cap_kb: Option<i64>, used: i64, credit: i64, size: i64) -> Result<(), Refusal> {
    if cap_kb == Some(0) {
        return Err(Refusal::Off);
    }
    let plan_gb = match allowance {
        Allowance::Gb(gb) if gb > 0 => gb,
        Allowance::Gb(_) => return Err(Refusal::NoneInPlan),
        Allowance::NoPlan => return Err(Refusal::NoPlan),
        Allowance::Ended => return Err(Refusal::Ended),
    };
    let limit = limit_bytes(plan_gb, cap_kb);
    let left = limit.saturating_sub(used).saturating_add(credit);
    if left <= 0 || size > left {
        return Err(Refusal::Full(limit));
    }
    Ok(())
}

/// A size as a person reads it: "5 GB", "1.5 GB", "512 MB", "100 KB". A
/// whole figure as it is, and anything else to one decimal place, rounded
/// down, so a sentence never promises more room than there is.
fn size_words(bytes: i64) -> String {
    for (unit, size) in [("GB", GB), ("MB", MB), ("KB", KB)] {
        if bytes >= size {
            let tenths = i128::from(bytes) * 10 / i128::from(size);
            let (whole, tenth) = (tenths / 10, tenths % 10);
            return if tenth == 0 {
                format!("{whole} {unit}")
            } else {
                format!("{whole}.{tenth} {unit}")
            };
        }
    }
    format!("{bytes} bytes")
}

impl Refusal {
    /// The one sentence the person reads. `organization` is the name of the
    /// organization that owns the item, and None for a person's own item.
    fn sentence(self, organization: Option<&str>) -> String {
        match (self, organization) {
            (Self::Off, _) => ATTACHMENTS_OFF.to_owned(),
            (Self::NoPlan | Self::Ended, None) => ATTACHING_IS_PREMIUM.to_owned(),
            (Self::NoPlan, Some(name)) => format!("{name} has no plan, so files can't be attached to its items."),
            (Self::Ended, Some(_)) => ORGANIZATION_ENDED.to_owned(),
            (Self::NoneInPlan, None) => "Your plan doesn't include attachments.".to_owned(),
            (Self::NoneInPlan, Some(name)) => format!("{name}'s plan doesn't include attachments."),
            (Self::Full(limit), None) => {
                format!("Your {} for attachments is full. Delete some to make room.", size_words(limit))
            }
            (Self::Full(limit), Some(name)) => {
                format!("{name}'s {} for attachments is full. Delete some to make room.", size_words(limit))
            }
        }
    }
}

/// The operator's caps on attachments, in KB, as the settings give them: None
/// for no cap, and 0 for attachments turned off.
#[derive(Clone, Copy, Debug)]
struct Caps {
    /// USER_ATTACHMENT_LIMIT
    person_kb: Option<i64>,
    /// ORG_ATTACHMENT_LIMIT
    organization_kb: Option<i64>,
}

/// Premium's features, as the one function answers: through the person's own
/// plan, a seat in an organization whose plan is in effect, or an MSP's
/// staff.
fn has_premium(gets: &PersonGets) -> bool {
    gets.premium || gets.premium_from_organization
}

/// The attachment check, handed the time and the caps.
async fn attachment_fits_at(
    cipher: &Cipher,
    size: i64,
    credit: i64,
    at: NaiveDateTime,
    caps: Caps,
    conn: &DbConn,
) -> EmptyResult {
    let terms = Terms::from_config();
    if let Some(user) = &cipher.user_uuid {
        let gets = what_a_person_gets(user, at, conn).await?;
        let allowance = if has_premium(&gets) {
            Allowance::Gb(gets.own.storage_gb(&terms).unwrap_or(0))
        } else {
            Allowance::NoPlan
        };
        let used = Attachment::size_by_user(user, conn).await;
        if let Err(why) = fits(allowance, caps.person_kb, used, credit, size) {
            err!(why.sentence(None))
        }
    } else if let Some(org) = &cipher.organization_uuid {
        let plan = plan_at(&PlanOwner::Organization(org.clone()), None, at, conn).await?;
        let allowance = match plan.state {
            None => Allowance::NoPlan,
            Some(PlanState::Ended) => Allowance::Ended,
            Some(_) => Allowance::Gb(plan.storage_gb(&terms).unwrap_or(0)),
        };
        let used = Attachment::size_by_org(org, conn).await;
        if let Err(why) = fits(allowance, caps.organization_kb, used, credit, size) {
            let name = Organization::find_by_uuid(org, conn).await.map(|org| org.name);
            err!(why.sentence(Some(name.as_deref().unwrap_or("This organization"))))
        }
    } else {
        err!("Cipher is neither owned by a user nor an organization")
    }
    Ok(())
}

/// Refuses a file of `size` bytes that the plan of whoever owns `cipher`
/// gives no room for: the person's plan for their own item, and the
/// organization's for a shared one. `credit` is what's already counted for
/// this same file (see `fits`).
///
/// Where plans aren't enforced this does nothing, and the server's own check
/// (`attachment_size_limit` in `ciphers.rs`), which runs after it either way,
/// decides as it always has.
pub async fn attachment_must_fit(cipher: &Cipher, size: i64, credit: i64, conn: &DbConn) -> EmptyResult {
    if !CONFIG.plans_enforced() {
        return Ok(());
    }
    let caps = Caps {
        person_kb: CONFIG.user_attachment_limit(),
        organization_kb: CONFIG.org_attachment_limit(),
    };
    attachment_fits_at(cipher, size, credit, Utc::now().naive_utc(), caps, conn).await
}

/// Refuses with `sentence` unless the person has Premium's features at `at`.
async fn needs_premium_at(user: &UserId, sentence: &'static str, at: NaiveDateTime, conn: &DbConn) -> EmptyResult {
    if !has_premium(&what_a_person_gets(user, at, conn).await?) {
        err!(sentence)
    }
    Ok(())
}

/// Creating a file Send is Premium's. Text Sends are free, and a file Send
/// that already exists is never checked: it keeps working until it expires or
/// is deleted. How much a person may send stays the server's
/// (`USER_SEND_LIMIT`), whatever their plan.
pub async fn file_send_needs_premium(user: &UserId, conn: &DbConn) -> EmptyResult {
    if !CONFIG.plans_enforced() {
        return Ok(());
    }
    needs_premium_at(user, SENDING_FILES_IS_PREMIUM, Utc::now().naive_utc(), conn).await
}

/// The data breach report is Premium's. Checked only where the server makes
/// the lookup itself, with its own key: without one the answer is a link to
/// the other site's free page, which a plan can't gate and doesn't pretend
/// to.
pub async fn breach_report_needs_premium(user: &UserId, conn: &DbConn) -> EmptyResult {
    if !CONFIG.plans_enforced() {
        return Ok(());
    }
    needs_premium_at(user, BREACH_REPORT_IS_PREMIUM, Utc::now().naive_utc(), conn).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const PERSON: Option<&str> = None;
    const ACME: Option<&str> = Some("Acme");

    #[test]
    fn a_plan_never_gives_more_than_a_cap_the_operator_set() {
        // No cap: what the plan gives.
        assert_eq!(limit_bytes(5, None), 5 * GB);
        // A cap under the plan wins. 1048576 KB is the hosted default, 1 GB.
        assert_eq!(limit_bytes(5, Some(1_048_576)), GB);
        assert_eq!(limit_bytes(5, Some(2048)), 2 * MB);
        // A cap over the plan changes nothing: the plan never gives more than it says.
        assert_eq!(limit_bytes(5, Some(10 * 1_048_576)), 5 * GB);
        // The cap exactly at the plan.
        assert_eq!(limit_bytes(5, Some(5 * 1_048_576)), 5 * GB);
        // Figures too big to multiply stop at the top and never wrap around.
        assert_eq!(limit_bytes(i64::MAX, None), i64::MAX);
        assert_eq!(limit_bytes(i64::MAX, Some(i64::MAX)), i64::MAX);
        assert_eq!(limit_bytes(i64::MAX, Some(1)), KB);
    }

    #[test]
    fn a_file_fits_up_to_the_last_byte_and_not_one_past_it() {
        let premium = Allowance::Gb(5);
        assert_eq!(fits(premium, None, 0, 0, 1), Ok(()));
        assert_eq!(fits(premium, None, 0, 0, 5 * GB), Ok(()));
        assert_eq!(fits(premium, None, 0, 0, 5 * GB + 1), Err(Refusal::Full(5 * GB)));
        assert_eq!(fits(premium, None, 5 * GB - 10, 0, 10), Ok(()));
        assert_eq!(fits(premium, None, 5 * GB - 10, 0, 11), Err(Refusal::Full(5 * GB)));
        // Full: nothing more, not even an empty file, as the server's own check has it.
        assert_eq!(fits(premium, None, 5 * GB, 0, 0), Err(Refusal::Full(5 * GB)));
        assert_eq!(fits(premium, None, 5 * GB, 0, 1), Err(Refusal::Full(5 * GB)));
        // Over the limit, after a lapse or a lowered limit: new uploads are refused.
        assert_eq!(fits(premium, None, 9 * GB, 0, 1), Err(Refusal::Full(5 * GB)));
        // A total the database couldn't add up counts as full.
        assert_eq!(fits(premium, None, i64::MAX, 0, 1), Err(Refusal::Full(5 * GB)));
    }

    #[test]
    fn the_record_a_v2_upload_already_made_isnt_counted_twice() {
        let premium = Allowance::Gb(5);
        // The record for this 1 GB file is already in `used`, which the file fills to the brim.
        assert_eq!(fits(premium, None, 5 * GB, GB, GB), Ok(()));
        // The data may be a little bigger than the record said, while there's room.
        assert_eq!(fits(premium, None, 4 * GB, GB, GB + MB), Ok(()));
        assert_eq!(fits(premium, None, 5 * GB, GB, GB + 1), Err(Refusal::Full(5 * GB)));
        // Storage over the limit by more than the record: still refused.
        assert_eq!(fits(premium, None, 7 * GB, GB, GB), Err(Refusal::Full(5 * GB)));
    }

    #[test]
    fn the_operators_cap_counts_when_its_lower_than_the_plan() {
        let premium = Allowance::Gb(5);
        // 2 MB for everyone: the plan's 5 GB doesn't lift it, and the figure is the cap's.
        assert_eq!(fits(premium, Some(2048), 0, 0, 2 * MB), Ok(()));
        assert_eq!(fits(premium, Some(2048), 0, 0, 2 * MB + 1), Err(Refusal::Full(2 * MB)));
        assert_eq!(fits(premium, Some(2048), 2 * MB, 0, 1), Err(Refusal::Full(2 * MB)));
        // A cap over the plan doesn't raise it.
        assert_eq!(fits(premium, Some(100 * 1_048_576), 5 * GB, 0, 1), Err(Refusal::Full(5 * GB)));
        // Attachments turned off are off for everyone, and that's what's said, whatever the plan.
        for allowance in [premium, Allowance::NoPlan, Allowance::Ended, Allowance::Gb(0)] {
            assert_eq!(fits(allowance, Some(0), 0, 0, 1), Err(Refusal::Off));
        }
    }

    #[test]
    fn without_a_plan_in_effect_nothing_is_attached_however_small() {
        for (allowance, why) in [
            (Allowance::NoPlan, Refusal::NoPlan),
            (Allowance::Ended, Refusal::Ended),
            (Allowance::Gb(0), Refusal::NoneInPlan),
            (Allowance::Gb(-1), Refusal::NoneInPlan),
        ] {
            for cap_kb in [None, Some(1_048_576)] {
                assert_eq!(fits(allowance, cap_kb, 0, 0, 0), Err(why));
                assert_eq!(fits(allowance, cap_kb, 0, 0, 1), Err(why));
                // Nor into the room a v2 record seemed to hold.
                assert_eq!(fits(allowance, cap_kb, GB, GB, 1), Err(why));
            }
        }
    }

    #[test]
    fn sizes_read_as_people_write_them() {
        assert_eq!(size_words(5 * GB), "5 GB");
        assert_eq!(size_words(GB), "1 GB");
        assert_eq!(size_words(50 * GB), "50 GB");
        assert_eq!(size_words(GB + GB / 2), "1.5 GB");
        assert_eq!(size_words(2 * MB), "2 MB");
        assert_eq!(size_words(512 * MB), "512 MB");
        assert_eq!(size_words(100 * KB), "100 KB");
        assert_eq!(size_words(KB + KB / 2), "1.5 KB");
        // Rounded down, never up: a sentence doesn't promise room that isn't there.
        assert_eq!(size_words(2 * GB - 1), "1.9 GB");
        assert_eq!(size_words(GB + 1), "1 GB");
        assert_eq!(size_words(GB - 1), "1023.9 MB");
        assert_eq!(size_words(i64::MAX), "8589934591.9 GB");
        assert_eq!(size_words(512), "512 bytes");
    }

    #[test]
    fn each_refusal_is_one_sentence() {
        assert_eq!(Refusal::NoPlan.sentence(PERSON), "Attaching files is part of Premium.");
        // A person whose Premium ended is on Free.
        assert_eq!(Refusal::Ended.sentence(PERSON), "Attaching files is part of Premium.");
        assert_eq!(
            Refusal::Full(5 * GB).sentence(PERSON),
            "Your 5 GB for attachments is full. Delete some to make room."
        );
        // The figure is the real one: another setting, or the operator's cap.
        assert_eq!(
            Refusal::Full(20 * GB).sentence(PERSON),
            "Your 20 GB for attachments is full. Delete some to make room."
        );
        assert_eq!(
            Refusal::Full(2 * MB).sentence(PERSON),
            "Your 2 MB for attachments is full. Delete some to make room."
        );
        assert_eq!(Refusal::NoneInPlan.sentence(PERSON), "Your plan doesn't include attachments.");

        // A shared item: the same, naming the organization.
        assert_eq!(Refusal::NoPlan.sentence(ACME), "Acme has no plan, so files can't be attached to its items.");
        assert_eq!(
            Refusal::Ended.sentence(ACME),
            "This organization's plan has ended, so nothing new can be added. Everything in it can still be opened, changed, exported, and deleted."
        );
        assert_eq!(
            Refusal::Full(5 * GB).sentence(ACME),
            "Acme's 5 GB for attachments is full. Delete some to make room."
        );
        assert_eq!(Refusal::NoneInPlan.sentence(ACME), "Acme's plan doesn't include attachments.");

        // The operator's switch reads as it always has, for a person's item and a shared one.
        assert_eq!(Refusal::Off.sentence(PERSON), "Attachments are disabled");
        assert_eq!(Refusal::Off.sentence(ACME), "Attachments are disabled");

        assert_eq!(SENDING_FILES_IS_PREMIUM, "Sending files is part of Premium. Sending text is free.");
        assert_eq!(BREACH_REPORT_IS_PREMIUM, "The data breach report is part of Premium.");
    }
}

// With a database: each check's decision, by the plans in it, handed a time.
#[cfg(all(test, sqlite))]
mod database_tests {
    use chrono::TimeDelta;
    use diesel::RunQueryDsl;

    use super::*;
    use crate::db::{
        DbPool,
        models::{
            Billed, Membership, MembershipStatus, MembershipType, Msp, MspRole, MspStaff, Plan, PlanName, PlanWrite,
            SetBy, Standing, User,
        },
    };

    /// Noon on March 1, 2027: the moment every check below is made.
    fn noon() -> NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2027, 3, 1).unwrap().and_hms_opt(12, 0, 0).unwrap()
    }

    const NO_CAPS: Caps = Caps {
        person_kb: None,
        organization_kb: None,
    };

    /// Paid through `until`, and canceled, so it ends there with no grace.
    fn paid(plan: PlanName, until: NaiveDateTime) -> PlanWrite {
        PlanWrite {
            plan,
            free_until: None,
            free_why: None,
            standing: Standing::Until,
            until: Some(until),
            renews: false,
            billed: Billed::ByHand,
        }
    }

    fn in_effect(plan: PlanName) -> PlanWrite {
        paid(plan, noon() + TimeDelta::days(30))
    }

    fn ended(plan: PlanName) -> PlanWrite {
        paid(plan, noon() - TimeDelta::days(30))
    }

    async fn set(whose: PlanOwner, write: PlanWrite, conn: &DbConn) {
        Plan::set(&whose, write, SetBy::Operator, conn).await.unwrap().expect("the owner exists");
    }

    async fn person(name: &str, conn: &DbConn) -> User {
        let mut user = User::new(&format!("{name}@example.test"), None);
        user.save(conn).await.unwrap();
        user
    }

    async fn organization(name: &str, conn: &DbConn) -> Organization {
        let org = Organization::new(name.to_owned(), "billing@example.test", None, None);
        org.save(conn).await.unwrap();
        org
    }

    async fn join(user: &User, org: &Organization, status: MembershipStatus, conn: &DbConn) {
        let mut member = Membership::new(user.uuid.clone(), org.uuid.clone(), None);
        member.atype = MembershipType::User as i32;
        member.status = status as i32;
        member.save(conn).await.unwrap();
    }

    /// An item of the person's own.
    async fn own_item(user: &User, conn: &DbConn) -> Cipher {
        let mut cipher = Cipher::new(1, "2.item".to_owned());
        cipher.user_uuid = Some(user.uuid.clone());
        cipher.save(conn).await.unwrap();
        cipher
    }

    /// An item the organization owns.
    async fn shared_item(org: &Organization, conn: &DbConn) -> Cipher {
        let mut cipher = Cipher::new(1, "2.item".to_owned());
        cipher.organization_uuid = Some(org.uuid.clone());
        cipher.save(conn).await.unwrap();
        cipher
    }

    /// A file of `size` bytes already attached to `cipher`: its record, which
    /// is all the check counts.
    async fn attached(cipher: &Cipher, size: i64, conn: &DbConn) {
        let id = crate::crypto::generate_attachment_id();
        Attachment::new(id, cipher.uuid.clone(), "2.name".to_owned(), size, Some("2.key".to_owned()))
            .save(conn)
            .await
            .unwrap();
    }

    /// What the person reads when a file of `size` bytes is attached to
    /// `cipher` at noon. None: it's attached.
    async fn attaching(cipher: &Cipher, size: i64, caps: Caps, conn: &DbConn) -> Option<String> {
        attachment_fits_at(cipher, size, 0, noon(), caps, conn).await.err().map(|refused| refused.message().to_owned())
    }

    async fn sending_a_file(user: &User, conn: &DbConn) -> Option<String> {
        needs_premium_at(&user.uuid, SENDING_FILES_IS_PREMIUM, noon(), conn)
            .await
            .err()
            .map(|refused| refused.message().to_owned())
    }

    async fn the_breach_report(user: &User, conn: &DbConn) -> Option<String> {
        needs_premium_at(&user.uuid, BREACH_REPORT_IS_PREMIUM, noon(), conn)
            .await
            .err()
            .map(|refused| refused.message().to_owned())
    }

    fn says(sentence: &str) -> Option<String> {
        Some(sentence.to_owned())
    }

    #[rocket::async_test]
    async fn on_free_nothing_is_attached_or_sent_and_theres_no_breach_report() {
        let conn = DbPool::for_test().await;
        let ana = person("ana", &conn).await;
        let item = own_item(&ana, &conn).await;

        assert_eq!(attaching(&item, 1, NO_CAPS, &conn).await, says("Attaching files is part of Premium."));
        assert_eq!(attaching(&item, 0, NO_CAPS, &conn).await, says("Attaching files is part of Premium."));
        assert_eq!(sending_a_file(&ana, &conn).await, says("Sending files is part of Premium. Sending text is free."));
        assert_eq!(the_breach_report(&ana, &conn).await, says("The data breach report is part of Premium."));

        // A plan that ended is Free again, and says the same.
        set(PlanOwner::User(ana.uuid.clone()), ended(PlanName::Premium), &conn).await;
        assert_eq!(attaching(&item, 1, NO_CAPS, &conn).await, says("Attaching files is part of Premium."));
        assert_eq!(sending_a_file(&ana, &conn).await, says("Sending files is part of Premium. Sending text is free."));
        assert_eq!(the_breach_report(&ana, &conn).await, says("The data breach report is part of Premium."));
    }

    #[rocket::async_test]
    async fn premium_attaches_up_to_its_storage_and_says_the_figure_when_full() {
        let conn = DbPool::for_test().await;
        let ana = person("ana", &conn).await;
        let item = own_item(&ana, &conn).await;
        set(PlanOwner::User(ana.uuid.clone()), in_effect(PlanName::Premium), &conn).await;
        let full = "Your 5 GB for attachments is full. Delete some to make room.";

        assert_eq!(attaching(&item, 1, NO_CAPS, &conn).await, None);
        assert_eq!(sending_a_file(&ana, &conn).await, None);
        assert_eq!(the_breach_report(&ana, &conn).await, None);

        // Somebody else's files don't count against hers.
        let ben = person("ben", &conn).await;
        attached(&own_item(&ben, &conn).await, 5 * GB, &conn).await;
        assert_eq!(attaching(&item, 1, NO_CAPS, &conn).await, None);

        attached(&item, 5 * GB - 100, &conn).await;
        assert_eq!(attaching(&item, 100, NO_CAPS, &conn).await, None);
        assert_eq!(attaching(&item, 101, NO_CAPS, &conn).await, says(full));
        // Files on another of her items count too.
        attached(&own_item(&ana, &conn).await, 100, &conn).await;
        assert_eq!(attaching(&item, 1, NO_CAPS, &conn).await, says(full));

        // The data for a record a v2 upload already made isn't counted twice.
        let noon = noon();
        assert!(attachment_fits_at(&item, 100, 100, noon, NO_CAPS, &conn).await.is_ok());
        assert_eq!(attachment_fits_at(&item, 101, 100, noon, NO_CAPS, &conn).await.unwrap_err().message(), full);

        // Full storage stops her sending no file and reading no report.
        assert_eq!(sending_a_file(&ana, &conn).await, None);
        assert_eq!(the_breach_report(&ana, &conn).await, None);
    }

    #[rocket::async_test]
    async fn the_operators_cap_wins_when_its_lower_and_never_raises_a_plan() {
        let conn = DbPool::for_test().await;
        let ana = person("ana", &conn).await;
        let item = own_item(&ana, &conn).await;
        set(PlanOwner::User(ana.uuid.clone()), in_effect(PlanName::Premium), &conn).await;
        let two_mb = Caps {
            person_kb: Some(2048),
            organization_kb: None,
        };

        assert_eq!(attaching(&item, 2 * MB, two_mb, &conn).await, None);
        assert_eq!(
            attaching(&item, 2 * MB + 1, two_mb, &conn).await,
            says("Your 2 MB for attachments is full. Delete some to make room.")
        );

        // A cap on organizations is no cap on a person, and a cap over the plan gives no more than the plan.
        let on_organizations = Caps {
            person_kb: None,
            organization_kb: Some(2048),
        };
        assert_eq!(attaching(&item, 3 * MB, on_organizations, &conn).await, None);
        let generous = Caps {
            person_kb: Some(100 * 1_048_576),
            organization_kb: None,
        };
        assert_eq!(
            attaching(&item, 5 * GB + 1, generous, &conn).await,
            says("Your 5 GB for attachments is full. Delete some to make room.")
        );

        // Attachments turned off: off for Premium too, and a cap never gives Free what its plan doesn't.
        let off = Caps {
            person_kb: Some(0),
            organization_kb: None,
        };
        assert_eq!(attaching(&item, 1, off, &conn).await, says("Attachments are disabled"));
        let ben = person("ben", &conn).await;
        let bens = own_item(&ben, &conn).await;
        assert_eq!(attaching(&bens, 1, generous, &conn).await, says("Attaching files is part of Premium."));
    }

    #[rocket::async_test]
    async fn a_seat_or_an_msps_staff_gives_premium_for_a_persons_own_items() {
        let conn = DbPool::for_test().await;
        let acme = organization("Acme", &conn).await;
        set(PlanOwner::Organization(acme.uuid.clone()), in_effect(PlanName::Business), &conn).await;

        // A seat in an organization whose plan is in effect.
        let member = person("member", &conn).await;
        join(&member, &acme, MembershipStatus::Confirmed, &conn).await;
        let item = own_item(&member, &conn).await;
        assert_eq!(attaching(&item, 5 * GB, NO_CAPS, &conn).await, None);
        assert_eq!(
            attaching(&item, 5 * GB + 1, NO_CAPS, &conn).await,
            says("Your 5 GB for attachments is full. Delete some to make room.")
        );
        assert_eq!(sending_a_file(&member, &conn).await, None);
        assert_eq!(the_breach_report(&member, &conn).await, None);

        // Invited isn't joined, and revoked holds no seat.
        for (name, status) in [("invited", MembershipStatus::Invited), ("revoked", MembershipStatus::Revoked)] {
            let outside = person(name, &conn).await;
            join(&outside, &acme, status, &conn).await;
            let item = own_item(&outside, &conn).await;
            assert_eq!(
                attaching(&item, 1, NO_CAPS, &conn).await,
                says("Attaching files is part of Premium."),
                "{name}"
            );
            assert!(sending_a_file(&outside, &conn).await.is_some(), "{name}");
            assert!(the_breach_report(&outside, &conn).await.is_some(), "{name}");
        }

        // An MSP's staff, while its pool is in effect.
        let msp = Msp::new("Northwind IT".to_owned());
        msp.insert(&conn).await.unwrap();
        let tech = person("tech", &conn).await;
        MspStaff::new(msp.uuid.clone(), tech.uuid.clone(), MspRole::Technician).insert(&conn).await.unwrap();
        let techs = own_item(&tech, &conn).await;
        assert_eq!(attaching(&techs, 1, NO_CAPS, &conn).await, says("Attaching files is part of Premium."));
        set(PlanOwner::Msp(msp.uuid.clone()), in_effect(PlanName::Msp), &conn).await;
        assert_eq!(attaching(&techs, 1, NO_CAPS, &conn).await, None);
        assert_eq!(sending_a_file(&tech, &conn).await, None);
        assert_eq!(the_breach_report(&tech, &conn).await, None);

        // When the organization's plan ends, so does what its members had through it.
        set(PlanOwner::Organization(acme.uuid.clone()), ended(PlanName::Business), &conn).await;
        assert_eq!(attaching(&item, 1, NO_CAPS, &conn).await, says("Attaching files is part of Premium."));
        assert_eq!(
            sending_a_file(&member, &conn).await,
            says("Sending files is part of Premium. Sending text is free.")
        );
        assert_eq!(the_breach_report(&member, &conn).await, says("The data breach report is part of Premium."));
    }

    #[rocket::async_test]
    async fn a_shared_item_goes_by_its_organizations_plan_and_names_it() {
        let conn = DbPool::for_test().await;
        let acme = organization("Acme", &conn).await;
        let item = shared_item(&acme, &conn).await;
        // Whoever attaches, with Premium of their own or without: it's the organization's plan that counts.
        let member = person("member", &conn).await;
        join(&member, &acme, MembershipStatus::Confirmed, &conn).await;
        set(PlanOwner::User(member.uuid.clone()), in_effect(PlanName::Premium), &conn).await;

        // No plan.
        assert_eq!(
            attaching(&item, 1, NO_CAPS, &conn).await,
            says("Acme has no plan, so files can't be attached to its items.")
        );

        // A plan in effect: 1 GB a person, pooled, and never less than 5 GB.
        set(PlanOwner::Organization(acme.uuid.clone()), in_effect(PlanName::Business), &conn).await;
        assert_eq!(attaching(&item, 5 * GB, NO_CAPS, &conn).await, None);
        let full = "Acme's 5 GB for attachments is full. Delete some to make room.";
        assert_eq!(attaching(&item, 5 * GB + 1, NO_CAPS, &conn).await, says(full));
        // What a member keeps in their own vault isn't the organization's.
        attached(&own_item(&member, &conn).await, 5 * GB, &conn).await;
        assert_eq!(attaching(&item, 5 * GB, NO_CAPS, &conn).await, None);
        // Files on any of the organization's items count.
        attached(&shared_item(&acme, &conn).await, 5 * GB, &conn).await;
        assert_eq!(attaching(&item, 1, NO_CAPS, &conn).await, says(full));

        // More seats, more room: seven people pool 7 GB.
        for n in 2..=7 {
            let more = person(&format!("member{n}"), &conn).await;
            join(&more, &acme, MembershipStatus::Confirmed, &conn).await;
        }
        assert_eq!(attaching(&item, 2 * GB, NO_CAPS, &conn).await, None);
        assert_eq!(
            attaching(&item, 2 * GB + 1, NO_CAPS, &conn).await,
            says("Acme's 7 GB for attachments is full. Delete some to make room.")
        );

        // The operator's cap on organizations, when it's lower.
        let one_gb = Caps {
            person_kb: None,
            organization_kb: Some(1_048_576),
        };
        assert_eq!(
            attaching(&item, 1, one_gb, &conn).await,
            says("Acme's 1 GB for attachments is full. Delete some to make room.")
        );
        let off = Caps {
            person_kb: None,
            organization_kb: Some(0),
        };
        assert_eq!(attaching(&item, 1, off, &conn).await, says("Attachments are disabled"));

        // The plan ends: nothing new, in the sentence for everything an ended organization refuses.
        set(PlanOwner::Organization(acme.uuid.clone()), ended(PlanName::Business), &conn).await;
        assert_eq!(
            attaching(&item, 1, NO_CAPS, &conn).await,
            says(
                "This organization's plan has ended, so nothing new can be added. Everything in it can still be opened, changed, exported, and deleted."
            )
        );
    }

    #[rocket::async_test]
    async fn a_family_gets_its_organizations_storage_too() {
        let conn = DbPool::for_test().await;
        let family = organization("Rivera family", &conn).await;
        let item = shared_item(&family, &conn).await;
        set(PlanOwner::Organization(family.uuid.clone()), in_effect(PlanName::Families), &conn).await;

        assert_eq!(attaching(&item, 5 * GB, NO_CAPS, &conn).await, None);
        assert_eq!(
            attaching(&item, 5 * GB + 1, NO_CAPS, &conn).await,
            says("Rivera family's 5 GB for attachments is full. Delete some to make room.")
        );
    }

    /// A plan that can't be read is the server's ordinary error: never Free,
    /// and never Premium.
    #[rocket::async_test]
    async fn a_plan_that_cant_be_read_fails_the_request() {
        let conn = DbPool::for_test().await;
        let ana = person("ana", &conn).await;
        let own = own_item(&ana, &conn).await;
        let acme = organization("Acme", &conn).await;
        let shared = shared_item(&acme, &conn).await;
        set(PlanOwner::User(ana.uuid.clone()), in_effect(PlanName::Premium), &conn).await;
        set(PlanOwner::Organization(acme.uuid.clone()), in_effect(PlanName::Business), &conn).await;
        assert_eq!(attaching(&own, 1, NO_CAPS, &conn).await, None);
        assert_eq!(attaching(&shared, 1, NO_CAPS, &conn).await, None);

        // The plans can no longer be read.
        conn.run(|conn| diesel::sql_query("DROP TABLE plans").execute(conn)).await.unwrap();

        let person_error = "Error working out what a person's plans give";
        assert_eq!(attaching(&own, 1, NO_CAPS, &conn).await, says(person_error));
        assert_eq!(sending_a_file(&ana, &conn).await, says(person_error));
        assert_eq!(the_breach_report(&ana, &conn).await, says(person_error));
        assert_eq!(attaching(&shared, 1, NO_CAPS, &conn).await, says("Error working out a plan"));
    }
}

// Keykeeper: the new-device check. In upstream's format the master password
// alone signs an account in anywhere unless it has two-step login. So an
// account without two-step login that signs in with its password on a device
// it has never used waits: until the person types the number the new device
// shows into a device already signed in to the account, or, when there's no
// such device, gives a code sent by email. No key moves: the new device has
// the master password already, and the check only decides whether its
// sign-in finishes. See DESIGN.md, "New-device check", in the meta repo.
//
// The new device's side has no session: it asks with the check's id and a
// token only it was given (`status`, `email`), then sends its password grant
// again with the token (upstream's `newDeviceOtp`). The approving side is
// the account's other signed-in sessions (`list`, `approve`, `deny`).

use std::net::IpAddr;

use chrono::{NaiveDateTime, TimeDelta, Utc};
use rocket::{Route, serde::json::Json};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        ApiResult, JsonResult,
        core::{
            keykeeper_device_approval::SignInMethod, keykeeper_two_step, log_user_event_detail,
            two_factor::email::obscure_email,
        },
    },
    auth::{ClientIp, Headers},
    db::{
        DbConn,
        models::{Device, DeviceType, EventType, KnownDeviceToken, NewDeviceCheck, User, sso_hash},
    },
    mail,
    util::format_date,
};

pub fn routes() -> Vec<Route> {
    routes![status, email, list, approve, deny]
}

/// How long a check waits: from the first sign-in attempt.
pub const CHECK_MINUTES: i64 = 10;
/// The number's length: two digits, 10 to 99. Each check takes one try, so
/// length doesn't stand against guessing; it makes the person look at the
/// new device.
pub const NUMBER_DIGITS: u32 = 2;
/// How long after "Can't use your other devices?" a code by email may be sent.
pub const EMAIL_DELAY_HOURS: i64 = 24;
/// How long a check lasts once a code may be sent after the wait.
const AFTER_DELAY_HOURS: i64 = 1;
/// The most checks waiting for one account at once.
const MAX_WAITING: usize = 3;
const CODE_DIGITS: u8 = 8;
const MAX_CODE_SENDS: i32 = 3;
const MAX_CODE_TRIES: i32 = 5;
/// A device unused this long can't approve: its session has ended (30
/// days, 90 for a phone: upstream's refresh token lifetimes).
const APPROVER_DAYS: i64 = 30;
const PHONE_APPROVER_DAYS: i64 = 90;

/// What a password sign-in brings to the check.
pub struct SignIn<'a> {
    pub user: &'a User,
    pub device: &'a Device,
    pub ip: &'a IpAddr,
    /// Whether the account had any two-step method on when it started.
    pub two_step_on: bool,
    /// The token two-step login's "remember" field carried (provider 5),
    /// where upstream's clients send back the token this check gave them.
    pub remembered: Option<&'a str>,
    /// Upstream's `newDeviceOtp`: the check's token once it's approved, or
    /// the code sent by email.
    pub otp: Option<&'a str>,
}

/// The new-device check for a password sign-in whose password and two-step
/// login checked out. Ok(None): it goes ahead, with nothing new to keep.
/// Ok(Some(token)): it goes ahead, and the device keeps this token (in
/// upstream's `TwoFactorToken` answer), which shows the next time that it's a
/// device the account knows. Err: it waits (a 400 with
/// `KeykeeperNewDeviceCheck`), or is refused.
pub async fn check_sign_in(s: SignIn<'_>, conn: &DbConn) -> ApiResult<Option<String>> {
    if !CONFIG.new_device_check() || s.two_step_on {
        return Ok(None);
    }
    let now = Utc::now().naive_utc();
    let user = &s.user.uuid;
    let device = s.device;

    // A device that has finished a sign-in and shows its token is known.
    if !device.is_new()
        && let Some(token) = s.remembered
        && KnownDeviceToken::matches(user, &device.uuid, token, conn).await
    {
        return Ok(None);
    }

    let devices = Device::find_by_user(user, conn).await;
    // The account's first sign-in: no device has ever finished one.
    if !devices.iter().any(|d| !d.is_new()) {
        return Ok(Some(KnownDeviceToken::issue(user, &device.uuid, now, conn).await));
    }

    let mut open = NewDeviceCheck::find_by_user(user, conn)
        .await
        .into_iter()
        .find(|c| c.device_uuid == device.uuid && c.device_type == device.atype && c.is_open(now));

    // Finishing: the approved check's token, or the code sent by email.
    if let (Some(otp), Some(check)) = (s.otp.map(str::trim).filter(|o| !o.is_empty()), open.as_mut()) {
        if is_code(otp) {
            return finish_with_code(check, otp, s.user, s.ip, now, conn).await;
        }
        if check.approved_at.is_some() && check.token_matches(otp) {
            check.used_at = Some(now);
            check.save(conn).await?;
            return Ok(Some(KnownDeviceToken::issue(user, &device.uuid, now, conn).await));
        }
    }

    let approvers = devices.iter().any(|d| d.uuid != device.uuid && can_approve(d, now));
    let covered = !keykeeper_two_step::requirements(user, conn).await?.is_empty();

    let mut check = if let Some(check) = open {
        check
    } else {
        {
            if !approvers && covered {
                err!(
                    "Your organization requires two-step login for your role, so this new device needs approval from a device where you're signed in, and none is. Sign in on a device you've used before.",
                    format!(
                        "New-device check: no device can approve for {}, and email codes don't count",
                        s.user.email
                    )
                )
            }
            if !approvers && !CONFIG.mail_enabled() {
                // Nothing can check it on a server that sends no email: it
                // goes through, as before this check, and the log says so.
                log_user_event_detail(
                    EventType::KeykeeperNewDeviceApproved,
                    user,
                    device.atype,
                    s.ip,
                    &format!(
                        "{}, with no device to approve it and no email to send a code to",
                        describe_device(device.atype, &device.name)
                    ),
                    conn,
                )
                .await;
                return Ok(Some(KnownDeviceToken::issue(user, &device.uuid, now, conn).await));
            }
            start(s.user, device, s.ip, now, conn).await?
        }
    };

    let token = check.new_token();
    settle_waiting(&mut check, s.user, now, conn).await;
    check.save(conn).await?;
    let state = state_json(&check, approvers, covered, now);
    let mut body = json!({
        "error": "invalid_grant",
        "error_description": NEW_DEVICE_MESSAGE,
        "ErrorModel": { "Message": NEW_DEVICE_MESSAGE, "Object": "error" },
        "KeykeeperNewDeviceCheck": state,
    });
    body["KeykeeperNewDeviceCheck"]["token"] = json!(token);
    err_json!(body, format!("New-device check for {}: waiting for approval", s.user.email))
}

/// Upstream's message for a sign-in its new device verification holds, so
/// upstream's clients keep the sign-in waiting as they do for that.
pub const NEW_DEVICE_MESSAGE: &str = "new device verification required";

/// A new check for this device: its number, and its time.
async fn start(
    user: &User,
    device: &Device,
    ip: &IpAddr,
    now: NaiveDateTime,
    conn: &DbConn,
) -> ApiResult<NewDeviceCheck> {
    NewDeviceCheck::delete_ended(now - TimeDelta::hours(AFTER_DELAY_HOURS), conn).await?;
    crate::ratelimit::check_limit_new_device_check(&user.uuid, &device.uuid)?;
    let waiting =
        NewDeviceCheck::find_by_user(&user.uuid, conn).await.into_iter().filter(|c| c.is_waiting(now)).count();
    if waiting >= MAX_WAITING {
        err_code!(
            "Too many sign-ins on new devices are waiting for approval for this account. Answer them, or wait 10 minutes.",
            429
        )
    }
    let check = NewDeviceCheck {
        uuid: crate::util::get_uuid(),
        user_uuid: user.uuid.clone(),
        device_uuid: device.uuid.clone(),
        device_type: device.atype,
        device_name: device.name.clone(),
        ip: ip.to_string(),
        token_hash: String::new(),
        number: new_number(),
        created_at: now,
        expires_at: now + TimeDelta::minutes(CHECK_MINUTES),
        approved_at: None,
        approved_how: None,
        approved_by: None,
        denied_at: None,
        denied_why: None,
        email_after: None,
        code_hash: None,
        code_sends: 0,
        code_tries: 0,
        used_at: None,
    };
    check.insert(conn).await?;
    log_user_event_detail(
        EventType::KeykeeperNewDeviceCheckStarted,
        &user.uuid,
        device.atype,
        ip,
        &describe_device(device.atype, &device.name),
        conn,
    )
    .await;
    Ok(check)
}

/// A number from 10 to 99, from the OS's random source, with no bias.
fn new_number() -> i32 {
    let low = 10u32.pow(NUMBER_DIGITS - 1);
    let span = 10u32.pow(NUMBER_DIGITS) - low;
    let limit = u32::MAX - (u32::MAX % span);
    loop {
        let n = u32::from_be_bytes(crate::crypto::get_random_bytes::<4>());
        if n < limit {
            return i32::try_from(low + n % span).expect("two digits");
        }
    }
}

/// The number as the person types it: exactly two digits.
fn typed_number(typed: &str) -> Option<i32> {
    let typed = typed.trim();
    (typed.len() == NUMBER_DIGITS as usize && typed.bytes().all(|b| b.is_ascii_digit()))
        .then(|| typed.parse().ok())
        .flatten()
}

fn is_code(otp: &str) -> bool {
    otp.len() == usize::from(CODE_DIGITS) && otp.bytes().all(|b| b.is_ascii_digit())
}

/// Whether a device can approve: a kind with the prompt (the web vault, the
/// extension, the desktop and phone apps; not the CLI or the SDK), that has
/// finished a sign-in, and was used recently enough that its session lasts.
pub fn can_approve(device: &Device, now: NaiveDateTime) -> bool {
    let phone = matches!(device.atype, 0 | 1 | 15);
    let kind = matches!(device.atype, 0..=20 | 26);
    let days = if phone {
        PHONE_APPROVER_DAYS
    } else {
        APPROVER_DAYS
    };
    kind && !device.is_new() && device.updated_at >= now - TimeDelta::days(days)
}

/// The device in words, from its kind, never from what the device calls
/// itself (anyone signing in chooses that), except our own apps' exact names.
pub fn describe_device(atype: i32, name: &str) -> String {
    let kind = DeviceType::from_i32(atype);
    let browser = || match kind.to_string().trim_end_matches(" Extension") {
        "Unknown Browser" => "a browser".to_owned(),
        b => b.to_owned(),
    };
    match atype {
        9..=14 | 17 | 18 | 26 => format!("Web vault in {}", browser()),
        2..=5 | 19 | 20 => format!("Extension in {}", browser()),
        0 | 1 | 6 | 7 | 8 | 15 => {
            const OURS: [&str; 5] = [
                "PassBundle on Windows",
                "PassBundle on macOS",
                "PassBundle on Linux",
                "PassBundle on Android",
                "PassBundle on iOS",
            ];
            if OURS.contains(&name) {
                name.to_owned()
            } else {
                match atype {
                    0 | 15 => "An app on Android".to_owned(),
                    1 => "An app on iOS".to_owned(),
                    6 => "An app on Windows".to_owned(),
                    7 => "An app on macOS".to_owned(),
                    _ => "An app on Linux".to_owned(),
                }
            }
        }
        16 => "An app on Windows".to_owned(),
        23 => "CLI on Windows".to_owned(),
        24 => "CLI on macOS".to_owned(),
        25 => "CLI on Linux".to_owned(),
        _ => "An unknown device".to_owned(),
    }
}

/// What the email option is now: "now" (a code can be sent), "later" (the
/// person may ask for one after the wait), "waiting" (asked; it can be sent
/// after `email_after`), or "never" (two-step login is required of them, or
/// the server sends no email and there's no wait to ask for).
fn email_state(check: &NewDeviceCheck, approvers: bool, covered: bool, now: NaiveDateTime) -> &'static str {
    if covered {
        "never"
    } else if let Some(after) = check.email_after {
        if after <= now {
            "now"
        } else {
            "waiting"
        }
    } else if !approvers {
        if CONFIG.mail_enabled() {
            "now"
        } else {
            "never"
        }
    } else {
        "later"
    }
}

/// On a server that sends no email, a wait that's over lets the sign-in
/// through without a code.
async fn settle_waiting(check: &mut NewDeviceCheck, user: &User, now: NaiveDateTime, conn: &DbConn) {
    if !CONFIG.mail_enabled() && check.is_waiting(now) && check.email_after.is_some_and(|after| after <= now) {
        check.approved_at = Some(now);
        check.approved_how = Some("waiting".to_owned());
        if let Ok(ip) = check.ip.parse::<IpAddr>() {
            log_user_event_detail(
                EventType::KeykeeperNewDeviceApproved,
                &user.uuid,
                check.device_type,
                &ip,
                &format!(
                    "{}, after a day's wait, on a server that sends no email",
                    describe_device(check.device_type, &check.device_name)
                ),
                conn,
            )
            .await;
        }
    }
}

/// What the new device is told about its check.
fn state_json(check: &NewDeviceCheck, approvers: bool, covered: bool, now: NaiveDateTime) -> Value {
    let status = if check.denied_at.is_some() {
        "denied"
    } else if check.approved_at.is_some() {
        "approved"
    } else {
        "waiting"
    };
    json!({
        "id": check.uuid,
        "number": format!("{:0width$}", check.number, width = NUMBER_DIGITS as usize),
        "status": status,
        "deniedWhy": check.denied_why,
        "expiresAt": format_date(&check.expires_at),
        "approvers": approvers,
        "email": email_state(check, approvers, covered, now),
        "emailAfter": check.email_after.as_ref().map(format_date),
        "codeSent": check.code_sends > 0,
        "object": "keykeeperNewDeviceCheck",
    })
}

async fn finish_with_code(
    check: &mut NewDeviceCheck,
    code: &str,
    user: &User,
    ip: &IpAddr,
    now: NaiveDateTime,
    conn: &DbConn,
) -> ApiResult<Option<String>> {
    let Some(hash) = check.code_hash.clone() else {
        err!("Ask for a code by email first.", "New-device check: a code, with none sent")
    };
    if check.approved_at.is_some() || check.code_tries >= MAX_CODE_TRIES {
        err!(
            "That code can't be used anymore. Sign in again to get a new one.",
            "New-device check: a code for a check that's done or out of tries"
        )
    }
    if !crate::crypto::ct_eq(hash, sso_hash(code)) {
        check.code_tries += 1;
        check.save(conn).await?;
        err!("That code didn't work. Check the email and try again.", "New-device check: a wrong code")
    }
    check.approved_at = Some(now);
    check.approved_how = Some("email".to_owned());
    check.used_at = Some(now);
    check.save(conn).await?;
    log_user_event_detail(
        EventType::KeykeeperNewDeviceApproved,
        &user.uuid,
        check.device_type,
        ip,
        &format!("{}, with a code by email", describe_device(check.device_type, &check.device_name)),
        conn,
    )
    .await;
    Ok(Some(KnownDeviceToken::issue(&user.uuid, &check.device_uuid, now, conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckToken {
    id: String,
    token: String,
}

/// The new device's check, by its id and token: the same 404 for one that
/// never was, has ended, or isn't this token's.
async fn own_check(data: &CheckToken, now: NaiveDateTime, conn: &DbConn) -> ApiResult<(NewDeviceCheck, User)> {
    let found = NewDeviceCheck::find(&data.id, conn).await;
    let Some(check) = found.filter(|c| c.expires_at > now && c.used_at.is_none() && c.token_matches(&data.token))
    else {
        err_code!("This sign-in has ended. Sign in again.", 404)
    };
    let Some(user) = User::find_by_uuid(&check.user_uuid, conn).await else {
        err_code!("This sign-in has ended. Sign in again.", 404)
    };
    Ok((check, user))
}

async fn approvers_for(check: &NewDeviceCheck, now: NaiveDateTime, conn: &DbConn) -> bool {
    Device::find_by_user(&check.user_uuid, conn)
        .await
        .iter()
        .any(|d| d.uuid != check.device_uuid && can_approve(d, now))
}

/// The new device asks how its check stands, every few seconds.
#[post("/keykeeper/new-device-check/status", data = "<data>")]
async fn status(data: Json<CheckToken>, ip: ClientIp, conn: DbConn) -> JsonResult {
    crate::ratelimit::check_limit_new_device_status(&ip.ip)?;
    let now = Utc::now().naive_utc();
    let (mut check, user) = own_check(&data, now, &conn).await?;
    let before = check.approved_at;
    settle_waiting(&mut check, &user, now, &conn).await;
    if check.approved_at != before {
        check.save(&conn).await?;
    }
    let covered = !keykeeper_two_step::requirements(&user.uuid, &conn).await?.is_empty();
    let approvers = approvers_for(&check, now, &conn).await;
    let mut state = state_json(&check, approvers, covered, now);
    if check.code_sends > 0 {
        state["emailTo"] = json!(obscure_email(&user.email));
    }
    Ok(Json(state))
}

/// "Email me a code", or "Can't use your other devices?": sends the code
/// when it may be sent now, or asks for one after the wait, which the
/// account's email and devices hear about at once.
#[post("/keykeeper/new-device-check/email", data = "<data>")]
async fn email(data: Json<CheckToken>, ip: ClientIp, conn: DbConn) -> JsonResult {
    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;
    let now = Utc::now().naive_utc();
    let (mut check, user) = own_check(&data, now, &conn).await?;
    if !check.is_waiting(now) {
        err!("This sign-in isn't waiting for approval anymore.")
    }
    let covered = !keykeeper_two_step::requirements(&user.uuid, &conn).await?.is_empty();
    let approvers = approvers_for(&check, now, &conn).await;
    let device = describe_device(check.device_type, &check.device_name);
    let check_ip: IpAddr = check.ip.parse().unwrap_or(ip.ip);
    match email_state(&check, approvers, covered, now) {
        "now" => {
            if !CONFIG.mail_enabled() {
                err!("This server can't send email.")
            }
            if check.code_sends >= MAX_CODE_SENDS {
                err_code!("A code was sent three times already. Check your email, or sign in again later.", 429)
            }
            let code = crate::crypto::generate_email_token(CODE_DIGITS);
            check.code_hash = Some(sso_hash(&code));
            check.code_sends += 1;
            check.code_tries = 0;
            check.save(&conn).await?;
            mail::send_new_device_check(&user.email, mail::NewDeviceMail::Code(&code), &device, &check.ip, &now)
                .await?;
        }
        "later" => {
            let waiting_elsewhere = NewDeviceCheck::find_by_user(&user.uuid, &conn)
                .await
                .iter()
                .any(|c| c.uuid != check.uuid && c.is_waiting(now) && c.email_after.is_some());
            if waiting_elsewhere {
                err_code!(
                    "Another sign-in on a new device is already waiting for a code by email. Wait for it, or deny it from a device where you're signed in.",
                    429
                )
            }
            let after = now + TimeDelta::hours(EMAIL_DELAY_HOURS);
            check.email_after = Some(after);
            check.expires_at = after + TimeDelta::hours(AFTER_DELAY_HOURS);
            check.save(&conn).await?;
            log_user_event_detail(
                EventType::KeykeeperNewDeviceEmailLater,
                &user.uuid,
                check.device_type,
                &check_ip,
                &device,
                &conn,
            )
            .await;
            if CONFIG.mail_enabled()
                && let Err(e) = mail::send_new_device_check(
                    &user.email,
                    mail::NewDeviceMail::Waiting {
                        email_after: &after,
                    },
                    &device,
                    &check.ip,
                    &now,
                )
                .await
            {
                error!("Error sending the new-device waiting email: {e:#?}");
            }
        }
        "waiting" => {}
        _ => err!("A code by email isn't available for this sign-in. Approve it from a device where you're signed in."),
    }
    let mut state = state_json(&check, approvers, covered, now);
    if check.code_sends > 0 {
        state["emailTo"] = json!(obscure_email(&user.email));
    }
    Ok(Json(state))
}

/// A signed-in session that may answer the account's checks: one that began
/// with the master password, single sign-on, or a device's approval, from a
/// device other than the new one. Not an API key's.
fn may_answer(signed_in: &SignInMethod) -> ApiResult<()> {
    if !signed_in.may_approve_new_device() {
        err!("Approve sign-ins from the web vault, the browser extension, or the PassBundle app.")
    }
    Ok(())
}

/// The account's checks waiting for an answer, for the prompt on its other
/// devices. Never the number: only the new device has it.
#[get("/keykeeper/new-device-checks")]
async fn list(headers: Headers, signed_in: SignInMethod, conn: DbConn) -> JsonResult {
    may_answer(&signed_in)?;
    let now = Utc::now().naive_utc();
    let checks = NewDeviceCheck::find_by_user(&headers.user.uuid, &conn).await;
    let data: Vec<Value> = checks
        .iter()
        .filter(|c| c.is_waiting(now) && c.device_uuid != headers.device.uuid)
        .map(|c| {
            json!({
                "id": c.uuid,
                "device": describe_device(c.device_type, &c.device_name),
                "deviceType": c.device_type,
                "ipAddress": c.ip,
                "location": crate::keykeeper_location::describe(&c.ip),
                "creationDate": format_date(&c.created_at),
                "expirationDate": format_date(&c.expires_at),
                "emailAfter": c.email_after.as_ref().map(format_date),
                "object": "keykeeperNewDeviceCheckRequest",
            })
        })
        .collect();
    Ok(Json(json!({
        "data": data,
        "locationSource": crate::keykeeper_location::attribution(),
        "serverDate": format_date(&now),
        "object": "list",
    })))
}

/// One of the account's checks still waiting, from another of its devices.
async fn waiting_check(id: &str, headers: &Headers, now: NaiveDateTime, conn: &DbConn) -> ApiResult<NewDeviceCheck> {
    let found = NewDeviceCheck::find(id, conn).await;
    let Some(check) =
        found.filter(|c| c.user_uuid == headers.user.uuid && c.is_waiting(now) && c.device_uuid != headers.device.uuid)
    else {
        err_code!("This sign-in has ended or was answered", 404)
    };
    Ok(check)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Answer {
    number: Option<String>,
}

/// Approve: the number typed must be the new device's. A wrong one denies
/// it at once: each check takes one try. No number, or anything but two
/// digits, changes nothing.
#[post("/keykeeper/new-device-checks/<id>/approve", data = "<data>")]
async fn approve(id: &str, data: Json<Answer>, headers: Headers, signed_in: SignInMethod, conn: DbConn) -> JsonResult {
    may_answer(&signed_in)?;
    let Some(typed) = data.number.as_deref().and_then(typed_number) else {
        err!("Type the two-digit number shown on the new device.")
    };
    let now = Utc::now().naive_utc();
    let mut check = waiting_check(id, &headers, now, &conn).await?;
    if typed != check.number {
        deny_check(&mut check, "number", &headers, now, &conn).await?;
        return Ok(Json(json!({ "approved": false, "denied": true, "deniedWhy": "number" })));
    }
    check.approved_at = Some(now);
    check.approved_how = Some("device".to_owned());
    check.approved_by = Some(headers.device.uuid.to_string());
    check.save(&conn).await?;
    log_user_event_detail(
        EventType::KeykeeperNewDeviceApproved,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &format!("{}, from {}", describe_device(check.device_type, &check.device_name), check.ip),
        &conn,
    )
    .await;
    Ok(Json(json!({ "approved": true, "denied": false })))
}

#[post("/keykeeper/new-device-checks/<id>/deny")]
async fn deny(id: &str, headers: Headers, signed_in: SignInMethod, conn: DbConn) -> JsonResult {
    may_answer(&signed_in)?;
    let now = Utc::now().naive_utc();
    let mut check = waiting_check(id, &headers, now, &conn).await?;
    deny_check(&mut check, "denied", &headers, now, &conn).await?;
    Ok(Json(json!({ "approved": false, "denied": true, "deniedWhy": "denied" })))
}

/// Denies a check: the new device hears it, the account's email gets why,
/// and the event log has it.
async fn deny_check(
    check: &mut NewDeviceCheck,
    why: &str,
    headers: &Headers,
    now: NaiveDateTime,
    conn: &DbConn,
) -> ApiResult<()> {
    check.denied_at = Some(now);
    check.denied_why = Some(why.to_owned());
    check.save(conn).await?;
    let device = describe_device(check.device_type, &check.device_name);
    log_user_event_detail(
        EventType::KeykeeperNewDeviceDenied,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &format!(
            "{device}, from {}: {}",
            check.ip,
            if why == "number" {
                "a wrong number"
            } else {
                "denied"
            }
        ),
        conn,
    )
    .await;
    if CONFIG.mail_enabled()
        && let Err(e) = mail::send_new_device_check(
            &headers.user.email,
            mail::NewDeviceMail::Denied {
                wrong_number: why == "number",
            },
            &device,
            &check.ip,
            &check.created_at,
        )
        .await
    {
        error!("Error sending the new-device denied email: {e:#?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::{DeviceId, UserId};

    fn device(atype: i32, finished: bool, days_ago: i64, now: NaiveDateTime) -> Device {
        let mut d = Device::new(DeviceId::from("d".to_owned()), UserId::from("u".to_owned()), "name".into(), atype);
        d.created_at = now - TimeDelta::days(days_ago + 1);
        d.updated_at = if finished {
            now - TimeDelta::days(days_ago)
        } else {
            d.created_at
        };
        d
    }

    fn check(now: NaiveDateTime) -> NewDeviceCheck {
        NewDeviceCheck {
            uuid: "c".into(),
            user_uuid: UserId::from("u".to_owned()),
            device_uuid: DeviceId::from("new".to_owned()),
            device_type: 10,
            device_name: "firefox".into(),
            ip: "203.0.113.7".into(),
            token_hash: String::new(),
            number: 47,
            created_at: now,
            expires_at: now + TimeDelta::minutes(CHECK_MINUTES),
            approved_at: None,
            approved_how: None,
            approved_by: None,
            denied_at: None,
            denied_why: None,
            email_after: None,
            code_hash: None,
            code_sends: 0,
            code_tries: 0,
            used_at: None,
        }
    }

    #[test]
    fn the_number_is_two_digits_from_10_to_99() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..5000 {
            let n = new_number();
            assert!((10..=99).contains(&n), "{n}");
            seen.insert(n);
        }
        // Every value turns up, so none is left out.
        assert_eq!(seen.len(), 90);
    }

    #[test]
    fn only_two_digits_typed_count_as_an_answer() {
        assert_eq!(typed_number("47"), Some(47));
        assert_eq!(typed_number(" 47 "), Some(47));
        for nothing in ["", " ", "4", "470", "4a", "-7", "+47", "٤٧", "47.0"] {
            assert_eq!(typed_number(nothing), None, "{nothing:?}");
        }
    }

    #[test]
    fn an_emailed_code_is_eight_digits() {
        assert!(is_code("12345678"));
        assert!(!is_code("1234567"));
        assert!(!is_code("abcdefgh"));
        // The check's own token is never taken for a code.
        assert!(!is_code(&crate::db::models::sso_random()));
    }

    #[test]
    fn the_token_is_kept_only_as_its_hash() {
        let now = Utc::now().naive_utc();
        let mut c = check(now);
        let token = c.new_token();
        assert_eq!(token.len(), 43);
        assert_ne!(c.token_hash, token);
        assert!(c.token_matches(&token));
        let other = c.clone().new_token();
        assert!(!c.token_matches(&other));
        // A new token replaces the old one.
        let newer = c.new_token();
        assert!(c.token_matches(&newer));
        assert!(!c.token_matches(&token));
    }

    #[test]
    fn a_check_ends_when_its_time_is_up_or_its_answered() {
        let now = Utc::now().naive_utc();
        let c = check(now);
        assert!(c.is_waiting(now));
        assert!(c.is_waiting(now + TimeDelta::minutes(CHECK_MINUTES) - TimeDelta::seconds(1)));
        assert!(!c.is_open(now + TimeDelta::minutes(CHECK_MINUTES)));
        let mut denied = c.clone();
        denied.denied_at = Some(now);
        assert!(!denied.is_open(now));
        let mut approved = c;
        approved.approved_at = Some(now);
        assert!(approved.is_open(now) && !approved.is_waiting(now));
        approved.used_at = Some(now);
        assert!(!approved.is_open(now));
    }

    #[test]
    fn which_devices_can_approve() {
        let now = Utc::now().naive_utc();
        // The web vault, the extension, the apps; finished, and recent.
        for atype in [9, 10, 12, 17, 2, 3, 20, 6, 7, 8, 0, 1] {
            assert!(can_approve(&device(atype, true, 1, now), now), "{atype}");
        }
        // Not the CLI, the SDK, or a server.
        for atype in [21, 22, 23, 24, 25] {
            assert!(!can_approve(&device(atype, true, 1, now), now), "{atype}");
        }
        // Not one that never finished a sign-in.
        assert!(!can_approve(&device(9, false, 0, now), now));
        // Unused for 30 days (90 for a phone): its session has ended.
        assert!(can_approve(&device(9, true, 29, now), now));
        assert!(!can_approve(&device(9, true, 31, now), now));
        assert!(can_approve(&device(0, true, 89, now), now));
        assert!(!can_approve(&device(0, true, 91, now), now));
    }

    #[test]
    fn the_email_code_is_offered_now_later_or_never() {
        let now = Utc::now().naive_utc();
        let c = check(now);
        // Two-step login is required of them: never.
        assert_eq!(email_state(&c, false, true, now), "never");
        assert_eq!(email_state(&c, true, true, now), "never");
        // A device can approve: only after the wait.
        assert_eq!(email_state(&c, true, false, now), "later");
        let mut asked = c;
        asked.email_after = Some(now + TimeDelta::hours(EMAIL_DELAY_HOURS));
        assert_eq!(email_state(&asked, true, false, now), "waiting");
        assert_eq!(email_state(&asked, true, false, now + TimeDelta::hours(EMAIL_DELAY_HOURS)), "now");
    }

    #[test]
    fn the_device_is_described_by_its_kind_not_its_name() {
        assert_eq!(describe_device(10, "firefox"), "Web vault in Firefox");
        assert_eq!(describe_device(14, "whatever"), "Web vault in a browser");
        assert_eq!(describe_device(2, "chrome"), "Extension in Chrome");
        assert_eq!(describe_device(5, "edge"), "Extension in Edge");
        assert_eq!(describe_device(6, "PassBundle on Windows"), "PassBundle on Windows");
        assert_eq!(describe_device(0, "PassBundle on Android"), "PassBundle on Android");
        // Whatever a new device calls itself never reaches the prompt.
        assert_eq!(describe_device(6, "Your work laptop"), "An app on Windows");
        assert_eq!(describe_device(9, "Your work laptop"), "Web vault in Chrome");
        assert_eq!(describe_device(25, "linux"), "CLI on Linux");
        assert_eq!(describe_device(21, "sdk"), "An unknown device");
    }
}

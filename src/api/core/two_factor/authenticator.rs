use data_encoding::BASE32;
use rocket::{Route, serde::json::Json};

use crate::{
    api::{
        EmptyResult, JsonResult, PasswordOrOtpData,
        core::keykeeper_two_step::{SetupHeaders, finish_setup},
        core::log_user_event,
        core::two_factor::generate_recover_code,
    },
    auth::{ClientIp, Headers, two_factor},
    crypto,
    db::{
        DbConn,
        models::{EventType, TwoFactor, TwoFactorType, UserId},
    },
    util::NumberOrString,
};

pub use crate::config::CONFIG;

pub fn routes() -> Vec<Route> {
    routes![generate_authenticator, activate_authenticator, activate_authenticator_put, disable_authenticator]
}

// Keykeeper: the setup endpoints also take a setup session (SetupHeaders),
// which a sign-in gets when the person's role requires two-step login and
// they haven't set it up (DESIGN.md, "Two-step login for admins").
#[post("/two-factor/get-authenticator", data = "<data>")]
async fn generate_authenticator(data: Json<PasswordOrOtpData>, headers: SetupHeaders, conn: DbConn) -> JsonResult {
    let user = headers.user;

    data.validate(&user, false, &conn).await?;

    let twofactor = TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::Authenticator, &conn).await;

    let (enabled, key) = match twofactor {
        Some(tf) => (true, tf.data),
        _ => (false, crypto::encode_random_bytes::<20>(&BASE32)),
    };

    Ok(Json(json!({
        "authenticator": json!({
            "enabled": enabled,
            "key": key,
        }),
        "userVerificationToken": two_factor::authenticator_token(user.uuid, key, enabled),
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnableAuthenticatorData {
    key: String,
    token: NumberOrString,
    user_verification_token: String,
}

#[post("/two-factor/authenticator", data = "<data>")]
async fn activate_authenticator(
    data: Json<EnableAuthenticatorData>,
    headers: SetupHeaders,
    conn: DbConn,
) -> JsonResult {
    let data: EnableAuthenticatorData = data.into_inner();
    let key = data.key;
    let token = data.token.into_string();

    let mut user = headers.user;

    two_factor::validate_authenticator(&data.user_verification_token, &user.uuid, &key, false)?;

    // Validate key as base32 and 20 bytes length
    let decoded_key: Vec<u8> = if let Ok(decoded) = BASE32.decode(key.as_bytes()) {
        decoded
    } else {
        err!("Invalid totp secret")
    };

    if decoded_key.len() != 20 {
        err!("Invalid key length")
    }

    // Validate the token provided with the key, and save new twofactor
    validate_totp_code(&user.uuid, &token, &key.to_uppercase(), &headers.ip, &conn).await?;

    generate_recover_code(&mut user, &conn).await;

    log_user_event(EventType::UserUpdated2fa, &user.uuid, headers.device_type, &headers.ip.ip, &conn).await;

    let mut answer = json!({
        "authenticator": json!({
            "enabled": true,
            "key": key,
        }),
    });
    // Keykeeper: a setup session ends here.
    finish_setup(headers.session.as_ref(), &mut user, &mut answer, &conn).await?;
    Ok(Json(answer))
}

#[put("/two-factor/authenticator", data = "<data>")]
async fn activate_authenticator_put(
    data: Json<EnableAuthenticatorData>,
    headers: SetupHeaders,
    conn: DbConn,
) -> JsonResult {
    activate_authenticator(data, headers, conn).await
}

pub async fn validate_totp_code_str(
    user_id: &UserId,
    totp_code: &str,
    secret: &str,
    ip: &ClientIp,
    conn: &DbConn,
) -> EmptyResult {
    if !totp_code.chars().all(char::is_numeric) {
        err!("TOTP code is not a number");
    }

    validate_totp_code(user_id, totp_code, secret, ip, conn).await
}

pub async fn validate_totp_code(
    user_id: &UserId,
    totp_code: &str,
    secret: &str,
    ip: &ClientIp,
    conn: &DbConn,
) -> EmptyResult {
    use totp_lite::{Sha1, totp_custom};

    let Ok(decoded_secret) = BASE32.decode(secret.as_bytes()) else {
        err!("Invalid TOTP secret")
    };

    let mut twofactor = match TwoFactor::find_by_user_and_type(user_id, TwoFactorType::Authenticator, conn).await {
        Some(tf) => tf,
        _ => TwoFactor::new(user_id.clone(), TwoFactorType::Authenticator, secret.to_owned()),
    };

    // The amount of steps back and forward in time
    // Also check if we need to disable time drifted TOTP codes.
    // If that is the case, we set the steps to 0 so only the current TOTP is valid.
    let steps = i64::from(!CONFIG.authenticator_disable_time_drift());

    // Get the current system time in UNIX Epoch (UTC)
    let current_time = chrono::Utc::now();
    let current_timestamp = current_time.timestamp();

    for step in -steps..=steps {
        let time_step = current_timestamp / 30i64 + step;

        // We need to calculate the time offsite and cast it as an u64.
        // Since we only have times into the future and the totp generator needs an u64 instead of the default i64.
        let time: u64 = (current_timestamp + step * 30i64).cast_unsigned();
        let generated = totp_custom::<Sha1>(30, 6, &decoded_secret, time);

        // Check the given code equals the generated and if the time_step is larger then the one last used.
        if generated == totp_code && time_step > twofactor.last_used {
            // If the step does not equals 0 the time is drifted either server or client side.
            if step != 0 {
                warn!("TOTP Time drift detected. The step offset is {step}");
            }

            // Save the last used time step so only totp time steps higher then this one are allowed.
            // This will also save a newly created twofactor if the code is correct.
            twofactor.last_used = time_step;
            twofactor.save(conn).await?;
            return Ok(());
        } else if generated == totp_code && time_step <= twofactor.last_used {
            warn!("This TOTP or a TOTP code within {steps} steps back or forward has already been used!");
            err!(
                format!("Invalid TOTP code! Server time: {} IP: {}", current_time.format("%F %T UTC"), ip.ip),
                ErrorEvent {
                    event: EventType::UserFailedLogIn2fa
                }
            );
        }
    }

    // Else no valid code received, deny access
    err!(
        format!("Invalid TOTP code! Server time: {} IP: {}", current_time.format("%F %T UTC"), ip.ip),
        ErrorEvent {
            event: EventType::UserFailedLogIn2fa
        }
    );
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DisableAuthenticatorData {
    key: String,
    user_verification_token: String,
}

#[delete("/two-factor/authenticator", data = "<data>")]
async fn disable_authenticator(data: Json<DisableAuthenticatorData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let user = headers.user;

    two_factor::validate_authenticator(&data.user_verification_token, &user.uuid, &data.key, true)?;
    // Keykeeper: their last method that counts for two-step login for admins
    // may go, which ends their sessions.
    let watch = crate::api::core::keykeeper_two_step::Watch::user(&user.uuid, &conn).await?;

    if let Some(twofactor) = TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::Authenticator, &conn).await {
        if twofactor.data == data.key {
            twofactor.delete(&conn).await?;
            log_user_event(EventType::UserDisabled2fa, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await;
        } else {
            err!(format!("TOTP key for user {} does not match recorded value, cannot deactivate", &user.email));
        }
    }

    super::check_2fa_state(&user, headers.device.atype, &headers.ip.ip, &conn).await?;
    watch.settle(&conn).await?;

    Ok(())
}

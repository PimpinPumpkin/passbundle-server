use chrono::Utc;
use rocket::{Route, serde::json::Json};

use crate::{
    api::{
        ApiResult, EmptyResult, JsonResult, PasswordOrOtpData,
        core::keykeeper_two_step::{SetupHeaders, finish_setup},
        core::log_user_event,
        core::two_factor::{VerificationTokenData, generate_recover_code},
    },
    auth::{Headers, two_factor, two_factor::DuoData},
    crypto,
    db::{
        DbConn,
        models::{EventType, TwoFactor, TwoFactorType, User, UserId},
    },
    error::MapResult,
    http_client::make_http_request,
};

pub fn routes() -> Vec<Route> {
    routes![get_duo, activate_duo, activate_duo_put, disable_duo,]
}

enum DuoStatus {
    Global(DuoData),
    // Using the global duo config
    User(DuoData),
    // Using the user's config
    Disabled(bool), // True if there is a global setting
}

impl DuoStatus {
    fn data(self) -> Option<DuoData> {
        match self {
            DuoStatus::Global(data) | DuoStatus::User(data) => Some(data),
            DuoStatus::Disabled(_) => None,
        }
    }
}

const DISABLED_MESSAGE_DEFAULT: &str = "<To use the global Duo keys, please leave these fields untouched>";

// Keykeeper: the setup endpoints also take a setup session (SetupHeaders),
// which a sign-in gets when the person's role requires two-step login and
// they haven't set it up (DESIGN.md, "Two-step login for admins").
#[post("/two-factor/get-duo", data = "<data>")]
async fn get_duo(data: Json<PasswordOrOtpData>, headers: SetupHeaders, conn: DbConn) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &conn).await?;

    let (enabled, duo) = match get_user_duo_data(&user.uuid, &conn).await {
        DuoStatus::Global(_) => (true, Some(DuoData::secret())),
        DuoStatus::User(data) => (true, Some(data.obscure())),
        DuoStatus::Disabled(true) => (false, Some(DuoData::msg(DISABLED_MESSAGE_DEFAULT))),
        DuoStatus::Disabled(false) => (false, None),
    };

    let duo_json = if let Some(data) = duo.as_ref() {
        json!({
            "enabled": enabled,
            "host": data.host,
            "clientSecret": data.sk,
            "clientId": data.ik,
        })
    } else {
        json!({
            "enabled": enabled,
            "host": null,
            "clientSecret": null,
            "clientId": null,
        })
    };

    Ok(Json(rocket::serde::json::json!({
        "duo": duo_json,
        "userVerificationToken": two_factor::duo_token(user.uuid, duo, enabled),
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnableDuoData {
    host: String,
    client_secret: String,
    client_id: String,
    user_verification_token: String,
}

impl From<EnableDuoData> for DuoData {
    fn from(d: EnableDuoData) -> Self {
        Self {
            host: d.host,
            ik: d.client_id,
            sk: d.client_secret,
        }
    }
}

fn check_duo_fields_custom(data: &EnableDuoData) -> bool {
    fn empty_or_default(s: &str) -> bool {
        let st = s.trim();
        st.is_empty() || s == DISABLED_MESSAGE_DEFAULT
    }

    !empty_or_default(&data.host) && !empty_or_default(&data.client_secret) && !empty_or_default(&data.client_id)
}

#[post("/two-factor/duo", data = "<data>")]
async fn activate_duo(data: Json<EnableDuoData>, headers: SetupHeaders, conn: DbConn) -> JsonResult {
    let data: EnableDuoData = data.into_inner();
    let mut user = headers.user;

    two_factor::validate_duo(&data.user_verification_token, &user.uuid, None, false)?;

    // Keykeeper: two-step login for admins counts Duo only with this
    // server's own Duo account, so a setup session sets up no other; and
    // replacing it with one's own may take someone's last method that counts.
    if headers.session.is_some() {
        if check_duo_fields_custom(&data) {
            err!(
                "Two-step login for your role counts Duo only with this server's own Duo account. Leave the Duo fields empty to use it."
            )
        }
        if !super::has_global_duo_credentials() {
            err!(
                "This server has no Duo account of its own, so Duo doesn't count for your role. Choose another method."
            )
        }
    }
    let watch = crate::api::core::keykeeper_two_step::Watch::user(&user.uuid, &conn).await?;

    let (data, data_str) = if check_duo_fields_custom(&data) {
        let data_req: DuoData = data.into();
        let data_str = serde_json::to_string(&data_req)?;
        duo_api_request("GET", "/auth/v2/check", "", &data_req).await.map_res("Failed to validate Duo credentials")?;
        (data_req.obscure(), data_str)
    } else {
        (DuoData::secret(), String::new())
    };

    let type_ = TwoFactorType::Duo;
    let twofactor = TwoFactor::new(user.uuid.clone(), type_, data_str);
    twofactor.save(&conn).await?;

    generate_recover_code(&mut user, &conn).await;

    log_user_event(EventType::UserUpdated2fa, &user.uuid, headers.device_type, &headers.ip.ip, &conn).await;

    let mut answer = json!({
        "duo": json!({
            "enabled": true,
            "host": data.host,
            "clientSecret": data.sk,
            "clientId": data.ik,
        }),
    });
    // Keykeeper: a setup session ends here.
    finish_setup(headers.session.as_ref(), &mut user, &mut answer, &conn).await?;
    watch.settle(&conn).await?;
    Ok(Json(answer))
}

#[put("/two-factor/duo", data = "<data>")]
async fn activate_duo_put(data: Json<EnableDuoData>, headers: SetupHeaders, conn: DbConn) -> JsonResult {
    activate_duo(data, headers, conn).await
}

#[delete("/two-factor/duo", data = "<data>")]
async fn disable_duo(data: Json<VerificationTokenData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let user = headers.user;
    // Keykeeper: their last method that counts for two-step login for admins
    // may go, which ends their sessions.
    let watch = crate::api::core::keykeeper_two_step::Watch::user(&user.uuid, &conn).await?;

    if let Some(twofactor) = TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::Duo, &conn).await {
        // Apply the same transformation than in `get_duo` to check we are disabling the correct one
        let duo = match to_user_duo_data(&twofactor) {
            DuoStatus::Global(_) => Some(DuoData::secret()),
            DuoStatus::User(data) => Some(data.obscure()),
            DuoStatus::Disabled(_) => None,
        };

        two_factor::validate_duo(&data.user_verification_token, &user.uuid, duo.as_ref(), true)?;

        twofactor.delete(&conn).await?;
        log_user_event(EventType::UserDisabled2fa, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await;
    }

    super::check_2fa_state(&user, headers.device.atype, &headers.ip.ip, &conn).await?;
    watch.settle(&conn).await?;

    Ok(())
}

async fn duo_api_request(method: &str, path: &str, params: &str, data: &DuoData) -> EmptyResult {
    use reqwest::{Method, header};
    use std::str::FromStr;

    // https://duo.com/docs/authapi#api-details
    let url = format!("https://{}{path}", data.host);
    let dt = Utc::now().to_rfc2822();
    let username = &data.ik;
    let fields = [&dt, method, &data.host, path, params];
    let password = crypto::hmac_sign(&data.sk, &fields.join("\n"));

    let m = Method::from_str(method).unwrap_or_default();

    make_http_request(m, &url)?
        .basic_auth(username, Some(password))
        .header(header::USER_AGENT, "vaultwarden:Duo/1.0 (Rust)")
        .header(header::DATE, dt)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

async fn get_user_duo_data(user_id: &UserId, conn: &DbConn) -> DuoStatus {
    // If the user doesn't have an entry, disabled
    let Some(twofactor) = TwoFactor::find_by_user_and_type(user_id, TwoFactorType::Duo, conn).await else {
        return DuoStatus::Disabled(DuoData::global().is_some());
    };

    to_user_duo_data(&twofactor)
}

fn to_user_duo_data(twofactor: &TwoFactor) -> DuoStatus {
    // If the user has the required values, we use those
    if let Ok(data) = serde_json::from_str(&twofactor.data) {
        return DuoStatus::User(data);
    }

    // Otherwise, we try to use the globals
    if let Some(global) = DuoData::global() {
        return DuoStatus::Global(global);
    }

    // If there are no globals configured, just disable it
    DuoStatus::Disabled(false)
}

// let (ik, sk, host) = get_duo_keys_email();
pub(crate) async fn get_duo_keys_email(email: &str, conn: &DbConn) -> ApiResult<(String, String, String)> {
    let data = match User::find_by_mail(email, conn).await {
        Some(u) => get_user_duo_data(&u.uuid, conn).await.data(),
        _ => DuoData::global(),
    }
    .map_res("Can't fetch Duo Keys")?;

    Ok((data.ik, data.sk, data.host))
}

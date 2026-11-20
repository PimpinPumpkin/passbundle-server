// Keykeeper: push to phones over UnifiedPush. When an account has a sign-in
// waiting for an answer (a "Sign in with a device" request, or a new-device
// check), the server tells the account's phones that have an endpoint, so a
// phone prompts while PassBundle is closed. A message says only its kind,
// encrypted to the phone's own keys (webpush.rs), and goes from a task of its
// own: a push service that's slow, down, or refused never delays or fails the
// request that caused it. The endpoint is an address a client gave, so it's
// guarded (guard.rs). See DESIGN.md, "Push to phones", in the meta repo.

pub mod guard;
pub mod webpush;

use std::{
    num::NonZeroU32,
    sync::{Arc, LazyLock, OnceLock},
    time::Duration,
};

use chrono::Utc;
use data_encoding::BASE64URL_NOPAD;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use reqwest::{
    Client, StatusCode,
    header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE},
};
use tokio::task::JoinHandle;

use crate::{
    CONFIG,
    db::{
        DbPool,
        models::{DeviceId, MAX_PUSH_ENDPOINTS_PER_ACCOUNT, PushEndpoint, UserId},
    },
};

use self::{guard::Policy, webpush::Vapid};

/// What a message says. Nothing else is ever in one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The account has a sign-in waiting for an answer: a "Sign in with a
    /// device" request or a new-device check.
    SignIn,
}

impl Kind {
    pub fn payload(self) -> &'static [u8] {
        match self {
            Self::SignIn => br#"{"kind":"sign-in"}"#,
        }
    }

    /// RFC 8030's Topic: a push service keeps only the newest undelivered
    /// message of a topic.
    fn topic(self) -> &'static str {
        match self {
            Self::SignIn => "sign-in",
        }
    }

    /// How long the push service keeps it: a request lasts 15 minutes, a
    /// new-device check 10.
    fn ttl(self) -> u32 {
        match self {
            Self::SignIn => 900,
        }
    }
}

/// The most messages a minute to one device; more are dropped.
pub const PER_DEVICE_PER_MINUTE: u32 = 10;
/// The most messages a minute to one account's devices, all of them
/// together; more are dropped: two sign-in requests a minute reach every
/// one of its endpoints (at most `MAX_PUSH_ENDPOINTS_PER_ACCOUNT`).
pub const PER_ACCOUNT_PER_MINUTE: u32 = 2 * MAX_PUSH_ENDPOINTS_PER_ACCOUNT;
/// How long the VAPID JWT is good for (RFC 8292 allows up to 24 hours).
const JWT_HOURS: i64 = 12;

/// The VAPID key file, beside the RSA key.
pub const VAPID_FILE: &str = "vapid_key.pem";

static VAPID: OnceLock<Vapid> = OnceLock::new();
static POOL: OnceLock<DbPool> = OnceLock::new();

/// Reads the server's VAPID key, or makes it on the first start, beside the
/// RSA key (its folder or bucket): called once, by auth::initialize_keys.
pub async fn init_vapid(operator: &opendal::Operator) -> Result<(), crate::Error> {
    let pem = match operator.read(VAPID_FILE).await {
        Ok(buffer) => buffer.to_vec(),
        Err(e) if e.kind() == opendal::ErrorKind::NotFound => {
            let pem = Vapid::generate_pem().map_err(std::io::Error::other)?;
            operator.write(VAPID_FILE, pem.clone()).await?;
            info!("Push key '{VAPID_FILE}' created beside the private key");
            pem
        }
        Err(e) => return Err(e.into()),
    };
    let vapid = Vapid::from_pem(&pem).map_err(std::io::Error::other)?;
    // A second call (tests) keeps the first key.
    drop(VAPID.set(vapid));
    Ok(())
}

/// The server's VAPID public key, base64url, once it's loaded.
pub fn vapid_public_key() -> Option<String> {
    VAPID.get().map(Vapid::public_key)
}

/// Lets push reach the database from its own tasks: called once at start.
pub fn start(pool: DbPool) {
    drop(POOL.set(pool));
}

/// Sends messages: the guarded client, where push may go, and the VAPID key.
pub struct Pusher {
    client: Client,
    policy: Policy,
    vapid: &'static Vapid,
    /// The VAPID `sub`: how a push service reaches the server's operator.
    subject: String,
    limiter: RateLimiter<[u8; 32], DashMapStateStore<[u8; 32]>, DefaultClock>,
    account_limiter: RateLimiter<[u8; 32], DashMapStateStore<[u8; 32]>, DefaultClock>,
}

/// What came of one message.
#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    Sent,
    /// The push service no longer has the endpoint (404 or 410).
    Gone,
    /// Over the device's or the account's limit: not sent.
    Limited,
    /// Anything else: refused here, unreachable, or another answer.
    Failed(String),
}

impl Delivery {
    pub fn of_status(status: StatusCode) -> Self {
        if status.is_success() {
            Self::Sent
        } else if status == StatusCode::NOT_FOUND || status == StatusCode::GONE {
            Self::Gone
        } else if status.is_redirection() {
            Self::Failed(format!("{status}: redirects aren't followed"))
        } else {
            Self::Failed(status.to_string())
        }
    }
}

impl Pusher {
    /// A pusher with this client's settings: where push may go, and, for
    /// tests only, the one certificate authority it trusts.
    pub fn new(
        policy: Policy,
        ca_pem: Option<&str>,
        vapid: &'static Vapid,
        subject: String,
        timeout: Duration,
    ) -> Result<Self, String> {
        let mut builder = Client::builder()
            .user_agent(format!("PassBundle push/{}", crate::VERSION.unwrap_or("dev")))
            .dns_resolver(Arc::new(guard::Resolver(policy.clone())))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .connect_timeout(Duration::from_secs(5).min(timeout))
            .timeout(timeout)
            .pool_idle_timeout(Duration::from_secs(30));
        if let Some(pem) = ca_pem {
            let certs = reqwest::Certificate::from_pem_bundle(pem.as_bytes())
                .map_err(|_| "UNIFIED_PUSH_TEST_ONLY_CA_FILE isn't a PEM certificate".to_owned())?;
            builder = builder.tls_certs_only(certs);
        }
        let client = builder.build().map_err(|e| format!("Couldn't set up HTTPS for push: {e}"))?;
        let per_minute = NonZeroU32::new(PER_DEVICE_PER_MINUTE).expect("non-zero");
        let per_account = NonZeroU32::new(PER_ACCOUNT_PER_MINUTE).expect("non-zero");
        Ok(Self {
            client,
            policy,
            vapid,
            subject,
            limiter: RateLimiter::keyed(Quota::per_minute(per_minute)),
            account_limiter: RateLimiter::keyed(Quota::per_minute(per_account)),
        })
    }

    /// The server's pusher, from its settings; none while push is off or the
    /// keys aren't loaded.
    pub fn current() -> Option<Arc<Self>> {
        static CURRENT: LazyLock<Option<Arc<Pusher>>> = LazyLock::new(|| {
            let vapid = VAPID.get()?;
            let ca = if CONFIG.unified_push_test_only_allow_private_addresses() {
                CONFIG.unified_push_test_only_ca_file().and_then(|path| match std::fs::read_to_string(&path) {
                    Ok(pem) => Some(pem),
                    Err(e) => {
                        error!("Couldn't read UNIFIED_PUSH_TEST_ONLY_CA_FILE {path}: {e}");
                        None
                    }
                })
            } else {
                None
            };
            match Pusher::new(Policy::current(), ca.as_deref(), vapid, CONFIG.domain_origin(), Duration::from_secs(10))
            {
                Ok(p) => Some(Arc::new(p)),
                Err(e) => {
                    error!("Push to phones is off: {e}");
                    None
                }
            }
        });
        if !CONFIG.unified_push_enabled() {
            return None;
        }
        CURRENT.clone()
    }

    /// Whether a message to this endpoint is over a limit: the device's, or
    /// the account's, across all its endpoints.
    fn limited(&self, endpoint: &PushEndpoint) -> bool {
        let key = |parts: &[&str]| {
            let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
            for (i, part) in parts.iter().enumerate() {
                if i > 0 {
                    ctx.update(&[0]);
                }
                ctx.update(part.as_bytes());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(ctx.finish().as_ref());
            key
        };
        let user = endpoint.user_uuid.to_string();
        let device = endpoint.device_uuid.to_string();
        // The device's first: a device over its own limit doesn't use up
        // the account's.
        self.limiter.check_key(&key(&[&user, &device])).is_err()
            || self.account_limiter.check_key(&key(&[&user])).is_err()
    }

    /// Encrypts one message to the endpoint's keys and posts it. The answer
    /// is never read past its status.
    pub async fn deliver(&self, endpoint: &PushEndpoint, kind: Kind) -> Delivery {
        if self.limited(endpoint) {
            return Delivery::Limited;
        }
        // Checked again: the server's settings may have changed since.
        let url = match guard::checked_url(&endpoint.endpoint, &self.policy) {
            Ok(u) => u,
            Err(e) => return Delivery::Failed(e),
        };
        let (Ok(public), Ok(auth)) =
            (BASE64URL_NOPAD.decode(endpoint.public_key.as_bytes()), BASE64URL_NOPAD.decode(endpoint.auth.as_bytes()))
        else {
            return Delivery::Failed("The endpoint's keys aren't base64url".into());
        };
        let body = match webpush::encrypt(&public, &auth, kind.payload()) {
            Ok(b) => b,
            Err(e) => return Delivery::Failed(e),
        };
        let audience = url.origin().ascii_serialization();
        let exp = Utc::now().timestamp() + JWT_HOURS * 3600;
        let authorization = match self.vapid.authorization(&audience, &self.subject, exp) {
            Ok(a) => a,
            Err(e) => return Delivery::Failed(e),
        };
        let sent = self
            .client
            .post(url)
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_ENCODING, "aes128gcm")
            .header("TTL", kind.ttl().to_string())
            .header("Urgency", "high")
            .header("Topic", kind.topic())
            .body(body)
            .send()
            .await;
        match sent {
            Ok(response) => Delivery::of_status(response.status()),
            // Without the URL: it works like a password for posting to the phone.
            Err(e) => Delivery::Failed(format!("{:?}", e.without_url())),
        }
    }
}

/// Tells the account's devices with an endpoint, except the one that asked,
/// that something of this kind is waiting. Never waits: the messages go from
/// a task of its own, so nothing about a push service reaches the request.
pub fn notify(user: &UserId, kind: Kind, except: Option<&DeviceId>) {
    let (Some(pusher), Some(pool)) = (Pusher::current(), POOL.get()) else {
        return;
    };
    drop(spawn_notify(pusher, pool.clone(), user.clone(), kind, except.cloned()));
}

/// `notify`'s task: the account's endpoints, each sent to at once; and an
/// endpoint its push service says is gone is removed.
pub fn spawn_notify(
    pusher: Arc<Pusher>,
    pool: DbPool,
    user: UserId,
    kind: Kind,
    except: Option<DeviceId>,
) -> JoinHandle<Vec<Delivery>> {
    tokio::spawn(async move {
        // The connection goes back before anything is sent: a slow push
        // service never holds one.
        let endpoints = match pool.get().await {
            Ok(conn) => PushEndpoint::find_by_user(&user, &conn).await,
            Err(_) => return Vec::new(),
        };
        let endpoints: Vec<PushEndpoint> =
            endpoints.into_iter().filter(|e| except.as_ref() != Some(&e.device_uuid)).collect();
        let deliveries = futures::future::join_all(endpoints.iter().map(|e| pusher.deliver(e, kind))).await;
        for (endpoint, delivery) in endpoints.iter().zip(&deliveries) {
            match delivery {
                Delivery::Sent => debug!("Pushed {kind:?} to a device of {user}"),
                Delivery::Limited => debug!("Didn't push {kind:?} to a device of {user}: over its limit"),
                Delivery::Gone => {
                    if let Ok(conn) = pool.get().await
                        && endpoint.delete_if_unchanged(&conn).await
                    {
                        info!("Removed a device's push endpoint of {user}: its push service no longer has it");
                    }
                }
                Delivery::Failed(why) => warn!("Couldn't push to a device of {user}: {why}"),
            }
        }
        deliveries
    })
}

#[cfg(test)]
mod tests;

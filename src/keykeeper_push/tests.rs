// Keykeeper: push to phones against a local HTTPS stand-in for a push
// service (the test's own, with a throwaway certificate), on a test
// database: what's posted and how, an endpoint its push service says is gone
// removed and others kept, the device that asked left out, the limit per
// device, a refused endpoint never reached, and a push service that never
// answers holding up nothing but its own task. See DESIGN.md, "Push to
// phones".

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use openssl::{
    asn1::Asn1Time,
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    x509::{
        X509Builder, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::*;
use crate::db::models::{Device, User};

fn provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        drop(rustls::crypto::ring::default_provider().install_default());
    }
}

/// What the stand-in got: the request's head (lowercase header names) and body.
#[derive(Clone, Debug)]
struct Received {
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// A push service on 127.0.0.1 that answers each path with a status of its
/// own, or never answers ("/hang"), and keeps what it got.
struct Standin {
    port: u16,
    ca_pem: String,
    received: Arc<Mutex<Vec<Received>>>,
}

/// A throwaway certificate for 127.0.0.1 and localhost: a server's, not a
/// CA's, trusted as it is.
fn certificate() -> (String, Vec<u8>, Vec<u8>) {
    let key = EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap();
    let key = PKey::from_ec_key(key).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "127.0.0.1").unwrap();
    let name = name.build();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&openssl::bn::BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap()).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(2).unwrap()).unwrap();
    b.append_extension(BasicConstraints::new().critical().build().unwrap()).unwrap();
    b.append_extension(KeyUsage::new().critical().digital_signature().build().unwrap()).unwrap();
    b.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap()).unwrap();
    let san =
        SubjectAlternativeName::new().ip("127.0.0.1").dns("localhost").build(&b.x509v3_context(None, None)).unwrap();
    b.append_extension(san).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = b.build();
    (String::from_utf8(cert.to_pem().unwrap()).unwrap(), cert.to_der().unwrap(), key.private_key_to_pkcs8().unwrap())
}

fn status_for(path: &str) -> Option<u16> {
    match path.rsplit('/').next().unwrap_or_default() {
        "gone" => Some(410),
        "missing" => Some(404),
        "broken" => Some(500),
        "moved" => Some(301),
        "hang" => None,
        _ => Some(201),
    }
}

impl Standin {
    async fn start() -> Self {
        provider();
        let (ca_pem, cert, key) = certificate();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert)],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&received);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let kept = Arc::clone(&kept);
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head, length) = loop {
                        let Ok(n) = tls.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..at]).into_owned();
                            let length = head
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_owned())
                                })
                                .and_then(|v| v.parse::<usize>().ok())
                                .unwrap_or(0);
                            buf.drain(..at + 4);
                            break (head, length);
                        }
                    };
                    while buf.len() < length {
                        let Ok(n) = tls.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let mut lines = head.lines();
                    let path = lines.next().unwrap_or_default().split(' ').nth(1).unwrap_or_default().to_owned();
                    let headers = lines
                        .filter_map(|l| l.split_once(':'))
                        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
                        .collect();
                    let status = status_for(&path);
                    kept.lock().unwrap().push(Received {
                        path,
                        headers,
                        body: buf,
                    });
                    let Some(status) = status else {
                        // Never answers, and keeps the connection open.
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        return;
                    };
                    let answer = format!(
                        "HTTP/1.1 {status} Whatever\r\ncontent-length: 2\r\nlocation: https://127.0.0.1/elsewhere\r\nconnection: close\r\n\r\nok"
                    );
                    drop(tls.write_all(answer.as_bytes()).await);
                    drop(tls.shutdown().await);
                });
            }
        });
        Self {
            port,
            ca_pem,
            received,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}/{path}", self.port)
    }

    fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}

fn vapid() -> &'static Vapid {
    Box::leak(Box::new(Vapid::from_pem(&Vapid::generate_pem().unwrap()).unwrap()))
}

fn testing_policy() -> Policy {
    Policy {
        private_ok: true,
        hosts: Vec::new(),
    }
}

fn pusher(standin: &Standin, policy: Policy, timeout: Duration) -> Arc<Pusher> {
    Arc::new(Pusher::new(policy, Some(&standin.ca_pem), vapid(), "https://vault.example.test".into(), timeout).unwrap())
}

/// A phone's keys, as its distributor's library makes them.
struct Phone {
    private: Vec<u8>,
    public: Vec<u8>,
    auth: [u8; 16],
}

fn phone() -> Phone {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    Phone {
        private: key.private_key().to_vec_padded(32).unwrap(),
        public: key.public_key().to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx).unwrap(),
        auth: crate::crypto::get_random_bytes::<16>(),
    }
}

/// An account with a device (an Android phone) for each endpoint path, each
/// with keys of its own.
async fn account(pool: &DbPool, standin: &Standin, paths: &[&str]) -> (UserId, Vec<(DeviceId, Phone)>) {
    let conn = pool.get().await.unwrap();
    let mut user = User::new(&format!("{}@example.test", crate::util::get_uuid()), None);
    user.save(&conn).await.unwrap();
    let mut devices = Vec::new();
    for path in paths {
        let mut device = Device::new(DeviceId::from(crate::util::get_uuid()), user.uuid.clone(), "Pixel".into(), 0);
        device.save(true, &conn).await.unwrap();
        let keys = phone();
        PushEndpoint {
            user_uuid: user.uuid.clone(),
            device_uuid: device.uuid.clone(),
            endpoint: standin.url(path),
            public_key: BASE64URL_NOPAD.encode(&keys.public),
            auth: BASE64URL_NOPAD.encode(&keys.auth),
            created_at: Utc::now().naive_utc(),
        }
        .save(&conn)
        .await
        .unwrap();
        devices.push((device.uuid, keys));
    }
    (user.uuid, devices)
}

async fn kept(pool: &DbPool, user: &UserId) -> Vec<String> {
    let conn = pool.get().await.unwrap();
    let mut paths: Vec<String> = PushEndpoint::find_by_user(user, &conn)
        .await
        .into_iter()
        .map(|e| e.endpoint.rsplit('/').next().unwrap_or_default().to_owned())
        .collect();
    paths.sort();
    paths
}

#[tokio::test(flavor = "multi_thread")]
async fn a_message_is_the_kind_alone_encrypted_to_the_phone_and_signed_with_vapid() {
    let standin = Standin::start().await;
    let pool = DbPool::for_test_pool_of(2);
    let (user, devices) = account(&pool, &standin, &["phone-ok"]).await;
    let pusher = pusher(&standin, testing_policy(), Duration::from_secs(10));

    let deliveries = spawn_notify(Arc::clone(&pusher), pool.clone(), user, Kind::SignIn, None).await.unwrap();
    assert_eq!(deliveries, [Delivery::Sent]);

    let got = standin.received();
    assert_eq!(got.len(), 1, "one message");
    let m = &got[0];
    assert_eq!(m.path, "/phone-ok");
    assert_eq!(m.headers["content-encoding"], "aes128gcm");
    assert_eq!(m.headers["content-type"], "application/octet-stream");
    assert_eq!(m.headers["ttl"], "900");
    assert_eq!(m.headers["urgency"], "high");
    assert_eq!(m.headers["topic"], "sign-in");
    let (t, k) = m.headers["authorization"].strip_prefix("vapid t=").unwrap().split_once(", k=").unwrap();
    assert_eq!(k, pusher.vapid.public_key());
    let claims: serde_json::Value =
        serde_json::from_slice(&BASE64URL_NOPAD.decode(t.split('.').nth(1).unwrap().as_bytes()).unwrap()).unwrap();
    assert_eq!(claims["aud"], format!("https://127.0.0.1:{}", standin.port));
    assert_eq!(claims["sub"], "https://vault.example.test");
    let exp = claims["exp"].as_i64().unwrap();
    let now = Utc::now().timestamp();
    assert!(exp > now + 11 * 3600 && exp <= now + 12 * 3600, "{exp}");

    // Only the phone's own keys open it, and it says the kind and nothing else.
    let (_, keys) = &devices[0];
    let plain = webpush::decrypt(&keys.private, &keys.auth, &m.body).expect("it opens with the phone's keys");
    assert_eq!(plain, br#"{"kind":"sign-in"}"#);
    let other = phone();
    assert!(webpush::decrypt(&other.private, &keys.auth, &m.body).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_410_or_404_removes_the_endpoint_and_other_failures_keep_it() {
    let standin = Standin::start().await;
    let pool = DbPool::for_test_pool_of(2);
    let (user, _) = account(&pool, &standin, &["a-gone", "b-missing", "c-broken", "d-moved", "e-ok"]).await;
    // The paths' last part picks the answer.
    let (user2, _) = account(&pool, &standin, &["gone", "missing", "broken", "moved", "ok"]).await;
    let pusher = pusher(&standin, testing_policy(), Duration::from_secs(10));

    let mut deliveries = spawn_notify(Arc::clone(&pusher), pool.clone(), user2.clone(), Kind::SignIn, None)
        .await
        .unwrap()
        .into_iter()
        .map(|d| format!("{d:?}"))
        .collect::<Vec<_>>();
    deliveries.sort();
    assert_eq!(deliveries.len(), 5);
    assert!(deliveries.contains(&"Gone".to_owned()));
    assert_eq!(deliveries.iter().filter(|d| *d == "Gone").count(), 2, "{deliveries:?}");
    assert_eq!(deliveries.iter().filter(|d| *d == "Sent").count(), 1, "{deliveries:?}");
    assert_eq!(kept(&pool, &user2).await, ["broken", "moved", "ok"]);

    // The other account's endpoints were never sent to, and stay.
    assert_eq!(kept(&pool, &user).await, ["a-gone", "b-missing", "c-broken", "d-moved", "e-ok"]);
    assert_eq!(standin.received().len(), 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_endpoint_registered_again_meanwhile_isnt_removed() {
    let standin = Standin::start().await;
    let pool = DbPool::for_test_pool_of(2);
    let (user, devices) = account(&pool, &standin, &["gone"]).await;
    let conn = pool.get().await.unwrap();
    let old = PushEndpoint::find(&user, &devices[0].0, &conn).await.unwrap();
    // The phone registers a new endpoint before the old one's answer comes.
    let new = PushEndpoint {
        endpoint: standin.url("new"),
        ..old.clone()
    };
    new.save(&conn).await.unwrap();
    assert!(!old.delete_if_unchanged(&conn).await);
    assert_eq!(PushEndpoint::find(&user, &devices[0].0, &conn).await.unwrap().endpoint, standin.url("new"));
    assert!(new.delete_if_unchanged(&conn).await);
    assert!(PushEndpoint::find(&user, &devices[0].0, &conn).await.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_device_that_asked_gets_nothing() {
    let standin = Standin::start().await;
    let pool = DbPool::for_test_pool_of(2);
    let (user, devices) = account(&pool, &standin, &["asking", "other"]).await;
    let pusher = pusher(&standin, testing_policy(), Duration::from_secs(10));
    let deliveries = spawn_notify(pusher, pool.clone(), user, Kind::SignIn, Some(devices[0].0.clone())).await.unwrap();
    assert_eq!(deliveries, [Delivery::Sent]);
    let paths: Vec<String> = standin.received().into_iter().map(|r| r.path).collect();
    assert_eq!(paths, ["/other"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_gets_ten_a_minute_at_most() {
    let standin = Standin::start().await;
    let pool = DbPool::for_test_pool_of(2);
    let (user, _) = account(&pool, &standin, &["busy"]).await;
    let pusher = pusher(&standin, testing_policy(), Duration::from_secs(10));
    let mut sent = 0;
    for _ in 0..12 {
        let d = spawn_notify(Arc::clone(&pusher), pool.clone(), user.clone(), Kind::SignIn, None).await.unwrap();
        match d.as_slice() {
            [Delivery::Sent] => sent += 1,
            [Delivery::Limited] => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(sent, PER_DEVICE_PER_MINUTE);
    assert_eq!(standin.received().len(), PER_DEVICE_PER_MINUTE as usize);
    assert_eq!(kept(&pool, &user).await, ["busy"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_endpoint_is_never_reached() {
    let standin = Standin::start().await;
    let pool = DbPool::for_test_pool_of(2);
    let (user, _) = account(&pool, &standin, &["ok"]).await;
    // A server without the test setting: 127.0.0.1 is private.
    let pusher = pusher(&standin, Policy::default(), Duration::from_secs(10));
    let deliveries = spawn_notify(pusher, pool.clone(), user.clone(), Kind::SignIn, None).await.unwrap();
    assert!(matches!(deliveries.as_slice(), [Delivery::Failed(why)] if why.contains("private")), "{deliveries:?}");
    assert!(standin.received().is_empty());
    assert_eq!(kept(&pool, &user).await, ["ok"]);

    // Nor through a name that resolves to it.
    let conn = pool.get().await.unwrap();
    let mut endpoint = PushEndpoint::find_by_user(&user, &conn).await.remove(0);
    endpoint.endpoint = format!("https://localhost:{}/ok", standin.port);
    endpoint.save(&conn).await.unwrap();
    drop(conn);
    let pusher = self::pusher(&standin, Policy::default(), Duration::from_secs(10));
    let deliveries = spawn_notify(pusher, pool.clone(), user.clone(), Kind::SignIn, None).await.unwrap();
    assert!(matches!(deliveries.as_slice(), [Delivery::Failed(_)]), "{deliveries:?}");
    assert!(standin.received().is_empty());

    // The same name, where the test setting allows loopback, goes through
    // the resolver's own check and arrives.
    let pusher = self::pusher(&standin, testing_policy(), Duration::from_secs(10));
    let deliveries = spawn_notify(pusher, pool.clone(), user, Kind::SignIn, None).await.unwrap();
    assert_eq!(deliveries, [Delivery::Sent]);
    assert_eq!(standin.received().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_service_that_never_answers_holds_up_only_its_own_task() {
    let standin = Standin::start().await;
    let pool = DbPool::for_test_pool_of(2);
    let (user, _) = account(&pool, &standin, &["hang", "ok"]).await;
    let pusher = pusher(&standin, testing_policy(), Duration::from_secs(1));

    // What a request does: hand it over, and go on at once.
    let started = Instant::now();
    let task = spawn_notify(pusher, pool.clone(), user.clone(), Kind::SignIn, None);
    assert!(started.elapsed() < Duration::from_millis(100), "{:?}", started.elapsed());
    // Meanwhile the database is free for the request's own work.
    let conn = pool.get().await.unwrap();
    assert_eq!(PushEndpoint::find_by_user(&user, &conn).await.len(), 2);
    drop(conn);

    let mut deliveries: Vec<String> = task.await.unwrap().into_iter().map(|d| format!("{d:?}")).collect();
    deliveries.sort();
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    assert!(deliveries[0].starts_with("Failed"), "{deliveries:?}");
    assert_eq!(deliveries[1], "Sent");
    // A timeout isn't "gone": the endpoint stays.
    assert_eq!(kept(&pool, &user).await, ["hang", "ok"]);
}

#[test]
fn statuses() {
    assert_eq!(Delivery::of_status(StatusCode::CREATED), Delivery::Sent);
    assert_eq!(Delivery::of_status(StatusCode::OK), Delivery::Sent);
    assert_eq!(Delivery::of_status(StatusCode::GONE), Delivery::Gone);
    assert_eq!(Delivery::of_status(StatusCode::NOT_FOUND), Delivery::Gone);
    assert!(matches!(Delivery::of_status(StatusCode::INTERNAL_SERVER_ERROR), Delivery::Failed(_)));
    assert!(matches!(Delivery::of_status(StatusCode::TOO_MANY_REQUESTS), Delivery::Failed(_)));
    assert!(matches!(Delivery::of_status(StatusCode::MOVED_PERMANENTLY), Delivery::Failed(_)));
    assert!(matches!(Delivery::of_status(StatusCode::UNAUTHORIZED), Delivery::Failed(_)));
}

#[test]
fn the_payload_is_the_kind_and_nothing_else() {
    let v: serde_json::Value = serde_json::from_slice(Kind::SignIn.payload()).unwrap();
    assert_eq!(v, serde_json::json!({ "kind": "sign-in" }));
}

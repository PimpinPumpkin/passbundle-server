use std::{
    net::IpAddr,
    num::NonZeroU32,
    sync::{
        LazyLock,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};

use crate::{CONFIG, Error};

type Limiter<T = IpAddr> = RateLimiter<T, DashMapStateStore<T>, DefaultClock>;

static LIMITER_LOGIN: LazyLock<Limiter> = LazyLock::new(|| {
    let seconds = Duration::from_secs(CONFIG.login_ratelimit_seconds());
    let burst = NonZeroU32::new(CONFIG.login_ratelimit_max_burst()).expect("Non-zero login ratelimit burst");
    RateLimiter::keyed(Quota::with_period(seconds).expect("Non-zero login ratelimit seconds").allow_burst(burst))
});

// Keykeeper: each account's own login limits, keyed by the email as typed,
// whether or not an account has it, so a refusal says nothing about which
// emails have accounts. The strict one counts per network, so guesses from
// elsewhere can't lock someone out; a looser one counts across every network,
// so guesses spread over many addresses still stop. Keys are hashes, a fixed
// 32 bytes whatever people type. See DESIGN.md, "Login limits".
type AccountKey = [u8; 32];
static LIMITER_LOGIN_ACCOUNT: LazyLock<Limiter<AccountKey>> = LazyLock::new(|| {
    let seconds = Duration::from_secs(CONFIG.login_ratelimit_account_seconds());
    let burst =
        NonZeroU32::new(CONFIG.login_ratelimit_account_max_burst()).expect("Non-zero account login ratelimit burst");
    RateLimiter::keyed(
        Quota::with_period(seconds).expect("Non-zero account login ratelimit seconds").allow_burst(burst),
    )
});
static LIMITER_LOGIN_ACCOUNT_ANYWHERE: LazyLock<Limiter<AccountKey>> = LazyLock::new(|| {
    let seconds = Duration::from_secs(CONFIG.login_ratelimit_account_anywhere_seconds());
    let burst = NonZeroU32::new(CONFIG.login_ratelimit_account_anywhere_max_burst())
        .expect("Non-zero account login ratelimit burst");
    RateLimiter::keyed(
        Quota::with_period(seconds).expect("Non-zero account login ratelimit seconds").allow_burst(burst),
    )
});
static ACCOUNT_CHECKS: AtomicU32 = AtomicU32::new(0);

// Keykeeper: pre-login, which every login starts with, gets an address's login
// allowance, counted on its own, instead of the shared unauthenticated one: it
// only says how to derive the key, the same way for an email without an
// account.
static LIMITER_PRELOGIN: LazyLock<Limiter> = LazyLock::new(|| {
    let seconds = Duration::from_secs(CONFIG.login_ratelimit_seconds());
    let burst = NonZeroU32::new(CONFIG.login_ratelimit_max_burst()).expect("Non-zero login ratelimit burst");
    RateLimiter::keyed(Quota::with_period(seconds).expect("Non-zero login ratelimit seconds").allow_burst(burst))
});

static LIMITER_ADMIN: LazyLock<Limiter> = LazyLock::new(|| {
    let seconds = Duration::from_secs(CONFIG.admin_ratelimit_seconds());
    let burst = NonZeroU32::new(CONFIG.admin_ratelimit_max_burst()).expect("Non-zero admin ratelimit burst");
    RateLimiter::keyed(Quota::with_period(seconds).expect("Non-zero admin ratelimit seconds").allow_burst(burst))
});

static LIMITER_UNAUTHENTICATED: LazyLock<Limiter> = LazyLock::new(|| {
    let seconds = Duration::from_secs(CONFIG.unauthenticated_ratelimit_seconds());
    let burst = NonZeroU32::new(CONFIG.unauthenticated_ratelimit_max_burst())
        .expect("Non-zero unauthenticated ratelimit burst");
    RateLimiter::keyed(
        Quota::with_period(seconds).expect("Non-zero unauthenticated ratelimit seconds").allow_burst(burst),
    )
});

pub fn check_limit_unauthenticated(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_UNAUTHENTICATED.check_key(ip) {
        Ok(()) => Ok(()),
        Err(_e) => {
            err_code!("Too many requests", 429);
        }
    }
}

pub fn check_limit_login(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_LOGIN.check_key(ip) {
        Ok(()) => Ok(()),
        Err(_e) => {
            err_code!("Too many login requests", 429);
        }
    }
}

pub fn check_limit_prelogin(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_PRELOGIN.check_key(ip) {
        Ok(()) => Ok(()),
        Err(_e) => {
            err_code!("Too many requests", 429);
        }
    }
}

/// An address's network: the /24 for IPv4 and the /64 for IPv6, which the
/// people at one office, or on one home connection, share.
fn network(ip: &IpAddr) -> [u8; 8] {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            [4, a, b, c, 0, 0, 0, 0]
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                network(&IpAddr::V4(v4))
            } else {
                let o = v6.octets();
                [o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]
            }
        }
    }
}

/// The key for an email as typed (trimmed and lowercase), with a network when
/// the limit is per network.
fn account_key(username: &str, net: Option<&[u8; 8]>) -> AccountKey {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(username.trim().to_lowercase().as_bytes());
    if let Some(net) = net {
        ctx.update(&[0]);
        ctx.update(net);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(ctx.finish().as_ref());
    key
}

/// Whether a login for this email from this address may go ahead under these
/// limiters: the per-network one, then the one across every network. A refusal
/// by the first doesn't use up the second.
fn account_allowed(
    per_network: &Limiter<AccountKey>,
    anywhere: &Limiter<AccountKey>,
    username: &str,
    ip: &IpAddr,
) -> bool {
    per_network.check_key(&account_key(username, Some(&network(ip)))).is_ok()
        && anywhere.check_key(&account_key(username, None)).is_ok()
}

pub fn check_limit_login_account(username: &str, ip: &IpAddr) -> Result<(), Error> {
    // Now and then, forget the keys whose limits have filled back up.
    if ACCOUNT_CHECKS.fetch_add(1, Ordering::Relaxed) % 1024 == 1023 {
        for limiter in [&*LIMITER_LOGIN_ACCOUNT, &*LIMITER_LOGIN_ACCOUNT_ANYWHERE] {
            limiter.retain_recent();
            limiter.shrink_to_fit();
        }
    }
    if account_allowed(&LIMITER_LOGIN_ACCOUNT, &LIMITER_LOGIN_ACCOUNT_ANYWHERE, username, ip) {
        Ok(())
    } else {
        err_code!("Too many login attempts for this account. Wait a minute and try again.", 429);
    }
}

pub fn check_limit_admin(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_ADMIN.check_key(ip) {
        Ok(()) => Ok(()),
        Err(_e) => {
            err_code!("Too many admin requests", 429);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, num::NonZeroU32, time::Duration};

    use governor::{Quota, RateLimiter};

    use super::{AccountKey, Limiter, account_allowed};

    fn limiter(burst: u32) -> Limiter<AccountKey> {
        RateLimiter::keyed(
            Quota::with_period(Duration::from_secs(3600)).unwrap().allow_burst(NonZeroU32::new(burst).unwrap()),
        )
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_account_gets_its_burst_per_network_then_waits() {
        let (per_network, anywhere) = (limiter(3), limiter(100));
        let office = ip("203.0.113.7");
        for _ in 0..3 {
            assert!(account_allowed(&per_network, &anywhere, "dana@acme.test", &office));
        }
        assert!(!account_allowed(&per_network, &anywhere, "dana@acme.test", &office));
        // The same /24 is the same network.
        assert!(!account_allowed(&per_network, &anywhere, "dana@acme.test", &ip("203.0.113.200")));
        // Another account is unaffected, and so is the same account elsewhere:
        // guesses from one network can't lock its owner out of another.
        assert!(account_allowed(&per_network, &anywhere, "lee@acme.test", &office));
        assert!(account_allowed(&per_network, &anywhere, "dana@acme.test", &ip("198.51.100.4")));
    }

    #[test]
    fn guesses_spread_over_many_networks_still_stop() {
        let (per_network, anywhere) = (limiter(10), limiter(5));
        for n in 0..5 {
            assert!(account_allowed(&per_network, &anywhere, "dana@acme.test", &ip(&format!("10.0.{n}.1"))));
        }
        assert!(!account_allowed(&per_network, &anywhere, "dana@acme.test", &ip("10.0.99.1")));
    }

    #[test]
    fn ipv6_counts_by_64_and_mapped_ipv4_as_ipv4() {
        let (per_network, anywhere) = (limiter(1), limiter(100));
        assert!(account_allowed(&per_network, &anywhere, "dana@acme.test", &ip("2001:db8:1:2::1")));
        assert!(!account_allowed(&per_network, &anywhere, "dana@acme.test", &ip("2001:db8:1:2:ffff::9")));
        assert!(account_allowed(&per_network, &anywhere, "dana@acme.test", &ip("2001:db8:1:3::1")));
        assert!(account_allowed(&per_network, &anywhere, "dana@acme.test", &ip("192.0.2.1")));
        assert!(!account_allowed(&per_network, &anywhere, "dana@acme.test", &ip("::ffff:192.0.2.9")));
    }

    #[test]
    fn the_same_email_typed_differently_shares_one_limit() {
        let (per_network, anywhere) = (limiter(2), limiter(100));
        let office = ip("203.0.113.7");
        assert!(account_allowed(&per_network, &anywhere, "Dana@Acme.test", &office));
        assert!(account_allowed(&per_network, &anywhere, "  dana@acme.test ", &office));
        assert!(!account_allowed(&per_network, &anywhere, "DANA@ACME.TEST", &office));
    }

    #[test]
    fn an_email_without_an_account_is_limited_the_same_way() {
        // Keyed by what was typed, so nothing tells which emails have accounts,
        // and a key is 32 bytes however long the email is.
        let (per_network, anywhere) = (limiter(1), limiter(100));
        let office = ip("203.0.113.7");
        assert!(account_allowed(&per_network, &anywhere, "nobody@nowhere.test", &office));
        assert!(!account_allowed(&per_network, &anywhere, "nobody@nowhere.test", &office));
        let long = "x".repeat(10_000);
        assert!(account_allowed(&per_network, &anywhere, &long, &office));
        assert!(!account_allowed(&per_network, &anywhere, &long, &office));
    }
}

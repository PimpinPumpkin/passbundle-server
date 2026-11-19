// Keykeeper: where push may go. The endpoint is an address a client gave the
// server, so it gets the event destinations' rules (keykeeper_streaming::
// guard::reach): https only, public addresses only, and every address a name
// resolves to checked. The check is the push client's resolver itself, so the
// connection goes only to an address that was checked, never to one a second
// lookup gave. The server's operator may narrow it to a list of push hosts
// (UNIFIED_PUSH_ALLOWED_HOSTS). Private and loopback addresses are reachable
// only with a setting for tests (UNIFIED_PUSH_TEST_ONLY_ALLOW_PRIVATE_ADDRESSES),
// and link-local addresses and cloud metadata services never. See DESIGN.md,
// "Push to phones".

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use crate::{
    CONFIG,
    keykeeper_streaming::guard::{Reach, blocked_by_regex, reach, valid_name},
};

/// The longest endpoint taken.
pub const MAX_URL_LEN: usize = 2048;

/// Where push may go, from the server's settings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// Loopback and private addresses too: tests only.
    pub private_ok: bool,
    /// The host names push may go to; empty is any public host.
    pub hosts: Vec<String>,
}

impl Policy {
    /// The server's settings.
    pub fn current() -> Self {
        Self {
            private_ok: CONFIG.unified_push_test_only_allow_private_addresses(),
            hosts: parse_hosts(&CONFIG.unified_push_allowed_hosts()).unwrap_or_default(),
        }
    }

    fn allows_host(&self, host: &str) -> bool {
        self.hosts.is_empty() || self.hosts.iter().any(|h| h == host)
    }
}

/// UNIFIED_PUSH_ALLOWED_HOSTS: host names separated by commas or spaces.
pub fn parse_hosts(text: &str) -> Result<Vec<String>, String> {
    let mut hosts = Vec::new();
    for item in text.split([',', ' ', '\n']).map(str::trim).filter(|s| !s.is_empty()) {
        let host = item.trim_end_matches('.').to_ascii_lowercase();
        if !valid_name(&host) || host.parse::<IpAddr>().is_ok() {
            return Err(format!("{item} isn't a host name"));
        }
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    Ok(hosts)
}

/// Whether push may go to this address, or why not.
pub fn check_ip(ip: IpAddr, policy: &Policy) -> Result<(), String> {
    if blocked_by_regex(&ip.to_string()) {
        return Err(format!("This server doesn't send to {ip}."));
    }
    match reach(ip) {
        Reach::Public => Ok(()),
        Reach::Private if policy.private_ok => Ok(()),
        Reach::Private => Err(format!("{ip} is a private address. Push goes only to public addresses.")),
        Reach::Never => Err(format!("Push can't go to {ip}: it's a link-local, reserved, or cloud metadata address.")),
    }
}

/// The host as it's checked: lowercase, without brackets or a final dot.
fn bare_host(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).map(str::to_owned).unwrap_or(host)
}

/// A host as it appears in an endpoint: on the list, if there is one, and
/// an address that's allowed or a name that could be.
fn check_host(host: &str, policy: &Policy) -> Result<(), String> {
    let host = bare_host(host);
    if !policy.allows_host(&host) {
        return Err(format!("This server sends push only to {}.", policy.hosts.join(", ")));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return check_ip(ip, policy);
    }
    if !valid_name(&host) {
        return Err("The endpoint's host isn't a host name or an address".into());
    }
    if blocked_by_regex(&host) {
        return Err(format!("This server doesn't send to {host}."));
    }
    Ok(())
}

/// An endpoint, checked: https, a host that could be allowed, no user name
/// or password, no fragment, and not too long. Names are resolved and
/// checked when a message is sent (`resolve`).
pub fn checked_url(text: &str, policy: &Policy) -> Result<url::Url, String> {
    let text = text.trim();
    if text.len() > MAX_URL_LEN {
        return Err(format!("An endpoint is at most {MAX_URL_LEN} characters"));
    }
    let url = url::Url::parse(text).map_err(|_| "The endpoint isn't a URL".to_owned())?;
    if url.scheme() != "https" {
        return Err("The endpoint must use https://".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("The endpoint can't have a user name or password in it".into());
    }
    if url.fragment().is_some() {
        return Err("The endpoint can't have a fragment".into());
    }
    let host = url.host_str().ok_or("The endpoint needs a host")?;
    check_host(host, policy)?;
    Ok(url)
}

/// The addresses push may connect to for a name: all of them allowed, or
/// the name is refused as a whole.
pub async fn resolve(host: &str, policy: &Policy) -> Result<Vec<SocketAddr>, String> {
    check_host(host, policy)?;
    let host = bare_host(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, 0)]);
    }
    let found = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host.as_str(), 0)))
        .await
        .map_err(|_| format!("Looking up {host} took too long"))?
        .map_err(|_| format!("{host} doesn't resolve to an address"))?;
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for addr in found {
        check_ip(addr.ip(), policy).map_err(|e| format!("{host}: {e}"))?;
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    if addrs.is_empty() {
        return Err(format!("{host} doesn't resolve to an address"));
    }
    Ok(addrs)
}

/// The push client's resolver: what it answers is what the connection may
/// use, so every address is checked here, and nowhere is there a second
/// lookup.
pub struct Resolver(pub Policy);

#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

impl reqwest::dns::Resolve for Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        let policy = self.0.clone();
        Box::pin(async move {
            let addrs = resolve(&host, &policy)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(Refused(e)) })?;
            let addrs: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public() -> Policy {
        Policy::default()
    }

    fn testing() -> Policy {
        Policy {
            private_ok: true,
            hosts: Vec::new(),
        }
    }

    fn refused(ip: &str, policy: &Policy) -> bool {
        check_ip(ip.parse().unwrap(), policy).is_err()
    }

    #[test]
    fn public_addresses_are_allowed() {
        for ip in ["93.184.215.14", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2a01:4f8::1"] {
            assert!(!refused(ip, &public()), "{ip}");
        }
    }

    #[test]
    fn every_non_public_ipv4_range_is_refused() {
        for ip in [
            "127.0.0.1",       // loopback
            "127.1.2.3",       // loopback
            "10.0.0.1",        // private
            "172.16.0.1",      // private
            "172.31.255.254",  // private
            "192.168.1.1",     // private
            "100.64.0.1",      // carrier-grade NAT
            "169.254.169.254", // link-local, and cloud metadata
            "169.254.1.1",     // link-local
            "168.63.129.16",   // Azure's platform address
            "100.100.100.200", // Alibaba Cloud's metadata
            "192.0.0.192",     // Oracle Cloud's metadata
            "0.0.0.0",         // this network
            "0.1.2.3",         // this network
            "224.0.0.1",       // multicast
            "239.255.255.250", // multicast
            "255.255.255.255", // broadcast
            "240.0.0.1",       // reserved
            "192.0.2.1",       // documentation
            "198.18.0.1",      // benchmarking
        ] {
            assert!(refused(ip, &public()), "{ip}");
        }
    }

    #[test]
    fn every_non_public_ipv6_range_is_refused() {
        for ip in [
            "::1",              // loopback
            "::",               // unspecified
            "fc00::1",          // unique local
            "fd12:3456::1",     // unique local
            "fe80::1",          // link-local
            "ff02::1",          // multicast
            "fd00:ec2::254",    // AWS's instance services
            "fd20:ce::254",     // Google Cloud's metadata
            "::ffff:127.0.0.1", // IPv4-mapped loopback
            "::ffff:169.254.169.254",
            "::ffff:8.8.8.8",      // IPv4-mapped, even public
            "64:ff9b::a00:1",      // NAT64
            "2002:a00:1::1",       // 6to4
            "2001:0:4136:e378::1", // Teredo
            "::10.0.0.1",          // IPv4-compatible
            "2001:db8::1",         // documentation
            "100::1",              // discard-only
        ] {
            assert!(refused(ip, &public()), "{ip}");
        }
    }

    #[test]
    fn the_test_setting_allows_loopback_and_private_but_never_link_local_or_metadata() {
        for ip in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "100.64.0.1", "::1", "fd12::1"] {
            assert!(refused(ip, &public()), "{ip}");
            assert!(!refused(ip, &testing()), "{ip}");
        }
        for ip in ["169.254.169.254", "168.63.129.16", "fe80::1", "fd00:ec2::254", "::ffff:127.0.0.1", "224.0.0.1"] {
            assert!(refused(ip, &testing()), "{ip}");
        }
    }

    #[test]
    fn an_endpoint_is_https_with_a_host_and_nothing_secret_in_it() {
        let p = public();
        assert!(checked_url("https://ntfy.sh/upAbC123?up=1", &p).is_ok());
        assert!(checked_url("https://push.example.com:8443/x", &p).is_ok());
        assert!(checked_url("https://8.8.8.8/x", &p).is_ok());
        for bad in [
            "http://ntfy.sh/upAbC123",
            "ftp://ntfy.sh/x",
            "https://user:pass@ntfy.sh/x",
            "https://user@ntfy.sh/x",
            "https://ntfy.sh/x#frag",
            "not a url",
            "https://",
            "https://127.0.0.1/x",
            "https://[::1]/x",
            "https://10.1.2.3/x",
            "https://169.254.169.254/latest/meta-data",
            "https://[fe80::1]/x",
            "https://[::ffff:10.0.0.1]/x",
        ] {
            assert!(checked_url(bad, &p).is_err(), "{bad}");
        }
        let long = format!("https://ntfy.sh/{}", "a".repeat(MAX_URL_LEN));
        assert!(checked_url(&long, &p).is_err());
    }

    #[test]
    fn the_allowed_hosts_narrow_it() {
        let p = Policy {
            private_ok: false,
            hosts: parse_hosts("ntfy.sh, Push.Example.com.").unwrap(),
        };
        assert_eq!(p.hosts, ["ntfy.sh", "push.example.com"]);
        assert!(checked_url("https://ntfy.sh/up1", &p).is_ok());
        assert!(checked_url("https://PUSH.example.com/up1", &p).is_ok());
        assert!(checked_url("https://evil.example.net/up1", &p).is_err());
        assert!(checked_url("https://sub.ntfy.sh/up1", &p).is_err());
        assert!(checked_url("https://8.8.8.8/up1", &p).is_err());
        assert!(parse_hosts("").unwrap().is_empty());
        assert!(parse_hosts("10.0.0.1").is_err());
        assert!(parse_hosts("not_a host!").is_err());
    }

    #[tokio::test]
    async fn a_name_that_resolves_to_a_private_address_is_refused() {
        // localhost resolves to 127.0.0.1 (and ::1) from the hosts file.
        let refused = resolve("localhost", &public()).await.expect_err("localhost is refused");
        assert!(refused.contains("private address"), "{refused}");
        // With the test setting, its loopback addresses are allowed.
        let addrs = resolve("localhost", &testing()).await.expect("allowed for tests");
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
        // An address written as the host is checked as it is.
        assert!(resolve("10.0.0.1", &public()).await.is_err());
        assert!(resolve("[::1]", &public()).await.is_err());
        assert_eq!(resolve("8.8.8.8", &public()).await.unwrap(), ["8.8.8.8:0".parse().unwrap()]);
    }

    #[tokio::test]
    async fn the_resolver_itself_refuses_them() {
        use reqwest::dns::Resolve;
        let resolver = Resolver(public());
        let name: reqwest::dns::Name = "localhost".parse().unwrap();
        assert!(resolver.resolve(name).await.is_err());
        let resolver = Resolver(testing());
        let name: reqwest::dns::Name = "localhost".parse().unwrap();
        assert!(resolver.resolve(name).await.is_ok());
    }
}

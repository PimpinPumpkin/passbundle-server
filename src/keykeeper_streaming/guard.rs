// Keykeeper: where events may go. Destinations are chosen by organizations'
// admins, so the server must not become a way into its own network or its
// cloud's metadata service. Every name is resolved here and every address it
// resolves to is checked before connecting, and the connection goes to the
// addresses that were checked (they're pinned on the request), so a second
// lookup can't answer differently. Proxies are never used, and webhooks
// don't follow redirects.
//
// Public addresses are allowed. Private ones (10/8, 172.16/12, 192.168/16,
// 100.64/10, fc00::/7, loopback) only where the server's admin listed them in
// EVENT_STREAMING_ALLOWED_NETWORKS: networks, addresses, or host names, each
// with an optional port. Loopback needs a loopback entry of its own, so no
// broad network opens the server itself. Link-local addresses, cloud metadata
// services, multicast, reserved ranges, and addresses that wrap IPv4 in IPv6
// are never allowed, and nor is anything HTTP_REQUEST_BLOCK_REGEX matches. A
// name with any address that isn't allowed is refused as a whole.
// See DESIGN.md, "Sending events to security tools".

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use ipnet::IpNet;
use regex::Regex;

use crate::{CONFIG, util::is_global};

/// How far an address reaches, for deciding whether events may go there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    Public,
    /// This machine or a private network.
    Private,
    /// Never: link-local, metadata services, multicast, reserved.
    Never,
}

/// Cloud metadata and platform services that no allowlist may open up.
/// 169.254.169.254 (AWS, Azure, Google, Oracle, DigitalOcean) is link-local
/// and refused with the rest of 169.254/16.
const METADATA_V4: [Ipv4Addr; 3] = [
    Ipv4Addr::new(100, 100, 100, 200), // Alibaba Cloud
    Ipv4Addr::new(168, 63, 129, 16),   // Azure's platform address
    Ipv4Addr::new(192, 0, 0, 192),     // Oracle Cloud
];
const METADATA_V6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254), // Google Cloud
    Ipv6Addr::new(0xfd00, 0x00c1, 0, 0, 0, 0, 0xa9fe, 0xa9fe), // Oracle Cloud
];

/// AWS keeps its instance services (metadata, time, DNS, EKS Pod Identity)
/// in fd00:ec2::/32.
fn aws_services(v6: Ipv6Addr) -> bool {
    let s = v6.segments();
    s[0] == 0xfd00 && s[1] == 0x0ec2
}

pub fn reach(ip: IpAddr) -> Reach {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if METADATA_V4.contains(&v4)
                || o[0] == 0
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || o[0] >= 240
            {
                Reach::Never
            } else if v4.is_loopback() || v4.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 0x40) {
                Reach::Private
            } else if is_global(IpAddr::V4(v4)) {
                Reach::Public
            } else {
                Reach::Never
            }
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // IPv4 written as IPv6, in any of its forms, could reach an IPv4
            // address the checks above would refuse.
            let wraps_ipv4 = v6.to_ipv4_mapped().is_some() // ::ffff:0:0/96
                || (s[0] == 0x64 && s[1] == 0xff9b) // NAT64
                || s[0] == 0x2002 // 6to4
                || (s[0] == 0x2001 && s[1] == 0) // Teredo
                || (s[..6] == [0; 6] && !v6.is_loopback() && !v6.is_unspecified()); // IPv4-compatible
            if METADATA_V6.contains(&v6)
                || aws_services(v6)
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || wraps_ipv4
            {
                Reach::Never
            } else if v6.is_loopback() || v6.is_unique_local() {
                Reach::Private
            } else if (s[0] & 0xe000) == 0x2000 && is_global(IpAddr::V6(v6)) {
                // Only global unicast (2000::/3) is public.
                Reach::Public
            } else {
                Reach::Never
            }
        }
    }
}

/// One entry of EVENT_STREAMING_ALLOWED_NETWORKS.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Where {
    Network(IpNet),
    Host(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    place: Where,
    port: Option<u16>,
}

/// The private networks, addresses, and host names the server's admin lets
/// events go to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    entries: Vec<Entry>,
}

fn parse_port(text: &str) -> Result<u16, String> {
    match text.parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(format!("{text} isn't a port")),
    }
}

fn parse_place(text: &str) -> Result<Where, String> {
    if let Ok(net) = text.parse::<IpNet>() {
        return Ok(Where::Network(net.trunc()));
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Ok(Where::Network(IpNet::from(ip)));
    }
    let host = text.trim_end_matches('.').to_ascii_lowercase();
    if valid_name(&host) {
        Ok(Where::Host(host))
    } else {
        Err(format!("{text} isn't a network, an address, or a host name"))
    }
}

impl Policy {
    /// Parses the setting: entries separated by commas or spaces, each a
    /// network (10.0.0.0/8), an address, or a host name, with an optional
    /// port (10.1.2.3:6514, [fd00::5]:6514, siem.corp.example:443).
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut entries = Vec::new();
        for item in text.split([',', ' ', '\n']).map(str::trim).filter(|s| !s.is_empty()) {
            let (place, port) = if let Some(rest) = item.strip_prefix('[') {
                let (inside, after) = rest.split_once(']').ok_or_else(|| format!("{item} is missing its ]"))?;
                let port = match after.strip_prefix(':') {
                    Some(p) => Some(parse_port(p)?),
                    None if after.is_empty() => None,
                    None => return Err(format!("{item} isn't a network or an address")),
                };
                (parse_place(inside)?, port)
            } else if item.matches(':').count() == 1 {
                let (place, port) = item.split_once(':').unwrap_or((item, ""));
                (parse_place(place)?, Some(parse_port(port)?))
            } else {
                (parse_place(item)?, None)
            };
            entries.push(Entry {
                place,
                port,
            });
        }
        Ok(Self {
            entries,
        })
    }

    /// The server's setting, parsed (once per value).
    pub fn current() -> Arc<Self> {
        static CACHE: Mutex<Option<(String, Arc<Policy>)>> = Mutex::new(None);
        let text = CONFIG.event_streaming_allowed_networks();
        let Ok(mut cache) = CACHE.lock() else {
            return Arc::default();
        };
        if let Some((seen, policy)) = cache.as_ref()
            && *seen == text
        {
            return Arc::clone(policy);
        }
        // The setting is checked when the server starts, so this parses.
        let policy = Arc::new(Self::parse(&text).unwrap_or_default());
        *cache = Some((text, Arc::clone(&policy)));
        policy
    }

    /// Whether any private network is allowed at all.
    pub fn any(&self) -> bool {
        !self.entries.is_empty()
    }

    /// Whether a private address may be reached, on this port, as this host
    /// name (when it came from a name). Loopback only through an entry that's
    /// itself loopback, never through a host name or a broader network.
    fn allows(&self, ip: IpAddr, host: Option<&str>, port: u16) -> bool {
        self.entries.iter().any(|e| {
            let place = match &e.place {
                Where::Network(net) => {
                    net.contains(&ip)
                        && (!ip.is_loopback() || (net.network().is_loopback() && net.broadcast().is_loopback()))
                }
                Where::Host(name) => !ip.is_loopback() && host.is_some_and(|h| h == name),
            };
            place && e.port.is_none_or(|p| p == port)
        })
    }
}

/// Whether HTTP_REQUEST_BLOCK_REGEX, the server's list of places it never
/// makes requests to, matches a host name or address.
fn blocked_by_regex(text: &str) -> bool {
    /// The pattern last seen, and what it compiled to.
    type Compiled = Option<(String, Option<Regex>)>;
    static COMPILED: LazyLock<Mutex<Compiled>> = LazyLock::new(Mutex::default);
    let Some(pattern) = CONFIG.http_request_block_regex() else {
        return false;
    };
    let Ok(mut compiled) = COMPILED.lock() else {
        return true;
    };
    if compiled.as_ref().is_none_or(|(seen, _)| *seen != pattern) {
        *compiled = Some((pattern.clone(), Regex::new(&pattern).ok()));
    }
    compiled.as_ref().and_then(|(_, re)| re.as_ref()).is_none_or(|re| re.is_match(text))
}

/// Whether events may go to this address and port, or why not. `host` is the
/// name it was resolved from, if any.
pub fn check_ip(ip: IpAddr, host: Option<&str>, port: u16, policy: &Policy) -> Result<(), String> {
    if blocked_by_regex(&ip.to_string()) {
        return Err(format!("This server doesn't send to {ip}."));
    }
    match reach(ip) {
        Reach::Public => Ok(()),
        Reach::Private if policy.allows(ip, host, port) => Ok(()),
        Reach::Private => Err(format!(
            "{ip} is a private address. Events go only to public addresses, and private ones the server's admin allows."
        )),
        Reach::Never => {
            Err(format!("Events can't go to {ip}: it's a link-local, reserved, or cloud metadata address."))
        }
    }
}

fn valid_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// A host name or IP address as typed: lowercase, no brackets, and something
/// that could be a host. IP literals are checked here with the port; names
/// when they're resolved.
pub fn checked_host(host: &str, port: u16, policy: &Policy) -> Result<String, String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(&host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        check_ip(ip, None, port, policy)?;
        return Ok(bare.to_owned());
    }
    if !valid_name(bare) {
        return Err("That isn't a host name or IP address".into());
    }
    if blocked_by_regex(bare) {
        return Err(format!("This server doesn't send to {bare}."));
    }
    Ok(bare.to_owned())
}

/// A webhook URL, checked: HTTPS, no user name or password in it (put a
/// token in the header instead), and a host that could be allowed.
pub fn checked_url(text: &str, policy: &Policy) -> Result<url::Url, String> {
    let text = text.trim();
    if text.len() > 2048 {
        return Err("A webhook URL is at most 2048 characters".into());
    }
    let url = url::Url::parse(text).map_err(|_| "That isn't a URL".to_owned())?;
    if url.scheme() != "https" {
        return Err("Webhooks must use https://".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Put credentials in the header, not the URL".into());
    }
    let host = url.host_str().ok_or("A webhook URL needs a host")?;
    checked_host(host, url.port_or_known_default().unwrap_or(443), policy)?;
    Ok(url)
}

/// Sentinel's endpoint: a data collection endpoint or a rule's own ingestion
/// endpoint, both under Azure Monitor's ingestion domain, with no path.
/// Checked when it's saved and again before each upload, since the app's
/// token goes there.
pub fn checked_sentinel_endpoint(text: &str, policy: &Policy) -> Result<String, String> {
    let url = checked_url(text, policy)?;
    let host = url.host_str().unwrap_or_default();
    let suffix = CONFIG.event_streaming_azure_ingest_suffix();
    let bare = suffix.trim_start_matches('.');
    if bare.is_empty() || !(host == bare || host.ends_with(&format!(".{bare}"))) {
        return Err(format!("The endpoint is the rule's or collection endpoint's address, ending in {suffix}"));
    }
    if url.path() != "/" || url.query().is_some() {
        return Err("Enter just the endpoint's address, without a path".into());
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// What the console shows of a webhook URL, which can carry a token: its
/// scheme, host, and port only.
pub fn shown_url(url: &url::Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("https://{host}:{port}/…"),
        None => format!("https://{host}/…"),
    }
}

/// Resolves a host to the addresses a connection may use on this port,
/// refusing the name when any of its addresses isn't allowed. The errors are
/// for the server's log: what people see is one message for anything that
/// goes wrong before a connection is made (see mod.rs), so a destination
/// can't be used to map the network.
pub async fn resolve(host: &str, port: u16, policy: &Policy) -> Result<Vec<SocketAddr>, String> {
    let host = checked_host(host, port, policy)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let found = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host.as_str(), port)))
        .await
        .map_err(|_| format!("Looking up {host} took too long"))?
        .map_err(|_| format!("{host} doesn't resolve to an address"))?;
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for addr in found {
        check_ip(addr.ip(), Some(&host), port, policy).map_err(|e| format!("{host}: {e}"))?;
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    if addrs.is_empty() {
        return Err(format!("{host} doesn't resolve to an address"));
    }
    Ok(addrs)
}

/// The resolver for event requests, behind the pinned addresses: any lookup
/// that gets here is checked too, though requests carry the addresses they
/// may use.
pub struct GuardedResolver;

#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // The port isn't known here, so only addresses allowed on every
            // port pass.
            let addrs = resolve(&host, 0, &Policy::current())
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

    fn r(ip: &str) -> Reach {
        reach(ip.parse().unwrap())
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn addresses_are_sorted_by_reach() {
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "203.0.114.1"] {
            assert_eq!(r(ip), Reach::Public, "{ip}");
        }
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.10", "100.64.0.1", "::1", "fd12:3456::1"] {
            assert_eq!(r(ip), Reach::Private, "{ip}");
        }
        for ip in [
            "169.254.169.254",
            "169.254.170.2",
            "100.100.100.200",
            "168.63.129.16",
            "192.0.0.192",
            "fd00:ec2::254",
            "fd00:ec2::23",
            "fd20:ce::254",
            "fd00:c1::a9fe:a9fe",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "::ffff:8.8.8.8",
            "0.0.0.0",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "::",
            "fe80::1",
            "ff02::1",
            "64:ff9b::a9fe:a9fe",
            "2002:a9fe:a9fe::1",
            "2001:0:4136:e378::1",
            "::a9fe:a9fe",
            "192.0.2.1",
            "198.18.0.1",
            "2001:db8::1",
            // Outside 2000::/3: not global unicast.
            "4000::1",
            "e000::1",
        ] {
            assert_eq!(r(ip), Reach::Never, "{ip}");
        }
    }

    #[test]
    fn private_addresses_need_an_entry_and_metadata_never_passes() {
        let none = Policy::default();
        let lan = Policy::parse("10.0.0.0/8, siem.corp.example:6514, [fd00::5]:443").unwrap();
        assert!(check_ip(ip("10.0.0.5"), None, 443, &none).is_err());
        assert!(check_ip(ip("10.0.0.5"), None, 443, &lan).is_ok());
        assert!(check_ip(ip("192.168.0.5"), None, 443, &lan).is_err());
        assert!(check_ip(ip("fd00::5"), None, 443, &lan).is_ok());
        assert!(check_ip(ip("fd00::5"), None, 8443, &lan).is_err(), "only its port");
        // A host name entry admits that name's private addresses, on its port.
        assert!(check_ip(ip("192.168.7.7"), Some("siem.corp.example"), 6514, &lan).is_ok());
        assert!(check_ip(ip("192.168.7.7"), Some("siem.corp.example"), 443, &lan).is_err());
        assert!(check_ip(ip("192.168.7.7"), Some("other.corp.example"), 6514, &lan).is_err());
        // Never through these, whatever's listed.
        let wide = Policy::parse("0.0.0.0/0, ::/0, 169.254.0.0/16").unwrap();
        for never in ["169.254.169.254", "100.100.100.200", "fd00:ec2::254", "fd20:ce::254"] {
            assert!(check_ip(ip(never), None, 80, &wide).is_err(), "{never}");
        }
        assert!(check_ip(ip("8.8.8.8"), None, 443, &none).is_ok());
    }

    #[test]
    fn loopback_needs_a_loopback_entry() {
        let wide = Policy::parse("0.0.0.0/0, ::/0, localhost").unwrap();
        assert!(check_ip(ip("127.0.0.1"), None, 443, &wide).is_err());
        assert!(check_ip(ip("127.0.0.1"), Some("localhost"), 443, &wide).is_err());
        assert!(check_ip(ip("::1"), None, 443, &wide).is_err());
        let local = Policy::parse("127.0.0.1").unwrap();
        assert!(check_ip(ip("127.0.0.1"), None, 443, &local).is_ok());
        assert!(check_ip(ip("127.0.0.2"), None, 443, &local).is_err());
        assert!(check_ip(ip("::1"), None, 443, &local).is_err());
        assert!(check_ip(ip("127.5.5.5"), None, 9, &Policy::parse("127.0.0.0/8").unwrap()).is_ok());
    }

    #[test]
    fn the_setting_parses_networks_addresses_names_and_ports() {
        let p = Policy::parse(" 10.0.0.0/8,192.168.1.10:6514 [fd00::/8]:443 siem.corp.example\nfd12::/16 ").unwrap();
        assert_eq!(p.entries.len(), 5);
        assert_eq!(p.entries[1].port, Some(6514));
        assert_eq!(p.entries[2].port, Some(443));
        assert_eq!(p.entries[3].place, Where::Host("siem.corp.example".into()));
        assert_eq!(p.entries[4].port, None);
        assert!(Policy::parse("").unwrap().entries.is_empty());
        for bad in ["10.0.0.0/33", "bad*host", "-x.example", "10.0.0.1:0", "10.0.0.1:x", "[fd00::5", "[fd00::5]x"] {
            assert!(Policy::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn webhook_urls_are_https_without_credentials() {
        let none = Policy::default();
        let local = Policy::parse("127.0.0.1").unwrap();
        assert!(checked_url("https://siem.example.com/hook?token=abc", &none).is_ok());
        assert!(checked_url("http://siem.example.com/hook", &none).is_err());
        assert!(checked_url("ftp://siem.example.com/", &none).is_err());
        assert!(checked_url("https://user:pass@siem.example.com/", &none).is_err());
        assert!(checked_url("https://127.0.0.1/hook", &none).is_err());
        assert!(checked_url("https://127.0.0.1:8443/hook", &local).is_ok());
        assert!(checked_url("https://[::1]/hook", &local).is_err());
        assert!(checked_url("https://169.254.169.254/latest/meta-data", &local).is_err());
        assert!(checked_url("https://[::ffff:a9fe:a9fe]/", &local).is_err());
        assert!(checked_url("not a url", &none).is_err());
        let url = checked_url("https://hooks.example.com:8088/services/collector?sig=SECRET", &none).unwrap();
        assert_eq!(shown_url(&url), "https://hooks.example.com:8088/…");
        assert!(!shown_url(&url).contains("SECRET"));
    }

    #[test]
    fn hosts_are_names_or_addresses() {
        let none = Policy::default();
        assert_eq!(checked_host("SIEM.Example.com.", 443, &none).unwrap(), "siem.example.com");
        assert!(checked_host("bad host", 443, &none).is_err());
        assert!(checked_host("-bad.example.com", 443, &none).is_err());
        assert!(checked_host("", 443, &none).is_err());
        assert!(checked_host("192.168.0.9", 443, &none).is_err());
        let lan = Policy::parse("fd00::/8").unwrap();
        assert_eq!(checked_host("[fd00::9]", 6514, &lan).unwrap(), "fd00::9");
    }

    #[tokio::test]
    async fn names_that_resolve_to_refused_addresses_are_refused() {
        let none = Policy::default();
        assert!(resolve("localhost", 6514, &none).await.is_err());
        // Even with 127.0.0.1 listed: localhost also resolves to ::1, and a
        // name entry never opens loopback.
        assert!(resolve("localhost", 6514, &Policy::parse("localhost").unwrap()).await.is_err());
        assert!(resolve("127.0.0.1", 6514, &none).await.is_err());
        let allowed = resolve("127.0.0.1", 6514, &Policy::parse("127.0.0.1").unwrap()).await.unwrap();
        assert_eq!(allowed, vec!["127.0.0.1:6514".parse().unwrap()]);
        assert!(resolve("169.254.169.254", 80, &Policy::parse("169.254.0.0/16").unwrap()).await.is_err());
    }
}

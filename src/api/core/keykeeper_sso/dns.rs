// Keykeeper: checking the DNS TXT record that proves an organization controls
// an email domain. The record sits on the domain itself, the way Microsoft
// 365 checks its "MS=" records: `passbundle-verification=<43 characters>`.
// Each check asks the DNS again (no cache), through the system's resolver,
// or a test's stand-in (SSO_DOMAIN_DNS_SERVER). DNSSEC isn't checked; see
// DESIGN.md, "Sign in with Microsoft Entra ID", "Threat model".

use std::{net::SocketAddr, time::Duration};

use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
    proto::rr::RData,
};

use crate::CONFIG;

fn resolver() -> Result<TokioResolver, String> {
    let mut builder = match CONFIG.sso_domain_dns_server() {
        Some(server) => {
            let addr: SocketAddr =
                server.parse().map_err(|_| format!("SSO_DOMAIN_DNS_SERVER isn't an address and port: {server}"))?;
            let mut name_server = NameServerConfig::udp(addr.ip());
            for c in &mut name_server.connections {
                c.port = addr.port();
            }
            TokioResolver::builder_with_config(
                ResolverConfig::from_name_servers(vec![name_server]),
                TokioRuntimeProvider::default(),
            )
        }
        None => {
            TokioResolver::builder(TokioRuntimeProvider::default()).map_err(|e| format!("no DNS resolver ({e})"))?
        }
    };
    let options = builder.options_mut();
    // A new record should count on the next check, not after a cache expires.
    options.cache_size = 0;
    options.timeout = Duration::from_secs(5);
    options.attempts = 2;
    builder.build().map_err(|e| format!("no DNS resolver ({e})"))
}

/// The domain's TXT records, each one's strings joined (RFC 1035 lets a
/// record hold several), or why they couldn't be read. A domain with no TXT
/// records has none, which isn't an error.
pub async fn txt_records(domain: &str) -> Result<Vec<String>, String> {
    let resolver = resolver()?;
    // Fully qualified, so no search domain is ever appended.
    let lookup = match resolver.txt_lookup(format!("{domain}.")).await {
        Ok(lookup) => lookup,
        Err(e) if e.is_no_records_found() || e.is_nx_domain() => return Ok(Vec::new()),
        Err(e) => return Err(format!("the DNS lookup for {domain} failed ({e})")),
    };
    Ok(lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::TXT(txt) => Some(txt.txt_data.iter().map(|s| String::from_utf8_lossy(s)).collect::<String>()),
            _ => None,
        })
        .collect())
}

/// Whether one of the records is exactly the expected value.
pub fn has_record(records: &[String], expected: &str) -> bool {
    records.iter().any(|r| r.trim() == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_record_counts() {
        let want = "passbundle-verification=AAAA";
        assert!(has_record(&["v=spf1 -all".into(), "passbundle-verification=AAAA".into()], want));
        assert!(has_record(&[" passbundle-verification=AAAA ".into()], want));
        for other in
            ["passbundle-verification=AAAAB", "passbundle-verification=aaaa", "xpassbundle-verification=AAAA", ""]
        {
            assert!(!has_record(&[other.into()], want), "{other}");
        }
        assert!(!has_record(&[], want));
    }
}

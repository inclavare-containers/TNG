use std::net::Ipv4Addr;

use anyhow::{bail, Context as _, Result};
use cidr::Ipv4Cidr;
use regex::Regex;

use crate::config::ingress::EndpointMatcherConfig;
use crate::config::match_rule::{HostMatchConfig, PortMatchConfig};
use crate::tunnel::endpoint::TngEndpoint;

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum HostMatch {
    /// Matches any endpoint type (domain or IP).
    Any,
    /// Envoy domain matcher — constructed with validation at init time.
    Domain(EnvoyDomainMatcher),
    /// Compiled regex — compiled at init time, not per-match.
    DomainRegex(Regex),
    /// Exact IPv4 match.
    Ip(Ipv4Addr),
    /// IPv4 CIDR range match.
    IpCidr(Ipv4Cidr),
}

impl HostMatch {
    pub fn from_config(rule: &HostMatchConfig) -> Result<Self> {
        Ok(match rule {
            HostMatchConfig::All {} => HostMatch::Any,
            HostMatchConfig::Domain { domain } => {
                HostMatch::Domain(EnvoyDomainMatcher::new(domain)?)
            }
            HostMatchConfig::DomainRegex { domain_regex } => HostMatch::DomainRegex(
                Regex::new(domain_regex)
                    .context("The value of 'domain_regex' should be a regex")?,
            ),
            HostMatchConfig::Ip { ip } => HostMatch::Ip(
                ip.parse::<Ipv4Addr>()
                    .with_context(|| format!("invalid IP address: {ip}"))?,
            ),
            HostMatchConfig::IpCidr { ip_cidr } => HostMatch::IpCidr(
                ip_cidr
                    .parse::<Ipv4Cidr>()
                    .with_context(|| format!("invalid CIDR range: {ip_cidr}"))?,
            ),
        })
    }

    pub(crate) fn matches(&self, endpoint: &crate::tunnel::endpoint::TngEndpoint) -> bool {
        match self {
            HostMatch::Any => true,
            HostMatch::Domain(matcher) => {
                if let Some(domain) = endpoint.addr().as_domain() {
                    matcher.is_match(domain)
                } else {
                    false
                }
            }
            HostMatch::DomainRegex(re) => {
                if let Some(domain) = endpoint.addr().as_domain() {
                    re.is_match(domain)
                } else {
                    false
                }
            }
            HostMatch::Ip(target) => endpoint.addr().as_ipv4() == Some(target),
            HostMatch::IpCidr(cidr) => endpoint
                .addr()
                .as_ipv4()
                .map(|ip| cidr.contains(ip))
                .unwrap_or(false),
        }
    }
}

/// Runtime port matcher.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum PortMatch {
    /// Matches any port (default when port is not specified).
    Any,
    /// Exact port match.
    Single(u16),
    /// Port range [start, end] inclusive.
    Range(u16, u16),
}

#[allow(dead_code)]
impl PortMatch {
    /// Validate and convert to the runtime `PortMatch` enum.
    pub(crate) fn from_config(config: &PortMatchConfig) -> Result<Self> {
        match (config.port, config.port_end) {
            (None, None) => Ok(PortMatch::Any),
            (Some(p), None) => Ok(PortMatch::Single(p)),
            (Some(start), Some(end)) if end >= start => Ok(PortMatch::Range(start, end)),
            (Some(_), Some(end)) => {
                bail!("`port_end` ({end}) must be >= `port`")
            }
            (None, Some(_)) => {
                bail!("`port_end` requires `port` to be specified")
            }
        }
    }

    pub(crate) fn matches(&self, port: u16) -> bool {
        match self {
            PortMatch::Any => true,
            PortMatch::Single(p) => port == *p,
            PortMatch::Range(start, end) => *start <= port && port <= *end,
        }
    }
}

#[derive(Debug)]
pub struct EndpointMatcher {
    items: Vec<EndpointMatcherItem>,
}

impl EndpointMatcher {
    pub fn new(dst_filters: &[EndpointMatcherConfig]) -> Result<Self> {
        let items = dst_filters
            .iter()
            .map(EndpointMatcherItem::from_config)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { items })
    }

    pub fn matches(&self, endpoint: &TngEndpoint) -> bool {
        if self.items.is_empty() {
            return true;
        }

        for item in &self.items {
            if item.matches(endpoint) {
                return true;
            }
        }
        false
    }
}

/// A single compiled match rule (host + port).
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct EndpointMatcherItem {
    pub(crate) host_match: HostMatch,
    pub(crate) port_match: PortMatch,
}

#[allow(dead_code)]
impl EndpointMatcherItem {
    /// Convert a config pair into a validated runtime matcher.
    pub(crate) fn from_config(config: &EndpointMatcherConfig) -> Result<Self> {
        Ok(Self {
            host_match: HostMatch::from_config(&config.host_match)?,
            port_match: PortMatch::from_config(&config.port_match)?,
        })
    }

    pub(crate) fn matches(&self, endpoint: &crate::tunnel::endpoint::TngEndpoint) -> bool {
        self.host_match.matches(endpoint) && self.port_match.matches(endpoint.port())
    }
}

/// This is a matcher that compatible with the [envoy domain matcher](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#config-route-v3-virtualhost).
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum EnvoyDomainMatcher {
    /// Exact domain names: www.foo.com.
    Exact(String),
    /// Suffix domain wildcards: *.foo.com or *-bar.foo.com.
    Suffix(String),
    /// Prefix domain wildcards: foo.* or foo-*.
    Prefix(String),
    /// Special wildcard * matching any domain.
    MatchAny,
}

#[allow(dead_code)]
impl EnvoyDomainMatcher {
    pub(crate) fn new(domain: &str) -> Result<Self> {
        if domain == "*" {
            Ok(EnvoyDomainMatcher::MatchAny)
        } else if let Some(stripped) = domain.strip_prefix('*') {
            Ok(EnvoyDomainMatcher::Suffix(stripped.to_owned()))
        } else if let Some(stripped) = domain.strip_suffix('*') {
            Ok(EnvoyDomainMatcher::Prefix(stripped.to_owned()))
        } else if !domain.contains('*') {
            Ok(EnvoyDomainMatcher::Exact(domain.to_owned()))
        } else {
            bail!("Wildcard * must be at the start or end of the domain pattern: {domain}")
        }
    }

    #[inline]
    pub(crate) fn is_match(&self, haystack: &str) -> bool {
        match self {
            EnvoyDomainMatcher::Exact(s) => haystack == s,
            EnvoyDomainMatcher::Suffix(s) => haystack.ends_with(s),
            EnvoyDomainMatcher::Prefix(s) => haystack.starts_with(s),
            EnvoyDomainMatcher::MatchAny => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::json;

    use super::*;

    use crate::tunnel::endpoint::TngEndpoint;

    #[test]
    fn test_domain_match() -> Result<()> {
        // When both `domain` and `domain_regex` are present, `domain` takes precedence
        // (untagged deserialization picks the first matching variant).
        let endpoint_matcher = EndpointMatcher::new(&[serde_json::from_value(json! {
            {
                "domain": "*",
                "domain_regex": ".*",
                "port": 9991
            }
        })?])?;
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 9991)));

        let endpoint_matcher = EndpointMatcher::new(&[serde_json::from_value(json! {
            {
                "port": 9991
            }
        })?])?;
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(endpoint_matcher.matches(&TngEndpoint::new("*.foo.com", 9991)));

        let endpoint_matcher = EndpointMatcher::new(&[serde_json::from_value(json! {
            {
                "domain": "*",
                "port": 9991
            }
        })?])?;
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(endpoint_matcher.matches(&TngEndpoint::new("*.foo.com", 9991)));

        let endpoint_matcher = EndpointMatcher::new(&[serde_json::from_value(json! {
            {
                "domain": "*.foo.com",
                "port": 9991
            }
        })?])?;
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(endpoint_matcher.matches(&TngEndpoint::new("*.foo.com", 9991)));
        assert!(!endpoint_matcher.matches(&TngEndpoint::new("www.bar.com", 9991)));

        let endpoint_matcher = EndpointMatcher::new(&[serde_json::from_value(json! {
            {
                "domain": "www.foo.*",
                "port": 9991
            }
        })?])?;
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.foo.cn", 9991)));
        assert!(!endpoint_matcher.matches(&TngEndpoint::new("*.foo.com", 9991)));
        assert!(!endpoint_matcher.matches(&TngEndpoint::new("www.bar.com", 9991)));

        let endpoint_matcher = EndpointMatcher::new(&[serde_json::from_value(json! {
            {
                "domain": "www.foo.com",
                "port": 9991
            }
        })?])?;
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(!endpoint_matcher.matches(&TngEndpoint::new("www.bar.com", 9991)));

        assert!(EndpointMatcher::new(&[serde_json::from_value(json! {
            {
                "domain": "www.*.com",
                "port": 9991
            }
        })?])
        .is_err());

        assert!(EndpointMatcher::new(&[serde_json::from_value(json! {
            {
                "domain_regex": "*",
                "port": 9991
            }
        })?])
        .is_err());

        let endpoint_matcher = EndpointMatcher::new(&[serde_json::from_value(json! {
            {
                "domain_regex": ".*",
                "port": 9991
            }
        })?])?;
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(endpoint_matcher.matches(&TngEndpoint::new("*.foo.com", 9991)));
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.bar.com", 9991)));

        let endpoint_matcher = EndpointMatcher::new(&[serde_json::from_value(json! {
            {
                "domain_regex": r".*foo\.com",
                "port": 9991
            }
        })?])?;
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.sub.foo.com", 9991)));
        assert!(endpoint_matcher.matches(&TngEndpoint::new("new-foo.com", 9991)));
        assert!(!endpoint_matcher.matches(&TngEndpoint::new("www.bar.com", 9991)));

        Ok(())
    }

    #[test]
    fn test_port_range_match() -> Result<()> {
        // Single port (existing behavior)
        let endpoint_matcher = EndpointMatcher::new(&[serde_json::from_value(json!({
            "domain": "*",
            "port": 9991
        }))?])?;
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(!endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 9992)));

        // Port range
        let endpoint_matcher = EndpointMatcher::new(&[serde_json::from_value(json!({
            "domain": "*",
            "port": 30000,
            "port_end": 30063
        }))?])?;
        assert!(!endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 29999))); // below range
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 30000))); // lower bound
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 30031))); // mid-range
        assert!(endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 30063))); // upper bound
        assert!(!endpoint_matcher.matches(&TngEndpoint::new("www.foo.com", 30064))); // above range

        // Port range with specific domain
        let endpoint_matcher = EndpointMatcher::new(&[serde_json::from_value(json!({
            "domain": "*.example.com",
            "port": 30000,
            "port_end": 30063
        }))?])?;
        assert!(endpoint_matcher.matches(&TngEndpoint::new("api.example.com", 30000)));
        assert!(!endpoint_matcher.matches(&TngEndpoint::new("api.other.com", 30000)));

        Ok(())
    }

    #[test]
    fn test_port_end_validation() -> Result<()> {
        // port_end without port — error
        assert!(EndpointMatcher::new(&[serde_json::from_value(json!({
            "domain": "*",
            "port_end": 30063
        }))?])
        .is_err());

        // port_end < port — error
        assert!(EndpointMatcher::new(&[serde_json::from_value(json!({
            "domain": "*",
            "port": 30063,
            "port_end": 30000
        }))?])
        .is_err());

        // port_end == port — valid (single port range)
        assert!(EndpointMatcher::new(&[serde_json::from_value(json!({
            "domain": "*",
            "port": 30000,
            "port_end": 30000
        }))?])
        .is_ok());

        // Valid range
        assert!(EndpointMatcher::new(&[serde_json::from_value(json!({
            "domain": "*",
            "port": 30000,
            "port_end": 30063
        }))?])
        .is_ok());

        Ok(())
    }

    #[test]
    fn test_ip_match() -> Result<()> {
        use std::net::Ipv4Addr;

        // Exact IP match
        let endpoint_matcher = EndpointMatcher::new(&[serde_json::from_value(json!({
            "ip": "10.0.0.1", "port": 80
        }))?])?;

        assert!(endpoint_matcher.matches(&TngEndpoint::from_ipv4(Ipv4Addr::new(10, 0, 0, 1), 80)));
        assert!(!endpoint_matcher.matches(&TngEndpoint::from_ipv4(Ipv4Addr::new(10, 0, 0, 2), 80)));
        // Domain endpoint should not match IP rule
        assert!(
            !endpoint_matcher.matches(&TngEndpoint::from_domain("api.example.com".to_owned(), 80))
        );

        Ok(())
    }

    #[test]
    fn test_ip_cidr_match() -> Result<()> {
        use std::net::Ipv4Addr;

        let endpoint_matcher = EndpointMatcher::new(&[serde_json::from_value(json!({
            "ip_cidr": "10.0.0.0/24", "port": 80
        }))?])?;

        assert!(endpoint_matcher.matches(&TngEndpoint::from_ipv4(Ipv4Addr::new(10, 0, 0, 1), 80)));
        assert!(endpoint_matcher.matches(&TngEndpoint::from_ipv4(Ipv4Addr::new(10, 0, 0, 254), 80)));
        assert!(!endpoint_matcher.matches(&TngEndpoint::from_ipv4(Ipv4Addr::new(10, 0, 1, 1), 80)));

        Ok(())
    }

    #[test]
    fn test_host_match_config_domain_wildcard() -> Result<()> {
        // domain: "*" → HostMatchConfig::Domain → EnvoyDomainMatcher::MatchAny
        let item = EndpointMatcherItem::from_config(&serde_json::from_value(
            json!({"domain": "*", "port": 9991}),
        )?)?;
        assert!(item.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(item.matches(&TngEndpoint::new("*.foo.com", 9991)));
        // IP endpoints should NOT match domain rules
        assert!(!item.matches(&TngEndpoint::from_ipv4(
            "192.168.1.1".parse().unwrap(),
            9991
        )));

        Ok(())
    }

    #[test]
    fn test_host_match_config_all() -> Result<()> {
        // No domain/ip fields → HostMatchConfig::All → HostMatch::Any
        let item =
            EndpointMatcherItem::from_config(&serde_json::from_value(json!({"port": 9991}))?)?;
        // Should match both domain and IP endpoints
        assert!(item.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(item.matches(&TngEndpoint::from_ipv4("10.0.0.1".parse().unwrap(), 9991)));

        Ok(())
    }

    #[test]
    fn test_host_match_config_suffix_wildcard() -> Result<()> {
        let item = EndpointMatcherItem::from_config(&serde_json::from_value(
            json!({"domain": "*.foo.com", "port": 9991}),
        )?)?;
        assert!(item.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(item.matches(&TngEndpoint::new("*.foo.com", 9991)));
        assert!(!item.matches(&TngEndpoint::new("www.bar.com", 9991)));

        Ok(())
    }

    #[test]
    fn test_host_match_config_prefix_wildcard() -> Result<()> {
        let item = EndpointMatcherItem::from_config(&serde_json::from_value(
            json!({"domain": "www.foo.*", "port": 9991}),
        )?)?;
        assert!(item.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(item.matches(&TngEndpoint::new("www.foo.cn", 9991)));
        assert!(!item.matches(&TngEndpoint::new("*.foo.com", 9991)));
        assert!(!item.matches(&TngEndpoint::new("www.bar.com", 9991)));

        Ok(())
    }

    #[test]
    fn test_host_match_config_exact_domain() -> Result<()> {
        let item = EndpointMatcherItem::from_config(&serde_json::from_value(
            json!({"domain": "www.foo.com", "port": 9991}),
        )?)?;
        assert!(item.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(!item.matches(&TngEndpoint::new("www.bar.com", 9991)));

        Ok(())
    }

    #[test]
    fn test_host_match_config_domain_regex() -> Result<()> {
        let item = EndpointMatcherItem::from_config(&serde_json::from_value(
            json!({"domain_regex": ".*", "port": 9991}),
        )?)?;
        assert!(item.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(item.matches(&TngEndpoint::new("*.foo.com", 9991)));
        assert!(item.matches(&TngEndpoint::new("www.bar.com", 9991)));

        let item = EndpointMatcherItem::from_config(&serde_json::from_value(
            json!({"domain_regex": r".*foo\.com", "port": 9991}),
        )?)?;
        assert!(item.matches(&TngEndpoint::new("www.foo.com", 9991)));
        assert!(item.matches(&TngEndpoint::new("www.sub.foo.com", 9991)));
        assert!(item.matches(&TngEndpoint::new("new-foo.com", 9991)));
        assert!(!item.matches(&TngEndpoint::new("www.bar.com", 9991)));

        Ok(())
    }

    #[test]
    fn test_host_match_config_invalid_middle_wildcard() -> Result<()> {
        let result = EndpointMatcherItem::from_config(&serde_json::from_value(
            json!({"domain": "www.*.com", "port": 9991}),
        )?);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_host_match_config_invalid_regex() -> Result<()> {
        let result = EndpointMatcherItem::from_config(&serde_json::from_value(
            json!({"domain_regex": "*", "port": 9991}),
        )?);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_host_match_config_ip() -> Result<()> {
        let item =
            EndpointMatcherItem::from_config(&serde_json::from_value(json!({"ip": "10.0.0.1"}))?)?;
        assert!(item.matches(&TngEndpoint::from_ipv4("10.0.0.1".parse().unwrap(), 80)));
        assert!(!item.matches(&TngEndpoint::from_ipv4("10.0.0.2".parse().unwrap(), 80)));
        // Domain endpoint should not match IP rule
        assert!(!item.matches(&TngEndpoint::from_domain("api.example.com".to_owned(), 80)));

        Ok(())
    }

    #[test]
    fn test_host_match_config_ip_cidr() -> Result<()> {
        let item = EndpointMatcherItem::from_config(&serde_json::from_value(
            json!({"ip_cidr": "10.0.0.0/24"}),
        )?)?;
        assert!(item.matches(&TngEndpoint::from_ipv4("10.0.0.1".parse().unwrap(), 80)));
        assert!(item.matches(&TngEndpoint::from_ipv4("10.0.0.254".parse().unwrap(), 80)));
        assert!(!item.matches(&TngEndpoint::from_ipv4("10.0.1.1".parse().unwrap(), 80)));

        Ok(())
    }

    #[test]
    fn test_port_match_any() -> Result<()> {
        let item =
            EndpointMatcherItem::from_config(&serde_json::from_value(json!({"domain": "*"}))?)?;
        // Any port should match
        assert!(item.matches(&TngEndpoint::new("www.foo.com", 80)));
        assert!(item.matches(&TngEndpoint::new("www.foo.com", 12345)));
        assert!(item.matches(&TngEndpoint::new("www.foo.com", 1)));

        Ok(())
    }

    #[test]
    fn test_port_end_validation_errors() -> Result<()> {
        // port_end without port
        assert!(EndpointMatcherItem::from_config(&serde_json::from_value(
            json!({"domain": "*", "port_end": 30063})
        )?,)
        .is_err());

        // port_end < port
        assert!(EndpointMatcherItem::from_config(&serde_json::from_value(
            json!({"domain": "*", "port": 30063, "port_end": 30000})
        )?,)
        .is_err());

        Ok(())
    }

    #[test]
    fn test_domain_and_domain_regex_together_domain_wins() -> Result<()> {
        // When both domain and domain_regex are present, untagged serde
        // picks the first matching variant → Domain. This matches the
        // old behavior where domain took precedence.
        let item = EndpointMatcherItem::from_config(&serde_json::from_value(
            json!({"domain": "*", "domain_regex": ".*", "port": 9991}),
        )?)?;
        assert!(item.matches(&TngEndpoint::new("www.foo.com", 9991)));

        Ok(())
    }
}

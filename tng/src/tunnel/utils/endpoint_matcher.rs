use anyhow::{bail, Context, Result};
use either::Either;
use regex::Regex;

use crate::{config::ingress::EndpointFilter, tunnel::endpoint::TngEndpoint};

#[derive(Debug)]
pub struct EndpointMatcher {
    items: Vec<MatchItem>,
}

#[derive(Debug)]
struct MatchItem {
    matcher: Either<Regex, EnvoyDomainMatcher>,
    port: u16,
    port_end: Option<u16>,
}

impl EndpointMatcher {
    pub fn new(dst_filters: &[EndpointFilter]) -> Result<Self> {
        let items = dst_filters
            .iter()
            .map(|dst_filter| -> Result<_> {
                let matcher = match (&dst_filter.domain, &dst_filter.domain_regex) {
                    (None, domain_regex) => {
                        let regex = Regex::new(domain_regex.as_deref().unwrap_or(".*"))
                            .context("The value of 'domain_regex' should be a regex")?;
                        Either::Left(regex)
                    }
                    (Some(domain), None) => Either::Right(EnvoyDomainMatcher::new(domain)?),
                    (Some(_), Some(_)) => {
                        bail!("Cannot specify both 'domain' and 'domain_regex")
                    }
                };
                let port = dst_filter.port.unwrap_or(80);
                if let Some(end) = dst_filter.port_end {
                    if dst_filter.port.is_none() {
                        bail!("`port_end` requires `port` to be specified");
                    }
                    if end < port {
                        bail!("`port_end` ({end}) must be >= `port` ({port})");
                    }
                }
                Ok(MatchItem {
                    matcher,
                    port,
                    port_end: dst_filter.port_end,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { items })
    }

    pub fn matches(&self, endpoint: &TngEndpoint) -> bool {
        if self.items.is_empty() {
            return true;
        }

        for item in &self.items {
            let is_match = match &item.matcher {
                Either::Left(m) => m.is_match(endpoint.host()),
                Either::Right(m) => m.is_match(endpoint.host()),
            };

            if is_match && Self::port_matches(item.port, item.port_end, endpoint.port()) {
                return true;
            }
        }
        false
    }

    fn port_matches(port: u16, port_end: Option<u16>, actual: u16) -> bool {
        match port_end {
            Some(end) => port <= actual && actual <= end,
            None => port == actual,
        }
    }
}

/// This is a matcher that compatible with the [envoy domain matcher](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#config-route-v3-virtualhost).
#[derive(Debug)]
enum EnvoyDomainMatcher {
    /// Exact domain names: www.foo.com.
    Exact(String),
    /// Suffix domain wildcards: *.foo.com or *-bar.foo.com.
    Suffix(String),
    /// Prefix domain wildcards: foo.* or foo-*.
    Prefix(String),
    /// Special wildcard * matching any domain.
    MatchAny,
}

impl EnvoyDomainMatcher {
    pub fn new(domain: &str) -> Result<Self> {
        if domain == "*" {
            Ok(EnvoyDomainMatcher::MatchAny)
        } else if let Some(stripped) = domain.strip_prefix('*') {
            Ok(EnvoyDomainMatcher::Suffix(stripped.to_owned()))
        } else if let Some(stripped) = domain.strip_suffix('*') {
            Ok(EnvoyDomainMatcher::Prefix(stripped.to_owned()))
        } else if !domain.contains('*') {
            Ok(EnvoyDomainMatcher::Exact(domain.to_owned()))
        } else {
            bail!("The wildcard * should not be used in the middle of the domain: {domain}")
        }
    }

    #[inline]
    pub fn is_match(&self, haystack: &str) -> bool {
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

    #[test]
    fn test_domain_match() -> Result<()> {
        assert!(EndpointMatcher::new(&[serde_json::from_value(json! {
            {
                "domain": "*",
                "domain_regex": ".*",
                "port": 9991
            }
        })?])
        .is_err());

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
}

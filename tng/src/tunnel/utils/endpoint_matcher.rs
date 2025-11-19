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
                Ok(MatchItem {
                    matcher,
                    port: dst_filter.port.unwrap_or(80),
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

            if is_match && item.port == endpoint.port() {
                return true;
            }
        }
        false
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
}

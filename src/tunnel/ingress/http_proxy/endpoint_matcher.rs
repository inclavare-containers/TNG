use anyhow::{Context, Result};
use regex::Regex;

use crate::{config::ingress::EndpointFilter, tunnel::ingress::core::TngEndpoint};

pub struct RegexEndpointMatcher {
    items: Vec<MatchItem>,
}

struct MatchItem {
    regex: Regex,
    port: u16,
}

impl RegexEndpointMatcher {
    pub fn new(dst_filters: &[EndpointFilter]) -> Result<Self> {
        let items = dst_filters
            .iter()
            .map(|dst_filter| -> Result<_> {
                let regex = Regex::new(&dst_filter.domain.as_deref().unwrap_or("*"))
                    .context("The value of 'domain' should be a regex")?;
                Ok(MatchItem {
                    regex,
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
            if item.regex.is_match(endpoint.host()) && item.port == endpoint.port() {
                return true;
            }
        }
        false
    }
}

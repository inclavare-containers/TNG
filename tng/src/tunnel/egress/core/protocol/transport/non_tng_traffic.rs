use anyhow::{Context, Result};

use crate::config::egress::DecapFromHttp;

pub struct DirectlyForwardTrafficDetector {
    regexes: Vec<regex::Regex>,
}

impl DirectlyForwardTrafficDetector {
    pub fn new(decap_from_http: &DecapFromHttp) -> Result<Self> {
        let regexes = decap_from_http
            .allow_non_tng_traffic_regexes
            .iter()
            .flat_map(|allow_non_tng_traffic_regexes| allow_non_tng_traffic_regexes.iter())
            .map(|regex| {
                regex::Regex::new(regex).with_context(|| format!("Invalid regex: {}", regex))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { regexes })
    }

    pub fn should_forward_directly(&self, path: &str) -> bool {
        self.regexes.iter().any(|regex| regex.is_match(path))
    }
}

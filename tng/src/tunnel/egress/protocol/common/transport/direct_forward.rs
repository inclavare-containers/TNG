use anyhow::{Context, Result};

use crate::{
    config::egress::{DirectForwardRule, DirectForwardRules},
    tunnel::utils::http_inspector::RequestInfo,
};

pub struct DirectForwardTrafficDetector {
    rule_matchers: Vec<RuleMatcher>,
}

impl DirectForwardTrafficDetector {
    pub fn new(rules: DirectForwardRules) -> Result<Self> {
        let rule_matchers = rules
            .0
            .iter()
            .map(|rule| RuleMatcher::new(rule))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { rule_matchers })
    }

    pub fn should_forward_directly(&self, request_info: &RequestInfo) -> bool {
        self.rule_matchers
            .iter()
            .any(|regex: &RuleMatcher| regex.is_match(request_info))
    }
}

struct RuleMatcher {
    http_path_regex: regex::Regex,
}

impl RuleMatcher {
    pub fn new(rule: &DirectForwardRule) -> Result<Self> {
        let regex = &rule.http_path;

        Ok(Self {
            http_path_regex: regex::Regex::new(regex)
                .with_context(|| format!("Invalid regex: {}", regex))?,
        })
    }

    pub fn is_match(&self, request_info: &RequestInfo) -> bool {
        match request_info {
            RequestInfo::Http1 { path, .. } | RequestInfo::Http2 { path, .. } => {
                self.http_path_regex.is_match(path)
            }
            RequestInfo::UnknownProtocol => false,
        }
    }
}

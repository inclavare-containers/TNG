use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Endpoint within a mapping rule. Host is always a single IPv4 address;
/// port can be a single value or a closed range [port, port_end].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEndpoint {
    pub host: Option<Ipv4Addr>,
    pub port: u16,
    /// Optional end port for port range matching.
    /// When set, represents a closed interval [port, port_end].
    pub port_end: Option<u16>,
}

/// A single mapping rule: one in→out forwarding pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingRule {
    pub r#in: RuleEndpoint,
    pub out: RuleEndpoint,
}

/// Legacy endpoint used during deserialization of old-style mapping configs.
#[derive(Debug, Clone, Deserialize)]
pub struct LegacyEndpoint {
    pub host: Option<Ipv4Addr>,
    pub port: u16,
}

/// Dual-mode deserialization for mapping args:
/// either new `{ "rules": [...] }` or legacy `{ "in": {...}, "out": {...} }`.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum MappingDe {
    /// New format: { "rules": [...] }
    Rules { rules: Vec<MappingRule> },
    /// Legacy format: { "in": {...}, "out": {...} }
    Legacy {
        #[serde(rename = "in")]
        r#in: LegacyEndpoint,
        out: LegacyEndpoint,
    },
}

impl MappingDe {
    /// Convert into a validated Vec<MappingRule>.
    /// Performs port_end validation, range size matching, and overlap checks.
    pub fn into_checked(self, label: &str) -> anyhow::Result<Vec<MappingRule>> {
        let rules = match self {
            MappingDe::Rules { rules } => rules,
            MappingDe::Legacy { r#in, out } => {
                vec![MappingRule {
                    r#in: RuleEndpoint {
                        host: r#in.host,
                        port: r#in.port,
                        port_end: None,
                    },
                    out: RuleEndpoint {
                        host: out.host,
                        port: out.port,
                        port_end: None,
                    },
                }]
            }
        };

        // Validate each rule
        for (i, rule) in rules.iter().enumerate() {
            // port_end >= port for in
            if let Some(end) = rule.r#in.port_end {
                if end < rule.r#in.port {
                    anyhow::bail!(
                        "{label} rule {i}: in port_end ({end}) must be >= port ({})",
                        rule.r#in.port
                    );
                }
            }
            // port_end >= port for out
            if let Some(end) = rule.out.port_end {
                if end < rule.out.port {
                    anyhow::bail!(
                        "{label} rule {i}: out port_end ({end}) must be >= port ({})",
                        rule.out.port
                    );
                }
            }
            // out.host required
            if rule.out.host.is_none() {
                anyhow::bail!("{label} rule {i}: out.host is required");
            }
            // Range size match
            let in_span = rule.r#in.port_end.unwrap_or(rule.r#in.port) - rule.r#in.port;
            let out_span = rule.out.port_end.unwrap_or(rule.out.port) - rule.out.port;
            if in_span != out_span {
                anyhow::bail!(
                    "{label} rule {i}: in port range size ({}) != out port range size ({})",
                    in_span + 1,
                    out_span + 1
                );
            }
        }

        // Check for overlapping in endpoints
        for i in 0..rules.len() {
            for j in (i + 1)..rules.len() {
                if endpoints_overlap(&rules[i].r#in, &rules[j].r#in) {
                    anyhow::bail!("{label}: rules {i} and {j} have overlapping in endpoints");
                }
            }
        }

        Ok(rules)
    }
}

fn endpoints_overlap(a: &RuleEndpoint, b: &RuleEndpoint) -> bool {
    if a.host.unwrap_or(Ipv4Addr::UNSPECIFIED) != b.host.unwrap_or(Ipv4Addr::UNSPECIFIED) {
        return false;
    }

    let a_start = a.port;
    let a_end = a.port_end.unwrap_or(a.port);
    let b_start = b.port;
    let b_end = b.port_end.unwrap_or(b.port);

    a_start <= b_end && b_start <= a_end
}

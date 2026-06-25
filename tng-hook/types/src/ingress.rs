use std::net::SocketAddrV4;

use serde::{Deserialize, Serialize};

/// Ingress hook mapping table distributed from TNG parent to the hook library via env var.
///
/// Serialized as JSON and passed via `TNG_HOOK_INGRESS_MAPPINGS` environment variable.
/// Groups capture rules by their shared proxy port — one ingress hook rule
/// produces one `IngressHookProxy` entry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IngressHookMappingTable {
    /// One entry per unique HTTP proxy port. Each proxy groups its
    /// capture rules that should be routed through it.
    pub proxies: Vec<IngressHookProxy>,
}

/// A single HTTP proxy endpoint with its associated capture rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressHookProxy {
    /// The internal HTTP proxy port on the TNG main process that
    /// handles CONNECT requests for the associated capture rules.
    pub proxy_port: u16,

    /// Capture rules that map to this proxy port.
    pub capture_rules: Vec<IngressHookCaptureRule>,
}

/// A single capture rule: match destination IP+port and route to the proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressHookCaptureRule {
    /// IPv4 CIDR or exact IP. Wildcard (match any IP) is represented as "*".
    /// Normal values: "10.0.0.0/24" (CIDR) or "192.168.1.1" (exact IP).
    pub host_cidr: String,

    /// Start of port range to intercept.
    pub port: u16,

    /// End of port range (inclusive). None = exact port match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_end: Option<u16>,
}

/// Internal lookup structure built from IngressHookMappingTable.
///
/// Built once at library init time, read-only thereafter.
pub struct IngressHookLookup {
    proxies: Vec<IngressHookProxy>,
}

impl IngressHookLookup {
    /// Build the lookup from a deserialized `IngressHookMappingTable`.
    pub fn from_table(table: &IngressHookMappingTable) -> Self {
        Self {
            proxies: table.proxies.clone(),
        }
    }

    /// Find the proxy port for a given destination (IP, port).
    /// Returns the first matching proxy_port, or None.
    /// Iterates proxies in order; within each proxy, checks capture_rules.
    pub fn find_proxy_port(&self, dst: SocketAddrV4) -> Option<u16> {
        for proxy in &self.proxies {
            for rule in &proxy.capture_rules {
                if rule.matches(dst) {
                    return Some(proxy.proxy_port);
                }
            }
        }
        None
    }
}

impl IngressHookCaptureRule {
    /// Check if this rule matches the given destination address.
    pub fn matches(&self, dst: SocketAddrV4) -> bool {
        // CIDR match
        let cidr_matches = if self.host_cidr == "*" {
            true
        } else if let Ok(cidr) = self.host_cidr.parse::<cidr::Ipv4Cidr>() {
            cidr.contains(dst.ip())
        } else if let Ok(ip) = self.host_cidr.parse::<std::net::Ipv4Addr>() {
            ip == *dst.ip()
        } else {
            false
        };
        if !cidr_matches {
            return false;
        }

        // Port range match
        let port_end = self.port_end.unwrap_or(self.port);
        dst.port() >= self.port && dst.port() <= port_end
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_ingress_capture_rule_exact_match() {
        let rule = IngressHookCaptureRule {
            host_cidr: "10.0.0.0/24".to_string(),
            port: 80,
            port_end: None,
        };
        assert!(rule.matches(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 80)));
        assert!(!rule.matches(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 443)));
        assert!(!rule.matches(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 80)));
    }

    #[test]
    fn test_ingress_capture_rule_port_range() {
        let rule = IngressHookCaptureRule {
            host_cidr: "10.0.0.0/24".to_string(),
            port: 8080,
            port_end: Some(8090),
        };
        assert!(rule.matches(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080)));
        assert!(rule.matches(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8085)));
        assert!(rule.matches(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8090)));
        assert!(!rule.matches(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8079)));
        assert!(!rule.matches(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8091)));
    }

    #[test]
    fn test_ingress_capture_rule_wildcard() {
        let rule = IngressHookCaptureRule {
            host_cidr: "*".to_string(),
            port: 443,
            port_end: None,
        };
        assert!(rule.matches(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443)));
        assert!(rule.matches(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 443)));
        assert!(!rule.matches(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80)));
    }

    #[test]
    fn test_ingress_lookup_first_match_wins() {
        let table = IngressHookMappingTable {
            proxies: vec![
                IngressHookProxy {
                    proxy_port: 49001,
                    capture_rules: vec![IngressHookCaptureRule {
                        host_cidr: "10.0.0.0/24".to_string(),
                        port: 80,
                        port_end: None,
                    }],
                },
                IngressHookProxy {
                    proxy_port: 49002,
                    capture_rules: vec![IngressHookCaptureRule {
                        host_cidr: "*".to_string(),
                        port: 80,
                        port_end: None,
                    }],
                },
            ],
        };
        let lookup = IngressHookLookup::from_table(&table);
        // 10.0.0.5:80 should match the first rule (49001), not the wildcard (49002)
        assert_eq!(
            lookup.find_proxy_port(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 80)),
            Some(49001)
        );
        // 192.168.1.1:80 should match the wildcard rule (49002)
        assert_eq!(
            lookup.find_proxy_port(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 80)),
            Some(49002)
        );
        // No match for port 443
        assert!(lookup
            .find_proxy_port(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 443))
            .is_none());
    }

    #[test]
    fn test_ingress_json_roundtrip() {
        let table = IngressHookMappingTable {
            proxies: vec![
                IngressHookProxy {
                    proxy_port: 49001,
                    capture_rules: vec![
                        IngressHookCaptureRule {
                            host_cidr: "10.0.0.0/24".to_string(),
                            port: 80,
                            port_end: None,
                        },
                        IngressHookCaptureRule {
                            host_cidr: "10.0.0.0/24".to_string(),
                            port: 443,
                            port_end: None,
                        },
                    ],
                },
                IngressHookProxy {
                    proxy_port: 49002,
                    capture_rules: vec![IngressHookCaptureRule {
                        host_cidr: "*".to_string(),
                        port: 8080,
                        port_end: Some(8090),
                    }],
                },
            ],
        };
        let json = serde_json::to_string(&table).unwrap();
        let parsed: IngressHookMappingTable = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.proxies.len(), 2);
        assert_eq!(parsed.proxies[0].proxy_port, 49001);
        assert_eq!(parsed.proxies[0].capture_rules.len(), 2);
        assert_eq!(parsed.proxies[1].capture_rules[0].port_end, Some(8090));
    }
}

use anyhow::bail;
use cidr::Ipv4Cidr;
use serde::{Deserialize, Serialize};
use serde_with::{formats::PreferMany, serde_as, OneOrMany};
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;

/// Wildcard CIDR (0.0.0.0/0 — match all).
#[allow(clippy::expect_used)]
fn wildcard_cidr() -> Ipv4Cidr {
    Ipv4Cidr::new(Ipv4Addr::UNSPECIFIED, 0).expect("0.0.0.0/0 is always valid")
}

/// Configuration for the hook-based egress mode.
///
/// Uses LD_PRELOAD to intercept the server application's bind()/getsockname()
/// syscalls, redirecting listening sockets through the TNG tunnel.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressHookArgs {
    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    #[serde(default = "Vec::new")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capture_listen: Vec<EgressHookInterceptEntry>,

    /// Resolved port mappings, built by `tng exec` at runtime.
    /// Each capture_listen entry is expanded into one or more TngEgressHookMappingEntry
    /// (ranges → individual ports, auto-allocated real ports resolved).
    /// This field is not serializable to the .so — a separate port-only
    /// EgressHookMappingTable is built for that.
    /// This field is not serialized — it's a runtime-only data channel from exec to runtime.
    #[serde(skip, default)]
    pub resolved_entries: Vec<TngEgressHookMappingEntry>,
}

/// A single intercept rule for the hook egress mode.
///
/// When the server application binds to the specified address/port,
/// TNG redirects it to a different (real) port.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressHookInterceptEntry {
    /// IPv4 address to match (e.g., "0.0.0.0", "192.168.1.1").
    /// When omitted, matches any bind address.
    pub host: Option<Ipv4Cidr>,

    /// Port to intercept. Required.
    pub port: Option<u16>,

    /// Optional end port for range matching.
    /// When omitted, TNG treats this as a single-port entry.
    /// When present without `redirect_to_port_end`, TNG auto-allocates the real port range.
    /// When present with `redirect_to_port_end`, TNG uses the specified redirect range.
    /// Must be >= port.
    pub port_end: Option<u16>,

    /// Real port to redirect to.
    /// If not specified, TNG auto-allocates an available port.
    pub redirect_to_port: Option<u16>,

    /// Optional end port for redirect range.
    /// Must be present if and only if `port_end` is present AND `redirect_to_port` is specified.
    /// Range length must match: `port_end - port == redirect_to_port_end - redirect_to_port`.
    /// Must be >= redirect_to_port.
    pub redirect_to_port_end: Option<u16>,
}

/// Internal mapping entry used by TNG exec/runtime.
///
/// Unlike EgressHookMappingEntry (passed to the .so), this includes the host
/// CIDR for runtime accept-time filtering.
#[derive(Debug, Clone)]
pub struct TngEgressHookMappingEntry {
    /// Host CIDR to match at accept time (e.g. 172.17.80.0/20)
    pub host_cidr: Ipv4Cidr,
    /// The port the app thinks it's binding to
    pub origin_port: u16,
    /// The actual port the app binds to (redirected by hook)
    pub real_port: u16,
}

impl TngEgressHookMappingEntry {
    /// Build a host filter rule from this mapping entry.
    ///
    /// Returns `None` when the host CIDR is 0.0.0.0/0 (match all),
    /// meaning no host-level filtering is needed.
    pub fn host_filter_rule(&self) -> Option<EgressHookHostFilterRule> {
        let cidr = &self.host_cidr;
        if cidr.first_address() == Ipv4Addr::UNSPECIFIED && cidr.network_length() == 0 {
            return None;
        }
        Some(EgressHookHostFilterRule {
            host_cidr: self.host_cidr,
            port_range: self.origin_port..=self.origin_port,
        })
    }
}

/// Host filter rule used at accept time.
///
/// A connection's local_addr.ip() is checked against this CIDR,
/// and the local port is checked against the port range.
#[derive(Debug, Clone)]
pub struct EgressHookHostFilterRule {
    pub host_cidr: Ipv4Cidr,
    pub port_range: RangeInclusive<u16>,
}

impl EgressHookInterceptEntry {
    /// Validate this entry and expand it into TNG-internal mapping entries.
    ///
    /// Returns a list of TngEgressHookMappingEntry tuples and the next
    /// unused auto-allocated port number.
    pub fn expand_mappings(
        &self,
        next_auto_port: u16,
    ) -> anyhow::Result<(Vec<TngEgressHookMappingEntry>, u16)> {
        let port = self
            .port
            .ok_or_else(|| anyhow::anyhow!("'port' is required"))?;
        let port_end = self.port_end.unwrap_or(port);

        if port_end < port {
            bail!("'port_end' ({}) must be >= 'port' ({})", port_end, port);
        }

        // Default host CIDR: 0.0.0.0/0 (match all) when not specified
        let host_cidr = self.host.unwrap_or(wildcard_cidr());

        let redirect_to_port = self.redirect_to_port;
        let redirect_to_port_end = self.redirect_to_port_end;

        // Helper to create a mapping entry
        let make_entry = |origin_port: u16, real_port: u16| TngEgressHookMappingEntry {
            host_cidr,
            origin_port,
            real_port,
        };

        match (redirect_to_port, redirect_to_port_end) {
            (None, None) => {
                // Auto-allocate all ports in range
                let range_len = (port_end - port + 1) as usize;
                let mut entries = Vec::with_capacity(range_len);
                let mut current_real = next_auto_port;

                for i in 0..range_len {
                    entries.push(make_entry(port + i as u16, current_real));
                    current_real = current_real.checked_add(1).unwrap_or(49152);
                    // wrap to ephemeral
                }

                Ok((entries, current_real))
            }
            (Some(rt), Some(rt_end)) => {
                if rt_end < rt {
                    bail!(
                        "'redirect_to_port_end' ({}) must be >= 'redirect_to_port' ({})",
                        rt_end,
                        rt
                    );
                }
                let range_len = port_end - port;
                let redirect_range_len = rt_end - rt;
                if range_len != redirect_range_len {
                    bail!(
                        "port range length ({}) must match redirect range length ({})",
                        range_len,
                        redirect_range_len
                    );
                }

                let count = range_len + 1;
                let mut entries = Vec::with_capacity(count as usize);

                for i in 0..count {
                    entries.push(make_entry(port + i, rt + i));
                }

                Ok((entries, next_auto_port))
            }
            (Some(rt), None) => {
                // Single redirect port without end — only valid for single-port entries
                if self.port_end.is_some() {
                    bail!("'redirect_to_port_end' must be set when 'redirect_to_port' is set with a port range (port_end is present)");
                }
                let entries = vec![make_entry(port, rt)];
                Ok((entries, next_auto_port))
            }
            (None, Some(_)) => {
                bail!("'redirect_to_port' must be set when 'redirect_to_port_end' is present");
            }
        }
    }
}

impl TryFrom<EgressHookInterceptEntry> for Vec<TngEgressHookMappingEntry> {
    type Error = anyhow::Error;

    fn try_from(value: EgressHookInterceptEntry) -> Result<Self, Self::Error> {
        let (entries, _) = value.expand_mappings(40000)?;
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::json;

    use super::*;

    #[test]
    fn test_deserialize_single_port() -> Result<()> {
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "port": 8080
        }))?;
        assert_eq!(entry.port, Some(8080));
        assert!(entry.port_end.is_none());
        assert!(entry.redirect_to_port.is_none());
        Ok(())
    }

    #[test]
    fn test_deserialize_with_redirect() -> Result<()> {
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "port": 8080,
            "redirect_to_port": 48080
        }))?;
        assert_eq!(entry.redirect_to_port, Some(48080));
        Ok(())
    }

    #[test]
    fn test_deserialize_port_range_with_redirect_range() -> Result<()> {
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "port": 8080,
            "port_end": 8090,
            "redirect_to_port": 48080,
            "redirect_to_port_end": 48090
        }))?;
        assert_eq!(entry.port_end, Some(8090));
        assert_eq!(entry.redirect_to_port_end, Some(48090));
        Ok(())
    }

    #[test]
    fn test_deserialize_host_specific() -> Result<()> {
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "host": "192.168.1.1",
            "port": 30002,
            "redirect_to_port": 45002
        }))?;
        assert!(entry.host.is_some());
        Ok(())
    }

    #[test]
    fn test_expand_single_port_auto_alloc() -> Result<()> {
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "port": 8080
        }))?;
        let (entries, next_port) = entry.expand_mappings(40000)?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].origin_port, 8080);
        assert_eq!(entries[0].real_port, 40000);
        assert_eq!(next_port, 40001);
        // host_cidr should be 0.0.0.0/0 when not specified
        assert!(entries[0].host_cidr.contains(&Ipv4Addr::UNSPECIFIED));
        Ok(())
    }

    #[test]
    fn test_expand_with_redirect() -> Result<()> {
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "port": 8080,
            "redirect_to_port": 48080
        }))?;
        let (entries, next_port) = entry.expand_mappings(40000)?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].origin_port, 8080);
        assert_eq!(entries[0].real_port, 48080);
        assert_eq!(next_port, 40000); // auto port unchanged
        Ok(())
    }

    #[test]
    fn test_expand_port_range_auto_alloc() -> Result<()> {
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "port": 8080,
            "port_end": 8082
        }))?;
        let (entries, next_port) = entry.expand_mappings(40000)?;
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].origin_port, 8080);
        assert_eq!(entries[0].real_port, 40000);
        assert_eq!(entries[1].origin_port, 8081);
        assert_eq!(entries[1].real_port, 40001);
        assert_eq!(entries[2].origin_port, 8082);
        assert_eq!(entries[2].real_port, 40002);
        assert_eq!(next_port, 40003);
        Ok(())
    }

    #[test]
    fn test_expand_port_range_with_redirect_range() -> Result<()> {
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "port": 8080,
            "port_end": 8082,
            "redirect_to_port": 48080,
            "redirect_to_port_end": 48082
        }))?;
        let (entries, _) = entry.expand_mappings(40000)?;
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].real_port, 48080);
        assert_eq!(entries[1].real_port, 48081);
        assert_eq!(entries[2].real_port, 48082);
        Ok(())
    }

    #[test]
    fn test_validation_port_end_without_redirect_end() {
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "port": 8080,
            "port_end": 8090
        }))
        .unwrap();
        let result = entry.expand_mappings(40000);
        // Should succeed with auto-allocation (redirect not required for auto)
        assert!(result.is_ok());
    }

    #[test]
    fn test_validation_redirect_port_without_redirect_end_when_range() {
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "port": 8080,
            "port_end": 8090,
            "redirect_to_port": 48080
        }))
        .unwrap();
        let result = entry.expand_mappings(40000);
        // This should fail because port_end is present but redirect_to_port_end is not
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_hook_args_empty() -> Result<()> {
        let args: EgressHookArgs = serde_json::from_value(json!({}))?;
        assert!(args.capture_listen.is_empty());
        Ok(())
    }

    #[test]
    fn test_deserialize_hook_args_array() -> Result<()> {
        let args: EgressHookArgs = serde_json::from_value(json!({
            "capture_listen": [
                { "port": 30001 },
                { "port": 8080, "port_end": 8090, "redirect_to_port": 48080, "redirect_to_port_end": 48090 }
            ]
        }))?;
        assert_eq!(args.capture_listen.len(), 2);
        Ok(())
    }

    #[test]
    fn test_validation_port_end_less_than_port() {
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "port": 8090,
            "port_end": 8080
        }))
        .unwrap();
        assert!(entry.expand_mappings(40000).is_err());
    }

    #[test]
    fn test_validation_range_length_mismatch() {
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "port": 8080,
            "port_end": 8085,
            "redirect_to_port": 48080,
            "redirect_to_port_end": 48090  // 11 vs 6 length mismatch
        }))
        .unwrap();
        assert!(entry.expand_mappings(40000).is_err());
    }

    #[test]
    fn test_host_filter_rule_wildcard_returns_none() {
        // When host CIDR is 0.0.0.0/0, host_filter_rule should return None
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "port": 8080,
            "redirect_to_port": 48080
        }))
        .unwrap();
        let (entries, _) = entry.expand_mappings(40000).unwrap();
        assert!(entries[0].host_filter_rule().is_none());
    }

    #[test]
    fn test_host_filter_rule_specific_host_returns_some() {
        // When host CIDR is a specific network, host_filter_rule should return Some
        let entry: EgressHookInterceptEntry = serde_json::from_value(json!({
            "host": "172.17.80.0/20",
            "port": 8080,
            "redirect_to_port": 48080
        }))
        .unwrap();
        let (entries, _) = entry.expand_mappings(40000).unwrap();
        let rule = entries[0].host_filter_rule().expect("expected Some");
        assert_eq!(rule.port_range, (8080..=8080));
        // Verify the CIDR matches
        assert!(rule
            .host_cidr
            .contains(&"172.17.80.0".parse::<Ipv4Addr>().unwrap()));
        assert!(!rule
            .host_cidr
            .contains(&"192.168.1.1".parse::<Ipv4Addr>().unwrap()));
    }
}

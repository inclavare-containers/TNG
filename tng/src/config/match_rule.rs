use serde::{Deserialize, Serialize};

/// Host/address matching rule. Serialized flat so that old JSON configs
/// work without a `"type"` discriminator. When none of the domain/ip fields
/// are present, deserializes to `HostMatchConfig::All`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HostMatchConfig {
    /// Exact domain name or Envoy-style wildcard: `"www.foo.com"`, `"*.foo.com"`, `"foo.*"`.
    Domain { domain: String },
    /// Regex domain match.
    DomainRegex { domain_regex: String },
    /// Exact IPv4 address match.
    Ip { ip: String },
    /// IPv4 CIDR range match.
    IpCidr { ip_cidr: String },
    /// Matches all endpoint types (domain and IP). Hit when no other variant matches.
    All {}, // Keep empty here for serde(untagged). See https://github.com/serde-rs/serde/issues/2918
}

/// Port matching configuration. Serialized flat alongside `HostMatchConfig`.
///
/// Default (both fields absent) = `PortMatch::Any`, meaning any port matches.
///
/// When `port_end` is set together with `port`, matches destination ports in
/// the range `[port, port_end]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortMatchConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Optional end port for port range matching.
    ///
    /// When set together with `port`, matches destination ports in the range `[port, port_end]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_end: Option<u16>,
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[test]
    fn test_host_match_config_serialize_roundtrip_domain() -> Result<()> {
        let original = HostMatchConfig::Domain {
            domain: "www.example.com".to_owned(),
        };
        let json = serde_json::to_string(&original)?;
        assert_eq!(json, r#"{"domain":"www.example.com"}"#);
        let deserialized: HostMatchConfig = serde_json::from_str(&json)?;
        match deserialized {
            HostMatchConfig::Domain { domain } => assert_eq!(domain, "www.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn test_host_match_config_serialize_roundtrip_ip() -> Result<()> {
        let original = HostMatchConfig::Ip {
            ip: "10.0.0.1".to_owned(),
        };
        let json = serde_json::to_string(&original)?;
        assert_eq!(json, r#"{"ip":"10.0.0.1"}"#);
        let deserialized: HostMatchConfig = serde_json::from_str(&json)?;
        match deserialized {
            HostMatchConfig::Ip { ip } => assert_eq!(ip, "10.0.0.1"),
            other => panic!("expected Ip, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn test_host_match_config_serialize_roundtrip_all() -> Result<()> {
        let original = HostMatchConfig::All {};
        let json = serde_json::to_string(&original)?;
        assert_eq!(json, "{}");
        let deserialized: HostMatchConfig = serde_json::from_str(&json)?;
        assert!(matches!(deserialized, HostMatchConfig::All {}));
        Ok(())
    }

    #[test]
    fn test_host_match_config_serialize_roundtrip_ip_cidr() -> Result<()> {
        let original = HostMatchConfig::IpCidr {
            ip_cidr: "10.0.0.0/24".to_owned(),
        };
        let json = serde_json::to_string(&original)?;
        assert_eq!(json, r#"{"ip_cidr":"10.0.0.0/24"}"#);
        let deserialized: HostMatchConfig = serde_json::from_str(&json)?;
        match deserialized {
            HostMatchConfig::IpCidr { ip_cidr } => assert_eq!(ip_cidr, "10.0.0.0/24"),
            other => panic!("expected IpCidr, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn test_host_match_config_serialize_roundtrip_domain_regex() -> Result<()> {
        let original = HostMatchConfig::DomainRegex {
            domain_regex: r".*\.example\.com".to_owned(),
        };
        let json = serde_json::to_string(&original)?;
        assert_eq!(json, r#"{"domain_regex":".*\\.example\\.com"}"#);
        let deserialized: HostMatchConfig = serde_json::from_str(&json)?;
        match deserialized {
            HostMatchConfig::DomainRegex { domain_regex } => {
                assert_eq!(domain_regex, r".*\.example\.com")
            }
            other => panic!("expected DomainRegex, got {other:?}"),
        }
        Ok(())
    }
}

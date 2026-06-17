use anyhow::bail;
use cidr::Ipv4Cidr;
use serde::{Deserialize, Serialize};
use serde_with::{formats::PreferMany, serde_as, OneOrMany};

use super::mapping_rule::MappingDe;
use super::{ra::RaArgsUnchecked, Endpoint};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddIngressArgs {
    #[serde(flatten)]
    pub ingress_mode: IngressMode,

    #[serde(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonArgs {
    #[serde(default = "Option::default")]
    #[serde(alias = "encap_in_http")]
    pub ohttp: Option<OHttpArgs>,

    #[serde(default = "bool::default")]
    pub web_page_inject: bool,

    #[serde(default = "Option::default")]
    pub rats_tls: Option<RatsTlsArgs>,

    #[serde(flatten)]
    pub ra_args: RaArgsUnchecked,
}

/// Configuration for rats-TLS transport.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RatsTlsArgs {
    /// When `true`, uses HTTP/2 CONNECT tunneling to multiplex multiple
    /// TCP streams over a single rats-TLS connection, reducing handshake overhead.
    /// Suitable for many short-lived connections with small data transfers.
    /// When `false` (default), each downstream connection creates an independent TLS
    /// session without HTTP/2 CONNECT or connection pooling, achieving higher
    /// per-stream throughput — recommended for high-bandwidth scenarios.
    /// Note: with `multiplex: true`, all streams share a single TLS connection
    /// whose bandwidth is limited by the TLS encryption capacity of one CPU core.
    #[serde(default)]
    pub multiplex: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum IngressMode {
    #[serde(rename = "mapping")]
    Mapping(IngressMappingArgs),

    #[serde(rename = "http_proxy")]
    HttpProxy(IngressHttpProxyArgs),

    #[serde(rename = "netfilter")]
    Netfilter(IngressNetfilterArgs),

    #[serde(rename = "socks5")]
    Socks5(IngressSocks5Args),
}

#[derive(Debug, Clone, Serialize)]
pub struct IngressMappingArgs {
    /// Parsed rules: either from the new `rules` array, or a single rule
    /// synthesized from the legacy `in`/`out` fields.
    pub rules: Vec<super::mapping_rule::MappingRule>,
}

impl<'de> Deserialize<'de> for IngressMappingArgs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let de = MappingDe::deserialize(deserializer)?;
        let rules = de
            .into_checked("ingress mapping")
            .map_err(serde::de::Error::custom)?;
        Ok(Self { rules })
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressHttpProxyArgs {
    pub proxy_listen: Endpoint,

    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    #[serde(default = "Vec::new")]
    // In TNG version <= 1.0.1, this field is named as `dst_filter`
    #[serde(alias = "dst_filter")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dst_filters: Vec<EndpointFilter>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressNetfilterArgs {
    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    #[serde(default = "Vec::new")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capture_dst: Vec<IngressNetfilterCaptureDstArgs>,

    #[serde(default = "Vec::new")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capture_cgroup: Vec<String>,

    #[serde(default = "Vec::new")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nocapture_cgroup: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub so_mark: Option<u32>,
}

/// Instead of using the IngressNetfilterCaptureDst directly, here we define a common struct for json parsing to get better deserialization error message.
/// See https://github.com/serde-rs/serde/issues/2157
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressNetfilterCaptureDstArgs {
    host: Option<Ipv4Cidr>,
    ipset: Option<String>,
    port: Option<u16>,

    /// Optional end port for port range matching.
    /// When set together with `port`, iptables will use `--dport port:port_end` syntax
    /// to match a contiguous range of destination ports [port, port_end].
    port_end: Option<u16>,
}

impl TryFrom<IngressNetfilterCaptureDstArgs> for IngressNetfilterCaptureDst {
    type Error = anyhow::Error;

    fn try_from(value: IngressNetfilterCaptureDstArgs) -> Result<Self, Self::Error> {
        let port_end = value.port_end;
        if let Some(end) = port_end {
            let Some(port) = value.port else {
                bail!("`port_end` requires `port` to be specified");
            };
            if end < port {
                bail!("`port_end` ({end}) must be >= `port` ({port})");
            }
        }
        Ok(match (value.host, value.ipset, value.port) {
            (None, None, None) => bail!("one of host, ipset, port must be specified"),
            (None, None, Some(port)) => IngressNetfilterCaptureDst::PortOnly { port, port_end },
            (None, Some(ipset), None) => IngressNetfilterCaptureDst::IpSetOnly { ipset },
            (None, Some(ipset), Some(port)) => IngressNetfilterCaptureDst::IpSetAndPort {
                ipset,
                port,
                port_end,
            },
            (Some(host), None, None) => IngressNetfilterCaptureDst::HostOnly { host },
            (Some(host), None, Some(port)) => IngressNetfilterCaptureDst::HostAndPort {
                host,
                port,
                port_end,
            },
            (Some(_), Some(_), _) => bail!("Only one of host or ipset can be specified"),
        })
    }
}

pub enum IngressNetfilterCaptureDst {
    HostOnly {
        host: Ipv4Cidr,
    },
    IpSetOnly {
        ipset: String,
    },
    PortOnly {
        port: u16,
        port_end: Option<u16>,
    },
    HostAndPort {
        host: Ipv4Cidr,
        port: u16,
        port_end: Option<u16>,
    },
    IpSetAndPort {
        ipset: String,
        port: u16,
        port_end: Option<u16>,
    },
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressSocks5Args {
    pub proxy_listen: Endpoint,

    #[serde(default = "Vec::new")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dst_filters: Vec<EndpointFilter>,

    pub auth: Option<Socks5AuthArgs>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5AuthArgs {
    pub username: String,

    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OHttpArgs {
    #[serde(default)]
    pub path_rewrites: Vec<PathRewrite>,

    /// Controls which headers from the downstream request are copied to the
    /// outer OHTTP POST request.
    #[serde(default)]
    pub header_passthrough: Option<IngressHeaderPassthroughConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PathRewrite {
    pub match_regex: String,
    pub substitution: String,
}

/// Configuration for copying selected headers from the downstream plaintext
/// request to the outer OHTTP POST request.
///
/// These headers are visible to intermediaries between Ingress and Egress
/// but are NOT forwarded to the upstream server — they remain encrypted
/// inside the OHTTP body.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct IngressHeaderPassthroughConfig {
    /// Header names to copy from the downstream request to the outer POST.
    #[serde(default)]
    pub request_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointFilter {
    /// Host name to match.
    ///
    /// Only some of the wildcards types are supported. See "domains" field in https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#config-route-v3-virtualhost
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_regex: Option<String>,

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
    use serde_json::json;

    use crate::config::TngConfig;

    use super::{IngressMode, IngressNetfilterCaptureDst, IngressNetfilterCaptureDstArgs};

    fn test_deserialize_netfilter_common(value: serde_json::Value) -> Result<()> {
        // Check deserialize
        let config: TngConfig = serde_json::from_value(value)?;

        let config_json = serde_json::to_string_pretty(&config)?;

        // Check deserialize
        let config2: TngConfig = serde_json::from_str(&config_json)?;

        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(config2)?
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_netfilter() -> Result<()> {
        test_deserialize_netfilter_common(json!(
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_dst": [
                                {
                                    "port": 30001
                                },
                                {
                                    "host": "127.0.0.1"
                                },
                                {
                                    "host": "127.0.0.1",
                                    "port": 30002
                                },
                                {
                                    "host": "10.1.1.0/24",
                                    "port": 30002
                                },
                                {
                                    "host": "127.0.0.1/32",
                                    "port": 30002
                                },
                                {
                                    "host": "127.0.0.1",
                                    "port": 30000,
                                    "port_end": 30031
                                },
                                {
                                    "port": 30000,
                                    "port_end": 30031
                                },
                            ],
                            "listen_port": 50000
                        },
                        "verify": {
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": [
                                "default"
                            ]
                        }
                    }
                ]
            }
        ))?;

        assert!(test_deserialize_netfilter_common(json!(
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_dst": [
                                {
                                    "host": "10.1.1.1/24", // Invalid CIDR
                                    "port": 30002
                                },
                            ],
                            "listen_port": 50000
                        },
                        "verify": {
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": [
                                "default"
                            ]
                        }
                    }
                ]
            }
        ))
        .is_err());

        Ok(())
    }

    fn test_deserialize_netfilter_capture_dst_common(value: serde_json::Value) -> Result<()> {
        IngressNetfilterCaptureDst::try_from(serde_json::from_value::<
            IngressNetfilterCaptureDstArgs,
        >(value)?)?;
        Ok(())
    }

    #[test]
    fn test_deserialize_netfilter_capture_dst() -> Result<()> {
        test_deserialize_netfilter_capture_dst_common(serde_json::json!(
        {
            "host": "10.1.1.0/24",
            "port": 30002
        }))?;

        test_deserialize_netfilter_capture_dst_common(serde_json::json!(
        {
            "ipset": "ipset_name",
            "port": 30002
        }))?;

        test_deserialize_netfilter_capture_dst_common(serde_json::json!(
        {
            "port": 30002
        }))?;

        // PortOnly with port_end
        test_deserialize_netfilter_capture_dst_common(serde_json::json!(
        {
            "port": 30000,
            "port_end": 30031
        }))?;

        // HostAndPort with port_end
        test_deserialize_netfilter_capture_dst_common(serde_json::json!(
        {
            "host": "10.1.1.0/24",
            "port": 30000,
            "port_end": 30031
        }))?;

        // IpSetAndPort with port_end
        test_deserialize_netfilter_capture_dst_common(serde_json::json!(
        {
            "ipset": "ipset_name",
            "port": 30000,
            "port_end": 30031
        }))?;

        assert!(
            test_deserialize_netfilter_capture_dst_common(serde_json::json!(
            {
                "host": "10.1.1.0/24",
                "ipset": "ipset_name",
                "port": 30002
            }))
            .is_err()
        );

        assert!(
            test_deserialize_netfilter_capture_dst_common(serde_json::json!(
            {
                "host": "10.1.1.0/24",
                "ipset": "ipset_name",
            }))
            .is_err()
        );

        assert!(test_deserialize_netfilter_capture_dst_common(serde_json::json!({})).is_err());

        // Invalid: port_end without port
        assert!(
            test_deserialize_netfilter_capture_dst_common(serde_json::json!(
            {
                "host": "10.1.1.0/24",
                "port_end": 30031
            }))
            .is_err()
        );

        // Invalid: port_end < port
        assert!(
            test_deserialize_netfilter_capture_dst_common(serde_json::json!(
            {
                "port": 30031,
                "port_end": 30000
            }))
            .is_err()
        );

        Ok(())
    }

    #[test]
    fn test_deserialize_ingress_netfilter_backward_compat() -> Result<()> {
        // Old single-object format (backward compatibility via OneOrMany)
        test_deserialize_netfilter_common(json!(
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 9991
                            }
                        },
                        "verify": {
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
        ))?;
        Ok(())
    }

    #[test]
    fn test_deserialize_ingress_netfilter_cgroup() -> Result<()> {
        // cgroup-based capture
        test_deserialize_netfilter_common(json!(
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_cgroup": ["/system.slice/vllm.service"],
                            "nocapture_cgroup": ["/system.slice/ssh.service"]
                        },
                        "verify": {
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
        ))?;
        Ok(())
    }

    #[test]
    fn test_deserialize_ingress_netfilter_capture_all() -> Result<()> {
        // Empty capture_dst = capture all TCP traffic
        test_deserialize_netfilter_common(json!(
            {
                "add_ingress": [
                    {
                        "netfilter": {},
                        "verify": {
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
        ))?;
        Ok(())
    }

    #[test]
    fn test_deserialize_endpoint_filter_port_end() -> Result<()> {
        // Valid: port + port_end
        let config: TngConfig = serde_json::from_value(json!({
            "add_ingress": [
                {
                    "http_proxy": {
                        "proxy_listen": { "host": "0.0.0.0", "port": 41000 },
                        "dst_filters": [
                            { "domain": "*", "port": 30000, "port_end": 30063 }
                        ]
                    },
                    "no_ra": true
                }
            ]
        }))?;
        // Serialize and round-trip
        let json = serde_json::to_string_pretty(&config)?;
        let config2: TngConfig = serde_json::from_str(&json)?;
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(config2)?
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_endpoint_filter_port_end_omitted_when_none() -> Result<()> {
        // port_end should NOT appear in serialized output when not set
        let config: TngConfig = serde_json::from_value(json!({
            "add_ingress": [
                {
                    "http_proxy": {
                        "proxy_listen": { "host": "0.0.0.0", "port": 41000 },
                        "dst_filters": [
                            { "domain": "*", "port": 5600 }
                        ]
                    },
                    "no_ra": true
                }
            ]
        }))?;
        let json = serde_json::to_string(&config)?;
        assert!(
            !json.contains("port_end"),
            "port_end should be omitted when None"
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_endpoint_filter_socks5_port_end() -> Result<()> {
        // Verify port_end also works for socks5
        let config: TngConfig = serde_json::from_value(json!({
            "add_ingress": [
                {
                    "socks5": {
                        "proxy_listen": { "host": "0.0.0.0", "port": 1080 },
                        "dst_filters": [
                            { "domain": "*.example.com", "port": 30000, "port_end": 30063 }
                        ]
                    },
                    "no_ra": true
                }
            ]
        }))?;
        let json = serde_json::to_string_pretty(&config)?;
        let config2: TngConfig = serde_json::from_str(&json)?;
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(config2)?
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_mapping_backward_compat() -> Result<()> {
        // Legacy format: single in/out
        let config: TngConfig = serde_json::from_value(json!(
            {
                "add_ingress": [
                    {
                        "mapping": {
                            "in": { "host": "0.0.0.0", "port": 10001 },
                            "out": { "host": "127.0.0.1", "port": 20001 }
                        },
                        "no_ra": true
                    }
                ]
            }
        ))?;
        // Verify round-trip: serialize and deserialize again
        let config_json = serde_json::to_string_pretty(&config)?;
        let config2: TngConfig = serde_json::from_str(&config_json)?;
        assert_eq!(
            serde_json::to_value(&config)?,
            serde_json::to_value(&config2)?
        );
        // Verify rules were parsed correctly
        if let IngressMode::Mapping(m) = &config.add_ingress[0].ingress_mode {
            assert_eq!(m.rules.len(), 1);
            assert_eq!(m.rules[0].r#in.host, Some("0.0.0.0".to_owned()));
            assert_eq!(m.rules[0].r#in.port, 10001);
            assert_eq!(m.rules[0].r#in.port_end, None);
            assert_eq!(m.rules[0].out.host, Some("127.0.0.1".to_owned()));
            assert_eq!(m.rules[0].out.port, 20001);
        } else {
            panic!("expected mapping mode");
        }
        Ok(())
    }

    #[test]
    fn test_deserialize_mapping_multi_rule() -> Result<()> {
        let config: TngConfig = serde_json::from_value(json!(
            {
                "add_ingress": [
                    {
                        "mapping": {
                            "rules": [
                                { "in": { "host": "0.0.0.0", "port": 10001 }, "out": { "host": "127.0.0.1", "port": 20001 } },
                                { "in": { "host": "0.0.0.0", "port": 10002 }, "out": { "host": "127.0.0.1", "port": 20002 } }
                            ]
                        },
                        "no_ra": true
                    }
                ]
            }
        ))?;
        // Verify round-trip
        let config_json = serde_json::to_string_pretty(&config)?;
        let config2: TngConfig = serde_json::from_str(&config_json)?;
        assert_eq!(
            serde_json::to_value(&config)?,
            serde_json::to_value(&config2)?
        );
        // Verify rules
        if let IngressMode::Mapping(m) = &config.add_ingress[0].ingress_mode {
            assert_eq!(m.rules.len(), 2);
            assert_eq!(m.rules[0].r#in.port, 10001);
            assert_eq!(m.rules[1].r#in.port, 10002);
        } else {
            panic!("expected mapping mode");
        }
        Ok(())
    }

    #[test]
    fn test_deserialize_mapping_port_range() -> Result<()> {
        let config: TngConfig = serde_json::from_value(json!(
            {
                "add_ingress": [
                    {
                        "mapping": {
                            "rules": [
                                {
                                    "in": { "host": "0.0.0.0", "port": 10010, "port_end": 10020 },
                                    "out": { "host": "127.0.0.1", "port": 20010, "port_end": 20020 }
                                }
                            ]
                        },
                        "no_ra": true
                    }
                ]
            }
        ))?;
        if let IngressMode::Mapping(m) = &config.add_ingress[0].ingress_mode {
            assert_eq!(m.rules[0].r#in.port_end, Some(10020));
            assert_eq!(m.rules[0].out.port_end, Some(20020));
        } else {
            panic!("expected mapping mode");
        }
        Ok(())
    }

    #[test]
    fn test_mapping_validation_port_end_less_than_port() {
        let result = serde_json::from_value::<TngConfig>(json!(
            {
                "add_ingress": [
                    {
                        "mapping": {
                            "rules": [
                                {
                                    "in": { "host": "0.0.0.0", "port": 10020, "port_end": 10010 },
                                    "out": { "host": "127.0.0.1", "port": 20010 }
                                }
                            ]
                        },
                        "no_ra": true
                    }
                ]
            }
        ));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("port_end"),
            "error should mention port_end: {err}"
        );
    }

    #[test]
    fn test_mapping_validation_range_size_mismatch() {
        let result = serde_json::from_value::<TngConfig>(json!(
            {
                "add_ingress": [
                    {
                        "mapping": {
                            "rules": [
                                {
                                    "in": { "host": "0.0.0.0", "port": 10010, "port_end": 10020 },
                                    "out": { "host": "127.0.0.1", "port": 20010, "port_end": 20015 }
                                }
                            ]
                        },
                        "no_ra": true
                    }
                ]
            }
        ));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("range size"),
            "error should mention range size: {err}"
        );
    }

    #[test]
    fn test_mapping_validation_overlapping_rules() {
        let result = serde_json::from_value::<TngConfig>(json!(
            {
                "add_ingress": [
                    {
                        "mapping": {
                            "rules": [
                                { "in": { "host": "0.0.0.0", "port": 10010, "port_end": 10020 }, "out": { "host": "127.0.0.1", "port": 20010, "port_end": 20020 } },
                                { "in": { "host": "0.0.0.0", "port": 10015, "port_end": 10025 }, "out": { "host": "127.0.0.1", "port": 20015, "port_end": 20025 } }
                            ]
                        },
                        "no_ra": true
                    }
                ]
            }
        ));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("overlapping"),
            "error should mention overlapping: {err}"
        );
    }

    #[test]
    fn test_mapping_validation_out_host_missing() {
        let result = serde_json::from_value::<TngConfig>(json!(
            {
                "add_ingress": [
                    {
                        "mapping": {
                            "rules": [
                                { "in": { "host": "0.0.0.0", "port": 10001 }, "out": { "port": 20001 } }
                            ]
                        },
                        "no_ra": true
                    }
                ]
            }
        ));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("out.host"),
            "error should mention out.host: {err}"
        );
    }
}

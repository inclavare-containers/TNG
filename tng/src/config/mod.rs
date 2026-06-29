use control_interface::ControlInterfaceArgs;
use egress::AddEgressArgs;
use ingress::AddIngressArgs;
use observability::{metric::MetricArgs, trace::TraceArgs};
use serde::{Deserialize, Serialize};

pub mod control_interface;
pub mod egress;
pub mod egress_hook;
pub mod ingress;
pub mod mapping_rule;
pub mod observability;
pub mod ra;

// Shared types used by both tng and tng-hook
pub use tng_hook_types::{
    EgressHookMappingEntry, EgressHookMappingTable, IngressHookCaptureRule,
    IngressHookMappingTable, IngressHookProxy,
};

// Internal TNG types (not serialized to .so)
pub use egress_hook::TngEgressHookMappingEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TngConfig {
    #[serde(default = "Option::default")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_interface: Option<ControlInterfaceArgs>,

    #[serde(default = "Option::default")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric: Option<MetricArgs>,

    #[serde(default = "Option::default")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<TraceArgs>,

    #[serde(default)]
    pub add_ingress: Vec<AddIngressArgs>,

    #[serde(default)]
    pub add_egress: Vec<AddEgressArgs>,

    /// The [address]:port where the envoy admin interface to bind on.
    #[serde(default = "Option::default")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_bind: Option<Endpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub port: u16,
}

/// Per-entry QUIC configuration for UDP tunneling, shared by ingress and egress.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpQuicArgs {
    /// Maximum QUIC datagram payload size. If not specified, quinn default is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_datagram_size: Option<usize>,
}

#[cfg(test)]
pub mod tests {
    use anyhow::Result;
    use egress::{EgressHeaderPassthroughConfig, EgressMode};
    use ingress::{IngressHeaderPassthroughConfig, IngressMode, PathRewrite};
    use ra::{AttestArgs, RaArgsUnchecked, VerifyArgs};

    use crate::config::mapping_rule::{MappingRule, RuleEndpoint};

    use crate::config::{
        egress::EgressMappingArgs,
        ra::{
            AttesterArgs, CocoAttesterArgs, CocoConverterArgs, CocoVerifierArgs, ConverterArgs,
            VerifierArgs,
        },
    };

    use super::*;

    #[test]
    fn test_serialize_deserialize() -> Result<()> {
        let config = TngConfig {
            admin_bind: None,
            control_interface: None,
            metric: None,
            trace: None,
            add_ingress: vec![AddIngressArgs {
                ingress_mode: IngressMode::Mapping(ingress::IngressMappingArgs {
                    rules: vec![MappingRule {
                        r#in: RuleEndpoint {
                            host: None,
                            port: 10001,
                            port_end: None,
                        },
                        out: RuleEndpoint {
                            host: Some("127.0.0.1".to_owned()),
                            port: 20001,
                            port_end: None,
                        },
                    }],
                }),
                common: ingress::CommonArgs{
                    web_page_inject: false,
                    ohttp: Some(ingress::OHttpArgs {
                        path_rewrites: vec![PathRewrite {
                            match_regex: "^/foo/bar/([^/]+)([/]?.*)$".to_owned(),
                            substitution: "/foo/bar/\\1".to_owned(),
                        }],
                        header_passthrough: Some(IngressHeaderPassthroughConfig {
                            request_headers: vec!["x-trace-id".to_owned()],
                        }),
                    }),
                    rats_tls: None,
                    quic: None,
                    ra_args: RaArgsUnchecked {
                        no_ra: false,
                        attest: None,
                        verify: Some(VerifyArgs::BackgroundCheck {
                            converter: ConverterArgs::Coco(CocoConverterArgs::Restful {
                                as_addr: "http://127.0.0.1:8080/".to_owned(),
                                policy_ids: vec!["default".to_owned()],
                                as_headers: Default::default(),
                            }),
                            verifier: VerifierArgs::Coco(CocoVerifierArgs::Restful {
                                as_addr: Some("http://127.0.0.1:8080/".to_owned()),
                                policy_ids: vec!["default".to_owned()],
                                as_headers: Default::default(),
                                trusted_certs_paths: Some(vec!["/tmp/as.pem".to_owned()]),
                                verify_signer_transparency: false,
                                skip_as_token_cert_verify: false,
                            }),
                        })
                    },
                }
            }],
            add_egress: vec![AddEgressArgs {
                egress_mode: EgressMode::Mapping (EgressMappingArgs{
                    rules: vec![MappingRule {
                        r#in: RuleEndpoint {
                            host: Some("127.0.0.1".to_owned()),
                            port: 20001,
                            port_end: None,
                        },
                        out: RuleEndpoint {
                            host: Some("127.0.0.1".to_owned()),
                            port: 30001,
                            port_end: None,
                        },
                    }],
                }),
                common:egress::CommonArgs{
                    direct_forward: None,
                    ohttp: Some(egress::OHttpArgs {
                        allow_non_tng_traffic_regexes: None,
                        cors: None,
                        key: Default::default(),
                        header_passthrough: Some(EgressHeaderPassthroughConfig {
                            response_headers: vec!["x-custom-header".to_owned()],
                        }),
                    }),
                    rats_tls: None,
                    quic: None,
                    ra_args: RaArgsUnchecked {
                        no_ra: false,
                        attest: Some(AttestArgs::BackgroundCheck {
                            attester: AttesterArgs::Coco(CocoAttesterArgs::Uds {
                                aa_addr: "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock".to_owned(),
                            }),
                            refresh_interval: None,
                        }),
                        verify: None,
                    },
                }
            }],
        };

        let config_json = serde_json::to_string_pretty(&config)?;

        let config2: TngConfig = serde_json::from_str(&config_json)?;

        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(config2)?
        );

        Ok(())
    }

    #[test]
    fn test_header_passthrough_deserialization() -> anyhow::Result<()> {
        use super::mapping_rule::{MappingRule, RuleEndpoint};
        use egress::EgressHeaderPassthroughConfig;
        use ingress::IngressHeaderPassthroughConfig;

        // Ingress config with header_passthrough
        let ingress_config = TngConfig {
            admin_bind: None,
            control_interface: None,
            metric: None,
            trace: None,
            add_ingress: vec![AddIngressArgs {
                ingress_mode: ingress::IngressMode::Mapping(ingress::IngressMappingArgs {
                    rules: vec![MappingRule {
                        r#in: RuleEndpoint {
                            host: None,
                            port: 10001,
                            port_end: None,
                        },
                        out: RuleEndpoint {
                            host: Some("127.0.0.1".to_owned()),
                            port: 20001,
                            port_end: None,
                        },
                    }],
                }),
                common: ingress::CommonArgs {
                    web_page_inject: false,
                    ohttp: Some(ingress::OHttpArgs {
                        path_rewrites: vec![],
                        header_passthrough: Some(IngressHeaderPassthroughConfig {
                            request_headers: vec![
                                "x-trace-id".to_owned(),
                                "x-tenant-id".to_owned(),
                            ],
                        }),
                    }),
                    rats_tls: None,
                    quic: None,
                    ra_args: RaArgsUnchecked {
                        no_ra: false,
                        attest: None,
                        verify: None,
                    },
                },
            }],
            add_egress: vec![],
        };
        let json = serde_json::to_string_pretty(&ingress_config)?;
        let parsed: TngConfig = serde_json::from_str(&json)?;
        let hp = parsed.add_ingress[0]
            .common
            .ohttp
            .as_ref()
            .unwrap()
            .header_passthrough
            .as_ref()
            .unwrap();
        assert_eq!(hp.request_headers, vec!["x-trace-id", "x-tenant-id"]);

        // Egress config with header_passthrough (using netfilter mode)
        let egress_config = TngConfig {
            admin_bind: None,
            control_interface: None,
            metric: None,
            trace: None,
            add_ingress: vec![],
            add_egress: vec![AddEgressArgs {
                egress_mode: egress::EgressMode::Netfilter(egress::EgressNetfilterArgs {
                    capture_dst: vec![],
                    capture_local_traffic: false,
                    capture_cgroup: vec![],
                    nocapture_cgroup: vec![],
                    listen_port: None,
                    so_mark: None,
                }),
                common: egress::CommonArgs {
                    direct_forward: None,
                    ohttp: Some(egress::OHttpArgs {
                        allow_non_tng_traffic_regexes: None,
                        cors: None,
                        key: Default::default(),
                        header_passthrough: Some(EgressHeaderPassthroughConfig {
                            response_headers: vec!["x-custom".to_owned()],
                        }),
                    }),
                    rats_tls: None,
                    quic: None,
                    ra_args: RaArgsUnchecked {
                        no_ra: false,
                        attest: None,
                        verify: None,
                    },
                },
            }],
        };
        let json = serde_json::to_string_pretty(&egress_config)?;
        let parsed: TngConfig = serde_json::from_str(&json)?;
        let hp = parsed.add_egress[0]
            .common
            .ohttp
            .as_ref()
            .unwrap()
            .header_passthrough
            .as_ref()
            .unwrap();
        assert_eq!(hp.response_headers, vec!["x-custom"]);

        // Empty header_passthrough
        let empty_config = TngConfig {
            admin_bind: None,
            control_interface: None,
            metric: None,
            trace: None,
            add_ingress: vec![],
            add_egress: vec![AddEgressArgs {
                egress_mode: egress::EgressMode::Netfilter(egress::EgressNetfilterArgs {
                    capture_dst: vec![],
                    capture_local_traffic: false,
                    capture_cgroup: vec![],
                    nocapture_cgroup: vec![],
                    listen_port: None,
                    so_mark: None,
                }),
                common: egress::CommonArgs {
                    direct_forward: None,
                    ohttp: Some(egress::OHttpArgs {
                        allow_non_tng_traffic_regexes: None,
                        cors: None,
                        key: Default::default(),
                        header_passthrough: Some(EgressHeaderPassthroughConfig {
                            response_headers: vec![],
                        }),
                    }),
                    rats_tls: None,
                    quic: None,
                    ra_args: RaArgsUnchecked {
                        no_ra: false,
                        attest: None,
                        verify: None,
                    },
                },
            }],
        };
        let json = serde_json::to_string_pretty(&empty_config)?;
        let parsed: TngConfig = serde_json::from_str(&json)?;
        let hp = parsed.add_egress[0]
            .common
            .ohttp
            .as_ref()
            .unwrap()
            .header_passthrough
            .as_ref()
            .unwrap();
        assert!(hp.response_headers.is_empty());

        Ok(())
    }

    #[test]
    fn test_mapping_udp_config_serialize() -> Result<()> {
        use egress::{
            CommonArgs as EgressCommonArgs, EgressMappingUdpArgs, EgressMode as EgressModeEnum,
        };
        use ingress::{CommonArgs, IngressMappingUdpArgs, IngressMode as IngressModeEnum};

        let config = TngConfig {
            admin_bind: None,
            control_interface: None,
            metric: None,
            trace: None,
            add_ingress: vec![AddIngressArgs {
                ingress_mode: IngressModeEnum::MappingUdp(IngressMappingUdpArgs {
                    r#in: Endpoint {
                        host: Some("0.0.0.0".to_owned()),
                        port: 10001,
                    },
                    out: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 8443,
                    },
                    idle_timeout_secs: Some(30),
                }),
                common: CommonArgs {
                    web_page_inject: false,
                    ohttp: None,
                    rats_tls: None,
                    quic: Some(UdpQuicArgs {
                        max_datagram_size: Some(1200),
                    }),
                    ra_args: RaArgsUnchecked {
                        no_ra: true,
                        attest: None,
                        verify: None,
                    },
                },
            }],
            add_egress: vec![AddEgressArgs {
                egress_mode: EgressModeEnum::MappingUdp(EgressMappingUdpArgs {
                    r#in: Endpoint {
                        host: Some("0.0.0.0".to_owned()),
                        port: 8443,
                    },
                    out: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 20001,
                    },
                    idle_timeout_secs: Some(30),
                }),
                common: EgressCommonArgs {
                    direct_forward: None,
                    ohttp: None,
                    rats_tls: None,
                    quic: Some(UdpQuicArgs {
                        max_datagram_size: Some(1200),
                    }),
                    ra_args: RaArgsUnchecked {
                        no_ra: true,
                        attest: None,
                        verify: None,
                    },
                },
            }],
        };

        let config_json = serde_json::to_string_pretty(&config)?;
        let config2: TngConfig = serde_json::from_str(&config_json)?;

        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(config2)?
        );

        Ok(())
    }

    #[test]
    fn test_mapping_udp_config_defaults() -> Result<()> {
        // Verify default values
        let udp_quic = UdpQuicArgs::default();
        assert!(udp_quic.max_datagram_size.is_none());

        // Verify UdpQuicArgs serializes to empty object when all fields are None
        let json = serde_json::to_string(&udp_quic)?;
        assert_eq!(json, "{}");

        Ok(())
    }

    #[test]
    fn test_mapping_udp_json_format() -> Result<()> {
        use egress::EgressMode as EgressModeEnum;
        use ingress::IngressMode as IngressModeEnum;

        // Exact JSON string from the design spec
        let config_json = r#"{
  "add_ingress": [
    {
      "mapping_udp": {
        "in": {
          "host": "0.0.0.0",
          "port": 10001
        },
        "out": {
          "host": "127.0.0.1",
          "port": 8443
        },
        "idle_timeout_secs": 30
      },
      "quic": {
        "max_datagram_size": 1200
      },
      "verify": {
        "model": "background_check",
        "as_provider": "coco",
        "as_type": "restful",
        "as_addr": "http://127.0.0.1:8080/",
        "policy_ids": ["default"]
      }
    }
  ],
  "add_egress": [
    {
      "mapping_udp": {
        "in": {
          "host": "0.0.0.0",
          "port": 8443
        },
        "out": {
          "host": "127.0.0.1",
          "port": 20001
        }
      },
      "quic": {
        "max_datagram_size": 1200
      },
      "attest": {
        "model": "background_check",
        "aa_provider": "coco",
        "aa_type": "uds",
        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
      }
    }
  ]
}"#;

        let config: TngConfig = serde_json::from_str(config_json)?;

        // Verify ingress mapping_udp config
        assert_eq!(config.add_ingress.len(), 1);
        match &config.add_ingress[0].ingress_mode {
            IngressModeEnum::MappingUdp(mapping) => {
                assert_eq!(mapping.r#in.host.as_deref(), Some("0.0.0.0"));
                assert_eq!(mapping.r#in.port, 10001);
                assert_eq!(mapping.out.host.as_deref(), Some("127.0.0.1"));
                assert_eq!(mapping.out.port, 8443);
                assert_eq!(mapping.idle_timeout_secs, Some(30));
            }
            _ => panic!("Expected MappingUdp ingress mode"),
        }

        // Verify egress mapping_udp config
        assert_eq!(config.add_egress.len(), 1);
        match &config.add_egress[0].egress_mode {
            EgressModeEnum::MappingUdp(mapping) => {
                assert_eq!(mapping.r#in.host.as_deref(), Some("0.0.0.0"));
                assert_eq!(mapping.r#in.port, 8443);
                assert_eq!(mapping.out.host.as_deref(), Some("127.0.0.1"));
                assert_eq!(mapping.out.port, 20001);
            }
            _ => panic!("Expected MappingUdp egress mode"),
        }

        // Verify quic config on ingress
        match &config.add_ingress[0].common.quic {
            Some(quic) => assert_eq!(quic.max_datagram_size, Some(1200)),
            None => panic!("Expected quic config on ingress"),
        }
        // Verify quic config on egress
        match &config.add_egress[0].common.quic {
            Some(quic) => assert_eq!(quic.max_datagram_size, Some(1200)),
            None => panic!("Expected quic config on egress"),
        }

        // Verify round-trip serialization
        let serialized = serde_json::to_string_pretty(&config)?;
        let config2: TngConfig = serde_json::from_str(&serialized)?;
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(config2)?
        );

        Ok(())
    }

    #[test]
    fn test_mapping_udp_idle_timeout_default() -> Result<()> {
        use ingress::IngressMode as IngressModeEnum;

        // JSON without idle_timeout_secs specified
        let config_json = r#"{
  "add_ingress": [
    {
      "mapping_udp": {
        "in": {
          "port": 10001
        },
        "out": {
          "host": "127.0.0.1",
          "port": 8443
        }
      }
    }
  ]
}"#;

        let config: TngConfig = serde_json::from_str(config_json)?;

        // Verify idle_timeout_secs defaults to None when not specified
        assert_eq!(config.add_ingress.len(), 1);
        match &config.add_ingress[0].ingress_mode {
            IngressModeEnum::MappingUdp(mapping) => {
                assert!(
                    mapping.idle_timeout_secs.is_none(),
                    "idle_timeout_secs should be None when not specified in JSON"
                );
            }
            _ => panic!("Expected MappingUdp ingress mode"),
        }

        Ok(())
    }

    #[test]
    fn test_mapping_udp_no_quic_config() -> Result<()> {
        use egress::EgressMode as EgressModeEnum;
        use ingress::IngressMode as IngressModeEnum;

        // JSON with no quic config at all
        let config_json = r#"{
  "add_ingress": [
    {
      "mapping_udp": {
        "in": {
          "port": 10001
        },
        "out": {
          "host": "127.0.0.1",
          "port": 8443
        }
      }
    }
  ],
  "add_egress": [
    {
      "mapping_udp": {
        "in": {
          "port": 8443
        },
        "out": {
          "host": "127.0.0.1",
          "port": 20001
        }
      }
    }
  ]
}"#;

        let config: TngConfig = serde_json::from_str(config_json)?;

        // Verify no quic config on entries
        assert!(config.add_ingress[0].common.quic.is_none());
        assert!(config.add_egress[0].common.quic.is_none());

        // Verify ingress works with no quic config
        assert_eq!(config.add_ingress.len(), 1);
        match &config.add_ingress[0].ingress_mode {
            IngressModeEnum::MappingUdp(mapping) => {
                assert_eq!(mapping.r#in.port, 10001);
                assert_eq!(mapping.out.port, 8443);
            }
            _ => panic!("Expected MappingUdp ingress mode"),
        }

        // Verify egress works with no quic config
        assert_eq!(config.add_egress.len(), 1);
        match &config.add_egress[0].egress_mode {
            EgressModeEnum::MappingUdp(mapping) => {
                assert_eq!(mapping.r#in.port, 8443);
                assert_eq!(mapping.out.port, 20001);
            }
            _ => panic!("Expected MappingUdp egress mode"),
        }

        Ok(())
    }
}

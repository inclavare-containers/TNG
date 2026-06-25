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
}

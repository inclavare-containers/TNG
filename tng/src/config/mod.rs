use control_interface::ControlInterfaceArgs;
use egress::AddEgressArgs;
use ingress::AddIngressArgs;
use observability::{metric::MetricArgs, trace::TraceArgs};
use serde::{Deserialize, Serialize};

pub mod control_interface;
pub mod egress;
pub mod ingress;
pub mod observability;
pub mod ra;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub port: u16,
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use egress::EgressMode;
    use ingress::{IngressMode, PathRewrite};
    use ra::{AttestArgs, RaArgsUnchecked, VerifyArgs};

    use crate::config::{
        egress::EgressMappingArgs,
        ra::{AttestationAgentArgs, AttestationServiceArgs, AttestationServiceTokenVerifyArgs},
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
                    r#in: Endpoint {
                        host: None,
                        port: 10001,
                    },
                    out: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 20001,
                    },
                }),
                common: ingress::CommonArgs{
                    web_page_inject: false,
                    ohttp: Some(ingress::OHttpArgs {
                        path_rewrites: vec![PathRewrite {
                            match_regex: "^/foo/bar/([^/]+)([/]?.*)$".to_owned(),
                            substitution: "/foo/bar/\\1".to_owned(),
                        }],
                    }),
                    ra_args: RaArgsUnchecked {
                        no_ra: false,
                        attest: None,
                        verify: Some(VerifyArgs::BackgroundCheck { as_args:   AttestationServiceArgs{
                            as_addr: "http://127.0.0.1:8080/".to_owned(),
                            as_is_grpc: false,
                            token_verify: AttestationServiceTokenVerifyArgs {
                                policy_ids: vec!["default".to_owned()],
                                trusted_certs_paths: Some(vec!["/tmp/as.pem".to_owned()]),
                            },
                        }})},
                }
            }],
            add_egress: vec![AddEgressArgs {
                egress_mode: EgressMode::Mapping (EgressMappingArgs{
                    r#in: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 20001,
                    },
                    out: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 30001,
                    },
                }),
                common:egress::CommonArgs{
                    direct_forward: None,
                    ohttp: Some(egress::OHttpArgs {
                        allow_non_tng_traffic_regexes: None,
                        cors: None,
                    }),
                    ra_args: RaArgsUnchecked {
                        no_ra: false,
                        attest: Some(AttestArgs::BackgroundCheck { aa_args: AttestationAgentArgs {
                            aa_addr: "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock".to_owned(),
                            refresh_interval: None,
                        }}),
                        verify: None,
                    },
                }
            }],
        };

        let config_json = serde_json::to_string_pretty(&config)?;

        let config2 = serde_json::from_str(&config_json)?;

        assert_eq!(config, config2);

        Ok(())
    }
}

use egress::AddEgressArgs;
use ingress::AddIngressArgs;
use serde::{Deserialize, Serialize};

pub mod attest;
pub mod egress;
pub mod ingress;
pub mod verify;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TngConfig {
    #[serde(default)]
    pub add_ingress: Vec<AddIngressArgs>,
    #[serde(default)]
    pub add_egress: Vec<AddEgressArgs>,
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
    use attest::AttestArgs;
    use egress::EgressMode;
    use ingress::{EncapInHttp, IngressMode, PathRewrite};
    use verify::VerifyArgs;

    use super::*;

    #[test]
    fn test_serialize_deserialize() -> Result<()> {
        let config = TngConfig {
            add_ingress: vec![AddIngressArgs {
                ingress_mode: IngressMode::Mapping {
                    r#in: Endpoint {
                        host: None,
                        port: 10001,
                    },
                    out: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 20001,
                    },
                },
                encap_in_http: Some(EncapInHttp {
                    path_rewrites: vec![PathRewrite {
                        match_regex: "^/api/predict/([^/]+)([/]?.*)$".to_owned(),
                        substitution: "/api/predict/\\1".to_owned(),
                    }],
                }),
                no_ra: false,
                attest: None,
                verify: Some(VerifyArgs {
                    as_addr: "http://127.0.0.1:8080/".to_owned(),
                    as_is_grpc: false,
                    policy_ids: vec!["default".to_owned()],
                }),
            }],
            add_egress: vec![AddEgressArgs {
                egress_mode: EgressMode::Mapping {
                    r#in: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 20001,
                    },
                    out: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 30001,
                    },
                },
                decap_from_http: true,
                no_ra: false,
                attest: Some(AttestArgs {
                    aa_addr: "unix:///tmp/attestation.sock".to_owned(),
                }),
                verify: None,
            }],
        };

        let config_json = serde_json::to_string_pretty(&config)?;

        println!("{config_json}");

        let config2 = serde_json::from_str(&config_json)?;

        assert_eq!(config, config2);

        Ok(())
    }
}

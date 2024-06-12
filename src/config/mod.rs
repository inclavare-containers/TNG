use egress::AddEgressArgs;
use ingress::AddIngressArgs;
use serde::{Deserialize, Serialize};

pub mod attest;
pub mod egress;
pub mod ingress;
pub mod verify;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    pub add_ingress: Vec<AddIngressArgs>,
    pub add_egress: Vec<AddEgressArgs>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Endpoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub port: u16,
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use attest::AttestArgs;
    use egress::EgressType;
    use ingress::IngressType;
    use verify::VerifyArgs;

    use super::*;

    #[test]
    fn test_serialize_deserialize() -> Result<()> {
        let config = Config {
            add_ingress: vec![AddIngressArgs {
                ingress_type: IngressType::Mapping {
                    r#in: Endpoint {
                        // host: Some("127.0.0.1".to_owned()),
                        host: None,
                        port: 10001,
                    },
                    out: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 20001,
                    },
                },
                attest: Some(AttestArgs {
                    as_addr: "http://127.0.0.1:50004/".to_owned(),
                    policy_ids: vec!["default".to_owned()],
                }),
                verify: None,
            }],
            add_egress: vec![AddEgressArgs {
                egress_type: EgressType::Mapping {
                    r#in: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 20001,
                    },
                    out: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 30001,
                    },
                },
                attest: None,
                verify: Some(VerifyArgs {
                    aa_addr: "unix:///tmp/attestation.sock".to_owned(),
                }),
            }],
        };

        let config_json = serde_json::to_string_pretty(&config)?;

        println!("{config_json}");

        let config2 = serde_json::from_str(&config_json)?;

        assert_eq!(config, config2);

        Ok(())
    }
}

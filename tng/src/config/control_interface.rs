use serde::{Deserialize, Serialize};

use super::Endpoint;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct ControlInterfaceArgs {
    pub restful: Option<RestfulArgs>,

    pub ttrpc: Option<TtrpcArgs>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RestfulArgs {
    #[serde(flatten)]
    pub address: Endpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TtrpcArgs {
    pub path: String,
}

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use serde_json::json;

    use crate::config::{
        ingress::{self, AddIngressArgs, IngressMode},
        ra::RaArgsUnchecked,
        Endpoint, TngConfig,
    };

    use super::*;

    #[test]
    fn test_deserialize_restful() -> Result<()> {
        let json_value = json!(
            {
                "control_interface": {
                    "restful": {
                        "host": "0.0.0.0",
                        "port": 50000
                    }
                },
                "add_ingress": [
                    {
                        "mapping": {
                            "in": {
                                "port": 10001
                            },
                            "out": {
                                "host": "127.0.0.1",
                                "port": 30001
                            }
                        },
                        "no_ra": true
                    }
                ]
            }
        );

        let expected = TngConfig {
            admin_bind: None,
            metric: None,
            trace: None,
            control_interface: Some(ControlInterfaceArgs {
                restful: Some(RestfulArgs {
                    address: Endpoint {
                        host: Some("0.0.0.0".to_owned()),
                        port: 50000,
                    },
                }),
                ..Default::default()
            }),
            add_ingress: vec![AddIngressArgs {
                ingress_mode: IngressMode::Mapping(ingress::IngressMappingArgs {
                    r#in: Endpoint {
                        host: None,
                        port: 10001,
                    },
                    out: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 30001,
                    },
                }),
                common: ingress::CommonArgs {
                    web_page_inject: false,
                    ohttp: None,
                    ra_args: RaArgsUnchecked {
                        no_ra: true,
                        attest: None,
                        verify: None,
                    },
                },
            }],
            add_egress: vec![],
        };

        let deserialized: TngConfig = serde_json::from_value(json_value)?;

        assert_eq!(deserialized, expected);
        Ok(())
    }

    #[test]
    fn test_deserialize_ttrpc() -> Result<()> {
        let json_value = json!(
            {
                "control_interface": {
                    "ttrpc": {
                        "path": "/var/run/tng.sock"
                    }
                },
                "add_ingress": [
                    {
                        "mapping": {
                            "in": {
                                "port": 10001
                            },
                            "out": {
                                "host": "127.0.0.1",
                                "port": 30001
                            }
                        },
                        "no_ra": true
                    }
                ]
            }
        );

        let expected = TngConfig {
            admin_bind: None,
            metric: None,
            trace: None,
            control_interface: Some(ControlInterfaceArgs {
                ttrpc: Some(TtrpcArgs {
                    path: "/var/run/tng.sock".to_string(),
                }),
                ..Default::default()
            }),
            add_ingress: vec![AddIngressArgs {
                ingress_mode: IngressMode::Mapping(ingress::IngressMappingArgs {
                    r#in: Endpoint {
                        host: None,
                        port: 10001,
                    },
                    out: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 30001,
                    },
                }),
                common: ingress::CommonArgs {
                    web_page_inject: false,
                    ohttp: None,
                    ra_args: RaArgsUnchecked {
                        no_ra: true,
                        attest: None,
                        verify: None,
                    },
                },
            }],
            add_egress: vec![],
        };

        let deserialized: TngConfig = serde_json::from_value(json_value)?;

        assert_eq!(deserialized, expected);
        Ok(())
    }
}

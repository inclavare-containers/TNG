use serde::{Deserialize, Serialize};

use crate::observability::exporter::falcon::FalconConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MetricArgs {
    #[serde(default)]
    pub exporters: Vec<ExportorType>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum ExportorType {
    #[serde(rename = "falcon")]
    Falcon(FalconConfig),
}

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use serde_json::json;

    use crate::config::{
        ingress::{AddIngressArgs, CommonArgs, IngressMappingArgs, IngressMode},
        ra::RaArgs,
        Endpoint, TngConfig,
    };

    use super::*;

    #[test]
    fn test_deserialize() -> Result<()> {
        let json_value = json!(
            {
                "metric": {
                    "exporters": [{
                        "type": "falcon",
                        "server_url": "http://127.0.0.1:1988",
                        "endpoint": "master-node",
                        "tags": {
                            "namespace": "ns1",
                            "app": "tng"
                        },
                        "step": 60
                    }]
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
            metric: Some(MetricArgs {
                exporters: vec![ExportorType::Falcon(FalconConfig {
                    server_url: "http://127.0.0.1:1988".to_owned(),
                    endpoint: "master-node".to_owned(),
                    tags: [
                        ("namespace".to_owned(), "ns1".to_owned()),
                        ("app".to_owned(), "tng".to_owned()),
                    ]
                    .into(),
                    step: 60,
                })],
            }),
            add_ingress: vec![AddIngressArgs {
                ingress_mode: IngressMode::Mapping(IngressMappingArgs {
                    r#in: Endpoint {
                        host: None,
                        port: 10001,
                    },
                    out: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 30001,
                    },
                }),
                common: CommonArgs {
                    encap_in_http: None,
                    web_page_inject: false,
                    ra_args: RaArgs {
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

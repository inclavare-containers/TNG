use std::sync::Arc;

use anyhow::Result;
use derivative::Derivative;
use serde::{Deserialize, Serialize};

use crate::observability::exporter::{
    falcon::FalconConfig, stdout::StdoutExporter, MetricExporter,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MetricArgs {
    #[serde(default)]
    pub exporters: Vec<ExportorType>,
}

#[derive(Clone, Serialize, Deserialize, Derivative)]
#[derivative(Debug, PartialEq)]
#[serde(tag = "type")]
pub enum ExportorType {
    #[serde(rename = "stdout")]
    Stdout {
        #[serde(default = "stdout_config_default_step")]
        step: u64,
    },

    #[serde(rename = "falcon")]
    Falcon(FalconConfig),

    #[cfg(test)]
    #[serde(skip)]
    #[serde(rename = "mock")]
    Mock {
        step: u64,

        #[derivative(Debug = "ignore")]
        #[derivative(PartialEq = "ignore")]
        exporter: std::sync::Arc<dyn MetricExporter + Send + Sync + 'static>,
    },
}

fn stdout_config_default_step() -> u64 {
    60
}

impl ExportorType {
    pub fn instantiate(
        &self,
    ) -> Result<(
        u64, /* step */
        Arc<dyn MetricExporter + Send + Sync + 'static>,
    )> {
        match self {
            ExportorType::Stdout { step } => Ok((*step, Arc::new(StdoutExporter {}))),
            ExportorType::Falcon(falcon_config) => {
                let falcon_exporter = crate::observability::exporter::falcon::FalconExporter::new(
                    falcon_config.clone(),
                )?;
                Ok((falcon_config.step, Arc::new(falcon_exporter)))
            }
            #[cfg(test)]
            ExportorType::Mock { step, exporter } => Ok((*step, exporter.clone())),
        }
    }
}

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use serde_json::json;

    use crate::config::{
        ingress::{AddIngressArgs, IngressMode},
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
                ingress_mode: IngressMode::Mapping {
                    r#in: Endpoint {
                        host: None,
                        port: 10001,
                    },
                    out: Endpoint {
                        host: Some("127.0.0.1".to_owned()),
                        port: 30001,
                    },
                },
                web_page_inject: false,
                encap_in_http: None,
                no_ra: true,
                attest: None,
                verify: None,
            }],
            add_egress: vec![],
        };

        let deserialized: TngConfig = serde_json::from_value(json_value)?;

        assert_eq!(deserialized, expected);

        Ok(())
    }
}

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub mod log;
pub mod metric;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OltpCommonExporterConfig {
    protocol: OltpExporterProtocol,
    headers: Option<HashMap<String, String>>,
    endpoint: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum OltpExporterProtocol {
    #[serde(rename = "http/protobuf")]
    HttpProtobuf,
    #[serde(rename = "http/json")]
    HttpJson,
    #[serde(rename = "grpc")]
    Grpc,
}

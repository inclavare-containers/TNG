use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub mod metric;
pub mod trace;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OltpCommonExporterConfig {
    pub protocol: OltpExporterProtocol,
    pub headers: Option<HashMap<String, String>>,
    pub endpoint: String,
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

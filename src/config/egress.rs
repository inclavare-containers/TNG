use serde::{Deserialize, Serialize};

use super::{ra::RaArgs, Endpoint};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AddEgressArgs {
    #[serde(flatten)]
    pub egress_mode: EgressMode,

    #[serde(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommonArgs {
    pub decap_from_http: Option<DecapFromHttp>,

    #[serde(flatten)]
    pub ra_args: RaArgs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum EgressMode {
    #[serde(rename = "mapping")]
    Mapping { r#in: Endpoint, out: Endpoint },

    #[serde(rename = "netfilter")]
    Netfilter {
        capture_dst: Endpoint,

        #[serde(default = "bool::default")]
        capture_local_traffic: bool,

        #[serde(skip_serializing_if = "Option::is_none")]
        listen_port: Option<u16>,

        #[serde(skip_serializing_if = "Option::is_none")]
        so_mark: Option<u32>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DecapFromHttp {
    #[serde(default = "Option::default")]
    pub allow_non_tng_traffic_regexes: Option<Vec<String>>,
}

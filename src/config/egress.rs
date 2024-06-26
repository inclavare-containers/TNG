use serde::{Deserialize, Serialize};

use super::{attest::AttestArgs, verify::VerifyArgs, Endpoint};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AddEgressArgs {
    #[serde(flatten)]
    pub egress_mode: EgressMode,

    #[serde(default = "bool::default")]
    pub decap_from_http: bool,

    #[serde(default = "bool::default")]
    pub no_ra: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub attest: Option<AttestArgs>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyArgs>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum EgressMode {
    /// --add-ingress='mapping,in=20001,out=127.0.0.1:30001'
    #[serde(rename = "mapping")]
    Mapping { r#in: Endpoint, out: Endpoint },
    #[serde(rename = "netfilter")]
    Netfilter {
        capture_dst: Endpoint,

        #[serde(skip_serializing_if = "Option::is_none")]
        listen_port: Option<u16>,

        #[serde(skip_serializing_if = "Option::is_none")]
        so_mark: Option<u32>,
    },
}

use serde::{Deserialize, Serialize};

use super::{attest::AttestArgs, verify::VerifyArgs, Endpoint};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AddIngressArgs {
    #[serde(flatten)]
    pub ingress_mode: IngressMode,

    #[serde(default = "Option::default")]
    pub encap_in_http: Option<EncapInHttp>,

    #[serde(default = "bool::default")]
    pub no_ra: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub attest: Option<AttestArgs>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyArgs>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum IngressMode {
    /// --add-ingress='mapping,in=10001,out=127.0.0.1:20001'
    #[serde(rename = "mapping")]
    Mapping { r#in: Endpoint, out: Endpoint },
    /// --add-ingress='http-proxy,dst=127.0.0.1:9991'
    #[serde(rename = "http_proxy")]
    HttpProxy { dst: Endpoint },
    /// --add-ingress='netfilter,dst=127.0.0.1:9991'
    #[serde(rename = "netfilter")]
    Netfilter { dst: Endpoint },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EncapInHttp {
    #[serde(default)]
    pub path_rewrites: Vec<PathRewrite>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PathRewrite {
    pub match_regex: String,
    pub substitution: String,
}

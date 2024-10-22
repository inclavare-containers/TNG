use serde::{Deserialize, Serialize};
use serde_with::{formats::PreferMany, serde_as, OneOrMany};

use super::{attest::AttestArgs, verify::VerifyArgs, Endpoint};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AddIngressArgs {
    #[serde(flatten)]
    pub ingress_mode: IngressMode,

    #[serde(default = "Option::default")]
    pub encap_in_http: Option<EncapInHttp>,

    #[serde(default = "bool::default")]
    pub web_page_inject: bool,

    #[serde(default = "bool::default")]
    pub no_ra: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub attest: Option<AttestArgs>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyArgs>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum IngressMode {
    #[serde(rename = "mapping")]
    Mapping { r#in: Endpoint, out: Endpoint },

    #[serde(rename = "http_proxy")]
    HttpProxy {
        proxy_listen: Endpoint,
        #[serde_as(as = "OneOrMany<_, PreferMany>")]
        #[serde(default = "Vec::new")]
        // In TNG version <= 1.0.1, this field is named as `dst_filter`
        #[serde(alias = "dst_filter")]
        dst_filters: Vec<EndpointFilter>,
    },

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EndpointFilter {
    /// Host name to match.
    ///
    /// Only some of the wildcards types are supported. See "domains" field in https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#config-route-v3-virtualhost
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

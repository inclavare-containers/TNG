use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::{attest::AttestArgs, verify::VerifyArgs, Endpoint};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AddIngressArgs {
    #[serde(flatten)]
    pub ingress_mode: IngressMode,

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

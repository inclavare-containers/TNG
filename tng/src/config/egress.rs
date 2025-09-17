use serde::{Deserialize, Serialize};

use super::{ra::RaArgsUnchecked, Endpoint};

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
    #[serde(alias = "decap_from_http")]
    pub ohttp: Option<OHttpArgs>,

    #[serde(default = "Option::default")]
    pub direct_forward: Option<DirectForwardRules>,

    #[serde(flatten)]
    pub ra_args: RaArgsUnchecked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DirectForwardRules(pub Vec<DirectForwardRule>);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DirectForwardRule {
    pub http_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EgressMappingArgs {
    pub r#in: Endpoint,
    pub out: Endpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EgressNetfilterArgs {
    pub capture_dst: Endpoint,

    #[serde(default = "bool::default")]
    pub capture_local_traffic: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub so_mark: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum EgressMode {
    #[serde(rename = "mapping")]
    Mapping(EgressMappingArgs),

    #[serde(rename = "netfilter")]
    Netfilter(EgressNetfilterArgs),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct OHttpArgs {
    #[serde(default = "Option::default")]
    pub allow_non_tng_traffic_regexes: Option<AllowNonTngTrafficRegexes>,

    /// CORS configuration for OHTTP server
    #[serde(default = "Option::default")]
    pub cors: Option<CorsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// Allow origins for CORS, e.g. ["https://example.com", "https://app.example.com"]
    #[serde(default)]
    pub allow_origins: Vec<String>,

    /// Allow methods for CORS, e.g. ["GET", "POST", "OPTIONS"]
    #[serde(default)]
    pub allow_methods: Vec<String>,

    /// Allow headers for CORS, e.g. ["Content-Type", "Authorization"]
    #[serde(default)]
    pub allow_headers: Vec<String>,

    /// Expose headers for CORS, e.g. ["X-Custom-Header"]
    #[serde(default)]
    pub expose_headers: Vec<String>,

    /// Allow credentials for CORS
    #[serde(default)]
    pub allow_credentials: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct AllowNonTngTrafficRegexes(Vec<String>);

impl From<AllowNonTngTrafficRegexes> for DirectForwardRules {
    fn from(value: AllowNonTngTrafficRegexes) -> Self {
        Self(
            value
                .0
                .into_iter()
                .map(|s| DirectForwardRule { http_path: s })
                .collect(),
        )
    }
}

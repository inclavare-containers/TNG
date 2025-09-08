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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OHttpArgs {
    #[serde(default = "Option::default")]
    pub allow_non_tng_traffic_regexes: Option<AllowNonTngTrafficRegexes>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

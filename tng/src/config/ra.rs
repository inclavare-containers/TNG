use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RaArgs {
    #[serde(default = "bool::default")]
    pub no_ra: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub attest: Option<AttestArgs>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyArgs>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AttestArgs {
    pub aa_addr: String,

    // The interval seconds to refresh the evidence.
    pub refresh_interval: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerifyArgs {
    pub as_addr: String,

    #[serde(default = "bool::default")]
    pub as_is_grpc: bool,

    pub policy_ids: Vec<String>,

    #[serde(default = "Default::default")]
    pub trusted_certs_paths: Option<Vec<String>>,
}

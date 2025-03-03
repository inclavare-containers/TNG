use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerifyArgs {
    pub as_addr: String,

    #[serde(default = "bool::default")]
    pub as_is_grpc: bool,

    pub policy_ids: Vec<String>,

    #[serde(default = "Default::default")]
    pub trusted_certs_paths: Vec<String>,
}

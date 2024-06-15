use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerifyArgs {
    pub as_addr: String,
    pub policy_ids: Vec<String>,
}

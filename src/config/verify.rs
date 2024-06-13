use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifyArgs {
    pub as_addr: String,
    pub policy_ids: Vec<String>,
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestArgs {
    pub as_addr: String,
    pub policy_ids: Vec<String>,
}

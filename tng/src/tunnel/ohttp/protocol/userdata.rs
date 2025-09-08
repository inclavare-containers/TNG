use serde::{Deserialize, Serialize};

use crate::tunnel::ohttp::protocol::HpkeKeyConfig;

/// Server side evidence user data
#[derive(Serialize, Deserialize, Debug)]
pub struct ServerUserData {
    /// Challenge token. This is a JWT string obtained from the attestation service
    pub challenge_token: String,

    /// HPKE (Hybrid Public Key Encryption) key configuration
    pub hpke_key_config: HpkeKeyConfig,
}

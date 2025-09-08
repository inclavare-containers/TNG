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

/// Client side evidence user data
#[derive(Serialize, Deserialize, Debug)]
pub struct ClientUserData {
    /// Challenge token. This is a JWT string obtained from the attestation service
    pub challenge_token: String,

    /// Client side public key encoded in base64
    pub pk_s: String,
}

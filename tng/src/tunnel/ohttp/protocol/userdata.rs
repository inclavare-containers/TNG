use anyhow::{bail, Result};
use rats_cert::tee::claims::Claims;
use serde::{Deserialize, Serialize};

use crate::tunnel::ohttp::protocol::HpkeKeyConfig;

/// Server side evidence user data
#[derive(Serialize, Deserialize, Debug)]
pub struct ServerUserData {
    /// Challenge token. This is a JWT string obtained from the attestation service
    #[serde(rename = "challenge_token")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_token: Option<String>,

    /// HPKE (Hybrid Public Key Encryption) key configuration
    #[serde(rename = "hpke_key_config")]
    pub hpke_key_config: HpkeKeyConfig,
}

impl ServerUserData {
    pub fn to_claims(&self) -> Result<Claims> {
        Ok(match serde_json::to_value(self)? {
            serde_json::Value::Object(map) => map,
            _ => bail!("the server evidence userdata should be an object"),
        })
    }
}

/// Client side evidence user data
#[derive(Serialize, Deserialize, Debug)]
pub struct ClientUserData {
    /// Challenge token. This is a JWT string obtained from the attestation service
    #[serde(rename = "challenge_token")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_token: Option<String>,

    /// Client side public key encoded in base64
    #[serde(rename = "pk_s")]
    pub pk_s: String,
}

impl ClientUserData {
    #[allow(unused)]
    pub fn to_claims(&self) -> Result<Claims> {
        Ok(match serde_json::to_value(self)? {
            serde_json::Value::Object(map) => map,
            _ => bail!("the client evidence userdata should be an object"),
        })
    }
}

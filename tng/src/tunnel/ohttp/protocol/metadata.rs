#![allow(clippy::module_inception)]
include!(concat!(env!("OUT_DIR"), "/tng.ohttp.metadata.rs"));

pub const METADATA_MAX_LEN: usize = 32 * 1024 * 1024; // 32MB

impl std::fmt::Debug for ServerKeyConfigHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerKeyConfigHint")
            .field("public_key", &hex::encode(&self.public_key))
            .finish()
    }
}

impl std::fmt::Debug for AttestedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestedPublicKey")
            .field("attestation_result", &self.attestation_result)
            .field("pk_s", &hex::encode(&self.pk_s))
            .finish()
    }
}

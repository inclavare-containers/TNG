#![allow(clippy::module_inception)]
include!(concat!(env!("OUT_DIR"), "/tng.ohttp.metadata.rs"));

/// Upper bound on the metadata block: a big-endian u32 length prefix plus
/// that many prost bytes. The length on the wire is client-supplied, so both
/// ends enforce this cap -- the ingress refuses to build a longer metadata,
/// and the egress refuses to reserve a read buffer that long before the
/// bytes arrive.
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
            .field("as_provider", &self.as_provider)
            .finish()
    }
}

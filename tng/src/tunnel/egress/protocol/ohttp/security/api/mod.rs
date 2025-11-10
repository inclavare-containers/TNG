pub mod background_check;
pub mod key_config;
pub mod tunnel;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::OnceCell;

use crate::config::ra::RaArgs;
use crate::error::TngError;
use crate::tunnel::ohttp::protocol::KeyConfigResponse;
use crate::tunnel::utils::maybe_cached::MaybeCached;

/// OHTTP API handler for processing TNG server interfaces
///
/// This struct implements the server-side APIs required for TNG OHTTP functionality,
/// including key configuration management, encrypted request processing, and attestation
/// handling in different modes (passport or background check).
///
/// The handler manages cryptographic keys, remote attestation data, and provides
/// caching mechanisms to optimize performance for repeated operations.
pub struct OhttpServerApi {
    /// Remote Attestation arguments
    ra_args: Arc<RaArgs>,
    /// OHTTP key configurations
    ohttp: Arc<ohttp::Server>,
    /// Cache for storing passport mode key configuration responses
    ///
    /// In passport mode, the server generates an attestation (passport) that is cached
    /// and reused for subsequent client requests to avoid expensive re-attestation.
    /// The cache automatically refreshes based on configured refresh strategy.
    passport_cache: OnceCell<MaybeCached<KeyConfigResponse, TngError>>,
}

impl OhttpServerApi {
    /// Create a new OHttp Server API handler
    ///
    /// This function generates OHTTP key configurations with the following algorithms:
    /// - KEM: X25519Sha256
    /// - Symmetric Algorithms:
    ///   - KDF: HkdfSha256
    ///   - AEAD: ChaCha20Poly1305, Aes256Gcm, Aes128Gcm
    pub fn new(ra_args: RaArgs) -> Result<Self, TngError> {
        // TODO: support multiple key config and select key config based on key id

        // Create key config with X25519Sha256 KEM and multiple symmetric algorithms, this will generate all the keys randomly
        let config = ohttp::KeyConfig::new(
            0, // key_id
            ohttp::hpke::Kem::X25519Sha256,
            vec![
                ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                ),
                ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::Aes256Gcm,
                ),
                ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::Aes128Gcm,
                ),
            ],
        )
        .map_err(TngError::from)?;

        // Initialize the ohttp server
        let ohttp = ohttp::Server::new(config).map_err(TngError::from)?;

        Ok(OhttpServerApi {
            ra_args: Arc::new(ra_args),
            ohttp: Arc::new(ohttp),
            passport_cache: Default::default(),
        })
    }
}

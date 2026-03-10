pub mod background_check;
pub mod key_config;
pub mod tunnel;

use std::sync::Arc;

use anyhow::Result;
#[cfg(unix)]
use tokio::sync::RwLock;

use crate::config::egress::KeyArgs;
use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::file::FileBasedKeyManager;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::PeerSharedKeyManager;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::{
    self_generated::SelfGeneratedKeyManager, KeyManager,
};
#[cfg(unix)]
use crate::tunnel::ohttp::key_config::PublicKeyData;
#[cfg(unix)]
use crate::tunnel::ohttp::protocol::KeyConfigResponse;
use crate::tunnel::ra_context::RaContext;
#[cfg(unix)]
use crate::tunnel::utils::maybe_cached::MaybeCached;
use crate::TokioRuntime;

/// OHTTP API handler for processing TNG server interfaces
///
/// This struct implements the server-side APIs required for TNG OHTTP functionality,
/// including key configuration management, encrypted request processing, and attestation
/// handling in different modes (passport or background check).
///
/// The handler manages cryptographic keys, remote attestation data, and provides
/// caching mechanisms to optimize performance for repeated operations.
pub struct OhttpServerApi {
    /// Pre-instantiated Remote Attestation context
    ra_context: Arc<RaContext>,
    /// Key manager for OHTTP key configurations
    key_manager: Arc<dyn KeyManager>,
    /// Cache for storing passport mode key configuration responses
    ///
    /// In passport mode, the server generates an attestation (passport) that is cached
    /// and reused for subsequent client requests to avoid expensive re-attestation.
    /// The cache automatically refreshes based on configured refresh strategy.
    /// When keys change, the cache is invalidated and regenerated.
    #[cfg(unix)]
    passport_cache: Arc<RwLock<Option<MaybeCached<(PublicKeyData, KeyConfigResponse), TngError>>>>,
}

impl OhttpServerApi {
    /// Create a new OHttp Server API handler
    ///
    /// This function creates an OHTTP server API with a default random key manager.
    pub async fn new(
        ra_context: Arc<RaContext>,
        key: KeyArgs,
        runtime: TokioRuntime,
    ) -> Result<Self, TngError> {
        // Create key manager based on configuration
        let key_manager: Arc<dyn KeyManager> = match key {
            KeyArgs::SelfGenerated { rotation_interval } => Arc::new(
                SelfGeneratedKeyManager::new_with_auto_refresh(runtime, rotation_interval)?,
            ),
            KeyArgs::File { path } => {
                Arc::new(FileBasedKeyManager::new(runtime, path.into()).await?)
            }
            KeyArgs::PeerShared(peer_shared_args) => {
                Arc::new(PeerSharedKeyManager::new(runtime, peer_shared_args).await?)
            }
        };

        Ok(OhttpServerApi {
            ra_context,
            key_manager,
            #[cfg(unix)]
            passport_cache: Arc::new(RwLock::new(None)),
        })
    }
}

pub mod background_check;
pub mod key_config;
pub mod tunnel;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{OnceCell, RwLock};

use crate::config::egress::KeyArgs;
use crate::config::ra::RaArgs;
use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::{
    self_generated::SelfGeneratedKeyManager, KeyManager,
};
use crate::tunnel::ohttp::protocol::KeyConfigResponse;
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
    /// Remote Attestation arguments
    ra_args: Arc<RaArgs>,
    /// Key manager for OHTTP key configurations
    pub(crate) key_manager: Arc<SelfGeneratedKeyManager>,
    /// Cache for storing passport mode key configuration responses
    ///
    /// In passport mode, the server generates an attestation (passport) that is cached
    /// and reused for subsequent client requests to avoid expensive re-attestation.
    /// The cache automatically refreshes based on configured refresh strategy.
    passport_cache: Arc<RwLock<OnceCell<MaybeCached<KeyConfigResponse, TngError>>>>,
}

impl OhttpServerApi {
    /// Create a new OHttp Server API handler
    ///
    /// This function creates an OHTTP server API with a default random key manager.
    pub async fn new(
        ra_args: RaArgs,
        key: KeyArgs,
        runtime: TokioRuntime,
    ) -> Result<Self, TngError> {
        // Create a default random key manager
        let KeyArgs::SelfGenerated { rotation_interval } = key;
        let key_manager =
            SelfGeneratedKeyManager::new_with_auto_refresh(runtime, rotation_interval)?;

        let passport_cache: Arc<RwLock<OnceCell<MaybeCached<KeyConfigResponse, TngError>>>> =
            Default::default();

        // Register a callback to reset the passport cache when key changes
        {
            let passport_cache_cloned = passport_cache.clone();
            key_manager
                .register_callback(move |event| {
                    tracing::debug!(?event, "Key change event");

                    let passport_cache_cloned = passport_cache_cloned.clone();
                    Box::pin(async move {
                        // Reset the passport cache
                        let _ = passport_cache_cloned.write().await.take();
                    })
                })
                .await;
        }

        Ok(OhttpServerApi {
            ra_args: Arc::new(ra_args),
            key_manager: Arc::new(key_manager),
            passport_cache,
        })
    }
}

use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::callback_manager::{
    CallbackManager, KeyChangeCallback, KeyChangeEvent,
};
use crate::tunnel::egress::protocol::ohttp::security::key_manager::{
    KeyInfo, KeyManager, KeyStatus,
};
use crate::tunnel::ohttp::key_config::{KeyConfigExtend, PublicKeyData};
use crate::tunnel::utils::runtime::supervised_task::SupervisedTaskResult;
use crate::tunnel::utils::runtime::TokioRuntime;

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use async_trait::async_trait;

/// Implementation of KeyManager that generates random keys with automatic rotation
pub struct SelfGeneratedKeyManager {
    /// Map of key IDs to key information
    inner: Arc<RandomKeyManagerInner>,
    /// Handle to cancel the refresh task when RandomKeyManager is dropped
    #[allow(unused)]
    refresh_task: tokio::task::JoinHandle<SupervisedTaskResult<()>>,
}

pub struct RandomKeyManagerInner {
    /// Map of key IDs to key information
    keys: tokio::sync::RwLock<HashMap<PublicKeyData, KeyInfo>>,
    /// List of registered callbacks triggered when a key is updated or created
    callback_manager: CallbackManager,

    rotation_interval: u64,
}

impl SelfGeneratedKeyManager {
    /// Create a new RandomKeyManager with auto-refresh task
    ///
    /// Initializes the key manager with an empty key set and starts a background
    /// task that automatically refreshes keys based on their expiration schedule
    pub fn new_with_auto_refresh(
        runtime: TokioRuntime,
        rotation_interval: u64,
        // callbacks: Option<&[Arc<
        //     dyn for<'a, 'b> Fn(
        //             &'a KeyChangeEvent<'b>,
        //         ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>
        //         + Send
        //         + Sync
        //         + 'static,
        // >]>
    ) -> Result<Self, TngError> {
        let inner = Arc::new(RandomKeyManagerInner {
            keys: tokio::sync::RwLock::new(HashMap::new()),
            callback_manager: CallbackManager::new(),
            rotation_interval,
        });

        let inner_clone = inner.clone();

        // Spawn the refresh task using the provided runtime
        let refresh_task = runtime.spawn_supervised_task_current_span(async move {
            loop {
                // Perform the refresh
                if let Err(e) = inner_clone.refresh_keys().await {
                    tracing::error!("Failed to refresh OHTTP keys: {:?}", e);
                }

                // Calculate the next refresh time
                let next_refresh = inner_clone.calculate_next_refresh_time().await;

                // Sleep until the next refresh
                tokio::time::sleep(next_refresh).await;
            }
        });

        Ok(Self {
            inner,
            refresh_task,
        })
    }
}

impl RandomKeyManagerInner {
    /// Calculate when the next key refresh should happen
    ///
    /// Returns the duration until the next refresh is needed
    async fn calculate_next_refresh_time(&self) -> std::time::Duration {
        let now = SystemTime::now();
        let mut earliest_time = now + Duration::from_secs(self.rotation_interval);

        let keys = self.keys.read().await;

        for key_info in keys.values() {
            if !matches!(key_info.status, KeyStatus::Stale) {
                // Compare with the stale time (when key should be marked stale)
                earliest_time = std::cmp::min(earliest_time, key_info.stale_at);
            }

            // Compare with the expiration time (when key should be removed)
            earliest_time = std::cmp::min(earliest_time, key_info.expire_at);
        }

        // Calculate time until earliest event
        if let Ok(duration) = earliest_time.duration_since(now) {
            // Make sure we return at least 1 second to prevent busy loops
            if duration.as_secs() > 0 {
                return duration;
            }
        }
        Duration::from_secs(1) // at least 1 second
    }

    /// Generate a new key with the specified ID
    fn generate_key_config(&self, key_id: u8) -> Result<ohttp::KeyConfig, TngError> {
        // Create key config with X25519Sha256 KEM and multiple symmetric algorithms
        let config = ohttp::KeyConfig::new(
            key_id,
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

        Ok(config)
    }

    /// Refresh keys based on their expiration times
    ///
    /// This method should be called periodically to manage key lifecycle:
    /// - Keys older than half their lifetime are marked as stale
    /// - Expired keys are removed
    /// - A new key is generated if no active key exists, with a lifetime of 2 * `rotation_interval`.
    async fn refresh_keys(&self) -> Result<(), TngError> {
        let now = SystemTime::now();
        let mut keys = self.keys.write().await;

        // Remove expired keys
        for (_, key_info) in keys.iter_mut() {
            // first, nofity the callbacks
            if key_info.expire_at <= now {
                self.callback_manager
                    .trigger(&KeyChangeEvent::Removed {
                        key_info: Cow::Borrowed(key_info),
                    })
                    .await;
            }
        }
        keys.retain(|_, key_info| key_info.expire_at > now);

        // Mark stale keys
        for (_, key_info) in keys.iter_mut() {
            if key_info.stale_at <= now && matches!(key_info.status, KeyStatus::Active) {
                self.callback_manager
                    .trigger(&KeyChangeEvent::StatusChanged {
                        key_info: Cow::Borrowed(key_info),
                        old_status: key_info.status,
                        new_status: KeyStatus::Stale,
                    })
                    .await;
                key_info.status = KeyStatus::Stale;
            }
        }

        // Add new active key if needed
        let have_active_key = keys
            .values()
            .any(|key_info| matches!(key_info.status, KeyStatus::Active));

        if !have_active_key {
            tracing::info!("Generating new OHTTP key");
            let new_key_id = (0..u8::MAX)
                .find(|id| {
                    !keys
                        .values()
                        .any(|key_info| key_info.key_config.key_id() == *id)
                })
                .unwrap_or_else(|| {
                    tracing::warn!("No unused key ID found, generating key with ID 0 instead");
                    0
                });

            let key_config = self.generate_key_config(new_key_id)?;
            let created_at = now;
            let stale_at = created_at + Duration::from_secs(self.rotation_interval);
            let expire_at = created_at + Duration::from_secs(self.rotation_interval * 2);

            let key_info = KeyInfo {
                key_config,
                status: KeyStatus::Active,
                created_at,
                stale_at,
                expire_at,
            };
            self.callback_manager
                .trigger(&KeyChangeEvent::Created {
                    key_info: Cow::Borrowed(&key_info),
                })
                .await;
            keys.insert(key_info.key_config.public_key_data()?, key_info);
        }

        Ok(())
    }
}

#[async_trait]
impl KeyManager for SelfGeneratedKeyManager {
    async fn get_fist_key_by_key_id(&self, key_id: u8) -> Result<KeyInfo, TngError> {
        let keys = self.inner.keys.read().await;
        keys.values()
            .find(|key_info| key_info.key_config.key_id() == key_id)
            .cloned()
            .ok_or(TngError::ServerKeyConfigNotFound(either::Either::Left(
                key_id,
            )))
    }

    async fn get_key_by_public_key_data(
        &self,
        public_key_data: &PublicKeyData,
    ) -> Result<KeyInfo, TngError> {
        let keys = self.inner.keys.read().await;
        keys.get(public_key_data)
            .cloned()
            .ok_or(TngError::ServerKeyConfigNotFound(either::Either::Right(
                public_key_data.clone(),
            )))
    }

    async fn get_client_visible_keys(&self) -> Result<Vec<KeyInfo>, TngError> {
        let keys = self.inner.keys.read().await;
        Ok(keys
            .values()
            .filter(|key_info| matches!(key_info.status, KeyStatus::Active))
            .cloned()
            .collect())
    }

    async fn register_callback(&self, callback: KeyChangeCallback) {
        self.inner
            .callback_manager
            .register_callback(callback)
            .await;
    }
}

impl Drop for SelfGeneratedKeyManager {
    fn drop(&mut self) {
        self.refresh_task.abort();
    }
}

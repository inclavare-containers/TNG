use std::{
    borrow::Cow,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{
    error::TngError,
    tunnel::{
        egress::protocol::ohttp::security::key_manager::{
            callback_manager::{CallbackManager, KeyChangeCallback, KeyChangeEvent},
            KeyInfo, KeyManager, KeyStatus,
        },
        ohttp::key_config::{KeyConfigExtend, PublicKeyData},
        utils::{file_watcher::FileWatcher, runtime::supervised_task::SupervisedTaskResult},
    },
    TokioRuntime,
};

/// A key manager that loads an HPKE private key from a PEM file and monitors the file for changes.
///
/// This implementation supports dynamic reloading of the OHTTP decryption key when the underlying
/// PEM file is updated on disk (e.g., via external certificate rotation tools).
///
/// It uses the `notify` crate to watch for filesystem events and automatically triggers callbacks
/// when a new key is loaded. Old keys are replaced immediately upon reload — it's expected that
/// clients will re-fetch public key configurations after updates.
///
/// # Thread Safety
/// Internally uses `Arc<RwLock<...>>` for shared access, making it safe to use across async tasks.
///
/// # Graceful Shutdown
/// The background watcher task is automatically aborted when this struct is dropped.
pub struct FileBasedKeyManager {
    /// Shared inner state containing the current key and callback registry.
    inner: Arc<FileBasedKeyManagerInner>,

    /// Background task responsible for monitoring file system changes.
    /// This task runs until the manager is dropped or manually aborted.
    #[allow(unused)]
    watch_task: tokio::task::JoinHandle<SupervisedTaskResult<()>>,
}

/// Inner mutable state of the `FileBasedKeyManager`, wrapped in `Arc` for sharing.
struct FileBasedKeyManagerInner {
    /// Current HPKE key information, or `None` if no valid key is loaded.
    ///
    /// Protected by a write lock during updates; readers can concurrently access the current key.
    /// When the file is modified, a new `KeyInfo` replaces the old one atomically.
    key: RwLock<Option<(PublicKeyData, KeyInfo)>>,

    /// Manages registration and invocation of callbacks on key lifecycle events (create/remove).
    ///
    /// Used to notify subscribers (like public key exporters or health monitors) when the key
    /// changes due to file reloads.
    callback_manager: CallbackManager,
}
impl FileBasedKeyManager {
    /// Create a new FileBasedKeyManager and start watching the file.
    ///
    /// Loads the initial key from the given PEM file and spawns a background task
    /// to monitor file changes using `notify`.
    ///
    /// The background watcher monitors both:
    /// - The target file directly, for in-place modifications.
    /// - The parent directory, to catch atomic rename operations (e.g. `mv` from outside editor).
    ///
    /// When a relevant change is detected (create, modify data/name), the key is reloaded
    /// asynchronously. If reload succeeds, the old key is replaced and callbacks are triggered.
    /// Failed reloads are logged but do not stop the watcher.
    ///
    /// The file watching logic is delegated to the [`FileWatcher`] module for better
    /// separation of concerns and testability.
    ///
    /// # Arguments
    ///
    /// * `runtime` - The Tokio runtime used to spawn the background watch task.
    /// * `path` - Path to the PEM-encoded PKCS#8 private key file.
    ///
    /// # Returns
    ///
    /// A `Result<Self, TngError>`:
    /// - `Ok` contains the initialized key manager with active watch task.
    /// - `Err` if the initial key load failed or file watching could not be started.
    ///
    /// # Errors
    ///
    /// - `TngError::LoadPrivateKeyFailed` if the initial PEM file cannot be read or parsed.
    /// - `TngError::WatchFileFailed` if the file watcher cannot be initialized.
    ///
    pub async fn new(runtime: TokioRuntime, path: PathBuf) -> Result<Self, TngError> {
        let key_info = Self::load_key_from_pem(&path).await?;

        let inner = Arc::new(FileBasedKeyManagerInner {
            key: RwLock::new(Some((key_info.key_config.public_key_data()?, key_info))),
            callback_manager: CallbackManager::new(),
        });

        let inner_clone = inner.clone();

        // Start the file watcher and receive events indicating when the file changes.
        let mut file_watcher = FileWatcher::new(path.clone())
            .map_err(|e| TngError::WatchFileFailed(path.clone(), e))?;

        let watch_task = runtime.spawn_supervised_task_current_span(async move {
            while let Some(result) = file_watcher.recv().await {
                match result {
                    Ok(()) => {
                        tracing::info!(?path, "Key file changed, attempting to reload OHTTP key");

                        match Self::load_key_from_pem(&path).await {
                            Ok(new_key_info) => {
                                let old_key_info = {
                                    let mut write = inner_clone.key.write().await;
                                    let public_key_data =
                                        match new_key_info.key_config.public_key_data() {
                                            Ok(public_key_data) => public_key_data,
                                            Err(error) => {
                                                tracing::error!(
                                                    ?path,
                                                    ?error,
                                                    "Failed to get public key data"
                                                );
                                                continue;
                                            }
                                        };
                                    write.replace((public_key_data, new_key_info.clone()))
                                };

                                // Trigger creation event for the new key
                                inner_clone
                                    .callback_manager
                                    .trigger(&KeyChangeEvent::Created {
                                        key_info: Cow::Borrowed(&new_key_info),
                                    })
                                    .await;

                                // Trigger removal event for the old key, if exists
                                if let Some((_, old)) = old_key_info {
                                    inner_clone
                                        .callback_manager
                                        .trigger(&KeyChangeEvent::Removed {
                                            key_info: Cow::Borrowed(&old),
                                        })
                                        .await;
                                }

                                tracing::info!(?path, "Successfully reloaded OHTTP key from file");
                            }
                            Err(error) => {
                                tracing::error!(
                                    ?path,
                                    ?error,
                                    "Failed to reload OHTTP key from file"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(?path, ?error, "Internal error in file watcher");
                    }
                }
            }
        });

        Ok(FileBasedKeyManager { inner, watch_task })
    }

    /// Loads and parses a PEM-encoded PKCS#8 private key into a usable `KeyInfo` structure.
    async fn load_key_from_pem(path: &Path) -> Result<KeyInfo, TngError> {
        use ohttp::hpke;

        let pem_data = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| TngError::LoadPrivateKeyFailed(path.into(), anyhow::Error::from(e)))?;

        let key_config = ohttp::KeyConfig::new_from_pkcs8_pem(
            0,
            hpke::Kem::X25519Sha256,
            vec![
                ohttp::SymmetricSuite::new(hpke::Kdf::HkdfSha256, hpke::Aead::ChaCha20Poly1305),
                ohttp::SymmetricSuite::new(hpke::Kdf::HkdfSha256, hpke::Aead::Aes256Gcm),
                ohttp::SymmetricSuite::new(hpke::Kdf::HkdfSha256, hpke::Aead::Aes128Gcm),
            ],
            &pem_data,
        )
        .map_err(TngError::from)?;

        let created_at = SystemTime::now();
        let expire_at = created_at + Duration::from_secs(86400 * 365 * 30); // 30 years, far future
        let stale_at = expire_at; // 30 years, far future

        Ok(KeyInfo {
            key_config,
            status: KeyStatus::Active,
            created_at,
            stale_at,
            expire_at,
        })
    }
}

#[async_trait]
impl KeyManager for FileBasedKeyManager {
    async fn get_fist_key_by_key_id(&self, key_id: u8) -> Result<KeyInfo, TngError> {
        let key = self.inner.key.read().await;
        match key.as_ref() {
            Some((_, k)) if k.key_config.key_id() == key_id => Ok(k.clone()),
            _ => Err(TngError::ServerKeyConfigNotFound(either::Either::Left(
                key_id,
            ))),
        }
    }

    async fn get_key_by_public_key_data(
        &self,
        public_key_data: &PublicKeyData,
    ) -> Result<KeyInfo, TngError> {
        let key = self.inner.key.read().await;
        match key.as_ref() {
            Some((p, k)) if p == public_key_data => Ok(k.clone()),
            _ => Err(TngError::ServerKeyConfigNotFound(either::Either::Right(
                public_key_data.clone(),
            ))),
        }
    }

    async fn get_client_visible_keys(&self) -> Result<Vec<KeyInfo>, TngError> {
        let key = self.inner.key.read().await;
        if let Some((_, info)) = key
            .as_ref()
            .filter(|(_, key_info)| matches!(key_info.status, KeyStatus::Active))
        {
            Ok(vec![info.clone()])
        } else {
            Ok(Default::default())
        }
    }

    async fn register_callback(&self, callback: KeyChangeCallback) {
        self.inner
            .callback_manager
            .register_callback(callback)
            .await;
    }
}

impl Drop for FileBasedKeyManager {
    fn drop(&mut self) {
        self.watch_task.abort();
    }
}

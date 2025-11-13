use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::Context;
use async_trait::async_trait;
use futures::Future;
use notify::{
    event::{DataChange, EventKind, ModifyKind},
    Event, RecommendedWatcher, RecursiveMode, Watcher,
};
use scopeguard::defer;
use tokio::sync::RwLock;

use crate::{
    error::TngError,
    tunnel::{
        egress::protocol::ohttp::security::key_manager::{
            callback_manager::{CallbackManager, KeyChangeEvent},
            KeyInfo, KeyManager, KeyStatus,
        },
        utils::runtime::supervised_task::SupervisedTaskResult,
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
    key: RwLock<Option<KeyInfo>>,

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
    pub async fn new(runtime: TokioRuntime, path: PathBuf) -> Result<Self, TngError> {
        let key_info = Self::load_key_from_pem(&path).await?;

        let inner = Arc::new(FileBasedKeyManagerInner {
            key: RwLock::new(Some(key_info)),
            callback_manager: CallbackManager::new(),
        });

        let inner_clone = inner.clone();

        // Spawn file watcher task
        let watch_task = runtime.spawn_supervised_task_current_span(async move {
            defer! {
                tracing::info!(?path, "Stop watching for OHTTP key updates");
            }

            let fut = async {
                tracing::info!(?path, "Start watching for OHTTP key updates");

                // Use blocking channel since notify is not async-native
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

                let mut watcher: RecommendedWatcher = Watcher::new(
                    move |res| {
                        let _ = tx.send(res); // ignore errors
                    },
                    notify::Config::default(),
                )
                .context("Failed to initialize file watcher")?;

                // Watch the parent directory to catch atomic renames
                if let Some(parent) = path.parent() {
                    watcher
                        .watch(parent, RecursiveMode::NonRecursive)
                        .with_context(|| format!("Failed to watch directory {:?}", parent))?;
                }

                // Also watch the file directly (for non-atomic changes)
                watcher
                    .watch(&path, RecursiveMode::NonRecursive)
                    .with_context(|| format!("Failed to watch file {:?}", path))?;

                while let Some(result) = rx.recv().await {
                    match result {
                        Ok(event) => {
                            if Self::is_relevant_event(&event, &path) {
                                match Self::load_key_from_pem(&path).await {
                                    Ok(new_key_info) => {
                                        let old_key_info = {
                                            let mut write = inner_clone.key.write().await;
                                            write.replace(new_key_info.clone())
                                        };

                                        // Trigger events
                                        inner_clone
                                            .callback_manager
                                            .trigger(&KeyChangeEvent::Created {
                                                key_info: &new_key_info,
                                            })
                                            .await;

                                        if let Some(old) = old_key_info {
                                            inner_clone
                                                .callback_manager
                                                .trigger(&KeyChangeEvent::Removed {
                                                    key_info: &old,
                                                })
                                                .await;
                                        }

                                        tracing::info!(
                                            ?path,
                                            "Successfully reloaded OHTTP key from file"
                                        );
                                    }
                                    Err(error) => {
                                        tracing::error!(
                                            ?path,
                                            ?error,
                                            "Failed to reload OHTTP key from file ",
                                        );
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            tracing::error!(?error, "File watch error");
                        }
                    }
                }

                Ok::<_, anyhow::Error>(())
            };

            if let Err(error) = fut.await {
                tracing::error!(?error, "File watch task failed");
            }
        });

        Ok(FileBasedKeyManager { inner, watch_task })
    }

    /// Determines whether a filesystem event should trigger a key reload.
    fn is_relevant_event(event: &Event, target_path: &Path) -> bool {
        // Check path
        if !event.paths.iter().any(|p| p == target_path) {
            return false;
        }

        // Check kind
        match &event.kind {
            EventKind::Modify(ModifyKind::Data(change)) => matches!(change, DataChange::Any),
            EventKind::Modify(_) => false, // Ignore other kinds of modifications
            EventKind::Create(_) => true,
            EventKind::Access(_) => false, // Ignore access events
            EventKind::Remove(_) => {
                tracing::warn!(
                    "OHTTP key file removed, will keep using the old key before recreation"
                );
                false
            }
            _ => true, // Be conservative: treat other events as relevant
        }
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
    async fn get_key(&self, key_id: u8) -> Result<KeyInfo, TngError> {
        let key = self.inner.key.read().await;
        match key.as_ref() {
            Some(k) if k.key_config.key_id() == key_id => Ok(k.clone()),
            _ => Err(TngError::ServerKeyConfigNotFound { key_id }),
        }
    }

    async fn get_all_keys(&self) -> Result<HashMap<u8, KeyInfo>, TngError> {
        let key = self.inner.key.read().await;
        if let Some(info) = key.as_ref() {
            let mut map = HashMap::with_capacity(1);
            map.insert(info.key_config.key_id(), info.clone());
            Ok(map)
        } else {
            Ok(HashMap::new())
        }
    }

    async fn register_callback(
        &self,
        callback: Arc<
            dyn for<'a, 'b> Fn(&'a KeyChangeEvent<'b>) -> Pin<Box<dyn Future<Output = ()> + Send>>
                + Send
                + Sync
                + 'static,
        >,
    ) {
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

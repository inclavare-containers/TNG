use futures::Future;
use std::{pin::Pin, sync::Arc};
use tokio::sync::RwLock;

use crate::tunnel::egress::protocol::ohttp::security::key_manager::{KeyInfo, KeyStatus};

/// Represents different types of key change events
#[derive(Debug, Clone)]
pub enum KeyChangeEvent<'a> {
    /// A new key has been created and added to the manager
    Created {
        /// The newly created key information
        key_info: &'a KeyInfo,
    },
    /// An existing key has been removed (e.g., expired)
    Removed {
        /// The key that was removed
        key_info: &'a KeyInfo,
    },
    /// The status of an existing key has changed (e.g., Active → Stale)
    StatusChanged {
        /// The key whose status changed
        key_info: &'a KeyInfo,
        /// Previous status
        old_status: KeyStatus,
        /// New status
        new_status: KeyStatus,
    },
}

/// Type alias for a callback that receives a key change event
pub type KeyChangeCallback =
    Arc<dyn Fn(&KeyChangeEvent) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Manages registration and invocation of callbacks for key changes
#[derive(Clone, Default)]
pub struct CallbackManager {
    callbacks: Arc<RwLock<Vec<KeyChangeCallback>>>,
}

impl CallbackManager {
    /// Create a new empty callback manager
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new callback
    ///
    /// The callback will be called whenever `trigger` is invoked.
    pub async fn register_callback<F>(&self, callback: F)
    where
        F: Fn(&'_ KeyChangeEvent<'_>) -> Pin<Box<dyn Future<Output = ()> + Send>>
            + Send
            + Sync
            + 'static,
    {
        let mut cbs = self.callbacks.write().await;
        cbs.push(Arc::new(callback));
    }

    /// Trigger all registered callbacks with the given event
    ///
    /// Runs synchronously. Consider offloading heavy work to another task.
    pub async fn trigger<'a>(&self, event: &KeyChangeEvent<'a>) {
        let callbacks = self.callbacks.read().await;
        for cb in callbacks.iter() {
            let () = cb(event).await;
        }
    }
}

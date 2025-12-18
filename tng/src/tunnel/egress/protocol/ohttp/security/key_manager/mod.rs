//! Key management for OHTTP servers
//!
//! This module provides abstractions for managing OHTTP key configurations.
//! It defines traits and implementations for different key management strategies:

use crate::tunnel::egress::protocol::ohttp::security::key_manager::callback_manager::KeyChangeCallback;
use crate::tunnel::ohttp::key_config::PublicKeyData;
use crate::{error::TngError, tunnel::ohttp::key_config::KeyConfigExtend};
use std::time::SystemTime;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

pub mod callback_manager;
pub mod file;
pub mod peer_shared;
pub mod self_generated;

/// Key status indicating whether a key is active or stale
#[derive(Debug, Clone, Copy)]
pub enum KeyStatus {
    /// Active key that should be provided to new clients
    Active,
    /// Stale key that is kept for existing connections but not given to new clients
    Stale,
}

/// Information about a key including the key config and its status
#[derive(Clone)]
pub struct KeyInfo {
    /// The OHTTP key configuration (not the full server)
    pub key_config: ohttp::KeyConfig,
    /// Status of the key (active or stale)
    pub status: KeyStatus,
    /// Time when the key was created
    pub created_at: SystemTime,
    /// Time when the key will stale
    pub stale_at: SystemTime,
    /// Time when the key will expire
    pub expire_at: SystemTime,
}

impl std::fmt::Debug for KeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut st = f.debug_struct("KeyInfo");
        match self.key_config.public_key_data() {
            Ok(public_key_data) => {
                st.field("public_key", &public_key_data);
            }
            Err(error) => {
                st.field("public_key", &error);
            }
        }
        st.field("status", &self.status)
            .field("created_at", &DateTime::<Utc>::from(self.created_at))
            .field("stale_at", &DateTime::<Utc>::from(self.stale_at))
            .field("expire_at", &DateTime::<Utc>::from(self.expire_at))
            .finish()
    }
}

/// Trait for managing OHTTP key configurations
///
/// This trait abstracts different ways of obtaining OHTTP key configurations,
/// allowing for flexibility in how keys are generated or acquired.
#[async_trait]
pub trait KeyManager: Send + Sync {
    /// Get an key info with their status by key ID
    ///
    /// Returns an key configuration for the given ID.
    async fn get_fist_key_by_key_id(&self, key_id: u8) -> Result<KeyInfo, TngError>;

    /// Get an key info with their status by key ID
    ///
    /// Returns an key configuration for the given ID.
    async fn get_key_by_public_key_data(
        &self,
        public_key_data: &PublicKeyData,
    ) -> Result<KeyInfo, TngError>;

    /// Get a list of keys that are visible and intended to be shared with clients
    ///
    /// Returns only keys that are active, valid, and safe to expose.
    async fn get_client_visible_keys(&self) -> Result<Vec<KeyInfo>, TngError>;

    /// Register a callback that will be called whenever a key is created or modified.
    ///
    /// The callback receives a reference to the updated `KeyInfo`.
    async fn register_callback(&self, callback: KeyChangeCallback);
}

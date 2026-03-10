//! Key management for OHTTP servers
//!
//! This module provides abstractions for managing OHTTP key configurations.
//! It defines traits and implementations for different key management strategies:

use crate::tunnel::ohttp::key_config::PublicKeyData;
use crate::{error::TngError, tunnel::ohttp::key_config::KeyConfigExtend};
use std::time::SystemTime;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

pub mod file;
pub mod peer_shared;
pub mod self_generated;

/// Key status indicating whether a key is pending, active or stale
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// Pending key that is waiting to be activated, can be used for new connections but not given to new clients
    Pending,
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
    /// Status of the key (pending, active or stale)
    pub status: KeyStatus,
    /// Time when the key will be activated
    pub actived_at: SystemTime,
    /// Time when the key will stale
    pub stale_at: SystemTime,
    /// Time when the key will expire
    pub expire_at: SystemTime,
}

impl KeyInfo {
    /// Generate a new KeyInfo with the specified parameters.
    ///
    /// According to serf-v2 protocol, the timestamps are calculated as:
    /// - actived_at: the provided activation time (may be in the future for pending keys)
    /// - stale_at: actived_at + rotation_interval
    /// - expire_at: stale_at + rotation_interval
    ///
    /// # Arguments
    /// * `key_id` - The key ID for the new key
    /// * `status` - The initial status (Pending, Active, or Stale)
    /// * `actived_at` - The time when the key will be activated
    /// * `rotation_interval` - The rotation interval in seconds
    pub fn generate(
        key_id: u8,
        status: KeyStatus,
        actived_at: SystemTime,
        rotation_interval: u64,
    ) -> Result<Self, TngError> {
        let stale_at = actived_at + std::time::Duration::from_secs(rotation_interval);
        let expire_at = stale_at + std::time::Duration::from_secs(rotation_interval);

        let key_config = ohttp::KeyConfig::new(
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

        Ok(Self {
            key_config,
            status,
            actived_at,
            stale_at,
            expire_at,
        })
    }

    /// Load a KeyInfo from a PEM-encoded PKCS#8 private key file.
    ///
    /// This is used by the file-based key manager to load a pre-existing private key.
    /// The loaded key will have:
    /// - key_id: 0 (fixed for file-based keys)
    /// - status: Active
    /// - actived_at: now
    /// - stale_at/expire_at: 30 years in the future (effectively never expiring)
    ///
    /// # Arguments
    /// * `pem_data` - The PEM-encoded PKCS#8 private key data
    pub fn from_pkcs8_pem(pem_data: &str) -> Result<Self, TngError> {
        use ohttp::hpke;

        let key_config = ohttp::KeyConfig::new_from_pkcs8_pem(
            0,
            hpke::Kem::X25519Sha256,
            vec![
                ohttp::SymmetricSuite::new(hpke::Kdf::HkdfSha256, hpke::Aead::ChaCha20Poly1305),
                ohttp::SymmetricSuite::new(hpke::Kdf::HkdfSha256, hpke::Aead::Aes256Gcm),
                ohttp::SymmetricSuite::new(hpke::Kdf::HkdfSha256, hpke::Aead::Aes128Gcm),
            ],
            pem_data,
        )
        .map_err(TngError::from)?;

        let actived_at = SystemTime::now();
        // For file-based keys, we set rotation_interval to 30 years (in seconds)
        // to make stale_at and expire_at far in the future
        let rotation_interval = 86400u64 * 365 * 30;
        let stale_at = actived_at + std::time::Duration::from_secs(rotation_interval);
        let expire_at = stale_at + std::time::Duration::from_secs(rotation_interval);

        Ok(Self {
            key_config,
            status: KeyStatus::Active,
            actived_at,
            stale_at,
            expire_at,
        })
    }
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
            .field("actived_at", &DateTime::<Utc>::from(self.actived_at))
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
    async fn get_key_by_public_key_data(
        &self,
        public_key_data: &PublicKeyData,
    ) -> Result<KeyInfo, TngError>;

    /// Get a list of keys that are visible and intended to be shared with clients
    ///
    /// Returns only keys that are active, valid, and safe to expose.
    async fn get_client_visible_keys(&self) -> Result<Vec<KeyInfo>, TngError>;
}

use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::{KeyInfo, KeyStatus};
use crate::tunnel::ohttp::key_config::{KeyConfigExtend, PublicKeyData};
use anyhow::Context as _;
use itertools::Itertools as _;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

/// Cluster key set containing all keys indexed by public_key.
///
/// This structure uses a unified HashMap as the single source of truth,
/// with KeyStatus indicating the state of each key.
#[derive(Debug, Clone)]
pub struct ClusterKeySet {
    /// All keys indexed by public_key (single source of truth)
    keys: HashMap<PublicKeyData, KeyInfo>,
    /// Rotation interval in seconds
    rotation_interval: u64,
    /// Notify key watcher to check immediately when key set changes
    notify: Option<Arc<tokio::sync::Notify>>,
}

impl ClusterKeySet {
    /// Create a new ClusterKeySet with an initial active key.
    ///
    /// Note that there must be at least one active key.
    /// This constructor is used during Bootstrap when the first active key is created.
    pub fn new(public_key: PublicKeyData, active_key: KeyInfo, rotation_interval: u64) -> Self {
        let mut keys = HashMap::new();
        keys.insert(public_key, active_key);
        Self {
            keys,
            rotation_interval,
            notify: None,
        }
    }

    /// Set the notify handle for key watcher.
    pub fn set_notify(&mut self, notify: Arc<tokio::sync::Notify>) {
        self.notify = Some(notify);
    }

    /// Trigger notification to key watcher.
    fn trigger_notify(&self) {
        if let Some(ref notify) = self.notify {
            notify.notify_one();
        }
    }

    /// Find a key by its public_key.
    pub fn get_key_by_public_key(&self, public_key: &PublicKeyData) -> Option<&KeyInfo> {
        self.keys.get(public_key)
    }

    /// Get the key that should be returned to clients.
    ///
    /// - If only one active key exists, return it
    /// - If multiple active keys exist, return the one with latest expire_at
    ///   (if expire_at is equal, the order is deterministic but arbitrary)
    pub fn get_client_visible_key(&self) -> Result<&KeyInfo, TngError> {
        // Multiple active keys: return the one with latest expire_at
        self.keys
            .iter()
            .filter(|(_, key_info)| matches!(key_info.status, KeyStatus::Active))
            .sorted_by_cached_key(|&(public_key, key_info)| (key_info.expire_at, public_key))
            .rev()
            .next()
            .map(|(_, key_info)| key_info)
            .ok_or(TngError::NoActiveKey)
    }

    /// Remove all expired keys (where expire_at <= now).
    ///
    /// Returns the number of keys removed.
    /// Note: Will not remove the only active key to maintain invariant.
    pub fn remove_expired_keys(&mut self, now: SystemTime) -> usize {
        let before_count = self.keys.len();
        // Step 1: Find all expired keys (expire_at <= now)
        let expired: Vec<PublicKeyData> = self
            .keys
            .iter()
            .filter(|(_, info)| info.expire_at <= now)
            .map(|(k, _)| k.clone())
            .collect();

        // If no keys are expired, nothing to do
        if !expired.is_empty() {
            // Step 2: Check if there are any *non-expired* Active keys
            let has_non_expired_active = self
                .keys
                .iter()
                .any(|(_, info)| info.status == KeyStatus::Active && info.expire_at > now);

            if has_non_expired_active {
                // If there's at least one active key that hasn't expired,
                // we can safely remove all expired ones.
                for key in expired {
                    self.keys.remove(&key);
                }
            } else {
                // Otherwise, all Active keys are expired (or no Active keys exist),
                // so we must preserve the Active key with the latest `stale_at`, if any.
                let key_to_preserve = self
                    .keys
                    .iter()
                    .filter(|(_, info)| info.status == KeyStatus::Active)
                    .max_by_key(|(_, info)| info.stale_at) // Find Active key with max stale_at
                    .map(|(k, _)| k.clone()); // Extract key reference

                // Remove all expired keys except the one we want to preserve (if it's among them)
                for key_ref in expired {
                    if key_to_preserve.as_ref() != Some(&key_ref) {
                        self.keys.remove(&key_ref);
                    }
                }
            }
        }

        let removed = before_count - self.keys.len();

        if removed > 0 {
            self.trigger_notify();
        }

        removed
    }

    /// Transition expired active keys (stale_at <= now) to stale status.
    ///
    /// Only transitions keys if there are other active keys remaining (at least one required).
    /// Returns the number of keys transitioned.
    pub fn transition_active_to_stale(&mut self, now: SystemTime) -> usize {
        let mut transitioned = 0;

        // Step 1: Collect all Active keys
        let active_keys: Vec<(&PublicKeyData, &KeyInfo)> = self
            .keys
            .iter()
            .filter(|(_, info)| info.status == KeyStatus::Active)
            .collect();

        // Step 2: Find those that should become Stale (stale_at <= now)
        let mut to_transition: Vec<PublicKeyData> = active_keys
            .iter()
            .filter(|(_, info)| info.stale_at <= now)
            .map(|(k, _)| (*k).clone())
            .collect();

        // If no key needs transition, nothing to do
        if !to_transition.is_empty() {
            // Step 3: Check if we'd remove *all* active keys?
            let would_remove_all = to_transition.len() == active_keys.len();

            if would_remove_all {
                // All active keys are stale-eligible, so we must preserve one
                // Pick the one with the latest `stale_at`
                let key_to_keep = active_keys
                    .iter()
                    .max_by_key(|(_, info)| info.stale_at)
                    .map(|(k, _)| (*k).clone());

                // Remove it from the transition list
                to_transition.retain(|k| Some(k) != key_to_keep.as_ref());
            }

            // Perform transitions
            for key in &to_transition {
                if let Some(info) = self.keys.get_mut(key) {
                    info.status = KeyStatus::Stale;
                    transitioned += 1;
                }
            }
        }

        if transitioned > 0 {
            self.trigger_notify();
        }

        transitioned
    }

    /// Transition pending keys (actived_at <= now) to active status.
    ///
    /// Returns the number of keys transitioned.
    pub fn transition_pending_to_active(&mut self, now: SystemTime) -> usize {
        let keys_to_activate: Vec<PublicKeyData> = self
            .keys
            .iter()
            .filter(|(_, k)| k.status == KeyStatus::Pending && k.actived_at <= now)
            .map(|(pk, _)| pk.clone())
            .collect();

        let mut activated = 0;
        for public_key in keys_to_activate {
            if let Some(key) = self.keys.get_mut(&public_key) {
                key.status = KeyStatus::Active;
                activated += 1;
            }
        }

        if activated > 0 {
            self.trigger_notify();
        }

        activated
    }

    /// Try to generate a new pending key if none exists.
    ///
    /// Returns true if a new pending key was generated, false if already has pending key.
    /// The actived_at is set to max(stale_at of all active keys).
    pub fn generate_pending_key_if_none(&mut self) -> anyhow::Result<bool> {
        // Only generate if no pending key exists
        let has_pending = self.keys.values().any(|k| k.status == KeyStatus::Pending);
        if has_pending {
            return Ok(false);
        }

        // Calculate actived_at as max(stale_at of all active keys)
        let actived_at = self
            .keys
            .values()
            .filter(|k| k.status == KeyStatus::Active)
            .map(|k| k.stale_at)
            .max()
            .unwrap_or_else(SystemTime::now);

        // Generate new pending key
        let pending_key = KeyInfo::generate(
            0, // key_id will be assigned based on timestamp
            KeyStatus::Pending,
            actived_at,
            self.rotation_interval,
        )
        .map_err(|e| anyhow::anyhow!("Failed to generate pending key: {}", e))?;

        // Insert and trigger notification
        self.keys
            .insert(pending_key.key_config.public_key()?, pending_key);
        self.trigger_notify();

        Ok(true)
    }

    /// Compute the next deadline for key status transition.
    ///
    /// Returns the earliest future time when a key transition will occur,
    /// or None if no future transitions are scheduled.
    pub fn next_deadline(&self) -> Option<SystemTime> {
        let mut next_times = Vec::new();

        for key in self.keys.values() {
            match key.status {
                KeyStatus::Pending => {
                    next_times.push(key.actived_at);
                }
                KeyStatus::Active => {
                    next_times.push(key.stale_at);
                }
                KeyStatus::Stale => {
                    next_times.push(key.expire_at);
                }
            }
        }

        next_times.into_iter().min()
    }

    /// Merge another ClusterKeySet into this one.
    ///
    /// For each key in the other set, if it's newer or doesn't exist here, insert it.
    /// Keys are compared by public_key and actived_at.
    pub fn merge(&mut self, other: ClusterKeySet) {
        let mut merged = false;

        for (public_key, key_info) in other.keys {
            // If not exist, we insert it
            if !self.keys.contains_key(&public_key) {
                self.keys.insert(public_key, key_info);
                merged = true;
            }
        }

        if merged {
            self.trigger_notify();
        }
    }

    /// Insert a key received from peer query response.
    ///
    /// This is used when we query a specific key from the cluster and receive it.
    /// The key is inserted only if it doesn't already exist locally.
    /// Returns true if the key was inserted, false if it already existed.
    pub fn insert_key_from_peer(&mut self, public_key: PublicKeyData, key_info: KeyInfo) -> bool {
        // Only insert if not already present
        if self.keys.contains_key(&public_key) {
            return false;
        }

        self.keys.insert(public_key, key_info);
        self.trigger_notify();
        true
    }
}

impl TryFrom<super::cluster_key_set::ClusterKeySet> for super::serf_message::pb::ClusterKeySet {
    type Error = anyhow::Error;

    fn try_from(value: super::cluster_key_set::ClusterKeySet) -> Result<Self, Self::Error> {
        Ok(Self {
            keys: value
                .keys
                .into_values()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .context("failed to convert keys")?,
            rotation_interval: value.rotation_interval,
        })
    }
}

impl TryFrom<super::serf_message::pb::ClusterKeySet> for super::cluster_key_set::ClusterKeySet {
    type Error = anyhow::Error;

    fn try_from(value: super::serf_message::pb::ClusterKeySet) -> Result<Self, Self::Error> {
        let mut keys = HashMap::new();

        for key_info in value.keys {
            let key: KeyInfo = key_info.try_into().context("failed to convert key")?;
            // Decode base64 public key back to PublicKeyData
            let public_key = key
                .key_config
                .public_key()
                .context("failed to create PublicKeyData")?;
            keys.insert(public_key, key);
        }

        Ok(Self {
            keys,
            rotation_interval: value.rotation_interval,
            notify: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::egress::protocol::ohttp::security::key_manager::KeyStatus;

    fn create_test_key(key_id: u8, status: KeyStatus, actived_at_offset: u64) -> KeyInfo {
        let actived_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(actived_at_offset);
        KeyInfo::generate(key_id, status, actived_at, 300).unwrap()
    }

    #[test]
    fn test_insert_and_get_key() {
        let key = create_test_key(1, KeyStatus::Active, 1000);
        let public_key = key.key_config.public_key().unwrap();

        let mut cks = ClusterKeySet::new(public_key.clone(), key, 300);

        let key2 = create_test_key(2, KeyStatus::Active, 2000);
        cks.keys.insert(key2.key_config.public_key().unwrap(), key2);

        assert!(cks.get_key_by_public_key(&public_key).is_some());
        assert_eq!(cks.keys.len(), 2);
    }

    #[test]
    fn test_get_client_visible_key_single() {
        let key = create_test_key(1, KeyStatus::Active, 1000);
        let public_key = key.key_config.public_key().unwrap();

        let cks = ClusterKeySet::new(public_key.clone(), key, 300);

        let visible = cks.get_client_visible_key().unwrap();
        assert_eq!(visible.key_config.public_key().unwrap(), public_key);
    }

    #[test]
    fn test_remove_expired_keys() {
        let now = SystemTime::now();

        // Create an active key that is NOT expired (to maintain Vec1 invariant)
        let active_key = KeyInfo {
            key_config: ohttp::KeyConfig::new(
                1,
                ohttp::hpke::Kem::X25519Sha256,
                vec![ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                )],
            )
            .unwrap(),
            status: KeyStatus::Active,
            actived_at: now - std::time::Duration::from_secs(1000),
            stale_at: now + std::time::Duration::from_secs(500),
            expire_at: now + std::time::Duration::from_secs(1000),
        };

        let mut cks =
            ClusterKeySet::new(active_key.key_config.public_key().unwrap(), active_key, 300);

        // Create a pending key that is expired
        let expired_pending = KeyInfo {
            key_config: ohttp::KeyConfig::new(
                2,
                ohttp::hpke::Kem::X25519Sha256,
                vec![ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                )],
            )
            .unwrap(),
            status: KeyStatus::Pending,
            actived_at: now - std::time::Duration::from_secs(1000),
            stale_at: now - std::time::Duration::from_secs(500),
            expire_at: now - std::time::Duration::from_secs(1),
        };
        cks.keys.insert(
            expired_pending.key_config.public_key().unwrap(),
            expired_pending,
        );
        assert_eq!(cks.keys.len(), 2);

        let removed = cks.remove_expired_keys(now);
        assert_eq!(removed, 1);
        assert_eq!(cks.keys.len(), 1);
        // Active key still exists (not removed to maintain invariant)
        assert!(cks.get_client_visible_key().unwrap().status == KeyStatus::Active);
    }
}

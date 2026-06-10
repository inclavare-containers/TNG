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

    /// Check if the key set is empty.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Count the number of active keys.
    #[cfg(test)]
    pub fn active_key_count(&self) -> usize {
        self.keys
            .values()
            .filter(|k| k.status == KeyStatus::Active)
            .count()
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
            .next_back()
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
    pub fn generate_pending_key_if_none(&mut self) -> anyhow::Result<Option<PublicKeyData>> {
        // Only generate if no pending key exists
        let has_pending = self.keys.values().any(|k| k.status == KeyStatus::Pending);
        if has_pending {
            return Ok(None);
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
        let public_key = pending_key.key_config.public_key()?;
        self.keys.insert(public_key.clone(), pending_key);
        self.trigger_notify();

        Ok(Some(public_key))
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

    /// Check if all non-pending keys are stale-eligible (stale_at <= now).
    ///
    /// This detects the case where `transition_active_to_stale` preserved all active keys
    /// (because there were no other active keys to keep), but those preserved keys are
    /// actually past their stale_at. In this scenario, rotation must be triggered to
    /// generate a replacement pending key — otherwise the cluster stays with a stale
    /// active key forever (the bootstrap-created initial key skips the Pending→Active path,
    /// so `transition_pending_to_active` never fires for it).
    ///
    /// Returns true if there are no pending keys and all active/stale keys have stale_at <= now.
    pub fn should_trigger_rotation_for_stale_active(&self, now: SystemTime) -> bool {
        // Don't trigger if there's already a pending key in flight
        let has_pending = self.keys.values().any(|k| k.status == KeyStatus::Pending);
        if has_pending {
            return false;
        }

        // Check if all active and stale keys are stale-eligible
        let non_pending: Vec<&KeyInfo> = self
            .keys
            .values()
            .filter(|k| k.status != KeyStatus::Pending)
            .collect();

        if non_pending.is_empty() {
            return false;
        }

        non_pending
            .iter()
            .all(|k| k.status != KeyStatus::Active || k.stale_at <= now)
    }

    /// Check if there are multiple active keys without a pending replacement.
    ///
    /// This detects split-brain scenarios where two independently-bootstrapped nodes
    /// merge their key sets, resulting in 2+ active keys. The master node should
    /// generate a new pending key to drive convergence.
    ///
    /// Returns true if there are ≥2 active keys and no pending key exists.
    pub fn has_multiple_active_without_pending(&self) -> bool {
        let active_count = self
            .keys
            .values()
            .filter(|k| k.status == KeyStatus::Active)
            .count();
        let has_pending = self.keys.values().any(|k| k.status == KeyStatus::Pending);
        active_count >= 2 && !has_pending
    }

    /// Merge another ClusterKeySet into this one.
    ///
    /// For each key in the other set, insert it if it doesn't already exist locally.
    /// Existing keys are preserved (local wins on conflict).
    pub fn merge(&mut self, other: ClusterKeySet) {
        let mut merged = false;

        for (public_key, key_info) in other.keys {
            // Insert only if the key is not present locally
            if let std::collections::hash_map::Entry::Vacant(e) = self.keys.entry(public_key) {
                e.insert(key_info);
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

    #[test]
    fn test_get_client_visible_key_no_active_returns_error() {
        let key = create_test_key(1, KeyStatus::Active, 1000);
        let public_key = key.key_config.public_key().unwrap();

        let mut cks = ClusterKeySet::new(public_key.clone(), key, 300);

        // Transition the only active key to stale
        if let Some(k) = cks.keys.get_mut(&public_key) {
            k.status = KeyStatus::Stale;
        }

        // Should return NoActiveKey error
        assert!(matches!(
            cks.get_client_visible_key(),
            Err(TngError::NoActiveKey)
        ));
    }

    #[test]
    fn test_get_client_visible_key_multiple_active_tiebreaker() {
        // Create two active keys with different expire_at
        let now = SystemTime::now();

        let key1 = KeyInfo {
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
            stale_at: now - std::time::Duration::from_secs(500),
            expire_at: now + std::time::Duration::from_secs(100),
        };

        let key2 = KeyInfo {
            key_config: ohttp::KeyConfig::new(
                2,
                ohttp::hpke::Kem::X25519Sha256,
                vec![ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                )],
            )
            .unwrap(),
            status: KeyStatus::Active,
            actived_at: now - std::time::Duration::from_secs(500),
            stale_at: now + std::time::Duration::from_secs(500),
            expire_at: now + std::time::Duration::from_secs(200),
        };

        let pk1 = key1.key_config.public_key().unwrap();
        let pk2 = key2.key_config.public_key().unwrap();

        let mut cks = ClusterKeySet::new(pk1.clone(), key1, 300);
        cks.keys.insert(pk2.clone(), key2);

        // Should return key2 (later expire_at)
        let visible = cks.get_client_visible_key().unwrap();
        assert_eq!(visible.key_config.public_key().unwrap(), pk2);
    }

    #[test]
    fn test_get_client_visible_key_ignores_pending_and_stale() {
        let now = SystemTime::now();

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

        let pending_key = KeyInfo {
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
            actived_at: now + std::time::Duration::from_secs(100),
            stale_at: now + std::time::Duration::from_secs(400),
            expire_at: now + std::time::Duration::from_secs(700),
        };

        let stale_key = KeyInfo {
            key_config: ohttp::KeyConfig::new(
                3,
                ohttp::hpke::Kem::X25519Sha256,
                vec![ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                )],
            )
            .unwrap(),
            status: KeyStatus::Stale,
            actived_at: now - std::time::Duration::from_secs(1000),
            stale_at: now - std::time::Duration::from_secs(500),
            expire_at: now + std::time::Duration::from_secs(500),
        };

        let active_pk = active_key.key_config.public_key().unwrap();
        let mut cks = ClusterKeySet::new(active_pk.clone(), active_key, 300);
        cks.keys
            .insert(pending_key.key_config.public_key().unwrap(), pending_key);
        cks.keys
            .insert(stale_key.key_config.public_key().unwrap(), stale_key);

        // Should return the active key, not pending or stale
        let visible = cks.get_client_visible_key().unwrap();
        assert_eq!(visible.key_config.public_key().unwrap(), active_pk);
        assert_eq!(visible.status, KeyStatus::Active);
    }

    #[test]
    fn test_merge_disjoint_keys() {
        let key1 = create_test_key(1, KeyStatus::Active, 1000);
        let pk1 = key1.key_config.public_key().unwrap();
        let mut cks_a = ClusterKeySet::new(pk1.clone(), key1, 300);

        let key2 = create_test_key(2, KeyStatus::Active, 2000);
        let pk2 = key2.key_config.public_key().unwrap();
        let cks_b = ClusterKeySet::new(pk2, key2, 300);

        cks_a.merge(cks_b);

        // Both keys should be present
        assert_eq!(cks_a.keys.len(), 2);
        assert!(cks_a.get_key_by_public_key(&pk1).is_some());
        assert_eq!(
            cks_a.get_key_by_public_key(&pk1).unwrap().status,
            KeyStatus::Active
        );
    }

    #[test]
    fn test_merge_overlapping_keys_local_wins() {
        let now = SystemTime::now();

        // Create two keys with same public key (same underlying key pair) but different metadata
        let key1_old = KeyInfo {
            key_config: ohttp::KeyConfig::new(
                1,
                ohttp::hpke::Kem::X25519Sha256,
                vec![ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                )],
            )
            .unwrap(),
            status: KeyStatus::Stale,
            actived_at: now - std::time::Duration::from_secs(1000),
            stale_at: now - std::time::Duration::from_secs(500),
            expire_at: now + std::time::Duration::from_secs(100),
        };

        let key1_new = KeyInfo {
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
            actived_at: now - std::time::Duration::from_secs(500),
            stale_at: now + std::time::Duration::from_secs(500),
            expire_at: now + std::time::Duration::from_secs(1000),
        };

        let pk1 = key1_old.key_config.public_key().unwrap();

        // Local has stale version, remote has active version
        let mut cks_local = ClusterKeySet::new(pk1.clone(), key1_old, 300);
        let mut cks_remote = ClusterKeySet::new(pk1.clone(), key1_new, 300);

        // Add a second key to remote to verify it still gets merged
        let key2 = create_test_key(2, KeyStatus::Active, 2000);
        let pk2 = key2.key_config.public_key().unwrap();
        cks_remote.keys.insert(pk2.clone(), key2);

        cks_local.merge(cks_remote);

        // Local's stale version should be preserved (local wins on overlap)
        assert_eq!(
            cks_local.get_key_by_public_key(&pk1).unwrap().status,
            KeyStatus::Stale
        );
        // But the disjoint key2 from remote should be inserted
        assert!(cks_local.get_key_by_public_key(&pk2).is_some());
    }

    #[test]
    fn test_merge_empty_into_empty() {
        // Create an empty ClusterKeySet via deserialization simulation
        let mut cks_a = ClusterKeySet {
            keys: HashMap::new(),
            rotation_interval: 300,
            notify: None,
        };
        let cks_b = ClusterKeySet {
            keys: HashMap::new(),
            rotation_interval: 300,
            notify: None,
        };

        cks_a.merge(cks_b);
        assert!(cks_a.is_empty());
    }

    #[test]
    fn test_next_deadline_empty() {
        let cks = ClusterKeySet {
            keys: HashMap::new(),
            rotation_interval: 300,
            notify: None,
        };

        assert!(cks.next_deadline().is_none());
    }

    #[test]
    fn test_next_deadline_mixed_statuses() {
        let now = SystemTime::now();

        let pending_key = KeyInfo {
            key_config: ohttp::KeyConfig::new(
                1,
                ohttp::hpke::Kem::X25519Sha256,
                vec![ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                )],
            )
            .unwrap(),
            status: KeyStatus::Pending,
            actived_at: now + std::time::Duration::from_secs(100),
            stale_at: now + std::time::Duration::from_secs(400),
            expire_at: now + std::time::Duration::from_secs(700),
        };

        let active_key = KeyInfo {
            key_config: ohttp::KeyConfig::new(
                2,
                ohttp::hpke::Kem::X25519Sha256,
                vec![ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                )],
            )
            .unwrap(),
            status: KeyStatus::Active,
            actived_at: now - std::time::Duration::from_secs(1000),
            stale_at: now + std::time::Duration::from_secs(200),
            expire_at: now + std::time::Duration::from_secs(500),
        };

        let stale_key_info = KeyInfo {
            key_config: ohttp::KeyConfig::new(
                3,
                ohttp::hpke::Kem::X25519Sha256,
                vec![ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                )],
            )
            .unwrap(),
            status: KeyStatus::Stale,
            actived_at: now - std::time::Duration::from_secs(2000),
            stale_at: now - std::time::Duration::from_secs(1000),
            expire_at: now + std::time::Duration::from_secs(50),
        };

        let pending_pk = pending_key.key_config.public_key().unwrap();
        let active_pk = active_key.key_config.public_key().unwrap();
        let stale_pk = stale_key_info.key_config.public_key().unwrap();

        let mut cks = ClusterKeySet::new(pending_pk, pending_key, 300);
        cks.keys.insert(active_pk, active_key);
        cks.keys.insert(stale_pk, stale_key_info);

        // next_deadline should return the earliest of:
        // - pending: actived_at (now + 100s)
        // - active: stale_at (now + 200s)
        // - stale: expire_at (now + 50s)
        let deadline = cks.next_deadline().unwrap();
        assert_eq!(deadline.duration_since(now).unwrap().as_secs(), 50);
    }

    #[test]
    fn test_generate_pending_key_if_none_already_exists() {
        let key = create_test_key(1, KeyStatus::Active, 1000);
        let public_key = key.key_config.public_key().unwrap();

        let mut cks = ClusterKeySet::new(public_key.clone(), key, 300);

        // First call should generate a pending key
        let result = cks.generate_pending_key_if_none();
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
        assert_eq!(cks.keys.len(), 2);

        // Second call should return None (no new key generated)
        let result = cks.generate_pending_key_if_none();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(cks.keys.len(), 2);
    }

    #[test]
    fn test_generate_pending_key_no_active_keys() {
        // Create an empty ClusterKeySet
        let mut cks = ClusterKeySet {
            keys: HashMap::new(),
            rotation_interval: 300,
            notify: None,
        };

        // Should still generate a pending key (actived_at defaults to SystemTime::now)
        let result = cks.generate_pending_key_if_none();
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
        assert_eq!(cks.keys.len(), 1);

        // The generated key should be Pending
        let generated = cks.keys.values().next().unwrap();
        assert_eq!(generated.status, KeyStatus::Pending);
    }

    #[test]
    fn test_transition_active_to_stale_preserves_last_active() {
        let now = SystemTime::now();

        // Create a single active key whose stale_at is in the past
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
            stale_at: now - std::time::Duration::from_secs(1),
            expire_at: now + std::time::Duration::from_secs(1000),
        };

        let pk = active_key.key_config.public_key().unwrap();
        let mut cks = ClusterKeySet::new(pk.clone(), active_key, 300);

        // Should NOT transition the only active key to stale
        let transitioned = cks.transition_active_to_stale(now);
        assert_eq!(transitioned, 0);
        assert!(cks.get_key_by_public_key(&pk).unwrap().status == KeyStatus::Active);
        assert_eq!(cks.active_key_count(), 1);
    }

    #[test]
    fn test_transition_active_to_stale_with_multiple_active() {
        let now = SystemTime::now();

        let key1 = KeyInfo {
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
            actived_at: now - std::time::Duration::from_secs(2000),
            stale_at: now - std::time::Duration::from_secs(100),
            expire_at: now + std::time::Duration::from_secs(1000),
        };

        let key2 = KeyInfo {
            key_config: ohttp::KeyConfig::new(
                2,
                ohttp::hpke::Kem::X25519Sha256,
                vec![ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                )],
            )
            .unwrap(),
            status: KeyStatus::Active,
            actived_at: now - std::time::Duration::from_secs(1000),
            stale_at: now - std::time::Duration::from_secs(50),
            expire_at: now + std::time::Duration::from_secs(1000),
        };

        let key3 = KeyInfo {
            key_config: ohttp::KeyConfig::new(
                3,
                ohttp::hpke::Kem::X25519Sha256,
                vec![ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                )],
            )
            .unwrap(),
            status: KeyStatus::Active,
            actived_at: now,
            stale_at: now + std::time::Duration::from_secs(300),
            expire_at: now + std::time::Duration::from_secs(600),
        };

        let pk1 = key1.key_config.public_key().unwrap();
        let pk2 = key2.key_config.public_key().unwrap();
        let pk3 = key3.key_config.public_key().unwrap();

        let mut cks = ClusterKeySet::new(pk1.clone(), key1, 300);
        cks.keys.insert(pk2.clone(), key2);
        cks.keys.insert(pk3.clone(), key3);

        // key1 and key2 should transition to stale, key3 should remain active
        let transitioned = cks.transition_active_to_stale(now);
        assert_eq!(transitioned, 2);
        assert!(cks.get_key_by_public_key(&pk1).unwrap().status == KeyStatus::Stale);
        assert!(cks.get_key_by_public_key(&pk2).unwrap().status == KeyStatus::Stale);
        assert!(cks.get_key_by_public_key(&pk3).unwrap().status == KeyStatus::Active);
        assert_eq!(cks.active_key_count(), 1);
    }

    #[test]
    fn test_transition_pending_to_active_boundary() {
        let now = SystemTime::now();

        let pending_key_at_boundary = KeyInfo {
            key_config: ohttp::KeyConfig::new(
                1,
                ohttp::hpke::Kem::X25519Sha256,
                vec![ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                )],
            )
            .unwrap(),
            status: KeyStatus::Pending,
            actived_at: now,
            stale_at: now + std::time::Duration::from_secs(300),
            expire_at: now + std::time::Duration::from_secs(600),
        };

        let pending_key_future = KeyInfo {
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
            actived_at: now + std::time::Duration::from_secs(100),
            stale_at: now + std::time::Duration::from_secs(400),
            expire_at: now + std::time::Duration::from_secs(700),
        };

        let active_key = KeyInfo {
            key_config: ohttp::KeyConfig::new(
                3,
                ohttp::hpke::Kem::X25519Sha256,
                vec![ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                )],
            )
            .unwrap(),
            status: KeyStatus::Active,
            actived_at: now - std::time::Duration::from_secs(1000),
            stale_at: now + std::time::Duration::from_secs(1000),
            expire_at: now + std::time::Duration::from_secs(2000),
        };

        let pending_pk1 = pending_key_at_boundary.key_config.public_key().unwrap();
        let pending_pk2 = pending_key_future.key_config.public_key().unwrap();
        let active_pk = active_key.key_config.public_key().unwrap();

        let mut cks = ClusterKeySet::new(pending_pk1.clone(), pending_key_at_boundary, 300);
        cks.keys.insert(pending_pk2.clone(), pending_key_future);
        cks.keys.insert(active_pk.clone(), active_key);

        // Only the boundary pending key should activate
        let activated = cks.transition_pending_to_active(now);
        assert_eq!(activated, 1);
        assert!(cks.get_key_by_public_key(&pending_pk1).unwrap().status == KeyStatus::Active);
        assert!(cks.get_key_by_public_key(&pending_pk2).unwrap().status == KeyStatus::Pending);
        assert!(cks.get_key_by_public_key(&active_pk).unwrap().status == KeyStatus::Active);
    }

    #[test]
    fn test_remove_expired_keys_all_active_expired_preserves_latest_stale() {
        let now = SystemTime::now();

        let key1 = KeyInfo {
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
            actived_at: now - std::time::Duration::from_secs(2000),
            stale_at: now - std::time::Duration::from_secs(1000),
            expire_at: now - std::time::Duration::from_secs(1),
        };

        let key2 = KeyInfo {
            key_config: ohttp::KeyConfig::new(
                2,
                ohttp::hpke::Kem::X25519Sha256,
                vec![ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                )],
            )
            .unwrap(),
            status: KeyStatus::Active,
            actived_at: now - std::time::Duration::from_secs(1000),
            stale_at: now - std::time::Duration::from_secs(500),
            expire_at: now - std::time::Duration::from_secs(1),
        };

        let pk1 = key1.key_config.public_key().unwrap();
        let pk2 = key2.key_config.public_key().unwrap();

        let mut cks = ClusterKeySet::new(pk1.clone(), key1, 300);
        cks.keys.insert(pk2.clone(), key2);

        // All active keys are expired. Should preserve the one with latest stale_at (key2)
        let removed = cks.remove_expired_keys(now);
        assert_eq!(removed, 1);
        assert_eq!(cks.keys.len(), 1);
        // key2 should be preserved (later stale_at)
        assert!(cks.get_key_by_public_key(&pk2).is_some());
        assert!(cks.get_key_by_public_key(&pk1).is_none());
    }

    #[test]
    fn test_insert_key_from_peer() {
        let key = create_test_key(1, KeyStatus::Active, 1000);
        let public_key = key.key_config.public_key().unwrap();

        let mut cks = ClusterKeySet::new(public_key.clone(), key, 300);

        // Insert a new key
        let new_key = create_test_key(2, KeyStatus::Active, 2000);
        let new_pk = new_key.key_config.public_key().unwrap();
        let inserted = cks.insert_key_from_peer(new_pk.clone(), new_key.clone());
        assert!(inserted);
        assert_eq!(cks.keys.len(), 2);

        // Insert duplicate should return false
        let inserted = cks.insert_key_from_peer(new_pk, new_key);
        assert!(!inserted);
        assert_eq!(cks.keys.len(), 2);
    }
}

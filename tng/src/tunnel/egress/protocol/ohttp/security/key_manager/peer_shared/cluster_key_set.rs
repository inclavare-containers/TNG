use crate::tunnel::egress::protocol::ohttp::security::key_manager::{KeyInfo, KeyStatus};
use crate::tunnel::ohttp::key_config::{KeyConfigExtend, PublicKeyData};
use std::time::SystemTime;
use vec1::Vec1;

/// Cluster key set containing all keys in different states.
///
/// This structure maintains the complete set of keys for the cluster,
/// organized into pending, active, and stale queues.
///
/// According to serf-v2 protocol, the active queue must contain at least one key
/// during normal operation. We use Vec1 to enforce this constraint at the type level.
#[derive(Debug, Clone)]
pub struct ClusterKeySet {
    /// Keys waiting to be activated
    pub pending: Vec<KeyInfo>,
    /// Currently active keys (at least one must exist during normal operation)
    pub active: Vec1<KeyInfo>,
    /// Expired keys kept for decrypting existing connections
    pub stale: Vec<KeyInfo>,
    /// Rotation interval in seconds
    pub rotation_interval: u64,
}

impl ClusterKeySet {
    /// Create a new ClusterKeySet with an initial active key.
    ///
    /// According to serf-v2 protocol, there must be at least one active key.
    /// This constructor is used during Bootstrap when the first active key is created.
    pub fn new(active_key: KeyInfo, rotation_interval: u64) -> Self {
        Self {
            pending: Vec::new(),
            active: Vec1::new(active_key),
            stale: Vec::new(),
            rotation_interval,
        }
    }

    /// Insert or update a key in the appropriate queue based on its status.
    ///
    /// If a key with the same public_key_data already exists, it will be replaced.
    pub fn insert_key(&mut self, key_info: KeyInfo) {
        // Remove existing key with same public_key_data from all queues
        if let Ok(public_key_data) = key_info.key_config.public_key_data() {
            self.remove_by_public_key(&public_key_data);
        }

        // Insert into appropriate queue
        match key_info.status {
            KeyStatus::Pending => self.pending.push(key_info),
            KeyStatus::Active => {
                // Add to active queue
                self.active.push(key_info);
            }
            KeyStatus::Stale => self.stale.push(key_info),
        }
    }

    /// Remove a key by its public_key_data from all queues.
    ///
    /// Note: This method does not remove from active queue to ensure
    /// at least one active key always exists (enforced by Vec1).
    fn remove_by_public_key(&mut self, public_key_data: &PublicKeyData) {
        self.pending.retain(|k| {
            k.key_config
                .public_key_data()
                .map(|pk| &pk != public_key_data)
                .unwrap_or(true)
        });
        // Note: We don't remove from active queue to maintain Vec1 invariant.
        // Active keys are only removed when they expire and are moved to stale.
        self.stale.retain(|k| {
            k.key_config
                .public_key_data()
                .map(|pk| &pk != public_key_data)
                .unwrap_or(true)
        });
    }

    /// Find a key by its public_key_data across all queues.
    pub fn get_key_by_public_key(&self, public_key_data: &PublicKeyData) -> Option<&KeyInfo> {
        self.pending
            .iter()
            .chain(self.active.iter())
            .chain(self.stale.iter())
            .find(|k| {
                k.key_config
                    .public_key_data()
                    .map(|pk| &pk == public_key_data)
                    .unwrap_or(false)
            })
    }

    /// Get the key that should be returned to clients.
    ///
    /// According to serf-v2 protocol:
    /// - If only one active key exists, return it
    /// - If multiple active keys exist, return the one with latest stale_at
    ///   (if stale_at is equal, the order is deterministic but arbitrary)
    pub fn get_client_visible_key(&self) -> &KeyInfo {
        if self.active.len() == 1 {
            return self.active.first();
        }

        // Multiple active keys: return the one with latest stale_at
        self.active
            .iter()
            .min_by(|a, b| {
                // Compare by stale_at (descending - later is better)
                b.stale_at.cmp(&a.stale_at)
            })
            .expect("Vec1 always has at least one element")
    }

    /// Remove all expired keys (where expire_at <= now).
    ///
    /// Returns the number of keys removed.
    /// Note: Expired active keys are moved to stale, not removed, to maintain Vec1 invariant.
    pub fn remove_expired_keys(&mut self, now: SystemTime) -> usize {
        let pending_before = self.pending.len();
        let stale_before = self.stale.len();

        self.pending.retain(|k| k.expire_at > now);

        // Move expired active keys to stale instead of removing them
        let expired_active: Vec<KeyInfo> = self
            .active
            .iter()
            .filter(|k| k.expire_at <= now)
            .cloned()
            .collect();

        for key in expired_active {
            let mut stale_key = key;
            stale_key.status = KeyStatus::Stale;
            self.stale.push(stale_key);
        }

        // Remove expired from active (Vec1::retain may fail if all are removed,
        // but protocol ensures at least one active key exists at all times)
        let _ = self.active.retain(|k| k.expire_at > now);

        self.stale.retain(|k| k.expire_at > now);

        (pending_before - self.pending.len()) + (stale_before - self.stale.len())
    }

    /// Find pending keys that should be activated (actived_at <= now).
    pub fn find_keys_to_activate(&self, now: SystemTime) -> Vec<&KeyInfo> {
        self.pending
            .iter()
            .filter(|k| k.actived_at <= now)
            .collect()
    }

    /// Find active keys that should be marked as stale (stale_at <= now).
    pub fn find_keys_to_stale(&self, now: SystemTime) -> Vec<&KeyInfo> {
        self.active.iter().filter(|k| k.stale_at <= now).collect()
    }

    /// Check if there is at least one active key.
    /// Always returns true due to Vec1 invariant.
    pub fn has_active_key(&self) -> bool {
        true
    }

    /// Check if there is any pending key.
    pub fn has_pending_key(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Get the maximum stale_at time among all active keys.
    pub fn max_active_stale_at(&self) -> Option<SystemTime> {
        self.active.iter().map(|k| k.stale_at).max()
    }

    /// Merge another ClusterKeySet into this one.
    ///
    /// For each key in the other set, if it's newer or doesn't exist here, insert it.
    /// Keys are compared by public_key_data and actived_at.
    pub fn merge(&mut self, other: &ClusterKeySet) {
        // Merge pending keys
        for key in &other.pending {
            if self.should_insert_key(key) {
                self.insert_key(key.clone());
            }
        }

        // Merge active keys
        for key in other.active.iter() {
            if self.should_insert_key(key) {
                self.insert_key(key.clone());
            }
        }

        // Merge stale keys
        for key in &other.stale {
            if self.should_insert_key(key) {
                self.insert_key(key.clone());
            }
        }
    }

    /// Check if a key should be inserted (doesn't exist or is newer).
    fn should_insert_key(&self, key: &KeyInfo) -> bool {
        let key_public_key = match key.key_config.public_key_data() {
            Ok(pk) => pk,
            Err(_) => return true, // If we can't get public key, insert anyway
        };

        match self.get_key_by_public_key(&key_public_key) {
            None => true,
            Some(existing) => key.actived_at > existing.actived_at,
        }
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
        let public_key = key.key_config.public_key_data().unwrap();

        let mut cks = ClusterKeySet::new(key, 300);

        let key2 = create_test_key(2, KeyStatus::Active, 2000);
        cks.insert_key(key2.clone());

        assert!(cks.get_key_by_public_key(&public_key).is_some());
        assert_eq!(cks.active.len(), 2);
    }

    #[test]
    fn test_get_client_visible_key_single() {
        let key = create_test_key(1, KeyStatus::Active, 1000);
        let public_key = key.key_config.public_key_data().unwrap();

        let cks = ClusterKeySet::new(key, 300);

        let visible = cks.get_client_visible_key();
        assert_eq!(visible.key_config.public_key_data().unwrap(), public_key);
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

        let mut cks = ClusterKeySet::new(active_key, 300);

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
        cks.insert_key(expired_pending);
        assert_eq!(cks.pending.len(), 1);

        let removed = cks.remove_expired_keys(now);
        assert_eq!(removed, 1);
        assert!(cks.pending.is_empty());
        // Active key still exists (not removed to maintain Vec1 invariant)
        assert_eq!(cks.active.len(), 1);
    }
}

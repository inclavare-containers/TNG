use crate::tunnel::egress::protocol::ohttp::security::key_manager::{KeyInfo, KeyStatus};
use crate::tunnel::ohttp::key_config::{KeyConfigExtend, PublicKeyData};
use anyhow::Context as _;
use std::sync::Arc;
use std::time::SystemTime;
use vec1::Vec1;

/// Cluster key set containing all keys in different states.
///
/// This structure maintains the complete set of keys for the cluster,
/// organized into pending, active, and stale queues.
///
/// The active queue must contain at least one key
/// during normal operation. We use Vec1 to enforce this constraint at the type level.
#[derive(Debug, Clone)]
pub struct ClusterKeySet {
    /// Keys waiting to be activated
    pending: Vec<KeyInfo>,
    /// Currently active keys (at least one must exist during normal operation)
    active: Vec1<KeyInfo>,
    /// Expired keys kept for decrypting existing connections
    stale: Vec<KeyInfo>,
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
    pub fn new(active_key: KeyInfo, rotation_interval: u64) -> Self {
        Self {
            pending: Vec::new(),
            active: Vec1::new(active_key),
            stale: Vec::new(),
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

    /// Insert or update a key in the appropriate queue based on its status.
    ///
    /// If a key with the same public_key_data already exists, it will be replaced.
    fn insert_key(&mut self, key_info: KeyInfo) {
        // Remove existing key with same public_key_data from all queues
        if let Ok(public_key_data) = key_info.key_config.public_key_data() {
            self.remove_by_public_key(&public_key_data);
        }

        // Insert into appropriate queue
        match key_info.status {
            KeyStatus::Pending => self.pending.push(key_info),
            KeyStatus::Active => self.active.push(key_info),
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
    /// Returns the number of keys removed from all queues.
    pub fn remove_expired_keys(&mut self, now: SystemTime) -> usize {
        let pending_before = self.pending.len();
        let active_before = self.active.len();
        let stale_before = self.stale.len();

        // Remove expired keys from all queues
        self.pending.retain(|k| k.expire_at > now);
        let _ = self.active.retain(|k| k.expire_at > now); // The Vec1::retain may failed but it will remain at least one active key in the queue.
        self.stale.retain(|k| k.expire_at > now);

        let removed = (pending_before - self.pending.len())
            + (active_before - self.active.len())
            + (stale_before - self.stale.len());

        if removed > 0 {
            self.trigger_notify();
        }

        removed
    }

    /// Transition expired active keys (stale_at <= now) to stale status.
    ///
    /// Only transitions keys if there are other active keys remaining (at least one required).
    /// Returns the number of keys transitioned.
    /// TODO: Optimize this
    pub fn transition_expired_active_to_stale(&mut self, now: SystemTime) -> usize {
        // Collect public keys of expired active keys
        let expired_keys: Vec<(KeyInfo, Vec<u8>)> = self
            .active
            .iter()
            .filter(|k| k.stale_at <= now)
            .filter_map(|k| {
                k.key_config
                    .public_key_data()
                    .ok()
                    .map(|pk| (k.clone(), pk.as_ref().to_vec()))
            })
            .collect();

        let mut transitioned = 0;
        for (key, public_key_data) in expired_keys {
            if self.active.len() > 1 {
                // Remove from active by public key data
                let _ = self.active.retain(|k| {
                    k.key_config
                        .public_key_data()
                        .map(|pk| pk.as_ref() != public_key_data)
                        .unwrap_or(true)
                });

                // Insert into stale
                let mut staled = key;
                staled.status = KeyStatus::Stale;
                self.stale.push(staled);
                transitioned += 1;
            }
            // Otherwise: retain as active (at least one active key required)
        }

        if transitioned > 0 {
            self.trigger_notify();
        }

        transitioned
    }

    /// Transition pending keys (actived_at <= now) to active status.
    ///
    /// Returns the number of keys transitioned.
    /// TODO: Optimize this
    pub fn transition_pending_to_active(&mut self, now: SystemTime) -> usize {
        let keys_to_activate: Vec<KeyInfo> = self
            .pending
            .iter()
            .filter(|k| k.actived_at <= now)
            .cloned()
            .collect();

        let mut activated = 0;
        for key in keys_to_activate {
            // Activate the pending key
            let mut activated_key = key;
            activated_key.status = KeyStatus::Active;
            self.insert_key(activated_key);
            activated += 1;
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
    pub fn try_generate_pending_key(&mut self) -> anyhow::Result<bool> {
        // Only generate if no pending key exists
        if !self.pending.is_empty() {
            return Ok(false);
        }

        // Calculate actived_at as max(stale_at of all active keys)
        let actived_at = {
            let this = &self;
            this.active
                .iter()
                .map(|k| k.stale_at)
                .max()
                .unwrap_or_else(|| this.active.first().stale_at)
        };

        // Generate new pending key
        let pending_key = KeyInfo::generate(
            0, // key_id will be assigned based on timestamp
            KeyStatus::Pending,
            actived_at,
            self.rotation_interval,
        )
        .map_err(|e| anyhow::anyhow!("Failed to generate pending key: {}", e))?;

        // Insert and trigger notification
        self.insert_key(pending_key);
        self.trigger_notify();

        Ok(true)
    }

    /// Compute the next deadline for key status transition.
    ///
    /// Returns the earliest future time when a key transition will occur,
    /// or None if no future transitions are scheduled.
    pub fn next_deadline(&self, now: SystemTime) -> Option<SystemTime> {
        let mut next_times = Vec::new();

        // Pending keys' actived_at
        for key in &self.pending {
            if key.actived_at > now {
                next_times.push(key.actived_at);
            }
        }

        // Active keys' stale_at
        for key in self.active.iter() {
            if key.stale_at > now {
                next_times.push(key.stale_at);
            }
        }

        // Stale keys' expire_at
        for key in &self.stale {
            if key.expire_at > now {
                next_times.push(key.expire_at);
            }
        }

        next_times.into_iter().min()
    }

    /// Merge another ClusterKeySet into this one.
    ///
    /// For each key in the other set, if it's newer or doesn't exist here, insert it.
    /// Keys are compared by public_key_data and actived_at.
    pub fn merge(&mut self, other: &ClusterKeySet) {
        let mut merged = false;

        // Merge pending keys
        for key in &other.pending {
            if self.should_insert_key(key) {
                self.insert_key(key.clone());
                merged = true;
            }
        }

        // Merge active keys
        for key in other.active.iter() {
            if self.should_insert_key(key) {
                self.insert_key(key.clone());
                merged = true;
            }
        }

        // Merge stale keys
        for key in &other.stale {
            if self.should_insert_key(key) {
                self.insert_key(key.clone());
                merged = true;
            }
        }

        if merged {
            self.trigger_notify();
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

impl TryFrom<super::cluster_key_set::ClusterKeySet> for super::serf_message::pb::ClusterKeySet {
    type Error = anyhow::Error;

    fn try_from(value: super::cluster_key_set::ClusterKeySet) -> Result<Self, Self::Error> {
        Ok(Self {
            pending: value
                .pending
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .context("failed to convert pending keys")?,
            active: value
                .active
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .context("failed to convert active keys")?,
            stale: value
                .stale
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .context("failed to convert stale keys")?,
            rotation_interval: value.rotation_interval,
        })
    }
}

impl TryFrom<super::serf_message::pb::ClusterKeySet> for super::cluster_key_set::ClusterKeySet {
    type Error = anyhow::Error;

    fn try_from(value: super::serf_message::pb::ClusterKeySet) -> Result<Self, Self::Error> {
        let pending: Vec<KeyInfo> = value
            .pending
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .context("failed to convert pending keys")?;

        let active_keys: Vec<KeyInfo> = value
            .active
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .context("failed to convert active keys")?;

        // ClusterKeySet requires at least one active key
        let active = Vec1::try_from(active_keys)
            .map_err(|_| anyhow::anyhow!("ClusterKeySet must have at least one active key"))?;

        let stale: Vec<KeyInfo> = value
            .stale
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .context("failed to convert stale keys")?;

        Ok(Self {
            pending,
            active,
            stale,
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

//! Process-shared caches for transparency-log authentication.
//!
//! Both caches store verified successes only. A failed resolve or a revoked
//! measurement is retried on the next appraisal; caching it would keep a stale
//! failure (or a stale revocation) alive until eviction.

use std::sync::Arc;

use anyhow::{Context, Result};
use moka::future::Cache;
use once_cell::sync::Lazy;

use super::rekor_v1::AuthenticatedRekorEntry;

/// A cached artifact-server success must expire so a revocation becomes
/// visible even without a capacity eviction or a process restart.
const RESOLVE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// The manifest sha256 as raw bytes. Constructing it validates the digest
/// length, so a malformed digest cannot enter a cache key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ManifestDigest([u8; 32]);

impl ManifestDigest {
    pub(crate) fn new(hex_digest: &str) -> Result<Self> {
        let bytes = hex::decode(hex_digest).context("hex-decode manifest digest")?;
        let digest: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("manifest digest must be 32 bytes, got {}", bytes.len())
        })?;
        Ok(Self(digest))
    }
}

/// The log-services list in stable (RFC 8785 JCS) canonical form. Two
/// semantically-equal lists produce the same key component.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CanonicalLogServices(String);

impl CanonicalLogServices {
    pub(crate) fn new(log_services_json: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(log_services_json)
            .context("parse log services for the resolve cache key")?;
        Ok(Self(super::dsse::canonical_json(&value)?))
    }
}

/// The identity of the publisher key a resolve was performed under: the
/// sha256 of the effective configured-or-built-in PEM. A resolve success is
/// only reusable under the same publisher key, so two policies that differ
/// only in `publisherPublicKeyPem` cannot share a cached success.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PublisherKeyId(String);

impl PublisherKeyId {
    pub(crate) fn new(configured_pem: Option<&str>) -> Self {
        use sha2::Digest as _;

        let mut hasher = sha2::Sha256::new();
        hasher.update(super::dsse::effective_publisher_pem(configured_pem).as_bytes());
        Self(hex::encode(hasher.finalize()))
    }
}

/// The key of one artifact-server resolve: the server, the manifest, the
/// requested log services, and the publisher key all participate, so a cached
/// success is only reused for the identical trust configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ResolveCacheKey {
    pub(crate) artifact_server_url: String,
    pub(crate) manifest_digest: ManifestDigest,
    pub(crate) log_services: CanonicalLogServices,
    pub(crate) publisher_key: PublisherKeyId,
}

/// The marker stored for a verified resolve. The value carries no data: the
/// appraisal only needs to know the resolve succeeded.
#[derive(Debug, Clone)]
pub(crate) struct ResolveCacheValue(());

impl ResolveCacheValue {
    pub(crate) fn verified() -> Self {
        Self(())
    }
}

/// The key of one on-demand rekor fetch. The entry is authenticated against a
/// trusted built-in key before it is cached, and the lookup is only used by
/// the on-demand fallback (which has no explicit rekor key), so the key
/// identity does not need to participate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RekorCacheKey {
    pub(crate) log_url: String,
    pub(crate) log_index: i64,
}

/// Owns both transparency-log caches. A converter either shares the process
/// default or injects its own instance, which is what tests do to keep
/// evaluations independent.
pub struct TransparencyCaches {
    resolve: Cache<ResolveCacheKey, ResolveCacheValue>,
    rekor: Cache<RekorCacheKey, AuthenticatedRekorEntry>,
}

impl TransparencyCaches {
    pub fn new() -> Self {
        // Capacity 1024 covers the small set of manifests one builtin-AS
        // instance appraises; 64 covers the handful of rekor entries a policy
        // falls back to.
        let resolve = Cache::builder()
            .max_capacity(1024)
            .time_to_live(RESOLVE_CACHE_TTL)
            .build();
        let rekor = Cache::builder().max_capacity(64).build();
        Self { resolve, rekor }
    }

    /// The process-wide default instance. Converters created with
    /// `BuiltinCocoConverter::new` share this, preserving the cross-instance
    /// cache sharing the host-await statics used to provide.
    pub(crate) fn shared() -> Arc<Self> {
        static SHARED: Lazy<Arc<TransparencyCaches>> =
            Lazy::new(|| Arc::new(TransparencyCaches::new()));
        SHARED.clone()
    }

    pub(crate) async fn resolve_hit(&self, key: &ResolveCacheKey) -> bool {
        self.resolve.get(key).await.is_some()
    }

    pub(crate) async fn insert_resolve(&self, key: ResolveCacheKey) {
        self.resolve
            .insert(key, ResolveCacheValue::verified())
            .await;
    }

    pub(crate) async fn rekor_entry(&self, key: &RekorCacheKey) -> Option<AuthenticatedRekorEntry> {
        self.rekor.get(key).await
    }

    pub(crate) async fn insert_rekor(&self, key: RekorCacheKey, entry: AuthenticatedRekorEntry) {
        self.rekor.insert(key, entry).await;
    }

    /// Mark every entry invalid. `moka` evicts lazily, which is enough for
    /// tests that force the network path.
    pub(crate) fn invalidate_all(&self) {
        self.resolve.invalidate_all();
        self.rekor.invalidate_all();
    }
}

impl Default for TransparencyCaches {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_digest_rejects_wrong_length() {
        assert!(ManifestDigest::new(&hex::encode([0u8; 32])).is_ok());
        let err = ManifestDigest::new("deadbeef").unwrap_err();
        assert!(err.to_string().contains("32 bytes"), "{err}");
        assert!(ManifestDigest::new("not-hex").is_err());
    }

    #[test]
    fn canonical_log_services_normalizes_order_and_whitespace() {
        let a = CanonicalLogServices::new(
            r#"[{"type":"rekor-v1","url":"https://r"},{"type":"rekor-v1","url":"https://s"}]"#,
        )
        .unwrap();
        let b = CanonicalLogServices::new(
            r#"[ {"url": "https://r", "type": "rekor-v1"}, {"url":"https://s","type":"rekor-v1"} ]"#,
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn publisher_key_id_uses_the_effective_key() {
        let builtin = PublisherKeyId::new(None);
        assert_eq!(builtin, PublisherKeyId::new(Some("")));
        assert_eq!(
            builtin,
            PublisherKeyId::new(Some(super::super::dsse::BUILTIN_LOG_ENTRY_PUB_KEY_PEM))
        );
        assert_ne!(builtin, PublisherKeyId::new(Some("another key")));
    }

    #[tokio::test]
    async fn resolve_cache_stores_only_inserted_keys() {
        let caches = TransparencyCaches::new();
        let key = ResolveCacheKey {
            artifact_server_url: "https://as".to_string(),
            manifest_digest: ManifestDigest::new(&hex::encode([1u8; 32])).unwrap(),
            log_services: CanonicalLogServices::new("[]").unwrap(),
            publisher_key: PublisherKeyId::new(None),
        };
        assert!(!caches.resolve_hit(&key).await);
        caches.insert_resolve(key.clone()).await;
        assert!(caches.resolve_hit(&key).await);
    }
}

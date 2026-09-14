//! Fast-path cache for the rats-tls certificate verification verdict.
//!
//! This module lives under `utils::rustls`, which is `#[cfg(not(wasm))]`: only the
//! native rustls cert-verify path (`verify_cert`) consults this cache, and wasm (which
//! only does ohttp and never runs the rustls RA verify path) is not pulled in at all.
//!
//! On the default attester config the peer reuses the same cert + evidence for a 600 s
//! refresh window (`MaybeCached::Periodically`), so frequent handshakes re-verify an
//! identical cert. This cache stores the successful `AttestationResult` keyed on
//! `SHA256(cert DER)` and short-circuits the full RA appraisal on a hit.
//!
//! Soundness: the verdict is a deterministic function of (cert DER, trust anchors,
//! policy), and the trust anchors / policy are immutable for the `VerifyContext`'s
//! lifetime, so a cached verdict stays valid for the TTL. Only successful verdicts are
//! cached; errors are never cached, so a miss always falls through to the full verify.

use std::time::Duration;

use moka::future::Cache;
use sha2::{Digest, Sha256};

use crate::tunnel::attestation_result::AttestationResult;

/// How long a cached verdict stays valid. Well inside the attester's 600 s cert-reuse
/// window; bounds staleness if a trust anchor or policy were ever rotated (which, today,
/// only happens by rebuilding the `VerifyContext`).
const CERT_VERIFY_CACHE_TTL: Duration = Duration::from_secs(60);

/// Upper bound on distinct cached certs. Each entry is one `AttestationResult` (an `Arc`
/// to a JWT string), so memory is bounded by this times a small constant.
const CERT_VERIFY_CACHE_MAX_ENTRIES: u64 = 1024;

/// A cache of successful cert-verification verdicts, held by the rustls cert verifier
/// (one per rustls config), so it is shared across all connections using that config.
#[derive(Debug, Clone)]
pub struct CertVerifyCache {
    inner: Cache<[u8; 32], AttestationResult>,
}

impl CertVerifyCache {
    /// Build a cache with the default TTL (60 s) and capacity (1024).
    pub fn default_sized() -> Self {
        let inner = Cache::builder()
            .time_to_live(CERT_VERIFY_CACHE_TTL)
            .max_capacity(CERT_VERIFY_CACHE_MAX_ENTRIES)
            .build();
        Self { inner }
    }

    /// Return a cached verdict for this cert hash if it is still valid.
    pub async fn get(&self, key: &[u8; 32]) -> Option<AttestationResult> {
        self.inner.get(key).await
    }

    /// Store a successful verdict. Only call this after verification succeeded.
    pub async fn insert(&self, key: [u8; 32], val: AttestationResult) {
        self.inner.insert(key, val).await;
    }
}

/// SHA-256 of the raw DER end-entity certificate, used as the cache key.
/// The cert embeds the DICE evidence extension and the SPKI whose hash is the binding
/// claim, so identical bytes imply an identical, deterministic verdict.
pub fn cert_hash(cert_der: &[u8]) -> [u8; 32] {
    Sha256::digest(cert_der).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result() -> AttestationResult {
        // CocoAsToken::new wraps a string without validating it; the cache never inspects
        // the token, so a placeholder keeps the test hermetic and dependency-free.
        use crate::tunnel::provider::TngToken;
        let token = TngToken::from(
            rats_cert::tee::coco::evidence::CocoAsToken::new("dummy.jwt".to_string())
                .expect("CocoAsToken::new never errors"),
        );
        AttestationResult::from_token(token)
    }

    #[tokio::test]
    async fn cache_hit_after_insert() {
        let cache = CertVerifyCache::default_sized();
        let key = [1u8; 32];
        let val = make_result();
        cache.insert(key, val).await;
        assert!(
            cache.get(&key).await.is_some(),
            "expected a cache hit after insert"
        );
    }

    #[tokio::test]
    async fn cache_miss_on_unknown_key() {
        let cache = CertVerifyCache::default_sized();
        assert!(
            cache.get(&[9u8; 32]).await.is_none(),
            "expected a miss on an unknown key"
        );
    }

    #[tokio::test]
    async fn cert_hash_is_stable() {
        let a = cert_hash(b"hello world");
        assert_eq!(a, cert_hash(b"hello world"));
        assert_ne!(a, cert_hash(b"hello worl!"));
    }
}

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rats_cert::cert::verify::CertVerifier;
use rats_cert::tee::GenericConverter;
use rats_cert::tee::GenericEvidence;
use rats_cert::tee::GenericVerifier;

use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::provider::{TngEvidence, TngToken};
use crate::tunnel::ra_context::VerifyContext;
use crate::tunnel::utils::rustls::ra::cert_cache::{cert_hash, CertVerifyCache};

fn parse_token_from_dice_cert(cbor_tag: u64, raw_evidence: &[u8]) -> Result<TngToken> {
    rats_cert::errors::Result::from(TngToken::create_evidence_from_dice(cbor_tag, raw_evidence))
        .map_err(|e| {
            anyhow!(
                "Failed to parse AS token from DICE cert (cbor_tag={:#x}): {e:#}",
                cbor_tag
            )
        })
}

fn parse_evidence_from_dice_cert(cbor_tag: u64, raw_evidence: &[u8]) -> Result<TngEvidence> {
    rats_cert::errors::Result::from(TngEvidence::create_evidence_from_dice(
        cbor_tag,
        raw_evidence,
    ))
    .map_err(|e| {
        anyhow!(
            "Failed to parse evidence from DICE cert (cbor_tag={:#x}): {e:#}",
            cbor_tag
        )
    })
}

#[derive(Debug)]
pub struct LazyCertVerifier {
    verify_ctx: Arc<VerifyContext>,
    /// Per-config verdict cache, shared across every connection using this rustls
    /// config. Keyed on the peer cert DER so repeated handshakes from the same attester
    /// (which reuses its cert for a refresh window) skip the full RA appraisal.
    cache: CertVerifyCache,
    pending_cert: spin::mutex::spin::SpinMutex<Option<Vec<u8>>>,
}

impl LazyCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>) -> Self {
        Self {
            verify_ctx,
            cache: CertVerifyCache::default_sized(),
            pending_cert: spin::mutex::spin::SpinMutex::new(None),
        }
    }

    /// Stores the peer's certificate for later async RA verification.
    ///
    /// This method is called during the TLS handshake by rustls's
    /// `verify_client_cert()` / `verify_server_cert()` callbacks, which are
    /// **synchronous**. Since RA verification requires contacting a remote
    /// Attestation Service (HTTP call with evidence conversion), it cannot be
    /// done synchronously.
    ///
    /// Instead, we capture the raw certificate here and return `Ok(())` to let
    /// the TLS handshake complete. After the handshake, the caller must invoke
    /// [`Self::verity_pending_cert`] (async) to perform the actual RA
    /// verification. If that step fails, the connection is rejected.
    ///
    /// Call chain:
    ///   1. TLS handshake → rustls calls `verify_client_cert()` (sync)
    ///      → this method stores the cert in `pending_cert`
    ///   2. Handshake complete → caller awaits `verity_pending_cert()` (async)
    ///      → extracts evidence, converts via AS, verifies token
    pub fn set_to_pending_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
    ) -> std::result::Result<(), rustls::Error> {
        // We just return ok here, and store the end entity certificate and verify it later.
        self.pending_cert.lock().replace(end_entity.to_vec());
        Ok(())
    }

    pub async fn verify_pending_cert(&self) -> Result<AttestationResult> {
        let pending_cert = self
            .pending_cert
            .lock()
            .take()
            .context("No rats-tls cert received")?;

        verify_cert(&self.verify_ctx, &self.cache, pending_cert).await
    }
}

#[cfg(not(wasm))]
#[derive(Debug)]
pub struct BlockingCertVerifier {
    verify_ctx: Arc<VerifyContext>,
    cache: CertVerifyCache,
}

#[cfg(not(wasm))]
impl BlockingCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>) -> Self {
        Self {
            verify_ctx,
            cache: CertVerifyCache::default_sized(),
        }
    }

    pub fn verify_cert_blocking(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
    ) -> Result<AttestationResult> {
        let end_entity = end_entity.to_vec();
        let verify_ctx = self.verify_ctx.clone();
        let cache = self.cache.clone();

        // Note: other code running concurrently **in the same task** will be suspended
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(verify_cert(&verify_ctx, &cache, end_entity))
        })
        .context("Failed to get cert verify result")
    }
}

async fn verify_cert(
    verify_ctx: &VerifyContext,
    cache: &CertVerifyCache,
    end_entity: Vec<u8>,
) -> Result<AttestationResult> {
    tracing::debug!("Verifying rats-tls cert");

    // Fast path: if we have already verified this exact cert recently, return the cached
    // verdict and skip the full RA appraisal. The cache is keyed on the cert DER, which
    // embeds the evidence and the pubkey-hash binding, so identical bytes imply an
    // identical, deterministic verdict for the lifetime of this VerifyContext.
    let key = cert_hash(&end_entity);
    if let Some(cached) = cache.get(&key).await {
        // trace, not debug: this fires on nearly every cached connection and is a
        // microscopic fast-path detail, not a meaningful per-connection diagnostic.
        tracing::trace!("rats-tls cert verify cache hit");
        return Ok(cached);
    }

    // Step 1: Extract evidence from certificate
    let pending_result = CertVerifier::new()
        .verify_der(&end_entity)
        .await
        .map_err(|e| anyhow!("Failed to extract evidence from certificate: {:?}", e))?;

    // Step 2: Based on verify mode, convert evidence to token and verify
    let token = match verify_ctx {
        VerifyContext::Passport { verifier } => {
            // Passport: extension must parse as an AS token (not raw evidence).
            let token =
                parse_token_from_dice_cert(pending_result.cbor_tag, &pending_result.raw_evidence)?;

            // Verify the token using pre-instantiated verifier
            verifier
                .verify_evidence(&token, &pending_result.report_data)
                .await
                .map_err(|e| anyhow!("Token verification failed: {:?}", e))?;

            token
        }
        VerifyContext::BackgroundCheck {
            converter,
            verifier,
        } => {
            // BackgroundCheck: extension must parse as raw evidence (then convert via AS).
            let evidence = parse_evidence_from_dice_cert(
                pending_result.cbor_tag,
                &pending_result.raw_evidence,
            )?;

            // Convert evidence to token via remote AS
            let token = converter
                .convert(&evidence)
                .await
                .map_err(|e| anyhow!("Failed to convert evidence to token: {:?}", e))?;

            // Verify the token
            verifier
                .verify_evidence(&token, &pending_result.report_data)
                .await
                .map_err(|e| anyhow!("Token verification failed: {:?}", e))?;

            token
        }
    };

    tracing::debug!("rats-rs cert verify finished successfully");

    let result = AttestationResult::from_token(token);
    // Only cache successful verdicts; errors returned above via `?` are never cached.
    cache.insert(key, result.clone()).await;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ra::{
        CocoConverterArgs, CocoVerifierArgs, ConverterArgs, VerifierArgs, VerifyArgs,
    };
    use rats_cert::cert::verify::PolicyConfig;

    /// Build a builtin (in-process AS) BackgroundCheck VerifyContext without any external
    /// service (no AA socket, no AS HTTP, no PCCS). Construction is hermetic; the builtin AS
    /// only talks to PCCS during `convert`, which these tests never reach.
    async fn make_builtin_verify_context() -> VerifyContext {
        let verify_args = VerifyArgs::BackgroundCheck {
            converter: ConverterArgs::Coco(CocoConverterArgs::Builtin {
                attestation_policy: PolicyConfig::HardwareWithReferenceValues,
                reference_values: vec![],
            }),
            verifier: VerifierArgs::Coco(CocoVerifierArgs::Builtin),
        };
        VerifyContext::from_verify_args(&verify_args)
            .await
            .expect("builtin VerifyContext must construct without external services")
    }

    /// A throwaway AttestationResult used to pre-seed the cache. CocoAsToken::new wraps a
    /// string without validating it; the cache stores it opaquely.
    fn make_cached_result() -> AttestationResult {
        let token = crate::tunnel::provider::TngToken::from(
            rats_cert::tee::coco::evidence::CocoAsToken::new("cached.jwt".to_string())
                .expect("CocoAsToken::new never errors"),
        );
        AttestationResult::from_token(token)
    }

    // A cache hit returns the seeded verdict WITHOUT running the cert parse / RA appraisal.
    // Proven by feeding bytes that are not a parseable cert: only a cache hit could succeed,
    // because a miss would reach CertVerifier::verify_der and reject these bytes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cache_hit_short_circuits_full_verify() {
        let ctx = make_builtin_verify_context().await;
        let cache = CertVerifyCache::default_sized();
        let cert_bytes = b"not-a-real-cert".to_vec();
        let key = cert_hash(&cert_bytes);
        let seeded = make_cached_result();
        cache.insert(key, seeded.clone()).await;

        let got = verify_cert(&ctx, &cache, cert_bytes)
            .await
            .expect("cache hit must return the seeded verdict");
        assert_eq!(got.token_str(), seeded.token_str());
    }

    // A cache miss falls through to the full verify path. With the same bogus bytes (no
    // pre-seeded entry) CertVerifier::verify_der rejects them, so verify_cert errors. This
    // proves a miss does not skip verification.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cache_miss_falls_through_to_full_verify() {
        let ctx = make_builtin_verify_context().await;
        let cache = CertVerifyCache::default_sized();
        let res = verify_cert(&ctx, &cache, b"not-a-real-cert".to_vec()).await;
        assert!(
            res.is_err(),
            "cache miss must fall through to full verification, which rejects bogus cert bytes"
        );
    }

    // Different cert bytes produce different cache keys, so a verdict seeded for one cert
    // must not be returned for another.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cache_key_is_per_cert() {
        let ctx = make_builtin_verify_context().await;
        let cache = CertVerifyCache::default_sized();
        let seeded = make_cached_result();
        cache.insert(cert_hash(b"cert-A"), seeded.clone()).await;

        // cert-B is not in the cache -> falls through -> bogus bytes rejected.
        let res = verify_cert(&ctx, &cache, b"cert-B".to_vec()).await;
        assert!(
            res.is_err(),
            "a different cert must not hit another cert's cache entry"
        );
    }
}

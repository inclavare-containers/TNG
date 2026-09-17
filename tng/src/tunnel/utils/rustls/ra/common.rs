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

/// Take the end-entity (first) peer certificate from a `peer_certificates()`
/// result. Errors if no cert was presented, which on a full rats-tls handshake
/// should never happen: a resumed handshake skips cert verification and never
/// reaches here, so a missing cert on the full-handshake path is a real error.
pub fn take_end_entity_cert(
    certs: Option<&[rustls::pki_types::CertificateDer<'static>]>,
) -> Result<Vec<u8>> {
    certs
        .and_then(|certs| certs.first().map(|c| c.as_ref().to_vec()))
        .context("No peer certificate on full rats-tls handshake")
}

/// Classify a rats-tls connection's attestation outcome from the negotiated
/// handshake kind. Centralizes the tri-state logic shared by the non-multiplex
/// 0-RTT path, the multiplex client handshake, and the server handshake:
///
/// - `Some` verifier + `Resumed`: rustls presented no fresh cert, so RA is not
///   re-run; the original full handshake's attestation is trusted via the PSK
///   binding (`Resumed`).
/// - `Some` verifier + any non-resumed kind: full handshake; fetch the peer
///   end-entity cert rustls validated and RA-verify it now (`Fresh`). The
///   rustls-facing `verify_*_cert` callback was a no-op (stateless), so this is
///   where the real appraisal happens.
/// - `None` verifier: no RA mode (`Unattested`), even on a resumed handshake.
pub async fn classify_attestation(
    verifier: Option<&LazyCertVerifier>,
    handshake_kind: Option<rustls::HandshakeKind>,
    peer_certs: Option<&[rustls::pki_types::CertificateDer<'static>]>,
) -> Result<crate::tunnel::attestation_result::AttestationState> {
    use crate::tunnel::attestation_result::AttestationState;
    match (verifier, handshake_kind) {
        (Some(_), Some(rustls::HandshakeKind::Resumed)) => Ok(AttestationState::Resumed),
        (Some(v), _) => {
            let cert = take_end_entity_cert(peer_certs)?;
            Ok(AttestationState::Fresh(v.verify_cert(cert).await?))
        }
        (None, _) => Ok(AttestationState::Unattested),
    }
}

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

/// Stateless lazy RA verifier.
///
/// Holds only immutable context (`verify_ctx`) and a verdict `cache` shared
/// across every connection using this rustls config. The rustls-facing
/// `verify_*_cert` callbacks are pure no-ops: they return success without
/// inspecting or storing the peer cert. Statelessness is what lets one
/// `LazyCertVerifier` be shared as a single `Arc` across handshakes, which is
/// the condition rustls checks (`Weak::ptr_eq` on the verifier) to allow TLS
/// 1.3 resumption. The peer cert is obtained post-handshake via
/// `peer_certificates()` and verified with [`Self::verify_cert`].
#[derive(Debug)]
pub struct LazyCertVerifier {
    verify_ctx: Arc<VerifyContext>,
    /// Shared verdict cache, one per `TlsConfigGenerator` (not per connection): handed in from the
    /// generator so two verifiers built from the same config share entries, letting a verdict
    /// cached on connection N short-circuit connection N+1 within the TTL.
    cache: Arc<CertVerifyCache>,
}

impl LazyCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>, cache: Arc<CertVerifyCache>) -> Self {
        Self { verify_ctx, cache }
    }

    /// Verify the peer's end-entity cert post-handshake. The caller obtains the
    /// cert from `peer_certificates()` after the TLS handshake completes; on a
    /// resumed handshake the cert is skipped (the PSK binding is trusted
    /// instead) so this is only reached on a full handshake.
    pub async fn verify_cert(&self, cert: Vec<u8>) -> Result<AttestationResult> {
        verify_cert(&self.verify_ctx, &self.cache, cert).await
    }
}

#[cfg(not(wasm))]
#[derive(Debug)]
pub struct BlockingCertVerifier {
    verify_ctx: Arc<VerifyContext>,
    cache: Arc<CertVerifyCache>,
}

#[cfg(not(wasm))]
impl BlockingCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>, cache: Arc<CertVerifyCache>) -> Self {
        Self { verify_ctx, cache }
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

    // The cache handle is shared between verifier instances (one per connection) built from the
    // same TlsConfigGenerator: a verdict seeded through one instance's handle is seen by the next.
    // This is the whole point of moving the cache off the per-connection verifier; without sharing,
    // every connection misses and the cache is dead weight.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shared_cache_survives_across_verifier_instances() {
        // Two independent VerifyContexts (the builtin one is cheap to rebuild) — what matters is
        // that both verifiers receive clones of the *same* Arc<CertVerifyCache>.
        let ctx1 = Arc::new(make_builtin_verify_context().await);
        let ctx2 = Arc::new(make_builtin_verify_context().await);
        let shared = Arc::new(CertVerifyCache::default_sized());
        let v1 = LazyCertVerifier::new(ctx1, shared.clone());
        let v2 = LazyCertVerifier::new(ctx2, shared.clone());

        let cert_bytes = b"not-a-real-cert".to_vec();
        let seeded = make_cached_result();
        // Seed through v1's handle.
        v1.cache
            .insert(cert_hash(&cert_bytes), seeded.clone())
            .await;

        // v2 must hit v1's entry; only a shared cache can return the seeded verdict for bytes
        // that are not a parseable cert (a miss would reach verify_der and reject them).
        let got = verify_cert(&v2.verify_ctx, &v2.cache, cert_bytes)
            .await
            .expect("v2 must hit the entry seeded through v1's shared cache handle");
        assert_eq!(got.token_str(), seeded.token_str());
    }
}

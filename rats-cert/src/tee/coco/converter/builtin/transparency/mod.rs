//! Transparency-log authentication.
//!
//! One seam, [`authenticate`], serves all three callers: the rekor-v1 primary
//! at policy-load time (which bakes the authenticated entry into Rego), the
//! artifact-server resolve at appraisal time, and the rekor on-demand fallback.
//! The two adapters behind it are [`rekor_v1::authenticate`] and
//! [`artifact_server::authenticate`].

pub(crate) mod artifact_server;
pub(crate) mod cache;
pub(crate) mod dsse;
pub(crate) mod key_table;
pub(crate) mod rekor_v1;

pub use cache::TransparencyCaches;

use super::policy_config::TransparencyServiceConfig;

/// The authenticated data a rekor-direct entry contributes to a policy: the
/// trusted `payloadHash`, the in-band DSSE signature, and the effective
/// publisher key the signature is verified against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedRekor {
    pub(crate) payload_hash: String,
    pub(crate) dsse_signature: String,
    pub(crate) publisher_key: String,
}

/// The outcome of authenticating one log service.
#[derive(Debug)]
pub(crate) enum Authentication {
    /// A rekor-direct entry authenticated without a bound manifest (policy
    /// load). The trusted payload hash and signature are baked into Rego and
    /// bound to the manifest at appraisal time.
    Rekor(AuthenticatedRekor),
    /// A bound manifest authenticated.
    Verified,
    /// The artifact server explicitly revoked the measurement.
    Revoked,
}

/// Authenticate a log service, optionally binding the result to `manifest`.
///
/// `manifest` is `None` only for the policy-load rekor path: there is no
/// manifest yet, so the adapter returns the authenticated entry for the Rego
/// bake and the binding happens at appraisal time. An artifact-server primary
/// does no I/O at load; it resolves at appraisal, so a `None` manifest returns
/// `Verified` without touching the network.
pub(crate) async fn authenticate(
    manifest: Option<&serde_json::Value>,
    service: &TransparencyServiceConfig,
    caches: &TransparencyCaches,
) -> anyhow::Result<Authentication> {
    match service {
        TransparencyServiceConfig::RekorV1 { .. } => {
            rekor_v1::authenticate(manifest, service, caches).await
        }
        TransparencyServiceConfig::ArtifactServer { .. } => match manifest {
            // The artifact-server primary resolves at appraisal time.
            None => Ok(Authentication::Verified),
            Some(manifest) => artifact_server::authenticate(manifest, service, caches).await,
        },
    }
}

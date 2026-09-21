use std::sync::Arc;

use anyhow::Result;
use rats_cert::tee::claims::Claims;
use rats_cert::tee::GenericEvidence;
use serde::Serialize;

use super::provider::TngToken;

/// The result of remote attestation.
///
/// This struct is cheap to clone.
#[derive(Clone)]
pub struct AttestationResult {
    /// Use Arc to avoid cloning the claims to save memory.
    #[allow(unused)]
    token: Arc<TngToken>,
}

/// The attestation outcome of a tunnel stream, distinguishing a freshly-verified
/// attestation from one trusted via TLS 1.3 session resumption.
///
/// `Option<AttestationResult>` cannot represent the resumed case: on a resumed
/// (PSK) handshake rustls skips `verify_client_cert`, so a fresh RA result is
/// neither available nor needed, yet the connection IS attested (the original
/// full handshake's attestation is trusted via the PSK binding). Collapsing
/// resumed into `None` would print `attested=false` for a securely-resumed
/// connection. The tri-state keeps resumed distinct from the genuine
/// no-attestation case (`Unattested`).
#[derive(Debug, Clone)]
pub enum AttestationState {
    /// Full handshake; the peer cert was freshly RA-verified this connection.
    Fresh(AttestationResult),
    /// Resumed handshake; the peer did not present a cert and RA was not re-run.
    /// The attestation from the original full handshake is trusted via the PSK
    /// binding (standard TLS 1.3 resumption semantics). Carries no token.
    Resumed,
    /// No remote attestation (e.g. `no_ra` mode, or no client/server auth).
    Unattested,
}

impl AttestationState {
    /// True for `Fresh` and `Resumed` (the connection is attested, freshly or
    /// via resumption). False only for `Unattested`.
    pub fn is_attested(&self) -> bool {
        matches!(self, Self::Fresh(_) | Self::Resumed)
    }

    /// The freshly-verified token, if any. `Resumed` and `Unattested` return
    /// `None` (a resumed connection carries no fresh token string).
    pub fn as_attestation_result(&self) -> Option<&AttestationResult> {
        match self {
            Self::Fresh(ar) => Some(ar),
            _ => None,
        }
    }
}

impl Serialize for AttestationResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self.token.as_str())
    }
}

impl std::fmt::Debug for AttestationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationResult")
            .field("token", &self.token.as_str())
            .finish()
    }
}

impl AttestationResult {
    pub fn from_token(token: TngToken) -> Self {
        Self {
            token: Arc::new(token),
        }
    }

    /// Return the raw JWT token string.
    pub fn token_str(&self) -> &str {
        self.token.as_str()
    }

    /// Expiry timestamp (JWT `exp` claim) of the underlying token.
    pub fn exp(&self) -> Result<u64> {
        self.token.exp()
    }

    /// Decoded JWT payload claims of the underlying attestation-result token.
    /// Pure local decode (split + base64url + parse); no AS call.
    pub fn claims(&self) -> Result<Claims> {
        self.token.get_claims().map_err(Into::into)
    }
}

use std::sync::Arc;

use rats_cert::tee::claims::Claims;
use serde::Serialize;

/// The result of remote attestation.
///
/// This struct is cheap to clone.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct AttestationResult {
    /// Use Arc to avoid cloning the claims to save memory.
    #[allow(unused)]
    claims: Arc<Claims>,
}

impl AttestationResult {
    pub fn from_claims(claims: Claims) -> Self {
        Self {
            claims: Arc::new(claims),
        }
    }

    pub fn claims(&self) -> &Claims {
        &self.claims
    }
}

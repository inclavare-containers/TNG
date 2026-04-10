use std::sync::Arc;

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
}

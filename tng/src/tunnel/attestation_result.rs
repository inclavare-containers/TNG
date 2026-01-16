use std::sync::Arc;

use rats_cert::tee::coco::evidence::CocoAsToken;
use serde::Serialize;

/// The result of remote attestation.
///
/// This struct is cheap to clone.
#[derive(Clone)]
pub struct AttestationResult {
    /// Use Arc to avoid cloning the claims to save memory.
    #[allow(unused)]
    token: Arc<CocoAsToken>,
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
    pub fn from_coco_as_token(token: CocoAsToken) -> Self {
        Self {
            token: Arc::new(token),
        }
    }
}

#[cfg(any(feature = "__builtin-as", feature = "__builtin-as-wasm"))]
pub mod builtin;
mod common;
pub mod remote;
pub mod token;
#[cfg(feature = "crypto-rustcrypto")]
pub mod transparency;

use super::evidence::CocoAsToken;
use crate::errors::Result;
use crate::tee::{GenericVerifier, ReportData};

/// Unified CocoVerifier enum
pub enum CocoVerifier {
    Remote(remote::CocoRemoteVerifier),
    #[cfg(any(feature = "__builtin-as", feature = "__builtin-as-wasm"))]
    Builtin(builtin::BuiltinCocoVerifier),
}

#[async_trait::async_trait]
impl GenericVerifier for CocoVerifier {
    type Evidence = CocoAsToken;

    async fn verify_evidence(
        &self,
        evidence: &Self::Evidence,
        report_data: &ReportData,
    ) -> Result<()> {
        match self {
            Self::Remote(verifier) => verifier.verify_evidence(evidence, report_data).await,
            #[cfg(any(feature = "__builtin-as", feature = "__builtin-as-wasm"))]
            Self::Builtin(verifier) => verifier.verify_evidence(evidence, report_data).await,
        }
    }
}

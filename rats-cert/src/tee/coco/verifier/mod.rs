#[cfg(feature = "__builtin-as")]
pub mod builtin;
mod common;
pub mod remote;
pub mod token;
pub mod transparency;

use super::evidence::CocoAsToken;
use crate::errors::Result;
use crate::tee::{GenericVerifier, ReportData};

/// Unified CocoVerifier enum
pub enum CocoVerifier {
    Remote(remote::CocoRemoteVerifier),
    #[cfg(feature = "__builtin-as")]
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
            #[cfg(feature = "__builtin-as")]
            Self::Builtin(verifier) => verifier.verify_evidence(evidence, report_data).await,
        }
    }
}

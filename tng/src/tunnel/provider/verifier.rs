use rats_cert::errors::*;
use rats_cert::tee::coco::verifier::CocoVerifier;
use rats_cert::tee::{GenericVerifier, ReportData};

use super::token::TngToken;

/// Provider-polymorphic verifier. Verifies an AS token against report data.
pub enum TngVerifier {
    Coco(CocoVerifier),
}

impl TngVerifier {
    pub fn provider_type(&self) -> super::provider_type::ProviderType {
        match self {
            Self::Coco(_) => super::provider_type::ProviderType::Coco,
        }
    }
}

#[async_trait::async_trait]
impl GenericVerifier for TngVerifier {
    type Evidence = TngToken;

    async fn verify_evidence(&self, token: &TngToken, report_data: &ReportData) -> Result<()> {
        match (self, token) {
            (Self::Coco(v), TngToken::Coco(t)) => v.verify_evidence(t, report_data).await,
        }
    }
}

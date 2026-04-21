use rats_cert::errors::*;
use rats_cert::tee::coco::verifier::CocoVerifier;
use rats_cert::tee::ita::ItaVerifier;
use rats_cert::tee::{GenericVerifier, ReportData};

use super::token::TngToken;

/// Provider-polymorphic verifier. Verifies an AS token against report data.
pub enum TngVerifier {
    Coco(CocoVerifier),
    Ita(ItaVerifier),
}

impl TngVerifier {
    pub fn provider_type(&self) -> super::provider_type::ProviderType {
        match self {
            Self::Coco(_) => super::provider_type::ProviderType::Coco,
            Self::Ita(_) => super::provider_type::ProviderType::Ita,
        }
    }
}

#[async_trait::async_trait]
impl GenericVerifier for TngVerifier {
    type Evidence = TngToken;

    async fn verify_evidence(&self, token: &TngToken, report_data: &ReportData) -> Result<()> {
        match (self, token) {
            (Self::Coco(v), TngToken::Coco(t)) => v.verify_evidence(t, report_data).await,
            (Self::Ita(v), TngToken::Ita(t)) => v.verify_evidence(t, report_data).await,
            _ => Err(Error::IncompatibleTypes {
                detail: "verifier and token provider mismatch".to_string(),
            }),
        }
    }
}

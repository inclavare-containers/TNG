use rats_cert::errors::*;
use rats_cert::tee::coco::verifier::CocoVerifier;
use rats_cert::tee::{GenericVerifier, ReportData};

use super::provider_type::ProviderType;
use super::token::TngToken;

pub enum TngVerifier {
    Coco(CocoVerifier),
}

impl TngVerifier {
    pub fn provider_type(&self) -> ProviderType {
        match self {
            Self::Coco(_) => ProviderType::Coco,
        }
    }
}

#[async_trait::async_trait]
impl GenericVerifier for TngVerifier {
    type Evidence = TngToken;

    async fn verify_evidence(&self, token: &TngToken, report_data: &ReportData) -> Result<()> {
        if self.provider_type() != token.provider_type() {
            return Err(Error::msg(format!(
                "{} verifier cannot verify {} token",
                self.provider_type(),
                token.provider_type()
            )));
        }
        match (self, token) {
            (Self::Coco(v), TngToken::Coco(t)) => v.verify_evidence(t, report_data).await,
            _ => unreachable!("provider type mismatch already checked"),
        }
    }
}

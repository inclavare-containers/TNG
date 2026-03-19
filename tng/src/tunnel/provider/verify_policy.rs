use rats_cert::cert::verify::{CocoVerifyPolicy, VerifyPolicy};
use rats_cert::errors::*;
use rats_cert::tee::ReportData;

use super::provider_type::ProviderType;
use super::token::TngToken;

pub enum TngVerifyPolicy {
    Coco(CocoVerifyPolicy),
}

impl TngVerifyPolicy {
    pub fn provider_type(&self) -> ProviderType {
        match self {
            Self::Coco(_) => ProviderType::Coco,
        }
    }
}

impl VerifyPolicy for TngVerifyPolicy {
    type ProcessedEvidence = TngToken;

    async fn process_evidence(
        &self,
        cbor_tag: u64,
        raw_evidence: &[u8],
    ) -> Result<TngToken> {
        match self {
            Self::Coco(p) => {
                Ok(p.process_evidence(cbor_tag, raw_evidence).await?.into())
            }
        }
    }

    async fn verify(&self, evidence: &TngToken, report_data: &ReportData) -> Result<()> {
        if self.provider_type() != evidence.provider_type() {
            return Err(Error::msg(format!(
                "{} verify policy cannot verify {} token",
                self.provider_type(),
                evidence.provider_type()
            )));
        }
        match (self, evidence) {
            (Self::Coco(p), TngToken::Coco(t)) => p.verify(t, report_data).await,
            _ => unreachable!("provider type mismatch already checked"),
        }
    }
}

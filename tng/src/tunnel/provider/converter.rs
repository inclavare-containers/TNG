use rats_cert::errors::*;
use rats_cert::tee::coco::converter::{CoCoNonce, CocoConverter};
use rats_cert::tee::ita::ItaConverter;
use rats_cert::tee::GenericConverter;

use super::evidence::TngEvidence;
use super::token::TngToken;

/// Provider-polymorphic converter. Converts evidence into an AS token.
/// Uses `try_into()` on evidence to enable cross-provider compatibility.
pub enum TngConverter {
    Coco(CocoConverter),
    Ita(ItaConverter),
}

impl TngConverter {
    pub fn provider_type(&self) -> super::provider_type::ProviderType {
        match self {
            Self::Coco(_) => super::provider_type::ProviderType::Coco,
            Self::Ita(_) => super::provider_type::ProviderType::Ita,
        }
    }
}

#[async_trait::async_trait]
impl GenericConverter for TngConverter {
    type InEvidence = TngEvidence;
    type OutEvidence = TngToken;
    type Nonce = String;

    async fn convert(&self, in_evidence: &TngEvidence) -> Result<TngToken> {
        match self {
            Self::Coco(c) => {
                let native_evidence = in_evidence.try_into()?;
                Ok(c.convert(&native_evidence).await?.into())
            }
            Self::Ita(c) => {
                let native_evidence = in_evidence.try_into()?;
                Ok(c.convert(&native_evidence).await?.into())
            }
        }
    }

    async fn get_nonce(&self) -> Result<String> {
        match self {
            Self::Coco(c) => {
                let CoCoNonce::Jwt(token) = c.get_nonce().await?;
                Ok(token)
            }
            Self::Ita(c) => c.get_nonce().await,
        }
    }
}

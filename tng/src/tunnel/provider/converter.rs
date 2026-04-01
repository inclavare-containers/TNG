use rats_cert::errors::*;
use rats_cert::tee::coco::converter::{CoCoNonce, CocoConverter};
use rats_cert::tee::GenericConverter;

use super::evidence::TngEvidence;
use super::token::TngToken;

pub enum TngConverter {
    Coco(CocoConverter),
}

#[async_trait::async_trait]
impl GenericConverter for TngConverter {
    type InEvidence = TngEvidence;
    type OutEvidence = TngToken;

    async fn convert(&self, in_evidence: &TngEvidence) -> Result<TngToken> {
        match self {
            Self::Coco(c) => {
                let native_evidence = in_evidence.try_into()?;
                Ok(c.convert(&native_evidence).await?.into())
            }
        }
    }
}

impl TngConverter {
    pub async fn get_nonce(&self) -> anyhow::Result<String> {
        match self {
            Self::Coco(c) => {
                let CoCoNonce::Jwt(token) = c.get_nonce().await?;
                Ok(token)
            }
        }
    }
}

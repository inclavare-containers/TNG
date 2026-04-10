use anyhow::Result;
use rats_cert::tee::coco::evidence::CocoAsToken;
use rats_cert::tee::claims::Claims;
use rats_cert::tee::{DiceParseEvidenceOutput, GenericEvidence};

use super::provider_type::ProviderType;

/// Provider-polymorphic attestation service token wrapper.
/// Each variant holds the native AS token type for that provider.
pub enum TngToken {
    Coco(CocoAsToken),
}

impl From<CocoAsToken> for TngToken {
    fn from(t: CocoAsToken) -> Self {
        Self::Coco(t)
    }
}

impl TngToken {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Coco(t) => t.as_str(),
        }
    }

    pub fn into_str(self) -> String {
        match self {
            Self::Coco(t) => t.into_str(),
        }
    }

    pub fn exp(&self) -> Result<u64> {
        match self {
            Self::Coco(t) => Ok(t.exp()?),
        }
    }

    pub fn provider_type(&self) -> ProviderType {
        match self {
            Self::Coco(_) => ProviderType::Coco,
        }
    }

    /// Construct from a wire token string. Currently assumes CoCo since
    /// only one provider exists. When a second provider is added, the wire
    /// protocol should include a provider tag (similar to TngEvidence).
    pub fn from_wire(raw: String) -> Result<Self> {
        Ok(Self::Coco(CocoAsToken::new(raw)?))
    }
}

impl GenericEvidence for TngToken {
    fn get_dice_cbor_tag(&self) -> u64 {
        match self {
            Self::Coco(t) => t.get_dice_cbor_tag(),
        }
    }

    fn get_dice_raw_evidence(&self) -> rats_cert::errors::Result<Vec<u8>> {
        match self {
            Self::Coco(t) => t.get_dice_raw_evidence(),
        }
    }

    fn get_claims(&self) -> rats_cert::errors::Result<Claims> {
        match self {
            Self::Coco(t) => t.get_claims(),
        }
    }

    fn create_evidence_from_dice(
        cbor_tag: u64,
        raw_evidence: &[u8],
    ) -> DiceParseEvidenceOutput<Self> {
        match CocoAsToken::create_evidence_from_dice(cbor_tag, raw_evidence) {
            DiceParseEvidenceOutput::Ok(t) => return DiceParseEvidenceOutput::Ok(t.into()),
            DiceParseEvidenceOutput::MatchButInvalid(e) => {
                return DiceParseEvidenceOutput::MatchButInvalid(e)
            }
            DiceParseEvidenceOutput::NotMatch => {}
        }

        DiceParseEvidenceOutput::NotMatch
    }
}

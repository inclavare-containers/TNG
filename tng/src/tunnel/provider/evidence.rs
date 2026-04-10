use anyhow::{anyhow, Result};
use rats_cert::tee::coco::evidence::CocoEvidence;
use rats_cert::tee::claims::Claims;
use rats_cert::tee::{DiceParseEvidenceOutput, GenericEvidence};

use super::provider_type::ProviderType;

/// Provider-polymorphic evidence wrapper.
/// Each variant holds the native evidence type for that provider.
pub enum TngEvidence {
    Coco(CocoEvidence),
}

impl From<CocoEvidence> for TngEvidence {
    fn from(e: CocoEvidence) -> Self {
        Self::Coco(e)
    }
}

impl TryFrom<&TngEvidence> for CocoEvidence {
    type Error = rats_cert::errors::Error;
    fn try_from(e: &TngEvidence) -> rats_cert::errors::Result<Self> {
        match e {
            TngEvidence::Coco(inner) => Ok(inner.clone()),
        }
    }
}

impl TngEvidence {
    pub fn provider_type(&self) -> ProviderType {
        match self {
            Self::Coco(_) => ProviderType::Coco,
        }
    }

    /// Serialize to JSON with a provider type envelope for wire safety.
    /// The receiver uses the `"provider"` tag to determine how to deserialize,
    /// since ingress and egress are separate TNG instances with independent configs.
    pub fn serialize_to_json(&self) -> Result<serde_json::Value> {
        match self {
            Self::Coco(e) => Ok(serde_json::json!({
                "provider": self.provider_type(),
                "evidence": e.serialize_to_json()?
            })),
        }
    }

    /// Deserialize from JSON, dispatching on the `"provider"` tag.
    pub fn deserialize_from_json(value: serde_json::Value) -> Result<Self> {
        let mut obj = match value {
            serde_json::Value::Object(map) => map,
            _ => return Err(anyhow!("evidence envelope is not a JSON object")),
        };
        let provider: ProviderType = obj
            .get("provider")
            .ok_or_else(|| anyhow!("missing 'provider' field in evidence"))?
            .as_str()
            .ok_or_else(|| anyhow!("'provider' field is not a string"))?
            .parse()?;
        let inner = obj
            .remove("evidence")
            .ok_or_else(|| anyhow!("missing 'evidence' field"))?;
        match provider {
            ProviderType::Coco => Ok(Self::Coco(CocoEvidence::deserialize_from_json(inner)?)),
        }
    }
}

impl GenericEvidence for TngEvidence {
    fn get_dice_cbor_tag(&self) -> u64 {
        match self {
            Self::Coco(e) => e.get_dice_cbor_tag(),
        }
    }

    fn get_dice_raw_evidence(&self) -> rats_cert::errors::Result<Vec<u8>> {
        match self {
            Self::Coco(e) => e.get_dice_raw_evidence(),
        }
    }

    fn get_claims(&self) -> rats_cert::errors::Result<Claims> {
        match self {
            Self::Coco(e) => e.get_claims(),
        }
    }

    fn create_evidence_from_dice(
        cbor_tag: u64,
        raw_evidence: &[u8],
    ) -> DiceParseEvidenceOutput<Self> {
        match CocoEvidence::create_evidence_from_dice(cbor_tag, raw_evidence) {
            DiceParseEvidenceOutput::Ok(e) => return DiceParseEvidenceOutput::Ok(e.into()),
            DiceParseEvidenceOutput::MatchButInvalid(e) => {
                return DiceParseEvidenceOutput::MatchButInvalid(e)
            }
            DiceParseEvidenceOutput::NotMatch => {}
        }

        DiceParseEvidenceOutput::NotMatch
    }
}

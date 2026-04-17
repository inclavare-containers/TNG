use anyhow::Result;
use rats_cert::tee::claims::Claims;
use rats_cert::tee::coco::evidence::CocoEvidence;
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

    /// Serialize to the CoCo evidence JSON object. OHTTP adds `aa_provider` beside this value.
    pub fn serialize_to_json(&self) -> serde_json::Result<serde_json::Value> {
        match self {
            Self::Coco(e) => e.serialize_to_json(),
        }
    }

    /// Deserialize evidence JSON for `provider` (OHTTP passes [`ProviderType`] from `aa_provider`).
    pub fn deserialize_from_json(provider: ProviderType, value: serde_json::Value) -> Result<Self> {
        match provider {
            ProviderType::Coco => Ok(Self::Coco(CocoEvidence::deserialize_from_json(value)?)),
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
        CocoEvidence::create_evidence_from_dice(cbor_tag, raw_evidence).map_ok::<Self>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid `CocoEvidence` JSON (`CocoEvidence::serialize_to_json` shape on master).
    fn minimal_legacy_coco_evidence_json() -> serde_json::Value {
        serde_json::json!({
            "aa_tee_type": "tdx",
            "aa_evidence": "aGVsbG8=",
            "aa_runtime_data": "{}",
            "aa_runtime_data_hash_algo": "sha256",
        })
    }

    #[test]
    fn coco_evidence_json_round_trip() {
        let inner = minimal_legacy_coco_evidence_json();
        let ev = TngEvidence::deserialize_from_json(ProviderType::Coco, inner.clone())
            .expect("deserialize");
        assert_eq!(ev.serialize_to_json().expect("serialize"), inner);
    }
}

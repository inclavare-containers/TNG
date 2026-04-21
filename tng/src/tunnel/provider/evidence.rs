use anyhow::Result;
use rats_cert::tee::claims::Claims;
use rats_cert::tee::coco::evidence::CocoEvidence;
use rats_cert::tee::ita::ItaEvidence;
use rats_cert::tee::{DiceParseEvidenceOutput, GenericEvidence};

use super::provider_type::ProviderType;

/// Provider-polymorphic evidence wrapper.
/// Each variant holds the native evidence type for that provider.
pub enum TngEvidence {
    Coco(CocoEvidence),
    Ita(ItaEvidence),
}

impl From<CocoEvidence> for TngEvidence {
    fn from(e: CocoEvidence) -> Self {
        Self::Coco(e)
    }
}

impl From<ItaEvidence> for TngEvidence {
    fn from(e: ItaEvidence) -> Self {
        Self::Ita(e)
    }
}

impl TryFrom<&TngEvidence> for CocoEvidence {
    type Error = rats_cert::errors::Error;
    fn try_from(e: &TngEvidence) -> rats_cert::errors::Result<Self> {
        match e {
            TngEvidence::Coco(inner) => Ok(inner.clone()),
            _ => Err(rats_cert::errors::Error::IncompatibleTypes {
                detail: format!("expected CoCo evidence, got {:?}", e.provider_type()),
            }),
        }
    }
}

impl TryFrom<&TngEvidence> for ItaEvidence {
    type Error = rats_cert::errors::Error;
    fn try_from(e: &TngEvidence) -> rats_cert::errors::Result<Self> {
        match e {
            TngEvidence::Ita(inner) => Ok(inner.clone()),
            _ => Err(rats_cert::errors::Error::IncompatibleTypes {
                detail: format!("expected ITA evidence, got {:?}", e.provider_type()),
            }),
        }
    }
}

impl TngEvidence {
    pub fn provider_type(&self) -> ProviderType {
        match self {
            Self::Coco(_) => ProviderType::Coco,
            Self::Ita(_) => ProviderType::Ita,
        }
    }

    /// Serialize to the CoCo evidence JSON object. OHTTP adds `aa_provider` beside this value.
    pub fn serialize_to_json(&self) -> serde_json::Result<serde_json::Value> {
        match self {
            Self::Coco(e) => e.serialize_to_json(),
            Self::Ita(e) => e.serialize_to_json(),
        }
    }

    /// Deserialize evidence JSON for `provider` (OHTTP passes [`ProviderType`] from `aa_provider`).
    pub fn deserialize_from_json(provider: ProviderType, value: serde_json::Value) -> Result<Self> {
        match provider {
            ProviderType::Coco => Ok(Self::Coco(CocoEvidence::deserialize_from_json(value)?)),
            ProviderType::Ita => Ok(Self::Ita(ItaEvidence::deserialize_from_json(value)?)),
        }
    }
}

impl GenericEvidence for TngEvidence {
    fn get_dice_cbor_tag(&self) -> u64 {
        match self {
            Self::Coco(e) => e.get_dice_cbor_tag(),
            Self::Ita(e) => e.get_dice_cbor_tag(),
        }
    }

    fn get_dice_raw_evidence(&self) -> rats_cert::errors::Result<Vec<u8>> {
        match self {
            Self::Coco(e) => e.get_dice_raw_evidence(),
            Self::Ita(e) => e.get_dice_raw_evidence(),
        }
    }

    fn get_claims(&self) -> rats_cert::errors::Result<Claims> {
        match self {
            Self::Coco(e) => e.get_claims(),
            Self::Ita(e) => e.get_claims(),
        }
    }

    fn create_evidence_from_dice(
        cbor_tag: u64,
        raw_evidence: &[u8],
    ) -> DiceParseEvidenceOutput<Self> {
        CocoEvidence::create_evidence_from_dice(cbor_tag, raw_evidence)
            .map_ok::<Self>()
            .or_else(|| {
                ItaEvidence::create_evidence_from_dice(cbor_tag, raw_evidence).map_ok::<Self>()
            })
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

    fn minimal_ita_evidence_json() -> serde_json::Value {
        use base64::prelude::BASE64_STANDARD;
        use base64::Engine as _;
        serde_json::json!({
            "tdx_quote": BASE64_STANDARD.encode(b"fake-tdx-quote"),
            "runtime_data": BASE64_STANDARD.encode(b"{}"),
        })
    }

    #[test]
    fn ita_evidence_json_round_trip() {
        let inner = minimal_ita_evidence_json();
        let ev = TngEvidence::deserialize_from_json(ProviderType::Ita, inner.clone())
            .expect("deserialize");
        assert_eq!(ev.provider_type(), ProviderType::Ita);
        assert_eq!(ev.serialize_to_json().expect("serialize"), inner);
    }

    #[test]
    fn cross_provider_try_from_fails() {
        let inner = minimal_ita_evidence_json();
        let ev = TngEvidence::deserialize_from_json(ProviderType::Ita, inner).expect("deserialize");
        assert!(CocoEvidence::try_from(&ev).is_err());
    }
}

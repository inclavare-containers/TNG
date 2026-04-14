use anyhow::{anyhow, Result};
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

    /// Serialize to JSON with a provider type envelope for wire safety.
    /// The receiver uses the `"provider"` tag to determine how to deserialize,
    /// since ingress and egress are separate TNG instances with independent configs.
    ///
    /// The `{ "provider", "evidence" }` wrapper is shared by all variants; only the inner
    /// `evidence` payload is provider-specific.
    pub fn serialize_to_json(&self) -> Result<serde_json::Value> {
        let evidence = match self {
            Self::Coco(e) => e.serialize_to_json()?,
        };
        Ok(serde_json::json!({
            "provider": self.provider_type(),
            "evidence": evidence,
        }))
    }

    /// Deserialize from JSON. Accepts either:
    /// - **Envelope**: `{ "provider": "...", "evidence": ... }` (multi-provider wire format).
    /// - **Legacy**: a full [`CocoEvidence`] JSON value with **no** top-level `"provider"` key,
    ///   as produced by pre–multi-provider TNG via `CocoEvidence::serialize_to_json`.
    pub fn deserialize_from_json(value: serde_json::Value) -> Result<Self> {
        let use_envelope = matches!(
            &value,
            serde_json::Value::Object(obj) if obj.contains_key("provider")
        );
        if !use_envelope {
            return Ok(Self::Coco(CocoEvidence::deserialize_from_json(value)?));
        }

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
    fn legacy_evidence_without_provider_matches_envelope_evidence() {
        let inner = minimal_legacy_coco_evidence_json();

        let from_legacy = TngEvidence::deserialize_from_json(inner.clone()).expect("legacy");

        let wrapped = serde_json::json!({
            "provider": "coco",
            "evidence": inner,
        });
        let from_envelope = TngEvidence::deserialize_from_json(wrapped).expect("envelope");

        assert_eq!(
            from_legacy.serialize_to_json().expect("serialize legacy"),
            from_envelope.serialize_to_json().expect("serialize envelope"),
        );
    }
}

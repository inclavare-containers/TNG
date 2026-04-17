use anyhow::Result;
use rats_cert::tee::claims::Claims;
use rats_cert::tee::coco::evidence::CocoAsToken;
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

    /// Construct from a wire token string. The `provider` parameter determines
    /// which provider-specific token type to construct.
    pub fn from_wire(provider: ProviderType, raw: String) -> Result<Self> {
        match provider {
            ProviderType::Coco => Ok(Self::Coco(CocoAsToken::new(raw)?)),
        }
    }

    /// JSON string value containing the JWT. OHTTP adds `as_provider` beside this in API types.
    pub fn serialize_to_json(&self) -> Result<serde_json::Value> {
        Ok(serde_json::Value::String(self.as_str().to_owned()))
    }

    /// Deserialize a JSON string JWT. `provider` comes from OHTTP `as_provider` (same idea as evidence).
    pub fn deserialize_from_json(provider: ProviderType, value: serde_json::Value) -> Result<Self> {
        match value {
            serde_json::Value::String(s) => Self::from_wire(provider, s),
            _ => Err(anyhow::anyhow!(
                "attestation token JSON must be a string (JWT)"
            )),
        }
    }

    /// Raw JWT for protobuf `string` fields (OHTTP request metadata); not JSON text.
    pub fn serialize_to_wire_str(&self) -> Result<String> {
        Ok(self.as_str().to_owned())
    }

    /// Parse [`Self::serialize_to_wire_str`] — thin wrapper around [`Self::from_wire`] for UTF-8 metadata.
    pub fn deserialize_from_wire_str(provider: ProviderType, s: &str) -> Result<Self> {
        Self::from_wire(provider, s.to_owned())
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
        CocoAsToken::create_evidence_from_dice(cbor_tag, raw_evidence).map_ok::<Self>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_jwt() -> String {
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
            .to_string()
    }

    #[test]
    fn json_string_round_trip() {
        let jwt = minimal_jwt();
        let t = TngToken::deserialize_from_json(
            ProviderType::Coco,
            serde_json::Value::String(jwt.clone()),
        )
        .expect("tok");
        assert_eq!(
            t.serialize_to_json().expect("ser"),
            serde_json::Value::String(jwt)
        );
    }

    #[test]
    fn wire_str_round_trip() {
        let jwt = minimal_jwt();
        let t = TngToken::from_wire(ProviderType::Coco, jwt.clone()).expect("tok");
        let s = t.serialize_to_wire_str().expect("wire");
        let t2 = TngToken::deserialize_from_wire_str(ProviderType::Coco, &s).expect("parse");
        assert_eq!(t.as_str(), t2.as_str());
    }
}

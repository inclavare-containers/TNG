use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Canonical provider type enum. The string representation of each variant
/// is defined exactly once in `as_str()`, and all other conversions
/// (Display, FromStr, Serialize, Deserialize) delegate to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderType {
    Coco,
}

impl ProviderType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Coco => "coco",
        }
    }

    /// Resolve optional `as_provider` / `aa_provider` from OHTTP JSON.
    ///
    /// `None` means payloads from before those additive fields existed; behavior matches
    /// legacy CoCo-only clients.
    pub fn from_optional_wire(opt: Option<Self>) -> Self {
        opt.unwrap_or(Self::Coco)
    }

    /// Resolve optional provider from a protobuf string field (or similar).
    ///
    /// Empty or whitespace-only strings are treated like a missing field (legacy CoCo).
    pub fn from_optional_wire_str(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            Ok(Self::from_optional_wire(None))
        } else {
            s.parse()
        }
    }
}

impl fmt::Display for ProviderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProviderType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const ALL: &[ProviderType] = &[ProviderType::Coco];
        ALL.iter()
            .find(|p| p.as_str() == s)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("unsupported provider: {s}"))
    }
}

impl Serialize for ProviderType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProviderType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_optional_wire_str_empty_is_legacy_coco() {
        assert_eq!(
            ProviderType::from_optional_wire_str("").unwrap(),
            ProviderType::Coco
        );
    }

    #[test]
    fn from_optional_wire_str_parses_known() {
        assert_eq!(
            ProviderType::from_optional_wire_str("coco").unwrap(),
            ProviderType::Coco
        );
    }

    #[test]
    fn serde_json_round_trip() {
        let original = ProviderType::Coco;
        let json = serde_json::to_value(original).unwrap();
        let back: ProviderType = serde_json::from_value(json).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(ProviderType::Coco.to_string(), ProviderType::Coco.as_str());
    }
}

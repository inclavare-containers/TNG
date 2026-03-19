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
    fn test_provider_type_roundtrip() {
        let provider = ProviderType::Coco;
        assert_eq!(provider.as_str(), "coco");
        assert_eq!(provider.to_string(), "coco");
        assert_eq!("coco".parse::<ProviderType>().unwrap(), ProviderType::Coco);
    }

    #[test]
    fn test_provider_type_unknown() {
        assert!("foobar".parse::<ProviderType>().is_err());
    }

    #[test]
    fn test_provider_type_serde() {
        let provider = ProviderType::Coco;
        let json = serde_json::to_string(&provider).unwrap();
        assert_eq!(json, "\"coco\"");
        let parsed: ProviderType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ProviderType::Coco);
    }
}

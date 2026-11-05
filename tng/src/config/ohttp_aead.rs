use serde::{Deserialize, Deserializer, Serialize};

/// A HPKE AEAD suite selectable for OHTTP by the `aead_suites` config field.
///
/// The KEM is fixed to DHKEM(X25519, HKDF-SHA256) and the KDF to HKDF-SHA256,
/// so the AEAD is the only selectable dimension. The wire values are
/// case-sensitive and take no aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AeadSuite {
    Aes128Gcm,
    Aes256Gcm,
    // `rename_all = "snake_case"` would render this variant as
    // `cha_cha20_poly1305`; the documented value is `chacha20_poly1305`.
    #[serde(rename = "chacha20_poly1305")]
    ChaCha20Poly1305,
}

/// A non-empty, duplicate-free ordered list of AEAD suites.
///
/// Both invariants are enforced during deserialization, so any value of this
/// type is a usable policy. Order is meaningful: it is the preference order
/// an ingress uses and the advertised order an egress publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct AeadSuites(Vec<AeadSuite>);

impl<'de> Deserialize<'de> for AeadSuites {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let aead_suites = Vec::<AeadSuite>::deserialize(deserializer)?;

        if aead_suites.is_empty() {
            return Err(serde::de::Error::custom(
                "aead_suites must not be empty; omit the field to use the default policy",
            ));
        }

        for (index, suite) in aead_suites.iter().enumerate() {
            if aead_suites[..index].contains(suite) {
                return Err(serde::de::Error::custom(format!(
                    "aead_suites contains duplicate value `{suite}`"
                )));
            }
        }

        Ok(AeadSuites(aead_suites))
    }
}

impl Default for AeadSuites {
    fn default() -> Self {
        AeadSuites(DEFAULT_OHTTP_AEAD_SUITES.to_vec())
    }
}

impl AeadSuites {
    pub fn as_slice(&self) -> &[AeadSuite] {
        &self.0
    }
}

/// The AEAD suites an egress advertises and accepts when `aead_suites` is
/// unset. AES-128-GCM stays first (the client picks the first supported suite
/// from the advertised list, and AES-128-GCM is the hardware-accelerated one).
pub const DEFAULT_OHTTP_AEAD_SUITES: [AeadSuite; 3] = [
    AeadSuite::Aes128Gcm,
    AeadSuite::Aes256Gcm,
    AeadSuite::ChaCha20Poly1305,
];

impl AeadSuite {
    pub const fn as_str(self) -> &'static str {
        match self {
            AeadSuite::Aes128Gcm => "aes128_gcm",
            AeadSuite::Aes256Gcm => "aes256_gcm",
            AeadSuite::ChaCha20Poly1305 => "chacha20_poly1305",
        }
    }

    pub(crate) fn to_ohttp_aead(self) -> ohttp::hpke::Aead {
        match self {
            AeadSuite::Aes128Gcm => ohttp::hpke::Aead::Aes128Gcm,
            AeadSuite::Aes256Gcm => ohttp::hpke::Aead::Aes256Gcm,
            AeadSuite::ChaCha20Poly1305 => ohttp::hpke::Aead::ChaCha20Poly1305,
        }
    }

    pub(crate) fn from_ohttp_aead(aead: ohttp::hpke::Aead) -> Self {
        match aead {
            ohttp::hpke::Aead::Aes128Gcm => AeadSuite::Aes128Gcm,
            ohttp::hpke::Aead::Aes256Gcm => AeadSuite::Aes256Gcm,
            ohttp::hpke::Aead::ChaCha20Poly1305 => AeadSuite::ChaCha20Poly1305,
        }
    }

    /// The full `(KDF, AEAD)` pair advertised in a key config. The KDF is
    /// fixed because the config exposes no KDF choice.
    pub(crate) fn to_symmetric_suite(self) -> ohttp::SymmetricSuite {
        ohttp::SymmetricSuite::new(ohttp::hpke::Kdf::HkdfSha256, self.to_ohttp_aead())
    }
}

impl std::fmt::Display for AeadSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{AeadSuite, AeadSuites};

    fn parse(text: &str) -> Result<AeadSuites, serde_json::Error> {
        serde_json::from_str(text)
    }

    #[test]
    fn parses_a_valid_list_in_order() {
        let suites = parse(r#"["aes256_gcm", "aes128_gcm", "chacha20_poly1305"]"#)
            .expect("valid list must parse");
        assert_eq!(
            suites.as_slice(),
            &[
                AeadSuite::Aes256Gcm,
                AeadSuite::Aes128Gcm,
                AeadSuite::ChaCha20Poly1305,
            ]
        );
    }

    #[test]
    fn rejects_an_empty_list() {
        let error = parse("[]").expect_err("empty list must fail");
        assert_eq!(
            error.to_string(),
            "aead_suites must not be empty; omit the field to use the default policy"
        );
    }

    #[test]
    fn rejects_a_duplicate_value() {
        let error = parse(r#"["aes256_gcm", "aes256_gcm"]"#).expect_err("duplicate must fail");
        assert_eq!(
            error.to_string(),
            "aead_suites contains duplicate value `aes256_gcm`"
        );
    }

    #[test]
    fn rejects_an_unknown_value() {
        let error = parse(r#"["aes192_gcm"]"#).expect_err("unknown value must fail");
        assert!(
            error.to_string().contains("unknown variant"),
            "unexpected message: {error}"
        );
    }

    #[test]
    fn value_matching_is_case_sensitive() {
        let error = parse(r#"["AES256_GCM"]"#).expect_err("uppercase must fail");
        assert!(
            error.to_string().contains("unknown variant"),
            "unexpected message: {error}"
        );
    }

    #[test]
    fn serializes_as_a_plain_array() {
        let suites = AeadSuites(vec![AeadSuite::Aes128Gcm, AeadSuite::ChaCha20Poly1305]);
        assert_eq!(
            serde_json::to_string(&suites).expect("serialize"),
            r#"["aes128_gcm","chacha20_poly1305"]"#
        );
    }
}

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use flatten_json_object::Flattener;
use serde_json::Value;

use crate::cert::dice::cbor::OCBR_TAG_EVIDENCE_ITA_TOKEN;
use crate::errors::*;
use crate::tee::claims::Claims;
use crate::tee::{DiceParseEvidenceOutput, GenericEvidence};

/// A JWT token issued by Intel Trust Authority.
///
/// This is the ITA equivalent of `CocoAsToken`. It wraps the raw JWT string
/// and implements `GenericEvidence` for DICE cert embedding and claims extraction.
#[derive(Clone)]
pub struct ItaToken {
    data: String,
}

impl ItaToken {
    pub fn new(token: String) -> Result<Self> {
        Ok(Self { data: token })
    }

    pub fn as_str(&self) -> &str {
        &self.data
    }

    pub fn into_str(self) -> String {
        self.data
    }

    pub fn exp(&self) -> Result<u64> {
        let split_token: Vec<&str> = self.data.split('.').collect();
        if split_token.len() != 3 {
            return Err(Error::ItaError("Illegal JWT format".to_string()));
        }

        let claims = URL_SAFE_NO_PAD
            .decode(split_token[1])
            .map_err(Error::Base64DecodeFailed)?;
        let claims_value =
            serde_json::from_slice::<Value>(&claims).map_err(Error::ParseJwtClaimsFailed)?;

        let Some(exp) = claims_value["exp"].as_u64() else {
            return Err(Error::MissingTokenField {
                detail: "token expiration unset".to_string(),
            });
        };

        Ok(exp)
    }
}

impl GenericEvidence for ItaToken {
    fn get_dice_cbor_tag(&self) -> u64 {
        OCBR_TAG_EVIDENCE_ITA_TOKEN
    }

    fn get_dice_raw_evidence(&self) -> Result<Vec<u8>> {
        Ok(self.data.as_bytes().to_owned())
    }

    fn get_claims(&self) -> Result<Claims> {
        let split_token: Vec<&str> = self.data.split('.').collect();
        if split_token.len() != 3 {
            return Err(Error::ItaError("Illegal ITA JWT format".to_string()));
        }
        let claims = URL_SAFE_NO_PAD
            .decode(split_token[1])
            .map_err(Error::Base64DecodeFailed)?;
        let claims_value: Value =
            serde_json::from_slice(&claims).map_err(Error::ParseJwtClaimsFailed)?;

        let flattened =
            Flattener::new()
                .flatten(&claims_value)
                .map_err(|e| Error::JwtClaimsFlattenFailed {
                    message: e.to_string(),
                })?;

        match flattened {
            Value::Object(m) => Ok(m),
            _ => Err(Error::ItaError(format!(
                "Invalid ITA claims value: {}",
                claims_value
            ))),
        }
    }

    fn create_evidence_from_dice(
        cbor_tag: u64,
        raw_evidence: &[u8],
    ) -> DiceParseEvidenceOutput<Self> {
        if cbor_tag == OCBR_TAG_EVIDENCE_ITA_TOKEN {
            return match std::str::from_utf8(raw_evidence) {
                Ok(token) => match Self::new(token.to_owned()) {
                    Ok(v) => DiceParseEvidenceOutput::Ok(v),
                    Err(e) => DiceParseEvidenceOutput::MatchButInvalid(e),
                },
                Err(e) => DiceParseEvidenceOutput::MatchButInvalid(Error::InvalidUtf8Slice(e)),
            };
        }
        DiceParseEvidenceOutput::NotMatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a structurally valid but unsigned JWT for parsing tests.
    /// Signature verification is not exercised here.
    fn make_jwt(claims: &serde_json::Value) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let sig = URL_SAFE_NO_PAD.encode(b"fake-sig");
        format!("{header}.{payload}.{sig}")
    }

    #[test]
    fn exp_extracted_from_claims() {
        let expected_exp = 1700000000u64;
        let jwt = make_jwt(&serde_json::json!({"sub": "test", "exp": expected_exp}));
        let token = ItaToken::new(jwt).unwrap();
        assert_eq!(token.exp().unwrap(), expected_exp);
    }

    #[test]
    fn exp_missing_returns_error() {
        let jwt = make_jwt(&serde_json::json!({"sub": "test"}));
        let token = ItaToken::new(jwt).unwrap();
        assert!(token.exp().is_err());
    }

    #[test]
    fn malformed_jwt_exp_error() {
        let token = ItaToken::new("not.a-jwt".into()).unwrap();
        assert!(token.exp().is_err());
    }

    #[test]
    fn dice_cbor_round_trip() {
        let jwt = make_jwt(&serde_json::json!({"sub": "test", "exp": 99}));
        let token = ItaToken::new(jwt.clone()).unwrap();
        assert_eq!(token.get_dice_cbor_tag(), OCBR_TAG_EVIDENCE_ITA_TOKEN);

        let raw = token.get_dice_raw_evidence().unwrap();
        let DiceParseEvidenceOutput::Ok(back) =
            ItaToken::create_evidence_from_dice(OCBR_TAG_EVIDENCE_ITA_TOKEN, &raw)
        else {
            panic!("expected DiceParseEvidenceOutput::Ok");
        };
        assert_eq!(back.as_str(), jwt);
    }

    #[test]
    fn wrong_tag_not_match() {
        assert!(matches!(
            ItaToken::create_evidence_from_dice(0xDEAD, b"anything"),
            DiceParseEvidenceOutput::NotMatch
        ));
    }

    #[test]
    fn get_claims_flattens_jwt_payload() {
        let jwt = make_jwt(&serde_json::json!({"sub": "test", "nested": {"a": 1}}));
        let token = ItaToken::new(jwt).unwrap();
        let claims = token.get_claims().unwrap();
        assert_eq!(claims.get("sub").and_then(|v| v.as_str()), Some("test"));
        assert!(claims.contains_key("nested.a"));
    }
}

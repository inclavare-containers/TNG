use super::super::evidence::CocoAsToken;
#[cfg(feature = "crypto-rustcrypto")]
use super::transparency;
use crate::tee::ReportData;
use crate::{errors::*, tee::GenericVerifier};

use serde_json::Value;

use std::collections::{HashMap, HashSet};

use super::ear_layout;
use super::token::{AttestationTokenVerifierConfig, TokenError, TokenVerifier};

pub(super) struct CommonCocoVerifier {
    /// The token verifier used to validate JWT.
    pub token_verifier: TokenVerifier,
    /// The policy ids to check.
    pub policy_ids: Vec<String>,
    /// Whether to verify the signer transparency claim in JWT tokens.
    pub verify_signer_transparency: bool,
}

impl CommonCocoVerifier {
    pub async fn verify_evidence_internal(
        &self,
        evidence: &CocoAsToken,
        report_data: &ReportData,
    ) -> Result<()> {
        let token = evidence.as_str();
        tracing::debug!(
            "Verify CoCo AS token \"{token}\" with policy ids: {:?}",
            self.policy_ids
        );

        let claims_value = self
            .token_verifier
            .verify(token.to_string())
            .await
            .map_err(|e| match e {
                TokenError::TokenVerificationFailed { source } => {
                    Error::CocoTokenVerifierError(source)
                }
            })?;

        let is_ear = if let Some(eat_profile) = claims_value.get("eat_profile") {
            if eat_profile != "tag:github.com,2024:confidential-containers/Trustee" {
                return Err(Error::UnsupportedEatProfile {
                    profile: eat_profile.to_string(),
                });
            }
            true
        } else {
            false
        };

        /* Check report_data matchs */
        if matches!(report_data, ReportData::None) {
            tracing::debug!("report_data is None — skipping runtime_data subset check");
        } else {
            let runtime_data_expected = crate::tee::wrap_runtime_data_as_structed(report_data)?;
            let runtime_data_in_token = if is_ear {
                // EAR JWT route. Both the draft-04 and the legacy claim
                // layouts are accepted.
                ear_layout::runtime_data(&claims_value)?
            } else {
                // Standard CoCo AS token route
                claims_value
                    .pointer("/customized_claims/runtime_data")
                    .ok_or_else(|| Error::MissingTokenField {
                        detail: "runtime_data".to_string(),
                    })?
            };

            let runtime_data_expected_map =
                runtime_data_expected
                    .as_object()
                    .ok_or_else(|| Error::MissingTokenField {
                        detail: "runtime_data_expected is not a map".to_string(),
                    })?;

            let runtime_data_in_token_map =
                runtime_data_in_token
                    .as_object()
                    .ok_or_else(|| Error::MissingTokenField {
                        detail: "runtime_data_in_token is not a map".to_string(),
                    })?;

            let is_subset = runtime_data_expected_map
                .iter()
                .all(|(key, value)| runtime_data_in_token_map.get(key) == Some(value));

            tracing::debug!(
                expected = ?runtime_data_expected_map,
                actually = ?runtime_data_in_token_map,
                is_subset,
                "compare runtime_data"
            );

            if !is_subset {
                return Err(Error::RuntimeDataMismatch);
            }
        } // end of report_data subset check (non-None branch)

        // Check expected policy-ids
        let allowed_policy_ids = if is_ear {
            // The claim layout is detected per submod.
            ear_layout::appraisal_policy_ids(&claims_value)?
        } else {
            /*
             * The content format of evaluation-reports is documented here: https://github.com/confidential-containers/trustee/blob/43d56f3a4a92a1cc691f63a8e1311bcc0d2b3fc8/attestation-service/docs/example.token.json#L6
             */
            claims_value
                .get("evaluation-reports")
                .and_then(|o| o.as_array())
                .ok_or_else(|| Error::MissingTokenField {
                    detail: "evaluation-reports".to_string(),
                })?
                .iter()
                .enumerate()
                .map(|(i, o)| -> Result<_> {
                    let policy_id =
                        o.get("policy-id").and_then(|v| v.as_str()).ok_or_else(|| {
                            Error::MissingTokenField {
                                detail: format!("evaluation-reports[{i}].policy-id"),
                            }
                        })?;
                    Ok(policy_id.to_string())
                })
                .collect::<Result<HashSet<_>>>()?
        };

        /* We accept the token only when all of the expected policy ids has { "allow": true } */
        for policy_id in &self.policy_ids {
            if !allowed_policy_ids.contains(policy_id.as_str()) {
                return Err(Error::PolicyEvaluationFailed {
                    policy_id: policy_id.to_string(),
                });
            }
        }

        // Verify signer transparency claim if enabled
        #[cfg(feature = "crypto-rustcrypto")]
        if self.verify_signer_transparency {
            transparency::verify_signer_transparency(token).map_err(|e| {
                Error::SignerTransparencyVerificationFailed {
                    detail: e.to_string(),
                }
            })?;
        }
        #[cfg(not(feature = "crypto-rustcrypto"))]
        let _ = self.verify_signer_transparency; // field exists but feature not enabled

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Signed-token coverage for the diagnostics error. These mint a JWT and
    /// call `verify_evidence_internal`, so the JWS check and the claims
    /// traversal between the token and the extension parse are covered too.
    /// The parse itself is unit-tested in `ear_layout`.
    #[cfg(feature = "crypto-rustcrypto")]
    mod signed_token {
        use super::*;
        use crate::tee::coco::diagnostics::APPRAISAL_DIAGNOSTICS_EXTENSION;
        use crate::tee::coco::verifier::token::AttestationTokenVerifierConfig;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::pkcs8::EncodePrivateKey;
        use rand::rngs::OsRng;

        /// Sign `claims` with a fresh P-256 key and run them through the
        /// production verifier entry point. The token header carries the
        /// matching public JWK and the verifier runs with `insecure_key`, so no
        /// certificate chain is involved.
        async fn verify_signed_claims(claims: Value) -> Result<()> {
            let token_verifier = TokenVerifier::from_config(AttestationTokenVerifierConfig {
                insecure_key: true,
                ..Default::default()
            })
            .await
            .expect("build token verifier");
            let verifier = CommonCocoVerifier {
                token_verifier,
                policy_ids: vec!["default".to_string()],
                verify_signer_transparency: false,
            };

            let secret = p256::SecretKey::random(&mut OsRng);
            let key = EncodingKey::from_ec_der(secret.to_pkcs8_der().expect("pkcs8").as_bytes());

            // Uncompressed SEC1 point: 0x04 || x || y, 32 bytes per coordinate.
            let point = secret.public_key().to_encoded_point(false);
            let point = point.as_bytes();
            let mut header = Header::new(Algorithm::ES256);
            header.jwk = Some(
                serde_json::from_value(json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "alg": "ES256",
                    "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
                    "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
                }))
                .expect("test public JWK"),
            );
            let token = encode(&header, &claims, &key).expect("sign token");

            let token = CocoAsToken::new(token).expect("wrap token");
            verifier
                .verify_evidence_internal(&token, &ReportData::None)
                .await
        }

        fn ear_claims(diagnostics: Option<Value>) -> Value {
            let mut submod = json!({
                "ear.appraisal-policy-id": "default",
                "ear.status": "contraindicated",
                "ear.trustworthiness-vector": {"executables": 0, "hardware": 2},
            });
            if let Some(diagnostics) = diagnostics {
                // The broker carries a policy's map-valued extension as a
                // JSON string; see the parse in `parse_appraisal_diagnostics`.
                submod[APPRAISAL_DIAGNOSTICS_EXTENSION] = Value::String(diagnostics.to_string());
            }
            json!({
                "eat_profile": "tag:github.com,2024:confidential-containers/Trustee",
                // The JWS validation requires an `exp` claim; its value is not
                // checked in tests.
                "exp": 4102444800u64,
                "submods": {"cpu0": submod},
            })
        }

        #[tokio::test]
        async fn signed_token_with_diagnostics_reports_the_failed_check() {
            let diagnostics = json!({
                "failed": [{
                    "dimension": "executables",
                    "check": "com.alibabacloud.container.image.vllm",
                    "expected": "sha256:85a7",
                    "actual": ["sha256:95a7"],
                    "reason": "mismatch",
                }]
            });

            let error = verify_signed_claims(ear_claims(Some(diagnostics)))
                .await
                .expect_err("non-affirming token must be rejected");

            match &error {
                Error::EarStatusNotAffirmingWithDiagnostics { diagnostics, .. } => {
                    assert_eq!(diagnostics.failed.len(), 1);
                    assert_eq!(
                        diagnostics.failed[0].check,
                        "com.alibabacloud.container.image.vllm"
                    );
                }
                other => panic!("expected structured diagnostics error, got {other:?}"),
            }

            let rendered = error.to_string();
            assert!(rendered.contains("failed checks:"), "{rendered}");
            assert!(
                rendered.contains("com.alibabacloud.container.image.vllm"),
                "{rendered}"
            );
            assert!(rendered.contains(r#"expected "sha256:85a7""#), "{rendered}");
            assert!(rendered.contains(r#"actual ["sha256:95a7"]"#), "{rendered}");
            assert!(rendered.contains("reason mismatch"), "{rendered}");
        }

        #[tokio::test]
        async fn signed_token_with_empty_diagnostics_keeps_the_plain_error() {
            for diagnostics in [json!({}), json!({"failed": []})] {
                let error = verify_signed_claims(ear_claims(Some(diagnostics)))
                    .await
                    .expect_err("non-affirming token must be rejected");

                assert!(
                    matches!(error, Error::EarStatusNotAffirming { .. }),
                    "{error:?}"
                );
                assert!(!error.to_string().contains("failed checks:"), "{error}");
                assert!(
                    !error.to_string().contains("no failed checks reported"),
                    "{error}"
                );
            }
        }

        #[tokio::test]
        async fn signed_token_without_diagnostics_keeps_the_plain_error() {
            let error = verify_signed_claims(ear_claims(None))
                .await
                .expect_err("non-affirming token must be rejected");

            assert!(
                matches!(error, Error::EarStatusNotAffirming { .. }),
                "{error:?}"
            );
            assert!(!error.to_string().contains("failed checks:"), "{error}");
        }
    }
}

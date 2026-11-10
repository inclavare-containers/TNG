//! Tests that drive the shared CoCo verifier through a real signed token.

/// Signed-token coverage for the diagnostics error. These mint a JWT and
/// call `verify_evidence_internal`, so the JWS check and the claims
/// traversal between the token and the extension parse are covered too.
/// The parse itself is unit-tested in `ear_layout`.
#[cfg(feature = "crypto-rustcrypto")]
mod signed_token {
    use super::super::common::CommonCocoVerifier;
    use crate::errors::*;
    use crate::tee::coco::diagnostics::APPRAISAL_DIAGNOSTICS_EXTENSION;
    use crate::tee::coco::evidence::CocoAsToken;
    use crate::tee::coco::verifier::token::{AttestationTokenVerifierConfig, TokenVerifier};
    use crate::tee::ReportData;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::EncodePrivateKey;
    use rand::rngs::OsRng;
    use serde_json::{json, Value};

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

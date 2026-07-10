//! Wasm-native builtin Attestation Service converter.
//!
//! Mirrors `BuiltinCocoConverter` (native, trustee-backed) but does NOT depend on the
//! `attestation-service` crate (whose unconditional `openssl` dep has no wasm target).
//! Instead it generates an ECDSA P-256 key with `rcgen` and signs an EAR-shaped JWT
//! with `jsonwebtoken`, embedding the AS public JWK in the JWT header. The paired
//! `BuiltinCocoVerifier` trusts that JWK (`insecure_key: true`, closed system).
//!
//! Appraisal is TrustAll only — no TEE verifier compiles for wasm. `Sample` reference
//! values are accepted for config compatibility but not appraised (the converter always
//! issues an affirming token).
//!
//! The module compiles on BOTH native (under `--features __builtin-as-wasm`) and wasm,
//! so a native `#[cfg(test)]` round-trip can validate the sign/verify correctness.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
    EllipticCurveKeyType, Jwk, KeyAlgorithm,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use serde_json::{json, Value};

use super::super::evidence::{CocoAsToken, CocoEvidence};
use super::builtin_config::{PolicyConfig, ReferenceValueConfig};
use super::CoCoNonce;
use crate::errors::*;
use crate::tee::coco::verifier::builtin::BuiltinCocoVerifier;
use crate::tee::GenericConverter;

/// Token validity — far-future unix timestamp (2100-01-01). The closed builtin system
/// (same TNG instance signs and verifies) does not require a wall-clock-based expiry.
/// `jsonwebtoken` validates `exp` by default (disabled under `cfg(test)`), so a fixed
/// far-future value keeps the token valid without depending on `web-time` (which is a
/// wasm-target-only dependency and thus unavailable on the native test path).
const TOKEN_EXP: u64 = 4_102_444_800; // 2100-01-01T00:00:00Z

pub struct WasmBuiltinCocoConverter {
    /// PKCS#8 DER private key bytes (used with `EncodingKey::from_ec_der`;
    /// the workspace disables jsonwebtoken's `use_pem` feature, so `from_ec_pem`
    /// is unavailable).
    as_key_der: Vec<u8>,
    /// The AS public key embedded in the JWT header (`header.jwk`). The paired
    /// verifier reads this with `insecure_key: true`.
    as_public_jwk: Jwk,
}

impl WasmBuiltinCocoConverter {
    /// Create a new converter with the given policy and reference values.
    ///
    /// On wasm only `TrustAll` and `HardwareOnly` are accepted (no regorus policy
    /// engine compiles for wasm). `HardwareWithReferenceValues`, `Inline`, and `Path`
    /// are REJECTED — the match returns `Error::WasmBuiltinPolicyNotSupported` because
    /// no regorus/AS policy engine compiles for wasm. The wasm converter does not
    /// appraise TEE evidence (it always issues an affirming token).
    pub async fn new(
        policy: &PolicyConfig,
        reference_values: &[ReferenceValueConfig],
    ) -> Result<Self> {
        // Validate policy is wasm-supported.
        match policy {
            PolicyConfig::TrustAll | PolicyConfig::HardwareOnly => {}
            PolicyConfig::HardwareWithReferenceValues
            | PolicyConfig::Inline { .. }
            | PolicyConfig::Path { .. } => {
                return Err(Error::WasmBuiltinPolicyNotSupported {
                    policy: format!("{:?}", policy),
                });
            }
        }
        // Validate reference-value kinds.
        for rv in reference_values {
            match rv {
                ReferenceValueConfig::Sample { .. } => {}
                ReferenceValueConfig::Slsa { .. }
                | ReferenceValueConfig::ReleaseManifest { .. } => {
                    return Err(Error::WasmBuiltinReferenceValueKindNotSupported {
                        kind: format!("{:?}", rv),
                    });
                }
            }
        }
        Self::generate_keys().map(|(key_der, jwk)| Self {
            as_key_der: key_der,
            as_public_jwk: jwk,
        })
    }

    /// Generate an ECDSA P-256 keypair with `rcgen` and build the public JWK.
    ///
    /// Returns the PKCS#8 DER private key (for `EncodingKey::from_ec_der`) and the
    /// public JWK (struct-literal form, matching the Task 1 spike test).
    fn generate_keys() -> Result<(Vec<u8>, Jwk)> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|source| Error::WasmBuiltinKeyGenFailed { source })?;
        let key_der = key_pair.serialize_der();

        // Build the public JWK from the uncompressed EC point.
        // `public_key_der()` returns a SubjectPublicKeyInfo DER; the uncompressed EC
        // point is the LAST 65 bytes (`0x04 || x(32) || y(32)`) for P-256.
        let pub_der = key_pair.public_key_der();
        let point = &pub_der[pub_der.len() - 65..];
        let x = URL_SAFE_NO_PAD.encode(&point[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&point[33..65]);

        let jwk = Jwk {
            common: CommonParameters {
                key_algorithm: Some(KeyAlgorithm::ES256),
                key_id: Some("wasm-builtin-as".to_string()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P256,
                x,
                y,
            }),
        };

        Ok((key_der, jwk))
    }

    /// Sign a JWT with the AS key, embedding the AS public JWK in the header.
    fn sign_jwt(&self, claims: &serde_json::Value) -> Result<String> {
        let header = Header {
            typ: Some("JWT".to_string()),
            alg: Algorithm::ES256,
            jwk: Some(self.as_public_jwk.clone()),
            ..Default::default()
        };
        let enc_key = EncodingKey::from_ec_der(&self.as_key_der);
        encode(&header, claims, &enc_key)
            .map_err(|source| Error::WasmBuiltinTokenSignFailed { source })
    }

    pub async fn new_verifier(&self) -> Result<BuiltinCocoVerifier> {
        BuiltinCocoVerifier::new_insecure().await
    }
}

#[async_trait::async_trait]
impl GenericConverter for WasmBuiltinCocoConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;
    type Nonce = CoCoNonce;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        // Parse runtime data (a JSON object) to embed as runtime_data_claims.
        let runtime_data: Value = serde_json::from_str(in_evidence.aa_runtime_data_ref())
            .map_err(Error::ParseRuntimeDataJsonFailed)?;

        // EAR JWT claims matching the verifier's pointer checks (see
        // `verify_evidence_internal` in verifier/common.rs):
        //   /eat_profile                          == "tag:github.com,2024:confidential-containers/Trustee"
        //   /submods/cpu0/ear.appraisal-policy-id  == "default"
        //   /submods/cpu0/ear.status               == "affirming"
        //   /submods/cpu0/ear.trustworthiness-vector  (must exist; value not checked)
        //   /submods/cpu0/ear.veraison.annotated-evidence/runtime_data_claims (a JSON map,
        //       must be a superset of the verifier's expected runtime data)
        //   exp (jsonwebtoken validates by default)
        let claims = json!({
            "eat_profile": "tag:github.com,2024:confidential-containers/Trustee",
            "exp": TOKEN_EXP,
            "submods": {
                "cpu0": {
                    "ear.appraisal-policy-id": "default",
                    "ear.status": "affirming",
                    "ear.trustworthiness-vector": {},
                    "ear.veraison.annotated-evidence": {
                        "runtime_data_claims": runtime_data,
                    }
                }
            }
        });

        // Embed the AS public JWK in the JWT header — the verifier reads `header.jwk`
        // (with `insecure_key: true` it trusts the embedded key directly).
        let token = self.sign_jwt(&claims)?;

        CocoAsToken::new(token)
    }

    async fn get_nonce(&self) -> Result<Self::Nonce> {
        // Minimal signed challenge JWT (random nonce). Uses rand OsRng which is
        // backed by getrandom on both native and wasm (the wasm-js backend is wired
        // via the tng-wasm crate's getrandom dep).
        use rand::RngCore;
        let mut nonce_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let claims = json!({
            "nonce": URL_SAFE_NO_PAD.encode(nonce_bytes),
            "exp": TOKEN_EXP,
        });
        let token = self.sign_jwt(&claims)?;
        Ok(CoCoNonce::Jwt(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::{GenericVerifier, ReportData};
    use kbs_types::Tee;

    /// Native correctness gate: the wasm builtin converter signs an EAR-JWT and the
    /// paired `BuiltinCocoVerifier` (insecure_key path) verifies it end-to-end.
    ///
    /// Uses an empty runtime-data map (`"{}"`) on both sides so the
    /// runtime-data subset check passes trivially, isolating the sign/verify gate
    /// from runtime-data matching.
    #[tokio::test]
    async fn wasm_builtin_sign_verify_roundtrip() {
        // Build a CocoEvidence whose aa_runtime_data is an empty JSON map. The wasm
        // converter embeds this as runtime_data_claims; the verifier checks that the
        // expected runtime data (derived from report_data) is a subset.
        let evidence = CocoEvidence::new_for_wasm_builtin(Tee::Sample, "{}".to_string())
            .expect("valid evidence");

        let converter = WasmBuiltinCocoConverter::new(&PolicyConfig::TrustAll, &[])
            .await
            .expect("converter new");
        let verifier = converter.new_verifier().await.expect("verifier new");

        let token = converter.convert(&evidence).await.expect("convert");

        // ReportData::Claims(empty map) wraps to {} (see wrap_runtime_data_as_structed),
        // which is a subset of the embedded {} runtime_data_claims.
        let report_data = ReportData::Claims(serde_json::Map::new());
        verifier
            .verify_evidence(&token, &report_data)
            .await
            .expect("verify_evidence must succeed for the builtin-issued token");
    }
}

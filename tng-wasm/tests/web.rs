//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]
#![feature(impl_trait_in_fn_trait_return)]

extern crate wasm_bindgen_test;

use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

// Configure tests to run in the browser environment.
wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_init() -> Result<(), JsError> {
    tng_wasm::init_tng();

    Ok(())
}

/// De-risk spike: rcgen keygen + jsonwebtoken sign/verify works on wasm32-unknown-unknown.
#[wasm_bindgen_test]
async fn rcgen_jsonwebtoken_sign_verify_roundtrip() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
        EllipticCurveKeyType, Jwk, KeyAlgorithm,
    };
    use jsonwebtoken::{
        decode, decode_header, Algorithm, DecodingKey, EncodingKey, Header, Validation,
    };
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    // 1. Generate an ECDSA P-256 keypair with rcgen.
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let key_der = key_pair.serialize_der();

    // 2. Extract the uncompressed public key point -> JWK (x, y base64url).
    let pub_der = key_pair.public_key_der();
    // pub_der is a SubjectPublicKeyInfo DER; the EC public key point is the last 65 bytes
    // (0x04 || x(32) || y(32)) for P-256.
    assert!(pub_der.len() >= 65);
    let point = &pub_der[pub_der.len() - 65..];
    assert_eq!(point[0], 0x04);
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

    // 3. Sign a JWT with header.jwk set.
    let header = Header {
        typ: Some("JWT".to_string()),
        alg: Algorithm::ES256,
        jwk: Some(jwk.clone()),
        ..Default::default()
    };
    // exp = far future (jsonwebtoken validates exp by default).
    let claims = serde_json::json!({
        "eat_profile": "tag:github.com,2024:confidential-containers/Trustee",
        "exp": 4_102_444_800u64, // 2100-01-01
        "submods": {
            "cpu0": {
                "ear.appraisal-policy-id": "default",
                "ear.status": "affirming",
                "ear.trustworthiness-vector": {},
                "ear.veraison.annotated-evidence": {
                    "runtime_data_claims": {}
                }
            }
        }
    });
    let enc_key = EncodingKey::from_ec_der(&key_der);
    let token = jsonwebtoken::encode(&header, &claims, &enc_key).unwrap();

    // 4. The header must carry the jwk (this is what JwkAttestationTokenVerifier reads).
    let decoded_header = decode_header(&token).unwrap();
    assert!(decoded_header.jwk.is_some(), "header must embed jwk");

    // 5. Verify signature against the embedded JWK (insecure_key path).
    let dkey = DecodingKey::from_jwk(&jwk).unwrap();
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_nbf = true;
    let token_data = decode::<serde_json::Value>(&token, &dkey, &validation).unwrap();
    assert_eq!(
        token_data.claims["submods"]["cpu0"]["ear.status"],
        "affirming"
    );
}

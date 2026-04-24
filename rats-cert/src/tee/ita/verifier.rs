use std::collections::HashMap;
use std::sync::LazyLock;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;

use crate::errors::*;
use crate::tee::{GenericVerifier, ReportData};

use super::token::ItaToken;

const ITA_JWKS_PATH: &str = "/certs";

/// Known `iss` (issuer) claim values that ITA tokens may contain.
const ITA_TOKEN_ISSUERS: &[&str] = &[
    "https://portal.trustauthority.intel.com",
    "Intel Trust Authority",
];

/// Process-global JWKS cache, keyed by JWKS URL.
static JWKS_CACHE: LazyLock<RwLock<HashMap<String, Vec<CachedKey>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub struct ItaVerifier {
    jwks_url: String,
    policy_ids: Vec<String>,
}

impl ItaVerifier {
    pub fn new(ita_jwks_base_addr: &str, policy_ids: &[String]) -> Result<Self> {
        Ok(Self {
            jwks_url: format!(
                "{}{}",
                ita_jwks_base_addr.trim_end_matches('/'),
                ITA_JWKS_PATH
            ),
            policy_ids: policy_ids.to_vec(),
        })
    }

    async fn verify_jwt(&self, token: &str) -> Result<Value> {
        if !self.jwks_url.starts_with("https://") {
            return Err(Error::ItaError(format!(
                "JWKS URL must use HTTPS: {}",
                self.jwks_url
            )));
        }

        let header = decode_header(token).map_err(Error::ItaVerifyTokenFailed)?;
        let kid = header
            .kid
            .ok_or_else(|| Error::ItaError("ITA JWT header missing kid".to_string()))?;

        if header.alg != Algorithm::PS384 {
            return Err(Error::ItaError(format!(
                "Unexpected JWT algorithm {:?}, expected PS384",
                header.alg
            )));
        }

        // Try with cached keys first
        if let Some(claims) = self.try_cached_verify(token, &kid).await? {
            return Ok(claims);
        }

        // Refresh and retry
        self.refresh_jwks().await?;

        if let Some(claims) = self.try_cached_verify(token, &kid).await? {
            return Ok(claims);
        }

        Err(Error::ItaError(format!(
            "No JWKS key found matching kid={kid} (even after refresh)"
        )))
    }

    async fn try_cached_verify(&self, token: &str, kid: &str) -> Result<Option<Value>> {
        let cache = JWKS_CACHE.read().await;
        let keys = match cache.get(&self.jwks_url) {
            Some(k) => k,
            None => return Ok(None),
        };
        let key = match keys.iter().find(|k| k.kid == kid) {
            Some(k) => k,
            None => return Ok(None),
        };

        let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e)
            .map_err(Error::ItaVerifyTokenFailed)?;

        let mut validation = Validation::new(Algorithm::PS384);
        validation.set_required_spec_claims(&["exp", "iss"]);
        validation.set_issuer(ITA_TOKEN_ISSUERS);
        validation.validate_exp = true;

        let token_data = decode::<Value>(token, &decoding_key, &validation)
            .map_err(Error::ItaVerifyTokenFailed)?;

        Ok(Some(token_data.claims))
    }

    async fn refresh_jwks(&self) -> Result<()> {
        let jwks_url = self.jwks_url.clone();

        let fut = async move {
            let client = Client::new();
            let resp = client
                .get(&jwks_url)
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|e| Error::ItaHttpRequestFailed {
                    endpoint: jwks_url.clone(),
                    source: e,
                })?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(Error::ItaHttpResponseError {
                    endpoint: jwks_url,
                    status_code: status.as_u16(),
                    response_body: body,
                });
            }

            let jwks: JwksResponse = resp
                .json()
                .await
                .map_err(|e| Error::ItaError(format!("Failed to parse JWKS response: {e}")))?;

            Ok(jwks
                .keys
                .into_iter()
                .map(|k| CachedKey {
                    kid: k.kid,
                    n: k.n,
                    e: k.e,
                })
                .collect::<Vec<CachedKey>>())
        };

        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        let keys = tokio_with_wasm::task::spawn(fut)
            .await
            .map_err(|e| Error::ItaError(format!("Failed to spawn JWKS refresh task: {e}")))
            .and_then(|e| e)?;
        #[cfg(not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        )))]
        let keys = fut.await?;

        let mut cache = JWKS_CACHE.write().await;
        cache.insert(self.jwks_url.clone(), keys);

        Ok(())
    }

    fn check_runtime_data_binding(claims: &Value, report_data: &ReportData) -> Result<()> {
        let runtime_data_expected = crate::tee::wrap_runtime_data_as_structed(report_data)?;

        let expected_map =
            runtime_data_expected
                .as_object()
                .ok_or_else(|| Error::IncompatibleTypes {
                    detail: "runtime_data_expected is not a map".to_string(),
                })?;

        if expected_map.is_empty() {
            return Ok(());
        }

        let tdx_claims = claims.get("tdx");

        let runtime_data_in_token = tdx_claims
            .and_then(|tdx| tdx.get("attester_runtime_data"))
            .or_else(|| tdx_claims.and_then(|tdx| tdx.get("attester_held_data")));

        let Some(runtime_data_in_token) = runtime_data_in_token else {
            return Err(Error::ItaError(
                "ITA token missing attester_runtime_data/attester_held_data in tdx claims"
                    .to_string(),
            ));
        };

        let token_map =
            runtime_data_in_token
                .as_object()
                .ok_or_else(|| Error::IncompatibleTypes {
                    detail: "runtime_data_in_token is not a map".to_string(),
                })?;

        let is_subset = expected_map
            .iter()
            .all(|(key, value)| token_map.get(key) == Some(value));

        if !is_subset {
            tracing::debug!(
                expected = ?expected_map,
                in_token = ?token_map,
                "ITA runtime_data subset check failed"
            );
            return Err(Error::RuntimeDataMismatch);
        }

        Ok(())
    }

    fn check_policy_matching(&self, claims: &Value) -> Result<()> {
        if let Some(unmatched) = claims.get("policy_ids_unmatched") {
            if let Some(arr) = unmatched.as_array() {
                if !arr.is_empty() {
                    let ids: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
                        .collect();
                    return Err(Error::ItaError(format!(
                        "ITA token has unmatched policy IDs: {ids:?}"
                    )));
                }
            } else {
                return Err(Error::ItaError(
                    "policy_ids_unmatched is not an array".to_string(),
                ));
            }
        }

        if self.policy_ids.is_empty() {
            return Ok(());
        }

        if let Some(matched) = claims.get("policy_ids_matched") {
            if let Some(arr) = matched.as_array() {
                let matched_ids: std::collections::HashSet<&str> = arr
                    .iter()
                    .filter_map(|v| v.get("id").and_then(|id| id.as_str()))
                    .collect();

                for expected_id in &self.policy_ids {
                    if !matched_ids.contains(expected_id.as_str()) {
                        return Err(Error::ItaError(format!(
                            "Expected policy ID '{expected_id}' not found in policy_ids_matched"
                        )));
                    }
                }
            } else {
                return Err(Error::ItaError(
                    "policy_ids_matched is not an array".to_string(),
                ));
            }
        } else {
            return Err(Error::ItaError(
                "ITA token missing policy_ids_matched, but policy_ids are configured".to_string(),
            ));
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl GenericVerifier for ItaVerifier {
    type Evidence = ItaToken;

    async fn verify_evidence(&self, evidence: &ItaToken, report_data: &ReportData) -> Result<()> {
        let token = evidence.as_str();
        tracing::debug!("Verifying ITA token with policy_ids: {:?}", self.policy_ids);

        let claims = self.verify_jwt(token).await?;
        Self::check_runtime_data_binding(&claims, report_data)?;
        self.check_policy_matching(&claims)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// JWKS types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Deserialize)]
struct JwkKey {
    kid: String,
    #[allow(dead_code)]
    kty: String,
    #[serde(default)]
    #[allow(dead_code)]
    alg: String,
    n: String,
    e: String,
}

#[derive(Clone)]
struct CachedKey {
    kid: String,
    n: String,
    e: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use serde_json::json;

    fn verifier(policy_ids: &[&str]) -> ItaVerifier {
        let ids: Vec<String> = policy_ids.iter().copied().map(String::from).collect();
        ItaVerifier::new("https://portal.trustauthority.intel.com", &ids).unwrap()
    }

    /// Generate an RSA key pair, sign a JWT with PS384, and pre-populate JWKS_CACHE
    /// so that `verify_jwt` can succeed without any network call.
    async fn setup_cached_key(jwks_url: &str, kid: &str, claims: &Value) -> String {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        {
            let mut cache = JWKS_CACHE.write().await;
            cache.insert(
                jwks_url.to_string(),
                vec![CachedKey {
                    kid: kid.to_string(),
                    n,
                    e,
                }],
            );
        }

        let pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        let mut header = jsonwebtoken::Header::new(Algorithm::PS384);
        header.kid = Some(kid.to_string());
        jsonwebtoken::encode(&header, claims, &encoding_key).unwrap()
    }

    // ---- verify_jwt happy path ----

    #[tokio::test]
    async fn verify_jwt_with_cached_key_succeeds() {
        let base = "https://test-verify-happy.example.com";
        let jwks_url = format!("{base}{ITA_JWKS_PATH}");
        let sub = "test-subject";
        let claims = json!({
            "iss": ITA_TOKEN_ISSUERS[1],
            "exp": 9999999999u64,
            "sub": sub
        });
        let token = setup_cached_key(&jwks_url, "test-kid-1", &claims).await;

        let v = ItaVerifier::new(base, &[]).unwrap();
        let result = v.verify_jwt(&token).await.unwrap();
        assert_eq!(result["sub"], sub);
    }

    // ---- verify_jwt error paths ----

    #[tokio::test]
    async fn verify_jwt_rejects_non_https() {
        let v = ItaVerifier::new("http://bad.example.com", &[]).unwrap();
        let err = v.verify_jwt("any.jwt.here").await.unwrap_err();
        assert!(
            matches!(&err, Error::ItaError(msg) if msg.contains("HTTPS")),
            "expected HTTPS error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_jwt_rejects_missing_kid() {
        let v = verifier(&[]);
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"PS384"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"test"}"#);
        let token = format!("{header}.{payload}.fake-sig");
        let err = v.verify_jwt(&token).await.unwrap_err();
        assert!(
            matches!(&err, Error::ItaError(msg) if msg.contains("kid")),
            "expected missing kid error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_jwt_rejects_wrong_algorithm() {
        let v = verifier(&[]);
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"k1"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"test"}"#);
        let token = format!("{header}.{payload}.fake-sig");
        let err = v.verify_jwt(&token).await.unwrap_err();
        assert!(
            matches!(&err, Error::ItaError(msg) if msg.contains("PS384")),
            "expected algorithm error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_jwt_kid_not_in_cache_fails() {
        let base = "https://test-kid-miss.example.com";
        let jwks_url = format!("{base}{ITA_JWKS_PATH}");
        let claims = json!({
            "iss": ITA_TOKEN_ISSUERS[1],
            "exp": 9999999999u64,
        });
        let token = setup_cached_key(&jwks_url, "cached-kid", &claims).await;

        // Replace the kid in the token header to cause a mismatch
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"PS384","kid":"unknown-kid"}"#);
        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!("{header}.{}.{}", parts[1], parts[2]);

        let v = ItaVerifier::new(base, &[]).unwrap();
        let err = v.verify_jwt(&tampered).await.unwrap_err();
        assert!(
            matches!(err, Error::ItaHttpRequestFailed { .. }),
            "expected refresh failure for unknown kid, got: {err:?}"
        );
    }

    // ---- check_policy_matching ----

    #[test]
    fn policy_no_ids_configured_passes() {
        let v = verifier(&[]);
        v.check_policy_matching(&json!({})).unwrap();
    }

    #[test]
    fn policy_unmatched_ids_fail() {
        let v = verifier(&[]);
        let claims = json!({
            "policy_ids_unmatched": [{"id": "bad-policy"}]
        });
        assert!(v.check_policy_matching(&claims).is_err());
    }

    #[test]
    fn policy_expected_id_present_passes() {
        let v = verifier(&["p1"]);
        let claims = json!({
            "policy_ids_matched": [{"id": "p1"}]
        });
        v.check_policy_matching(&claims).unwrap();
    }

    #[test]
    fn policy_expected_id_missing_fails() {
        let v = verifier(&["p1", "p2"]);
        let claims = json!({
            "policy_ids_matched": [{"id": "p1"}]
        });
        assert!(v.check_policy_matching(&claims).is_err());
    }

    #[test]
    fn policy_ids_configured_but_field_missing_fails() {
        let v = verifier(&["p1"]);
        assert!(v.check_policy_matching(&json!({})).is_err());
    }

    #[test]
    fn policy_ids_matched_not_array_fails() {
        let v = verifier(&["p1"]);
        let claims = json!({"policy_ids_matched": "not-an-array"});
        assert!(v.check_policy_matching(&claims).is_err());
    }

    // ---- check_runtime_data_binding ----

    #[test]
    fn runtime_data_binding_claims_subset_passes() {
        let claims = json!({
            "tdx": {
                "attester_runtime_data": {"key": "value", "extra": true}
            }
        });
        let report_data =
            ReportData::Claims(serde_json::from_value(json!({"key": "value"})).unwrap());
        ItaVerifier::check_runtime_data_binding(&claims, &report_data).unwrap();
    }

    #[test]
    fn runtime_data_binding_mismatch_fails() {
        let claims = json!({
            "tdx": {
                "attester_runtime_data": {"key": "wrong"}
            }
        });
        let report_data =
            ReportData::Claims(serde_json::from_value(json!({"key": "value"})).unwrap());
        assert!(ItaVerifier::check_runtime_data_binding(&claims, &report_data).is_err());
    }

    #[test]
    fn runtime_data_binding_missing_tdx_claims_fails() {
        let report_data =
            ReportData::Claims(serde_json::from_value(json!({"key": "value"})).unwrap());
        assert!(ItaVerifier::check_runtime_data_binding(&json!({}), &report_data).is_err());
    }

    #[test]
    fn runtime_data_binding_empty_claims_skips_check() {
        let report_data = ReportData::Claims(serde_json::Map::new());
        ItaVerifier::check_runtime_data_binding(&json!({}), &report_data).unwrap();
        ItaVerifier::check_runtime_data_binding(
            &json!({"tdx": {"attester_runtime_data": {"extra": true}}}),
            &report_data,
        )
        .unwrap();
    }

    #[test]
    fn runtime_data_binding_non_object_token_data_fails() {
        let report_data =
            ReportData::Claims(serde_json::from_value(json!({"key": "value"})).unwrap());

        for non_object in [json!("a string"), json!(0xBAD), json!([1, 2]), json!(null)] {
            let claims = json!({
                "tdx": {
                    "attester_runtime_data": non_object,
                }
            });
            assert!(
                ItaVerifier::check_runtime_data_binding(&claims, &report_data).is_err(),
                "should reject non-object attester_runtime_data: {claims}"
            );
        }
    }
}

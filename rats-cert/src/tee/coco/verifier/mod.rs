use super::evidence::{CocoAsToken, CocoEvidence};
use crate::cert::verify::AttestationServiceConfig;
use crate::tee::ReportData;
use crate::{errors::*, tee::GenericVerifier};

use serde_json::Value;

use std::collections::{HashMap, HashSet};

mod token;
use token::{AttestationTokenVerifierConfig, TokenVerifier};

pub struct CocoVerifier {
    /// The token verifier used for validating JWT.
    token_verifier: TokenVerifier,
    /// The policy ids need to check
    policy_ids: Vec<String>,
}

impl CocoVerifier {
    pub async fn new(
        as_addr_config: Option<AttestationServiceConfig>,
        trusted_certs_paths: &Option<Vec<String>>,
        policy_ids: &Vec<String>,
    ) -> Result<Self> {
        if let Some(as_addr_config) = &as_addr_config {
            if as_addr_config.as_is_grpc {
                return Err(Error::kind_with_msg(
                    ErrorKind::CocoVerifyTokenFailed,
                    "Grpc is not supported for CoCo AS token verification",
                ));
            }
        }

        let trusted_certs_paths = trusted_certs_paths.clone().unwrap_or_default();

        // Check if any trust source is provided
        let has_trust_source = !trusted_certs_paths.is_empty() || as_addr_config.is_some();

        if !has_trust_source {
            Err(Error::kind_with_msg(
                ErrorKind::CocoVerifyTokenFailed,
                "No trust source provided (neither trusted_certs_paths nor as_addr)".to_string(),
            ))?
        }

        let config = AttestationTokenVerifierConfig {
            trusted_certs_paths,
            trusted_jwk_sets: Default::default(),
            as_addr: as_addr_config.as_ref().map(|config| config.as_addr.clone()),
            as_headers: as_addr_config
                .as_ref()
                .map(|config| config.as_headers.clone()),
            insecure_key: false,
        };

        let token_verifier = TokenVerifier::from_config(config).await?;

        Ok(Self {
            token_verifier,
            policy_ids: policy_ids.to_owned(),
        })
    }

    async fn verify_evidence_internal(
        &self,
        evidence: &CocoAsToken,
        report_data: &ReportData,
    ) -> Result<()> {
        let token = evidence.as_str();
        tracing::debug!(
            "Verify CoCo AS token \"{token}\" with policy ids: {:?}",
            self.policy_ids
        );

        let claims_value = self.token_verifier.verify(token.to_string()).await?;

        let is_ear = if let Some(eat_profile) = claims_value.get("eat_profile") {
            if eat_profile != "tag:github.com,2024:confidential-containers/Trustee" {
                return Err(Error::msg(format!(
                    "Unsupported EAT profile: {}",
                    eat_profile
                )));
            }
            true
        } else {
            false
        };

        /* Check report_data matchs */
        let runtime_data_expected = CocoEvidence::wrap_runtime_data_as_structed(report_data)?;
        let runtime_data_in_token = if is_ear {
            // EAR JWT route
            claims_value
                .pointer("/submods/cpu0/ear.veraison.annotated-evidence/runtime_data_claims")
                .ok_or_else(|| Error::msg("Can not found `runtime_data_claims` in EAR token"))?
        } else {
            // Standard CoCo AS token route
            claims_value
                .pointer("/customized_claims/runtime_data")
                .ok_or_else(|| Error::msg("Can not found `runtime_data` in CoCo AS token"))?
        };

        let runtime_data_expected_map = runtime_data_expected
            .as_object()
            .ok_or_else(|| Error::msg("runtime_data_expected is not a map"))?;

        let runtime_data_in_token_map = runtime_data_in_token
            .as_object()
            .ok_or_else(|| Error::msg("runtime_data_in_token is not a map"))?;

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
            return Err(Error::msg("runtime_data mismatch"));
        }

        // Check expected policy-ids
        let allowed_policy_ids = if is_ear {
            let submods = claims_value
                .pointer("/submods")
                .and_then(|v| v.as_object())
                .ok_or_else(|| Error::msg("Can not found `/submods` object in EAR token"))?;

            let mut policy_ids = HashSet::new();
            for (key, value) in submods {
                let policy_id = value
                    .pointer("/ear.appraisal-policy-id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        Error::msg(format!(
                            "Can not found `/submods/{}/ear.appraisal-policy-id` in EAR token",
                            key
                        ))
                    })?;

                // Check ear.status and trustworthiness-vector, the value of ear.status should be one of (affirming, warning, contraindicated)
                let status = value
                    .pointer("/ear.status")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        Error::msg(format!(
                            "Can not found `/submods/{}/ear.status` in EAR token",
                            key
                        ))
                    })?;

                let trustworthiness_vector = value
                    .pointer("/ear.trustworthiness-vector")
                    .ok_or_else(|| {
                        Error::msg(format!(
                            "Can not found `/submods/{}/ear.trustworthiness-vector` in EAR token",
                            key
                        ))
                    })?;

                if status != "affirming" {
                    return Err(Error::msg(format!(
                            "EAR status should be \"affirming\" but got {:?} for {}, trustworthiness-vector: {}",
                            status, key, trustworthiness_vector
                        )));
                }

                policy_ids.insert(policy_id.to_owned());
            }

            if policy_ids.len() > 1 {
                return Err(Error::msg(
                    "Different policy IDs found in EAR token, which is not supported",
                ));
            }

            if policy_ids.is_empty() {
                return Err(Error::msg("No valid policy ID found in EAR token"));
            }
            policy_ids
        } else {
            /*
             * The content format of evaluation-reports is documented here: https://github.com/confidential-containers/trustee/blob/43d56f3a4a92a1cc691f63a8e1311bcc0d2b3fc8/attestation-service/docs/example.token.json#L6
             */
            claims_value
                .get("evaluation-reports")
                .and_then(|o| o.as_array())
                .ok_or_else(|| {
                    Error::msg("Can not found `evaluation-reports` array in CoCo AS token")
                })?
                .iter()
                .enumerate()
                .map(|(i, o)| -> Result<_> {
                    let policy_id =
                        o.get("policy-id").and_then(|v| v.as_str()).ok_or_else(|| {
                            Error::msg(format!(
                                "Can not found `policy-id` in evaluation-reports[{i}]: {o}"
                            ))
                        })?;
                    Ok(policy_id.to_string())
                })
                .collect::<Result<HashSet<_>>>()?
        };

        /* We accept the token only when all of the expected policy ids has { "allow": true } */
        for policy_id in &self.policy_ids {
            if !allowed_policy_ids.contains(policy_id.as_str()) {
                return Err(Error::msg(format!(
                    "The token is not acceptable due to evaluation failure on policy_id `{policy_id}`"
                )));
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl GenericVerifier for CocoVerifier {
    type Evidence = CocoAsToken;

    async fn verify_evidence(
        &self,
        evidence: &Self::Evidence,
        report_data: &ReportData,
    ) -> Result<()> {
        self.verify_evidence_internal(evidence, report_data)
            .await
            .context("Failed to verify CoCo AS token")
            .map_err(|e| {
                if e.get_kind() == ErrorKind::Unknown {
                    e.with_kind(ErrorKind::CocoVerifyTokenFailed)
                } else {
                    e
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::claims::Claims;

    /// Helper function to run JWT verification tests
    async fn run_jwt_verification_test(
        token_str: &str,
        test_name: &str,
        policy_ids: Vec<String>,
        trusted_certs_paths: Option<Vec<String>>,
    ) {
        let token = CocoAsToken::new(token_str.trim().to_string())
            .expect(&format!("Failed to create CocoAsToken from {}", test_name));

        let report_data = ReportData::Claims(Claims::default());

        let verifier = CocoVerifier::new(None, &trusted_certs_paths, &policy_ids)
            .await
            .expect("Failed to create CocoVerifier");

        let result = verifier.verify_evidence(&token, &report_data).await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_verify_simple_jwt_token() {
        let (_dir, cert_path) = write_pem_to_temp_file(
            include_str!("test_cases/simple.as-ca.pem"),
            "simple.as-ca.pem",
        );

        run_jwt_verification_test(
            include_str!("test_cases/simple.jwt"),
            "Simple JWT",
            vec!["default".to_string()],
            Some(vec![cert_path]),
        )
        .await;
    }

    #[tokio::test]
    async fn test_verify_ear_jwt_token() {
        let (_dir, cert_path) =
            write_pem_to_temp_file(include_str!("test_cases/ear.as-ca.pem"), "ear.as-ca.pem");

        run_jwt_verification_test(
            include_str!("test_cases/ear.jwt"),
            "EAR JWT",
            vec!["default".to_string()],
            Some(vec![cert_path]),
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_simple_jwt_token_policy_id_mismatch() {
        let (_dir, cert_path) = write_pem_to_temp_file(
            include_str!("test_cases/simple.as-ca.pem"),
            "simple.as-ca.pem",
        );

        run_jwt_verification_test(
            include_str!("test_cases/simple.jwt"),
            "Simple JWT with wrong policy_id",
            vec!["non-existent-policy".to_string()],
            Some(vec![cert_path]),
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_ear_jwt_token_policy_id_mismatch() {
        let (_dir, cert_path) =
            write_pem_to_temp_file(include_str!("test_cases/ear.as-ca.pem"), "ear.as-ca.pem");

        run_jwt_verification_test(
            include_str!("test_cases/ear.jwt"),
            "EAR JWT with wrong policy_id",
            vec!["non-existent-policy".to_string()],
            Some(vec![cert_path]),
        )
        .await;
    }

    fn write_pem_to_temp_file(pem: &str, filename: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("to create tempdir for test cert");
        let path = dir.path().join(filename);
        std::fs::write(&path, pem).expect("to write test cert");
        (dir, path.to_string_lossy().into_owned())
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_simple_jwt_token_with_wrong_trusted_cert() {
        let (_dir, wrong_cert_path) =
            write_pem_to_temp_file(include_str!("test_cases/ear.as-ca.pem"), "ear.as-ca.pem");

        run_jwt_verification_test(
            include_str!("test_cases/simple.jwt"),
            "Simple JWT with wrong trusted cert",
            vec!["default".to_string()],
            Some(vec![wrong_cert_path]),
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_ear_jwt_token_with_wrong_trusted_cert() {
        let (_dir, wrong_cert_path) = write_pem_to_temp_file(
            include_str!("test_cases/simple.as-ca.pem"),
            "simple.as-ca.pem",
        );

        run_jwt_verification_test(
            include_str!("test_cases/ear.jwt"),
            "EAR JWT with wrong trusted cert",
            vec!["default".to_string()],
            Some(vec![wrong_cert_path]),
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_simple_jwt_token_with_empty_trusted_certs() {
        run_jwt_verification_test(
            include_str!("test_cases/simple.jwt"),
            "Simple JWT with empty trusted_certs",
            vec!["default".to_string()],
            None,
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_ear_jwt_token_with_empty_trusted_certs() {
        run_jwt_verification_test(
            include_str!("test_cases/ear.jwt"),
            "EAR JWT with empty trusted_certs",
            vec!["default".to_string()],
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn test_verify_ear_with_additional_device_jwt_token() {
        let (_dir, cert_path) = write_pem_to_temp_file(
            include_str!("test_cases/ear_with_additional_device.as-ca.pem"),
            "ear_with_additional_device.as-ca.pem",
        );

        run_jwt_verification_test(
            include_str!("test_cases/ear_with_additional_device.jwt"),
            "EAR JWT with additional device evidence",
            vec!["default".to_string()],
            Some(vec![cert_path]),
        )
        .await;
    }
}

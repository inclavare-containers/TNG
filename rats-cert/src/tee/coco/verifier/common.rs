use super::super::evidence::{CocoAsToken, CocoEvidence};
use crate::tee::ReportData;
use crate::{errors::*, tee::GenericVerifier};

use serde_json::Value;

use std::collections::{HashMap, HashSet};

use super::token::{AttestationTokenVerifierConfig, TokenVerifier};

pub(super) struct CommonCocoVerifier {
    /// The token verifier used for validating JWT.
    pub token_verifier: TokenVerifier,
    /// The policy ids need to check
    pub policy_ids: Vec<String>,
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
            .map_err(Error::CocoTokenVerifierError)?;

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
        let runtime_data_expected = CocoEvidence::wrap_runtime_data_as_structed(report_data)?;
        let runtime_data_in_token = if is_ear {
            // EAR JWT route
            claims_value
                .pointer("/submods/cpu0/ear.veraison.annotated-evidence/runtime_data_claims")
                .ok_or_else(|| Error::MissingTokenField {
                    detail: "runtime_data_claims".to_string(),
                })?
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

        // Check expected policy-ids
        let allowed_policy_ids = if is_ear {
            let submods = claims_value
                .pointer("/submods")
                .and_then(|v| v.as_object())
                .ok_or_else(|| Error::MissingTokenField {
                    detail: "/submods".to_string(),
                })?;

            let mut policy_ids = HashSet::new();
            for (key, value) in submods {
                let policy_id = value
                    .pointer("/ear.appraisal-policy-id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::MissingTokenField {
                        detail: format!("/submods/{}/ear.appraisal-policy-id", key),
                    })?;

                // Check ear.status and trustworthiness-vector, the value of ear.status should be one of (affirming, warning, contraindicated)
                let status = value
                    .pointer("/ear.status")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::MissingTokenField {
                        detail: format!("/submods/{}/ear.status", key),
                    })?;

                let trustworthiness_vector = value
                    .pointer("/ear.trustworthiness-vector")
                    .ok_or_else(|| Error::MissingTokenField {
                        detail: format!("/submods/{}/ear.trustworthiness-vector", key),
                    })?;

                if status != "affirming" {
                    return Err(Error::EarStatusNotAffirming {
                        status: status.to_string(),
                        tee_type: key.to_string(),
                        trustworthiness: trustworthiness_vector.to_string(),
                    });
                }

                policy_ids.insert(policy_id.to_owned());
            }

            if policy_ids.len() > 1 {
                return Err(Error::MultiplePolicyIds);
            }

            if policy_ids.is_empty() {
                return Err(Error::NoValidPolicyId);
            }
            policy_ids
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

        Ok(())
    }
}

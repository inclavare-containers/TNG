//! The EAR claim layouts accepted by the CoCo verifier.
//!
//! Trustee changed the issued EAR token layout in EAR draft-04. The profile
//! tag stayed the same, so the layout has to be detected from the claim names:
//! draft-04 uses `ear_status`, `ear_appraisal_policy_ids`, `ear_attester_claims`
//! and `ear_verifier_claims`, while the pre-draft-04 layout nests the same data
//! under `ear.status`, `ear.appraisal-policy-id` and
//! `ear.veraison.annotated-evidence`.
//!
//! `CommonCocoVerifier` accepts both so it can verify tokens from the builtin
//! AS (pinned to the pre-draft-04 layout) and from an upstream AS that has
//! moved to draft-04.

use serde_json::Value;
use std::collections::HashSet;

use super::super::diagnostics::{AppraisalDiagnostics, APPRAISAL_DIAGNOSTICS_EXTENSION};
use crate::errors::{Error, Result};

/// Which EAR claim layout a submod uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EarLayout {
    /// EAR draft-04: `ear_status`, `ear_verifier_claims.runtime_data`, ...
    Draft04,
    /// The layout Trustee emitted before EAR draft-04.
    Legacy,
}

impl EarLayout {
    /// Detect the layout of one submod. Draft-04 wins if a transitional token
    /// carries both layouts.
    fn detect(submod: &Value) -> Option<Self> {
        if submod.get("ear_status").is_some()
            || submod.get("ear_attester_claims").is_some()
            || submod.get("ear_verifier_claims").is_some()
        {
            Some(Self::Draft04)
        } else if submod.get("ear.status").is_some()
            || submod.get("ear.veraison.annotated-evidence").is_some()
        {
            Some(Self::Legacy)
        } else {
            None
        }
    }

    fn status(self, submod: &Value) -> Option<&Value> {
        match self {
            Self::Draft04 => submod.get("ear_status"),
            Self::Legacy => submod.get("ear.status"),
        }
    }

    fn trustworthiness_vector(self, submod: &Value) -> Option<&Value> {
        match self {
            Self::Draft04 => submod.get("ear_trustworthiness_vector"),
            Self::Legacy => submod.get("ear.trustworthiness-vector"),
        }
    }

    /// The policy ids this submod was appraised under. Draft-04 carries an
    /// array, the legacy layout a single string.
    fn appraisal_policy_ids(self, submod: &Value) -> Option<Vec<&str>> {
        match self {
            Self::Draft04 => submod
                .get("ear_appraisal_policy_ids")
                .and_then(Value::as_array)
                .and_then(|ids| ids.iter().map(Value::as_str).collect()),
            Self::Legacy => submod
                .get("ear.appraisal-policy-id")
                .and_then(Value::as_str)
                .map(|id| vec![id]),
        }
    }

    /// The parsed runtime data the verifier bound to the evidence.
    fn runtime_data(self, submod: &Value) -> Option<&Value> {
        match self {
            Self::Draft04 => submod.pointer("/ear_verifier_claims/runtime_data"),
            Self::Legacy => submod.pointer("/ear.veraison.annotated-evidence/runtime_data_claims"),
        }
    }

    fn status_path(self) -> &'static str {
        match self {
            Self::Draft04 => "/ear_status",
            Self::Legacy => "/ear.status",
        }
    }

    fn trustworthiness_path(self) -> &'static str {
        match self {
            Self::Draft04 => "/ear_trustworthiness_vector",
            Self::Legacy => "/ear.trustworthiness-vector",
        }
    }

    fn policy_ids_path(self) -> &'static str {
        match self {
            Self::Draft04 => "/ear_appraisal_policy_ids",
            Self::Legacy => "/ear.appraisal-policy-id",
        }
    }

    fn runtime_data_path(self) -> &'static str {
        match self {
            Self::Draft04 => "/ear_verifier_claims/runtime_data",
            Self::Legacy => "/ear.veraison.annotated-evidence/runtime_data_claims",
        }
    }
}

fn submod<'a>(claims: &'a Value, key: &str) -> Result<&'a Value> {
    claims
        .pointer("/submods")
        .and_then(|submods| submods.get(key))
        .ok_or_else(|| Error::MissingTokenField {
            detail: format!("/submods/{key}"),
        })
}

fn detect_or_missing(submod: &Value, key: &str) -> Result<EarLayout> {
    EarLayout::detect(submod).ok_or_else(|| Error::MissingTokenField {
        detail: format!(
            "/submods/{key}: expected draft-04 (ear_status) or legacy (ear.status) EAR claims"
        ),
    })
}

/// The parsed runtime data bound to the `cpu0` submod.
pub(super) fn runtime_data(claims: &Value) -> Result<&Value> {
    let cpu0 = submod(claims, "cpu0")?;
    let layout = detect_or_missing(cpu0, "cpu0")?;
    layout
        .runtime_data(cpu0)
        .ok_or_else(|| Error::MissingTokenField {
            detail: format!("/submods/cpu0{}", layout.runtime_data_path()),
        })
}

/// The set of appraisal policy ids declared by the token. Every submod must be
/// affirming; the token must name exactly one policy id.
pub(super) fn appraisal_policy_ids(claims: &Value) -> Result<HashSet<String>> {
    let submods = claims
        .pointer("/submods")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::MissingTokenField {
            detail: "/submods".to_string(),
        })?;

    let mut policy_ids = HashSet::new();
    for (key, submod) in submods {
        let layout = detect_or_missing(submod, key)?;

        let ids = layout
            .appraisal_policy_ids(submod)
            .ok_or_else(|| Error::MissingTokenField {
                detail: format!("/submods/{key}{}", layout.policy_ids_path()),
            })?;

        let status = layout
            .status(submod)
            .and_then(Value::as_str)
            .ok_or_else(|| Error::MissingTokenField {
                detail: format!("/submods/{key}{}", layout.status_path()),
            })?;
        let trustworthiness_vector =
            layout
                .trustworthiness_vector(submod)
                .ok_or_else(|| Error::MissingTokenField {
                    detail: format!("/submods/{key}{}", layout.trustworthiness_path()),
                })?;

        if status != "affirming" {
            return Err(ear_status_not_affirming(
                key,
                submod,
                status,
                &trustworthiness_vector.to_string(),
            ));
        }

        policy_ids.extend(ids.into_iter().map(str::to_owned));
    }

    // TODO: cascaded policies can declare several ids in draft-04. TNG still
    // expects one effective policy id per token, so keep the existing guard.
    if policy_ids.len() > 1 {
        return Err(Error::MultiplePolicyIds);
    }
    if policy_ids.is_empty() {
        return Err(Error::NoValidPolicyId);
    }
    Ok(policy_ids)
}

/// Reads the optional `tng.appraisal-diagnostics` extension off one submod.
/// Policies currently emit it as a JSON string because the pinned `ear` crate
/// serializes map-valued extensions as key/value pair arrays; accepting the
/// object form too keeps this working across an `ear` upgrade. The extension is
/// a plain submod key, so it is read the same way for both claim layouts.
fn parse_appraisal_diagnostics(submod_key: &str, submod: &Value) -> Option<AppraisalDiagnostics> {
    let extension = submod.get(APPRAISAL_DIAGNOSTICS_EXTENSION)?;
    let parsed: std::result::Result<AppraisalDiagnostics, serde_json::Error> = match extension {
        Value::String(payload) => serde_json::from_str(payload),
        extension => serde_json::from_value(extension.clone()),
    };
    match parsed {
        // An empty list carries no information; fall back to the plain error
        // instead of rendering "(no failed checks reported)".
        Ok(diagnostics) if !diagnostics.failed.is_empty() => Some(diagnostics),
        Ok(_) => None,
        Err(error) => {
            tracing::debug!(
                submod = submod_key,
                extension = APPRAISAL_DIAGNOSTICS_EXTENSION,
                error = ?error,
                "ignoring malformed appraisal diagnostics; falling back to the plain error"
            );
            None
        }
    }
}

/// Picks the non-affirming error variant, attaching the structured diagnostics
/// when the policy reported them through the extension.
fn ear_status_not_affirming(
    tee_type: &str,
    submod: &Value,
    status: &str,
    trustworthiness: &str,
) -> Error {
    match parse_appraisal_diagnostics(tee_type, submod) {
        Some(diagnostics) => Error::EarStatusNotAffirmingWithDiagnostics {
            status: status.to_string(),
            tee_type: tee_type.to_string(),
            trustworthiness: trustworthiness.to_string(),
            diagnostics,
        },
        None => Error::EarStatusNotAffirming {
            status: status.to_string(),
            tee_type: tee_type.to_string(),
            trustworthiness: trustworthiness.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use serde_json::json;

    /// A real token issued by the pre-draft-04 AS, captured from a local
    /// background-check flow.
    const LEGACY_TOKEN: &str = include_str!("testdata/legacy-ear-token.jwt");

    /// The token body from the upstream draft-04 migration PR. Upstream ships
    /// no signed JWT fixture, so this is the issued claims set; the test
    /// exercises claim parsing, not signature verification.
    const DRAFT04_TOKEN: &str = include_str!("testdata/draft04-ear-token.json");

    fn jwt_claims(token: &str) -> Value {
        let payload = token.trim().split('.').nth(1).expect("JWT payload segment");
        let bytes = URL_SAFE_NO_PAD
            .decode(payload.trim_end_matches('='))
            .expect("base64url payload");
        serde_json::from_slice(&bytes).expect("JSON payload")
    }

    fn draft04_submod(status: &str, ids: &[&str]) -> Value {
        json!({
            "ear_status": status,
            "ear_trustworthiness_vector": {"hardware": 2},
            "ear_appraisal_policy_ids": ids,
            "ear_attester_claims": {
                "tee": "tdx",
                "claims": {},
                "report_data": "00",
                "init_data": "00"
            },
            "ear_verifier_claims": {
                "runtime_data": {"nonce": "n"}
            }
        })
    }

    fn legacy_submod(status: &str, id: &str) -> Value {
        json!({
            "ear.status": status,
            "ear.trustworthiness-vector": {"hardware": 2},
            "ear.appraisal-policy-id": id,
            "ear.veraison.annotated-evidence": {
                "runtime_data_claims": {"nonce": "n"}
            }
        })
    }

    fn claims(submod: Value) -> Value {
        json!({"submods": {"cpu0": submod}})
    }

    fn diagnostics_payload() -> &'static str {
        "{\"failed\":[{\"dimension\":\"executables\",\"check\":\"com.alibabacloud.container.image.vllm\",\"expected\":\"sha256:85a7\",\"actual\":[\"sha256:95a7\"],\"reason\":\"mismatch\"}]}"
    }

    fn legacy_submod_with_diagnostics() -> Value {
        let mut submod = legacy_submod("contraindicated", "policy");
        submod[APPRAISAL_DIAGNOSTICS_EXTENSION] = json!(diagnostics_payload());
        submod
    }

    fn not_affirming_error(submod: &Value) -> Error {
        let (status, trustworthiness) = if submod.get("ear_status").is_some() {
            (&submod["ear_status"], &submod["ear_trustworthiness_vector"])
        } else {
            (&submod["ear.status"], &submod["ear.trustworthiness-vector"])
        };
        let status = status.as_str().unwrap();
        let trustworthiness = trustworthiness.to_string();
        ear_status_not_affirming("cpu0", submod, status, &trustworthiness)
    }

    #[test]
    fn extension_yields_structured_diagnostics_error() {
        let error = not_affirming_error(&legacy_submod_with_diagnostics());
        match &error {
            Error::EarStatusNotAffirmingWithDiagnostics {
                status,
                tee_type,
                diagnostics,
                ..
            } => {
                assert_eq!(status, "contraindicated");
                assert_eq!(tee_type, "cpu0");
                assert_eq!(diagnostics.failed.len(), 1);
                assert_eq!(diagnostics.failed[0].dimension, "executables");
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

    #[test]
    fn diagnostics_extension_is_layout_independent() {
        let mut submod = draft04_submod("contraindicated", &["default"]);
        submod[APPRAISAL_DIAGNOSTICS_EXTENSION] = json!(diagnostics_payload());

        match not_affirming_error(&submod) {
            Error::EarStatusNotAffirmingWithDiagnostics { diagnostics, .. } => {
                assert_eq!(diagnostics.failed[0].dimension, "executables");
            }
            other => panic!("expected structured diagnostics error, got {other:?}"),
        }
    }

    #[test]
    fn missing_extension_keeps_the_plain_error() {
        let error = not_affirming_error(&legacy_submod("contraindicated", "policy"));
        assert!(
            matches!(error, Error::EarStatusNotAffirming { .. }),
            "{error:?}"
        );
        assert!(!error.to_string().contains("failed checks:"), "{error}");
    }

    #[test]
    fn extension_may_be_a_json_object() {
        let mut submod = legacy_submod("contraindicated", "policy");
        submod[APPRAISAL_DIAGNOSTICS_EXTENSION] = json!({
            "failed": [{"dimension": "hardware", "check": "tdx"}]
        });

        match not_affirming_error(&submod) {
            Error::EarStatusNotAffirmingWithDiagnostics { diagnostics, .. } => {
                assert_eq!(diagnostics.failed[0].check, "tdx");
            }
            other => panic!("expected structured diagnostics error, got {other:?}"),
        }
    }

    #[test]
    fn empty_failed_list_keeps_the_plain_error() {
        let mut submod = legacy_submod("contraindicated", "policy");
        submod[APPRAISAL_DIAGNOSTICS_EXTENSION] = json!("{}");

        let error = not_affirming_error(&submod);
        assert!(
            matches!(error, Error::EarStatusNotAffirming { .. }),
            "{error:?}"
        );
        assert!(
            !error.to_string().contains("no failed checks reported"),
            "{error}"
        );
    }

    #[test]
    fn unparseable_extension_falls_back_to_the_plain_error() {
        let mut submod = legacy_submod("contraindicated", "policy");
        submod[APPRAISAL_DIAGNOSTICS_EXTENSION] = json!("not a diagnostics payload");

        let error = not_affirming_error(&submod);
        assert!(
            matches!(error, Error::EarStatusNotAffirming { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn detects_both_layouts() {
        assert_eq!(
            EarLayout::detect(&draft04_submod("affirming", &["default"])),
            Some(EarLayout::Draft04)
        );
        assert_eq!(
            EarLayout::detect(&legacy_submod("affirming", "default")),
            Some(EarLayout::Legacy)
        );
        assert_eq!(EarLayout::detect(&json!({})), None);
    }

    #[test]
    fn draft04_wins_when_both_layouts_are_present() {
        let mut submod = draft04_submod("affirming", &["default"]);
        submod["ear.status"] = json!("affirming");
        assert_eq!(EarLayout::detect(&submod), Some(EarLayout::Draft04));
    }

    #[test]
    fn runtime_data_reads_both_layouts() {
        let draft04 = claims(draft04_submod("affirming", &["default"]));
        let legacy = claims(legacy_submod("affirming", "default"));
        assert_eq!(runtime_data(&draft04).unwrap(), &json!({"nonce": "n"}));
        assert_eq!(runtime_data(&legacy).unwrap(), &json!({"nonce": "n"}));
    }

    #[test]
    fn runtime_data_absent_is_reported() {
        let mut submod = draft04_submod("affirming", &["default"]);
        submod
            .as_object_mut()
            .unwrap()
            .remove("ear_verifier_claims");
        let err = runtime_data(&claims(submod)).unwrap_err();
        assert!(matches!(err, Error::MissingTokenField { .. }));
    }

    #[test]
    fn appraisal_policy_ids_reads_both_layouts() {
        let draft04 = claims(draft04_submod("affirming", &["default"]));
        let legacy = claims(legacy_submod("affirming", "default"));
        assert_eq!(
            appraisal_policy_ids(&draft04).unwrap(),
            HashSet::from(["default".to_string()])
        );
        assert_eq!(
            appraisal_policy_ids(&legacy).unwrap(),
            HashSet::from(["default".to_string()])
        );
    }

    #[test]
    fn multiple_policy_ids_are_rejected() {
        let claims = claims(draft04_submod("affirming", &["a", "b"]));
        assert!(matches!(
            appraisal_policy_ids(&claims),
            Err(Error::MultiplePolicyIds)
        ));
    }

    #[test]
    fn non_string_policy_id_is_rejected() {
        let mut submod = draft04_submod("affirming", &["default"]);
        submod["ear_appraisal_policy_ids"] = json!(["default", 1]);
        let claims = claims(submod);
        assert!(matches!(
            appraisal_policy_ids(&claims),
            Err(Error::MissingTokenField { .. })
        ));
    }

    #[test]
    fn non_affirming_status_is_rejected() {
        let claims = claims(draft04_submod("contraindicated", &["default"]));
        assert!(matches!(
            appraisal_policy_ids(&claims),
            Err(Error::EarStatusNotAffirming { .. })
        ));
    }

    #[test]
    fn unknown_layout_is_rejected() {
        let claims = claims(json!({"some": "claim"}));
        assert!(matches!(
            appraisal_policy_ids(&claims),
            Err(Error::MissingTokenField { .. })
        ));
    }

    #[test]
    fn empty_token_has_no_policy_id() {
        let claims = json!({"submods": {}});
        assert!(matches!(
            appraisal_policy_ids(&claims),
            Err(Error::NoValidPolicyId)
        ));
    }

    #[test]
    fn real_legacy_token_is_parsed() {
        let claims = jwt_claims(LEGACY_TOKEN);
        let cpu0 = &claims["submods"]["cpu0"];
        assert_eq!(EarLayout::detect(cpu0), Some(EarLayout::Legacy));
        // The local flow used an empty report-data claim set.
        assert_eq!(runtime_data(&claims).unwrap(), &json!({}));
        assert_eq!(
            appraisal_policy_ids(&claims).unwrap(),
            HashSet::from(["default".to_string()])
        );
    }

    #[test]
    fn real_draft04_token_is_parsed() {
        let claims: Value = serde_json::from_str(DRAFT04_TOKEN).expect("JSON token body");
        let cpu0 = &claims["submods"]["cpu0"];
        assert_eq!(EarLayout::detect(cpu0), Some(EarLayout::Draft04));

        let runtime = runtime_data(&claims).unwrap();
        assert!(runtime.get("tee-pubkey").is_some());

        // The example token is not affirming, which proves the status was read
        // from the draft-04 path. Make it affirming and re-run the policy-id
        // extraction on the same real claim shape.
        assert!(matches!(
            appraisal_policy_ids(&claims),
            Err(Error::EarStatusNotAffirming { .. })
        ));
        let mut affirming = claims;
        affirming["submods"]["cpu0"]["ear_status"] = json!("affirming");
        assert_eq!(
            appraisal_policy_ids(&affirming).unwrap(),
            HashSet::from(["default".to_string()])
        );
    }
}

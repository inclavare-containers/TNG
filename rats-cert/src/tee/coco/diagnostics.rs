//! The structured payload a policy reports through the
//! `tng.appraisal-diagnostics` EAR extension when an appraisal is not
//! affirming.

use serde::{Deserialize, Serialize};
use std::fmt;

/// EAR extension name carrying the failed-check list. Private to TNG; other
/// policies may reuse it with their own `check` identifiers.
pub(crate) const APPRAISAL_DIAGNOSTICS_EXTENSION: &str = "tng.appraisal-diagnostics";

/// Private extension key. The EAR spec assigns non-negative keys to its own
/// extensions, so an unregistered extension uses a negative one.
pub(crate) const APPRAISAL_DIAGNOSTICS_KEY: i32 = -1001;

/// The checks an appraisal failed, as reported by the attesting policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AppraisalDiagnostics {
    #[serde(default)]
    pub failed: Vec<AppraisalDiagnostic>,
}

/// One failed check. `dimension` is the AR4SI dimension name the check gates;
/// `check` is an identifier the policy defines (for the `modules` policy, the
/// module type, plus a sub-check suffix for posture entries).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppraisalDiagnostic {
    pub dimension: String,
    pub check: String,
    #[serde(default)]
    pub expected: Option<serde_json::Value>,
    #[serde(default)]
    pub actual: Option<serde_json::Value>,
    #[serde(default)]
    pub reason: Option<String>,
}

impl fmt::Display for AppraisalDiagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.failed.is_empty() {
            return f.write_str("(no failed checks reported)");
        }
        let mut first = true;
        for failed in &self.failed {
            if !first {
                f.write_str("\n")?;
            }
            first = false;
            write!(f, "- {failed}")?;
        }
        Ok(())
    }
}

impl fmt::Display for AppraisalDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.dimension, self.check)?;
        if let Some(expected) = &self.expected {
            write!(f, ", expected {expected}")?;
        }
        if let Some(actual) = &self.actual {
            write!(f, ", actual {actual}")?;
        }
        if let Some(reason) = &self.reason {
            write!(f, ", reason {reason}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn payload_round_trips_and_renders() {
        let payload = r#"{
            "failed": [
                {
                    "dimension": "executables",
                    "check": "com.alibabacloud.container.image.vllm",
                    "expected": "sha256:85a7",
                    "actual": ["sha256:95a7"],
                    "reason": "mismatch"
                },
                {
                    "dimension": "hardware",
                    "check": "tdx",
                    "reason": "platform-not-recognized"
                }
            ]
        }"#;
        let diagnostics: AppraisalDiagnostics =
            serde_json::from_str(payload).expect("diagnostics payload parses");
        assert_eq!(diagnostics.failed.len(), 2);
        assert_eq!(
            diagnostics.to_string(),
            "- [executables] com.alibabacloud.container.image.vllm, \
             expected \"sha256:85a7\", actual [\"sha256:95a7\"], reason mismatch\n\
             - [hardware] tdx, reason platform-not-recognized"
        );
    }

    #[test]
    fn missing_optional_fields_and_empty_list_are_accepted() {
        let diagnostics: AppraisalDiagnostics = serde_json::from_str(
            r#"{"failed": [{"dimension": "hardware", "check": "tdx.debug"}]}"#,
        )
        .expect("optional fields are optional");
        assert_eq!(diagnostics.failed[0].expected, None);
        assert_eq!(diagnostics.failed[0].actual, None);
        assert_eq!(diagnostics.failed[0].reason, None);

        let empty: AppraisalDiagnostics = serde_json::from_str("{}").expect("default failed list");
        assert_eq!(empty.failed, Vec::new());
        assert_eq!(empty.to_string(), "(no failed checks reported)");
    }

    #[test]
    fn diagnostics_serialize_to_the_rego_payload_shape() {
        let diagnostics = AppraisalDiagnostics {
            failed: vec![AppraisalDiagnostic {
                dimension: "hardware".to_string(),
                check: "tdx.debug".to_string(),
                expected: Some(json!("debug bit clear")),
                actual: Some(json!("0100001000000000")),
                reason: Some("mismatch".to_string()),
            }],
        };
        let value = serde_json::to_value(&diagnostics).expect("serialize");
        assert_eq!(
            value,
            json!({"failed": [{
                "dimension": "hardware",
                "check": "tdx.debug",
                "expected": "debug bit clear",
                "actual": "0100001000000000",
                "reason": "mismatch"
            }]})
        );
    }
}

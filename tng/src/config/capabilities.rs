//! Which RA configuration fields each provider/model/as_type combination uses.
//!
//! This is the single owner of the field matrix that the wasm demo UI and the
//! attestation-info projection both need. Native production code selects
//! fields through the typed config enums; it does not consult this table.

use serde::Serialize;

/// Field capabilities for one RA configuration combination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigCapabilities {
    /// The `as_type` selector applies (CoCo only).
    pub as_type: bool,
    /// The attestation-service address is consumed.
    pub as_addr: bool,
    /// The ITA API key is consumed.
    pub api_key: bool,
    /// The ITA JWKS address is consumed.
    pub ita_jwks_addr: bool,
    /// `skip_as_token_cert_verify` is consumed.
    pub skip_as_token_cert_verify: bool,
    /// The builtin policy selector is consumed.
    pub builtin_policy: bool,
    /// The builtin reference-value editor is consumed.
    pub builtin_reference_values: bool,
    /// `policy_ids` is consumed.
    pub policy_ids: bool,
    /// `trusted_certs_paths` is consumed (native only; wasm has no file
    /// access).
    pub trusted_certs: bool,
}

impl ConfigCapabilities {
    /// Capabilities for a `(provider, model, as_type)` combination.
    ///
    /// The demo's selectors only produce known values. Unknown strings behave
    /// like the least-specific combination, matching the previous UI rules.
    pub fn new(provider: &str, model: &str, as_type: &str) -> Self {
        let is_coco = provider == "coco";
        let is_ita = provider == "ita";
        let is_passport = model == "passport";
        let is_builtin = is_coco && as_type == "builtin";
        Self {
            as_type: is_coco,
            as_addr: if is_coco {
                !is_builtin
            } else {
                !is_ita || !is_passport
            },
            api_key: is_ita && !is_passport,
            ita_jwks_addr: is_ita,
            skip_as_token_cert_verify: if is_coco { !is_builtin } else { !is_ita },
            builtin_policy: is_builtin,
            builtin_reference_values: is_builtin,
            policy_ids: !is_builtin,
            trusted_certs: is_coco && !is_builtin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(provider: &str, model: &str, as_type: &str) -> ConfigCapabilities {
        ConfigCapabilities::new(provider, model, as_type)
    }

    #[test]
    fn coco_remote_consumes_the_service_fields() {
        for as_type in ["restful", "grpc"] {
            for model in ["passport", "background_check"] {
                let c = caps("coco", model, as_type);
                let label = format!("coco/{model}/{as_type}");
                assert!(c.as_type, "{label}");
                assert!(c.as_addr, "{label}");
                assert!(c.skip_as_token_cert_verify, "{label}");
                assert!(c.policy_ids, "{label}");
                assert!(c.trusted_certs, "{label}");
                assert!(!c.api_key, "{label}");
                assert!(!c.ita_jwks_addr, "{label}");
                assert!(!c.builtin_policy, "{label}");
                assert!(!c.builtin_reference_values, "{label}");
            }
        }
    }

    #[test]
    fn coco_builtin_owns_its_policy_and_uses_no_remote_service_fields() {
        for model in ["passport", "background_check"] {
            let c = caps("coco", model, "builtin");
            let label = format!("coco/{model}/builtin");
            assert!(c.as_type, "{label}");
            assert!(!c.as_addr, "{label}");
            assert!(!c.policy_ids, "{label}");
            assert!(!c.skip_as_token_cert_verify, "{label}");
            assert!(!c.trusted_certs, "{label}");
            assert!(c.builtin_policy, "{label}");
            assert!(c.builtin_reference_values, "{label}");
            assert!(!c.api_key, "{label}");
            assert!(!c.ita_jwks_addr, "{label}");
        }
    }

    #[test]
    fn ita_background_check_consumes_the_api_key_and_api_url() {
        let c = caps("ita", "background_check", "restful");
        assert!(!c.as_type);
        assert!(c.as_addr);
        assert!(c.api_key);
        assert!(c.ita_jwks_addr);
        assert!(c.policy_ids);
        assert!(!c.skip_as_token_cert_verify);
        assert!(!c.trusted_certs);
        assert!(!c.builtin_policy);
        assert!(!c.builtin_reference_values);
    }

    #[test]
    fn ita_passport_is_jwks_only() {
        let c = caps("ita", "passport", "restful");
        assert!(!c.as_type);
        assert!(!c.as_addr);
        assert!(!c.api_key);
        assert!(c.ita_jwks_addr);
        assert!(c.policy_ids);
        assert!(!c.skip_as_token_cert_verify);
        assert!(!c.trusted_certs);
        assert!(!c.builtin_policy);
        assert!(!c.builtin_reference_values);
    }
}

//! Policy-kind descriptions for consumers that build a policy chooser.
//!
//! Only the wasm SDK and this crate's tests need this list; native production
//! code selects a builtin policy by configuration, not by kind.

use serde::Serialize;

use super::policy_config::{ModuleGroupsConfig, PolicyConfig};

impl PolicyConfig {
    /// Human-readable name for consumers that render a policy chooser.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::HardwareOnly => "Hardware only",
            Self::HardwareOnlyStrict => "Hardware only, strict",
            Self::TrustAll => "Trust all",
            Self::Modules { .. } => "Modules",
            Self::Inline { .. } => "Inline",
            #[cfg(not(wasm))]
            Self::Path { .. } => "Path",
        }
    }

    /// Every policy kind compiled for this target, in display order. One entry
    /// per variant; `path` is absent on wasm because file access is not
    /// available there.
    pub fn capabilities() -> Vec<PolicyCapability> {
        [
            PolicyConfig::HardwareOnly,
            PolicyConfig::HardwareOnlyStrict,
            PolicyConfig::Modules {
                modules: ModuleGroupsConfig::default(),
            },
            PolicyConfig::TrustAll,
            PolicyConfig::Inline {
                content: String::new(),
            },
            #[cfg(not(wasm))]
            PolicyConfig::Path {
                path: String::new(),
            },
        ]
        .iter()
        .map(|policy| PolicyCapability {
            policy_type: policy.name(),
            name: policy.display_name(),
            accepts_reference_values: policy.accepts_reference_values(),
            is_default: matches!(policy, PolicyConfig::HardwareOnly),
            has_content: matches!(policy, PolicyConfig::Inline { .. }),
        })
        .collect()
    }
}

/// One selectable policy kind, described for consumers that build a policy
/// chooser (for example the browser demo).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PolicyCapability {
    /// The `type` tag this policy kind uses in configuration.
    #[serde(rename = "type")]
    pub policy_type: &'static str,
    /// Human-readable name for this policy kind.
    pub name: &'static str,
    /// Whether the kind accepts a non-empty external `reference_values` list.
    pub accepts_reference_values: bool,
    /// Whether the kind is the default when `attestation_policy` is omitted.
    pub is_default: bool,
    /// Whether this kind's config object carries user-supplied `content`.
    pub has_content: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_capabilities_match_the_compiled_variants() {
        let caps = PolicyConfig::capabilities();

        #[cfg(not(wasm))]
        let expected_types = [
            "hardware_only",
            "hardware_only_strict",
            "modules",
            "trust_all",
            "inline",
            "path",
        ];
        #[cfg(wasm)]
        let expected_types = [
            "hardware_only",
            "hardware_only_strict",
            "modules",
            "trust_all",
            "inline",
        ];

        let types: Vec<_> = caps.iter().map(|c| c.policy_type).collect();
        assert_eq!(types, expected_types);
        assert!(caps.iter().all(|c| !c.name.is_empty()));

        // Exactly one default, and it is hardware_only.
        let defaults: Vec<_> = caps.iter().filter(|c| c.is_default).collect();
        assert_eq!(defaults.len(), 1);
        assert_eq!(defaults[0].policy_type, "hardware_only");

        // Accepting external reference values is the same rule the constructor
        // enforces: only user-supplied content does.
        let accepting: Vec<_> = caps
            .iter()
            .filter(|c| c.accepts_reference_values)
            .map(|c| c.policy_type)
            .collect();
        #[cfg(not(wasm))]
        assert_eq!(accepting, ["inline", "path"]);
        #[cfg(wasm)]
        assert_eq!(accepting, ["inline"]);

        let with_content: Vec<_> = caps
            .iter()
            .filter(|c| c.has_content)
            .map(|c| c.policy_type)
            .collect();
        assert_eq!(with_content, ["inline"]);
    }
}

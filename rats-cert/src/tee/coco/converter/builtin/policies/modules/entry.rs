//! The typed module-entry model: one variant per entry kind.
//!
//! Parsing turns the raw config strings and JSON values into these types once,
//! so the render phase never dispatches on a type string.

use super::super::super::policy_config::{
    value_shape, GpuPostureConfig, ModuleEntryConfig, TransparencyLogEntryConfig,
};
use super::super::super::transparency::RekorBaseline;
use super::hardware::{HardwareCheck, NvidiaHardwareConfig, TdxHardwareConfig};
use super::measurement::families::{self, parse_module_type};
use super::measurement::{Measurement, MeasurementFamily};
use super::Dimension;
use super::Platform;
use anyhow::Context;
use std::collections::BTreeSet;

/// A parsed, validated module entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ModuleEntry {
    /// A pinned measurement, one variant per extraction family.
    Measurement(Measurement),
    /// A platform or accelerator posture check.
    HardwareCheck(HardwareCheck),
    /// A ReleaseManifest baseline anchored in a transparency log. Gates the
    /// dimensions implied by its published measurement types; platform posture
    /// is expressed by a separate posture entry.
    TransparencyLog {
        config: TransparencyLogEntryConfig,
        /// Verified rekor data for a rekor-v1 primary, filled by the resolve
        /// phase. An artifact-server primary resolves its manifest at appraisal
        /// time and stays `None`.
        resolved: Option<RekorBaseline>,
    },
}

impl ModuleEntry {
    /// Parse one raw config entry into the typed model.
    pub(super) fn parse(config: &ModuleEntryConfig) -> anyhow::Result<Self> {
        Self::parse_typed(config, EntryType::parse(&config.module_type)?)
    }

    /// Validate one entry's value against its already-parsed type.
    fn parse_typed(config: &ModuleEntryConfig, entry_type: EntryType<'_>) -> anyhow::Result<Self> {
        let value_obj = || match &config.value {
            serde_json::Value::Object(_) => Ok(()),
            other => anyhow::bail!(
                "module type {:?} expects an object value, got {}",
                config.module_type,
                value_shape(other)
            ),
        };

        match entry_type {
            EntryType::Measurement { family, name } => Ok(Self::Measurement(
                families::build_measurement(family, name, &config.module_type, &config.value)?,
            )),
            EntryType::Tdx => {
                value_obj()?;
                Ok(Self::HardwareCheck(HardwareCheck::Tdx(
                    TdxHardwareConfig::parse(&config.value)?,
                )))
            }
            EntryType::Nvidia => {
                value_obj()?;
                Ok(Self::HardwareCheck(HardwareCheck::Nvidia(
                    NvidiaHardwareConfig::parse(&config.value)?,
                )))
            }
            EntryType::AlibabaGpu => {
                value_obj()?;
                let _: GpuPostureConfig = serde_json::from_value(config.value.clone())
                    .context("invalid com.alibabacloud.gpu config")?;
                Ok(Self::HardwareCheck(HardwareCheck::AlibabaGpu))
            }
            EntryType::TransparencyLog => {
                value_obj()?;
                let config: TransparencyLogEntryConfig =
                    serde_json::from_value(config.value.clone())
                        .context("invalid transparency_log config")?;
                Ok(Self::TransparencyLog {
                    config,
                    resolved: None,
                })
            }
        }
    }

    /// The AR4SI dimensions this entry gates. A measurement entry uses the
    /// dimension its family owns; a transparency-log entry gates every
    /// dimension its published types imply; every hardware check gates
    /// `hardware`.
    pub(super) fn dimensions(&self) -> BTreeSet<Dimension> {
        match self {
            Self::Measurement(measurement) => {
                std::iter::once(measurement.family().dimension()).collect()
            }
            Self::HardwareCheck(_) => std::iter::once(Dimension::Hardware).collect(),
            Self::TransparencyLog { config, .. } => config
                .published_measurements
                .iter()
                .filter_map(|t| families::dimension_for_published_type(t))
                .collect(),
        }
    }

    /// The TEE platform this entry's evidence is rooted at. Every current
    /// variant reads from `input.tdx`: the quote and event-log measurements,
    /// the AAEL event-log families, and the evaluated `nvidia_gpu.*` claims.
    pub(super) fn platform(&self) -> Platform {
        Platform::Tdx
    }
}

/// A module entry type, parsed from the raw `type` string in one place.
/// Measurement families come from the family registry, which owns every
/// accepted spelling and its canonical form.
pub(super) enum EntryType<'a> {
    Tdx,
    Nvidia,
    AlibabaGpu,
    Measurement {
        family: MeasurementFamily,
        name: &'a str,
    },
    TransparencyLog,
}

impl<'a> EntryType<'a> {
    pub(super) fn parse(raw: &'a str) -> anyhow::Result<Self> {
        match raw {
            "com.alibabacloud.gpu" => Ok(Self::AlibabaGpu),
            "tdx" => Ok(Self::Tdx),
            "nvidia" => Ok(Self::Nvidia),
            "transparency_log" => Ok(Self::TransparencyLog),
            _ => parse_module_type(raw)
                .map(|(family, name)| Self::Measurement { family, name })
                .ok_or_else(|| unknown_module_type(raw)),
        }
    }

    /// The canonical type spelling. Only the vendor-coupled entries carry the
    /// `com.alibabacloud.` prefix in their canonical form.
    pub(super) fn canonical(&self) -> String {
        match self {
            Self::Tdx => "tdx".to_string(),
            Self::Nvidia => "nvidia".to_string(),
            Self::AlibabaGpu => "com.alibabacloud.gpu".to_string(),
            Self::Measurement { family, name } => family.canonical_spelling(name),
            Self::TransparencyLog => "transparency_log".to_string(),
        }
    }

    /// Whether the entry may repeat within one group. `transparency_log`
    /// entries are separate baselines AND-ed together, and repeated container
    /// image entries for one repo coalesce into one digest set.
    pub(super) fn may_repeat(&self) -> bool {
        matches!(
            self,
            Self::TransparencyLog
                | Self::Measurement {
                    family: MeasurementFamily::ContainerImage,
                    ..
                }
        )
    }
}

pub(super) fn unknown_module_type(raw: &str) -> anyhow::Error {
    anyhow::anyhow!("unknown module type {raw:?}")
}

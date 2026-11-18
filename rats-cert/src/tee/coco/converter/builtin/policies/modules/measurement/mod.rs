//! The pinned-measurement model: one typed value per extraction family, plus
//! the digest and identifier newtypes each family validates against.

use std::collections::BTreeSet;

use strum::EnumDiscriminants;

use super::super::super::policy_config::value_shape;

pub(crate) mod families;

/// A pinned measurement. The family enum is generated from these variants, so
/// the registry cannot drift from the value space.
#[derive(Debug, Clone, PartialEq, Eq, EnumDiscriminants)]
#[strum_discriminants(name(MeasurementFamily))]
#[strum_discriminants(derive(Hash, PartialOrd, Ord, strum::EnumIter))]
pub(crate) enum Measurement {
    /// `input.tdx.quote.body.mr_td` (TDX quote MRs), a SHA-384 digest.
    TdxTdShim(Sha384Digest),
    /// `input.tdx.quote.body.mr_td` (TDX quote MRs), a SHA-384 digest.
    TdxOvmf(Sha384Digest),
    /// `td_payload` eventlog measurement, a SHA-384 digest.
    TdxKernel(Sha384Digest),
    /// `EV_EFI_BOOT_SERVICES_APPLICATION` eventlog measurement, a SHA-384
    /// digest.
    TdxUki(Sha384Digest),
    /// `td_payload_info` boot-cmdline dm-verity root hash, a SHA-256 digest.
    RootfsCc(Sha256Digest),
    /// AAEL `kangaroo/pull-image` digests for the named repo. A repo may run
    /// several versions in one TD, so the expected value is the whole set:
    /// evidence must report exactly these digests, no more and no fewer.
    ContainerImage(ContainerImageMeasurement),
    /// AAEL `pai/load-model` hash for the named model.
    AiModel(AiModelMeasurement),
}

impl Measurement {
    /// The extraction family this measurement belongs to.
    pub(super) fn family(&self) -> MeasurementFamily {
        MeasurementFamily::from(self)
    }

    /// The per-entry name a family's key takes: the repository or model id for
    /// a parameterized family, empty for a fixed one.
    pub(super) fn name(&self) -> &str {
        match self {
            Self::ContainerImage(image) => image.repo.as_str(),
            Self::AiModel(model) => model.model_id.as_str(),
            Self::TdxTdShim(_)
            | Self::TdxOvmf(_)
            | Self::TdxKernel(_)
            | Self::TdxUki(_)
            | Self::RootfsCc(_) => "",
        }
    }

    /// The single value the measurement compares against, or `None` for the
    /// set-valued container-image family.
    pub(super) fn pin(&self) -> Option<&str> {
        match self {
            Self::TdxTdShim(digest)
            | Self::TdxOvmf(digest)
            | Self::TdxKernel(digest)
            | Self::TdxUki(digest) => Some(digest.as_str()),
            Self::RootfsCc(digest) => Some(digest.as_str()),
            Self::AiModel(model) => Some(model.digest.as_str()),
            Self::ContainerImage(_) => None,
        }
    }
}

/// A 48-byte SHA-384 digest, stored as 96 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sha384Digest(String);

impl Sha384Digest {
    const HEX_LEN: usize = 96;

    pub(super) fn parse(raw_type: &str, value: &serde_json::Value) -> anyhow::Result<Self> {
        let value = string_value(raw_type, value)?;
        if !families::is_lower_hex(value, Self::HEX_LEN) {
            anyhow::bail!(
                "module type {raw_type:?} value must be {} lowercase hex chars",
                Self::HEX_LEN
            );
        }
        Ok(Self(value.to_string()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A 32-byte SHA-256 digest, stored as 64 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sha256Digest(String);

impl Sha256Digest {
    const HEX_LEN: usize = 64;

    pub(super) fn parse(raw_type: &str, value: &serde_json::Value) -> anyhow::Result<Self> {
        let value = string_value(raw_type, value)?;
        if !families::is_lower_hex(value, Self::HEX_LEN) {
            anyhow::bail!(
                "module type {raw_type:?} value must be {} lowercase hex chars",
                Self::HEX_LEN
            );
        }
        Ok(Self(value.to_string()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A `sha256:<64 lowercase hex>` OCI manifest digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ImageDigest(String);

impl ImageDigest {
    pub(super) fn parse(
        raw_type: &str,
        name: &str,
        value: &serde_json::Value,
    ) -> anyhow::Result<Self> {
        let value = string_value(raw_type, value)?;
        let valid = value
            .strip_prefix("sha256:")
            .is_some_and(|hex| families::is_lower_hex(hex, 64));
        if !valid {
            anyhow::bail!(
                "com.alibabacloud.container.image.{name} value must be sha256:<64 lowercase hex>"
            );
        }
        Ok(Self(value.to_string()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The repository segment of an image reference that appraisal extracts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RepositoryName(String);

impl RepositoryName {
    pub(super) fn parse(name: &str) -> anyhow::Result<Self> {
        if !families::is_valid_image_repo_name(name) {
            anyhow::bail!(
                "container.image name {name:?} must be a single repository segment using only ASCII letters, digits, '.', '_' and '-'"
            );
        }
        Ok(Self(name.to_string()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// An AI model identifier, which may carry `/`, `.`, `@`, `:` and `+`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModelId(String);

impl ModelId {
    pub(super) fn parse(name: &str) -> anyhow::Result<Self> {
        if !families::is_valid_module_name(name) {
            anyhow::bail!("ai.model name {name:?} has an invalid character");
        }
        Ok(Self(name.to_string()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// One or more digests observed for a container repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerImageMeasurement {
    pub(super) repo: RepositoryName,
    pub(super) digests: BTreeSet<ImageDigest>,
}

impl ContainerImageMeasurement {
    pub(super) fn parse(
        raw_type: &str,
        name: &str,
        value: &serde_json::Value,
    ) -> anyhow::Result<Self> {
        let repo = RepositoryName::parse(name)?;
        let digest = ImageDigest::parse(raw_type, name, value)?;
        Ok(Self {
            repo,
            digests: BTreeSet::from([digest]),
        })
    }
}

/// A model load event: one model id pinned to one hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AiModelMeasurement {
    pub(super) model_id: ModelId,
    pub(super) digest: Sha256Digest,
}

impl AiModelMeasurement {
    pub(super) fn parse(
        raw_type: &str,
        name: &str,
        value: &serde_json::Value,
    ) -> anyhow::Result<Self> {
        let model_id = ModelId::parse(name)?;
        let digest = Sha256Digest::parse(raw_type, value)?;
        Ok(Self { model_id, digest })
    }
}

fn string_value<'a>(raw_type: &str, value: &'a serde_json::Value) -> anyhow::Result<&'a str> {
    match value {
        serde_json::Value::String(value) => Ok(value.as_str()),
        other => anyhow::bail!(
            "module type {raw_type:?} expects a string value, got {}",
            value_shape(other)
        ),
    }
}

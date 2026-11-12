//! The `modules` attestation policy: entry parsing, validation, and Rego
//! generation.

use super::super::policy_config::{
    value_shape, GpuPostureConfig, ModuleEntryConfig, ModuleGroupsConfig, NvidiaPostureConfig,
    TcbMinStatus, TdxBit, TdxCollateralConfig, TdxEventlog, TdxPostureConfig, TdxSeptVe,
    TdxTcbConfig, TransparencyLogEntryConfig,
};
use super::measurements::{self, Families};
use super::transparency_log::{self, ResolvedRekor};
use crate::errors::*;
use anyhow::Context;

/// A parsed, validated measurement/posture module: the concrete variant the
/// generator switches on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Module {
    /// `input.tdx.quote.body.mr_td` (TDX quote MRs), 96 hex.
    TdShim {
        value: String,
    },
    /// `input.tdx.quote.body.mr_td` (TDX quote MRs), 96 hex.
    Ovmf {
        value: String,
    },
    /// `td_payload` eventlog measurement, 96 hex.
    Kernel {
        value: String,
    },
    /// `EV_EFI_BOOT_SERVICES_APPLICATION` eventlog measurement, 96 hex.
    Uki {
        value: String,
    },
    /// `td_payload_info` boot-cmdline dm-verity root hash, 64 hex.
    RootfsCc {
        value: String,
    },
    /// AAEL `kangaroo/pull-image` digest for the named repo, `sha256:`64 hex.
    ContainerImage {
        repo: String,
        digest: String,
    },
    /// AAEL `pai/load-model` hash for the named model, 64 hex.
    AiModel {
        model_id: String,
        digest: String,
    },
    Tdx(TdxPostureConfig),
    Nvidia(NvidiaPostureConfig),
    /// `com.alibabacloud.gpu`: the guest-reported AAEL attestation event.
    Gpu,
    /// `transparency_log`: a ReleaseManifest baseline anchored in a
    /// transparency log. Gates the dimensions implied by its published
    /// measurement types; platform posture is expressed by a separate `tdx`
    /// entry.
    TransparencyLog(TransparencyLogEntryConfig),
}

impl Module {
    /// The AR4SI dimensions this module gates. Measurements describe what the
    /// platform executes, except the rootfs hash which describes the file
    /// system; posture modules describe the hardware/TCB state. A
    /// transparency-log entry can publish several measurement types, so it
    /// gates every dimension those types imply.
    fn dimensions(&self) -> std::collections::BTreeSet<Dimension> {
        match self {
            Module::TransparencyLog(cfg) => cfg
                .published_measurements
                .iter()
                .filter_map(|t| measurements::dimension_for_type(t))
                .collect(),
            Module::Tdx(_) | Module::Nvidia(_) | Module::Gpu => {
                std::iter::once(Dimension::Hardware).collect()
            }
            Module::RootfsCc { .. } => std::iter::once(Dimension::FileSystem).collect(),
            _ => std::iter::once(Dimension::Executables).collect(),
        }
    }

    /// The TEE platform this entry's evidence is rooted at. Every current
    /// variant reads from `input.tdx`: the quote and event-log measurements,
    /// the AAEL event-log families, and the evaluated `nvidia_gpu.*` claims.
    fn platform(&self) -> Platform {
        Platform::Tdx
    }
}

/// TEE platforms a module entry can depend on. Only TDX exists today; the
/// generated policy uses the platform's recognition predicate as the hardware
/// base, and a second platform would add its own variant and predicate.
enum Platform {
    Tdx,
}

impl Platform {
    /// The predicate that recognises this platform in the appraisal input.
    fn recognition(&self) -> &'static str {
        match self {
            Platform::Tdx => "tdx_recognized",
        }
    }

    /// The Rego helper that defines [`Self::recognition`].
    fn recognition_rule(&self) -> &'static str {
        match self {
            Platform::Tdx => {
                "tdx_recognized if {\n\tinput.tdx.quote.header.tee_type == \"81000000\"\n\tinput.tdx.quote.header.vendor_id == \"939a7233f79c4ca9940a0db3957f0607\"\n}"
            }
        }
    }
}

/// A module entry type, parsed from the raw `type` string in one place.
/// A permanent unprefixed alias parses to the same variant as its canonical
/// `com.alibabacloud.` spelling, so normalization and duplicate detection
/// cannot disagree about what a spelling means.
enum EntryType<'a> {
    Tdx,
    Nvidia,
    AlibabaGpu,
    TdShim,
    Ovmf,
    Kernel,
    Uki,
    RootfsCc,
    ContainerImage { repo: &'a str },
    AiModel { model_id: &'a str },
    TransparencyLog,
}

impl<'a> EntryType<'a> {
    fn parse(raw: &'a str) -> anyhow::Result<Self> {
        // Vendor-prefixed canonical spellings first.
        if raw == "com.alibabacloud.gpu" {
            return Ok(Self::AlibabaGpu);
        }
        if let Some(repo) = raw.strip_prefix("com.alibabacloud.container.image.") {
            return Ok(Self::ContainerImage { repo });
        }
        if let Some(model_id) = raw.strip_prefix("com.alibabacloud.ai.model.") {
            return Ok(Self::AiModel { model_id });
        }
        if raw == "com.alibabacloud.rootfs.cc" {
            return Ok(Self::RootfsCc);
        }

        // Unprefixed non-vendor types.
        match raw {
            "tdx" => Ok(Self::Tdx),
            "nvidia" => Ok(Self::Nvidia),
            "tdx.td-shim" => Ok(Self::TdShim),
            "tdx.ovmf" => Ok(Self::Ovmf),
            "tdx.kernel" => Ok(Self::Kernel),
            "tdx.uki" => Ok(Self::Uki),
            "rootfs.cc" => Ok(Self::RootfsCc),
            "transparency_log" => Ok(Self::TransparencyLog),
            _ => {
                // Permanent unprefixed aliases of the vendor-prefixed
                // measurement families.
                if let Some(repo) = raw.strip_prefix("container.image.") {
                    Ok(Self::ContainerImage { repo })
                } else if let Some(model_id) = raw.strip_prefix("ai.model.") {
                    Ok(Self::AiModel { model_id })
                } else {
                    Err(unknown_module_type(raw))
                }
            }
        }
    }

    /// The canonical type spelling. Only the vendor-coupled entries carry the
    /// `com.alibabacloud.` prefix in their canonical form.
    fn canonical(&self) -> String {
        match self {
            Self::Tdx => "tdx".to_string(),
            Self::Nvidia => "nvidia".to_string(),
            Self::AlibabaGpu => "com.alibabacloud.gpu".to_string(),
            Self::TdShim => "tdx.td-shim".to_string(),
            Self::Ovmf => "tdx.ovmf".to_string(),
            Self::Kernel => "tdx.kernel".to_string(),
            Self::Uki => "tdx.uki".to_string(),
            Self::RootfsCc => "com.alibabacloud.rootfs.cc".to_string(),
            Self::ContainerImage { repo } => {
                format!("com.alibabacloud.container.image.{repo}")
            }
            Self::AiModel { model_id } => format!("com.alibabacloud.ai.model.{model_id}"),
            Self::TransparencyLog => "transparency_log".to_string(),
        }
    }
}

fn unknown_module_type(raw: &str) -> anyhow::Error {
    anyhow::anyhow!("unknown module type {raw:?}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Dimension {
    Executables,
    FileSystem,
    Hardware,
}

/// Name segment charset: letters, digits and `. _ / @ : + -`.
fn is_valid_module_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '@' | ':' | '+' | '-')
        })
}

/// The repository segment of an image reference that appraisal extracts:
/// the last '/'-separated path component, with any tag or digest stripped.
/// A name containing '/', '@', or ':' can never equal that segment, so it is
/// rejected at load instead of failing closed only at appraisal.
pub(super) fn is_valid_image_repo_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// A lowercase hex string of exactly `len` characters.
fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A `sha256:<64 lowercase hex>` OCI manifest digest.
fn is_sha256_digest(s: &str) -> bool {
    match s.strip_prefix("sha256:") {
        Some(hex) => is_lower_hex(hex, 64),
        None => false,
    }
}

impl ModuleEntryConfig {
    /// Test helper: parse the type spelling and convert in one step, mirroring
    /// what `parse_module_groups` does.
    #[cfg(test)]
    fn to_module_parsed(&self) -> anyhow::Result<Module> {
        self.to_module(EntryType::parse(&self.module_type)?)
    }

    /// Validate one entry's value and build a [`Module`]. The type spelling was
    /// already parsed into an [`EntryType`] by the caller, so this only checks
    /// the value shape against that family.
    fn to_module(&self, entry_type: EntryType<'_>) -> anyhow::Result<Module> {
        let value_str = || match &self.value {
            serde_json::Value::String(s) => Ok(s.clone()),
            other => anyhow::bail!(
                "module type {:?} expects a string value, got {}",
                self.module_type,
                value_shape(other)
            ),
        };
        let value_obj = || match &self.value {
            serde_json::Value::Object(_) => Ok(()),
            other => anyhow::bail!(
                "module type {:?} expects an object value, got {}",
                self.module_type,
                value_shape(other)
            ),
        };

        match entry_type {
            EntryType::Tdx => {
                value_obj()?;
                let cfg: TdxPostureConfig = serde_json::from_value(self.value.clone())
                    .context("invalid tdx posture config")?;
                if let Some(coll) = &cfg.collateral {
                    if let Some(date) = &coll.min_tcb_date {
                        if iso_date_to_epoch_secs(date).is_none() {
                            anyhow::bail!("tdx collateral min_tcb_date {date:?} is not YYYY-MM-DD");
                        }
                    }
                }
                Ok(Module::Tdx(cfg))
            }
            EntryType::AlibabaGpu => {
                value_obj()?;
                let _: GpuPostureConfig = serde_json::from_value(self.value.clone())
                    .context("invalid com.alibabacloud.gpu config")?;
                Ok(Module::Gpu)
            }
            EntryType::Nvidia => {
                value_obj()?;
                let cfg: NvidiaPostureConfig = serde_json::from_value(self.value.clone())
                    .context("invalid nvidia posture config")?;
                // `min_count` 0 would accept an empty GPU set. Omitting the
                // entry entirely is the documented way to disable GPU
                // appraisal, so a present entry must require at least one GPU.
                if cfg.min_count == 0 {
                    anyhow::bail!("nvidia min_count must be at least 1");
                }
                for d in &cfg.measurement_digest {
                    if !is_lower_hex(d, 96) {
                        anyhow::bail!(
                            "nvidia measurement_digest entries must be 96 lowercase hex chars"
                        );
                    }
                }
                Ok(Module::Nvidia(cfg))
            }
            EntryType::TdShim => {
                let v = value_str()?;
                if !is_lower_hex(&v, 96) {
                    anyhow::bail!(
                        "module type {:?} value must be 96 lowercase hex chars",
                        self.module_type
                    );
                }
                Ok(Module::TdShim { value: v })
            }
            EntryType::Ovmf => {
                let v = value_str()?;
                if !is_lower_hex(&v, 96) {
                    anyhow::bail!(
                        "module type {:?} value must be 96 lowercase hex chars",
                        self.module_type
                    );
                }
                Ok(Module::Ovmf { value: v })
            }
            EntryType::Kernel => {
                let v = value_str()?;
                if !is_lower_hex(&v, 96) {
                    anyhow::bail!(
                        "module type {:?} value must be 96 lowercase hex chars",
                        self.module_type
                    );
                }
                Ok(Module::Kernel { value: v })
            }
            EntryType::Uki => {
                let v = value_str()?;
                if !is_lower_hex(&v, 96) {
                    anyhow::bail!(
                        "module type {:?} value must be 96 lowercase hex chars",
                        self.module_type
                    );
                }
                Ok(Module::Uki { value: v })
            }
            EntryType::RootfsCc => {
                let v = value_str()?;
                if !is_lower_hex(&v, 64) {
                    anyhow::bail!(
                        "module type {:?} value must be 64 lowercase hex chars",
                        self.module_type
                    );
                }
                Ok(Module::RootfsCc { value: v })
            }
            EntryType::TransparencyLog => {
                value_obj()?;
                let cfg: TransparencyLogEntryConfig = serde_json::from_value(self.value.clone())
                    .context("invalid transparency_log config")?;
                transparency_log::validate_entry(&cfg)?;
                Ok(Module::TransparencyLog(cfg))
            }
            EntryType::ContainerImage { repo } => {
                if !is_valid_image_repo_name(repo) {
                    anyhow::bail!(
                        "container.image name {repo:?} must be a single repository segment using only ASCII letters, digits, '.', '_' and '-'"
                    );
                }
                let digest = value_str()?;
                if !is_sha256_digest(&digest) {
                    anyhow::bail!(
                        "com.alibabacloud.container.image.{repo} value must be sha256:<64 lowercase hex>"
                    );
                }
                Ok(Module::ContainerImage {
                    repo: repo.to_string(),
                    digest,
                })
            }
            EntryType::AiModel { model_id } => {
                if !is_valid_module_name(model_id) {
                    anyhow::bail!("ai.model name {model_id:?} has an invalid character");
                }
                let digest = value_str()?;
                if !is_lower_hex(&digest, 64) {
                    anyhow::bail!(
                        "com.alibabacloud.ai.model.{model_id} value must be 64 lowercase hex chars"
                    );
                }
                Ok(Module::AiModel {
                    model_id: model_id.to_string(),
                    digest,
                })
            }
        }
    }
}

/// Parse and validate every group. Rejects an unknown type, a value whose
/// shape/charset is wrong, or a duplicate module type within the same group.
/// Cross-group duplication is legal (each group is an independent baseline).
pub(crate) fn parse_module_groups(config: &ModuleGroupsConfig) -> anyhow::Result<Vec<Vec<Module>>> {
    let mut groups = Vec::new();
    for (gi, group) in config.as_groups().into_iter().enumerate() {
        // Duplicate detection is a structural check and runs before value
        // validation, so a repeated type is reported even when a value is also
        // malformed. Parsing to EntryType first makes the canonical spelling
        // and its alias collide within one group.
        let mut seen = std::collections::HashSet::new();
        let mut entry_types = Vec::with_capacity(group.len());
        for entry in group {
            let entry_type = EntryType::parse(&entry.module_type)?;
            // `transparency_log` may repeat within one group: several
            // log-anchored baselines are AND-ed (every one must verify),
            // unlike the single-baseline measurement and posture types.
            if !matches!(entry_type, EntryType::TransparencyLog)
                && !seen.insert(entry_type.canonical())
            {
                anyhow::bail!(
                    "duplicate module type {:?} within group {gi}",
                    entry_type.canonical()
                );
            }
            entry_types.push(entry_type);
        }
        let mut parsed = Vec::new();
        for (entry, entry_type) in group.iter().zip(entry_types) {
            parsed.push(entry.to_module(entry_type)?);
        }
        groups.push(parsed);
    }
    Ok(groups)
}

/// Build the `modules` Rego policy.
///
/// Each entry emits an entry predicate and gates one or more AR4SI dimensions:
/// measurements gate `executables`, except `rootfs.cc` which gates
/// `file_system`; `transparency_log` baselines gate every dimension their
/// published measurement types imply; posture entries gate `hardware`. Per
/// group and dimension a `group_<i>_<dimension>_ok` predicate ANDs that group's
/// entries of the dimension; a dimension aggregates with OR over the groups
/// that carry entries of it. A dimension with no entries stays at its affirming
/// default, so a failing posture cannot drag down `executables` and vice versa.
///
/// Every entry declares the TEE platform its evidence is rooted at, and
/// `hardware` affirms only when that platform is recognised and the group's
/// posture entries pass. With entries but no posture entries, hardware
/// requires platform recognition alone. An empty module list declares no
/// dependency, so it emits no recognition rule and `hardware` stays
/// non-affirming (97); `executables`, `configuration`, and `file_system` keep
/// their affirming defaults.
///
/// A `transparency_log` entry with a rekor-v1 primary fetches and authenticates
/// its log entry here, before rendering. An artifact-server primary defers to
/// appraisal time and does no I/O at load.
pub(super) async fn build_modules_policy(config: &ModuleGroupsConfig) -> Result<String> {
    let groups = parse_module_groups(config).map_err(Error::BuiltinPolicyTemplateFailed)?;

    let resolved = {
        let mut resolved = Vec::new();
        for module in groups.iter().flatten() {
            if let Module::TransparencyLog(cfg) = module {
                resolved.push(
                    transparency_log::resolve_entry(cfg)
                        .await
                        .map_err(Error::TransparencyLogFetchFailed)?,
                );
            }
        }
        resolved
    };

    render_modules_policy(&groups, &resolved).map_err(Error::BuiltinPolicyTemplateFailed)
}

/// Render a policy from already-parsed entries and already-resolved rekor data,
/// performing no network I/O. `resolved` holds one slot per `transparency_log`
/// entry in flatten order: `Some` for a rekor-v1 primary, `None` for an
/// artifact-server primary.
#[cfg(test)]
pub(super) fn build_modules_policy_with_resolved(
    config: &ModuleGroupsConfig,
    resolved: &[Option<ResolvedRekor>],
) -> anyhow::Result<String> {
    let groups = parse_module_groups(config)?;
    render_modules_policy(&groups, resolved)
}

fn render_modules_policy(
    groups: &[Vec<Module>],
    resolved: &[Option<ResolvedRekor>],
) -> anyhow::Result<String> {
    // Entries are associated with resolved slots by position, so the two
    // sequences must line up exactly. Reject a mismatch up front: an
    // over-supplied slice would otherwise be silently ignored.
    let transparency_entries = groups
        .iter()
        .flatten()
        .filter(|m| matches!(m, Module::TransparencyLog(_)))
        .count();
    if transparency_entries != resolved.len() {
        anyhow::bail!(
            "resolved rekor data has {} slots for {} transparency_log entries",
            resolved.len(),
            transparency_entries
        );
    }
    let mut resolved_entries = resolved.iter();
    let mut helpers: Vec<String> = Vec::new();
    let mut group_dimension_rules: Vec<String> = Vec::new();
    let mut executables_rules: Vec<String> = Vec::new();
    let mut file_system_rules: Vec<String> = Vec::new();
    let mut hardware_rules: Vec<String> = Vec::new();
    let mut has_executables = false;
    let mut has_file_system = false;
    // Measurement-extraction families the policy needs, emitted once for the
    // whole policy. Measurement entries select their own family;
    // transparency_log entries contribute the families their declared
    // published types need.
    let mut families = Families::default();
    // The platform the policy depends on. No entry means no dependency and no
    // recognition predicate is emitted. While only one platform exists, one
    // shared recognition block covers every group; when a second platform
    // lands, the block must be emitted once per distinct platform in use.
    let mut policy_platform: Option<Platform> = None;

    for (gi, group) in groups.iter().enumerate() {
        let mut executables_preds: Vec<String> = Vec::new();
        let mut file_system_preds: Vec<String> = Vec::new();
        let mut hardware_preds: Vec<String> = Vec::new();
        for (j, module) in group.iter().enumerate() {
            let pred = format!("m_{gi}_{j}");
            policy_platform.get_or_insert_with(|| module.platform());
            let body = match module {
                Module::Tdx(cfg) => {
                    let (body, extra) = tdx_posture_rule(cfg, &pred)?;
                    helpers.extend(extra);
                    body
                }
                Module::Nvidia(cfg) => nvidia_posture_rule(cfg, &pred),
                Module::Gpu => gpu_posture_rule(&pred),
                Module::TransparencyLog(cfg) => {
                    // Every transparency entry consumes its own resolved slot,
                    // in flatten order, so multiple entries cannot share or
                    // overwrite each other's baked data.
                    let entry = resolved_entries.next().ok_or_else(|| {
                        anyhow::anyhow!(
                            "no resolved rekor data for transparency_log entry m_{gi}_{j}"
                        )
                    })?;
                    families.extend_published_types(&cfg.published_measurements);
                    let prefix = format!("t_{gi}_{j}");
                    transparency_log::build_entry_rules(cfg, entry.as_ref(), &pred, &prefix)?
                }
                measurement => {
                    if let Some(family) = measurements::family_of_module(measurement) {
                        families.insert(family);
                    }
                    measurements::predicate(measurement, &pred).ok_or_else(|| {
                        anyhow::anyhow!("posture module passed to the measurement emitter")
                    })?
                }
            };
            for dimension in module.dimensions() {
                match dimension {
                    Dimension::Executables => executables_preds.push(pred.clone()),
                    Dimension::FileSystem => file_system_preds.push(pred.clone()),
                    Dimension::Hardware => hardware_preds.push(pred.clone()),
                }
            }
            helpers.push(body);
        }

        if !executables_preds.is_empty() {
            has_executables = true;
            group_dimension_rules.push(format!(
                "group_{gi}_executables_ok if {{\n{}\n}}",
                indent(&executables_preds)
            ));
            executables_rules.push(format!(
                "executables := 2 if {{\n\tgroup_{gi}_executables_ok\n}}"
            ));
        }
        if !file_system_preds.is_empty() {
            has_file_system = true;
            group_dimension_rules.push(format!(
                "group_{gi}_file_system_ok if {{\n{}\n}}",
                indent(&file_system_preds)
            ));
            file_system_rules.push(format!(
                "file_system := 2 if {{\n\tgroup_{gi}_file_system_ok\n}}"
            ));
        }
        if !hardware_preds.is_empty() {
            group_dimension_rules.push(format!(
                "group_{gi}_hardware_ok if {{\n{}\n}}",
                indent(&hardware_preds)
            ));
            // One shared recognition predicate covers every group while only
            // one platform exists. With multiple platforms this per-group rule
            // must select the group's own platform predicate.
            if let Some(platform) = policy_platform.as_ref() {
                hardware_rules.push(format!(
                    "hardware := 2 if {{\n\t{}\n\tgroup_{gi}_hardware_ok\n}}",
                    platform.recognition()
                ));
            }
        }
    }

    // Without executable-dimension entries the dimension stays affirming;
    // requiring a measurement that was never configured would be fail-closed
    // in the wrong direction. The file-system dimension behaves the same way.
    let executables_default = if has_executables { 97 } else { 2 };
    let file_system_default = if has_file_system { 97 } else { 2 };

    // With entries but no posture entries, hardware reduces to recognition of
    // the platform the entries depend on. With no entries at all, no
    // recognition rule is emitted and the non-affirming default applies.
    if hardware_rules.is_empty() {
        if let Some(platform) = policy_platform.as_ref() {
            hardware_rules.push(format!(
                "hardware := 2 if {{\n\t{}\n}}",
                platform.recognition()
            ));
        }
    }
    let recognition_block = match policy_platform.as_ref() {
        Some(platform) => format!("\n\n{}", platform.recognition_rule()),
        None => String::new(),
    };

    // The shared measurement-extraction rules are emitted once, ahead of the
    // per-entry rules that call them, and only for the families in use.
    let extraction = families.rules();
    let mut helper_parts: Vec<String> = Vec::new();
    if !extraction.is_empty() {
        helper_parts.push(extraction.trim_end().to_string());
    }
    helper_parts.extend(helpers);
    let helper_block = if helper_parts.is_empty() {
        String::new()
    } else {
        format!("{}\n\n", helper_parts.join("\n\n"))
    };
    let dimension_block = if group_dimension_rules.is_empty() {
        String::new()
    } else {
        format!("{}\n\n", group_dimension_rules.join("\n\n"))
    };
    let executables_block = executables_rules.join("\n\n");
    let file_system_block = if file_system_rules.is_empty() {
        String::new()
    } else {
        format!("{}\n\n", file_system_rules.join("\n\n"))
    };

    let policy = format!(
        r#"package policy

import rego.v1

# Modular verification rules. Each entry gates one or more AR4SI dimensions:
# boot/workload measurements gate `executables`, the rootfs dm-verity hash
# gates `file_system`, and platform posture (TDX, GPU) gates `hardware`.
# `transparency_log` entries gate every dimension their published measurement
# types imply. Within a group the entries of one dimension AND; a dimension is
# OR-ed over the groups that carry entries of it, so a group without entries of
# a dimension does not constrain it. A dimension with no entries stays
# affirming, except `hardware`, which depends on the platform every entry's
# evidence comes from: it affirms only when that platform is recognised. An
# empty module list declares no dependency and emits no recognition rule, so
# `hardware` stays at its non-affirming default.
default configuration := 2
default file_system := {file_system_default}
default hardware := 97
default executables := {executables_default}

{helper_block}{dimension_block}{executables_block}

{file_system_block}{hardware_block}{recognition_block}
"#,
        hardware_block = hardware_rules.join("\n\n"),
    );
    Ok(policy)
}

/// Indent a list of conjunct names one tab per line, for a rule body.
fn indent(items: &[String]) -> String {
    items
        .iter()
        .map(|i| format!("\t{i}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Emit the `name if { ... }` rule for a `tdx` posture entry plus helper rules
/// for the disjunctive checks (service-TD zero, rejected advisories). Every
/// field defaults to its strict choice; a field that "allows"/"optionals" adds
/// no constraint. There is no `nonce_binding` field: the `report_data` session
/// binding is enforced unconditionally by the verifier's `runtime_data` path,
/// so it is not a policy knob and is not emitted here.
fn tdx_posture_rule(cfg: &TdxPostureConfig, name: &str) -> anyhow::Result<(String, Vec<String>)> {
    let mut body: Vec<String> = Vec::new();
    let mut extra: Vec<String> = Vec::new();

    if cfg.debug == TdxBit::Deny {
        body.push(
            "\tregex.match(\"^[0-9a-f][02468ace]\", input.tdx.quote.body.td_attributes)"
                .to_string(),
        );
    }
    if cfg.sept_ve_disable == TdxSeptVe::Require {
        body.push(
            "\tregex.match(\"^[0-9a-f]{6}[13579bdf]\", input.tdx.quote.body.td_attributes)"
                .to_string(),
        );
    }
    if cfg.perfmon == TdxBit::Deny {
        body.push(
            "\tregex.match(\"^[0-9a-f]{14}[0-7]\", input.tdx.quote.body.td_attributes)".to_string(),
        );
    }
    if cfg.service_td == TdxBit::Deny {
        let helper = format!("{name}_svc_td");
        body.push(format!("\t{helper}"));
        extra.push(format!(
            r#"{helper} if {{
	not input.tdx.quote.body.mr_servicetd
}}

{helper} if {{
	regex.match("^0{{96}}$", input.tdx.quote.body.mr_servicetd)
}}"#
        ));
    }

    // TCB gate (opt-in). A revoked status always rejects; `up_to_date` further
    // rejects the out-of-date ranks. `advisory_ids` is a comma-joined string.
    if let Some(tcb) = &cfg.tcb {
        body.push("\tv := input.tdx.tcb_verification".to_string());
        body.push("\tv.tcb_status != \"Revoked\"".to_string());
        if tcb.min_status == TcbMinStatus::UpToDate {
            body.push(
                "\tv.tcb_status in [\"UpToDate\", \"ConfigurationNeeded\", \"SWHardeningNeeded\", \"ConfigurationAndSWHardeningNeeded\"]".to_string(),
            );
        }
        if !tcb.reject_advisories.is_empty() {
            let helper = format!("{name}_adv");
            let reject = rego_string_array(&tcb.reject_advisories);
            let allow = rego_string_array(&tcb.allow_advisories);
            body.push(format!("\tnot {helper}"));
            extra.push(format!(
                r#"{helper} if {{
	some a in {reject}
	a in split(input.tdx.tcb_verification.advisory_ids, ",")
	not a in {allow}
}}"#
            ));
        }
    }

    // Collateral gate (opt-in). All thresholds are compared against the
    // epoch-second fields that the native TDX verifier places in
    // `tcb_verification`.
    if let Some(coll) = &cfg.collateral {
        body.push("\tvc := input.tdx.tcb_verification".to_string());
        if !coll.allow_expired {
            body.push("\tvc.collateral_expired == false".to_string());
        }
        if let Some(date) = &coll.min_tcb_date {
            let epoch = iso_date_to_epoch_secs(date).with_context(|| {
                format!("validated tdx collateral min_tcb_date {date:?} is not convertible to epoch seconds")
            })?;
            body.push(format!("\tvc.tcb_level_date_tag >= {epoch}"));
        }
        if let Some(days) = coll.max_collateral_age_days {
            let secs = days as i64 * 86400;
            body.push(format!(
                "\t(time.now_ns() / 1000000000) - vc.latest_issue_date <= {secs}"
            ));
        }
    }

    if cfg.eventlog == TdxEventlog::Required {
        body.push("\tcount(input.tdx.uefi_event_logs) > 0".to_string());
    }

    if body.is_empty() {
        return Ok((format!("{name} if {{\n\ttrue\n}}"), extra));
    }
    Ok((format!("{name} if {{\n{}\n}}", body.join("\n")), extra))
}

/// Emit the `com.alibabacloud.gpu` rule: the guest-reported AAEL GPU
/// attestation event must exist and every such event must report zero for both
/// result codes.
fn gpu_posture_rule(pred: &str) -> String {
    format!(
        r#"{pred} if {{
	events := [e |
		some e in input.tdx.uefi_event_logs
		e.type_name == "EV_EVENT_TAG"
		e.details.unicode_name == "AAEL"
		e.details.data.domain == "alibabacloud.com"
		e.details.data.operation == "gpu/attestation"
	]
	count(events) > 0
	every e in events {{
		e.details.data.content["gpu-collect-evidence-result-code"] == 0
		e.details.data.content["gpu-attest-result-code"] == 0
	}}
}}"#
    )
}

/// Emit the `nvidia` posture rule: the standard trustee NVIDIA appraisal over
/// the evaluated per-GPU claims, rejecting the raw/skip passthrough form (which
/// carries attestation_report and lacks measurement).
fn nvidia_posture_rule(cfg: &NvidiaPostureConfig, pred: &str) -> String {
    let mut gpu_body: Vec<String> = Vec::new();
    gpu_body.push("\t\tnot g.attestation_report".to_string());
    if cfg.require_report {
        gpu_body.push("\t\tg.measurement".to_string());
    }
    if cfg.require_cc_mode {
        gpu_body.push("\t\tg.cc_enabled == true".to_string());
    }
    if !cfg.allow_uuids.is_empty() {
        gpu_body.push(format!(
            "\t\tg.uuid in {}",
            rego_string_array(&cfg.allow_uuids)
        ));
    }
    if !cfg.allow_driver_versions.is_empty() {
        gpu_body.push(format!(
            "\t\tg.driver_version in {}",
            rego_string_array(&cfg.allow_driver_versions)
        ));
    }
    if !cfg.allow_vbios_versions.is_empty() {
        gpu_body.push(format!(
            "\t\tg.vbios_version in {}",
            rego_string_array(&cfg.allow_vbios_versions)
        ));
    }
    if !cfg.measurement_digest.is_empty() {
        gpu_body.push(format!(
            "\t\tg.measurement in {}",
            rego_string_array(&cfg.measurement_digest)
        ));
    }
    let gpu_conj = gpu_body.join("\n");
    format!(
        r#"{pred} if {{
	gpus := [g |
		g := input.tdx[k]
		startswith(k, "nvidia_gpu.")
	]
	count(gpus) >= {min}
	every g in gpus {{
{inner}
	}}
}}"#,
        min = cfg.min_count,
        inner = gpu_conj
    )
}

/// Render a slice of strings as a Rego array literal.
fn rego_string_array(items: &[String]) -> String {
    let inner = items
        .iter()
        .map(|s| format!("{s:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{inner}]")
}

/// Convert a strict `YYYY-MM-DD` date to Unix epoch seconds (UTC midnight).
/// Returns `None` for anything else, including a calendar-invalid day (e.g.
/// `2026-02-31`), which the caller surfaces as a config error.
fn iso_date_to_epoch_secs(date: &str) -> Option<i64> {
    let bytes = date.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    // Positions 4 and 7 are the separators; every other byte must be an ASCII
    // digit, which also keeps the fixed-offset slices below on char boundaries.
    if !bytes
        .iter()
        .enumerate()
        .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
    {
        return None;
    }
    let year: i64 = date[0..4].parse().ok()?;
    let month: i64 = date[5..7].parse().ok()?;
    let day: i64 = date[8..10].parse().ok()?;
    if !(1..=12).contains(&month) {
        return None;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=max_day).contains(&day) {
        return None;
    }
    // Civil-days algorithm (Howard Hinnant) for days since 1970-01-01.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::eval_policy_vector;
    use super::*;
    use crate::tee::coco::converter::builtin::converter::BuiltinCocoConverter;
    use crate::tee::coco::converter::builtin::policy_config::{
        PolicyConfig, ReferenceValueConfig, SampleProvenancePayloadConfig,
    };
    use reference_value_provider_service::extractors::extractor_modules::sample::Provenance;
    use serde_json::json;

    // --- modules policy -----------------------------------------------------

    fn modules_cfg(json: &str) -> ModuleGroupsConfig {
        serde_json::from_str(json).expect("modules config parses")
    }

    /// Render a policy without network I/O. None of these tests use a
    /// `transparency_log` entry, so no resolved rekor data is needed.
    fn build_policy(config: &ModuleGroupsConfig) -> anyhow::Result<String> {
        build_modules_policy_with_resolved(config, &[])
    }

    #[test]
    fn modules_config_flat_and_nested_parse() {
        // Flat single group.
        let flat: PolicyConfig = serde_json::from_str(
            r#"{"type":"modules","modules":[{"type":"tdx.ovmf","value":"aaaa"}]}"#,
        )
        .expect("flat parse");
        let PolicyConfig::Modules { modules } = &flat else {
            panic!("expected Modules");
        };
        assert!(matches!(modules, ModuleGroupsConfig::Single(_)));
        assert_eq!(modules.as_groups().len(), 1);

        // Nested multi-group.
        let nested: PolicyConfig = serde_json::from_str(
        r#"{"type":"modules","modules":[[{"type":"tdx.ovmf","value":"aaaa"}],[{"type":"tdx.kernel","value":"bbbb"}]]}"#,
    )
    .expect("nested parse");
        let PolicyConfig::Modules { modules } = &nested else {
            panic!("expected Modules");
        };
        assert!(matches!(modules, ModuleGroupsConfig::Groups(_)));
        assert_eq!(modules.as_groups().len(), 2);

        // Missing `modules` field defaults to one empty group.
        let bare: PolicyConfig = serde_json::from_str(r#"{"type":"modules"}"#).expect("bare parse");
        let PolicyConfig::Modules { modules } = &bare else {
            panic!("expected Modules");
        };
        assert_eq!(modules.as_groups().len(), 1);
        assert!(modules.as_groups()[0].is_empty());
    }

    #[test]
    fn modules_entry_validation() {
        let ok_hex96 = "a".repeat(96);
        let ok_hex64 = "b".repeat(64);
        let ok_sha = format!("sha256:{}", "c".repeat(64));

        // Good values parse.
        for (t, v) in [
            ("tdx.td-shim", ok_hex96.clone()),
            ("tdx.ovmf", ok_hex96.clone()),
            ("tdx.kernel", ok_hex96.clone()),
            ("tdx.uki", ok_hex96.clone()),
            (
                "com.alibabacloud.container.image.model-server",
                ok_sha.clone(),
            ),
            (
                "com.alibabacloud.ai.model.Qwen/Qwen3.8-27B",
                ok_hex64.clone(),
            ),
            ("com.alibabacloud.rootfs.cc", ok_hex64.clone()),
        ] {
            let entry = ModuleEntryConfig {
                module_type: t.to_string(),
                value: json!(v),
            };
            assert!(entry.to_module_parsed().is_ok(), "expected ok for {t}");
        }
        // The unprefixed spellings are permanent aliases of the two
        // Alibaba-coupled measurement families.
        for (t, v) in [
            ("container.image.model-server", ok_sha.clone()),
            ("ai.model.Qwen/Qwen3.8-27B", ok_hex64.clone()),
            ("rootfs.cc", ok_hex64.clone()),
        ] {
            let entry = ModuleEntryConfig {
                module_type: t.to_string(),
                value: json!(v),
            };
            assert!(entry.to_module_parsed().is_ok(), "expected ok for {t}");
        }

        // Bad value shapes.
        assert!(ModuleEntryConfig {
            module_type: "tdx.ovmf".to_string(),
            value: json!("tooshort"),
        }
        .to_module_parsed()
        .is_err());
        // uppercase hex rejected
        assert!(ModuleEntryConfig {
            module_type: "tdx.ovmf".to_string(),
            value: json!("A".repeat(96)),
        }
        .to_module_parsed()
        .is_err());
        // The rootfs root hash is exactly 64 lowercase hex chars; any other
        // `rootfs.` spelling is an unknown type.
        assert!(ModuleEntryConfig {
            module_type: "com.alibabacloud.rootfs.cc".to_string(),
            value: json!("A".repeat(64)),
        }
        .to_module_parsed()
        .is_err());
        assert!(ModuleEntryConfig {
            module_type: "rootfs.cc".to_string(),
            value: json!("a".repeat(63)),
        }
        .to_module_parsed()
        .is_err());
        for t in ["rootfs.foo", "rootfs."] {
            assert!(
                ModuleEntryConfig {
                    module_type: t.to_string(),
                    value: json!("a".repeat(64)),
                }
                .to_module_parsed()
                .is_err(),
                "unknown type {t} must be rejected"
            );
        }
        // container.image needs sha256: prefix
        assert!(ModuleEntryConfig {
            module_type: "container.image.foo".to_string(),
            value: json!("c".repeat(64)),
        }
        .to_module_parsed()
        .is_err());
        // measurement entry with an object value is rejected
        assert!(ModuleEntryConfig {
            module_type: "tdx.ovmf".to_string(),
            value: json!({}),
        }
        .to_module_parsed()
        .is_err());

        // Unprefixed `gpu` has no alias and is rejected, as is the vendor
        // prefix on a type that is not Alibaba-coupled.
        assert!(ModuleEntryConfig {
            module_type: "gpu".to_string(),
            value: json!({}),
        }
        .to_module_parsed()
        .is_err());
        assert!(ModuleEntryConfig {
            module_type: "com.alibabacloud.tdx.ovmf".to_string(),
            value: json!(ok_hex96.clone()),
        }
        .to_module_parsed()
        .is_err());
        assert!(ModuleEntryConfig {
            module_type: "com.alibabacloud.nvidia".to_string(),
            value: json!({}),
        }
        .to_module_parsed()
        .is_err());
        // Unknown type rejected.
        assert!(ModuleEntryConfig {
            module_type: "cpu".to_string(),
            value: json!("x"),
        }
        .to_module_parsed()
        .is_err());

        // Bad name charset rejected.
        assert!(ModuleEntryConfig {
            module_type: "ai.model.ba d".to_string(),
            value: json!(ok_hex64.clone()),
        }
        .to_module_parsed()
        .is_err());
        // Posture module with wrong value type rejected.
        assert!(ModuleEntryConfig {
            module_type: "tdx".to_string(),
            value: json!("not-an-object"),
        }
        .to_module_parsed()
        .is_err());
        assert!(ModuleEntryConfig {
            module_type: "nvidia".to_string(),
            value: json!([]),
        }
        .to_module_parsed()
        .is_err());

        // Each measurement family rejects its own malformed baseline value.
        for t in [
            "tdx.kernel",
            "tdx.uki",
            "ai.model.Qwen/Qwen3.8-27B",
            "rootfs.cc",
            "com.alibabacloud.rootfs.cc",
        ] {
            assert!(
                ModuleEntryConfig {
                    module_type: t.to_string(),
                    value: json!("tooshort"),
                }
                .to_module_parsed()
                .is_err(),
                "short value must fail for {t}"
            );
        }
        // Name-bearing families reject a bad charset in the name segment.
        for t in ["container.image.ba d", "ai.model.ba d"] {
            assert!(
                ModuleEntryConfig {
                    module_type: t.to_string(),
                    value: json!(ok_hex64.clone()),
                }
                .to_module_parsed()
                .is_err(),
                "bad name charset must fail for {t}"
            );
        }
        // Name-bearing families reject an empty name segment, canonical and
        // alias spellings alike.
        for t in ["com.alibabacloud.container.image.", "container.image."] {
            assert!(
                ModuleEntryConfig {
                    module_type: t.to_string(),
                    value: json!(ok_sha.clone()),
                }
                .to_module_parsed()
                .is_err(),
                "empty repo must fail for {t}"
            );
        }
        for t in ["com.alibabacloud.ai.model.", "ai.model."] {
            assert!(
                ModuleEntryConfig {
                    module_type: t.to_string(),
                    value: json!(ok_hex64.clone()),
                }
                .to_module_parsed()
                .is_err(),
                "empty model-id must fail for {t}"
            );
        }

        // The container image repository is a single path segment: characters
        // that can never appear in the extracted repo tail are rejected.
        for t in [
            "container.image.foo/bar",
            "container.image.foo@sha256",
            "container.image.foo:tag",
        ] {
            assert!(
                ModuleEntryConfig {
                    module_type: t.to_string(),
                    value: json!(ok_sha.clone()),
                }
                .to_module_parsed()
                .is_err(),
                "expected reject for {t}"
            );
        }
        // Dots, underscores and dashes remain valid in the repository segment.
        for t in ["container.image.model-server", "container.image.my-app.v2"] {
            assert!(
                ModuleEntryConfig {
                    module_type: t.to_string(),
                    value: json!(ok_sha.clone()),
                }
                .to_module_parsed()
                .is_ok(),
                "expected ok for {t}"
            );
        }
        // The tightening is container-image specific: a model id keeps `/`.
        assert!(ModuleEntryConfig {
            module_type: "ai.model.Qwen/Qwen3.8-27B".to_string(),
            value: json!(ok_hex64.clone()),
        }
        .to_module_parsed()
        .is_ok());

        // Non-string values are rejected with a shape-name error, one arm per
        // JSON kind.
        for v in [serde_json::Value::Null, json!(true), json!(123), json!([])] {
            assert!(
                ModuleEntryConfig {
                    module_type: "tdx.ovmf".to_string(),
                    value: v,
                }
                .to_module_parsed()
                .is_err(),
                "non-string measurement value must fail"
            );
        }

        // tdx collateral min_tcb_date must be YYYY-MM-DD.
        assert!(ModuleEntryConfig {
            module_type: "tdx".to_string(),
            value: json!({ "collateral": { "min_tcb_date": "2026/1/2" } }),
        }
        .to_module_parsed()
        .is_err());

        // nvidia measurement_digest entries must be 96 lowercase hex chars.
        assert!(ModuleEntryConfig {
            module_type: "nvidia".to_string(),
            value: json!({ "measurement_digest": ["tooshort"] }),
        }
        .to_module_parsed()
        .is_err());

        // A present nvidia entry must require at least one GPU: min_count 0 is
        // rejected (omitting the entry is how GPU appraisal is disabled).
        let err = ModuleEntryConfig {
            module_type: "nvidia".to_string(),
            value: json!({ "min_count": 0 }),
        }
        .to_module_parsed()
        .unwrap_err()
        .to_string();
        assert!(err.contains("min_count must be at least 1"), "{err}");
        assert!(ModuleEntryConfig {
            module_type: "nvidia".to_string(),
            value: json!({ "min_count": 1 }),
        }
        .to_module_parsed()
        .is_ok());
    }

    #[test]
    fn modules_nvidia_standard_appraisal_only() {
        // `nvidia` now always means the standard trustee appraisal; an empty
        // object is valid and takes the documented defaults.
        let module = ModuleEntryConfig {
            module_type: "nvidia".to_string(),
            value: json!({}),
        }
        .to_module_parsed()
        .expect("empty nvidia value must parse");
        let Module::Nvidia(cfg) = module else {
            panic!("expected Nvidia");
        };
        assert!(cfg.require_cc_mode);
        assert!(cfg.require_report);
        assert_eq!(cfg.min_count, 1);
        assert!(cfg.allow_uuids.is_empty());

        // The removed `verify` switch is now an unknown field.
        let err = ModuleEntryConfig {
            module_type: "nvidia".to_string(),
            value: json!({ "verify": "local" }),
        }
        .to_module_parsed()
        .unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("unknown field `verify`"), "{err}");
    }

    #[test]
    fn modules_vendor_namespace_aliases() {
        let digest = format!("sha256:{}", "c".repeat(64));
        let hash = "b".repeat(64);
        for (canonical, alias, value) in [
            (
                "com.alibabacloud.container.image.model-server",
                "container.image.model-server",
                json!(digest),
            ),
            (
                "com.alibabacloud.ai.model.Qwen/Qwen3.8-27B",
                "ai.model.Qwen/Qwen3.8-27B",
                json!(hash),
            ),
            ("com.alibabacloud.rootfs.cc", "rootfs.cc", json!(hex64('e'))),
        ] {
            let canonical_module = ModuleEntryConfig {
                module_type: canonical.to_string(),
                value: value.clone(),
            }
            .to_module_parsed()
            .expect("canonical parses");
            let alias_module = ModuleEntryConfig {
                module_type: alias.to_string(),
                value: value.clone(),
            }
            .to_module_parsed()
            .expect("alias parses");
            assert_eq!(
                canonical_module, alias_module,
                "{canonical} and {alias} must parse identically"
            );

            // Both spellings must generate byte-identical rego.
            let canonical_policy =
                build_policy(&ModuleGroupsConfig::Single(vec![ModuleEntryConfig {
                    module_type: canonical.to_string(),
                    value: value.clone(),
                }]))
                .expect("build canonical");
            let alias_policy = build_policy(&ModuleGroupsConfig::Single(vec![ModuleEntryConfig {
                module_type: alias.to_string(),
                value,
            }]))
            .expect("build alias");
            assert_eq!(canonical_policy, alias_policy);
        }
    }

    /// Build the `td_payload_info` platform-config-flags event carrying a
    /// `verity-root` dm-mod.create mapping for `root`.
    fn rootfs_event(index: Option<i64>, root: &str) -> serde_json::Value {
        let details = format!(
            "td_payload_info reboot=k root=/dev/vda1 dm-mod.create=\"verity-root,,,ro,0 1011712 verity 1 /dev/vda1 /dev/vda2 4096 4096 126464 0 sha256 {root} {tail};\"",
            tail = "0".repeat(64)
        );
        let mut e = json!({
            "type_name": "EV_PLATFORM_CONFIG_FLAGS",
            "details": { "string": details },
        });
        if let Some(index) = index {
            e["index"] = json!(index);
        }
        e
    }

    #[test]
    fn modules_rootfs_cc_gates_file_system() {
        let root = hex64('a');
        let policy = build_policy(&modules_cfg(&format!(
            r#"[{{"type":"rootfs.cc","value":"{root}"}}]"#
        )))
        .expect("build");

        // The rootfs entry is attributed to `file_system`, which becomes
        // non-affirming by default; `executables` keeps its affirming default.
        assert!(policy.contains("default file_system := 97"));
        assert!(policy.contains("default executables := 2"));
        assert!(policy.contains("group_0_file_system_ok if {"));
        assert!(policy.contains("file_system := 2 if {\n\tgroup_0_file_system_ok\n}"));
        assert!(!policy.contains("group_0_executables_ok"));
        assert_eq!(
            policy
                .matches("actual_measurement(\"rootfs.cc\") :=")
                .count(),
            1
        );

        // A config without a rootfs entry keeps the affirming default and
        // emits no file_system rules.
        let old = build_policy(&modules_cfg(&format!(
            r#"[{{"type":"tdx.ovmf","value":"{}"}}]"#,
            hex96('1')
        )))
        .expect("build");
        assert!(old.contains("default file_system := 2"));
        assert!(!old.contains("group_0_file_system_ok"));
        assert!(!old.contains("file_system := 2 if {"));
    }

    #[tokio::test]
    async fn modules_rootfs_cc_matches_and_rejects() {
        let root = hex64('a');
        let cfg = format!(r#"[{{"type":"rootfs.cc","value":"{root}"}}]"#);

        let ok = tdx_input(serde_json::Value::Null, &[rootfs_event(Some(2), &root)]);
        assert_eq!(
            eval_modules(&cfg, &ok).await,
            (2, 2, 2, 2),
            "a matching rootfs measurement must affirm file_system"
        );

        // A mismatched root hash moves only the file_system dimension.
        let mismatch = tdx_input(
            serde_json::Value::Null,
            &[rootfs_event(Some(2), &hex64('b'))],
        );
        assert_eq!(
            eval_modules(&cfg, &mismatch).await,
            (2, 2, 2, 97),
            "a tampered root hash must reject file_system, leaving executables affirming"
        );

        // A missing or mis-indexed event is fail-closed.
        let none = tdx_input(serde_json::Value::Null, &[json!({ "event": "ok" })]);
        assert_eq!(
            eval_modules(&cfg, &none).await,
            (2, 2, 2, 97),
            "a missing td_payload_info event must reject file_system"
        );
        let bad_index = tdx_input(serde_json::Value::Null, &[rootfs_event(Some(1), &root)]);
        assert_eq!(
            eval_modules(&cfg, &bad_index).await,
            (2, 2, 2, 97),
            "an event at a non-RTMR1 index must reject file_system"
        );
    }

    /// `rootfs.cc` reads `input.tdx`, so it depends on TDX recognition for the
    /// `hardware` dimension even though the measurement itself only gates
    /// `file_system`.
    #[tokio::test]
    async fn modules_rootfs_cc_requires_tdx_recognition() {
        let root = hex64('a');
        let cfg = format!(r#"[{{"type":"rootfs.cc","value":"{root}"}}]"#);
        let input = json!({
            "tdx": {
                "quote": {
                    "header": {"tee_type": "00000000", "vendor_id": "deadbeef"},
                    "body": {"td_attributes": "0000001000000000"},
                },
                "uefi_event_logs": [rootfs_event(Some(2), &root)],
            }
        })
        .to_string();
        assert_eq!(
            eval_modules(&cfg, &input).await,
            (2, 97, 2, 2),
            "a non-TDX quote must leave hardware non-affirming while file_system matches"
        );
    }

    // The loop is the extension point: every Platform variant must be listed
    // here, and the lint only fires while the list has one entry.
    #[allow(clippy::single_element_loop)]
    #[test]
    fn platform_recognition_predicate_matches_its_rule() {
        // Every Platform variant must be listed here. The rule text has to
        // define the predicate that recognition() names, so a second platform
        // cannot ship with a mismatched helper name.
        for platform in [Platform::Tdx] {
            let name = platform.recognition();
            let rule = platform.recognition_rule();
            let expected = format!("{name} if {{");
            assert!(
                rule.starts_with(&expected),
                "platform rule must define {name:?}: {rule}"
            );
        }
    }

    #[test]
    fn modules_entry_type_parse_accepts_every_accepted_spelling() {
        // Every accepted spelling must parse; the diagnostic reports the
        // rejected string alone.
        let accepted = [
            "tdx",
            "nvidia",
            "com.alibabacloud.gpu",
            "tdx.td-shim",
            "tdx.ovmf",
            "tdx.kernel",
            "tdx.uki",
            "transparency_log",
            "com.alibabacloud.container.image.model-server",
            "container.image.model-server",
            "com.alibabacloud.ai.model.Qwen/Qwen3.8-27B",
            "ai.model.Qwen/Qwen3.8-27B",
            "com.alibabacloud.rootfs.cc",
            "rootfs.cc",
        ];
        for spelling in accepted {
            assert!(
                EntryType::parse(spelling).is_ok(),
                "accepted spelling {spelling:?} must parse"
            );
        }

        // `rootfs.` is a fixed type, not a namespace: any other spelling is
        // unknown.
        assert!(EntryType::parse("rootfs.foo").is_err());
        assert!(EntryType::parse("rootfs.").is_err());

        // The diagnostic no longer enumerates the accepted types.
        let err = unknown_module_type("not.a.module").to_string();
        assert_eq!(err, "unknown module type \"not.a.module\"");
    }

    #[test]
    fn modules_duplicate_type_rules() {
        // Same type twice within one group is rejected (before value checks).
        let dup_same_group = modules_cfg(
            r#"[{"type":"tdx.ovmf","value":"aaaa"},{"type":"tdx.ovmf","value":"bbbb"}]"#,
        );
        assert!(parse_module_groups(&dup_same_group)
            .unwrap_err()
            .to_string()
            .contains("duplicate"));

        // Same type across different groups is legal (independent baselines).
        let dup_cross_group = modules_cfg(&format!(
            r#"[[{{"type":"tdx.ovmf","value":"{}"}}],[{{"type":"tdx.ovmf","value":"{}"}}]]"#,
            hex96('a'),
            hex96('b')
        ));
        assert!(parse_module_groups(&dup_cross_group).is_ok());

        // `transparency_log` is the one type exempt from the same-group
        // duplicate rejection: several log-anchored baselines are AND-ed.
        let dup_transparency = modules_cfg(
            r#"[
              {"type":"transparency_log","value":{"publishedMeasurements":["tdx.td-shim"],"services":[{"type":"rekor-v1","logUrl":"https://r1","logIndex":1}]}},
              {"type":"transparency_log","value":{"publishedMeasurements":["tdx.td-shim"],"services":[{"type":"rekor-v1","logUrl":"https://r2","logIndex":2}]}}
            ]"#,
        );
        assert!(
            parse_module_groups(&dup_transparency).is_ok(),
            "repeated transparency_log entries within one group must be legal"
        );

        // Mixed spellings of a canonical type collide after normalization.
        for (canonical, alias, value) in [
            (
                "com.alibabacloud.container.image.model-server",
                "container.image.model-server",
                format!("sha256:{}", hex64('c')),
            ),
            (
                "com.alibabacloud.ai.model.Qwen/Qwen3.8-27B",
                "ai.model.Qwen/Qwen3.8-27B",
                hex64('d'),
            ),
            ("com.alibabacloud.rootfs.cc", "rootfs.cc", hex64('e')),
        ] {
            let mixed = ModuleGroupsConfig::Single(vec![
                ModuleEntryConfig {
                    module_type: canonical.to_string(),
                    value: json!(value),
                },
                ModuleEntryConfig {
                    module_type: alias.to_string(),
                    value: json!(value),
                },
            ]);
            let err = parse_module_groups(&mixed).unwrap_err().to_string();
            assert!(err.contains("duplicate"), "{canonical}/{alias}: {err}");
        }
    }

    #[test]
    fn modules_policy_rego_snapshot() {
        let ovmf = hex96('1');
        let policy = build_policy(&modules_cfg(&format!(
            r#"[
          {{"type":"tdx","value":{{}}}},
          {{"type":"tdx.ovmf","value":"{ovmf}"}}
        ]"#,
        )))
        .expect("build");
        assert!(policy.contains("package policy"));
        assert!(policy.contains("import rego.v1"));
        // Both dimensions carry entries, so executables defaults non-affirming.
        assert!(policy.contains("default executables := 97"));
        assert!(policy.contains("default hardware := 97"));
        // The pinned value is embedded as a literal in a one-line equality
        // predicate; the extraction rule itself reads the quote field.
        assert!(policy.contains(&format!(
            "m_0_1 if {{\n\tactual_measurement(\"tdx.ovmf\") == \"{ovmf}\"\n}}"
        )));
        assert!(policy.contains("digest := input.tdx.quote.body.mr_td"));
        // One extraction block for the whole policy.
        assert_eq!(
            policy
                .matches("actual_measurement(\"tdx.ovmf\") :=")
                .count(),
            1
        );
        assert!(!policy.contains("query_reference_value"));
        // per-dimension group predicates
        assert!(policy.contains("group_0_executables_ok if {"));
        assert!(policy.contains("group_0_hardware_ok if {"));
        // executables ORs the measurement groups; hardware requires recognition
        assert!(policy.contains("executables := 2 if {\n\tgroup_0_executables_ok\n}"));
        assert!(policy.contains("hardware := 2 if {\n\ttdx_recognized\n\tgroup_0_hardware_ok\n}"));
        assert!(policy.contains("tdx_recognized if {"));
        assert!(policy.contains(r#"input.tdx.quote.header.tee_type == "81000000""#));
        assert!(policy
            .contains(r#"input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607""#));
        // Only TDX is recognised; the legacy CSV/TPM/system paths are gone.
        assert!(!policy.contains("input.csv"));
        assert!(!policy.contains("input.tpm"));
        assert!(!policy.contains("input.system"));
        // tdx posture default: debug regex + eventlog count
        assert!(policy
            .contains("regex.match(\"^[0-9a-f][02468ace]\", input.tdx.quote.body.td_attributes)"));
        assert!(policy.contains("count(input.tdx.uefi_event_logs) > 0"));
    }

    #[test]
    fn modules_policy_no_executables_keeps_executables_affirming() {
        // A posture-only policy must not make the executables dimension depend
        // on the posture: there are no measurement entries to satisfy.
        let policy = build_policy(&modules_cfg(r#"[{"type":"tdx","value":{}}]"#)).expect("build");
        assert!(policy.contains("default executables := 2"));
        assert!(!policy.contains("group_0_executables_ok"));
        // No measurement entries, so hardware reduces to recognition plus the
        // posture group.
        assert!(policy.contains("hardware := 2 if {\n\ttdx_recognized\n\tgroup_0_hardware_ok\n}"));
        // A posture-only policy needs no measurement extraction at all.
        assert!(!policy.contains("actual_measurement"));
    }

    #[test]
    fn modules_policy_measurement_entry_emits_extraction_once() {
        // A measurement entry emits its extraction family once, whether or not
        // a transparency_log entry is present.
        let image = format!("sha256:{}", "c".repeat(64));
        let policy = build_policy(&modules_cfg(&format!(
            r#"[{{"type":"com.alibabacloud.container.image.model-server","value":"{image}"}}]"#
        )))
        .expect("build");
        assert_eq!(policy.matches("image_repo_name(ref) :=").count(), 1);
        assert_eq!(
            policy.matches("actual_measurement(type) :=").count(),
            1,
            "{policy}"
        );
        // The one-line predicate names the canonical (unprefixed) key.
        assert!(policy.contains(&format!(
            "m_0_0 if {{\n\tactual_measurement(\"container.image.model-server\") == \"{image}\"\n}}"
        )));
        // No format regex is emitted: the pin is validated at load instead.
        assert!(!policy.contains("regex.match(\"^sha256:"), "{policy}");
        // The blob-length host function is not part of any generated policy.
        assert!(!policy.contains("td_payload_blob_length"), "{policy}");
    }

    #[test]
    fn modules_policy_no_posture_uses_tdx_recognition_only() {
        let ovmf = hex96('1');
        let policy = build_policy(&modules_cfg(&format!(
            r#"[{{"type":"tdx.ovmf","value":"{ovmf}"}}]"#
        )))
        .expect("build");
        assert!(!policy.contains("group_0_hardware_ok"));
        assert!(policy.contains("tdx_recognized if {"));
        assert!(policy.contains("hardware := 2 if {\n\ttdx_recognized\n}"));
        // The empty list declares no dependency: no recognition rule and no
        // hardware-affirming rule, so the default hardware := 97 applies.
        let empty = build_policy(&modules_cfg("[]")).expect("build");
        assert!(empty.contains("default executables := 2"));
        assert!(empty.contains("default hardware := 97"));
        assert!(!empty.contains("tdx_recognized"));
        assert!(!empty.contains("hardware := 2 if {"));
    }

    #[test]
    fn modules_policy_rego_snapshot_groups_or() {
        let policy = build_policy(&modules_cfg(
        r#"[
          [{"type":"tdx.ovmf","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
          [{"type":"tdx.ovmf","value":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]
        ]"#,
    ))
    .expect("build");
        // two groups -> two OR-ed executables disjuncts
        assert_eq!(
            policy.matches("executables := 2 if {").count(),
            2,
            "{policy}"
        );
        assert_eq!(policy.matches("group_0_executables_ok if {").count(), 1);
        assert_eq!(policy.matches("group_1_executables_ok if {").count(), 1);
        // each group carries its own pinned literal; no group-suffixed reference names
        let (a, b) = ("a".repeat(96), "b".repeat(96));
        assert!(policy.contains(&format!("actual_measurement(\"tdx.ovmf\") == \"{a}\"")));
        assert!(policy.contains(&format!("actual_measurement(\"tdx.ovmf\") == \"{b}\"")));
        // Two entries share one extraction rule.
        assert_eq!(
            policy
                .matches("actual_measurement(\"tdx.ovmf\") :=")
                .count(),
            1
        );
        assert!(!policy.contains("query_reference_value"));
        assert!(!policy.contains(".g0") && !policy.contains(".g1"));
    }

    #[test]
    fn modules_policy_tdx_rejects_nonce_binding_key() {
        // `nonce_binding` was removed: the report_data session binding is a
        // verifier baseline, not a policy knob. `deny_unknown_fields` rejects
        // the key at deserialization with a clear error.
        let err = build_policy(&modules_cfg(
            r#"[{"type":"tdx","value":{"nonce_binding":"required"}}]"#,
        ))
        .expect_err("nonce_binding must be rejected as an unknown field");
        let msg = format!("{err:#}");
        assert!(msg.contains("nonce_binding"), "{msg}");
        assert!(msg.contains("unknown field"), "{msg}");

        // The remaining permissive fields still parse once nonce_binding is
        // gone.
        assert!(build_policy(&modules_cfg(
        r#"[{"type":"tdx","value":{"debug":"allow","perfmon":"allow","service_td":"allow","sept_ve_disable":"allow","eventlog":"optional"}}]"#
    ))
    .is_ok());
    }

    #[test]
    fn modules_policy_tdx_tcb_collateral_rules() {
        let policy = build_policy(&modules_cfg(
        r#"[{"type":"tdx","value":{
            "tcb":{"min_status":"up_to_date","reject_advisories":["INTEL-SA-00001","INTEL-SA-00002"],"allow_advisories":["INTEL-SA-00002"]},
            "collateral":{"allow_expired":false,"min_tcb_date":"2026-06-01","max_collateral_age_days":30}
        }}]"#,
    ))
    .expect("build");
        assert!(policy.contains("v.tcb_status != \"Revoked\""));
        assert!(policy.contains("UpToDate"));
        assert!(policy.contains("advisory_ids"));
        // 2026-06-01 UTC midnight -> epoch seconds
        let epoch = iso_date_to_epoch_secs("2026-06-01").expect("epoch");
        assert_eq!(epoch, 1780272000);
        assert!(policy.contains(&format!("tcb_level_date_tag >= {epoch}")));
        assert!(policy.contains("30 * 86400") || policy.contains("2592000"));
        assert!(policy.contains("time.now_ns()"));

        // A malformed date is a config error.
        let err = build_policy(&modules_cfg(
            r#"[{"type":"tdx","value":{"collateral":{"min_tcb_date":"06/01/2026"}}}]"#,
        ))
        .expect_err("bad date must reject");
        assert!(err.to_string().contains("YYYY-MM-DD"), "{err}");
    }

    #[tokio::test]
    async fn modules_policy_rejects_external_reference_values() {
        let policy = PolicyConfig::Modules {
            modules: modules_cfg("[]"),
        };
        // A modules policy's verification rules do not consume reference
        // values, so supplying them is a configuration error. Reject it at
        // construction.
        let mut rvs = std::collections::HashMap::new();
        rvs.insert("measurement.tdx.ovmf".to_string(), json!(["x"]));
        let reference = ReferenceValueConfig::Sample {
            payload: SampleProvenancePayloadConfig::Inline {
                content: Provenance { rvs },
            },
        };
        let result = BuiltinCocoConverter::new(&policy, std::slice::from_ref(&reference)).await;
        let err = match result {
            Ok(_) => panic!("external reference_values must be rejected"),
            Err(e) => e,
        };
        assert!(
            format!("{err:?}").contains("does not accept external reference_values"),
            "{err:?}"
        );
    }

    #[test]
    fn iso_date_to_epoch_secs_matches_provided() {
        // 2026-06-01 UTC midnight.
        assert_eq!(iso_date_to_epoch_secs("2026-06-01"), Some(1780272000));
        // 1970-01-01.
        assert_eq!(iso_date_to_epoch_secs("1970-01-01"), Some(0));
        // 2000-02-29 (leap).
        assert_eq!(iso_date_to_epoch_secs("2000-02-29"), Some(951782400));
        assert_eq!(iso_date_to_epoch_secs("2026-13-01"), None);
        assert_eq!(iso_date_to_epoch_secs("2026-06"), None);
        assert_eq!(iso_date_to_epoch_secs("2026-06-01T00:00:00"), None);
        // Strict 4-2-2 digits only.
        assert_eq!(iso_date_to_epoch_secs("2026-6-1"), None);
        // Calendar validity, not just a day-in-1..=31 range.
        assert_eq!(iso_date_to_epoch_secs("2026-02-31"), None);
        assert_eq!(iso_date_to_epoch_secs("2026-00-10"), None);
        assert_eq!(iso_date_to_epoch_secs("2100-02-29"), None);
    }

    /// Evaluate a `modules` policy over `input`. The generated policy embeds
    /// every pinned value as a literal, so no reference values are involved.
    async fn eval_modules(cfg_json: &str, input: &str) -> (i8, i8, i8, i8) {
        let cfg = modules_cfg(cfg_json);
        let policy = build_policy(&cfg).expect("build modules policy");
        eval_policy_vector(&policy, input).await
    }

    /// 96-char lowercase hex string made of `ch` repeated (a stand-in digest).
    fn hex96(ch: char) -> String {
        ch.to_string().repeat(96)
    }
    fn hex64(ch: char) -> String {
        ch.to_string().repeat(64)
    }

    /// A minimal TDX claims input (recognized non-debug quote) whose event log
    /// contains the given events. `body_extra` keys are merged into the quote
    /// body; the default `td_attributes` keeps the SEPT #VE bit 28 set and the
    /// debug/perfmon bits clear, so it satisfies the strict `tdx {}` defaults.
    fn tdx_input(body_extra: serde_json::Value, events: &[serde_json::Value]) -> String {
        tdx_input_full(body_extra, serde_json::Value::Null, events)
    }

    /// [`tdx_input`] plus `tdx_extra` keys merged into the `tdx` object (e.g.
    /// the flat `nvidia_gpu.0` claims).
    fn tdx_input_full(
        body_extra: serde_json::Value,
        tdx_extra: serde_json::Value,
        events: &[serde_json::Value],
    ) -> String {
        let mut body = json!({ "td_attributes": "0000001000000000" });
        if let Some(map) = body_extra.as_object() {
            for (k, v) in map {
                body[k] = v.clone();
            }
        }
        let mut tdx = json!({
            "quote": {
                "header": {
                    "tee_type": "81000000",
                    "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                },
                "body": body,
            },
            "uefi_event_logs": events,
        });
        if let Some(map) = tdx_extra.as_object() {
            for (k, v) in map {
                tdx[k] = v.clone();
            }
        }
        json!({ "tdx": tdx }).to_string()
    }

    #[tokio::test]
    async fn modules_ovmf_and_kernel_match_and_mismatch() {
        let ovmf = hex96('1');
        let kernel = hex96('2');
        let cfg = format!(
            r#"[{{"type":"tdx.ovmf","value":"{ovmf}"}},{{"type":"tdx.kernel","value":"{kernel}"}}]"#
        );
        let kernel_event = |d: &str| {
            json!({
                "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
                "details": { "string": "td_payload" },
                "index": 2,
                "digests": [ { "alg": "SHA-384", "digest": d } ],
            })
        };

        let input = tdx_input(json!({ "mr_td": ovmf.clone() }), &[kernel_event(&kernel)]);
        assert_eq!(
            eval_modules(&cfg, &input).await,
            (2, 2, 2, 2),
            "matching ovmf + kernel must affirm"
        );

        // Measurement failures only move the executables dimension; hardware
        // recognition is unaffected.
        let bad_ovmf = tdx_input(json!({ "mr_td": hex96('9') }), &[kernel_event(&kernel)]);
        assert_eq!(
            eval_modules(&cfg, &bad_ovmf).await,
            (97, 2, 2, 2),
            "ovmf mismatch must reject executables (fail-closed)"
        );

        let input2 = tdx_input(
            json!({ "mr_td": ovmf.clone() }),
            &[kernel_event(&hex96('9'))],
        );
        assert_eq!(
            eval_modules(&cfg, &input2).await,
            (97, 2, 2, 2),
            "kernel mismatch must reject executables"
        );

        let no_event = tdx_input(json!({ "mr_td": ovmf }), &[json!({ "event": "ok" })]);
        assert_eq!(
            eval_modules(&cfg, &no_event).await,
            (97, 2, 2, 2),
            "missing kernel event rejects executables (fail-closed)"
        );

        // Conflicting td_payload events fail closed even when one of them
        // matches: the pinned digest is not selected out of an ambiguous log.
        let ambiguous = tdx_input(
            json!({ "mr_td": hex96('1') }),
            &[kernel_event(&hex96('2')), kernel_event(&hex96('9'))],
        );
        assert_eq!(
            eval_modules(&cfg, &ambiguous).await,
            (97, 2, 2, 2),
            "a matching td_payload plus a conflicting one must reject"
        );
    }

    #[tokio::test]
    async fn modules_kernel_rtmr_and_digest_contract() {
        let kernel = hex96('2');
        let cfg = format!(r#"[{{"type":"tdx.kernel","value":"{kernel}"}}]"#);
        let event_with = |index: Option<i64>, digests: serde_json::Value, body: &str| {
            let mut e = json!({
                "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
                "details": { "string": "td_payload" },
                "event": body,
                "digests": digests,
            });
            if let Some(index) = index {
                e["index"] = json!(index);
            }
            e
        };
        let sha384 = |d: &str| json!([{ "alg": "SHA-384", "digest": d }]);

        // RTMR1 (index 2) with a SHA-384 digest affirms.
        let ok = tdx_input(
            serde_json::Value::Null,
            &[event_with(Some(2), sha384(&kernel), "AAAA")],
        );
        assert_eq!(eval_modules(&cfg, &ok).await, (2, 2, 2, 2));

        // A missing index rejects: `not e.index == 2` is true when the field
        // is undefined.
        let missing_index = tdx_input(
            serde_json::Value::Null,
            &[event_with(None, sha384(&kernel), "AAAA")],
        );
        assert_eq!(
            eval_modules(&cfg, &missing_index).await,
            (97, 2, 2, 2),
            "a td_payload event without an index must reject"
        );

        let bad_index = tdx_input(
            serde_json::Value::Null,
            &[event_with(Some(1), sha384(&kernel), "AAAA")],
        );
        assert_eq!(
            eval_modules(&cfg, &bad_index).await,
            (97, 2, 2, 2),
            "a td_payload event at a non-RTMR1 index must reject"
        );

        // Two events with the SAME event body, one missing a SHA-384 digest:
        // the per-event check must not be deduplicated by the event body.
        let same_body = tdx_input(
            serde_json::Value::Null,
            &[
                event_with(Some(2), sha384(&kernel), "SAME"),
                event_with(
                    Some(2),
                    json!([{ "alg": "SHA-256", "digest": hex64('a') }]),
                    "SAME",
                ),
            ],
        );
        assert_eq!(
            eval_modules(&cfg, &same_body).await,
            (97, 2, 2, 2),
            "one of two same-body events without SHA-384 must reject"
        );

        let conflict = tdx_input(
            serde_json::Value::Null,
            &[
                event_with(Some(2), sha384(&kernel), "AAAA"),
                event_with(Some(2), sha384(&hex96('9')), "BBBB"),
            ],
        );
        assert_eq!(
            eval_modules(&cfg, &conflict).await,
            (97, 2, 2, 2),
            "conflicting td_payload digests must reject"
        );

        // No blob-length constraint: an arbitrary/malformed `event` body is
        // never parsed, so the digest alone decides.
        let arbitrary_blob = tdx_input(
            serde_json::Value::Null,
            &[event_with(Some(2), sha384(&kernel), "not-base64")],
        );
        assert_eq!(
            eval_modules(&cfg, &arbitrary_blob).await,
            (2, 2, 2, 2),
            "blob length is not part of the td_payload contract"
        );
    }

    #[tokio::test]
    async fn modules_empty_list_asserts_nothing() {
        // An empty module list declares no dependency, so the appraisal asserts
        // nothing: executables/configuration/file_system stay affirming while
        // hardware stays at its non-affirming default (97), whatever the
        // evidence form.
        let policy = build_policy(&modules_cfg("[]")).expect("build");
        let tdx = tdx_input(serde_json::Value::Null, &[json!({ "event": "ok" })]);
        let evidence = [
            tdx.clone(),
            json!({ "csv": { "version": "2" } }).to_string(),
            json!({ "tpm": true }).to_string(),
            json!({ "system": { "cpu": "x" } }).to_string(),
            "{}".to_string(),
        ];
        for input in evidence {
            assert_eq!(
                eval_policy_vector(&policy, &input).await,
                (2, 97, 2, 2),
                "empty modules list must assert nothing for input {input}"
            );
        }

        // Documented difference from hardware_only: on TDX evidence the empty
        // list still does not recognise the platform, while hardware_only does.
        let hardware_only = include_str!("static/hardware_only.rego");
        assert_eq!(
            eval_policy_vector(hardware_only, &tdx).await,
            (2, 2, 2, 2),
            "hardware_only recognises TDX"
        );
        assert_eq!(
            eval_policy_vector(&policy, &tdx).await,
            (2, 97, 2, 2),
            "an empty modules list does not recognise TDX"
        );
        let csv = json!({ "csv": { "version": "2" } }).to_string();
        assert_eq!(
            eval_policy_vector(hardware_only, &csv).await,
            (2, 2, 2, 2),
            "hardware_only recognises CSV"
        );
        assert_eq!(
            eval_policy_vector(&policy, &csv).await,
            (2, 97, 2, 2),
            "an empty modules list does not recognise CSV either"
        );
    }

    #[tokio::test]
    async fn modules_container_image_and_model_gates() {
        let digest = format!("sha256:{}", hex64('a'));
        let model_hash = hex64('b');
        let cfg = format!(
            r#"[{{"type":"com.alibabacloud.container.image.model-server","value":"{digest}"}},{{"type":"com.alibabacloud.ai.model.Qwen/Qwen3.8-27B","value":"{model_hash}"}}]"#
        );
        let pull_event = |d: &str| {
            json!({
                "type_name": "EV_EVENT_TAG",
                "details": { "unicode_name": "AAEL", "data": {
                    "domain": "alibabacloud.com",
                    "operation": "kangaroo/pull-image",
                    "content": {
                        "reference": "registry.example.com/ns/model-server:latest",
                        "digest": d,
                    }
                } }
            })
        };
        let load_event = json!({
            "type_name": "EV_EVENT_TAG",
            "details": { "unicode_name": "AAEL", "data": {
                "domain": "alibabacloud.com",
                "operation": "pai/load-model",
                "content": { "model-id": "Qwen/Qwen3.8-27B", "hash": model_hash }
            } }
        });

        let input = tdx_input(
            serde_json::Value::Null,
            &[pull_event(&digest), load_event.clone()],
        );
        assert_eq!(
            eval_modules(&cfg, &input).await,
            (2, 2, 2, 2),
            "matching image + model events must affirm"
        );

        let input_bad_image = tdx_input(
            serde_json::Value::Null,
            &[
                pull_event(&format!("sha256:{}", hex64('f'))),
                load_event.clone(),
            ],
        );
        assert_eq!(
            eval_modules(&cfg, &input_bad_image).await,
            (97, 2, 2, 2),
            "image digest mismatch must reject executables"
        );

        let input_no_model = tdx_input(serde_json::Value::Null, &[pull_event(&digest)]);
        assert_eq!(
            eval_modules(&cfg, &input_no_model).await,
            (97, 2, 2, 2),
            "missing load-model event must reject executables (fail-closed)"
        );

        // Extra load-model events fail closed: every pai/load-model event must
        // name the pinned model with the pinned hash.
        let load_event_for = |model_id: &str, hash: &str| {
            json!({
                "type_name": "EV_EVENT_TAG",
                "details": { "unicode_name": "AAEL", "data": {
                    "domain": "alibabacloud.com",
                    "operation": "pai/load-model",
                    "content": { "model-id": model_id, "hash": hash }
                } }
            })
        };
        let extra_model = tdx_input(
            serde_json::Value::Null,
            &[
                pull_event(&digest),
                load_event.clone(),
                load_event_for("Qwen/Qwen3.8-14B", &hex64('b')),
            ],
        );
        assert_eq!(
            eval_modules(&cfg, &extra_model).await,
            (97, 2, 2, 2),
            "a load-model event for a different model-id must reject"
        );
        let extra_hash = tdx_input(
            serde_json::Value::Null,
            &[
                pull_event(&digest),
                load_event.clone(),
                load_event_for("Qwen/Qwen3.8-27B", &hex64('c')),
            ],
        );
        assert_eq!(
            eval_modules(&cfg, &extra_hash).await,
            (97, 2, 2, 2),
            "a load-model event for the pinned model-id with a different hash must reject"
        );
    }

    #[tokio::test]
    async fn modules_uki_gate() {
        let uki = hex96('8');
        let cfg = format!(r#"[{{"type":"tdx.uki","value":"{uki}"}}]"#);
        let uki_event = |d: &str| {
            json!({
                "type_name": "EV_EFI_BOOT_SERVICES_APPLICATION",
                "details": { "device_paths": ["File(\\EFI\\BOOT\\BOOTX64.EFI)"] },
                "index": 1,
                "digests": [ { "alg": "SHA-384", "digest": d } ],
            })
        };
        let input = tdx_input(serde_json::Value::Null, &[uki_event(&uki)]);
        assert_eq!(eval_modules(&cfg, &input).await, (2, 2, 2, 2), "uki match");
        // Two boot-application events that both carry the pinned digest affirm.
        let two_matching = tdx_input(serde_json::Value::Null, &[uki_event(&uki), uki_event(&uki)]);
        assert_eq!(
            eval_modules(&cfg, &two_matching).await,
            (2, 2, 2, 2),
            "two matching boot-application events affirm"
        );
        // Every boot-application event must match: one extra event with a
        // different digest fails closed.
        let mixed = tdx_input(
            serde_json::Value::Null,
            &[uki_event(&uki), uki_event(&hex96('a'))],
        );
        assert_eq!(
            eval_modules(&cfg, &mixed).await,
            (97, 2, 2, 2),
            "an extra boot-application event with a different digest must reject"
        );
        let bad = tdx_input(serde_json::Value::Null, &[uki_event(&hex96('f'))]);
        assert_eq!(
            eval_modules(&cfg, &bad).await,
            (97, 2, 2, 2),
            "uki mismatch rejects"
        );
        let no_event = tdx_input(serde_json::Value::Null, &[json!({ "event": "ok" })]);
        assert_eq!(
            eval_modules(&cfg, &no_event).await,
            (97, 2, 2, 2),
            "missing uki event fails closed"
        );
    }

    #[tokio::test]
    async fn modules_tdx_debug_bit_flips_to_non_affirming() {
        let cfg = r#"[{"type":"tdx","value":{}}]"#;
        let ok = tdx_input(serde_json::Value::Null, &[json!({ "event": "ok" })]);
        assert_eq!(
            eval_modules(cfg, &ok).await,
            (2, 2, 2, 2),
            "non-debug strict affirms"
        );

        // Debug bit set (byte0 low nibble odd) -> reject. A posture failure
        // moves only the hardware dimension.
        let debug = ok.replace("0000001000000000", "0100001000000000");
        assert_ne!(ok, debug, "debug flip must change the input");
        assert_eq!(
            eval_modules(cfg, &debug).await,
            (2, 97, 2, 2),
            "debug-enabled TDX must reject the hardware dimension"
        );

        // An empty module list declares no dependency: it ignores the debug bit
        // but also does not recognise TDX, so hardware stays non-affirming.
        assert_eq!(
            eval_modules("[]", &debug).await,
            (2, 97, 2, 2),
            "empty modules ignores the debug bit and recognises no platform"
        );
    }

    #[tokio::test]
    async fn modules_tdx_posture_equals_hardware_only_strict_on_tdx() {
        // Both policies gate only the hardware dimension; on TDX evidence the
        // strict modules posture reproduces hardware_only_strict.
        let cfg = r#"[{"type":"tdx","value":{"sept_ve_disable":"allow","perfmon":"allow","service_td":"allow"}}]"#;
        let modules = build_policy(&modules_cfg(cfg)).expect("build");
        let strict = include_str!("static/hardware_only_strict.rego");

        let ok = tdx_input(serde_json::Value::Null, &[json!({ "event": "ok" })]);
        assert_eq!(
            eval_policy_vector(&modules, &ok).await,
            eval_policy_vector(strict, &ok).await
        );

        let debug = ok.replace("0000001000000000", "0100001000000000");
        assert_eq!(
            eval_policy_vector(&modules, &debug).await,
            eval_policy_vector(strict, &debug).await
        );

        let no_eventlog = tdx_input(json!({ "mr_td": hex96('1') }), &[]);
        assert_eq!(
            eval_policy_vector(&modules, &no_eventlog).await,
            eval_policy_vector(strict, &no_eventlog).await
        );
    }

    #[tokio::test]
    async fn modules_tdx_sept_perfmon_service_td_bits() {
        let cfg = r#"[{"type":"tdx","value":{}}]"#;
        let ok = tdx_input(serde_json::Value::Null, &[json!({ "event": "ok" })]);
        assert_eq!(
            eval_modules(cfg, &ok).await,
            (2, 2, 2, 2),
            "sept set, perfmon clear"
        );

        // SEPT #VE bit missing (char6 = 0) -> reject hardware.
        let no_sept = ok.replace("0000001000000000", "0000000000000000");
        assert_eq!(
            eval_modules(cfg, &no_sept).await,
            (2, 97, 2, 2),
            "sept bit clear rejects hardware"
        );

        // perfmon bit set (last byte 0x80 -> char14 = 8) -> reject hardware.
        let perf = ok.replace("0000001000000000", "0000001000000080");
        assert_eq!(
            eval_modules(cfg, &perf).await,
            (2, 97, 2, 2),
            "perfmon set rejects hardware"
        );

        // Non-zero mr_servicetd -> reject (service_td deny).
        let svc = tdx_input(
            json!({ "mr_servicetd": hex96('a') }),
            &[json!({ "event": "ok" })],
        );
        assert_eq!(
            eval_modules(cfg, &svc).await,
            (2, 97, 2, 2),
            "non-zero service TD rejects hardware"
        );
        // All-zero mr_servicetd -> affirms.
        let svc_zero = tdx_input(
            json!({ "mr_servicetd": hex96('0') }),
            &[json!({ "event": "ok" })],
        );
        assert_eq!(
            eval_modules(cfg, &svc_zero).await,
            (2, 2, 2, 2),
            "zero service TD affirms"
        );
    }

    /// Build a TDX input carrying a synthetic `tcb_verification` claim.
    fn tcb_input(tcb: serde_json::Value) -> String {
        tdx_input_full(
            serde_json::Value::Null,
            json!({ "tcb_verification": tcb }),
            &[json!({ "event": "ok" })],
        )
    }

    #[tokio::test]
    async fn modules_tdx_tcb_status_and_advisories() {
        let up_to_date = r#"[{"type":"tdx","value":{"tcb":{"min_status":"up_to_date"}}}]"#;
        assert_eq!(
            eval_modules(up_to_date, &tcb_input(json!({"tcb_status": "UpToDate"}))).await,
            (2, 2, 2, 2),
            "UpToDate satisfies min_status up_to_date"
        );
        assert_eq!(
            eval_modules(up_to_date, &tcb_input(json!({"tcb_status": "OutOfDate"}))).await,
            (2, 97, 2, 2),
            "OutOfDate fails min_status up_to_date in the hardware dimension"
        );
        assert_eq!(
            eval_modules(up_to_date, &tcb_input(json!({"tcb_status": "Revoked"}))).await,
            (2, 97, 2, 2),
            "Revoked always rejects hardware"
        );

        // out_of_date accepts the out-of-date family but still rejects Revoked.
        let out_of_date = r#"[{"type":"tdx","value":{"tcb":{"min_status":"out_of_date"}}}]"#;
        assert_eq!(
            eval_modules(out_of_date, &tcb_input(json!({"tcb_status": "OutOfDate"}))).await,
            (2, 2, 2, 2),
            "out_of_date accepts OutOfDate"
        );
        assert_eq!(
            eval_modules(out_of_date, &tcb_input(json!({"tcb_status": "Revoked"}))).await,
            (2, 97, 2, 2),
            "out_of_date still rejects Revoked"
        );

        // reject_advisories: an advisory in the comma-joined list rejects; one
        // outside the list passes; allow_advisories exempts a rejected advisory.
        let advisories = r#"[{"type":"tdx","value":{"tcb":{"reject_advisories":["INTEL-SA-00001","INTEL-SA-00002"],"allow_advisories":["INTEL-SA-00002"]}}}]"#;
        assert_eq!(
            eval_modules(
                advisories,
                &tcb_input(json!({"tcb_status":"UpToDate","advisory_ids":"INTEL-SA-00009"}))
            )
            .await,
            (2, 2, 2, 2),
            "an advisory outside the reject list passes"
        );
        assert_eq!(
            eval_modules(
                advisories,
                &tcb_input(json!({"tcb_status":"UpToDate","advisory_ids":"INTEL-SA-00001"}))
            )
            .await,
            (2, 97, 2, 2),
            "a rejected advisory rejects hardware"
        );
        assert_eq!(
            eval_modules(
                advisories,
                &tcb_input(json!({"tcb_status":"UpToDate","advisory_ids":"INTEL-SA-00002"}))
            )
            .await,
            (2, 2, 2, 2),
            "an allowed advisory is exempt from reject_advisories"
        );
    }

    // Test-only clock used to build epoch-relative fixtures; the test runs on
    // the host, and `std::time::SystemTime::now` is correct there.
    #[allow(clippy::disallowed_methods)]
    #[tokio::test]
    async fn modules_tdx_collateral_gates() {
        // allow_expired=false rejects expired collateral.
        let not_expired = r#"[{"type":"tdx","value":{"collateral":{"allow_expired":false}}}]"#;
        assert_eq!(
            eval_modules(
                not_expired,
                &tcb_input(json!({"tcb_status":"UpToDate","collateral_expired":true}))
            )
            .await,
            (2, 97, 2, 2),
            "expired collateral rejects hardware when not allowed"
        );
        assert_eq!(
            eval_modules(
                not_expired,
                &tcb_input(json!({"tcb_status":"UpToDate","collateral_expired":false}))
            )
            .await,
            (2, 2, 2, 2),
            "fresh collateral affirms"
        );

        // min_tcb_date is inclusive: the exact epoch boundary passes, one
        // second earlier fails. A collateral config implies `allow_expired`
        // false, so fresh collateral is part of the same gate.
        let min_date = r#"[{"type":"tdx","value":{"collateral":{"min_tcb_date":"2026-06-01"}}}]"#;
        let epoch = iso_date_to_epoch_secs("2026-06-01").expect("epoch");
        assert_eq!(
            eval_modules(
                min_date,
                &tcb_input(
                    json!({"tcb_status":"UpToDate","collateral_expired":false,"tcb_level_date_tag":epoch})
                )
            )
            .await,
            (2, 2, 2, 2),
            "tcb_level_date_tag at the boundary passes"
        );
        assert_eq!(
            eval_modules(
                min_date,
                &tcb_input(
                    json!({"tcb_status":"UpToDate","collateral_expired":false,"tcb_level_date_tag":epoch - 1})
                )
            )
            .await,
            (2, 97, 2, 2),
            "tcb_level_date_tag one second before the boundary fails"
        );

        // max_collateral_age_days measures from latest_issue_date (epoch secs).
        let max_age = r#"[{"type":"tdx","value":{"collateral":{"max_collateral_age_days":30}}}]"#;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after the epoch")
            .as_secs() as i64;
        assert_eq!(
            eval_modules(
                max_age,
                &tcb_input(
                    json!({"tcb_status":"UpToDate","collateral_expired":false,"latest_issue_date": now - 10})
                )
            )
            .await,
            (2, 2, 2, 2),
            "collateral issued 10 seconds ago is fresh"
        );
        assert_eq!(
            eval_modules(
                max_age,
                &tcb_input(
                    json!({"tcb_status":"UpToDate","collateral_expired":false,"latest_issue_date": now - 40 * 86400})
                )
            )
            .await,
            (2, 97, 2, 2),
            "collateral issued 40 days ago exceeds a 30 day maximum"
        );
    }

    #[tokio::test]
    async fn modules_gpu_aael_attestation_codes() {
        let cfg = r#"[{"type":"com.alibabacloud.gpu","value":{}}]"#;
        let gpu_event = |collect: i64, attest: i64| {
            json!({
                "type_name": "EV_EVENT_TAG",
                "details": { "unicode_name": "AAEL", "data": {
                    "domain": "alibabacloud.com",
                    "operation": "gpu/attestation",
                    "content": {
                        "gpu-collect-evidence-result-code": collect,
                        "gpu-attest-result-code": attest,
                    }
                } }
            })
        };
        let input = tdx_input(serde_json::Value::Null, &[gpu_event(0, 0)]);
        assert_eq!(
            eval_modules(cfg, &input).await,
            (2, 2, 2, 2),
            "both result codes 0 affirm hardware"
        );

        let bad_collect = tdx_input(serde_json::Value::Null, &[gpu_event(3, 0)]);
        assert_eq!(
            eval_modules(cfg, &bad_collect).await,
            (2, 97, 2, 2),
            "non-zero evidence-collection code rejects hardware"
        );
        let bad_attest = tdx_input(serde_json::Value::Null, &[gpu_event(0, 5)]);
        assert_eq!(
            eval_modules(cfg, &bad_attest).await,
            (2, 97, 2, 2),
            "non-zero attestation code rejects hardware"
        );

        // Every event must pass, not just one of several.
        let one_bad = tdx_input(serde_json::Value::Null, &[gpu_event(0, 0), gpu_event(0, 5)]);
        assert_eq!(
            eval_modules(cfg, &one_bad).await,
            (2, 97, 2, 2),
            "an extra failing gpu event rejects hardware"
        );

        let none = tdx_input(serde_json::Value::Null, &[json!({ "event": "ok" })]);
        assert_eq!(
            eval_modules(cfg, &none).await,
            (2, 97, 2, 2),
            "missing gpu event rejects hardware (fail-closed)"
        );

        // The value is an empty object; any field is an unknown-field error.
        let err = ModuleEntryConfig {
            module_type: "com.alibabacloud.gpu".to_string(),
            value: json!({ "verify": "local" }),
        }
        .to_module_parsed()
        .unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"), "{err:#}");
    }

    #[tokio::test]
    async fn modules_nvidia_standard_appraisal_pass_and_skip_reject() {
        let m = hex96('3');
        let cfg = format!(
            r#"[{{"type":"nvidia","value":{{"min_count":1,"allow_uuids":["GPU-x"],"measurement_digest":["{m}"]}}}}]"#
        );
        let event = json!({ "event": "ok" });
        // Evaluated GPU claim (measurement present, no attestation_report).
        let evaluated = tdx_input_full(
            serde_json::Value::Null,
            json!({ "nvidia_gpu.0": {
            "uuid": "GPU-x", "name": "L20C", "driver_version": "570.148.05",
            "vbios_version": "96.00.f4", "cc_enabled": true, "measurement": m
        } }),
            std::slice::from_ref(&event),
        );
        assert_eq!(
            eval_modules(&cfg, &evaluated).await,
            (2, 2, 2, 2),
            "evaluated GPU claims affirm"
        );

        // Skip-mode raw passthrough: attestation_report + index present, no
        // measurement -> the nvidia appraisal must reject hardware.
        let raw = tdx_input_full(
            serde_json::Value::Null,
            json!({ "nvidia_gpu.0": {
            "index": 0, "uuid": "GPU-x", "cc_enabled": true,
            "attestation_report": "BASE64"
        } }),
            std::slice::from_ref(&event),
        );
        assert_eq!(
            eval_modules(&cfg, &raw).await,
            (2, 97, 2, 2),
            "skip passthrough (raw attestation_report) must reject under the nvidia appraisal"
        );

        // No GPU claims at all -> min_count fail-closed.
        let no_gpu = tdx_input(serde_json::Value::Null, &[json!({ "event": "ok" })]);
        assert_eq!(
            eval_modules(&cfg, &no_gpu).await,
            (2, 97, 2, 2),
            "nvidia with no GPU evidence rejects hardware (fail-closed)"
        );

        // Driver/VBIOS allow-lists gate the evaluated claims.
        let cfg_pinned = r#"[{"type":"nvidia","value":{"min_count":1,"allow_driver_versions":["570.148.05"],"allow_vbios_versions":["96.00.f4"]}}]"#;
        assert_eq!(
            eval_modules(cfg_pinned, &evaluated).await,
            (2, 2, 2, 2),
            "pinned driver + vbios versions affirm"
        );
        let wrong_driver = tdx_input_full(
            serde_json::Value::Null,
            json!({ "nvidia_gpu.0": {
            "uuid": "GPU-x", "name": "L20C", "driver_version": "999.0.0",
            "vbios_version": "96.00.f4", "cc_enabled": true, "measurement": m
        } }),
            std::slice::from_ref(&event),
        );
        assert_eq!(
            eval_modules(cfg_pinned, &wrong_driver).await,
            (2, 97, 2, 2),
            "driver version outside the allow-list must reject hardware"
        );
    }

    #[tokio::test]
    async fn modules_multi_group_or_binds_across_entries() {
        // Two baselines: (ovmf=A, kernel=Ka) and (ovmf=B, kernel=Kb).
        let (a, b) = (hex96('1'), hex96('2'));
        let (ka, kb) = (hex96('3'), hex96('4'));
        let cfg = format!(
            r#"[[{{"type":"tdx.ovmf","value":"{a}"}},{{"type":"tdx.kernel","value":"{ka}"}}],[{{"type":"tdx.ovmf","value":"{b}"}},{{"type":"tdx.kernel","value":"{kb}"}}]]"#
        );
        let kernel_event = |d: &str| {
            json!({
                "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
                "details": { "string": "td_payload" },
                "index": 2,
                "digests": [ { "alg": "SHA-384", "digest": d } ],
            })
        };

        // Matching baseline B (ovmf=B, kernel=Kb) -> affirm via OR.
        let input_b = tdx_input(json!({ "mr_td": b }), &[kernel_event(&kb)]);
        assert_eq!(
            eval_modules(&cfg, &input_b).await,
            (2, 2, 2, 2),
            "matching one of two baselines affirms (group OR)"
        );

        // Cross-group binding: ovmf=A (group 0) but kernel=Kb (group 1). Neither
        // baseline is fully satisfied -> non-affirming.
        let mixed = tdx_input(json!({ "mr_td": a }), &[kernel_event(&kb)]);
        assert_eq!(
            eval_modules(&cfg, &mixed).await,
            (97, 2, 2, 2),
            "cross-group mix (ovmf A + kernel B) must reject: group AND binding"
        );
    }

    #[tokio::test]
    async fn modules_dimensions_aggregate_independently() {
        // Group 0 constrains only the hardware dimension (a posture entry),
        // group 1 only the executables dimension (a measurement). Each
        // dimension ORs over the groups that carry entries of it, so the
        // measurement in group 1 can affirm while the posture in group 0 fails.
        let cfg = format!(
            r#"[[{{"type":"tdx","value":{{}}}}],[{{"type":"tdx.ovmf","value":"{}"}}]]"#,
            hex96('1')
        );
        let posture_fails = tdx_input(
            json!({ "mr_td": hex96('1'), "td_attributes": "0100001000000000" }),
            &[json!({ "event": "ok" })],
        );
        assert_eq!(
            eval_modules(&cfg, &posture_fails).await,
            (2, 97, 2, 2),
            "a passing measurement does not rescue a failing posture (and vice versa)"
        );

        let both_pass = tdx_input(json!({ "mr_td": hex96('1') }), &[json!({ "event": "ok" })]);
        assert_eq!(
            eval_modules(&cfg, &both_pass).await,
            (2, 2, 2, 2),
            "each dimension affirming independently affirms the appraisal"
        );

        let measurement_fails =
            tdx_input(json!({ "mr_td": hex96('9') }), &[json!({ "event": "ok" })]);
        assert_eq!(
            eval_modules(&cfg, &measurement_fails).await,
            (97, 2, 2, 2),
            "a failing measurement leaves the recognized hardware affirming"
        );
    }

    #[tokio::test]
    async fn modules_measurement_only_hardware_depends_on_tdx() {
        // A measurement-only policy still declares TDX as its platform, so
        // hardware affirms on TDX evidence and never on another platform's
        // evidence, even though the measurement itself only gates executables.
        let cfg = format!(r#"[{{"type":"tdx.ovmf","value":"{}"}}]"#, hex96('1'));
        let tdx = tdx_input(json!({ "mr_td": hex96('1') }), &[json!({ "event": "ok" })]);
        assert_eq!(
            eval_modules(&cfg, &tdx).await,
            (2, 2, 2, 2),
            "TDX evidence affirms hardware for a measurement-only policy"
        );

        // The measurement passes, but the quote header does not identify TDX:
        // hardware stays non-affirming while executables is unaffected.
        let bad_vendor = tdx.replace(
            "939a7233f79c4ca9940a0db3957f0607",
            "00000000000000000000000000000000",
        );
        assert_eq!(
            eval_modules(&cfg, &bad_vendor).await,
            (2, 97, 2, 2),
            "a wrong TDX vendor id must reject the hardware dimension"
        );

        for input in [
            json!({ "csv": { "version": "2" } }).to_string(),
            json!({ "tpm": true }).to_string(),
            json!({ "system": { "cpu": "x" } }).to_string(),
            "{}".to_string(),
        ] {
            assert_eq!(
                eval_modules(&cfg, &input).await,
                (97, 97, 2, 2),
                "non-TDX evidence must not affirm hardware for input {input}"
            );
        }
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn modules_rego_appraises_real_pai_event_log() {
        // The real PAI AAEL kangaroo/pull-image event resolves to repo
        // `busybox` carrying this digest. Pinned from cmaas's
        // `TestExtractAAELContainerEvents`, same as the transparency_log test.
        const REAL_BUSYBOX_DIGEST: &str =
            "sha256:16ece118a36d152ed7562347741470b1bb0b0f7561ff1fe0049857a03d4fec5d";
        // The real PAI td_payload measurement: the SHA-384 digest on the
        // `EV_EFI_PLATFORM_FIRMWARE_BLOB2` event whose details string is
        // `td_payload` (index 2) in this fixture.
        const REAL_KERNEL_DIGEST: &str =
            "85619a9146b5c1409bf034bdabd6d93df26a5a23b41b43f92a7a4025760a1c4f110194ae75a2b9625b0de97f2b00fc8f";
        const TAMPERED_BUSYBOX_DIGEST: &str =
            "sha256:26ece118a36d152ed7562347741470b1bb0b0f7561ff1fe0049857a03d4fec5d";
        const TAMPERED_KERNEL_DIGEST: &str =
            "95619a9146b5c1409bf034bdabd6d93df26a5a23b41b43f92a7a4025760a1c4f110194ae75a2b9625b0de97f2b00fc8f";

        // Parse the real CC event log through the production `eventlog` crate.
        // `CcEventLog` serializes with the `uefi_event_logs` field name, so its
        // JSON IS the Rego input's `tdx.uefi_event_logs` array.
        let ccel_bytes =
            std::fs::read("src/tee/coco/converter/builtin/tests/fixtures/tdx_CCEL_data_pai")
                .expect("read real PAI event-log fixture");
        let ccel: eventlog::CcEventLog =
            ccel_bytes.try_into().expect("parse real PAI CC event log");
        let parsed = serde_json::to_value(&ccel)
            .expect("serialize parsed CC event log")
            .as_object()
            .expect("parsed event log is an object")
            .clone();

        // Mirror the synthetic tests' quote shape: recognized TDX header and
        // non-debug attributes, with the parsed event log spliced in.
        let mut tdx = serde_json::Map::new();
        tdx.insert(
            "quote".to_string(),
            serde_json::json!({
                "header": {
                    "tee_type": "81000000",
                    "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                },
                "body": { "td_attributes": "0000001000000000" },
            }),
        );
        tdx.insert(
            "uefi_event_logs".to_string(),
            parsed["uefi_event_logs"].clone(),
        );
        let input = serde_json::json!({ "tdx": tdx }).to_string();

        // A policy pinning the real busybox digest affirms; a tampered pin
        // rejects on the executables dimension.
        let image_cfg = format!(
            r#"[{{"type":"com.alibabacloud.container.image.busybox","value":"{REAL_BUSYBOX_DIGEST}"}}]"#
        );
        assert_eq!(
            eval_modules(&image_cfg, &input).await,
            (2, 2, 2, 2),
            "the real PAI busybox pull event must affirm against its pinned digest"
        );
        let bad_image_cfg = format!(
            r#"[{{"type":"com.alibabacloud.container.image.busybox","value":"{TAMPERED_BUSYBOX_DIGEST}"}}]"#
        );
        assert_eq!(
            eval_modules(&bad_image_cfg, &input).await,
            (97, 2, 2, 2),
            "a tampered busybox digest must reject executables"
        );

        // A policy pinning the real td_payload digest affirms; a tampered pin
        // rejects on the executables dimension.
        let kernel_cfg = format!(r#"[{{"type":"tdx.kernel","value":"{REAL_KERNEL_DIGEST}"}}]"#);
        assert_eq!(
            eval_modules(&kernel_cfg, &input).await,
            (2, 2, 2, 2),
            "the real PAI td_payload measurement must affirm against its pinned digest"
        );
        let bad_kernel_cfg =
            format!(r#"[{{"type":"tdx.kernel","value":"{TAMPERED_KERNEL_DIGEST}"}}]"#);
        assert_eq!(
            eval_modules(&bad_kernel_cfg, &input).await,
            (97, 2, 2, 2),
            "a tampered kernel digest must reject executables"
        );
    }
}

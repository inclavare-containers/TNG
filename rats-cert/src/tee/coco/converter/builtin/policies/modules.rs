//! The `modules` attestation policy: entry parsing, validation, and Rego
//! generation.

use super::super::policy_config::{
    value_shape, GpuPostureConfig, ModuleEntryConfig, ModuleGroupsConfig, NvidiaPostureConfig,
    TcbMinStatus, TdxBit, TdxCollateralConfig, TdxEventlog, TdxPostureConfig, TdxSeptVe,
    TdxTcbConfig, TransparencyLogEntryConfig,
};
use super::transparency_log::{self, ResolvedRekor};
use crate::errors::*;
use crate::tee::coco::diagnostics::{APPRAISAL_DIAGNOSTICS_EXTENSION, APPRAISAL_DIAGNOSTICS_KEY};
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
    /// transparency log. Gates `executables`; platform posture is expressed by
    /// a separate `tdx` entry.
    TransparencyLog(TransparencyLogEntryConfig),
}

impl Module {
    /// The AR4SI dimension this module gates. Measurements describe what the
    /// platform executes; posture modules describe the hardware/TCB state.
    fn dimension(&self) -> Dimension {
        match self {
            Module::TdShim { .. }
            | Module::Ovmf { .. }
            | Module::Kernel { .. }
            | Module::Uki { .. }
            | Module::ContainerImage { .. }
            | Module::AiModel { .. }
            | Module::TransparencyLog(_) => Dimension::Executables,
            Module::Tdx(_) | Module::Nvidia(_) | Module::Gpu => Dimension::Hardware,
        }
    }

    /// The TEE platform this entry's evidence is rooted at. Every current
    /// variant reads from `input.tdx`: the quote and event-log measurements,
    /// the AAEL event-log families, and the evaluated `nvidia_gpu.*` claims.
    fn platform(&self) -> Platform {
        Platform::Tdx
    }

    /// The canonical type spelling, used as the diagnostic `check` name of a
    /// measurement entry.
    fn canonical_type(&self) -> String {
        match self {
            Module::TdShim { .. } => "tdx.td-shim".to_string(),
            Module::Ovmf { .. } => "tdx.ovmf".to_string(),
            Module::Kernel { .. } => "tdx.kernel".to_string(),
            Module::Uki { .. } => "tdx.uki".to_string(),
            Module::ContainerImage { repo, .. } => {
                format!("com.alibabacloud.container.image.{repo}")
            }
            Module::AiModel { model_id, .. } => format!("com.alibabacloud.ai.model.{model_id}"),
            Module::Tdx(_) => "tdx".to_string(),
            Module::Nvidia(_) => "nvidia".to_string(),
            Module::Gpu => "com.alibabacloud.gpu".to_string(),
            Module::TransparencyLog(_) => "transparency_log".to_string(),
        }
    }

    /// The pinned measurement value, or `None` for a posture entry, which has
    /// no single expected value.
    fn pinned_value(&self) -> Option<&str> {
        match self {
            Module::TdShim { value }
            | Module::Ovmf { value }
            | Module::Kernel { value }
            | Module::Uki { value } => Some(value),
            Module::ContainerImage { digest, .. } | Module::AiModel { digest, .. } => Some(digest),
            Module::Tdx(_) | Module::Nvidia(_) | Module::Gpu | Module::TransparencyLog(_) => None,
        }
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

    /// The diagnostic `check` name reported for the platform itself.
    fn check_name(&self) -> &'static str {
        match self {
            Platform::Tdx => "tdx",
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

        // Unprefixed non-vendor types.
        match raw {
            "tdx" => Ok(Self::Tdx),
            "nvidia" => Ok(Self::Nvidia),
            "tdx.td-shim" => Ok(Self::TdShim),
            "tdx.ovmf" => Ok(Self::Ovmf),
            "tdx.kernel" => Ok(Self::Kernel),
            "tdx.uki" => Ok(Self::Uki),
            "transparency_log" => Ok(Self::TransparencyLog),
            _ => {
                // Permanent unprefixed aliases of the two vendor measurement
                // families.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dimension {
    Executables,
    Hardware,
}

impl Dimension {
    /// The AR4SI dimension name, as it appears in a diagnostic payload and in
    /// the `dimension_value` lookup.
    fn as_str(self) -> &'static str {
        match self {
            Dimension::Executables => "executables",
            Dimension::Hardware => "hardware",
        }
    }
}

/// Name segment charset: letters, digits and `. _ / @ : + -`.
fn is_valid_module_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '@' | ':' | '+' | '-')
        })
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
            EntryType::TransparencyLog => {
                value_obj()?;
                let cfg: TransparencyLogEntryConfig = serde_json::from_value(self.value.clone())
                    .context("invalid transparency_log config")?;
                transparency_log::validate_entry(&cfg)?;
                Ok(Module::TransparencyLog(cfg))
            }
            EntryType::ContainerImage { repo } => {
                if !is_valid_module_name(repo) {
                    anyhow::bail!("container.image name {repo:?} has an invalid character");
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
/// Each entry emits an entry predicate and belongs to exactly one AR4SI
/// dimension: measurements and `transparency_log` baselines gate `executables`,
/// posture entries gate `hardware`. Per group and dimension a
/// `group_<i>_<dimension>_ok` predicate ANDs that group's entries of the
/// dimension; a dimension aggregates with OR over the groups that carry
/// entries of it. A dimension with no entries stays at its affirming default,
/// so a failing posture cannot drag down `executables` and vice versa.
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
///
/// Every entry also emits a diagnostic, and the policy carries a
/// `tng.appraisal-diagnostics` extension listing the checks that failed. A
/// posture entry is split into one diagnostic per enabled sub-check, so a
/// failure names the specific check (`tdx.debug`, `nvidia.cc_enabled`)
/// instead of the whole posture. The extension is undefined while nothing
/// fails, so a successful appraisal's token is unchanged.
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
    let mut entry_rules: Vec<String> = Vec::new();
    // Diagnostic rule names, in emission order, for the `failed_checks`
    // collector.
    let mut diag_names: Vec<String> = Vec::new();
    let mut group_dimension_rules: Vec<String> = Vec::new();
    let mut executables_rules: Vec<String> = Vec::new();
    let mut hardware_rules: Vec<String> = Vec::new();
    let mut has_executables = false;
    // Whether any transparency entry exists; its shared measurement-extraction
    // rules are emitted once for the whole policy.
    let mut has_transparency = false;
    // The platform the policy depends on. No entry means no dependency and no
    // recognition predicate is emitted. While only one platform exists, one
    // shared recognition block covers every group; when a second platform
    // lands, the block must be emitted once per distinct platform in use.
    let mut policy_platform: Option<Platform> = None;
    // Whether the policy references the pull-image repo-name extractor; defined
    // once when any container.image entry appears.
    let mut need_repo_name = false;
    // GPU claim / event projections shared by the sub-checks of one posture
    // family, defined once per policy when such an entry appears.
    let mut need_nvidia_gpus = false;
    let mut need_gpu_events = false;

    for (gi, group) in groups.iter().enumerate() {
        let mut executables_preds: Vec<String> = Vec::new();
        let mut hardware_preds: Vec<String> = Vec::new();
        for (j, module) in group.iter().enumerate() {
            let pred = format!("m_{gi}_{j}");
            let diag = format!("diag_{gi}_{j}");
            policy_platform.get_or_insert_with(|| module.platform());
            let dimension = module.dimension().as_str();
            let block = match module {
                Module::Tdx(cfg) => {
                    let (checks, extra) = tdx_posture_rule(cfg, &pred)?;
                    helpers.extend(extra);
                    diag_names.extend(checks.iter().map(|c| format!("{diag}_{}", c.suffix)));
                    posture_rules(&pred, &diag, "tdx", dimension, &checks)
                }
                Module::Nvidia(cfg) => {
                    need_nvidia_gpus = true;
                    let checks = nvidia_posture_rule(cfg);
                    diag_names.extend(checks.iter().map(|c| format!("{diag}_{}", c.suffix)));
                    posture_rules(&pred, &diag, "nvidia", dimension, &checks)
                }
                Module::Gpu => {
                    need_gpu_events = true;
                    let checks = gpu_posture_rule();
                    diag_names.extend(checks.iter().map(|c| format!("{diag}_{}", c.suffix)));
                    posture_rules(&pred, &diag, "gpu", dimension, &checks)
                }
                Module::TransparencyLog(cfg) => {
                    // Every transparency entry consumes its own resolved slot,
                    // in flatten order, so multiple entries cannot share or
                    // overwrite each other's baked data.
                    let entry = resolved_entries.next().ok_or_else(|| {
                        anyhow::anyhow!(
                            "no resolved rekor data for transparency_log entry m_{gi}_{j}"
                        )
                    })?;
                    has_transparency = true;
                    diag_names.push(diag.clone());
                    let prefix = format!("t_{gi}_{j}");
                    format!(
                        "{}\n\n{}",
                        transparency_log::build_entry_rules(cfg, entry.as_ref(), &pred, &prefix)?,
                        transparency_log_diag_rules(&pred, &diag, dimension),
                    )
                }
                measurement => {
                    let observed = format!("observed_{gi}_{j}");
                    diag_names.push(diag.clone());
                    format!(
                        "{}\n\n{}\n\n{}",
                        measurement_rule(measurement, &pred)?,
                        measurement_observed_rule(measurement, &observed)?,
                        measurement_diag_rules(measurement, &pred, &diag, &observed, dimension)?,
                    )
                }
            };
            if matches!(module, Module::ContainerImage { .. }) {
                need_repo_name = true;
            }
            match module.dimension() {
                Dimension::Executables => executables_preds.push(pred),
                Dimension::Hardware => hardware_preds.push(pred),
            }
            entry_rules.push(block);
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
    // in the wrong direction.
    let executables_default = if has_executables { 97 } else { 2 };

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

// The shared transparency extraction rules are emitted once, ahead of the
    // per-entry rules that call them. They use `image_repo_name`, so a
    // transparency entry needs that helper too.
    let mut helper_parts: Vec<String> = Vec::new();
    if has_transparency {
        need_repo_name = true;
        helper_parts.push(
            transparency_log::measurement_extraction_rules()
                .trim_end()
                .to_string(),
        );
    }

    // The platform's own diagnostic: without it a non-recognised platform only
    // shows up as a silently non-affirming hardware dimension.
    let diagnostics_block = match policy_platform.as_ref() {
        Some(platform) => {
            let mut names = diag_names;
            names.push("diag_platform".to_string());
            format!(
                "\n\n{}\n\n{}",
                platform_diagnostic_rule(platform),
                failed_checks_block(&names)
            )
        }
        None => String::new(),
    };

    if need_nvidia_gpus {
        helpers.push(NVIDIA_GPUS_HELPER.to_string());
    }
    if need_gpu_events {
        helpers.push(GPU_ATTESTATION_EVENTS_HELPER.to_string());
    }
    helper_parts.extend(helpers);

    let helper_block = if helper_parts.is_empty() {
        String::new()
    } else {
        format!("{}\n\n", helper_parts.join("\n\n"))
    };
    let repo_name_block = if need_repo_name {
        // The repo tail of an image reference: last '/' segment, before any
        // ':' tag or '@' digest.
        "image_repo_name(ref) := name if {\n\tsegs := split(ref, \"/\")\n\tlast := segs[count(segs) - 1]\n\tname := split(split(last, \"@\")[0], \":\")[0]\n}\n\n".to_string()
    } else {
        String::new()
    };
    let entry_block = if entry_rules.is_empty() {
        String::new()
    } else {
        format!("{}\n\n", entry_rules.join("\n\n"))
    };
    let dimension_block = if group_dimension_rules.is_empty() {
        String::new()
    } else {
        format!("{}\n\n", group_dimension_rules.join("\n\n"))
    };
    let executables_block = executables_rules.join("\n\n");

    let policy = format!(
        r#"package policy

import rego.v1

# Modular verification rules. Each entry belongs to one AR4SI dimension:
# boot/workload measurements gate `executables`, platform posture (TDX, GPU)
# gates `hardware`. Within a group the entries of one dimension AND; a
# dimension is OR-ed over the groups that carry entries of it, so a group
# without entries of a dimension does not constrain it. A dimension with no
# entries stays affirming, except `hardware`, which depends on the platform
# every entry's evidence comes from: it affirms only when that platform is
# recognised. An empty module list declares no dependency and emits no
# recognition rule, so `hardware` stays at its non-affirming default.
default configuration := 2
default file_system := 2
default hardware := 97
default executables := {executables_default}

{helper_block}{repo_name_block}{entry_block}{dimension_block}{executables_block}

{hardware_block}{recognition_block}{diagnostics_block}
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

/// Emit the `<pred> if { ... }` rule for a measurement entry. The pinned value
/// is spliced in as a Rego string literal; validation in `to_module` guarantees
/// it contains no quoting hazard. The container.image variant additionally
/// depends on the `image_repo_name` helper, which the caller emits once for the
/// whole policy.
fn measurement_rule(module: &Module, pred: &str) -> anyhow::Result<String> {
    Ok(match module {
        Module::TdShim { value } | Module::Ovmf { value } => format!(
            r#"{pred} if {{
	input.tdx.quote.body.mr_td == {value:?}
}}"#
        ),
        Module::Kernel { value } => format!(
            r#"{pred} if {{
	some e in input.tdx.uefi_event_logs
	e.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"
	e.details.string == "td_payload"
	some d in e.digests
	d.alg == "SHA-384"
	d.digest == {value:?}
	# fail-closed on ambiguity: every td_payload descriptor event must carry
	# the same SHA-384 digest. The RTMR register index is firmware-dependent
	# ordering, not part of the td_payload contract, so it is not pinned here;
	# a distinct-digest set of size != 1 leaves this rule undefined.
	ds := {{x | some e2 in input.tdx.uefi_event_logs; e2.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; e2.details.string == "td_payload"; some d2 in e2.digests; d2.alg == "SHA-384"; x := d2.digest}}
	count(ds) == 1
}}"#
        ),
        Module::Uki { value } => format!(
            r#"{pred} if {{
	events := [e |
		some e in input.tdx.uefi_event_logs
		e.type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"
	]
	count(events) > 0
	every e in events {{
		some d in e.digests
		d.alg == "SHA-384"
		d.digest == {value:?}
	}}
}}"#
        ),
        Module::ContainerImage { repo, digest } => format!(
            r#"{pred} if {{
	events := [e |
		some e in input.tdx.uefi_event_logs
		e.type_name == "EV_EVENT_TAG"
		e.details.unicode_name == "AAEL"
		e.details.data.domain == "alibabacloud.com"
		e.details.data.operation == "kangaroo/pull-image"
		image_repo_name(e.details.data.content.reference) == {repo:?}
	]
	count(events) > 0
	every e in events {{
		e.details.data.content.digest == {digest:?}
	}}
}}"#
        ),
        Module::AiModel { model_id, digest } => format!(
            r#"{pred} if {{
	events := [e |
		some e in input.tdx.uefi_event_logs
		e.type_name == "EV_EVENT_TAG"
		e.details.unicode_name == "AAEL"
		e.details.data.domain == "alibabacloud.com"
		e.details.data.operation == "pai/load-model"
	]
	count(events) > 0
	every e in events {{
		e.details.data.content["model-id"] == {model_id:?}
		e.details.data.content["hash"] == {digest:?}
	}}
}}"#
        ),
        // Posture variants are emitted by `tdx_posture_rule` /
        // `nvidia_posture_rule`, and `transparency_log` by
        // `transparency_log::build_entry_rules`; the caller never passes them
        // here.
        Module::Tdx(_) | Module::Nvidia(_) | Module::Gpu | Module::TransparencyLog(_) => {
            anyhow::bail!("posture module passed to the measurement emitter")
        }
    })
}

/// Emit the `<observed> := ...` projection rule for a measurement entry: what
/// the evidence actually carries, with no pass/fail judgement. Diagnostics
/// render it as `actual`.
fn measurement_observed_rule(module: &Module, observed: &str) -> anyhow::Result<String> {
    // Event-log families iterate over a defaulted list so the projection is
    // `[]` rather than undefined when the evidence carries no event log.
    let events = r#"object.get(object.get(input, "tdx", {}), "uefi_event_logs", [])"#;
    Ok(match module {
        Module::TdShim { .. } | Module::Ovmf { .. } => format!(
            r#"{observed} := object.get(object.get(object.get(object.get(input, "tdx", {{}}), "quote", {{}}), "body", {{}}), "mr_td", null)"#
        ),
        Module::Kernel { .. } => format!(
            r#"{observed} := [d.digest |
	some e in {events}
	e.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"
	e.details.string == "td_payload"
	some d in e.digests
	d.alg == "SHA-384"
]"#
        ),
        Module::Uki { .. } => format!(
            r#"{observed} := [d.digest |
	some e in {events}
	e.type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"
	some d in e.digests
	d.alg == "SHA-384"
]"#
        ),
        Module::ContainerImage { repo, .. } => format!(
            r#"{observed} := [e.details.data.content.digest |
	some e in {events}
	e.type_name == "EV_EVENT_TAG"
	e.details.unicode_name == "AAEL"
	e.details.data.domain == "alibabacloud.com"
	e.details.data.operation == "kangaroo/pull-image"
	image_repo_name(e.details.data.content.reference) == {repo:?}
]"#
        ),
        Module::AiModel { .. } => format!(
            r#"{observed} := [{{"model-id": e.details.data.content["model-id"], "hash": e.details.data.content["hash"]}} |
	some e in {events}
	e.type_name == "EV_EVENT_TAG"
	e.details.unicode_name == "AAEL"
	e.details.data.domain == "alibabacloud.com"
	e.details.data.operation == "pai/load-model"
]"#
        ),
        Module::Tdx(_) | Module::Nvidia(_) | Module::Gpu | Module::TransparencyLog(_) => {
            anyhow::bail!("posture module passed to the measurement projection emitter")
        }
    })
}

/// Emit the matched/mismatch diagnostic pair for a measurement entry.
fn measurement_diag_rules(
    module: &Module,
    pred: &str,
    diag: &str,
    observed: &str,
    dimension: &str,
) -> anyhow::Result<String> {
    let Some(expected) = module.pinned_value() else {
        anyhow::bail!("posture module passed to the measurement diagnostics emitter");
    };
    let check = module.canonical_type();
    Ok(format!(
        r#"{diag} := {{
	"dimension": {dimension:?},
	"check": {check:?},
	"matched": true,
	"expected": {expected:?},
	"actual": {observed},
}} if {{
	{pred}
}}

{diag} := {{
	"dimension": {dimension:?},
	"check": {check:?},
	"matched": false,
	"expected": {expected:?},
	"actual": {observed},
	"reason": "mismatch",
}} if {{
	not {pred}
}}"#
    ))
}

/// Emit the matched/mismatch diagnostic pair for a `transparency_log` entry.
///
/// Its baseline is the manifest recorded in the transparency log, not a value
/// from this config, so the diagnostic carries no `expected`/`actual`: the
/// logged manifest is not ours to disclose, and reporting it would bloat the
/// token. The reason alone still separates a mismatch from a missing check.
fn transparency_log_diag_rules(pred: &str, diag: &str, dimension: &str) -> String {
    format!(
        r#"{diag} := {{
	"dimension": {dimension:?},
	"check": "transparency_log",
	"matched": true,
}} if {{
	{pred}
}}

{diag} := {{
	"dimension": {dimension:?},
	"check": "transparency_log",
	"matched": false,
	"reason": "transparency-log-mismatch",
}} if {{
	not {pred}
}}"#
    )
}

/// Total projection of a quote-body field, used as a diagnostic `actual`. The
/// outer `object.get` guard keeps the projection defined on evidence without a
/// TDX block: an undefined `actual` would make the whole `failed_checks` list
/// undefined.
const TD_ATTRIBUTES_ACTUAL: &str = r#"object.get(object.get(object.get(object.get(input, "tdx", {}), "quote", {}), "body", {}), "td_attributes", null)"#;
const MR_SERVICETD_ACTUAL: &str = r#"object.get(object.get(object.get(object.get(input, "tdx", {}), "quote", {}), "body", {}), "mr_servicetd", null)"#;

/// Total projection of a `tcb_verification` field.
fn tcb_actual(field: &str) -> String {
    format!(
        r#"object.get(object.get(object.get(input, "tdx", {{}}), "tcb_verification", {{}}), {field:?}, null)"#
    )
}

/// The evaluated per-GPU claims, keyed by their `input.tdx` field name.
/// Defined once per policy when an `nvidia` entry appears; both the sub-check
/// predicates and their diagnostic projections read it. Carrying the key lets
/// a diagnostic identify the GPU without embedding the whole claim, which in
/// the raw/skip form carries the base64 `attestation_report`.
const NVIDIA_GPUS_HELPER: &str = r#"nvidia_gpus := [{"gpu": k, "claim": g} |
	tdx := object.get(input, "tdx", {})
	some k, g in tdx
	startswith(k, "nvidia_gpu.")
]"#;

/// The guest-reported AAEL GPU attestation events, defined once per policy when
/// a `com.alibabacloud.gpu` entry appears.
const GPU_ATTESTATION_EVENTS_HELPER: &str = r#"gpu_attestation_events := [e |
	some e in object.get(object.get(input, "tdx", {}), "uefi_event_logs", [])
	e.type_name == "EV_EVENT_TAG"
	e.details.unicode_name == "AAEL"
	e.details.data.domain == "alibabacloud.com"
	e.details.data.operation == "gpu/attestation"
]"#;

/// One enabled sub-check of a posture entry. Each becomes its own predicate and
/// its own diagnostic, so a failing posture reports which checks failed instead
/// of one opaque verdict. The aggregate predicate still ANDs them for the
/// dimension rule.
struct PostureCheck {
    /// Suffix of the sub-check: its predicate is `<pred>_<suffix>` and its
    /// diagnostic check name is `<prefix>.<suffix>`.
    suffix: &'static str,
    /// What the check requires, rendered into the diagnostic.
    expected: String,
    /// Rego expression yielding the observed value, rendered as `actual`.
    actual_expr: String,
    /// Body lines of the sub-check predicate, unindented.
    body: Vec<String>,
}

/// Emit a posture entry as one predicate per enabled sub-check, an aggregate
/// predicate that ANDs them, and a matched/mismatch diagnostic pair per
/// sub-check. A posture entry with no enabled sub-check keeps an unconditional
/// predicate and contributes no diagnostic.
fn posture_rules(
    pred: &str,
    diag: &str,
    check_prefix: &str,
    dimension: &str,
    checks: &[PostureCheck],
) -> String {
    if checks.is_empty() {
        return format!("{pred} if {{\n\ttrue\n}}");
    }

    let mut blocks: Vec<String> = checks
        .iter()
        .map(|check| {
            format!(
                "{pred}_{suffix} if {{\n{body}\n}}",
                suffix = check.suffix,
                body = indent(&check.body),
            )
        })
        .collect();

    let conjuncts = checks
        .iter()
        .map(|check| format!("\t{pred}_{}", check.suffix))
        .collect::<Vec<_>>()
        .join("\n");
    blocks.push(format!("{pred} if {{\n{conjuncts}\n}}"));

    for check in checks {
        let sub_check = format!("{pred}_{}", check.suffix);
        let check_name = format!("{check_prefix}.{}", check.suffix);
        blocks.push(format!(
            r#"{diag}_{suffix} := {{
	"dimension": {dimension:?},
	"check": {check_name:?},
	"matched": true,
	"expected": {expected:?},
	"actual": {actual},
}} if {{
	{sub_check}
}}

{diag}_{suffix} := {{
	"dimension": {dimension:?},
	"check": {check_name:?},
	"matched": false,
	"expected": {expected:?},
	"actual": {actual},
	"reason": "mismatch",
}} if {{
	not {sub_check}
}}"#,
            suffix = check.suffix,
            expected = check.expected,
            actual = check.actual_expr,
        ));
    }
    blocks.join("\n\n")
}

/// Emit the sub-checks of a `tdx` posture entry plus helper rules for the
/// disjunctive checks (service-TD zero, rejected advisories). Every field
/// defaults to its strict choice; a field that "allows"/"optionals" adds no
/// sub-check. There is no `nonce_binding` field: the `report_data` session
/// binding is enforced unconditionally by the verifier's `runtime_data` path,
/// so it is not a policy knob and is not emitted here.
fn tdx_posture_rule(
    cfg: &TdxPostureConfig,
    name: &str,
) -> anyhow::Result<(Vec<PostureCheck>, Vec<String>)> {
    let mut checks: Vec<PostureCheck> = Vec::new();
    let mut extra: Vec<String> = Vec::new();

    if cfg.debug == TdxBit::Deny {
        checks.push(PostureCheck {
            suffix: "debug",
            expected: "debug bit clear".to_string(),
            actual_expr: TD_ATTRIBUTES_ACTUAL.to_string(),
            body: vec![
                r#"regex.match("^[0-9a-f][02468ace]", input.tdx.quote.body.td_attributes)"#
                    .to_string(),
            ],
        });
    }
    if cfg.sept_ve_disable == TdxSeptVe::Require {
        checks.push(PostureCheck {
            suffix: "sept_ve_disable",
            expected: "SEPT #VE disable bit set".to_string(),
            actual_expr: TD_ATTRIBUTES_ACTUAL.to_string(),
            body: vec![
                r#"regex.match("^[0-9a-f]{6}[13579bdf]", input.tdx.quote.body.td_attributes)"#
                    .to_string(),
            ],
        });
    }
    if cfg.perfmon == TdxBit::Deny {
        checks.push(PostureCheck {
            suffix: "perfmon",
            expected: "perfmon bit clear".to_string(),
            actual_expr: TD_ATTRIBUTES_ACTUAL.to_string(),
            body: vec![
                r#"regex.match("^[0-9a-f]{14}[0-7]", input.tdx.quote.body.td_attributes)"#
                    .to_string(),
            ],
        });
    }
    if cfg.service_td == TdxBit::Deny {
        // Zero and absent are both acceptable: a v4 quote carries a zero
        // service-TD measurement, an older one omits the field.
        let helper = format!("{name}_svc_td");
        extra.push(format!(
            r#"{helper} if {{
	not input.tdx.quote.body.mr_servicetd
}}

{helper} if {{
	regex.match("^0{{96}}$", input.tdx.quote.body.mr_servicetd)
}}"#
        ));
        checks.push(PostureCheck {
            suffix: "service_td",
            expected: "mr_servicetd zero or absent".to_string(),
            actual_expr: MR_SERVICETD_ACTUAL.to_string(),
            body: vec![helper],
        });
    }

    // TCB gate (opt-in). A revoked status always rejects; `up_to_date` further
    // rejects the out-of-date ranks. `advisory_ids` is a comma-joined string.
    if let Some(tcb) = &cfg.tcb {
        let mut body = vec![
            "v := input.tdx.tcb_verification".to_string(),
            "v.tcb_status != \"Revoked\"".to_string(),
        ];
        let expected = if tcb.min_status == TcbMinStatus::UpToDate {
            body.push(
                "v.tcb_status in [\"UpToDate\", \"ConfigurationNeeded\", \"SWHardeningNeeded\", \"ConfigurationAndSWHardeningNeeded\"]".to_string(),
            );
            "tcb_status != Revoked and tcb_status in [UpToDate, ConfigurationNeeded, SWHardeningNeeded, ConfigurationAndSWHardeningNeeded]".to_string()
        } else {
            "tcb_status != Revoked".to_string()
        };
        checks.push(PostureCheck {
            suffix: "tcb_status",
            expected,
            actual_expr: tcb_actual("tcb_status"),
            body,
        });

        if !tcb.reject_advisories.is_empty() {
            let helper = format!("{name}_adv");
            let reject = rego_string_array(&tcb.reject_advisories);
            let allow = rego_string_array(&tcb.allow_advisories);
            extra.push(format!(
                r#"{helper} if {{
	some a in {reject}
	a in split(input.tdx.tcb_verification.advisory_ids, ",")
	not a in {allow}
}}"#
            ));
            checks.push(PostureCheck {
                suffix: "tcb_advisories",
                expected: format!("no advisory in {reject} unless allowed by {allow}"),
                actual_expr: tcb_actual("advisory_ids"),
                body: vec![format!("not {helper}")],
            });
        }
    }

    // Collateral gate (opt-in). All thresholds are compared against the
    // epoch-second fields that the native TDX verifier places in
    // `tcb_verification`.
    if let Some(coll) = &cfg.collateral {
        if !coll.allow_expired {
            checks.push(PostureCheck {
                suffix: "collateral_expired",
                expected: "collateral not expired".to_string(),
                actual_expr: tcb_actual("collateral_expired"),
                body: vec![
                    "vc := input.tdx.tcb_verification".to_string(),
                    "vc.collateral_expired == false".to_string(),
                ],
            });
        }
        if let Some(date) = &coll.min_tcb_date {
            let epoch = iso_date_to_epoch_secs(date).with_context(|| {
                format!("validated tdx collateral min_tcb_date {date:?} is not convertible to epoch seconds")
            })?;
            checks.push(PostureCheck {
                suffix: "collateral_min_tcb_date",
                expected: format!("tcb_level_date_tag >= {date}"),
                actual_expr: tcb_actual("tcb_level_date_tag"),
                body: vec![
                    "vc := input.tdx.tcb_verification".to_string(),
                    format!("vc.tcb_level_date_tag >= {epoch}"),
                ],
            });
        }
        if let Some(days) = coll.max_collateral_age_days {
            let secs = days as i64 * 86400;
            checks.push(PostureCheck {
                suffix: "collateral_max_age",
                expected: format!("collateral age <= {days} days"),
                actual_expr: tcb_actual("latest_issue_date"),
                body: vec![
                    "vc := input.tdx.tcb_verification".to_string(),
                    // No leading parenthesis: a newline followed by `(` would
                    // parse as a call of the previous line's expression.
                    format!("time.now_ns() / 1000000000 - vc.latest_issue_date <= {secs}"),
                ],
            });
        }
    }

    if cfg.eventlog == TdxEventlog::Required {
        checks.push(PostureCheck {
            suffix: "eventlog",
            expected: "non-empty event log".to_string(),
            actual_expr:
                r#"count(object.get(object.get(input, "tdx", {}), "uefi_event_logs", []))"#
                    .to_string(),
            body: vec!["count(input.tdx.uefi_event_logs) > 0".to_string()],
        });
    }

    Ok((checks, extra))
}

/// Emit the sub-checks of a `com.alibabacloud.gpu` entry: the guest-reported
/// AAEL GPU attestation event must exist and every such event must report zero
/// for both result codes.
fn gpu_posture_rule() -> Vec<PostureCheck> {
    vec![
        PostureCheck {
            suffix: "event_present",
            expected: "gpu/attestation event present".to_string(),
            actual_expr: "count(gpu_attestation_events)".to_string(),
            body: vec!["count(gpu_attestation_events) > 0".to_string()],
        },
        PostureCheck {
            suffix: "result_codes",
            expected: "collect and attest result codes are 0".to_string(),
            actual_expr: r#"[{"collect": e.details.data.content["gpu-collect-evidence-result-code"], "attest": e.details.data.content["gpu-attest-result-code"]} | some e in gpu_attestation_events]"#.to_string(),
            body: vec![
                "every e in gpu_attestation_events {".to_string(),
                r#"	e.details.data.content["gpu-collect-evidence-result-code"] == 0"#.to_string(),
                r#"	e.details.data.content["gpu-attest-result-code"] == 0"#.to_string(),
                "}".to_string(),
            ],
        },
    ]
}

/// A compact diagnostic projection of the GPUs an allow-list check rejects:
/// the GPU key and UUID, plus the one field the check inspects. The whole
/// claim is never projected: a raw/skip report's `attestation_report` must not
/// reach the token or the client's error text.
fn nvidia_actual(field: Option<&str>, condition: &str) -> String {
    let mut projection = "\"gpu\": e.gpu, \"uuid\": e.claim.uuid".to_string();
    if let Some(field) = field {
        projection.push_str(&format!(", {field:?}: e.claim.{field}"));
    }
    format!("[{{{projection}}} | some e in nvidia_gpus; {condition}]")
}

/// Emit the sub-checks of an `nvidia` posture entry: the standard trustee
/// NVIDIA appraisal over the evaluated per-GPU claims, rejecting the raw/skip
/// passthrough form (which carries attestation_report and lacks measurement).
fn nvidia_posture_rule(cfg: &NvidiaPostureConfig) -> Vec<PostureCheck> {
    let mut checks = vec![
        PostureCheck {
            suffix: "count",
            expected: format!(">= {} GPU(s)", cfg.min_count),
            actual_expr: "count(nvidia_gpus)".to_string(),
            body: vec![format!("count(nvidia_gpus) >= {}", cfg.min_count)],
        },
        PostureCheck {
            suffix: "raw_form",
            expected: "no raw/skip passthrough report".to_string(),
            actual_expr: nvidia_actual(None, "e.claim.attestation_report"),
            body: vec![
                "every e in nvidia_gpus {".to_string(),
                "\tnot e.claim.attestation_report".to_string(),
                "}".to_string(),
            ],
        },
    ];

    if cfg.require_report {
        checks.push(PostureCheck {
            suffix: "measurement",
            expected: "measurement present".to_string(),
            actual_expr: nvidia_actual(None, "not e.claim.measurement"),
            body: vec![
                "every e in nvidia_gpus {".to_string(),
                "\te.claim.measurement".to_string(),
                "}".to_string(),
            ],
        });
    }
    if cfg.require_cc_mode {
        checks.push(PostureCheck {
            suffix: "cc_enabled",
            expected: "cc_enabled == true".to_string(),
            actual_expr: nvidia_actual(Some("cc_enabled"), "e.claim.cc_enabled != true"),
            body: vec![
                "every e in nvidia_gpus {".to_string(),
                "\te.claim.cc_enabled == true".to_string(),
                "}".to_string(),
            ],
        });
    }
    if !cfg.allow_uuids.is_empty() {
        // `uuid` is the check's field as well as the identifier, so the
        // projection carries it once.
        let allow = rego_string_array(&cfg.allow_uuids);
        checks.push(PostureCheck {
            suffix: "uuid",
            expected: format!("uuid in {allow}"),
            actual_expr: nvidia_actual(None, &format!("not e.claim.uuid in {allow}")),
            body: vec![
                "every e in nvidia_gpus {".to_string(),
                format!("\te.claim.uuid in {allow}"),
                "}".to_string(),
            ],
        });
    }
    if !cfg.allow_driver_versions.is_empty() {
        let allow = rego_string_array(&cfg.allow_driver_versions);
        checks.push(PostureCheck {
            suffix: "driver_version",
            expected: format!("driver_version in {allow}"),
            actual_expr: nvidia_actual(
                Some("driver_version"),
                &format!("not e.claim.driver_version in {allow}"),
            ),
            body: vec![
                "every e in nvidia_gpus {".to_string(),
                format!("\te.claim.driver_version in {allow}"),
                "}".to_string(),
            ],
        });
    }
    if !cfg.allow_vbios_versions.is_empty() {
        let allow = rego_string_array(&cfg.allow_vbios_versions);
        checks.push(PostureCheck {
            suffix: "vbios_version",
            expected: format!("vbios_version in {allow}"),
            actual_expr: nvidia_actual(
                Some("vbios_version"),
                &format!("not e.claim.vbios_version in {allow}"),
            ),
            body: vec![
                "every e in nvidia_gpus {".to_string(),
                format!("\te.claim.vbios_version in {allow}"),
                "}".to_string(),
            ],
        });
    }
    if !cfg.measurement_digest.is_empty() {
        let allow = rego_string_array(&cfg.measurement_digest);
        checks.push(PostureCheck {
            suffix: "measurement_digest",
            expected: format!("measurement in {allow}"),
            actual_expr: nvidia_actual(
                Some("measurement"),
                &format!("not e.claim.measurement in {allow}"),
            ),
            body: vec![
                "every e in nvidia_gpus {".to_string(),
                format!("\te.claim.measurement in {allow}"),
                "}".to_string(),
            ],
        });
    }
    checks
}

/// The platform's own diagnostic: reports evidence that does not identify the
/// platform the policy's entries are rooted at.
fn platform_diagnostic_rule(platform: &Platform) -> String {
    let recognition = platform.recognition();
    let check = platform.check_name();
    format!(
        r#"diag_platform := {{
	"dimension": "hardware",
	"check": {check:?},
	"matched": true,
}} if {{
	{recognition}
}}

diag_platform := {{
	"dimension": "hardware",
	"check": {check:?},
	"matched": false,
	"reason": "platform-not-recognized",
}} if {{
	not {recognition}
}}"#
    )
}

/// Emit the collector that turns the non-matching diagnostics into the
/// extension payload. A check whose dimension still affirms is dropped: it
/// failed only against a baseline that lost its OR group, or a posture that
/// lost to another group, so reporting it would contradict the verdict.
///
/// The value is marshalled to a JSON string because the pinned `ear` crate
/// serializes a map-valued extension as key/value pairs, not a JSON object.
fn failed_checks_block(diag_names: &[String]) -> String {
    format!(
        r#"dimension_value("executables") := executables
dimension_value("hardware") := hardware

failed_checks := [d |
	some raw in [{names}]
	not raw.matched
	dimension_value(raw.dimension) != 2
	d := object.remove(raw, ["matched"])
]

extensions := [{{
	"name": {extension:?},
	"key": {key},
	"value": json.marshal({{"failed": failed_checks}}),
}}] if {{
	count(failed_checks) > 0
}}"#,
        names = diag_names.join(", "),
        extension = APPRAISAL_DIAGNOSTICS_EXTENSION,
        key = APPRAISAL_DIAGNOSTICS_KEY,
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
    use super::*;
    use crate::tee::coco::converter::builtin::converter::BuiltinCocoConverter;
    use crate::tee::coco::converter::builtin::policies::transparency_log::{
        eval_policy_extensions, eval_policy_vector,
    };
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
        for t in ["tdx.kernel", "tdx.uki", "ai.model.Qwen/Qwen3.8-27B"] {
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
        ];
        for spelling in accepted {
            assert!(
                EntryType::parse(spelling).is_ok(),
                "accepted spelling {spelling:?} must parse"
            );
        }

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
        // the pinned value is embedded as a literal, with no RVPS lookup
        assert!(policy.contains(&format!("input.tdx.quote.body.mr_td == \"{ovmf}\"")));
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
    }

    #[test]
    fn modules_policy_without_transparency_has_no_actual_measurement_rule() {
        // The shared transparency measurement-extraction rules are emitted
        // once, and only when a `transparency_log` entry exists. A
        // container.image entry emits the repo-name helper but must not pull
        // in those rules.
        let image = format!("sha256:{}", "c".repeat(64));
        let policy = build_policy(&modules_cfg(&format!(
            r#"[{{"type":"com.alibabacloud.container.image.model-server","value":"{image}"}}]"#
        )))
        .expect("build");
        assert!(policy.contains("image_repo_name"));
        assert!(!policy.contains("actual_measurement"), "{policy}");
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
        // each group carries its own literal; no group-suffixed reference names
        let (a, b) = ("a".repeat(96), "b".repeat(96));
        assert!(policy.contains(&format!("input.tdx.quote.body.mr_td == \"{a}\"")));
        assert!(policy.contains(&format!("input.tdx.quote.body.mr_td == \"{b}\"")));
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

    /// The `failed` list of the policy's `tng.appraisal-diagnostics`
    /// extension, or `None` when the policy emits no extension.
    async fn eval_failed_checks(cfg_json: &str, input: &str) -> Option<Vec<serde_json::Value>> {
        let cfg = modules_cfg(cfg_json);
        let policy = build_policy(&cfg).expect("build modules policy");
        let extensions = eval_policy_extensions(&policy, input).await?;
        let entries = extensions
            .as_array()
            .unwrap_or_else(|| panic!("extensions is an array: {extensions}"));
        let extension = entries
            .iter()
            .find(|e| e["name"] == APPRAISAL_DIAGNOSTICS_EXTENSION)
            .expect("diagnostics extension present");
        assert_eq!(extension["key"], APPRAISAL_DIAGNOSTICS_KEY);
        // The pinned `ear` crate cannot carry a nested object as an extension
        // value, so the policy marshals the payload to a JSON string.
        let payload = extension["value"]
            .as_str()
            .expect("diagnostics value is a json string");
        let payload: serde_json::Value = serde_json::from_str(payload).expect("payload parses");
        Some(
            payload["failed"]
                .as_array()
                .expect("failed is an array")
                .clone(),
        )
    }

    /// One `pai/load-model` AAEL event for `Qwen/Qwen3.8-27B`.
    fn pai_load_model_event(hash: &str) -> serde_json::Value {
        json!({
            "type_name": "EV_EVENT_TAG",
            "details": { "unicode_name": "AAEL", "data": {
                "domain": "alibabacloud.com",
                "operation": "pai/load-model",
                "content": { "model-id": "Qwen/Qwen3.8-27B", "hash": hash }
            } }
        })
    }

    #[tokio::test]
    async fn modules_diagnostics_report_measurement_mismatches() {
        let image = format!("sha256:{}", hex64('a'));
        let kernel = hex96('1');
        let model = hex64('b');
        let cfg = format!(
            r#"[{{"type":"com.alibabacloud.container.image.vllm","value":"{image}"}},{{"type":"tdx.kernel","value":"{kernel}"}},{{"type":"com.alibabacloud.ai.model.Qwen/Qwen3.8-27B","value":"{model}"}}]"#
        );
        let kernel_event = |d: &str| {
            json!({
                "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
                "details": { "string": "td_payload" },
                "index": 2,
                "digests": [ { "alg": "SHA-384", "digest": d } ],
            })
        };
        let pull_event = |d: &str| {
            json!({
                "type_name": "EV_EVENT_TAG",
                "details": { "unicode_name": "AAEL", "data": {
                    "domain": "alibabacloud.com",
                    "operation": "kangaroo/pull-image",
                    "content": {
                        "reference": "registry.example.com/ns/vllm:latest",
                        "digest": d,
                    }
                } }
            })
        };

        let ok = tdx_input(
            serde_json::Value::Null,
            &[
                kernel_event(&kernel),
                pull_event(&image),
                pai_load_model_event(&model),
            ],
        );
        assert_eq!(eval_modules(&cfg, &ok).await, (2, 2, 2, 2));
        assert!(
            eval_failed_checks(&cfg, &ok).await.is_none(),
            "a successful appraisal emits no diagnostics extension"
        );

        // Container image mismatch.
        let tampered_image = format!("sha256:{}", hex64('f'));
        let bad_image = tdx_input(
            serde_json::Value::Null,
            &[
                kernel_event(&kernel),
                pull_event(&tampered_image),
                pai_load_model_event(&model),
            ],
        );
        let failed = eval_failed_checks(&cfg, &bad_image)
            .await
            .expect("extension present");
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert_eq!(failed[0]["dimension"], "executables");
        assert_eq!(failed[0]["check"], "com.alibabacloud.container.image.vllm");
        assert_eq!(failed[0]["expected"], json!(image));
        assert_eq!(failed[0]["actual"], json!([tampered_image]));
        assert_eq!(failed[0]["reason"], "mismatch");
        assert!(
            failed[0].get("matched").is_none(),
            "matched is internal and must not reach the payload"
        );

        // Kernel mismatch.
        let tampered_kernel = hex96('9');
        let bad_kernel = tdx_input(
            serde_json::Value::Null,
            &[
                kernel_event(&tampered_kernel),
                pull_event(&image),
                pai_load_model_event(&model),
            ],
        );
        let failed = eval_failed_checks(&cfg, &bad_kernel)
            .await
            .expect("extension present");
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert_eq!(failed[0]["check"], "tdx.kernel");
        assert_eq!(failed[0]["actual"], json!([tampered_kernel]));

        // Model hash mismatch: the actual is the observed model/hash pairs.
        let tampered_model = hex64('e');
        let bad_model = tdx_input(
            serde_json::Value::Null,
            &[
                kernel_event(&kernel),
                pull_event(&image),
                pai_load_model_event(&tampered_model),
            ],
        );
        let failed = eval_failed_checks(&cfg, &bad_model)
            .await
            .expect("extension present");
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert_eq!(
            failed[0]["check"],
            "com.alibabacloud.ai.model.Qwen/Qwen3.8-27B"
        );
        assert_eq!(
            failed[0]["actual"],
            json!([{ "model-id": "Qwen/Qwen3.8-27B", "hash": tampered_model }])
        );
    }

    #[tokio::test]
    async fn modules_diagnostics_report_tdx_posture_sub_checks() {
        let cfg = r#"[{"type":"tdx","value":{}}]"#;
        let ok = tdx_input(serde_json::Value::Null, &[json!({ "event": "ok" })]);
        assert_eq!(eval_modules(cfg, &ok).await, (2, 2, 2, 2));
        assert!(
            eval_failed_checks(cfg, &ok).await.is_none(),
            "a passing posture emits no diagnostics extension"
        );

        // Debug bit set: only that sub-check is reported, with the raw
        // attribute word as `actual`.
        let debug = ok.replace("0000001000000000", "0100001000000000");
        let failed = eval_failed_checks(cfg, &debug)
            .await
            .expect("extension present");
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert_eq!(failed[0]["dimension"], "hardware");
        assert_eq!(failed[0]["check"], "tdx.debug");
        assert_eq!(failed[0]["expected"], "debug bit clear");
        assert_eq!(failed[0]["actual"], "0100001000000000");
        assert_eq!(failed[0]["reason"], "mismatch");

        // Missing event log: only the eventlog sub-check is reported.
        let no_eventlog = tdx_input(serde_json::Value::Null, &[]);
        let failed = eval_failed_checks(cfg, &no_eventlog)
            .await
            .expect("extension present");
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert_eq!(failed[0]["check"], "tdx.eventlog");
        assert_eq!(failed[0]["expected"], "non-empty event log");
        assert_eq!(failed[0]["actual"], json!(0));

        // Several failing sub-checks are all reported, in check order.
        let multi = tdx_input(json!({ "td_attributes": "0100001000000080" }), &[]);
        let failed = eval_failed_checks(cfg, &multi)
            .await
            .expect("extension present");
        let checks: Vec<_> = failed.iter().map(|f| f["check"].clone()).collect();
        assert_eq!(
            checks,
            vec![
                json!("tdx.debug"),
                json!("tdx.perfmon"),
                json!("tdx.eventlog"),
            ],
            "{failed:?}"
        );
    }

    #[tokio::test]
    async fn modules_diagnostics_report_nvidia_cc_enabled() {
        let measurement = hex96('3');
        let cfg = r#"[{"type":"nvidia","value":{"min_count":1}}]"#;
        let gpu_input = |cc_enabled: bool| {
            tdx_input_full(
                serde_json::Value::Null,
                json!({ "nvidia_gpu.0": {
                    "uuid": "GPU-x", "name": "L20C", "driver_version": "570.148.05",
                    "vbios_version": "96.00.f4", "cc_enabled": cc_enabled,
                    "measurement": measurement.clone()
                } }),
                &[json!({ "event": "ok" })],
            )
        };

        let ok = gpu_input(true);
        assert_eq!(eval_modules(cfg, &ok).await, (2, 2, 2, 2));
        assert!(eval_failed_checks(cfg, &ok).await.is_none());

        let failed = eval_failed_checks(cfg, &gpu_input(false))
            .await
            .expect("extension present");
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert_eq!(failed[0]["dimension"], "hardware");
        assert_eq!(failed[0]["check"], "nvidia.cc_enabled");
        assert_eq!(failed[0]["expected"], "cc_enabled == true");
        assert_eq!(failed[0]["reason"], "mismatch");
        let actual = failed[0]["actual"].as_array().expect("gpu list");
        assert_eq!(
            actual,
            &vec![json!({
                "gpu": "nvidia_gpu.0",
                "uuid": "GPU-x",
                "cc_enabled": false,
            })],
            "{failed:?}"
        );
    }

    #[tokio::test]
    async fn modules_diagnostics_report_gpu_result_codes() {
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

        let ok = tdx_input(serde_json::Value::Null, &[gpu_event(0, 0)]);
        assert!(eval_failed_checks(cfg, &ok).await.is_none());

        let failed =
            eval_failed_checks(cfg, &tdx_input(serde_json::Value::Null, &[gpu_event(0, 5)]))
                .await
                .expect("extension present");
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert_eq!(failed[0]["dimension"], "hardware");
        assert_eq!(failed[0]["check"], "gpu.result_codes");
        assert_eq!(
            failed[0]["expected"],
            "collect and attest result codes are 0"
        );
        assert_eq!(failed[0]["actual"], json!([{ "collect": 0, "attest": 5 }]));

        // A missing attestation event fails the presence sub-check only. The
        // vacuous result-code check must not add a second, misleading failure.
        let none = tdx_input(serde_json::Value::Null, &[]);
        let failed = eval_failed_checks(cfg, &none)
            .await
            .expect("extension present");
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert_eq!(failed[0]["check"], "gpu.event_present");
        assert_eq!(failed[0]["expected"], "gpu/attestation event present");
        assert_eq!(failed[0]["actual"], json!(0));
    }

    #[tokio::test]
    async fn modules_diagnostics_skip_winning_or_group_failures() {
        let (a, b) = (hex96('1'), hex96('2'));
        let cfg = format!(
            r#"[[{{"type":"tdx.ovmf","value":"{a}"}}],[{{"type":"tdx.ovmf","value":"{b}"}}]]"#
        );
        let input = tdx_input(json!({ "mr_td": a }), &[json!({ "event": "ok" })]);
        assert_eq!(eval_modules(&cfg, &input).await, (2, 2, 2, 2));
        assert!(
            eval_failed_checks(&cfg, &input).await.is_none(),
            "the losing group of an affirming OR group must not be reported"
        );

        // Neither group matches: the dimension is non-affirming and both
        // baseline failures are reported.
        let neither = tdx_input(json!({ "mr_td": hex96('9') }), &[json!({ "event": "ok" })]);
        let failed = eval_failed_checks(&cfg, &neither)
            .await
            .expect("extension present");
        assert_eq!(failed.len(), 2, "{failed:?}");
        assert!(failed.iter().all(|f| f["check"] == "tdx.ovmf"));
        assert!(failed.iter().all(|f| f["dimension"] == "executables"));

        // Non-TDX evidence leaves both dimensions non-affirming: the platform
        // itself is reported, with no observed measurement.
        let csv = json!({ "csv": { "version": "2" } }).to_string();
        let failed = eval_failed_checks(&cfg, &csv)
            .await
            .expect("extension present");
        let platform = failed
            .iter()
            .find(|f| f["check"] == "tdx")
            .expect("platform check reported");
        assert_eq!(platform["dimension"], "hardware");
        assert_eq!(platform["reason"], "platform-not-recognized");
        assert!(failed.iter().any(|f| f["check"] == "tdx.ovmf"));
        assert!(
            failed.iter().all(|f| f["actual"].is_null()),
            "no TDX evidence means no observed measurement: {failed:?}"
        );
    }

    // Test-only clock used to build epoch-relative fixtures; the test runs on
    // the host, and `std::time::SystemTime::now` is correct there.
    #[allow(clippy::disallowed_methods)]
    #[tokio::test]
    async fn modules_diagnostics_report_tdx_tcb_and_collateral_sub_checks() {
        // Every attribute sub-check disabled, so only the TCB and collateral
        // sub-checks can fail.
        let cfg = r#"[{"type":"tdx","value":{
            "debug":"allow","sept_ve_disable":"allow","perfmon":"allow",
            "service_td":"allow","eventlog":"optional",
            "tcb":{"min_status":"up_to_date","reject_advisories":["INTEL-SA-00001"]},
            "collateral":{"allow_expired":false,"min_tcb_date":"2026-06-01","max_collateral_age_days":30}
        }}]"#;
        let epoch = iso_date_to_epoch_secs("2026-06-01").expect("epoch");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after the epoch")
            .as_secs() as i64;

        let ok = tcb_input(json!({
            "tcb_status": "UpToDate",
            "advisory_ids": "",
            "collateral_expired": false,
            "tcb_level_date_tag": epoch,
            "latest_issue_date": now,
        }));
        assert!(eval_failed_checks(cfg, &ok).await.is_none());

        // All five TCB/collateral sub-checks failing at once.
        let stale_issue = now - 40 * 86400;
        let bad = tcb_input(json!({
            "tcb_status": "OutOfDate",
            "advisory_ids": "INTEL-SA-00001",
            "collateral_expired": true,
            "tcb_level_date_tag": epoch - 1,
            "latest_issue_date": stale_issue,
        }));
        let failed = eval_failed_checks(cfg, &bad)
            .await
            .expect("extension present");
        let checks: Vec<_> = failed.iter().map(|f| f["check"].clone()).collect();
        assert_eq!(
            checks,
            vec![
                json!("tdx.tcb_status"),
                json!("tdx.tcb_advisories"),
                json!("tdx.collateral_expired"),
                json!("tdx.collateral_min_tcb_date"),
                json!("tdx.collateral_max_age"),
            ],
            "{failed:?}"
        );
        let actual: Vec<_> = failed.iter().map(|f| f["actual"].clone()).collect();
        assert_eq!(
            actual,
            vec![
                json!("OutOfDate"),
                json!("INTEL-SA-00001"),
                json!(true),
                json!(epoch - 1),
                json!(stale_issue),
            ]
        );
    }

    #[tokio::test]
    async fn modules_diagnostics_project_nvidia_allow_list_failures() {
        let pinned_digest = hex96('3');
        let observed_digest = hex96('4');
        let cfg = format!(
            r#"[{{"type":"nvidia","value":{{
                "allow_uuids":["GPU-a"],
                "allow_driver_versions":["570.148.05"],
                "allow_vbios_versions":["96.00.f4"],
                "measurement_digest":["{pinned_digest}"]
            }}}}]"#
        );
        let input = tdx_input_full(
            serde_json::Value::Null,
            json!({ "nvidia_gpu.0": {
                "uuid": "GPU-x", "name": "L20C", "driver_version": "999.0.0",
                "vbios_version": "1.2.3", "cc_enabled": true,
                "measurement": observed_digest.clone()
            } }),
            &[json!({ "event": "ok" })],
        );
        let failed = eval_failed_checks(&cfg, &input)
            .await
            .expect("extension present");
        let checks: Vec<_> = failed.iter().map(|f| f["check"].clone()).collect();
        assert_eq!(
            checks,
            vec![
                json!("nvidia.uuid"),
                json!("nvidia.driver_version"),
                json!("nvidia.vbios_version"),
                json!("nvidia.measurement_digest"),
            ],
            "{failed:?}"
        );
        let actual: Vec<_> = failed.iter().map(|f| f["actual"].clone()).collect();
        assert_eq!(
            actual,
            vec![
                // `uuid` is both the identifier and the checked field, so it
                // appears once.
                json!([{ "gpu": "nvidia_gpu.0", "uuid": "GPU-x" }]),
                json!([{ "gpu": "nvidia_gpu.0", "uuid": "GPU-x", "driver_version": "999.0.0" }]),
                json!([{ "gpu": "nvidia_gpu.0", "uuid": "GPU-x", "vbios_version": "1.2.3" }]),
                json!([{ "gpu": "nvidia_gpu.0", "uuid": "GPU-x", "measurement": observed_digest }]),
            ]
        );
    }

    #[tokio::test]
    async fn modules_diagnostics_nvidia_actual_never_leaks_the_raw_report() {
        // Skip/raw passthrough: the claim carries the base64 attestation
        // report and no measurement, so both the raw_form and measurement
        // sub-checks fail.
        const RAW_REPORT: &str = "SENSITIVE-BASE64-ATTESTATION-REPORT";
        let cfg = r#"[{"type":"nvidia","value":{"min_count":1}}]"#;
        let input = tdx_input_full(
            serde_json::Value::Null,
            json!({ "nvidia_gpu.0": {
                "index": 0, "uuid": "GPU-x", "cc_enabled": true,
                "attestation_report": RAW_REPORT
            } }),
            &[json!({ "event": "ok" })],
        );
        let failed = eval_failed_checks(cfg, &input)
            .await
            .expect("extension present");
        let checks: Vec<_> = failed.iter().map(|f| f["check"].clone()).collect();
        assert_eq!(
            checks,
            vec![json!("nvidia.raw_form"), json!("nvidia.measurement")],
            "{failed:?}"
        );
        // Each actual identifies the GPU without embedding its claim.
        for check in &failed {
            assert_eq!(
                check["actual"],
                json!([{ "gpu": "nvidia_gpu.0", "uuid": "GPU-x" }])
            );
        }
        let payload = serde_json::to_string(&failed).expect("serialize failed checks");
        assert!(
            !payload.contains(RAW_REPORT) && !payload.contains("attestation_report"),
            "the raw report must never reach a diagnostic: {payload}"
        );
    }
}

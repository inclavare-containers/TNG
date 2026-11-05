//! The `modules` attestation policy: entry parsing, validation, and Rego
//! generation.

use super::super::policy_config::{
    value_shape, GpuPostureConfig, ModuleEntryConfig, ModuleGroupsConfig, NvidiaPostureConfig,
    TcbMinStatus, TdxBit, TdxCollateralConfig, TdxEventlog, TdxPostureConfig, TdxSeptVe,
    TdxTcbConfig,
};
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
            | Module::AiModel { .. } => Dimension::Executables,
            Module::Tdx(_) | Module::Nvidia(_) | Module::Gpu => Dimension::Hardware,
        }
    }
}

/// One accepted module family. Vendor-coupled families live under the
/// `com.alibabacloud.` prefix; the two measurement families also accept an
/// unprefixed permanent alias.
struct ModuleFamily {
    /// Canonical type spelling, or the prefix of a suffixed family.
    canonical: &'static str,
    /// Placeholder for a free-form name segment that follows `canonical`.
    placeholder: Option<&'static str>,
    /// Permanent unprefixed alias prefix, when one exists.
    unprefixed_alias: Option<&'static str>,
}

const MODULE_FAMILIES: &[ModuleFamily] = &[
    ModuleFamily {
        canonical: "tdx",
        placeholder: None,
        unprefixed_alias: None,
    },
    ModuleFamily {
        canonical: "nvidia",
        placeholder: None,
        unprefixed_alias: None,
    },
    ModuleFamily {
        canonical: "tdx.td-shim",
        placeholder: None,
        unprefixed_alias: None,
    },
    ModuleFamily {
        canonical: "tdx.ovmf",
        placeholder: None,
        unprefixed_alias: None,
    },
    ModuleFamily {
        canonical: "tdx.kernel",
        placeholder: None,
        unprefixed_alias: None,
    },
    ModuleFamily {
        canonical: "tdx.uki",
        placeholder: None,
        unprefixed_alias: None,
    },
    ModuleFamily {
        canonical: "com.alibabacloud.gpu",
        placeholder: None,
        unprefixed_alias: None,
    },
    ModuleFamily {
        canonical: "com.alibabacloud.container.image.",
        placeholder: Some("<repo>"),
        unprefixed_alias: Some("container.image."),
    },
    ModuleFamily {
        canonical: "com.alibabacloud.ai.model.",
        placeholder: Some("<model-id>"),
        unprefixed_alias: Some("ai.model."),
    },
];

fn unknown_module_type(raw: &str) -> anyhow::Error {
    let known = MODULE_FAMILIES
        .iter()
        .map(|f| match f.placeholder {
            Some(placeholder) => match f.unprefixed_alias {
                Some(alias) => format!("{}{placeholder} (alias {alias}{placeholder})", f.canonical),
                None => format!("{}{placeholder}", f.canonical),
            },
            None => f.canonical.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::anyhow!("unknown module type {raw:?}; known types: {known}")
}

/// Normalize an entry type to its canonical spelling. A permanent alias is
/// rewritten to its canonical `com.alibabacloud.` form; any type not described
/// by [`MODULE_FAMILIES`] is rejected, which is also where prefix legality is
/// enforced.
fn normalized_module_type(raw: &str) -> anyhow::Result<String> {
    for family in MODULE_FAMILIES {
        if family.placeholder.is_some() {
            for prefix in std::iter::once(family.canonical).chain(family.unprefixed_alias) {
                if let Some(suffix) = raw.strip_prefix(prefix) {
                    return Ok(format!("{}{suffix}", family.canonical));
                }
            }
        } else if raw == family.canonical {
            return Ok(family.canonical.to_string());
        }
    }
    Err(unknown_module_type(raw))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dimension {
    Executables,
    Hardware,
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
    /// Parse and validate one entry into a concrete [`Module`]. Rejects unknown
    /// types, malformed values, and bad name segments as configuration errors.
    fn to_module(&self) -> anyhow::Result<Module> {
        let module_type = normalized_module_type(&self.module_type)?;
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

        match module_type.as_str() {
            "tdx" => {
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
            "com.alibabacloud.gpu" => {
                value_obj()?;
                let _: GpuPostureConfig = serde_json::from_value(self.value.clone())
                    .context("invalid com.alibabacloud.gpu config")?;
                Ok(Module::Gpu)
            }
            "nvidia" => {
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
            "tdx.td-shim" => {
                let v = value_str()?;
                if !is_lower_hex(&v, 96) {
                    anyhow::bail!(
                        "module type {:?} value must be 96 lowercase hex chars",
                        self.module_type
                    );
                }
                Ok(Module::TdShim { value: v })
            }
            "tdx.ovmf" => {
                let v = value_str()?;
                if !is_lower_hex(&v, 96) {
                    anyhow::bail!(
                        "module type {:?} value must be 96 lowercase hex chars",
                        self.module_type
                    );
                }
                Ok(Module::Ovmf { value: v })
            }
            "tdx.kernel" => {
                let v = value_str()?;
                if !is_lower_hex(&v, 96) {
                    anyhow::bail!(
                        "module type {:?} value must be 96 lowercase hex chars",
                        self.module_type
                    );
                }
                Ok(Module::Kernel { value: v })
            }
            "tdx.uki" => {
                let v = value_str()?;
                if !is_lower_hex(&v, 96) {
                    anyhow::bail!(
                        "module type {:?} value must be 96 lowercase hex chars",
                        self.module_type
                    );
                }
                Ok(Module::Uki { value: v })
            }
            other => {
                // Extensible, name-bearing families.
                if let Some(repo) = other.strip_prefix("com.alibabacloud.container.image.") {
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
                } else if let Some(model_id) = other.strip_prefix("com.alibabacloud.ai.model.") {
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
                } else {
                    Err(unknown_module_type(&self.module_type))
                }
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
        // malformed.
        let mut seen = std::collections::HashSet::new();
        for entry in group {
            // Duplicate detection is normalized so the canonical spelling and
            // its alias collide within one group.
            let canonical = normalized_module_type(&entry.module_type)?;
            if !seen.insert(canonical.clone()) {
                anyhow::bail!("duplicate module type {canonical:?} within group {gi}");
            }
        }
        let mut parsed = Vec::new();
        for entry in group {
            parsed.push(entry.to_module()?);
        }
        groups.push(parsed);
    }
    Ok(groups)
}

/// Build the `modules` Rego policy.
///
/// Each entry emits an entry predicate and belongs to exactly one AR4SI
/// dimension: measurements gate `executables`, posture entries gate `hardware`.
/// Per group and dimension a `group_<i>_<dimension>_ok` predicate ANDs that
/// group's entries of the dimension; a dimension aggregates with OR over the
/// groups that carry entries of it. A dimension with no entries stays at its
/// affirming default, so a failing posture cannot drag down `executables` and
/// vice versa.
///
/// `hardware` is additionally gated on `tee_recognized`, the fixed platform
/// recognition baseline shared with `hardware_only`. With no posture entries,
/// `hardware := 2 if { tee_recognized }` reproduces `hardware_only`, and an
/// empty module list leaves every dimension affirming except hardware
/// recognition, exactly the `hardware_only` posture.
pub(super) fn build_modules_policy(config: &ModuleGroupsConfig) -> Result<String> {
    build_modules_policy_inner(config).map_err(|e| Error::BuiltinPolicyTemplateFailed {
        detail: format!("{e:#}"),
    })
}

fn build_modules_policy_inner(config: &ModuleGroupsConfig) -> anyhow::Result<String> {
    let groups = parse_module_groups(config)?;

    let mut helpers: Vec<String> = Vec::new();
    let mut group_dimension_rules: Vec<String> = Vec::new();
    let mut executables_rules: Vec<String> = Vec::new();
    let mut hardware_rules: Vec<String> = Vec::new();
    let mut has_executables = false;
    // Whether the policy references the pull-image repo-name extractor; defined
    // once when any container.image entry appears.
    let mut need_repo_name = false;

    for (gi, group) in groups.iter().enumerate() {
        let mut executables_preds: Vec<String> = Vec::new();
        let mut hardware_preds: Vec<String> = Vec::new();
        for (j, module) in group.iter().enumerate() {
            let pred = format!("m_{gi}_{j}");
            let body = match module {
                Module::Tdx(cfg) => {
                    let (body, extra) = tdx_posture_rule(cfg, &pred)?;
                    helpers.extend(extra);
                    body
                }
                Module::Nvidia(cfg) => nvidia_posture_rule(cfg, &pred),
                Module::Gpu => gpu_posture_rule(&pred),
                measurement => measurement_rule(measurement, &pred)?,
            };
            if matches!(module, Module::ContainerImage { .. }) {
                need_repo_name = true;
            }
            match module.dimension() {
                Dimension::Executables => executables_preds.push(pred),
                Dimension::Hardware => hardware_preds.push(pred),
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
        if !hardware_preds.is_empty() {
            group_dimension_rules.push(format!(
                "group_{gi}_hardware_ok if {{\n{}\n}}",
                indent(&hardware_preds)
            ));
            hardware_rules.push(format!(
                "hardware := 2 if {{\n\ttee_recognized\n\tgroup_{gi}_hardware_ok\n}}"
            ));
        }
    }

    // Without executable-dimension entries the dimension stays affirming;
    // requiring a measurement that was never configured would be fail-closed
    // in the wrong direction.
    let executables_default = if has_executables { 97 } else { 2 };

    // With no posture entries the hardware dimension reduces to platform
    // recognition, the `hardware_only` posture.
    if hardware_rules.is_empty() {
        hardware_rules.push("hardware := 2 if {\n\ttee_recognized\n}".to_string());
    }

    let helper_block = if helpers.is_empty() {
        String::new()
    } else {
        format!("{}\n\n", helpers.join("\n\n"))
    };
    let repo_name_block = if need_repo_name {
        // The repo tail of an image reference: last '/' segment, before any
        // ':' tag or '@' digest.
        "image_repo_name(ref) := name if {\n\tsegs := split(ref, \"/\")\n\tlast := segs[count(segs) - 1]\n\tname := split(split(last, \"@\")[0], \":\")[0]\n}\n\n".to_string()
    } else {
        String::new()
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
# entries stays affirming. `hardware` is additionally gated on the fixed TEE
# recognition baseline below. Empty module list => equivalent to hardware_only.
default configuration := 2
default file_system := 2
default hardware := 97
default executables := {executables_default}

{helper_block}{repo_name_block}{dimension_block}{executables_block}

{hardware_block}

# Fixed platform-recognition baseline, shared with hardware_only. These paths
# identify the TEE; the hardware dimension's posture entries add constraints
# on top of them.
tee_recognized if {{
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
}}

tee_recognized if {{
	input.csv.version in ["1", "2"]
}}

tee_recognized if {{
	input.tpm
}}

tee_recognized if {{
	input.system
}}
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
        // `nvidia_posture_rule`; the caller never passes them here.
        Module::Tdx(_) | Module::Nvidia(_) | Module::Gpu => {
            anyhow::bail!("posture module passed to the measurement emitter")
        }
    })
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
    use super::*;
    use crate::tee::coco::converter::builtin::converter::BuiltinCocoConverter;
    use crate::tee::coco::converter::builtin::policies::transparency_log::eval_policy_vector;
    use crate::tee::coco::converter::builtin::policy_config::{
        PolicyConfig, ReferenceValueConfig, SampleProvenancePayloadConfig,
    };
    use reference_value_provider_service::extractors::extractor_modules::sample::Provenance;
    use serde_json::json;

    // --- modules policy -----------------------------------------------------

    fn modules_cfg(json: &str) -> ModuleGroupsConfig {
        serde_json::from_str(json).expect("modules config parses")
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
            assert!(entry.to_module().is_ok(), "expected ok for {t}");
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
            assert!(entry.to_module().is_ok(), "expected ok for {t}");
        }

        // Bad value shapes.
        assert!(ModuleEntryConfig {
            module_type: "tdx.ovmf".to_string(),
            value: json!("tooshort"),
        }
        .to_module()
        .is_err());
        // uppercase hex rejected
        assert!(ModuleEntryConfig {
            module_type: "tdx.ovmf".to_string(),
            value: json!("A".repeat(96)),
        }
        .to_module()
        .is_err());
        // container.image needs sha256: prefix
        assert!(ModuleEntryConfig {
            module_type: "container.image.foo".to_string(),
            value: json!("c".repeat(64)),
        }
        .to_module()
        .is_err());
        // measurement entry with an object value is rejected
        assert!(ModuleEntryConfig {
            module_type: "tdx.ovmf".to_string(),
            value: json!({}),
        }
        .to_module()
        .is_err());

        // Unprefixed `gpu` has no alias and is rejected, as is the vendor
        // prefix on a type that is not Alibaba-coupled.
        assert!(ModuleEntryConfig {
            module_type: "gpu".to_string(),
            value: json!({}),
        }
        .to_module()
        .is_err());
        assert!(ModuleEntryConfig {
            module_type: "com.alibabacloud.tdx.ovmf".to_string(),
            value: json!(ok_hex96.clone()),
        }
        .to_module()
        .is_err());
        assert!(ModuleEntryConfig {
            module_type: "com.alibabacloud.nvidia".to_string(),
            value: json!({}),
        }
        .to_module()
        .is_err());
        // Unknown type rejected.
        assert!(ModuleEntryConfig {
            module_type: "cpu".to_string(),
            value: json!("x"),
        }
        .to_module()
        .is_err());

        // Bad name charset rejected.
        assert!(ModuleEntryConfig {
            module_type: "ai.model.ba d".to_string(),
            value: json!(ok_hex64.clone()),
        }
        .to_module()
        .is_err());
        // Posture module with wrong value type rejected.
        assert!(ModuleEntryConfig {
            module_type: "tdx".to_string(),
            value: json!("not-an-object"),
        }
        .to_module()
        .is_err());
        assert!(ModuleEntryConfig {
            module_type: "nvidia".to_string(),
            value: json!([]),
        }
        .to_module()
        .is_err());

        // Each measurement family rejects its own malformed baseline value.
        for t in ["tdx.kernel", "tdx.uki", "ai.model.Qwen/Qwen3.8-27B"] {
            assert!(
                ModuleEntryConfig {
                    module_type: t.to_string(),
                    value: json!("tooshort"),
                }
                .to_module()
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
                .to_module()
                .is_err(),
                "bad name charset must fail for {t}"
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
                .to_module()
                .is_err(),
                "non-string measurement value must fail"
            );
        }

        // tdx collateral min_tcb_date must be YYYY-MM-DD.
        assert!(ModuleEntryConfig {
            module_type: "tdx".to_string(),
            value: json!({ "collateral": { "min_tcb_date": "2026/1/2" } }),
        }
        .to_module()
        .is_err());

        // nvidia measurement_digest entries must be 96 lowercase hex chars.
        assert!(ModuleEntryConfig {
            module_type: "nvidia".to_string(),
            value: json!({ "measurement_digest": ["tooshort"] }),
        }
        .to_module()
        .is_err());

        // A present nvidia entry must require at least one GPU: min_count 0 is
        // rejected (omitting the entry is how GPU appraisal is disabled).
        let err = ModuleEntryConfig {
            module_type: "nvidia".to_string(),
            value: json!({ "min_count": 0 }),
        }
        .to_module()
        .unwrap_err()
        .to_string();
        assert!(err.contains("min_count must be at least 1"), "{err}");
        assert!(ModuleEntryConfig {
            module_type: "nvidia".to_string(),
            value: json!({ "min_count": 1 }),
        }
        .to_module()
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
        .to_module()
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
        .to_module()
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
            .to_module()
            .expect("canonical parses");
            let alias_module = ModuleEntryConfig {
                module_type: alias.to_string(),
                value: value.clone(),
            }
            .to_module()
            .expect("alias parses");
            assert_eq!(
                canonical_module, alias_module,
                "{canonical} and {alias} must parse identically"
            );

            // Both spellings must generate byte-identical rego.
            let canonical_policy =
                build_modules_policy(&ModuleGroupsConfig::Single(vec![ModuleEntryConfig {
                    module_type: canonical.to_string(),
                    value: value.clone(),
                }]))
                .expect("build canonical");
            let alias_policy =
                build_modules_policy(&ModuleGroupsConfig::Single(vec![ModuleEntryConfig {
                    module_type: alias.to_string(),
                    value,
                }]))
                .expect("build alias");
            assert_eq!(canonical_policy, alias_policy);
        }
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
        let policy = build_modules_policy(&modules_cfg(&format!(
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
        assert!(policy.contains("hardware := 2 if {\n\ttee_recognized\n\tgroup_0_hardware_ok\n}"));
        assert!(policy.contains("tee_recognized if {"));
        // tdx posture default: debug regex + eventlog count
        assert!(policy
            .contains("regex.match(\"^[0-9a-f][02468ace]\", input.tdx.quote.body.td_attributes)"));
        assert!(policy.contains("count(input.tdx.uefi_event_logs) > 0"));
    }

    #[test]
    fn modules_policy_no_executables_keeps_executables_affirming() {
        // A posture-only policy must not make the executables dimension depend
        // on the posture: there are no measurement entries to satisfy.
        let policy =
            build_modules_policy(&modules_cfg(r#"[{"type":"tdx","value":{}}]"#)).expect("build");
        assert!(policy.contains("default executables := 2"));
        assert!(!policy.contains("group_0_executables_ok"));
        // No measurement entries, so hardware reduces to recognition plus the
        // posture group.
        assert!(policy.contains("hardware := 2 if {\n\ttee_recognized\n\tgroup_0_hardware_ok\n}"));
    }

    #[test]
    fn modules_policy_no_posture_uses_tee_recognition_only() {
        let ovmf = hex96('1');
        let policy = build_modules_policy(&modules_cfg(&format!(
            r#"[{{"type":"tdx.ovmf","value":"{ovmf}"}}]"#
        )))
        .expect("build");
        assert!(!policy.contains("group_0_hardware_ok"));
        assert!(policy.contains("hardware := 2 if {\n\ttee_recognized\n}"));
        // The empty list also reduces hardware to recognition.
        let empty = build_modules_policy(&modules_cfg("[]")).expect("build");
        assert!(empty.contains("default executables := 2"));
        assert!(empty.contains("hardware := 2 if {\n\ttee_recognized\n}"));
    }

    #[test]
    fn modules_policy_rego_snapshot_groups_or() {
        let policy = build_modules_policy(&modules_cfg(
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
        let err = build_modules_policy(&modules_cfg(
            r#"[{"type":"tdx","value":{"nonce_binding":"required"}}]"#,
        ))
        .expect_err("nonce_binding must be rejected as an unknown field");
        let msg = err.to_string();
        assert!(msg.contains("nonce_binding"), "{msg}");
        assert!(msg.contains("unknown field"), "{msg}");

        // The remaining permissive fields still parse once nonce_binding is
        // gone.
        assert!(build_modules_policy(&modules_cfg(
        r#"[{"type":"tdx","value":{"debug":"allow","perfmon":"allow","service_td":"allow","sept_ve_disable":"allow","eventlog":"optional"}}]"#
    ))
    .is_ok());
    }

    #[test]
    fn modules_policy_tdx_tcb_collateral_rules() {
        let policy = build_modules_policy(&modules_cfg(
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
        let err = build_modules_policy(&modules_cfg(
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
        let policy = build_modules_policy(&cfg).expect("build modules policy");
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
    async fn modules_empty_list_equals_hardware_only() {
        // An empty module list must behave exactly like hardware_only for the
        // same evidence, not merely look similar in the generated text.
        let policy = build_modules_policy(&modules_cfg("[]")).expect("build");
        let hardware_only = include_str!("static/hardware_only.rego");

        let tdx = tdx_input(serde_json::Value::Null, &[json!({ "event": "ok" })]);
        let tdx_bad_vendor = tdx.replace(
            "939a7233f79c4ca9940a0db3957f0607",
            "00000000000000000000000000000000",
        );
        let evidence = [
            tdx,
            tdx_bad_vendor,
            json!({ "csv": { "version": "2" } }).to_string(),
            json!({ "tpm": true }).to_string(),
            json!({ "system": { "cpu": "x" } }).to_string(),
            "{}".to_string(),
        ];
        for input in evidence {
            assert_eq!(
                eval_policy_vector(&policy, &input).await,
                eval_policy_vector(hardware_only, &input).await,
                "modules [] must match hardware_only for input {input}"
            );
        }
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

        // Omitting the tdx entry imposes no posture requirement: same debug
        // input affirms like hardware_only.
        assert_eq!(
            eval_modules("[]", &debug).await,
            (2, 2, 2, 2),
            "empty modules ignores the debug bit (hardware_only equivalence)"
        );
    }

    #[tokio::test]
    async fn modules_tdx_posture_equals_hardware_only_strict_on_tdx() {
        // Both policies gate only the hardware dimension; on TDX evidence the
        // strict modules posture reproduces hardware_only_strict.
        let cfg = r#"[{"type":"tdx","value":{"sept_ve_disable":"allow","perfmon":"allow","service_td":"allow"}}]"#;
        let modules = build_modules_policy(&modules_cfg(cfg)).expect("build");
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
        .to_module()
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
            eval_modules(&cfg_pinned, &evaluated).await,
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
            eval_modules(&cfg_pinned, &wrong_driver).await,
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
    async fn modules_hardware_recognition_without_executables() {
        // With no posture entries, hardware affirms on any recognized TEE, not
        // only TDX. A measurement entry still has to pass for executables; the
        // hardware dimension must not be dragged along with it.
        let cfg = format!(r#"[{{"type":"tdx.ovmf","value":"{}"}}]"#, hex96('1'));
        let csv = json!({ "csv": { "version": "2" } }).to_string();
        assert_eq!(
            eval_modules(&cfg, &csv).await,
            (97, 2, 2, 2),
            "CSV recognition affirms hardware while the missing TDX measurement rejects executables"
        );
    }
}

//! Diagnostic rules for the `modules` policy: what the evidence actually
//! carries, the per-sub-check posture rules, and the
//! `tng.appraisal-diagnostics` extension block.

use super::{indent, iso_date_to_epoch_secs, Module, Platform};
use crate::tee::coco::converter::builtin::policy_config::{
    NvidiaPostureConfig, PrintableAscii, TcbMinStatus, TdxBit, TdxEventlog, TdxPostureConfig,
    TdxSeptVe,
};
use crate::tee::coco::diagnostics::{APPRAISAL_DIAGNOSTICS_EXTENSION, APPRAISAL_DIAGNOSTICS_KEY};
use anyhow::Context;

/// Emit the `<observed> := ...` projection rule for a measurement entry: what
/// the evidence actually carries, with no pass/fail judgement. Diagnostics
/// render it as `actual`.
pub(super) fn measurement_observed_rule(module: &Module, observed: &str) -> anyhow::Result<String> {
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
pub(super) fn measurement_diag_rules(
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
pub(super) fn transparency_log_diag_rules(pred: &str, diag: &str, dimension: &str) -> String {
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
pub(super) const NVIDIA_GPUS_HELPER: &str = r#"nvidia_gpus := [{"gpu": k, "claim": g} |
	tdx := object.get(input, "tdx", {})
	some k, g in tdx
	startswith(k, "nvidia_gpu.")
]"#;

/// The guest-reported AAEL GPU attestation events, defined once per policy when
/// a `com.alibabacloud.gpu` entry appears.
pub(super) const GPU_ATTESTATION_EVENTS_HELPER: &str = r#"gpu_attestation_events := [e |
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
    // `object.get(..., null)` keeps the GPU in the projection when a field is
    // missing; a bare `e.claim.<field>` is undefined and would drop the element.
    let mut projection = r#""gpu": e.gpu, "uuid": object.get(e.claim, "uuid", null)"#.to_string();
    if let Some(field) = field {
        projection.push_str(&format!(
            ", {field:?}: object.get(e.claim, {field:?}, null)"
        ));
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
            actual_expr: nvidia_actual(
                Some("cc_enabled"),
                r#"object.get(e.claim, "cc_enabled", null) != true"#,
            ),
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

/// Rule name of the platform recognition diagnostic. The assembler lists it in
/// the `failed_checks` collector, so the name is owned here.
pub(super) const PLATFORM_DIAG_NAME: &str = "diag_platform";

/// The platform's own diagnostic: reports evidence that does not identify the
/// platform the policy's entries are rooted at.
pub(super) fn platform_diagnostic_rule(platform: &Platform) -> String {
    let recognition = platform.recognition();
    let check = platform.check_name();
    let name = PLATFORM_DIAG_NAME;
    format!(
        r#"{name} := {{
	"dimension": "hardware",
	"check": {check:?},
	"matched": true,
}} if {{
	{recognition}
}}

{name} := {{
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
pub(super) fn failed_checks_block(diag_names: &[String]) -> String {
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

/// Render a slice of strings as a Rego array literal. The values are
/// `PrintableAscii`, so Rust's `{:?}` escaping cannot produce the `\u{...}`
/// form that regorus rejects.
fn rego_string_array(items: &[PrintableAscii]) -> String {
    let inner = items
        .iter()
        .map(|s| format!("{:?}", s.as_ref()))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{inner}]")
}

/// A rendered posture entry: its sub-check predicates, the matched/mismatch
/// diagnostic pairs, the diagnostic rule names the `failed_checks` collector
/// must list, and any helper rules the entry depends on.
pub(super) struct RenderedEntry {
    pub rules: String,
    pub diag_names: Vec<String>,
    pub helpers: Vec<String>,
}

/// Render a `tdx` posture entry as predicates, diagnostics, and helpers.
pub(super) fn tdx_entry_rules(
    cfg: &TdxPostureConfig,
    pred: &str,
    diag: &str,
    dimension: &str,
) -> anyhow::Result<RenderedEntry> {
    let (checks, helpers) = tdx_posture_rule(cfg, pred)?;
    Ok(render_entry(pred, diag, "tdx", dimension, &checks, helpers))
}

/// Render an `nvidia` posture entry as predicates and diagnostics.
pub(super) fn nvidia_entry_rules(
    cfg: &NvidiaPostureConfig,
    pred: &str,
    diag: &str,
    dimension: &str,
) -> RenderedEntry {
    render_entry(
        pred,
        diag,
        "nvidia",
        dimension,
        &nvidia_posture_rule(cfg),
        Vec::new(),
    )
}

/// Render a `com.alibabacloud.gpu` posture entry as predicates and diagnostics.
pub(super) fn gpu_entry_rules(pred: &str, diag: &str, dimension: &str) -> RenderedEntry {
    render_entry(
        pred,
        diag,
        "gpu",
        dimension,
        &gpu_posture_rule(),
        Vec::new(),
    )
}

fn render_entry(
    pred: &str,
    diag: &str,
    check_prefix: &str,
    dimension: &str,
    checks: &[PostureCheck],
    helpers: Vec<String>,
) -> RenderedEntry {
    RenderedEntry {
        diag_names: checks
            .iter()
            .map(|c| format!("{diag}_{}", c.suffix))
            .collect(),
        rules: posture_rules(pred, diag, check_prefix, dimension, checks),
        helpers,
    }
}
#[cfg(test)]
mod tests {
    use super::super::test_support::{
        build_policy, eval_modules, hex64, hex96, modules_cfg, tcb_input, tdx_input, tdx_input_full,
    };
    use super::super::{build_modules_policy_with_resolved, iso_date_to_epoch_secs};
    use super::*;
    use crate::tee::coco::converter::builtin::policies::test_support::{
        eval_policy_extensions, eval_policy_vector,
    };
    use crate::tee::coco::converter::builtin::policies::transparency_log::ResolvedRekor;
    use serde_json::json;
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
    async fn modules_diagnostics_nvidia_actual_keeps_a_gpu_with_a_missing_field() {
        // A claim without `cc_enabled` fails that posture check. The
        // projection must still identify the GPU and show the missing field as
        // null; a bare field access would be undefined and drop the element.
        let cfg = r#"[{"type":"nvidia","value":{"min_count":1}}]"#;
        let input = tdx_input_full(
            serde_json::Value::Null,
            json!({ "nvidia_gpu.0": {
                "uuid": "GPU-x", "measurement": hex96('3')
            } }),
            &[json!({ "event": "ok" })],
        );
        let failed = eval_failed_checks(cfg, &input)
            .await
            .expect("extension present");
        let checks: Vec<_> = failed.iter().map(|f| f["check"].clone()).collect();
        assert_eq!(checks, vec![json!("nvidia.cc_enabled")], "{failed:?}");
        assert_eq!(
            failed[0]["actual"],
            json!([{ "gpu": "nvidia_gpu.0", "uuid": "GPU-x", "cc_enabled": null }])
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

    /// A failing `transparency_log` entry reports a minimal diagnostic: the
    /// baseline lives in the transparency log, so there is nothing from this
    /// config to disclose as `expected`/`actual`.
    #[tokio::test]
    async fn modules_diagnostics_report_transparency_log_mismatch() {
        let cfg = modules_cfg(
            r#"[{"type":"transparency_log","value":{
                "publishedMeasurements":["tdx.td-shim"],
                "services":[{"type":"rekor-v1","logUrl":"https://rekor.example","logIndex":1}]
            }}]"#,
        );
        // A payload hash that cannot match the manifest reconstructed from the
        // input. The DSSE conjunct is never reached: the hash comparison fails
        // first.
        let resolved = ResolvedRekor {
            payload_hash: "0".repeat(64),
            dsse_signature: "unused".to_string(),
            publisher_key: "unused".to_string(),
        };
        let policy = build_modules_policy_with_resolved(&cfg, &[Some(resolved)])
            .expect("build modules policy");
        let input = tdx_input(
            json!({ "mr_td": "a".repeat(96) }),
            &[json!({ "event": "ok" })],
        );

        let extensions = eval_policy_extensions(&policy, &input)
            .await
            .expect("diagnostics extension present");
        let extension = extensions
            .as_array()
            .expect("extensions is an array")
            .iter()
            .find(|e| e["name"] == APPRAISAL_DIAGNOSTICS_EXTENSION)
            .expect("diagnostics extension present");
        let payload: serde_json::Value =
            serde_json::from_str(extension["value"].as_str().expect("json string"))
                .expect("payload parses");
        let failed = payload["failed"].as_array().expect("failed is an array");
        assert_eq!(failed.len(), 1, "{failed:?}");
        let check = &failed[0];
        assert_eq!(check["dimension"], "executables");
        assert_eq!(check["check"], "transparency_log");
        assert_eq!(check["reason"], "transparency-log-mismatch");
        assert!(check.get("matched").is_none(), "{check:?}");
        assert!(check.get("expected").is_none(), "{check:?}");
        assert!(check.get("actual").is_none(), "{check:?}");

        assert_eq!(
            eval_policy_vector(&policy, &input).await,
            (97, 2, 2, 2),
            "a failed transparency_log entry must reject executables"
        );
    }
}

//! Hardware posture entries and the Rego rules for `tdx`, `nvidia`, and
//! `com.alibabacloud.gpu`.

use super::super::super::policy_config::{
    NvidiaPostureConfig, TcbMinStatus, TdxBit, TdxEventlog, TdxPostureConfig, TdxSeptVe,
};
use super::measurement::families::is_lower_hex;
use anyhow::Context;

/// A parsed, validated hardware posture check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HardwareCheck {
    Tdx(TdxHardwareConfig),
    Nvidia(NvidiaHardwareConfig),
    /// The guest-reported AAEL GPU attestation event.
    AlibabaGpu,
}

/// A `tdx` posture entry. Every field defaults to its strict choice, so
/// `{"type":"tdx","value":{}}` appraises the full strict posture. There is no
/// total on/off switch: the entry's presence in a group imposes the posture;
/// omitting the entry imposes none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TdxHardwareConfig {
    pub(super) posture: TdxPostureConfig,
    /// The `min_tcb_date` converted to epoch seconds, filled by `prepare`.
    pub(super) min_tcb_date_epoch: Option<i64>,
}

impl TdxHardwareConfig {
    pub(super) fn parse(value: &serde_json::Value) -> anyhow::Result<Self> {
        let posture: TdxPostureConfig =
            serde_json::from_value(value.clone()).context("invalid tdx posture config")?;
        if let Some(date) = posture
            .collateral
            .as_ref()
            .and_then(|collateral| collateral.min_tcb_date.as_ref())
        {
            if iso_date_to_epoch_secs(date).is_none() {
                anyhow::bail!("tdx collateral min_tcb_date {date:?} is not YYYY-MM-DD");
            }
        }
        Ok(Self {
            posture,
            min_tcb_date_epoch: None,
        })
    }

    /// Resolve the per-entry data the renderer needs but cannot derive from a
    /// cache: the collateral date in the epoch seconds the verifier reports.
    pub(super) fn prepare(&mut self) -> anyhow::Result<()> {
        self.min_tcb_date_epoch = match self
            .posture
            .collateral
            .as_ref()
            .and_then(|collateral| collateral.min_tcb_date.as_ref())
        {
            Some(date) => Some(iso_date_to_epoch_secs(date).with_context(|| {
                format!(
                    "validated tdx collateral min_tcb_date {date:?} is not convertible to epoch seconds"
                )
            })?),
            None => None,
        };
        Ok(())
    }
}

/// An `nvidia` GPU-appraisal entry: the standard NVIDIA appraisal over the
/// evaluated per-GPU `nvidia_gpu.<i>` claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NvidiaHardwareConfig {
    pub(super) posture: NvidiaPostureConfig,
}

impl NvidiaHardwareConfig {
    pub(super) fn parse(value: &serde_json::Value) -> anyhow::Result<Self> {
        let posture: NvidiaPostureConfig =
            serde_json::from_value(value.clone()).context("invalid nvidia posture config")?;
        // `min_count` 0 would accept an empty GPU set. Omitting the entry
        // entirely is the documented way to disable GPU appraisal, so a
        // present entry must require at least one GPU.
        if posture.min_count == 0 {
            anyhow::bail!("nvidia min_count must be at least 1");
        }
        for digest in &posture.measurement_digest {
            if !is_lower_hex(digest, 96) {
                anyhow::bail!("nvidia measurement_digest entries must be 96 lowercase hex chars");
            }
        }
        Ok(Self { posture })
    }
}

/// Emit the `name if { ... }` rule for a `tdx` posture entry plus helper rules
/// for the disjunctive checks (service-TD zero, rejected advisories). Every
/// field defaults to its strict choice; a field that "allows"/"optionals" adds
/// no constraint. There is no `nonce_binding` field: the `report_data` session
/// binding is enforced unconditionally by the verifier's `runtime_data` path,
/// so it is not a policy knob and is not emitted here.
pub(super) fn tdx_posture_rule(
    hardware: &TdxHardwareConfig,
    name: &str,
) -> anyhow::Result<(String, Vec<String>)> {
    let cfg = &hardware.posture;
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
            let epoch = hardware.min_tcb_date_epoch.ok_or_else(|| {
                anyhow::anyhow!("tdx collateral min_tcb_date {date:?} was not prepared")
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
pub(super) fn gpu_posture_rule(pred: &str) -> String {
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
pub(super) fn nvidia_posture_rule(cfg: &NvidiaHardwareConfig, pred: &str) -> String {
    let cfg = &cfg.posture;
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
pub(super) fn iso_date_to_epoch_secs(date: &str) -> Option<i64> {
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

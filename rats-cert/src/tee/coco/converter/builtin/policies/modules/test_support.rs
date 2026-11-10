//! Shared fixtures for the `modules` policy tests.

use super::build_modules_policy_with_resolved;
use crate::tee::coco::converter::builtin::policies::test_support::eval_policy_vector;
use crate::tee::coco::converter::builtin::policy_config::ModuleGroupsConfig;
use serde_json::json;

/// Parse a `modules` config from its JSON shape.
pub(super) fn modules_cfg(json: &str) -> ModuleGroupsConfig {
    serde_json::from_str(json).expect("modules config parses")
}

/// Render a policy without network I/O. The tests that only inspect or
/// evaluate generated Rego use no `transparency_log` entry, so no resolved
/// rekor data is needed; the entry's own tests supply their own slots.
pub(super) fn build_policy(config: &ModuleGroupsConfig) -> anyhow::Result<String> {
    build_modules_policy_with_resolved(config, &[])
}

/// Evaluate a `modules` policy over `input`. The generated policy embeds
/// every pinned value as a literal, so no reference values are involved.
pub(super) async fn eval_modules(cfg_json: &str, input: &str) -> (i8, i8, i8, i8) {
    let cfg = modules_cfg(cfg_json);
    let policy = build_policy(&cfg).expect("build modules policy");
    eval_policy_vector(&policy, input).await
}

/// 96-char lowercase hex string made of `ch` repeated (a stand-in digest).
pub(super) fn hex96(ch: char) -> String {
    ch.to_string().repeat(96)
}
pub(super) fn hex64(ch: char) -> String {
    ch.to_string().repeat(64)
}

/// A minimal TDX claims input (recognized non-debug quote) whose event log
/// contains the given events. `body_extra` keys are merged into the quote
/// body; the default `td_attributes` keeps the SEPT #VE bit 28 set and the
/// debug/perfmon bits clear, so it satisfies the strict `tdx {}` defaults.
pub(super) fn tdx_input(body_extra: serde_json::Value, events: &[serde_json::Value]) -> String {
    tdx_input_full(body_extra, serde_json::Value::Null, events)
}

/// [`tdx_input`] plus `tdx_extra` keys merged into the `tdx` object (e.g.
/// the flat `nvidia_gpu.0` claims).
pub(super) fn tdx_input_full(
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

/// Build a TDX input carrying a synthetic `tcb_verification` claim.
pub(super) fn tcb_input(tcb: serde_json::Value) -> String {
    tdx_input_full(
        serde_json::Value::Null,
        json!({ "tcb_verification": tcb }),
        &[json!({ "event": "ok" })],
    )
}

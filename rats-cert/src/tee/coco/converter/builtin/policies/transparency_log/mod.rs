//! The `transparency_log` module entry: config validation, Rego fragments, and
//! the rekor-v1 and artifact-server service implementations.

use super::super::policy_config::{TransparencyLogEntryConfig, TransparencyServiceConfig};

pub(crate) mod artifact_server;
pub(crate) mod rekor_v1;

/// Validate one `transparency_log` module entry. Runs at policy load, before
/// any Rekor fetch or appraisal, so a malformed entry is a configuration error
/// rather than a panic downstream.
pub(super) fn validate_entry(cfg: &TransparencyLogEntryConfig) -> anyhow::Result<()> {
    let pm = cfg.published_measurements.as_slice();
    if pm.is_empty() {
        anyhow::bail!("publishedMeasurements must be non-empty");
    }
    let mut seen = std::collections::HashSet::new();
    for t in pm {
        if !matches!(
            t.as_str(),
            "tdx.td-shim" | "tdx.kernel" | "container.image.cmaas-runtime"
        ) {
            anyhow::bail!("unsupported publishedMeasurements type {t}");
        }
        if !seen.insert(t) {
            anyhow::bail!("duplicate publishedMeasurements type {t}");
        }
    }

    if cfg.services.is_empty() {
        anyhow::bail!("services must be non-empty");
    }
    let mut artifact_server = false;
    for (i, svc) in cfg.services.iter().enumerate() {
        match svc {
            TransparencyServiceConfig::ArtifactServer {
                url,
                log_services,
                publisher_public_key_pem: _,
            } => {
                artifact_server = true;
                if cfg.services.len() != 1 {
                    anyhow::bail!("artifact-server must be the only primary service");
                }
                if url.is_empty() {
                    anyhow::bail!("services[{i}] url is required");
                }
                if log_services.is_empty() {
                    anyhow::bail!("services[{i}] logServices non-empty");
                }
                let mut ls = std::collections::HashSet::new();
                for (j, s) in log_services.iter().enumerate() {
                    if s.type_ != "rekor-v1" {
                        anyhow::bail!("services[{i}].logServices[{j}] type must be rekor-v1");
                    }
                    if s.url.is_empty() {
                        anyhow::bail!("services[{i}].logServices[{j}] url required");
                    }
                    if !ls.insert((s.type_.clone(), s.url.trim_end_matches('/'))) {
                        anyhow::bail!("services[{i}].logServices[{j}] duplicate");
                    }
                }
            }
            TransparencyServiceConfig::RekorV1 {
                log_url, log_index, ..
            } => {
                if log_url.is_empty() {
                    anyhow::bail!("services[{i}] logUrl required");
                }
                if *log_index < 0 {
                    anyhow::bail!("services[{i}] logIndex must be >= 0");
                }
            }
        }
    }

    // A rekor-v1 primary is the entry's only service: it has no fallback and
    // the renderer uses `services[0]` as the primary.
    if !artifact_server && cfg.services.len() != 1 {
        anyhow::bail!("services must contain exactly one rekor-v1 service");
    }

    match (
        cfg.fallback_services.as_ref(),
        cfg.fallback_published_measurements.as_ref(),
    ) {
        (None, Some(_)) => {
            anyhow::bail!("fallbackPublishedMeasurements requires fallbackServices");
        }
        (None, None) => return Ok(()),
        (Some(fs), _) => {
            if !artifact_server {
                anyhow::bail!("fallbackServices is only supported with an artifact-server primary");
            }
            if fs.is_empty() {
                anyhow::bail!("fallbackServices must be non-empty");
            }
            for (i, svc) in fs.iter().enumerate() {
                match svc {
                    TransparencyServiceConfig::RekorV1 {
                        log_url, log_index, ..
                    } => {
                        if log_url.is_empty() {
                            anyhow::bail!("fallbackServices[{i}] logUrl required");
                        }
                        if *log_index < 0 {
                            anyhow::bail!("fallbackServices[{i}] logIndex >= 0");
                        }
                    }
                    _ => anyhow::bail!("fallbackServices[{i}] must be rekor-v1"),
                }
            }
            if let Some(fpm) = &cfg.fallback_published_measurements {
                if fpm.is_empty() {
                    anyhow::bail!("fallbackPublishedMeasurements non-empty");
                }
                let primary: std::collections::HashSet<&String> = pm.iter().collect();
                for t in fpm {
                    if !primary.contains(t) {
                        anyhow::bail!(
                            "fallbackPublishedMeasurements type {t} not in publishedMeasurements"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// The authenticated data a rekor-v1 primary contributes to an entry: the baked
/// payloadHash plus the DSSE signature and publisher key used at appraisal.
#[derive(Debug, Clone)]
pub(super) struct ResolvedRekor {
    pub payload_hash: String,
    pub dsse_signature: String,
    pub publisher_key: String,
}

/// Fetch and authenticate the rekor-v1 entry a `transparency_log` module entry
/// names, returning the data baked into its Rego. An artifact-server primary
/// resolves at appraisal time, so it contributes no resolved data.
#[cfg(feature = "crypto-rustcrypto")]
pub(super) async fn resolve_entry(
    cfg: &TransparencyLogEntryConfig,
) -> anyhow::Result<Option<ResolvedRekor>> {
    use super::super::host_fns::resolve_dsse_signature;

    let TransparencyServiceConfig::RekorV1 {
        log_url,
        log_index,
        rekor_public_key_pem,
        publisher_public_key_pem,
    } = cfg
        .services
        .first()
        .ok_or_else(|| anyhow::anyhow!("services must be non-empty"))?
    else {
        return Ok(None);
    };

    tracing::info!(
        log_url,
        log_index,
        "Loading transparency_log entry: fetching Rekor v1 entry"
    );
    let auth =
        rekor_v1::fetch_trusted_payload_hash(log_url, *log_index, rekor_public_key_pem.as_deref())
            .await?;
    // DSSE verification is mandatory: fall back to the built-in publisher key
    // when the config leaves it empty.
    let publisher_key = publisher_public_key_pem
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(artifact_server::BUILTIN_LOG_ENTRY_PUB_KEY_PEM);
    Ok(Some(ResolvedRekor {
        payload_hash: auth.payload_hash,
        dsse_signature: resolve_dsse_signature(&auth.dsse_signature)?.to_string(),
        publisher_key: publisher_key.to_string(),
    }))
}

/// Render a slice of strings as a Rego array literal.
fn rego_string_array(items: &[String]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// The shared `actual_measurement` extraction rules, emitted once when a
/// modules policy contains at least one `transparency_log` entry.
///
/// These are the transparency templates' original extraction bodies. They are
/// intentionally not shared with the modules measurement predicates yet: the
/// `tdx.kernel` rule here pins the RTMR index and the 32 MiB blob length, while
/// the modules rule does not. Unifying the two is a separate follow-up.
pub(super) fn measurement_extraction_rules() -> &'static str {
    r#"# extract the actual measurement value for a type from rego input.
# Each rule gates its digest on a canonical-format regex: td-shim/td-kernel
# require 96 lowercase hex chars; container.image.* require sha256:+64 lowercase
# hex. A value that fails the format check makes the rule undefined → the
# measurement is dropped from the reconstructed manifest → its hash mismatches
# t_<group>_<index>_payload_hash → the m_<group>_<index> entry predicate fails → reject (fail-closed).
actual_measurement("tdx.td-shim") := digest if {
    digest := input.tdx.quote.body.mr_td
    regex.match("^[0-9a-f]{96}$", digest)
}

actual_measurement("tdx.kernel") := digest if {
    some e in input.tdx.uefi_event_logs
    e.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"
    # Exact descriptor match against "td_payload". The UEFI event-log parser
    # exposes the description WITHOUT the trailing NUL (`data[1..length]`,
    # length includes the NUL byte), so the parsed `e.details.string` is
    # `"td_payload"` (10 chars). A `startswith` prefix would wrongly match
    # unrelated `td_payload_*` descriptors.
    e.details.string == "td_payload"
    e.index == 2
    some d in e.digests
    d.alg == "SHA-384"
    digest := d.digest
    regex.match("^[0-9a-f]{96}$", digest)
    # Guard (#2): fail-closed if ANY descriptor-matching td_payload event has
    # register index != 2. A td_payload descriptor-matching event must extend
    # RTMR1 (register index 2); any such event with a non-2 index is a
    # violation. Without this guard the `e2.index == 2` filter inside the
    # comprehensions below would silently exclude such an event from the
    # conflict set rather than rejecting. The set is empty iff no
    # descriptor-matching event has a non-2 index → count == 0 lets the rule
    # proceed; any bad event → count 1 → rule undefined → drop → reject
    # (fail-closed).
    bad_index_events := {1 | some eb in input.tdx.uefi_event_logs; eb.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; eb.details.string == "td_payload"; eb.index != 2}
    count(bad_index_events) == 0
    # Guard (#3): fail-closed if ANY descriptor-matching td_payload event
    # (extending RTMR1) lacks a SHA-384 digest. A td_payload event must carry a
    # 48-byte SHA-384 digest; an event with no digests (or no SHA-384 digest)
    # is a violation. Without this guard the
    # `some d2 ... d2.alg == "SHA-384"` filter inside the comprehensions below
    # would silently exclude such an event from the conflict set rather than
    # rejecting. The 96-hex regex on the extracted value already enforces
    # the 48-byte length on matching events; this guard rejects events that
    # have NO SHA-384 digest at all. Compare the distinct set of
    # descriptor-matching index-2 events (by `event` body) against the subset
    # that carries a SHA-384 digest — equal counts iff every such event has a
    # SHA-384 digest.
    td_index2_events := {ev | some e2 in input.tdx.uefi_event_logs; e2.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; e2.details.string == "td_payload"; e2.index == 2; ev := e2.event}
    td_index2_with_sha384 := {ev | some e2 in input.tdx.uefi_event_logs; e2.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; e2.details.string == "td_payload"; e2.index == 2; some d2 in e2.digests; d2.alg == "SHA-384"; ev := e2.event}
    count(td_index2_events) == count(td_index2_with_sha384)
    # Conflicting-events check across ALL td_payload descriptor+RTMR1 events.
    # A digest OR blobLength disagreement is a conflict ("conflicting
    # td_payload events") — both the digest and the blobLength must agree
    # across every matching event. Build distinct digest and blobLength sets
    # WITHOUT the 32 MiB pre-filter so a non-32 MiB td_payload event is counted
    # as a conflict rather than silently excluded. The distinct-digest set must
    # have exactly one element (all digests agree); the distinct-length set must
    # equal exactly {33554432} (all lengths agree AND the agreed length is
    # 32 MiB = 32<<20). A 32 MiB + non-32 MiB td_payload pair → length set
    # {33554432, other} → set != {33554432} → rule undefined → drop →
    # reject (fail-closed).
    matching_digests := {dg | some e2 in input.tdx.uefi_event_logs; e2.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; e2.details.string == "td_payload"; e2.index == 2; some d2 in e2.digests; d2.alg == "SHA-384"; dg := d2.digest}
    count(matching_digests) == 1
    matching_lengths := {tng.td_payload_blob_length([e2.event]) | some e2 in input.tdx.uefi_event_logs; e2.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; e2.details.string == "td_payload"; e2.index == 2; some d2 in e2.digests; d2.alg == "SHA-384"}
    matching_lengths == {33554432}
}

actual_measurement(type) := digest if {
    startswith(type, "container.image.")
    repo := replace(type, "container.image.", "")
    some e in input.tdx.uefi_event_logs
    e.details.unicode_name == "AAEL"
    e.details.data.domain == "alibabacloud.com"
    e.details.data.operation == "kangaroo/pull-image"
    image_repo_name(e.details.data.content.reference) == repo
    digest := e.details.data.content.digest
    regex.match("^sha256:[0-9a-f]{64}$", digest)
    # Explicit conflicting-events check: all AAEL kangaroo/pull-image events
    # for this repo must agree on the digest. A conflict makes the
    # distinct-digest set size > 1 → rule undefined → measurement dropped →
    # manifest mismatch → reject (fail-closed).
    matching_digests := {dg | some e2 in input.tdx.uefi_event_logs; e2.details.unicode_name == "AAEL"; e2.details.data.domain == "alibabacloud.com"; e2.details.data.operation == "kangaroo/pull-image"; image_repo_name(e2.details.data.content.reference) == repo; dg := e2.details.data.content.digest}
    count(matching_digests) == 1
    # NOTE: AAEL event-digest integrity (sha384(event) == digests[0]) is NOT
    # re-verified here. It is verified by the attestation-service event-log
    # replay (trustee CcEventLog
    # replay_and_match, which replays events against RTMRs) before claims reach
    # the policy — TNG's Rego layer trusts that replay. This is by-design
    # delegated to the AS event-log replay, not silently skipped.
}

"#
}

/// Render the Rego rules for one `transparency_log` module entry.
///
/// `pred` is the entry predicate the modules builder ANDs into its group, and
/// `prefix` namespaces every global identifier the entry defines so several
/// entries coexist in one policy. A rekor-v1 primary expects `resolved` to
/// carry the data fetched and authenticated at load; an artifact-server primary
/// resolves its manifest at appraisal time and ignores `resolved`.
pub(super) fn build_entry_rules(
    cfg: &TransparencyLogEntryConfig,
    resolved: Option<&ResolvedRekor>,
    pred: &str,
    prefix: &str,
) -> anyhow::Result<String> {
    let primary = cfg
        .services
        .first()
        .ok_or_else(|| anyhow::anyhow!("services must be non-empty"))?;
    let mut sorted_pm = cfg.published_measurements.clone();
    sorted_pm.sort();
    let pm_lit = rego_string_array(&sorted_pm);

    match primary {
        TransparencyServiceConfig::RekorV1 { .. } => {
            let resolved = resolved.ok_or_else(|| {
                anyhow::anyhow!("rekor-v1 transparency_log entry was not resolved")
            })?;
            Ok(format!(
                r#"# transparency_log entry: rekor-v1 primary, payloadHash + DSSE baked at load
{prefix}_payload_hash := {payload_hash:?}
{prefix}_schema_version := {schema_version:?}
{prefix}_published_measurements := {pm_lit}
# baked: DSSE publisher signature + trusted publisher public key
{prefix}_dsse_signature := {dsse_signature:?}
{prefix}_publisher_key := {publisher_key:?}

# reconstruct the manifest object (rego object keys serialize sorted == ASCII
# JCS; json.marshal is compact; no numbers in this shape)
{prefix}_reconstructed_manifest := {{
    "measurements": [{{"type": t, "value": actual_measurement(t)}} | some t in {prefix}_published_measurements],
    "schemaVersion": {prefix}_schema_version,
}}

# The transparency-log manifest check and the mandatory DSSE publisher
# binding. Any mismatch leaves the entry predicate undefined (fail-closed).
{pred} if {{
    tng.sha256(json.marshal({prefix}_reconstructed_manifest)) == {prefix}_payload_hash
    tng.verify_dsse_signature([json.marshal({prefix}_reconstructed_manifest), {prefix}_dsse_signature, {prefix}_publisher_key]) == true
}}

"#,
                prefix = prefix,
                payload_hash = resolved.payload_hash,
                schema_version = cfg.schema_version,
                pm_lit = pm_lit,
                dsse_signature = resolved.dsse_signature,
                publisher_key = resolved.publisher_key,
                pred = pred,
            ))
        }
        TransparencyServiceConfig::ArtifactServer {
            url,
            log_services,
            publisher_public_key_pem,
        } => {
            let url_lit = serde_json::to_string(url)?;
            let ls_lit = serde_json::to_string(log_services)?;
            // Bake the configured publisher key, or empty string when none is
            // set; the host-await treats empty as "use the built-in publisher
            // key", so baking "" preserves the default path.
            let publisher_key_lit = serde_json::to_string(
                publisher_public_key_pem
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(""),
            )?;

            let (fallback_lit, fallback_rules) = match (
                &cfg.fallback_published_measurements,
                &cfg.fallback_services,
            ) {
                (Some(fpm), Some(fs)) => {
                    let (log_url, log_index) = match fs.first() {
                        Some(TransparencyServiceConfig::RekorV1 {
                            log_url, log_index, ..
                        }) => (log_url, *log_index),
                        Some(_) => {
                            anyhow::bail!("fallbackServices must contain only rekor-v1 services")
                        }
                        None => anyhow::bail!("fallbackServices is empty"),
                    };
                    let mut fpm_sorted = fpm.clone();
                    fpm_sorted.sort();
                    let fpm_lit = rego_string_array(&fpm_sorted);
                    (
                        format!(
                            "\n{prefix}_fallback_published_measurements := {fpm_lit}\n\
                                 {prefix}_fallback_log_url := {log_url:?}\n\
                                 {prefix}_fallback_log_index := {log_index}\n"
                        ),
                        format!(
                            r#"
{prefix}_fallback_manifest := {{"measurements": [{{"type": t, "value": actual_measurement(t)}} | some t in {prefix}_fallback_published_measurements], "schemaVersion": {prefix}_schema_version}}
{pred} if {{
    {prefix}_primary_status == "fail"
    tng.fetch_rekor_on_demand([{prefix}_fallback_log_url, {prefix}_fallback_log_index, json.marshal({prefix}_fallback_manifest), {prefix}_publisher_key]) == true
}}
"#
                        ),
                    )
                }
                _ => (String::new(), String::new()),
            };

            Ok(format!(
                r#"# transparency_log entry: artifact-server primary, resolved at appraisal
{prefix}_schema_version := {schema_version:?}
{prefix}_published_measurements := {pm_lit}
{prefix}_artifact_server_url := {url_lit}
{prefix}_log_services := {ls_lit}
# baked: configured publisher key PEM (empty string → host-await uses the
# built-in publisher key baseline)
{prefix}_publisher_key := {publisher_key_lit}{fallback_lit}

{prefix}_full_manifest := {{
    "measurements": [{{"type": t, "value": actual_measurement(t)}} | some t in {prefix}_published_measurements],
    "schemaVersion": {prefix}_schema_version,
}}

{prefix}_primary_status := tng.resolve_artifact_server([{prefix}_artifact_server_url, json.marshal({prefix}_full_manifest), json.marshal({prefix}_log_services), {prefix}_publisher_key])
{pred} if {{ {prefix}_primary_status == "ok" }}
{fallback_rules}"#,
                prefix = prefix,
                schema_version = cfg.schema_version,
                pm_lit = pm_lit,
                url_lit = url_lit,
                ls_lit = ls_lit,
                publisher_key_lit = publisher_key_lit,
                fallback_lit = fallback_lit,
                fallback_rules = fallback_rules,
                pred = pred,
            ))
        }
    }
}

/// Evaluate a bundled rego policy against `input` and return the four AR4SI
/// trust-vector values as (executables, hardware, configuration, file_system).
#[cfg(test)]
pub(crate) async fn eval_policy_vector(policy: &str, input: &str) -> (i8, i8, i8, i8) {
    eval_policy_vector_with_rvs(policy, input, &[]).await
}

/// Same as [`eval_policy_vector`], but first registers each `(name, value)`
/// pair as a sample reference value in the in-memory RVPS so policies that
/// call `query_reference_value` resolve against real data.
#[cfg(test)]
pub(crate) async fn eval_policy_vector_with_rvs(
    policy: &str,
    input: &str,
    rvs: &[(&str, &str)],
) -> (i8, i8, i8, i8) {
    // The four rules our templates define. The real AS also queries four more
    // AR4SI claims (instance-identity, runtime-opaque, ...); those are simply
    // skipped when a policy leaves them undefined, so they need not be queried.
    let rules = vec![
        "executables".to_string(),
        "hardware".to_string(),
        "configuration".to_string(),
        "file_system".to_string(),
    ];
    let result = eval_policy_rules_with_rvs(policy, input, rvs, rules).await;
    let get = |name: &str| -> i8 {
        result
            .get(name)
            .and_then(|v| v.as_i64())
            .and_then(|n| i8::try_from(n).ok())
            .unwrap_or_else(|| panic!("policy did not produce a value for {name}"))
    };
    (
        get("executables"),
        get("hardware"),
        get("configuration"),
        get("file_system"),
    )
}

/// Evaluate `data.policy.extensions` for `policy` over `input`. Returns `None`
/// when the policy defines no `extensions` rule or the rule is undefined,
/// which is how a successful appraisal leaves the token unchanged.
#[cfg(test)]
pub(crate) async fn eval_policy_extensions(policy: &str, input: &str) -> Option<serde_json::Value> {
    let value = eval_policy_rules_with_rvs(policy, input, &[], vec!["extensions".to_string()])
        .await
        .remove("extensions")?;
    // An undefined complete rule reaches the rule map as regorus's undefined
    // sentinel rather than being omitted.
    if value == serde_json::Value::String("<undefined>".to_string()) {
        return None;
    }
    Some(value)
}

/// Evaluate the named `data.policy.*` rules over `input`, with each `(name,
/// value)` pair registered as a sample reference value first.
#[cfg(test)]
async fn eval_policy_rules_with_rvs(
    policy: &str,
    input: &str,
    rvs: &[(&str, &str)],
    rules: Vec<String>,
) -> std::collections::HashMap<String, serde_json::Value> {
    use attestation_service::policy_engine::PolicyEngine as _;
    use attestation_service::rvps::RvpsApi as _;
    use base64::Engine as _;
    use std::sync::Arc;

    let rvps = attestation_service::rvps::builtin::BuiltinRvps::new(
        reference_value_provider_service::config::Config {
            storage_backend: None,
            storage:
                reference_value_provider_service::storage::ReferenceValueStorageConfig::InMemory(
                    reference_value_provider_service::storage::in_memory::Config {},
                ),
        },
    )
    .expect("create in-memory RVPS for policy test");
    for (name, value) in rvs {
        let provenance = serde_json::json!({ *name: [ *value ] });
        let payload_b64 = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&provenance).expect("serialize provenance"));
        let message = serde_json::json!({
            "version": "0.1.0",
            "type": "sample",
            "payload": payload_b64,
        })
        .to_string();
        rvps.verify_and_extract(&message)
            .await
            .expect("register sample reference value");
    }

    let engine = attestation_service::policy_engine::opa::OPAInMemory::with_raw_default_policy(
        policy,
        super::super::DEFAULT_POLICY_ID,
        // The artifact-server address is only consumed under
        // attestation-service's `policy-artifact-server` feature (not
        // enabled for these tests), so this value has no effect here.
        // Pass trustee's own default to mirror upstream usage.
        attestation_service::config::DEFAULT_ARTIFACT_SERVER_ADDRESS,
    )
    .expect("create OPA in-memory engine")
    // Inject `tng.sha256` so the transparency-log rego policy's
    // `tng.sha256(json.marshal(manifest))` call resolves to a real
    // sha256 during the behavior test below. Under `crypto-rustcrypto`,
    // `tng.verify_dsse_signature` is injected too; see
    // `builtin_as_host_await_functions`.
    .with_extra_extension_functions(
        crate::tee::coco::converter::builtin::host_fns::builtin_as_host_await_functions(),
    );
    // The upstream `PolicyEngine::evaluate` resolves Rego
    // `query_reference_value(...)` calls through a `ReferenceValueResolver`
    // (backed by the `RvpsApi` implementor above, preloaded with the test's
    // sample reference values).
    let resolver = Arc::new(attestation_service::rvps::ReferenceValueResolver::new(
        Arc::new(rvps) as Arc<dyn attestation_service::rvps::RvpsApi>,
    ));
    engine
        .evaluate(input, super::super::DEFAULT_POLICY_ID, rules, resolver)
        .await
        .expect("evaluate policy")
        .rules_result
}

#[cfg(test)]
mod tests {
    use super::super::load_policy;
    use super::super::modules::{build_modules_policy_with_resolved, parse_module_groups, Module};
    use super::*;
    use crate::crypto::HashAlgo;
    use crate::tee::coco::converter::builtin::converter::BuiltinCocoConverter;
    use crate::tee::coco::converter::builtin::host_fns::{dsse_pae, DSSE_PAYLOAD_TYPE};
    use crate::tee::coco::converter::builtin::policy_config::{
        ArtifactLogService, ModuleGroupsConfig, PolicyConfig, ReferenceValueConfig,
        SampleProvenancePayloadConfig, TransparencyServiceConfig,
    };
    use crate::tee::coco::evidence::{tee_from_str, CocoEvidence};
    use crate::tee::{GenericConverter, GenericVerifier, ReportData};
    use anyhow::Result;
    use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    use reference_value_provider_service::extractors::extractor_modules::sample::Provenance;
    use serde_json::{json, Value};
    use serial_test::serial;
    use sha2::Digest;

    const TDX_VENDOR_ID: &str = "939a7233f79c4ca9940a0db3957f0607";

    // --- helpers -----------------------------------------------------------

    fn hex96(ch: char) -> String {
        ch.to_string().repeat(96)
    }

    fn hex64(ch: char) -> String {
        ch.to_string().repeat(64)
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = sha2::Sha256::new();
        sha2::Digest::update(&mut h, bytes);
        hex::encode(sha2::Digest::finalize(h))
    }

    /// Canonical (RFC 8785 JCS) JSON, the form `json.marshal` produces and the
    /// form the publisher signs over.
    fn jcs_compact(value: &Value) -> String {
        rekor_v1::canonical_json(value).expect("canonical JSON serialize")
    }

    fn manifest(schema: &str, measurements: &[(&str, &str)]) -> Value {
        let measurements: Vec<Value> = measurements
            .iter()
            .map(|(t, v)| json!({"type": t, "value": v}))
            .collect();
        json!({"schemaVersion": schema, "measurements": measurements})
    }

    fn transparency_entry(value: Value) -> Value {
        json!({"type": "transparency_log", "value": value})
    }

    fn rekor_entry_value(published_measurements: &[&str], log_index: i64) -> Value {
        json!({
            "publishedMeasurements": published_measurements,
            "schemaVersion": "1.0.0",
            "services": [{
                "type": "rekor-v1",
                "logUrl": "https://rekor.example.com",
                "logIndex": log_index,
            }],
        })
    }

    fn artifact_entry_value(
        artifact_url: &str,
        log_url: &str,
        fallback: Option<(&str, i64)>,
    ) -> Value {
        let mut value = json!({
            "publishedMeasurements": ["container.image.cmaas-runtime"],
            "schemaVersion": "1.0.0",
            "services": [{
                "type": "artifact-server",
                "url": artifact_url,
                "logServices": [{"type": "rekor-v1", "url": log_url}],
            }],
        });
        if let Some((fallback_url, fallback_index)) = fallback {
            value["fallbackPublishedMeasurements"] = json!(["container.image.cmaas-runtime"]);
            value["fallbackServices"] = json!([{
                "type": "rekor-v1",
                "logUrl": fallback_url,
                "logIndex": fallback_index,
            }]);
        }
        value
    }

    /// Render a modules policy from an entries JSON value and already-resolved
    /// rekor data (one slot per transparency entry, in flatten order).
    fn render(entries: Value, resolved: &[Option<ResolvedRekor>]) -> String {
        let cfg: ModuleGroupsConfig =
            serde_json::from_value(entries).expect("modules config parses");
        build_modules_policy_with_resolved(&cfg, resolved).expect("render modules policy")
    }

    fn render_rekor(published_measurements: &[&str], resolved: &ResolvedRekor) -> String {
        render(
            json!([transparency_entry(rekor_entry_value(
                published_measurements,
                1
            ))]),
            &[Some(resolved.clone())],
        )
    }

    /// Build the resolved rekor data for a manifest: its JCS payload hash and a
    /// DSSE signature bound to the test publisher key.
    #[cfg(feature = "crypto-rustcrypto")]
    fn resolved_from_manifest(manifest: &Value) -> ResolvedRekor {
        let payload_hash = sha256_hex(jcs_compact(manifest).as_bytes());
        let (dsse_signature, publisher_key) = sign_dsse_for_manifest(manifest);
        ResolvedRekor {
            payload_hash,
            dsse_signature,
            publisher_key,
        }
    }

    /// A TDX appraisal input. `mr_td` is included only when given;
    /// `td_attributes` defaults to the non-debug value used throughout these
    /// tests.
    fn tdx_quote_input(mr_td: Option<&str>, td_attributes: &str, events: &[Value]) -> String {
        let mut body = json!({"td_attributes": td_attributes});
        if let Some(mr_td) = mr_td {
            body["mr_td"] = json!(mr_td);
        }
        json!({
            "tdx": {
                "quote": {
                    "header": {"tee_type": "81000000", "vendor_id": TDX_VENDOR_ID},
                    "body": body,
                },
                "uefi_event_logs": events,
            }
        })
        .to_string()
    }

    fn tdx_input(events: &[Value]) -> String {
        tdx_quote_input(None, "0000001000000000", events)
    }

    fn aael_event(digest: &str) -> Value {
        json!({
            "type_name": "EV_EVENT_TAG",
            "details": {
                "unicode_name": "AAEL",
                "data": {
                    "domain": "alibabacloud.com",
                    "operation": "kangaroo/pull-image",
                    "content": {
                        "reference": "registry.example.com/ns/cmaas-runtime:latest",
                        "digest": digest,
                    },
                },
            },
        })
    }

    fn td_payload_event(event_b64: &str, digest: &str, index: i64) -> Value {
        json!({
            "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
            "details": {"string": "td_payload"},
            "event": event_b64,
            "digests": [{"alg": "SHA-384", "digest": digest}],
            "index": index,
        })
    }

    // --- bundled templates --------------------------------------------------

    #[tokio::test]
    async fn test_rego_hardware_only_recognizes_known_tees() {
        let policy = include_str!("../static/hardware_only.rego");

        // TDX with the canonical Intel quoting-enclave vendor_id -> all affirming.
        let tdx = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}}}}"#;
        assert_eq!(eval_policy_vector(policy, tdx).await, (2, 2, 2, 2));

        // Hygon CSV v2.
        let csv = r#"{"csv":{"version":"2"}}"#;
        assert_eq!(eval_policy_vector(policy, csv).await, (2, 2, 2, 2));

        // TPM and generic SYSTEM attesters.
        let tpm = r#"{"tpm":{"firmware_version":"1.0"}}"#;
        assert_eq!(eval_policy_vector(policy, tpm).await, (2, 2, 2, 2));
        let system = r#"{"system":{}}"#;
        assert_eq!(eval_policy_vector(policy, system).await, (2, 2, 2, 2));
    }

    #[tokio::test]
    async fn test_rego_hardware_only_rejects_unrecognized_hardware() {
        let policy = include_str!("../static/hardware_only.rego");

        // A valid TDX tee_type but a WRONG vendor_id: hardware must stay at its
        // "unrecognized" default (97 -> Contraindicated), while the other three
        // dimensions remain affirming. This pins the exact canonical vendor_id.
        let tdx_bad_vendor = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}}}"#;
        assert_eq!(
            eval_policy_vector(policy, tdx_bad_vendor).await,
            (2, 97, 2, 2)
        );

        // No TEE evidence at all -> hardware stays unrecognized.
        assert_eq!(eval_policy_vector(policy, "{}").await, (2, 97, 2, 2));
    }

    #[tokio::test]
    async fn test_rego_hardware_only_strict_requires_non_debug_tdx_eventlog() {
        let policy = include_str!("../static/hardware_only_strict.rego");

        let valid_tdx = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"},"body":{"td_attributes":"0000001000000080"}},"uefi_event_logs":[{"event":"ok"}]}}"#;
        assert_eq!(eval_policy_vector(policy, valid_tdx).await, (2, 2, 2, 2));

        let debug_tdx = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"},"body":{"td_attributes":"0100001000000080"}},"uefi_event_logs":[{"event":"ok"}]}}"#;
        assert_eq!(eval_policy_vector(policy, debug_tdx).await, (2, 97, 2, 2));

        let missing_eventlog = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"},"body":{"td_attributes":"0000001000000080"}}}}"#;
        assert_eq!(
            eval_policy_vector(policy, missing_eventlog).await,
            (2, 97, 2, 2)
        );
    }

    #[tokio::test]
    async fn test_rego_trust_all_affirms_everything() {
        let policy = include_str!("../static/trust_all.rego");

        // trust_all affirms every dimension regardless of input, even with no
        // TEE evidence and an unrecognized vendor_id.
        assert_eq!(eval_policy_vector(policy, "{}").await, (2, 2, 2, 2));
        let bad_tdx =
            r#"{"tdx":{"quote":{"header":{"tee_type":"00000000","vendor_id":"deadbeef"}}}}"#;
        assert_eq!(eval_policy_vector(policy, bad_tdx).await, (2, 2, 2, 2));
    }

    // --- entry parsing and validation --------------------------------------

    #[test]
    fn transparency_log_entry_parses_flat_and_nested() {
        let value = rekor_entry_value(&["tdx.td-shim"], 7);

        // Flat list: one group.
        let flat: ModuleGroupsConfig =
            serde_json::from_value(json!([transparency_entry(value.clone())])).expect("parse");
        let groups = parse_module_groups(&flat).expect("validate");
        assert_eq!(groups.len(), 1);
        match &groups[0][0] {
            Module::TransparencyLog(cfg) => {
                assert_eq!(cfg.published_measurements, vec!["tdx.td-shim".to_string()]);
                assert_eq!(cfg.schema_version, "1.0.0");
                assert_eq!(cfg.services.len(), 1);
                match &cfg.services[0] {
                    TransparencyServiceConfig::RekorV1 {
                        log_url, log_index, ..
                    } => {
                        assert_eq!(log_url, "https://rekor.example.com");
                        assert_eq!(*log_index, 7);
                    }
                    other => panic!("expected RekorV1, got {other:?}"),
                }
            }
            other => panic!("expected TransparencyLog, got {other:?}"),
        }

        // Nested list: one transparency entry per group.
        let nested: ModuleGroupsConfig = serde_json::from_value(json!([
            [transparency_entry(value.clone())],
            [transparency_entry(rekor_entry_value(&["tdx.kernel"], 8))],
        ]))
        .expect("parse");
        let groups = parse_module_groups(&nested).expect("validate");
        assert_eq!(groups.len(), 2);
        assert!(matches!(groups[0][0], Module::TransparencyLog(_)));
        assert!(matches!(groups[1][0], Module::TransparencyLog(_)));
    }

    #[test]
    fn transparency_log_entry_defaults_and_publisher_key() {
        // `schemaVersion` defaults to 1.0.0; an optional publisher key parses.
        let value = json!({
            "publishedMeasurements": ["container.image.cmaas-runtime"],
            "services": [{
                "type": "rekor-v1",
                "logUrl": "https://rekor.example.com",
                "logIndex": 1,
                "publisherPublicKeyPem": "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
            }],
        });
        let cfg: ModuleGroupsConfig =
            serde_json::from_value(json!([transparency_entry(value)])).expect("parse");
        let groups = parse_module_groups(&cfg).expect("validate");
        let Module::TransparencyLog(entry) = &groups[0][0] else {
            panic!("expected TransparencyLog");
        };
        assert_eq!(entry.schema_version, "1.0.0");
        assert!(matches!(
            &entry.services[0],
            TransparencyServiceConfig::RekorV1 {
                publisher_public_key_pem: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn transparency_log_entry_validation_rejects() {
        fn entry_error(value: Value) -> String {
            let cfg: ModuleGroupsConfig =
                serde_json::from_value(json!([transparency_entry(value)])).expect("modules parse");
            format!("{:#}", parse_module_groups(&cfg).unwrap_err())
        }

        let rekor = json!({"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1});
        let artifact = json!({
            "type": "artifact-server",
            "url": "https://as",
            "logServices": [{"type": "rekor-v1", "url": "https://r"}],
        });

        // Value shape.
        assert!(entry_error(json!("not-an-object")).contains("expects an object value"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [rekor.clone()],
            "bogus": true,
        }))
        .contains("unknown field"));
        assert!(entry_error(json!({"services": [rekor.clone()]}))
            .contains("missing field `publishedMeasurements`"));

        // publishedMeasurements.
        assert!(
            entry_error(json!({"publishedMeasurements": [], "services": [rekor]}))
                .contains("publishedMeasurements must be non-empty")
        );
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.uki"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
        }))
        .contains("unsupported publishedMeasurements type"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim", "tdx.td-shim"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
        }))
        .contains("duplicate publishedMeasurements type"));

        // services.
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [],
        }))
        .contains("services must be non-empty"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [
                {"type": "artifact-server", "url": "https://as",
                 "logServices": [{"type": "rekor-v1", "url": "https://r"}]},
                {"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1},
            ],
        }))
        .contains("artifact-server must be the only primary service"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [
                {"type": "rekor-v1", "logUrl": "https://r1", "logIndex": 1},
                {"type": "rekor-v1", "logUrl": "https://r2", "logIndex": 2},
            ],
        }))
        .contains("exactly one rekor-v1 service"));

        // artifact-server field constraints.
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
        }))
        .contains("url is required"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as", "logServices": []}],
        }))
        .contains("logServices non-empty"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v2", "url": "https://r"}]}],
        }))
        .contains("type must be rekor-v1"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": ""}]}],
        }))
        .contains("url required"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [
                              {"type": "rekor-v1", "url": "https://r"},
                              {"type": "rekor-v1", "url": "https://r/"},
                          ]}],
        }))
        .contains("duplicate"));

        // rekor-v1 field constraints.
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "rekor-v1", "logUrl": "", "logIndex": 1}],
        }))
        .contains("logUrl required"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": -1}],
        }))
        .contains("logIndex must be >= 0"));

        // fallback pairing.
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        }))
        .contains("fallbackPublishedMeasurements requires fallbackServices"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 2}],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        }))
        .contains("only supported with an artifact-server primary"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [artifact.clone()],
            "fallbackServices": [],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        }))
        .contains("fallbackServices must be non-empty"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [
                {"type": "artifact-server", "url": "https://as2",
                 "logServices": [{"type": "rekor-v1", "url": "https://r2"}]},
            ],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        }))
        .contains("must be rekor-v1"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
            "fallbackPublishedMeasurements": ["tdx.kernel"],
        }))
        .contains("not in publishedMeasurements"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "", "logIndex": 1}],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        }))
        .contains("fallbackServices[0] logUrl required"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": -1}],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        }))
        .contains("fallbackServices[0] logIndex >= 0"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
            "fallbackPublishedMeasurements": [],
        }))
        .contains("fallbackPublishedMeasurements non-empty"));
    }

    // --- Rego shape --------------------------------------------------------

    #[test]
    fn transparency_log_shared_rules_emitted_once() {
        let resolved = [
            Some(ResolvedRekor {
                payload_hash: "00".repeat(32),
                dsse_signature: "sig-a".to_string(),
                publisher_key: "key-a".to_string(),
            }),
            Some(ResolvedRekor {
                payload_hash: "11".repeat(32),
                dsse_signature: "sig-b".to_string(),
                publisher_key: "key-b".to_string(),
            }),
        ];
        let policy = render(
            json!([
                transparency_entry(rekor_entry_value(&["tdx.td-shim"], 1)),
                transparency_entry(rekor_entry_value(&["tdx.kernel"], 2)),
            ]),
            &resolved,
        );

        // Per-entry prefixes keep the two entries' baked data apart.
        assert!(policy.contains("t_0_0_payload_hash := "), "{policy}");
        assert!(policy.contains("t_0_1_payload_hash := "), "{policy}");
        assert!(policy.contains("t_0_0_reconstructed_manifest"), "{policy}");
        assert!(policy.contains("t_0_1_reconstructed_manifest"), "{policy}");
        assert!(policy.contains("m_0_0 if {"), "{policy}");
        assert!(policy.contains("m_0_1 if {"), "{policy}");

        // The shared measurement extraction and its repo-name helper are
        // emitted once for the whole policy.
        assert_eq!(
            policy
                .matches("actual_measurement(\"tdx.td-shim\")")
                .count(),
            1
        );
        assert_eq!(
            policy.matches("actual_measurement(\"tdx.kernel\")").count(),
            1
        );
        assert_eq!(policy.matches("image_repo_name(ref) :=").count(), 1);
        assert!(!policy.contains("query_reference_value"));

        // Both predicates AND into the group's executables dimension, which is
        // non-affirming by default.
        assert!(policy.contains("default executables := 97"));
        assert!(policy.contains("group_0_executables_ok if {\n\tm_0_0\n\tm_0_1\n}"));
        assert!(policy.contains("executables := 2 if {\n\tgroup_0_executables_ok\n}"));

        // Transparency gates only executables; hardware is recognition only.
        assert!(!policy.contains("group_0_hardware_ok"));
        assert!(policy.contains("hardware := 2 if {\n\ttdx_recognized\n}"));
    }

    #[test]
    fn transparency_log_artifact_server_rego() {
        let policy = render(
            json!([transparency_entry(artifact_entry_value(
                "https://attest.example.com",
                "https://rekor.sigstore.dev",
                Some(("https://fallback.example.com", 42)),
            ))]),
            &[None],
        );

        assert!(policy.contains("tng.resolve_artifact_server"), "{policy}");
        assert!(policy.contains("tng.fetch_rekor_on_demand"), "{policy}");
        assert!(
            policy.contains("\"https://attest.example.com\""),
            "{policy}"
        );
        assert!(
            policy.contains("t_0_0_primary_status := tng.resolve_artifact_server"),
            "{policy}"
        );
        assert!(
            policy.contains("m_0_0 if { t_0_0_primary_status == \"ok\" }"),
            "{policy}"
        );
        assert!(
            policy.contains("t_0_0_primary_status == \"fail\""),
            "{policy}"
        );
        assert!(policy.contains("t_0_0_fallback_manifest"), "{policy}");
        // The artifact-server primary bakes no payloadHash.
        assert!(!policy.contains("payload_hash :="), "{policy}");

        // Without a fallback, no fallback rules are emitted.
        let no_fallback = render(
            json!([transparency_entry(artifact_entry_value(
                "https://attest.example.com",
                "https://rekor.sigstore.dev",
                None,
            ))]),
            &[None],
        );
        assert!(!no_fallback.contains("t_0_0_fallback"), "{no_fallback}");
        assert!(
            !no_fallback.contains("fetch_rekor_on_demand"),
            "{no_fallback}"
        );
        assert!(
            no_fallback.contains("m_0_0 if { t_0_0_primary_status == \"ok\" }"),
            "{no_fallback}"
        );
    }

    // --- repeat semantics ---------------------------------------------------

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_repeats_and_within_group_or_across_groups() {
        let mr_td = hex96('a');
        let digest = format!("sha256:{}", hex64('b'));
        let manifest_a = manifest("1.0.0", &[("tdx.td-shim", mr_td.as_str())]);
        let manifest_b = manifest(
            "1.0.0",
            &[("container.image.cmaas-runtime", digest.as_str())],
        );
        let resolved = [
            Some(resolved_from_manifest(&manifest_a)),
            Some(resolved_from_manifest(&manifest_b)),
        ];
        let entry_a = transparency_entry(rekor_entry_value(&["tdx.td-shim"], 1));
        let entry_b = transparency_entry(rekor_entry_value(&["container.image.cmaas-runtime"], 2));

        let same_group = render(json!([entry_a.clone(), entry_b.clone()]), &resolved);
        let cross_group = render(json!([[entry_a], [entry_b]]), &resolved);

        let both = tdx_quote_input(
            Some(mr_td.as_str()),
            "0000001000000000",
            &[aael_event(&digest)],
        );
        let only_a = tdx_quote_input(Some(mr_td.as_str()), "0000001000000000", &[]);
        let only_b = tdx_quote_input(
            Some(&hex96('9')),
            "0000001000000000",
            &[aael_event(&digest)],
        );
        let none = tdx_quote_input(Some(&hex96('9')), "0000001000000000", &[]);

        // Same group: every transparency entry must verify (AND).
        assert_eq!(
            eval_policy_vector(&same_group, &both).await,
            (2, 2, 2, 2),
            "both log-anchored baselines matching must affirm"
        );
        assert_eq!(
            eval_policy_vector(&same_group, &only_a).await,
            (97, 2, 2, 2),
            "one of two same-group baselines failing must reject (AND)"
        );
        assert_eq!(
            eval_policy_vector(&same_group, &only_b).await,
            (97, 2, 2, 2),
            "one of two same-group baselines failing must reject (AND)"
        );

        // Separate groups: either baseline is acceptable (OR).
        assert_eq!(
            eval_policy_vector(&cross_group, &only_a).await,
            (2, 2, 2, 2),
            "either cross-group baseline matching must affirm"
        );
        assert_eq!(
            eval_policy_vector(&cross_group, &only_b).await,
            (2, 2, 2, 2),
            "either cross-group baseline matching must affirm"
        );
        assert_eq!(
            eval_policy_vector(&cross_group, &none).await,
            (97, 2, 2, 2),
            "no cross-group baseline matching must reject"
        );
    }

    // --- rekor-v1 behavior (injected resolved data) ------------------------

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_matching_and_mismatch() {
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let logged = manifest("1.0.0", &[("container.image.cmaas-runtime", digest)]);
        let resolved = resolved_from_manifest(&logged);
        let policy = render_rekor(&["container.image.cmaas-runtime"], &resolved);

        let ok = tdx_input(&[aael_event(digest)]);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "matching measurements must affirm"
        );

        let tampered = ok.replace(
            digest,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(
            eval_policy_vector(&policy, &tampered).await,
            (97, 2, 2, 2),
            "tampered digest must reject executables"
        );

        let wrong_repo = ok.replace("cmaas-runtime", "other-runtime");
        assert_eq!(
            eval_policy_vector(&policy, &wrong_repo).await,
            (97, 2, 2, 2),
            "wrong repo must reject executables"
        );

        let no_aael = tdx_input(&[]);
        assert_eq!(
            eval_policy_vector(&policy, &no_aael).await,
            (97, 2, 2, 2),
            "missing AAEL event must reject executables (fail-closed)"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_rejects_wrong_schema_version() {
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let ok = tdx_input(&[aael_event(digest)]);

        // Correct schema version -> affirm.
        let correct = manifest("1.0.0", &[("container.image.cmaas-runtime", digest)]);
        let policy = render_rekor(
            &["container.image.cmaas-runtime"],
            &resolved_from_manifest(&correct),
        );
        assert_eq!(eval_policy_vector(&policy, &ok).await, (2, 2, 2, 2));

        // The logged manifest carries "9.9.9" while the entry config bakes
        // "1.0.0": the reconstruction differs -> reject.
        let wrong = manifest("9.9.9", &[("container.image.cmaas-runtime", digest)]);
        let policy = render_rekor(
            &["container.image.cmaas-runtime"],
            &resolved_from_manifest(&wrong),
        );
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (97, 2, 2, 2),
            "mismatched schemaVersion must reject executables"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_rejects_wrong_payload_hash() {
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let logged = manifest("1.0.0", &[("container.image.cmaas-runtime", digest)]);
        let ok = tdx_input(&[aael_event(digest)]);

        let policy = render_rekor(
            &["container.image.cmaas-runtime"],
            &resolved_from_manifest(&logged),
        );
        assert_eq!(eval_policy_vector(&policy, &ok).await, (2, 2, 2, 2));

        let mut wrong = resolved_from_manifest(&logged);
        wrong.payload_hash = "00".repeat(32);
        let policy = render_rekor(&["container.image.cmaas-runtime"], &wrong);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (97, 2, 2, 2),
            "wrong payloadHash must reject executables"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_sorts_published_measurements_by_type() {
        let cmaas_digest =
            "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let mr_td = "321ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";
        // The type-sorted manifest (the publisher's canonical form): the
        // runtime type sorts before td-shim (c < t).
        let logged = manifest(
            "1.0.0",
            &[
                ("container.image.cmaas-runtime", cmaas_digest),
                ("tdx.td-shim", mr_td),
            ],
        );
        let resolved = resolved_from_manifest(&logged);
        let ok = tdx_quote_input(Some(mr_td), "0000001000000000", &[aael_event(cmaas_digest)]);

        for order in [
            ["container.image.cmaas-runtime", "tdx.td-shim"],
            ["tdx.td-shim", "container.image.cmaas-runtime"],
        ] {
            let policy = render_rekor(&order, &resolved);
            assert_eq!(
                eval_policy_vector(&policy, &ok).await,
                (2, 2, 2, 2),
                "measurement order {order:?} must affirm (types are sorted before hashing)"
            );
        }

        let mut wrong = resolved.clone();
        wrong.payload_hash = "00".repeat(32);
        let policy = render_rekor(&["container.image.cmaas-runtime", "tdx.td-shim"], &wrong);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (97, 2, 2, 2),
            "wrong payloadHash must reject even when the order is sorted"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_td_shim_matching_and_tamper() {
        let mr_td = "321ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";
        let logged = manifest("1.0.0", &[("tdx.td-shim", mr_td)]);
        let policy = render_rekor(&["tdx.td-shim"], &resolved_from_manifest(&logged));

        let ok = tdx_quote_input(Some(mr_td), "0000001000000000", &[]);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "matching td-shim mr_td must affirm"
        );

        let tampered = "421ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";
        let bad = ok.replace(mr_td, tampered);
        assert_eq!(
            eval_policy_vector(&policy, &bad).await,
            (97, 2, 2, 2),
            "tampered td-shim mr_td must reject executables"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_td_kernel_matching_and_tamper() {
        let kernel = "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let event_32mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAACAAAAAA==";
        let logged = manifest("1.0.0", &[("tdx.kernel", kernel)]);
        let policy = render_rekor(&["tdx.kernel"], &resolved_from_manifest(&logged));

        let ok = tdx_input(&[td_payload_event(event_32mib, kernel, 2)]);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "matching td_payload digest + 32 MiB blob must affirm"
        );

        let tampered = "b1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let bad = ok.replace(kernel, tampered);
        assert_eq!(
            eval_policy_vector(&policy, &bad).await,
            (97, 2, 2, 2),
            "tampered td_payload digest must reject executables"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_td_kernel_descriptor_must_be_exact() {
        let kernel = "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let event_32mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAACAAAAAA==";
        let logged = manifest("1.0.0", &[("tdx.kernel", kernel)]);
        let policy = render_rekor(&["tdx.kernel"], &resolved_from_manifest(&logged));

        let exact = tdx_input(&[td_payload_event(event_32mib, kernel, 2)]);
        assert_eq!(
            eval_policy_vector(&policy, &exact).await,
            (2, 2, 2, 2),
            "exact td_payload descriptor must affirm"
        );

        // A prefix-only descriptor must not match the exact comparison.
        let prefixed = serde_json::to_string(&json!({
            "tdx": {
                "quote": {
                    "header": {"tee_type": "81000000", "vendor_id": TDX_VENDOR_ID},
                    "body": {"td_attributes": "0000001000000000"},
                },
                "uefi_event_logs": [{
                    "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
                    "details": {"string": "td_payload_extra"},
                    "event": event_32mib,
                    "digests": [{"alg": "SHA-384", "digest": kernel}],
                    "index": 2,
                }],
            }
        }))
        .expect("serialize input");
        assert_eq!(
            eval_policy_vector(&policy, &prefixed).await,
            (97, 2, 2, 2),
            "prefix-only td_payload_* descriptor must reject (exact match required)"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_td_kernel_blob_length_must_be_32mib() {
        let kernel = "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let event_32mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAACAAAAAA==";
        let event_16mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAABAAAAAA==";
        let logged = manifest("1.0.0", &[("tdx.kernel", kernel)]);
        let policy = render_rekor(&["tdx.kernel"], &resolved_from_manifest(&logged));

        let ok = tdx_input(&[td_payload_event(event_32mib, kernel, 2)]);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "td_payload blob length == 32 MiB must affirm"
        );

        let wrong_blob = tdx_input(&[td_payload_event(event_16mib, kernel, 2)]);
        assert_eq!(
            eval_policy_vector(&policy, &wrong_blob).await,
            (97, 2, 2, 2),
            "td_payload blob length != 32 MiB must reject"
        );

        let malformed = tdx_input(&[td_payload_event("AAAA", kernel, 2)]);
        assert_eq!(
            eval_policy_vector(&policy, &malformed).await,
            (97, 2, 2, 2),
            "malformed td_payload event must reject (fail-closed)"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_td_kernel_conflicting_blob_length_rejects() {
        let kernel = "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let event_32mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAACAAAAAA==";
        let event_16mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAABAAAAAA==";
        let logged = manifest("1.0.0", &[("tdx.kernel", kernel)]);
        let policy = render_rekor(&["tdx.kernel"], &resolved_from_manifest(&logged));

        let single = tdx_input(&[td_payload_event(event_32mib, kernel, 2)]);
        assert_eq!(eval_policy_vector(&policy, &single).await, (2, 2, 2, 2));

        let dup_same = tdx_input(&[
            td_payload_event(event_32mib, kernel, 2),
            td_payload_event(event_32mib, kernel, 2),
        ]);
        assert_eq!(
            eval_policy_vector(&policy, &dup_same).await,
            (2, 2, 2, 2),
            "duplicate 32 MiB td_payload events (same digest) must affirm"
        );

        // Same digest but a blobLength disagreement is a conflict.
        let conflict = tdx_input(&[
            td_payload_event(event_32mib, kernel, 2),
            td_payload_event(event_16mib, kernel, 2),
        ]);
        assert_eq!(
            eval_policy_vector(&policy, &conflict).await,
            (97, 2, 2, 2),
            "32 MiB + 16 MiB td_payload pair (same digest) must reject (blobLength conflict)"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_td_kernel_rejects_non_rtmr1_index() {
        let kernel = "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let event_32mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAACAAAAAA==";
        let logged = manifest("1.0.0", &[("tdx.kernel", kernel)]);
        let policy = render_rekor(&["tdx.kernel"], &resolved_from_manifest(&logged));

        let single = tdx_input(&[td_payload_event(event_32mib, kernel, 2)]);
        assert_eq!(eval_policy_vector(&policy, &single).await, (2, 2, 2, 2));

        // A descriptor-matching event at index != 2 violates the RTMR1
        // requirement even when another index-2 event matches.
        let bad = tdx_input(&[
            td_payload_event(event_32mib, kernel, 2),
            td_payload_event(event_32mib, kernel, 1),
        ]);
        assert_eq!(
            eval_policy_vector(&policy, &bad).await,
            (97, 2, 2, 2),
            "descriptor-matching td_payload event at index != 2 must reject (fail-closed)"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_td_kernel_rejects_missing_sha384_digest() {
        let kernel = "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let event_32mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAACAAAAAA==";
        let logged = manifest("1.0.0", &[("tdx.kernel", kernel)]);
        let policy = render_rekor(&["tdx.kernel"], &resolved_from_manifest(&logged));

        let with_sha384 = tdx_input(&[td_payload_event(event_32mib, kernel, 2)]);
        assert_eq!(
            eval_policy_vector(&policy, &with_sha384).await,
            (2, 2, 2, 2)
        );

        let no_sha384 = serde_json::to_string(&json!({
            "tdx": {
                "quote": {
                    "header": {"tee_type": "81000000", "vendor_id": TDX_VENDOR_ID},
                    "body": {"td_attributes": "0000001000000000"},
                },
                "uefi_event_logs": [{
                    "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
                    "details": {"string": "td_payload"},
                    "event": event_32mib,
                    "digests": [{"alg": "SHA-256", "digest": hex64('0')}],
                    "index": 2,
                }],
            }
        }))
        .expect("serialize input");
        assert_eq!(
            eval_policy_vector(&policy, &no_sha384).await,
            (97, 2, 2, 2),
            "td_payload event without a SHA-384 digest must reject (fail-closed)"
        );

        let empty_digests = serde_json::to_string(&json!({
            "tdx": {
                "quote": {
                    "header": {"tee_type": "81000000", "vendor_id": TDX_VENDOR_ID},
                    "body": {"td_attributes": "0000001000000000"},
                },
                "uefi_event_logs": [{
                    "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
                    "details": {"string": "td_payload"},
                    "event": event_32mib,
                    "digests": [],
                    "index": 2,
                }],
            }
        }))
        .expect("serialize input");
        assert_eq!(
            eval_policy_vector(&policy, &empty_digests).await,
            (97, 2, 2, 2),
            "td_payload event with an empty digests array must reject (fail-closed)"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_td_kernel_extracts_real_pai_event_log() {
        // The real PAI TD kernel measurement carried by the td_payload
        // firmware-blob2 event at RTMR1 in `tdx_CCEL_data_pai`.
        let kernel = "85619a9146b5c1409bf034bdabd6d93df26a5a23b41b43f92a7a4025760a1c4f110194ae75a2b9625b0de97f2b00fc8f";

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

        let mut tdx = serde_json::Map::new();
        tdx.insert(
            "quote".to_string(),
            json!({
                "header": {"tee_type": "81000000", "vendor_id": TDX_VENDOR_ID},
                "body": {"td_attributes": "0000001000000000"},
            }),
        );
        tdx.insert(
            "uefi_event_logs".to_string(),
            parsed["uefi_event_logs"].clone(),
        );
        let input = json!({"tdx": tdx}).to_string();

        let logged = manifest("1.0.0", &[("tdx.kernel", kernel)]);
        let policy = render_rekor(&["tdx.kernel"], &resolved_from_manifest(&logged));
        assert_eq!(
            eval_policy_vector(&policy, &input).await,
            (2, 2, 2, 2),
            "real PAI event log must extract the real kernel measurement and affirm"
        );

        let tampered = "85619a9146b5c1409bf034bdabd6d93df26a5a23b41b43f92a7a4025760a1c4f110194ae75a2b9625b0de97f2b00fc80";
        let bad_logged = manifest("1.0.0", &[("tdx.kernel", tampered)]);
        let bad_policy = render_rekor(&["tdx.kernel"], &resolved_from_manifest(&bad_logged));
        assert_eq!(
            eval_policy_vector(&bad_policy, &input).await,
            (97, 2, 2, 2),
            "a published kernel that differs from the real PAI event-log kernel must reject"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_container_image_extracts_real_pai_event_log() {
        // The real PAI AAEL pull-image event resolves to repo `busybox`. The
        // allowed published measurement type is `container.image.cmaas-runtime`,
        // so rewrite the reference's repo tail while keeping the real event
        // structure and digest.
        let image_digest =
            "sha256:16ece118a36d152ed7562347741470b1bb0b0f7561ff1fe0049857a03d4fec5d";

        let ccel_bytes =
            std::fs::read("src/tee/coco/converter/builtin/tests/fixtures/tdx_CCEL_data_pai")
                .expect("read real PAI event-log fixture");
        let ccel: eventlog::CcEventLog =
            ccel_bytes.try_into().expect("parse real PAI CC event log");
        let mut parsed = serde_json::to_value(&ccel)
            .expect("serialize parsed CC event log")
            .as_object()
            .expect("parsed event log is an object")
            .clone();
        for event in parsed["uefi_event_logs"]
            .as_array_mut()
            .expect("event log array")
        {
            if let Some(reference) = event.pointer_mut("/details/data/content/reference") {
                if let Some(s) = reference.as_str() {
                    *reference = json!(s.replace("busybox", "cmaas-runtime"));
                }
            }
        }

        let mut tdx = serde_json::Map::new();
        tdx.insert(
            "quote".to_string(),
            json!({
                "header": {"tee_type": "81000000", "vendor_id": TDX_VENDOR_ID},
                "body": {"td_attributes": "0000001000000000"},
            }),
        );
        tdx.insert(
            "uefi_event_logs".to_string(),
            parsed["uefi_event_logs"].clone(),
        );
        let input = json!({"tdx": tdx}).to_string();

        let logged = manifest("1.0.0", &[("container.image.cmaas-runtime", image_digest)]);
        let policy = render_rekor(
            &["container.image.cmaas-runtime"],
            &resolved_from_manifest(&logged),
        );
        assert_eq!(
            eval_policy_vector(&policy, &input).await,
            (2, 2, 2, 2),
            "real PAI event log must extract the real image measurement and affirm"
        );

        let tampered = "sha256:26ece118a36d152ed7562347741470b1bb0b0f7561ff1fe0049857a03d4fec5d";
        let bad_logged = manifest("1.0.0", &[("container.image.cmaas-runtime", tampered)]);
        let bad_policy = render_rekor(
            &["container.image.cmaas-runtime"],
            &resolved_from_manifest(&bad_logged),
        );
        assert_eq!(
            eval_policy_vector(&bad_policy, &input).await,
            (97, 2, 2, 2),
            "a published image digest that differs from the real PAI AAEL event must reject"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_rejects_conflicting_container_image_events() {
        let digest_a = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let digest_b = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let logged = manifest("1.0.0", &[("container.image.cmaas-runtime", digest_a)]);
        let policy = render_rekor(
            &["container.image.cmaas-runtime"],
            &resolved_from_manifest(&logged),
        );

        let single = tdx_input(&[aael_event(digest_a)]);
        assert_eq!(eval_policy_vector(&policy, &single).await, (2, 2, 2, 2));

        let dup_same = tdx_input(&[aael_event(digest_a), aael_event(digest_a)]);
        assert_eq!(
            eval_policy_vector(&policy, &dup_same).await,
            (2, 2, 2, 2),
            "duplicate AAEL events with the same digest must still affirm"
        );

        let conflict = tdx_input(&[aael_event(digest_a), aael_event(digest_b)]);
        assert_eq!(
            eval_policy_vector(&policy, &conflict).await,
            (97, 2, 2, 2),
            "conflicting AAEL digests must reject (explicit conflict detection)"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_rejects_malformed_measurement_value_format() {
        let good = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let logged = manifest("1.0.0", &[("container.image.cmaas-runtime", good)]);
        let policy = render_rekor(
            &["container.image.cmaas-runtime"],
            &resolved_from_manifest(&logged),
        );

        let ok = tdx_input(&[aael_event(good)]);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "well-formed sha256:+64hex digest must affirm"
        );

        for malformed in [
            "sha256:D42F6E1B2AAFB59383D0892824AEBF5E0A2E27DAD989A3FB26552A6E77E4BE46",
            "sha256:abc123",
            "d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
        ] {
            let bad = tdx_input(&[aael_event(malformed)]);
            assert_eq!(
                eval_policy_vector(&policy, &bad).await,
                (97, 2, 2, 2),
                "malformed digest {malformed:?} must reject (format check)"
            );
        }
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_requires_valid_dsse_signature() {
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let logged = manifest("1.0.0", &[("container.image.cmaas-runtime", digest)]);
        let ok = tdx_input(&[aael_event(digest)]);

        let resolved = resolved_from_manifest(&logged);
        let policy = render_rekor(&["container.image.cmaas-runtime"], &resolved);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "matching manifest with a valid DSSE signature must affirm"
        );

        // A signature that does not verify rejects even though the payloadHash
        // still matches: DSSE verification is mandatory.
        let mut bad_signature = resolved.clone();
        bad_signature.dsse_signature = BASE64_STANDARD.encode([0u8; 64]);
        let policy = render_rekor(&["container.image.cmaas-runtime"], &bad_signature);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (97, 2, 2, 2),
            "invalid DSSE signature must reject executables"
        );

        // A different valid P-256 publisher key rejects even though the
        // payloadHash matches (publisher-identity binding).
        let mut wrong_key = resolved;
        wrong_key.publisher_key = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n\
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n\
-----END PUBLIC KEY-----\n"
            .to_string();
        let policy = render_rekor(&["container.image.cmaas-runtime"], &wrong_key);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (97, 2, 2, 2),
            "wrong publisher key must reject even when the payloadHash matches"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_dsse_verifies_against_builtin_publisher_key() {
        // Extract the real DSSE signature from the fixture entry.
        let entry_raw = include_str!("../../tests/fixtures/rekor_v1_entry.json");
        let entry: Value = serde_json::from_str(entry_raw).expect("parse fixture");
        let body_bytes = BASE64_STANDARD
            .decode(entry["body"].as_str().expect("body"))
            .expect("decode entry body");
        let body: Value = serde_json::from_slice(&body_bytes).expect("parse body");
        let dsse_signature = body["spec"]["signatures"][0]["signature"]
            .as_str()
            .expect("signature")
            .to_string();

        let payload_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let ok = tdx_input(&[aael_event(digest)]);

        // Built-in key + real signature -> DSSE verifies -> affirm.
        let mut resolved = ResolvedRekor {
            payload_hash: payload_hash.to_string(),
            dsse_signature: dsse_signature.clone(),
            publisher_key: artifact_server::BUILTIN_LOG_ENTRY_PUB_KEY_PEM.to_string(),
        };
        let policy = render_rekor(&["container.image.cmaas-runtime"], &resolved);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "built-in publisher key + real DSSE signature must affirm"
        );

        // A bogus signature with the built-in key rejects.
        resolved.dsse_signature = BASE64_STANDARD.encode([0u8; 64]);
        let policy = render_rekor(&["container.image.cmaas-runtime"], &resolved);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (97, 2, 2, 2),
            "wrong DSSE signature must reject against the built-in publisher key"
        );
    }

    #[test]
    fn transparency_log_rekor_always_emits_dsse_verify() {
        let resolved = ResolvedRekor {
            payload_hash: "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8"
                .to_string(),
            dsse_signature: "sig".to_string(),
            publisher_key: "key".to_string(),
        };
        let policy = render_rekor(&["container.image.cmaas-runtime"], &resolved);
        assert!(
            policy.contains("tng.verify_dsse_signature("),
            "a rekor-v1 entry must always emit DSSE verification: {policy}"
        );
        assert!(policy.contains("t_0_0_dsse_signature := "));
        assert!(policy.contains("t_0_0_publisher_key := "));
    }

    #[test]
    fn serde_json_serialization_matches_real_rekor_payload_hash() {
        let logged = manifest(
            "1.0.0",
            &[(
                "container.image.cmaas-runtime",
                "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
            )],
        );
        assert_eq!(
            sha256_hex(jcs_compact(&logged).as_bytes()),
            "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8",
            "JCS (sorted compact) form must equal the real rekor payloadHash"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_dsse_signature_validates_real_fixture_signature() {
        use p256::ecdsa::signature::Verifier;

        let entry_raw = include_str!("../../tests/fixtures/rekor_v1_entry.json");
        let entry: Value = serde_json::from_str(entry_raw).expect("parse fixture");
        let body_bytes = BASE64_STANDARD
            .decode(entry["body"].as_str().expect("body"))
            .expect("decode entry body");
        let body: Value = serde_json::from_slice(&body_bytes).expect("parse body");
        let sig0 = &body["spec"]["signatures"][0];
        let sig_b64 = sig0["signature"].as_str().expect("signature").to_string();
        let verifier_pem = String::from_utf8(
            BASE64_STANDARD
                .decode(sig0["verifier"].as_str().expect("verifier"))
                .expect("decode verifier b64"),
        )
        .expect("publisher PEM utf8");

        let logged = manifest(
            "1.0.0",
            &[(
                "container.image.cmaas-runtime",
                "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
            )],
        );
        let payload = jcs_compact(&logged);

        let verify = |payload_str: &str, sig_b64: &str, key_pem: &str| -> bool {
            (|| -> anyhow::Result<bool> {
                let key = rekor_v1::parse_p256_public_key(key_pem)?;
                let sig_bytes = BASE64_STANDARD.decode(sig_b64)?;
                let signature = p256::ecdsa::Signature::from_der(&sig_bytes)?;
                let pae = dsse_pae(DSSE_PAYLOAD_TYPE, payload_str.as_bytes());
                key.verify(&pae, &signature)?;
                Ok(true)
            })()
            .unwrap_or(false)
        };

        assert!(
            verify(&payload, &sig_b64, &verifier_pem),
            "real fixture DSSE signature must verify with its publisher key"
        );

        let tampered = payload.replace(
            "d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
            "e42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
        );
        assert_ne!(payload, tampered, "tamper did not change payload");
        assert!(
            !verify(&tampered, &sig_b64, &verifier_pem),
            "tampered manifest must fail DSSE verification"
        );

        let wrong_pem = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n\
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n\
-----END PUBLIC KEY-----\n";
        assert!(
            !verify(&payload, &sig_b64, wrong_pem),
            "wrong publisher key must fail DSSE verification"
        );
    }

    // --- hardware mapping ---------------------------------------------------

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_hardware_is_platform_recognition_only() {
        let mr_td = hex96('a');
        let logged = manifest("1.0.0", &[("tdx.td-shim", mr_td.as_str())]);
        let policy = render_rekor(&["tdx.td-shim"], &resolved_from_manifest(&logged));

        let ok = tdx_quote_input(Some(mr_td.as_str()), "0000001000000000", &[]);
        assert_eq!(eval_policy_vector(&policy, &ok).await, (2, 2, 2, 2));

        // The old platform scoring is gone: hardware depends on recognition
        // alone, so the debug bit does not affect it. Add a `tdx` entry to
        // enforce the strict posture.
        let debug = tdx_quote_input(Some(mr_td.as_str()), "0100001000000000", &[]);
        assert_eq!(
            eval_policy_vector(&policy, &debug).await,
            (2, 2, 2, 2),
            "transparency_log alone must not gate the hardware debug bit"
        );

        let bad_vendor = ok.replace(TDX_VENDOR_ID, &"0".repeat(32));
        assert_eq!(
            eval_policy_vector(&policy, &bad_vendor).await,
            (2, 97, 2, 2),
            "a wrong TDX vendor id must reject hardware while executables still passes"
        );

        assert_eq!(
            eval_policy_vector(&policy, "{}").await,
            (97, 97, 2, 2),
            "no evidence must leave executables and hardware non-affirming"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_with_tdx_entry_enforces_posture() {
        let mr_td = hex96('a');
        let logged = manifest("1.0.0", &[("tdx.td-shim", mr_td.as_str())]);
        let resolved = [Some(resolved_from_manifest(&logged))];
        let policy = render(
            json!([
                transparency_entry(rekor_entry_value(&["tdx.td-shim"], 1)),
                {"type": "tdx", "value": {}},
            ]),
            &resolved,
        );

        let event = json!({"event": "ok"});
        let ok = tdx_quote_input(
            Some(mr_td.as_str()),
            "0000001000000000",
            std::slice::from_ref(&event),
        );
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "transparency + non-debug TDX with an event log must affirm"
        );

        let debug = tdx_quote_input(
            Some(mr_td.as_str()),
            "0100001000000000",
            std::slice::from_ref(&event),
        );
        assert_eq!(
            eval_policy_vector(&policy, &debug).await,
            (2, 97, 2, 2),
            "the tdx entry must reject a debug platform while executables still passes"
        );

        let no_eventlog = tdx_quote_input(Some(mr_td.as_str()), "0000001000000000", &[]);
        assert_eq!(
            eval_policy_vector(&policy, &no_eventlog).await,
            (2, 97, 2, 2),
            "the tdx entry must require an event log (hardware only)"
        );

        let wrong_measurement = tdx_quote_input(Some(&hex96('9')), "0000001000000000", &[event]);
        assert_eq!(
            eval_policy_vector(&policy, &wrong_measurement).await,
            (97, 2, 2, 2),
            "a measurement mismatch must reject executables while hardware still passes"
        );
    }

    // --- artifact-server behavior ------------------------------------------

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_artifact_server_rejects_defensive_fallback_shapes() {
        let log_services = vec![ArtifactLogService {
            type_: "rekor-v1".to_string(),
            url: "https://rekor.sigstore.dev".to_string(),
        }];
        let primary = TransparencyServiceConfig::ArtifactServer {
            url: "https://x".to_string(),
            log_services,
            publisher_public_key_pem: None,
        };
        let base = TransparencyLogEntryConfig {
            published_measurements: vec!["tdx.td-shim".to_string()],
            schema_version: "1.0.0".to_string(),
            services: vec![primary],
            fallback_published_measurements: Some(vec!["tdx.td-shim".to_string()]),
            fallback_services: None,
        };

        // A non-rekor-v1 fallback service is rejected even when validation is
        // bypassed (defense in depth for direct callers).
        let mut cfg = base.clone();
        cfg.fallback_services = Some(vec![TransparencyServiceConfig::ArtifactServer {
            url: "https://x2".to_string(),
            log_services: vec![],
            publisher_public_key_pem: None,
        }]);
        let err = build_entry_rules(&cfg, None, "m_0_0", "t_0_0").unwrap_err();
        assert!(
            err.to_string()
                .contains("fallbackServices must contain only rekor-v1"),
            "{err}"
        );

        // An empty fallback service list is rejected.
        let mut cfg = base;
        cfg.fallback_services = Some(vec![]);
        let err = build_entry_rules(&cfg, None, "m_0_0", "t_0_0").unwrap_err();
        assert!(
            err.to_string().contains("fallbackServices is empty"),
            "{err}"
        );
    }

    /// Load the evidence fixture and extract the matched
    /// `(release_manifest, log_entry, entry_url, log_index)` tuple.
    fn cmaas_transparency_tuple() -> (Value, Value, String, i64) {
        let evidence: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/cmaas_evidence_with_rekor_v1_transparency.json"
        ))
        .expect("parse evidence fixture");
        let manifest = evidence["transparency"]["release_manifest"].clone();
        let log_entry = evidence["transparency"]["log_entries"][0]["log_entry"].clone();
        let entry_url = evidence["transparency"]["log_entries"][0]["url"]
            .as_str()
            .expect("entry url")
            .to_string();
        let log_index = log_entry["logIndex"].as_i64().expect("logIndex");
        (manifest, log_entry, entry_url, log_index)
    }

    fn resolve_response_body(manifest: &Value, log_entry: &Value, entry_url: &str) -> String {
        const LOG_ENTRY_PUB_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsGjh0eIF22/JwEkRvU5KROvNsL/F\nK6qP/kbKO0CoelOqRKJQuC9z0ruwyx12S94/m69+iaan0SKR1IJjIbbfHw==\n-----END PUBLIC KEY-----";
        const SIGSTORE_REKOR_V1_PUB_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\nkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n-----END PUBLIC KEY-----";
        json!({
            "status": "resolved",
            "release_manifest": manifest,
            "log_entries": [{
                "type": "rekor-v1",
                "url": entry_url,
                "log_entry": log_entry,
                "entry_verifier": {"type": "public_key", "content": LOG_ENTRY_PUB_KEY_PEM},
                "log_verifier": {"public_key_pem": SIGSTORE_REKOR_V1_PUB_KEY_PEM}
            }]
        })
        .to_string()
    }

    fn rekor_entries_body(log_entry: &Value) -> String {
        let uuid = "00000000-0000-0000-0000-000000000000";
        json!({ uuid: log_entry }).to_string()
    }

    fn cmaas_tdx_input(manifest: &Value) -> String {
        let digest = manifest["measurements"][0]["value"]
            .as_str()
            .expect("fixture manifest measurement value");
        tdx_input(&[aael_event(digest)])
    }

    async fn build_branch_b_policy(
        artifact_url: &str,
        entry_url: &str,
        fallback_log_url: &str,
        fallback_log_index: i64,
    ) -> String {
        let cfg_json = json!({
            "type": "modules",
            "modules": [transparency_entry(artifact_entry_value(
                artifact_url,
                entry_url,
                Some((fallback_log_url, fallback_log_index)),
            ))],
        });
        let cfg: PolicyConfig = serde_json::from_value(cfg_json).expect("parse cfg");
        let encoded = load_policy(&cfg).await.expect("encode").expect("policy");
        String::from_utf8(URL_SAFE_NO_PAD.decode(&encoded).unwrap()).unwrap()
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    #[serial]
    async fn transparency_log_artifact_server_primary_and_fallback() {
        let (manifest, log_entry, entry_url, log_index) = cmaas_transparency_tuple();
        let input = cmaas_tdx_input(&manifest);
        let resolve_body = resolve_response_body(&manifest, &log_entry, &entry_url);
        let rekor_body = rekor_entries_body(&log_entry);

        // Primary success; the fallback points at a dead port and must not be
        // consulted.
        artifact_server::invalidate_host_await_caches_for_test();
        {
            let server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::path("/api/v1/transparency/resolve"))
                .respond_with(
                    wiremock::ResponseTemplate::new(200).set_body_string(resolve_body.clone()),
                )
                .expect(1)
                .mount(&server)
                .await;
            let policy =
                build_branch_b_policy(&server.uri(), &entry_url, "http://127.0.0.1:1", log_index)
                    .await;
            let vec = eval_policy_vector(&policy, &input).await;
            assert_eq!(
                vec.0, 2,
                "primary success must affirm executables (got {vec:?})"
            );
        }

        // Artifact-server 500; the fallback rekor mock serves the fixture
        // entry and authenticates it.
        artifact_server::invalidate_host_await_caches_for_test();
        {
            let as_server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::path("/api/v1/transparency/resolve"))
                .respond_with(
                    wiremock::ResponseTemplate::new(500).set_body_string("upstream error"),
                )
                .mount(&as_server)
                .await;
            let rekor_server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/api/v1/log/entries"))
                .and(wiremock::matchers::query_param(
                    "logIndex",
                    log_index.to_string(),
                ))
                .respond_with(
                    wiremock::ResponseTemplate::new(200).set_body_string(rekor_body.clone()),
                )
                .expect(1)
                .mount(&rekor_server)
                .await;
            let policy =
                build_branch_b_policy(&as_server.uri(), &entry_url, &rekor_server.uri(), log_index)
                    .await;
            let vec = eval_policy_vector(&policy, &input).await;
            assert_eq!(
                vec.0, 2,
                "fallback success must affirm executables (got {vec:?})"
            );
        }

        // Both fail -> executables stays at its contraindicated default.
        artifact_server::invalidate_host_await_caches_for_test();
        {
            let as_server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::path("/api/v1/transparency/resolve"))
                .respond_with(
                    wiremock::ResponseTemplate::new(500).set_body_string("upstream error"),
                )
                .mount(&as_server)
                .await;
            let rekor_server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/api/v1/log/entries"))
                .and(wiremock::matchers::query_param(
                    "logIndex",
                    log_index.to_string(),
                ))
                .respond_with(wiremock::ResponseTemplate::new(500).set_body_string("rekor down"))
                .mount(&rekor_server)
                .await;
            let policy =
                build_branch_b_policy(&as_server.uri(), &entry_url, &rekor_server.uri(), log_index)
                    .await;
            let vec = eval_policy_vector(&policy, &input).await;
            assert_eq!(vec.0, 97, "both-fail must deny executables (got {vec:?})");
        }
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    #[serial]
    async fn transparency_log_artifact_server_revoked_skips_fallback() {
        let (manifest, log_entry, entry_url, log_index) = cmaas_transparency_tuple();
        let input = cmaas_tdx_input(&manifest);
        let rekor_body = rekor_entries_body(&log_entry);

        artifact_server::invalidate_host_await_caches_for_test();
        let as_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/transparency/resolve"))
            .respond_with(
                wiremock::ResponseTemplate::new(403).set_body_string(
                    json!({
                        "error_code": "measurement_revoked",
                        "error_message": "the measurement was revoked",
                        "request_id": "test-req-3"
                    })
                    .to_string(),
                ),
            )
            .mount(&as_server)
            .await;
        let rekor_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/log/entries"))
            .and(wiremock::matchers::query_param(
                "logIndex",
                log_index.to_string(),
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(rekor_body))
            .expect(0) // a revoked primary must never reach the fallback
            .mount(&rekor_server)
            .await;
        let policy =
            build_branch_b_policy(&as_server.uri(), &entry_url, &rekor_server.uri(), log_index)
                .await;
        let vec = eval_policy_vector(&policy, &input).await;
        assert_eq!(
            vec.0, 97,
            "a revoked measurement must deny executables without consulting the rekor fallback (got {vec:?})"
        );
        rekor_server.verify().await;
    }

    /// When the primary resolves successfully, regorus must not evaluate the
    /// fallback network call. A raw TCP listener makes an eager call
    /// observable.
    // Test-only spawn: the wasm-safety rule behind the disallowed list does
    // not apply to a host-only tokio test.
    #[allow(clippy::disallowed_methods)]
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    #[serial]
    async fn transparency_log_artifact_server_does_not_call_fallback_when_primary_ok() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use tokio::net::TcpListener;

        artifact_server::invalidate_host_await_caches_for_test();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = listener.local_addr().unwrap();
        let fallback_called = Arc::new(AtomicBool::new(false));
        let called_clone = fallback_called.clone();
        tokio::spawn(async move {
            for _ in 0..4 {
                if listener.accept().await.is_ok() {
                    called_clone.store(true, Ordering::SeqCst);
                }
            }
        });

        let evidence: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/cmaas_evidence_with_rekor_v1_transparency.json"
        ))
        .unwrap();
        let manifest = evidence["transparency"]["release_manifest"].clone();
        let log_entry = evidence["transparency"]["log_entries"][0]["log_entry"].clone();
        let entry_url = evidence["transparency"]["log_entries"][0]["url"]
            .as_str()
            .unwrap()
            .to_string();
        let resolve_body = resolve_response_body(&manifest, &log_entry, &entry_url);

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/transparency/resolve"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(resolve_body))
            .mount(&server)
            .await;

        let cfg_json = json!({
            "type": "modules",
            "modules": [transparency_entry(artifact_entry_value(
                &server.uri(),
                &entry_url,
                Some((&format!("http://{}", fallback_addr), 42)),
            ))],
        });
        let cfg: PolicyConfig = serde_json::from_value(cfg_json).unwrap();
        let encoded = load_policy(&cfg).await.unwrap().expect("policy");
        let policy = String::from_utf8(URL_SAFE_NO_PAD.decode(&encoded).unwrap()).unwrap();

        let digest = manifest["measurements"][0]["value"]
            .as_str()
            .expect("fixture manifest measurement value");
        let input = tdx_input(&[aael_event(digest)]);

        let vec = eval_policy_vector(&policy, &input).await;
        assert_eq!(vec.0, 2, "primary_ok must affirm executables (got {vec:?})");

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !fallback_called.load(Ordering::SeqCst),
            "tng.fetch_rekor_on_demand must NOT be called when primary_ok is true"
        );
    }

    // --- reference values ---------------------------------------------------

    #[tokio::test]
    async fn modules_with_transparency_rejects_reference_values() {
        let policy = PolicyConfig::Modules {
            modules: serde_json::from_value(json!([transparency_entry(artifact_entry_value(
                "https://attest.example.com",
                "https://rekor.sigstore.dev",
                None,
            ))]))
            .expect("modules config"),
        };
        let mut rvs = std::collections::HashMap::new();
        rvs.insert("measurement.tdx.ovmf".to_string(), json!(["x"]));
        let reference = ReferenceValueConfig::Sample {
            payload: SampleProvenancePayloadConfig::Inline {
                content: Provenance { rvs },
            },
        };
        let err = match BuiltinCocoConverter::new(&policy, std::slice::from_ref(&reference)).await {
            Ok(_) => panic!("external reference_values must be rejected"),
            Err(e) => e,
        };
        assert!(
            format!("{err:?}").contains("does not accept external reference_values"),
            "{err:?}"
        );
    }

    // --- live rekor end-to-end ---------------------------------------------

    /// Requires live network access to rekor.sigstore.dev (fetch by logIndex).
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn new_with_transparency_log_policy_fetches_reference_values() {
        let cfg: PolicyConfig = serde_json::from_str(
            r#"{
                "type": "modules",
                "modules": [{
                    "type": "transparency_log",
                    "value": {
                        "publishedMeasurements": ["container.image.cmaas-runtime"],
                        "schemaVersion": "1.0.0",
                        "services": [{
                            "type": "rekor-v1",
                            "logUrl": "https://rekor.sigstore.dev",
                            "logIndex": 2544139140
                        }]
                    }
                }]
            }"#,
        )
        .expect("parse modules transparency_log config");
        let result = BuiltinCocoConverter::new(&cfg, &[]).await;
        assert!(
            result.is_ok(),
            "BuiltinCocoConverter::new with a transparency_log module failed: {:?}",
            result.err()
        );
    }

    /// The shared main flow: parse config -> converter.new (live rekor fetch +
    /// authenticate + bake payloadHash) -> build CocoEvidence -> convert ->
    /// verify_evidence.
    async fn run_transparency_log_appraisal(
        cfg_json: &str,
        quote: &str,
        cc_eventlog: &str,
    ) -> Result<()> {
        let cfg: PolicyConfig = serde_json::from_str(cfg_json)?;
        let converter = BuiltinCocoConverter::new(&cfg, &[])
            .await?
            .for_testing_skip_runtime_data();
        let verifier = converter.new_verifier().await?;
        let evidence = build_cmaas_evidence(quote, cc_eventlog);
        let token = converter.convert(&evidence).await;
        let token = match token {
            Ok(t) => t,
            Err(error) => {
                if format!("{error:?}")
                    .contains("feature `tdx-verifier` is not enabled for `verifier` crate")
                {
                    return Ok(()); // environment limitation, not a real failure
                }
                return Err(error.into());
            }
        };
        verifier.verify_evidence(&token, &ReportData::None).await?;
        Ok(())
    }

    fn cmaas_fixture_quote_and_eventlog() -> (String, String) {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/cmaas_evidence_with_rekor_v1_transparency.json"
        ))
        .expect("parse evidence fixture");
        let ev = &fixture["evidence"];
        (
            ev["quote"].as_str().expect("quote").to_string(),
            ev["cc_eventlog"].as_str().expect("cc_eventlog").to_string(),
        )
    }

    fn build_cmaas_evidence(quote: &str, cc_eventlog: &str) -> CocoEvidence {
        let tee = tee_from_str("tdx").expect("tee");
        let aa_evidence = serde_json::to_vec(&json!({
            "quote": quote,
            "cc_eventlog": cc_eventlog,
        }))
        .expect("serialize aa_evidence");
        CocoEvidence::new(
            tee,
            aa_evidence,
            None,
            "{}".to_string(),
            HashAlgo::Sha256,
            None,
        )
        .expect("build CocoEvidence")
    }

    fn flip_one_char(s: &str) -> String {
        let mut chars: Vec<char> = s.chars().collect();
        let idx = chars
            .iter()
            .position(|c| *c == 'A' || *c == 'B')
            .unwrap_or(0);
        chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
        chars.into_iter().collect()
    }

    const BOGUS_P256_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsGjh0eIF22/JwEkRvU5KROvNsL/F\nK6qP/kbKO0CoelOqRKJQuC9z0ruwyx12S94/m69+iaan0SKR1IJjIbbfHw==\n-----END PUBLIC KEY-----\n";

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn evidence_appraises_with_transparency_log_policy() {
        let cfg = r#"{"type":"modules","modules":[{"type":"transparency_log","value":{"publishedMeasurements":["container.image.cmaas-runtime"],"schemaVersion":"1.0.0","services":[{"type":"rekor-v1","logUrl":"https://rekor.sigstore.dev","logIndex":2310520944}]}}]}"#;
        let (quote, cc_eventlog) = cmaas_fixture_quote_and_eventlog();

        // Happy path.
        assert!(
            run_transparency_log_appraisal(cfg, &quote, &cc_eventlog)
                .await
                .is_ok(),
            "correct config + evidence must affirm"
        );

        // 1. An unsupported measurement type is rejected at load.
        let cfg_t1 = cfg.replace("cmaas-runtime", "cmaas-WRONG");
        assert!(
            run_transparency_log_appraisal(&cfg_t1, &quote, &cc_eventlog)
                .await
                .is_err(),
            "wrong publishedMeasurements type must fail"
        );

        // 2. Wrong schemaVersion.
        let cfg_t2 = cfg.replace("1.0.0", "9.9.9");
        assert!(
            run_transparency_log_appraisal(&cfg_t2, &quote, &cc_eventlog)
                .await
                .is_err(),
            "wrong schemaVersion must fail"
        );

        // 3. Wrong logIndex (out-of-range -> fetch 404).
        let cfg_t3 = cfg.replace("2310520944", "99999999999");
        assert!(
            run_transparency_log_appraisal(&cfg_t3, &quote, &cc_eventlog)
                .await
                .is_err(),
            "wrong logIndex must fail"
        );

        // 4. Wrong logUrl (non-existent host -> fetch fails).
        let cfg_t4 = cfg.replace("rekor.sigstore.dev", "rekor.invalid.example");
        assert!(
            run_transparency_log_appraisal(&cfg_t4, &quote, &cc_eventlog)
                .await
                .is_err(),
            "wrong logUrl must fail"
        );

        // 5. Wrong rekorPublicKeyPem (bogus P-256 key).
        let cfg_t5 = cfg.replace(
            "\"logIndex\":2310520944}",
            &format!(
                "\"logIndex\":2310520944,\"rekorPublicKeyPem\":\"{}\"}}",
                BOGUS_P256_PEM
            ),
        );
        assert!(
            run_transparency_log_appraisal(&cfg_t5, &quote, &cc_eventlog)
                .await
                .is_err(),
            "wrong rekorPublicKeyPem must fail"
        );

        // 6. Wrong publisherPublicKeyPem (bogus key -> DSSE verify fails).
        let cfg_t6 = cfg.replace(
            "\"logIndex\":2310520944}",
            &format!(
                "\"logIndex\":2310520944,\"publisherPublicKeyPem\":\"{}\"}}",
                BOGUS_P256_PEM
            ),
        );
        assert!(
            run_transparency_log_appraisal(&cfg_t6, &quote, &cc_eventlog)
                .await
                .is_err(),
            "wrong publisherPublicKeyPem must fail"
        );

        // 7. Tampered quote.
        let tampered_quote = flip_one_char(&quote);
        assert!(
            run_transparency_log_appraisal(cfg, &tampered_quote, &cc_eventlog)
                .await
                .is_err(),
            "tampered quote must fail"
        );

        // 8. Tampered cc_eventlog (no AAEL events -> reject).
        assert!(
            run_transparency_log_appraisal(cfg, &quote, "AAAA")
                .await
                .is_err(),
            "tampered cc_eventlog must fail"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn secure_proxy_readme_json_round_trips() {
        let json = std::fs::read_to_string(
            "src/tee/coco/converter/builtin/tests/fixtures/secure_proxy_artifact_server_config.json",
        )
        .expect("read fixture");
        let policy: PolicyConfig = serde_json::from_str(&json).expect("parse into PolicyConfig");
        let PolicyConfig::Modules { modules } = &policy else {
            panic!("fixture must be a modules policy");
        };
        parse_module_groups(modules).expect("artifact-server + fallback entry validates");
        let round = serde_json::to_string(&policy).expect("serialize");
        let reparsed: PolicyConfig = serde_json::from_str(&round).expect("re-parse");
        assert_eq!(
            serde_json::to_value(&policy).unwrap(),
            serde_json::to_value(&reparsed).unwrap(),
            "PolicyConfig must round-trip"
        );
    }

    /// A rekor-v1 primary that names more than one service is a configuration
    /// error, caught before any network access.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn load_policy_rejects_multiple_rekor_v1_services() {
        let cfg_json = json!({
            "type": "modules",
            "modules": [transparency_entry(json!({
                "publishedMeasurements": ["tdx.td-shim"],
                "schemaVersion": "1.0.0",
                "services": [
                    {"type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 1},
                    {"type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 2},
                ],
            }))],
        });
        let cfg: PolicyConfig = serde_json::from_value(cfg_json).unwrap();
        let err = load_policy(&cfg).await.unwrap_err();
        assert!(
            format!("{err:?}").contains("exactly one rekor-v1 service"),
            "{err:?}"
        );
    }

    // --- DSSE signing helpers ----------------------------------------------

    /// Sign a manifest with a fixed test P-256 key and return
    /// `(dsse_signature_b64, publisher_key_pem)`.
    #[cfg(feature = "crypto-rustcrypto")]
    fn sign_dsse_for_manifest(manifest: &Value) -> (String, String) {
        use p256::ecdsa::signature::Signer;

        // Fixed deterministic test signing key (RFC 6979 nonce).
        let secret_bytes: [u8; 32] = [0x42; 32];
        let signing_key = p256::ecdsa::SigningKey::from_bytes((&secret_bytes).into())
            .expect("fixed test key valid");
        let payload = jcs_compact(manifest);
        let pae = dsse_pae(DSSE_PAYLOAD_TYPE, payload.as_bytes());
        let sig: p256::ecdsa::Signature = signing_key.sign(&pae);
        let sig_b64 = BASE64_STANDARD.encode(sig.to_der());
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
        let sec1 = verifying_key.to_sec1_bytes();
        // P-256 SPKI DER: SEQUENCE { AlgId(ecPublicKey, prime256v1),
        // BIT STRING(0x00 || SEC1 point) }.
        let prefix: [u8; 26] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let mut spki = Vec::with_capacity(prefix.len() + sec1.len());
        spki.extend_from_slice(&prefix);
        spki.extend_from_slice(&sec1);
        let b64 = BASE64_STANDARD.encode(&spki);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n");
        (sig_b64, pem)
    }
}

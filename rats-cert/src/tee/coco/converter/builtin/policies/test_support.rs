//! Test-only helpers shared by the builtin converter test modules.
//!
//! Everything here is compiled only under `cfg(test)`. The modules deliberately
//! keep one copy of the fixtures, key material, evidence builders, and policy
//! invocation helpers so the tests cannot drift apart.

#![allow(dead_code)] // each test module uses a different subset

use super::super::policy_config::ModuleGroupsConfig;
use super::modules::transparency_log::ResolvedRekor;
use super::modules::{parse_module_groups, render_modules_policy, Module};
use serde_json::{json, Value};

/// Compile-time fixture loading. A test that reads these passes regardless of
/// the working directory it was started from.
pub(crate) mod fixtures {
    pub(crate) const TDX_CCEL_DATA_PAI: &[u8] =
        include_bytes!("../tests/fixtures/tdx_CCEL_data_pai");
    pub(crate) const REKOR_V1_ENTRY_JSON: &str =
        include_str!("../tests/fixtures/rekor_v1_entry.json");
    pub(crate) const REKOR_V1_MANIFEST_JSON: &str =
        include_str!("../tests/fixtures/rekor_v1_manifest.json");
    pub(crate) const CMAAS_EVIDENCE_WITH_REKOR_V1_TRANSPARENCY_JSON: &str =
        include_str!("../tests/fixtures/cmaas_evidence_with_rekor_v1_transparency.json");
    pub(crate) const SECURE_PROXY_ARTIFACT_SERVER_CONFIG_JSON: &str =
        include_str!("../tests/fixtures/secure_proxy_artifact_server_config.json");
}

/// The canonical Intel TDX quoting-enclave vendor id.
pub(crate) const TDX_VENDOR_ID: &str = "939a7233f79c4ca9940a0db3957f0607";

/// The Sigstore Rekor v1 public key: checkpoint and SET verification key. The
/// fixture entry's `logID` is `sha256(SPKI)` of this key.
pub(crate) const SIGSTORE_REKOR_V1_PUB_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\nkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n-----END PUBLIC KEY-----";

/// The DSSE publisher key that signed the fixtures. The production code uses
/// the same PEM as its fail-closed default, so this aliases that constant
/// instead of maintaining a second literal.
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) const DSSE_PUBLISHER_PUB_KEY_PEM: &str =
    super::super::transparency::dsse::BUILTIN_LOG_ENTRY_PUB_KEY_PEM;

/// Lowercase hex string of `len` characters made of `ch` repeated.
pub(crate) fn hex_repeat(ch: char, len: usize) -> String {
    ch.to_string().repeat(len)
}

pub(crate) fn hex96(ch: char) -> String {
    hex_repeat(ch, 96)
}

pub(crate) fn hex64(ch: char) -> String {
    hex_repeat(ch, 64)
}

/// A ReleaseManifest in the publisher's canonical object shape.
pub(crate) fn manifest(schema: &str, measurements: &[(&str, &str)]) -> Value {
    let measurements: Vec<Value> = measurements
        .iter()
        .map(|(t, v)| json!({"type": t, "value": v}))
        .collect();
    json!({"schemaVersion": schema, "measurements": measurements})
}

/// Canonical (RFC 8785 JCS) JSON, the form `json.marshal` produces and the
/// form the publisher signs over.
pub(crate) fn jcs_compact(value: &Value) -> String {
    super::super::transparency::dsse::canonical_json(value).expect("canonical JSON serialize")
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    sha2::Digest::update(&mut h, bytes);
    hex::encode(sha2::Digest::finalize(h))
}

// --- TDX appraisal input builders ------------------------------------------

/// A minimal TDX claims input whose event log contains `events` and whose quote
/// body carries the default non-debug `td_attributes` (SEPT #VE bit set).
pub(crate) fn tdx_input(events: &[Value]) -> String {
    tdx_input_with_body(Value::Null, events)
}

/// [`tdx_input`] with `body_extra` keys merged into the quote body.
pub(crate) fn tdx_input_with_body(body_extra: Value, events: &[Value]) -> String {
    tdx_input_full(body_extra, Value::Null, events)
}

/// [`tdx_input`] plus `tdx_extra` keys merged into the `tdx` object (e.g. the
/// flat `nvidia_gpu.0` claims), or a synthetic `tcb_verification` claim.
pub(crate) fn tdx_input_full(body_extra: Value, tdx_extra: Value, events: &[Value]) -> String {
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
                "vendor_id": TDX_VENDOR_ID,
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

/// A TDX input with an explicit `mr_td` (only when given) and
/// `td_attributes`.
pub(crate) fn tdx_quote_input(
    mr_td: Option<&str>,
    td_attributes: &str,
    events: &[Value],
) -> String {
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

// --- Evidence event builders ----------------------------------------------

/// A PAI `AAEL` `kangaroo/pull-image` event for an explicit image reference.
pub(crate) fn aael_event_for_reference(reference: &str, digest: &str) -> Value {
    json!({
        "type_name": "EV_EVENT_TAG",
        "details": {
            "unicode_name": "AAEL",
            "data": {
                "domain": "alibabacloud.com",
                "operation": "kangaroo/pull-image",
                "content": {
                    "reference": reference,
                    "digest": digest,
                },
            },
        },
    })
}

/// A PAI `AAEL` pull-image event for `cmaas-runtime`.
pub(crate) fn aael_event(digest: &str) -> Value {
    aael_event_for_reference("registry.example.com/ns/cmaas-runtime:latest", digest)
}

/// A PAI `AAEL` `pai/load-model` event.
pub(crate) fn load_model_event(model_id: &str, hash: &str) -> Value {
    json!({
        "type_name": "EV_EVENT_TAG",
        "details": {
            "unicode_name": "AAEL",
            "data": {
                "domain": "alibabacloud.com",
                "operation": "pai/load-model",
                "content": {"model-id": model_id, "hash": hash},
            },
        },
    })
}

/// A PAI `AAEL` `gpu/attestation` event with the two result codes.
pub(crate) fn gpu_attestation_event(collect: i64, attest: i64) -> Value {
    json!({
        "type_name": "EV_EVENT_TAG",
        "details": {
            "unicode_name": "AAEL",
            "data": {
                "domain": "alibabacloud.com",
                "operation": "gpu/attestation",
                "content": {
                    "gpu-collect-evidence-result-code": collect,
                    "gpu-attest-result-code": attest,
                },
            },
        },
    })
}

/// A `td_payload` firmware-blob2 event at `index` carrying a SHA-384 digest.
pub(crate) fn td_payload_event(event_b64: &str, digest: &str, index: i64) -> Value {
    json!({
        "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
        "details": {"string": "td_payload"},
        "event": event_b64,
        "digests": [{"alg": "SHA-384", "digest": digest}],
        "index": index,
    })
}

/// A `td_payload_info` platform-config-flags event carrying a one-line
/// `verity-root` dm-mod.create mapping for `root`.
pub(crate) fn rootfs_event_message(root: &str) -> String {
    format!(
        "td_payload_info reboot=k root=/dev/vda1 dm-mod.create=\"verity-root,,,ro,0 1011712 verity 1 /dev/vda1 /dev/vda2 4096 4096 126464 0 sha256 {root} {tail};\"",
        tail = "0".repeat(64)
    )
}

/// A `td_payload_info` event at RTMR1 (or `index` if given) for `root`.
pub(crate) fn rootfs_event(index: Option<i64>, root: &str) -> Value {
    let mut e = json!({
        "type_name": "EV_PLATFORM_CONFIG_FLAGS",
        "details": {"string": rootfs_event_message(root)},
    });
    if let Some(index) = index {
        e["index"] = json!(index);
    }
    e
}

/// A `td_payload` firmware-blob2 event with an arbitrary digest list.
pub(crate) fn kernel_event(index: Option<i64>, digests: Value) -> Value {
    let mut e = json!({
        "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
        "details": {"string": "td_payload"},
        "digests": digests,
    });
    if let Some(index) = index {
        e["index"] = json!(index);
    }
    e
}

/// A SHA-384 digest list for [`kernel_event`].
pub(crate) fn sha384_digests(digest: &str) -> Value {
    json!([{"alg": "SHA-384", "digest": digest}])
}

/// A UKI `EV_EFI_BOOT_SERVICES_APPLICATION` event carrying a SHA-384 digest.
pub(crate) fn uki_event(digest: &str) -> Value {
    json!({
        "type_name": "EV_EFI_BOOT_SERVICES_APPLICATION",
        "details": {"device_paths": ["File(\\EFI\\BOOT\\BOOTX64.EFI)"]},
        "index": 1,
        "digests": [{"alg": "SHA-384", "digest": digest}],
    })
}

// --- Fixture loaders -------------------------------------------------------

/// The `uefi_event_logs` array parsed from the real PAI CC event-log fixture.
pub(crate) fn pai_event_log_events() -> Vec<Value> {
    let ccel: eventlog::CcEventLog = fixtures::TDX_CCEL_DATA_PAI
        .to_vec()
        .try_into()
        .expect("parse real PAI CC event log");
    let parsed = serde_json::to_value(&ccel).expect("serialize parsed CC event log");
    parsed["uefi_event_logs"]
        .as_array()
        .expect("parsed event log carries uefi_event_logs")
        .clone()
}

/// A TDX appraisal input carrying the real PAI event log.
pub(crate) fn pai_tdx_input() -> String {
    tdx_input(&pai_event_log_events())
}

/// The matched `(release_manifest, log_entry, entry_url, log_index)` tuple of
/// the cmaas evidence fixture.
pub(crate) fn cmaas_transparency_tuple() -> (Value, Value, String, i64) {
    let evidence: Value =
        serde_json::from_str(fixtures::CMAAS_EVIDENCE_WITH_REKOR_V1_TRANSPARENCY_JSON)
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

/// A Rekor `GET /api/v1/log/entries` response body: `{uuid: entry}`.
pub(crate) fn rekor_entries_body(log_entry: &Value) -> String {
    let uuid = "00000000-0000-0000-0000-000000000000";
    json!({ uuid: log_entry }).to_string()
}

/// A TDX appraisal input carrying the image measurement of the fixture
/// manifest.
pub(crate) fn cmaas_tdx_input(manifest: &Value) -> String {
    let digest = manifest["measurements"][0]["value"]
        .as_str()
        .expect("fixture manifest measurement value");
    tdx_input(&[aael_event(digest)])
}

/// The artifact-server `resolve` response body carrying the fixture entry and
/// both verifiers.
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) fn resolve_response_body(
    manifest: &Value,
    log_entry: &Value,
    entry_url: &str,
) -> String {
    json!({
        "status": "resolved",
        "release_manifest": manifest,
        "log_entries": [{
            "type": "rekor-v1",
            "url": entry_url,
            "log_entry": log_entry,
            "entry_verifier": {"type": "public_key", "content": DSSE_PUBLISHER_PUB_KEY_PEM},
            "log_verifier": {"public_key_pem": SIGSTORE_REKOR_V1_PUB_KEY_PEM}
        }]
    })
    .to_string()
}

// --- Transparency config builders -----------------------------------------

/// Wrap a module value as a `transparency_log` entry.
pub(crate) fn transparency_entry(value: Value) -> Value {
    json!({"type": "transparency_log", "value": value})
}

/// A `transparency_log` entry value with a rekor-v1 primary.
pub(crate) fn rekor_entry_value(published_measurements: &[&str], log_index: i64) -> Value {
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

/// A `transparency_log` entry value with an artifact-server primary.
pub(crate) fn artifact_entry_value(
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

// --- Policy rendering helpers ---------------------------------------------

/// Render a modules policy from a parsed config and injected resolved rekor
/// data, without network I/O. `resolved` holds one slot per transparency entry,
/// in flatten order. The slots are attached to the parsed module tree before
/// the pure render phase runs.
pub(in crate::tee::coco::converter::builtin::policies) fn render_modules(
    config: &ModuleGroupsConfig,
    resolved: &[Option<ResolvedRekor>],
) -> String {
    let mut groups = parse_module_groups(config).expect("parse modules policy");
    attach_resolved(&mut groups, resolved);
    render_modules_policy(&groups).expect("render modules policy")
}

/// Attach injected resolved data to the transparency entries of a parsed
/// module tree, in flatten order.
fn attach_resolved(groups: &mut [Vec<Module>], resolved: &[Option<ResolvedRekor>]) {
    let mut slots = resolved.iter();
    for module in groups.iter_mut().flatten() {
        if let Module::TransparencyLog { resolved: slot, .. } = module {
            *slot = slots
                .next()
                .expect("resolved data for every transparency_log entry")
                .clone();
        }
    }
    assert!(
        slots.next().is_none(),
        "no resolved data left over after every transparency_log entry"
    );
}

/// [`render_modules`] from a JSON entries value.
pub(in crate::tee::coco::converter::builtin::policies) fn render_modules_json(
    entries: Value,
    resolved: &[Option<ResolvedRekor>],
) -> String {
    let cfg: ModuleGroupsConfig = serde_json::from_value(entries).expect("modules config parses");
    render_modules(&cfg, resolved)
}

/// Render a modules policy holding one rekor-v1 transparency entry for
/// `published`.
pub(in crate::tee::coco::converter::builtin::policies) fn render_rekor(
    published: &[&str],
    resolved: &ResolvedRekor,
) -> String {
    render_modules_json(
        json!([transparency_entry(rekor_entry_value(published, 1))]),
        &[Some(resolved.clone())],
    )
}

/// The `(quote, cc_eventlog)` strings of the cmaas evidence fixture.
pub(crate) fn cmaas_fixture_quote_and_eventlog() -> (String, String) {
    let fixture: Value =
        serde_json::from_str(fixtures::CMAAS_EVIDENCE_WITH_REKOR_V1_TRANSPARENCY_JSON)
            .expect("parse evidence fixture");
    let ev = &fixture["evidence"];
    (
        ev["quote"].as_str().expect("quote").to_string(),
        ev["cc_eventlog"].as_str().expect("cc_eventlog").to_string(),
    )
}

// --- DSSE signing helpers --------------------------------------------------

/// Build the resolved rekor data for a manifest: its JCS payload hash and a
/// DSSE signature bound to the fixed test publisher key.
#[cfg(feature = "crypto-rustcrypto")]
pub(in crate::tee::coco::converter::builtin::policies) fn resolved_from_manifest(
    manifest: &Value,
) -> ResolvedRekor {
    let payload_hash = sha256_hex(jcs_compact(manifest).as_bytes());
    let (dsse_signature, publisher_key) = sign_dsse_for_manifest(manifest);
    ResolvedRekor {
        payload_hash,
        dsse_signature,
        publisher_key,
    }
}

/// Sign a manifest with a fixed test P-256 key and return
/// `(dsse_signature_b64, publisher_key_pem)`.
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) fn sign_dsse_for_manifest(manifest: &Value) -> (String, String) {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    use p256::ecdsa::signature::Signer;

    // Fixed deterministic test signing key (RFC 6979 nonce).
    let secret_bytes: [u8; 32] = [0x42; 32];
    let signing_key =
        p256::ecdsa::SigningKey::from_bytes((&secret_bytes).into()).expect("fixed test key valid");
    let payload = jcs_compact(manifest);
    let pae = super::super::transparency::dsse::dsse_pae(
        super::super::transparency::dsse::DSSE_PAYLOAD_TYPE,
        payload.as_bytes(),
    );
    let sig: p256::ecdsa::Signature = signing_key.sign(&pae);
    let sig_b64 = BASE64_STANDARD.encode(sig.to_der());
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let sec1 = verifying_key.to_sec1_bytes();
    // P-256 SPKI DER: SEQUENCE { AlgId(ecPublicKey, prime256v1),
    // BIT STRING(0x00 || SEC1 point) }.
    let prefix: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let mut spki = Vec::with_capacity(prefix.len() + sec1.len());
    spki.extend_from_slice(&prefix);
    spki.extend_from_slice(&sec1);
    let b64 = BASE64_STANDARD.encode(&spki);
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n");
    (sig_b64, pem)
}

// --- Invocation helpers ----------------------------------------------------

/// Evaluate a Rego policy against `input` and return the four AR4SI
/// trust-vector values as (executables, hardware, configuration, file_system).
pub(crate) async fn eval_policy_vector(policy: &str, input: &str) -> (i8, i8, i8, i8) {
    use attestation_service::policy_engine::PolicyEngine as _;
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
    // sha256 during the behavior tests. Under `crypto-rustcrypto`,
    // `tng.verify_dsse_signature` is injected too; see
    // `builtin_as_host_await_functions`.
    .with_extra_extension_functions(super::super::host_fns::builtin_as_host_await_functions());
    // The four rules our templates define. The real AS also queries four more
    // AR4SI claims (instance-identity, runtime-opaque, ...); those are simply
    // skipped when a policy leaves them undefined, so they need not be queried.
    let rules = vec![
        "executables".to_string(),
        "hardware".to_string(),
        "configuration".to_string(),
        "file_system".to_string(),
    ];
    // The upstream `PolicyEngine::evaluate` resolves Rego
    // `query_reference_value(...)` calls through a `ReferenceValueResolver`.
    // None of these templates query reference values, so an empty in-memory
    // RVPS resolver suffices.
    let resolver = Arc::new(attestation_service::rvps::ReferenceValueResolver::new(
        Arc::new(rvps) as Arc<dyn attestation_service::rvps::RvpsApi>,
    ));
    let result = engine
        .evaluate(input, super::super::DEFAULT_POLICY_ID, rules, resolver)
        .await
        .expect("evaluate policy");
    let get = |name: &str| -> i8 {
        result
            .rules_result
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

/// Call an `ExtensionFunction` closure the same way the regorus VM does: the
/// closure takes an owned `regorus::Value` and returns a boxed future.
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) async fn invoke_extension(
    hv: &attestation_service::policy_engine::opa::ExtensionFunction,
    arg: regorus::Value,
) -> regorus::Value {
    let hv = hv.clone();
    hv(arg).await.expect("host-await call must succeed")
}

//! Test-only policy harness: parse/render helpers and OPA evaluation.
//!
//! Everything here is compiled only under `cfg(test)`. The helpers need
//! visibility into [`modules`](super::modules), so they live beside it rather
//! than with the shared fixtures.

use super::super::policy_config::ModuleGroupsConfig;
#[cfg(feature = "crypto-rustcrypto")]
use super::super::test_fixtures::{jcs_compact, sha256_hex};
use super::super::test_fixtures::{rekor_entry_value, transparency_entry};
use super::super::transparency::{RekorBaseline, VerifiedRekorEntry};
use super::modules::{
    parse_module_groups, prepare_module_groups, render_modules_policy, ModuleEntry,
};
use serde_json::{json, Value};

// --- Policy rendering helpers ---------------------------------------------

/// Render a modules policy from a parsed config and injected resolved rekor
/// data, without network I/O. `resolved` holds one slot per transparency entry,
/// in flatten order. The slots are attached to the parsed module tree before
/// the pure render phase runs.
pub(in crate::tee::coco::converter::builtin::policies) fn render_modules(
    config: &ModuleGroupsConfig,
    resolved: &[Option<RekorBaseline>],
) -> String {
    let mut groups = parse_module_groups(config).expect("parse modules policy");
    prepare_module_groups(&mut groups).expect("prepare modules policy");
    attach_resolved(&mut groups, resolved);
    render_modules_policy(&groups).expect("render modules policy")
}

/// Attach injected resolved data to the transparency entries of a parsed
/// module tree, in flatten order.
fn attach_resolved(groups: &mut [Vec<ModuleEntry>], resolved: &[Option<RekorBaseline>]) {
    let mut slots = resolved.iter();
    for module in groups.iter_mut().flatten() {
        if let ModuleEntry::TransparencyLog { resolved: slot, .. } = module {
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
    resolved: &[Option<RekorBaseline>],
) -> String {
    let cfg: ModuleGroupsConfig = serde_json::from_value(entries).expect("modules config parses");
    render_modules(&cfg, resolved)
}

/// Render a modules policy holding one rekor-v1 transparency entry for
/// `published`.
pub(in crate::tee::coco::converter::builtin::policies) fn render_rekor(
    published: &[&str],
    resolved: &RekorBaseline,
) -> String {
    render_modules_json(
        json!([transparency_entry(rekor_entry_value(published, 1))]),
        &[Some(resolved.clone())],
    )
}

// --- DSSE signing helpers --------------------------------------------------

/// Build the resolved rekor data for a manifest: its JCS payload hash and a
/// DSSE signature bound to the fixed test publisher key.
#[cfg(feature = "crypto-rustcrypto")]
pub(in crate::tee::coco::converter::builtin::policies) fn resolved_from_manifest(
    manifest: &Value,
) -> RekorBaseline {
    let payload_hash = sha256_hex(jcs_compact(manifest).as_bytes());
    let (dsse_signature, publisher_key) = sign_dsse_for_manifest(manifest);
    RekorBaseline {
        entry: VerifiedRekorEntry {
            payload_hash,
            dsse_signature,
        },
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
    // `tng.verify_dsse_signature` is injected too. Each evaluation gets a
    // fresh cache instance so tests cannot pollute one another.
    .with_extra_extension_functions(super::super::host_fns::builtin_as_host_await_functions(
        Arc::new(super::super::transparency::TransparencyCaches::new()),
    ));
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

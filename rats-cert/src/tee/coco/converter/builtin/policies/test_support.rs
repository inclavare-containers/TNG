//! Shared Rego evaluation helpers for the builtin policy tests.
//!
//! The `modules` and `transparency_log` test modules both build a policy and
//! evaluate it through the same in-memory AS engine, so the fixtures live here
//! instead of inside either policy module.

/// Evaluate a bundled rego policy against `input` and return the four AR4SI
/// trust-vector values as (executables, hardware, configuration, file_system).
pub(super) async fn eval_policy_vector(policy: &str, input: &str) -> (i8, i8, i8, i8) {
    eval_policy_vector_with_rvs(policy, input, &[]).await
}

/// Same as [`eval_policy_vector`], but first registers each `(name, value)`
/// pair as a sample reference value in the in-memory RVPS so policies that
/// call `query_reference_value` resolve against real data.
pub(super) async fn eval_policy_vector_with_rvs(
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
pub(super) async fn eval_policy_extensions(policy: &str, input: &str) -> Option<serde_json::Value> {
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

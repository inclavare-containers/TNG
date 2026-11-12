//! Test-only helpers shared by the `modules` and `transparency_log` policy
//! test modules.

/// Evaluate a bundled rego policy against `input` and return the four AR4SI
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
    // sha256 during the behavior test below. Under `crypto-rustcrypto`,
    // `tng.verify_dsse_signature` is injected too; see
    // `builtin_as_host_await_functions`.
    .with_extra_extension_functions(
        crate::tee::coco::converter::builtin::host_fns::builtin_as_host_await_functions(),
    );
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

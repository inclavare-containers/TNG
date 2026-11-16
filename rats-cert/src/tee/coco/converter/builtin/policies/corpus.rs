//! Data-driven equivalence corpus for the builtin policy semantics.
//!
//! Every case pins a policy configuration, an appraisal input, and the four
//! AR4SI trust-vector values the appraisal must produce. The corpus is the
//! executable definition of "semantics unchanged": a refactor of the converter
//! must keep every expected value here without editing the table.
//!
//! Bundled templates and `modules` entries run against evidence constructed in
//! memory. `transparency_log` cases use the resolved-data injection seam for a
//! rekor-v1 primary and a local wiremock server for an artifact-server primary,
//! so no case touches the network. Every evaluation gets a fresh cache, so the
//! artifact-server cases run independently.

use super::test_support::{
    aael_event, artifact_entry_value, cmaas_tdx_input, cmaas_transparency_tuple,
    eval_policy_vector, gpu_attestation_event, hex64, hex96, load_model_event, manifest,
    pai_tdx_input, rekor_entries_body, rekor_entry_value, render_modules_json,
    resolve_response_body, resolved_from_manifest, rootfs_event, sha384_digests, td_payload_event,
    tdx_input, tdx_input_full, tdx_input_with_body, transparency_entry, uki_event, TDX_VENDOR_ID,
};
use serde_json::{json, Value};

type Vector = (i8, i8, i8, i8);

const AFFIRM: Vector = (2, 2, 2, 2);
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// How a corpus case produces its Rego source.
enum PolicySpec {
    /// A bundled template evaluated verbatim.
    Bundled(&'static str),
    /// A `modules` config with no `transparency_log` entry.
    Modules(Value),
    /// A single rekor-v1 `transparency_log` entry, with the resolved data
    /// derived from `manifest`.
    Rekor {
        entry: Value,
        manifest: Value,
        payload_hash_override: Option<&'static str>,
    },
    /// A single artifact-server `transparency_log` entry. URLs and the log
    /// index are substituted from the local mock servers at run time.
    Artifact {
        entry: Value,
        primary: MockResponse,
        fallback: Option<MockResponse>,
    },
}

#[derive(Clone, Copy)]
enum MockResponse {
    Resolved,
    ServerError,
    Revoked,
}

struct Case {
    name: &'static str,
    policy: PolicySpec,
    input: Value,
    expected: Vector,
}

fn entry(module_type: &str, value: Value) -> Value {
    json!({"type": module_type, "value": value})
}

fn input_of(rendered: String) -> Value {
    serde_json::from_str(&rendered).expect("corpus input is JSON")
}

fn cases() -> Vec<Case> {
    let hardware_only = include_str!("static/hardware_only.rego");
    let hardware_only_strict = include_str!("static/hardware_only_strict.rego");
    let trust_all = include_str!("static/trust_all.rego");

    // Bind every pin as `&str`: the table reuses them, and `json!` copies a
    // borrowed string instead of moving it.
    let pins = (
        hex96('a'),
        hex96('b'),
        hex96('c'),
        hex96('d'),
        hex64('a'),
        format!("sha256:{}", hex64('a')),
        format!("sha256:{}", hex64('b')),
        format!("sha256:{}", hex64('c')),
        hex64('b'),
        hex96('3'),
    );
    let (td_shim, ovmf, kernel, uki, rootfs, image_a, image_b, image_c, model, nvidia_measurement) = (
        pins.0.as_str(),
        pins.1.as_str(),
        pins.2.as_str(),
        pins.3.as_str(),
        pins.4.as_str(),
        pins.5.as_str(),
        pins.6.as_str(),
        pins.7.as_str(),
        pins.8.as_str(),
        pins.9.as_str(),
    );

    let tdx_recognized = json!({
        "tdx": {"quote": {"header": {"tee_type": "81000000", "vendor_id": TDX_VENDOR_ID}}}
    });
    let tdx_wrong_vendor = json!({
        "tdx": {"quote": {"header": {"tee_type": "81000000", "vendor_id": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}}
    });
    let strict_ok = json!({
        "tdx": {
            "quote": {"header": {"tee_type": "81000000", "vendor_id": TDX_VENDOR_ID},
                      "body": {"td_attributes": "0000001000000080"}},
            "uefi_event_logs": [{"event": "ok"}]
        }
    });
    let strict_debug = json!({
        "tdx": {
            "quote": {"header": {"tee_type": "81000000", "vendor_id": TDX_VENDOR_ID},
                      "body": {"td_attributes": "0100001000000080"}},
            "uefi_event_logs": [{"event": "ok"}]
        }
    });
    let strict_no_eventlog = json!({
        "tdx": {
            "quote": {"header": {"tee_type": "81000000", "vendor_id": TDX_VENDOR_ID},
                      "body": {"td_attributes": "0000001000000080"}}
        }
    });

    let ok_event = json!({"event": "ok"});
    let nvidia_claims = json!({
        "nvidia_gpu.0": {
            "uuid": "GPU-x", "name": "L20C", "driver_version": "570.148.05",
            "vbios_version": "96.00.f4", "cc_enabled": true,
            "measurement": nvidia_measurement,
        }
    });
    let nvidia_raw_skip = json!({
        "nvidia_gpu.0": {
            "index": 0, "uuid": "GPU-x", "cc_enabled": true,
            "attestation_report": "BASE64",
        }
    });

    let image_entry = |published: &[&str], log_index: i64| rekor_entry_value(published, log_index);
    let rekor = |entry: Value, manifest: Value, payload_hash_override: Option<&'static str>| {
        PolicySpec::Rekor {
            entry,
            manifest,
            payload_hash_override,
        }
    };

    vec![
        // --- bundled templates --------------------------------------------
        Case {
            name: "hardware_only/tdx",
            policy: PolicySpec::Bundled(hardware_only),
            input: tdx_recognized.clone(),
            expected: AFFIRM,
        },
        Case {
            name: "hardware_only/csv",
            policy: PolicySpec::Bundled(hardware_only),
            input: json!({"csv": {"version": "2"}}),
            expected: AFFIRM,
        },
        Case {
            name: "hardware_only/unrecognized",
            policy: PolicySpec::Bundled(hardware_only),
            input: json!({}),
            expected: (2, 97, 2, 2),
        },
        Case {
            name: "hardware_only/wrong-vendor",
            policy: PolicySpec::Bundled(hardware_only),
            input: tdx_wrong_vendor.clone(),
            expected: (2, 97, 2, 2),
        },
        Case {
            name: "hardware_only_strict/valid",
            policy: PolicySpec::Bundled(hardware_only_strict),
            input: strict_ok,
            expected: AFFIRM,
        },
        Case {
            name: "hardware_only_strict/debug",
            policy: PolicySpec::Bundled(hardware_only_strict),
            input: strict_debug,
            expected: (2, 97, 2, 2),
        },
        Case {
            name: "hardware_only_strict/no-eventlog",
            policy: PolicySpec::Bundled(hardware_only_strict),
            input: strict_no_eventlog,
            expected: (2, 97, 2, 2),
        },
        Case {
            name: "trust_all/empty",
            policy: PolicySpec::Bundled(trust_all),
            input: json!({}),
            expected: AFFIRM,
        },
        Case {
            name: "trust_all/bad-tdx",
            policy: PolicySpec::Bundled(trust_all),
            input: tdx_wrong_vendor,
            expected: AFFIRM,
        },
        // --- modules: measurement entries ---------------------------------
        Case {
            name: "modules/tdx.td-shim-match",
            policy: PolicySpec::Modules(json!([entry("tdx.td-shim", json!(td_shim))])),
            input: input_of(tdx_input_with_body(json!({"mr_td": td_shim}), &[])),
            expected: AFFIRM,
        },
        Case {
            name: "modules/tdx.td-shim-mismatch",
            policy: PolicySpec::Modules(json!([entry("tdx.td-shim", json!(td_shim))])),
            input: input_of(tdx_input_with_body(json!({"mr_td": hex96('9')}), &[])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "modules/tdx.ovmf-match",
            policy: PolicySpec::Modules(json!([entry("tdx.ovmf", json!(ovmf))])),
            input: input_of(tdx_input_with_body(json!({"mr_td": ovmf}), &[])),
            expected: AFFIRM,
        },
        Case {
            name: "modules/tdx.ovmf-mismatch",
            policy: PolicySpec::Modules(json!([entry("tdx.ovmf", json!(ovmf))])),
            input: input_of(tdx_input_with_body(json!({"mr_td": hex96('9')}), &[])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "modules/tdx.kernel-match",
            policy: PolicySpec::Modules(json!([entry("tdx.kernel", json!(kernel))])),
            input: input_of(tdx_input(&[td_payload_event("AAAA", kernel, 2)])),
            expected: AFFIRM,
        },
        Case {
            name: "modules/tdx.kernel-mismatch",
            policy: PolicySpec::Modules(json!([entry("tdx.kernel", json!(kernel))])),
            input: input_of(tdx_input(&[td_payload_event("AAAA", &hex96('9'), 2)])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "modules/tdx.uki-match",
            policy: PolicySpec::Modules(json!([entry("tdx.uki", json!(uki))])),
            input: input_of(tdx_input(&[uki_event(uki)])),
            expected: AFFIRM,
        },
        Case {
            name: "modules/tdx.uki-mismatch",
            policy: PolicySpec::Modules(json!([entry("tdx.uki", json!(uki))])),
            input: input_of(tdx_input(&[uki_event(&hex96('9'))])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "modules/rootfs.cc-match",
            policy: PolicySpec::Modules(json!([entry("rootfs.cc", json!(rootfs))])),
            input: input_of(tdx_input(&[rootfs_event(Some(2), rootfs)])),
            expected: AFFIRM,
        },
        Case {
            name: "modules/rootfs.cc-mismatch",
            policy: PolicySpec::Modules(json!([entry("rootfs.cc", json!(rootfs))])),
            input: input_of(tdx_input(&[rootfs_event(Some(2), &hex64('b'))])),
            expected: (2, 2, 2, 97),
        },
        Case {
            name: "modules/container.image-single-match",
            policy: PolicySpec::Modules(json!([entry(
                "container.image.runtime",
                json!(image_a)
            )])),
            input: input_of(tdx_input(&[aael_event_for_repo("runtime", image_a)])),
            expected: AFFIRM,
        },
        Case {
            name: "modules/container.image-single-mismatch",
            policy: PolicySpec::Modules(json!([entry(
                "container.image.runtime",
                json!(image_a)
            )])),
            input: input_of(tdx_input(&[aael_event_for_repo("runtime", image_c)])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "modules/container.image-digest-set-match",
            policy: PolicySpec::Modules(json!([
                entry("container.image.runtime", json!(image_a)),
                entry("container.image.runtime", json!(image_b)),
            ])),
            input: input_of(tdx_input(&[
                aael_event_for_repo("runtime", image_a),
                aael_event_for_repo("runtime", image_b),
            ])),
            expected: AFFIRM,
        },
        Case {
            name: "modules/container.image-digest-set-missing",
            policy: PolicySpec::Modules(json!([
                entry("container.image.runtime", json!(image_a)),
                entry("container.image.runtime", json!(image_b)),
            ])),
            input: input_of(tdx_input(&[aael_event_for_repo("runtime", image_a)])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "modules/container.image-digest-set-extra",
            policy: PolicySpec::Modules(json!([
                entry("container.image.runtime", json!(image_a)),
                entry("container.image.runtime", json!(image_b)),
            ])),
            input: input_of(tdx_input(&[
                aael_event_for_repo("runtime", image_a),
                aael_event_for_repo("runtime", image_b),
                aael_event_for_repo("runtime", image_c),
            ])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "modules/ai.model-match",
            policy: PolicySpec::Modules(json!([entry(
                "ai.model.Qwen/Qwen3.8-27B",
                json!(model)
            )])),
            input: input_of(tdx_input(&[load_model_event("Qwen/Qwen3.8-27B", model)])),
            expected: AFFIRM,
        },
        Case {
            name: "modules/ai.model-mismatch",
            policy: PolicySpec::Modules(json!([entry(
                "ai.model.Qwen/Qwen3.8-27B",
                json!(model)
            )])),
            input: input_of(tdx_input(&[load_model_event("Qwen/Qwen3.8-27B", &hex64('c'))])),
            expected: (97, 2, 2, 2),
        },
        // --- modules: posture entries -------------------------------------
        Case {
            name: "modules/tdx-posture-pass",
            policy: PolicySpec::Modules(json!([entry("tdx", json!({}))])),
            input: input_of(tdx_input(std::slice::from_ref(&ok_event))),
            expected: AFFIRM,
        },
        Case {
            name: "modules/tdx-posture-debug",
            policy: PolicySpec::Modules(json!([entry("tdx", json!({}))])),
            input: input_of(tdx_input_with_body(
                json!({"td_attributes": "0100001000000000"}),
                std::slice::from_ref(&ok_event),
            )),
            expected: (2, 97, 2, 2),
        },
        Case {
            name: "modules/gpu-attestation-pass",
            policy: PolicySpec::Modules(json!([entry("com.alibabacloud.gpu", json!({}))])),
            input: input_of(tdx_input(&[gpu_attestation_event(0, 0)])),
            expected: AFFIRM,
        },
        Case {
            name: "modules/gpu-attestation-fail",
            policy: PolicySpec::Modules(json!([entry("com.alibabacloud.gpu", json!({}))])),
            input: input_of(tdx_input(&[gpu_attestation_event(0, 5)])),
            expected: (2, 97, 2, 2),
        },
        Case {
            name: "modules/nvidia-evaluated",
            policy: PolicySpec::Modules(json!([entry(
                "nvidia",
                json!({"min_count": 1, "allow_uuids": ["GPU-x"],
                       "measurement_digest": [nvidia_measurement]})
            )])),
            input: input_of(tdx_input_full(
                Value::Null,
                nvidia_claims,
                std::slice::from_ref(&ok_event),
            )),
            expected: AFFIRM,
        },
        Case {
            name: "modules/nvidia-raw-skip",
            policy: PolicySpec::Modules(json!([entry(
                "nvidia",
                json!({"min_count": 1, "allow_uuids": ["GPU-x"],
                       "measurement_digest": [nvidia_measurement]})
            )])),
            input: input_of(tdx_input_full(
                Value::Null,
                nvidia_raw_skip,
                std::slice::from_ref(&ok_event),
            )),
            expected: (2, 97, 2, 2),
        },
        Case {
            name: "modules/dimensions-independent",
            policy: PolicySpec::Modules(json!([
                [entry("tdx", json!({}))],
                [entry("tdx.ovmf", json!(ovmf))],
            ])),
            input: input_of(tdx_input_with_body(
                json!({"mr_td": ovmf, "td_attributes": "0100001000000000"}),
                &[ok_event],
            )),
            expected: (2, 97, 2, 2),
        },
        Case {
            name: "modules/cross-group-or-baseline-b",
            policy: PolicySpec::Modules(json!([
                [entry("tdx.kernel", json!(kernel))],
                [entry("tdx.td-shim", json!(td_shim))],
            ])),
            // Only group B matches; the executables dimension ORs the groups.
            input: input_of(tdx_input_with_body(json!({"mr_td": td_shim}), &[])),
            expected: AFFIRM,
        },
        Case {
            name: "modules/cross-group-or-no-baseline",
            policy: PolicySpec::Modules(json!([
                [entry("tdx.kernel", json!(kernel))],
                [entry("tdx.td-shim", json!(td_shim))],
            ])),
            input: input_of(tdx_input(&[])),
            expected: (97, 2, 2, 2),
        },
        // --- transparency_log: rekor-v1 primary ---------------------------
        Case {
            name: "transparency/rekor-image-match",
            policy: rekor(
                image_entry(&["container.image.cmaas-runtime"], 1),
                manifest(
                    "1.0.0",
                    &[(
                        "container.image.cmaas-runtime",
                        "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
                    )],
                ),
                None,
            ),
            input: input_of(tdx_input(&[aael_event(
                "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
            )])),
            expected: AFFIRM,
        },
        Case {
            name: "transparency/rekor-image-tampered",
            policy: rekor(
                image_entry(&["container.image.cmaas-runtime"], 1),
                manifest(
                    "1.0.0",
                    &[(
                        "container.image.cmaas-runtime",
                        "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
                    )],
                ),
                None,
            ),
            input: input_of(tdx_input(&[aael_event(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "transparency/rekor-image-missing",
            policy: rekor(
                image_entry(&["container.image.cmaas-runtime"], 1),
                manifest(
                    "1.0.0",
                    &[(
                        "container.image.cmaas-runtime",
                        "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
                    )],
                ),
                None,
            ),
            input: input_of(tdx_input(&[])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "transparency/rekor-td-shim-match",
            policy: rekor(
                image_entry(&["tdx.td-shim"], 1),
                manifest("1.0.0", &[("tdx.td-shim", td_shim)]),
                None,
            ),
            input: input_of(tdx_input_with_body(json!({"mr_td": td_shim}), &[])),
            expected: AFFIRM,
        },
        Case {
            name: "transparency/rekor-td-shim-mismatch",
            policy: rekor(
                image_entry(&["tdx.td-shim"], 1),
                manifest("1.0.0", &[("tdx.td-shim", td_shim)]),
                None,
            ),
            input: input_of(tdx_input_with_body(json!({"mr_td": hex96('9')}), &[])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "transparency/rekor-kernel-match",
            policy: rekor(
                image_entry(&["tdx.kernel"], 1),
                manifest("1.0.0", &[("tdx.kernel", kernel)]),
                None,
            ),
            input: input_of(tdx_input(&[td_payload_event("AAAA", kernel, 2)])),
            expected: AFFIRM,
        },
        Case {
            name: "transparency/rekor-rootfs-match",
            policy: rekor(
                image_entry(&["rootfs.cc"], 1),
                manifest("1.0.0", &[("rootfs.cc", rootfs)]),
                None,
            ),
            input: input_of(tdx_input(&[rootfs_event(Some(2), rootfs)])),
            expected: AFFIRM,
        },
        Case {
            name: "transparency/rekor-rootfs-tampered",
            policy: rekor(
                image_entry(&["rootfs.cc"], 1),
                manifest("1.0.0", &[("rootfs.cc", rootfs)]),
                None,
            ),
            input: input_of(tdx_input(&[rootfs_event(Some(2), &hex64('b'))])),
            expected: (2, 2, 2, 97),
        },
        Case {
            name: "transparency/rekor-image-digest-set-match",
            policy: rekor(
                image_entry(&["container.image.cmaas-runtime"], 1),
                manifest(
                    "1.0.0",
                    &[
                        ("container.image.cmaas-runtime", image_a),
                        ("container.image.cmaas-runtime", image_b),
                    ],
                ),
                None,
            ),
            input: input_of(tdx_input(&[
                aael_event(image_a),
                aael_event(image_b),
            ])),
            expected: AFFIRM,
        },
        Case {
            name: "transparency/rekor-image-digest-set-missing",
            policy: rekor(
                image_entry(&["container.image.cmaas-runtime"], 1),
                manifest(
                    "1.0.0",
                    &[
                        ("container.image.cmaas-runtime", image_a),
                        ("container.image.cmaas-runtime", image_b),
                    ],
                ),
                None,
            ),
            input: input_of(tdx_input(&[aael_event(image_a)])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "transparency/rekor-wrong-schema",
            policy: rekor(
                image_entry(&["container.image.cmaas-runtime"], 1),
                manifest(
                    "9.9.9",
                    &[(
                        "container.image.cmaas-runtime",
                        "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
                    )],
                ),
                None,
            ),
            input: input_of(tdx_input(&[aael_event(
                "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
            )])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "transparency/rekor-wrong-payload-hash",
            policy: rekor(
                image_entry(&["container.image.cmaas-runtime"], 1),
                manifest(
                    "1.0.0",
                    &[(
                        "container.image.cmaas-runtime",
                        "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
                    )],
                ),
                Some(ZERO_HASH),
            ),
            input: input_of(tdx_input(&[aael_event(
                "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
            )])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "transparency/rekor-declared-type-missing",
            policy: rekor(
                image_entry(
                    &["tdx.kernel", "container.image.cmaas-runtime"],
                    1,
                ),
                manifest(
                    "1.0.0",
                    &[(
                        "container.image.cmaas-runtime",
                        "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
                    )],
                ),
                None,
            ),
            input: input_of(tdx_input(&[aael_event(
                "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
            )])),
            expected: (97, 2, 2, 2),
        },
        // --- transparency_log: artifact-server primary --------------------
        Case {
            name: "transparency/artifact-primary-resolved",
            policy: PolicySpec::Artifact {
                entry: artifact_value(None),
                primary: MockResponse::Resolved,
                fallback: None,
            },
            input: input_of(tdx_input(&[aael_event(
                "sha256:f3cb13cd3ff3b772dd69eaa8d6b70fe945cfa423e55ab1b6fadd7e462db27852",
            )])),
            expected: AFFIRM,
        },
        Case {
            name: "transparency/artifact-primary-fail-no-fallback",
            policy: PolicySpec::Artifact {
                entry: artifact_value(None),
                primary: MockResponse::ServerError,
                fallback: None,
            },
            input: input_of(tdx_input(&[aael_event(
                "sha256:f3cb13cd3ff3b772dd69eaa8d6b70fe945cfa423e55ab1b6fadd7e462db27852",
            )])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "transparency/artifact-primary-fail-fallback-resolved",
            policy: PolicySpec::Artifact {
                entry: artifact_value(Some(MockResponse::Resolved)),
                primary: MockResponse::ServerError,
                fallback: Some(MockResponse::Resolved),
            },
            input: input_of(tdx_input(&[aael_event(
                "sha256:f3cb13cd3ff3b772dd69eaa8d6b70fe945cfa423e55ab1b6fadd7e462db27852",
            )])),
            expected: AFFIRM,
        },
        Case {
            name: "transparency/artifact-primary-revoked",
            policy: PolicySpec::Artifact {
                entry: artifact_value(Some(MockResponse::Resolved)),
                primary: MockResponse::Revoked,
                fallback: Some(MockResponse::Resolved),
            },
            input: input_of(tdx_input(&[aael_event(
                "sha256:f3cb13cd3ff3b772dd69eaa8d6b70fe945cfa423e55ab1b6fadd7e462db27852",
            )])),
            expected: (97, 2, 2, 2),
        },
        Case {
            name: "transparency/artifact-both-fail",
            policy: PolicySpec::Artifact {
                entry: artifact_value(Some(MockResponse::ServerError)),
                primary: MockResponse::ServerError,
                fallback: Some(MockResponse::ServerError),
            },
            input: input_of(tdx_input(&[aael_event(
                "sha256:f3cb13cd3ff3b772dd69eaa8d6b70fe945cfa423e55ab1b6fadd7e462db27852",
            )])),
            expected: (97, 2, 2, 2),
        },
        // --- the real PAI event log ---------------------------------------
        Case {
            name: "real-pai/container-image",
            policy: PolicySpec::Modules(json!([entry(
                "com.alibabacloud.container.image.busybox",
                json!("sha256:16ece118a36d152ed7562347741470b1bb0b0f7561ff1fe0049857a03d4fec5d")
            )])),
            input: input_of(pai_tdx_input()),
            expected: AFFIRM,
        },
        Case {
            name: "real-pai/kernel",
            policy: PolicySpec::Modules(json!([entry(
                "tdx.kernel",
                json!("85619a9146b5c1409bf034bdabd6d93df26a5a23b41b43f92a7a4025760a1c4f110194ae75a2b9625b0de97f2b00fc8f")
            )])),
            input: input_of(pai_tdx_input()),
            expected: AFFIRM,
        },
    ]
}

/// An AAEL pull-image event whose reference resolves to `repo`.
fn aael_event_for_repo(repo: &str, digest: &str) -> Value {
    super::test_support::aael_event_for_reference(
        &format!("registry.example.com/ns/{repo}:latest"),
        digest,
    )
}

/// The artifact-server entry value. URLs and the log index are placeholders
/// replaced with the local mock server coordinates at run time.
fn artifact_value(fallback: Option<MockResponse>) -> Value {
    let mut value = json!({
        "publishedMeasurements": ["container.image.cmaas-runtime"],
        "schemaVersion": "1.0.0",
        "services": [{
            "type": "artifact-server",
            "url": "{artifact_url}",
            "logServices": [{"type": "rekor-v1", "url": "{entry_url}"}],
        }],
    });
    if fallback.is_some() {
        value["fallbackPublishedMeasurements"] = json!(["container.image.cmaas-runtime"]);
        value["fallbackServices"] = json!([{
            "type": "rekor-v1",
            "logUrl": "{rekor_url}",
            "logIndex": "{log_index}",
        }]);
    }
    value
}

fn render_case(case: &Case) -> String {
    match &case.policy {
        PolicySpec::Bundled(source) => (*source).to_string(),
        PolicySpec::Modules(config) => render_modules_json(config.clone(), &[]),
        PolicySpec::Rekor {
            entry,
            manifest,
            payload_hash_override,
        } => {
            let mut resolved = resolved_from_manifest(manifest);
            if let Some(hash) = payload_hash_override {
                resolved.payload_hash = (*hash).to_string();
            }
            render_modules_json(
                json!([transparency_entry(entry.clone())]),
                &[Some(resolved)],
            )
        }
        PolicySpec::Artifact { .. } => {
            unreachable!("artifact-server cases are rendered by the mock test")
        }
    }
}

/// The artifact-server fallback manifest reconstructs through the same sorted
/// digest-set extraction as the full manifest. The artifact corpus runner uses
/// the fixed cmaas manifest, so this structural check keeps the shared
/// multi-digest expansion pinned for the fallback path too.
#[test]
fn transparency_artifact_fallback_manifest_expands_digest_sets() {
    let policy = render_modules_json(
        json!([transparency_entry(artifact_entry_value(
            "https://attest.example.com",
            "https://rekor.sigstore.dev",
            Some(("https://fallback.example.com", 1)),
        ))]),
        &[None],
    );
    for prefix in ["fallback", "full"] {
        let rule = format!(
            "t_0_0_{prefix}_manifest_entries_0 := entries if {{\n\tdigests := sort(actual_measurement_set(\"container.image.cmaas-runtime\"))"
        );
        assert!(
            policy.contains(&rule),
            "the {prefix} manifest must expand the image digest set through the sorted extraction: {policy}"
        );
    }
}

#[tokio::test]
async fn corpus_matches_expected_trust_vectors() {
    for case in cases()
        .into_iter()
        .filter(|case| !matches!(&case.policy, PolicySpec::Artifact { .. }))
    {
        let policy = render_case(&case);
        let actual = eval_policy_vector(&policy, &case.input.to_string()).await;
        assert_eq!(
            actual, case.expected,
            "corpus case {:?} changed; a semantic refactor must keep the expected vector",
            case.name
        );
    }
}

#[tokio::test]
async fn corpus_artifact_server_cases() {
    let (manifest, log_entry, entry_url, log_index) = cmaas_transparency_tuple();
    let resolve_body = resolve_response_body(&manifest, &log_entry, &entry_url);
    let rekor_body = rekor_entries_body(&log_entry);
    let artifact_input = cmaas_tdx_input(&manifest);

    for case in cases()
        .into_iter()
        .filter(|case| matches!(&case.policy, PolicySpec::Artifact { .. }))
    {
        let PolicySpec::Artifact {
            entry,
            primary,
            fallback,
        } = &case.policy
        else {
            unreachable!()
        };

        let primary_server = wiremock::MockServer::start().await;
        mount_resolve(&primary_server, *primary, &resolve_body).await;
        let rekor_uri = match fallback {
            Some(behavior) => {
                let server = wiremock::MockServer::start().await;
                mount_rekor(&server, *behavior, &rekor_body, log_index).await;
                Some(server.uri())
            }
            None => None,
        };

        let mut text = entry.to_string();
        text = text.replace("{artifact_url}", &primary_server.uri());
        text = text.replace("{entry_url}", &entry_url);
        text = text.replace("\"{log_index}\"", &log_index.to_string());
        if let Some(uri) = &rekor_uri {
            text = text.replace("{rekor_url}", uri);
        }
        let entry: Value = serde_json::from_str(&text).expect("render artifact entry");
        let policy = render_modules_json(json!([transparency_entry(entry)]), &[None]);
        let actual = eval_policy_vector(&policy, &artifact_input).await;
        assert_eq!(
            actual, case.expected,
            "artifact-server corpus case {:?} changed",
            case.name
        );
    }
}

async fn mount_resolve(server: &wiremock::MockServer, behavior: MockResponse, resolve_body: &str) {
    use wiremock::matchers::{method, path};
    let response = match behavior {
        MockResponse::Resolved => {
            wiremock::ResponseTemplate::new(200).set_body_string(resolve_body)
        }
        MockResponse::ServerError => {
            wiremock::ResponseTemplate::new(500).set_body_string("upstream error")
        }
        MockResponse::Revoked => wiremock::ResponseTemplate::new(403).set_body_string(
            json!({
                "error_code": "measurement_revoked",
                "error_message": "the measurement was revoked",
                "request_id": "corpus-revoked",
            })
            .to_string(),
        ),
    };
    wiremock::Mock::given(method("POST"))
        .and(path("/api/v1/transparency/resolve"))
        .respond_with(response)
        .mount(server)
        .await;
}

async fn mount_rekor(
    server: &wiremock::MockServer,
    behavior: MockResponse,
    rekor_body: &str,
    log_index: i64,
) {
    use wiremock::matchers::{method, path, query_param};
    let response = match behavior {
        MockResponse::Resolved => wiremock::ResponseTemplate::new(200).set_body_string(rekor_body),
        MockResponse::ServerError | MockResponse::Revoked => {
            wiremock::ResponseTemplate::new(500).set_body_string("rekor down")
        }
    };
    wiremock::Mock::given(method("GET"))
        .and(path("/api/v1/log/entries"))
        .and(query_param("logIndex", log_index.to_string()))
        .respond_with(response)
        .mount(server)
        .await;
}

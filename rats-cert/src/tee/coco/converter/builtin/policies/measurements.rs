//! The shared `actual_measurement(type)` extraction rules.
//!
//! Both the `modules` measurement entries and `transparency_log` manifest
//! reconstruction read the same per-type value through these rules, so the two
//! policies cannot disagree about what the evidence measured. A rendered policy
//! emits only the families it uses, and each helper at most once.

use std::collections::BTreeSet;

use super::modules::Module;

/// One measurement-extraction family. Families are emitted independently; a
/// policy selects the ones its measurement entries and transparency-log
/// declared types need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum MeasurementFamily {
    TdxTdShim,
    TdxOvmf,
    TdxKernel,
    TdxUki,
    ContainerImage,
    AiModel,
}

/// The set of families a policy needs, with deterministic emission order.
#[derive(Debug, Default, Clone)]
pub(super) struct Families(BTreeSet<MeasurementFamily>);

impl Families {
    pub(super) fn insert(&mut self, family: MeasurementFamily) {
        self.0.insert(family);
    }

    /// Add the families a transparency-log entry's declared published types
    /// need. Validation restricts those types to the families below, so an
    /// unrecognized spelling contributes nothing here (it is rejected earlier
    /// as a configuration error).
    pub(super) fn extend_published_types<'a>(
        &mut self,
        types: impl IntoIterator<Item = &'a String>,
    ) {
        for t in types {
            if let Some(family) = family_for_type(t) {
                self.0.insert(family);
            }
        }
    }

    /// The Rego extraction source for the selected families, or an empty
    /// string when none are selected.
    pub(super) fn rules(&self) -> String {
        if self.0.is_empty() {
            return String::new();
        }
        let mut parts: Vec<&str> = Vec::new();
        if self.0.contains(&MeasurementFamily::TdxKernel)
            || self.0.contains(&MeasurementFamily::TdxUki)
        {
            parts.push(HAS_SHA384_DIGEST);
        }
        if self.0.contains(&MeasurementFamily::ContainerImage) {
            parts.push(IMAGE_REPO_NAME);
        }
        for family in &self.0 {
            parts.push(family.rule());
        }
        let mut out = parts.join("\n\n");
        out.push('\n');
        out
    }
}

impl MeasurementFamily {
    fn rule(self) -> &'static str {
        match self {
            Self::TdxTdShim => TDX_TD_SHIM,
            Self::TdxOvmf => TDX_OVMF,
            Self::TdxKernel => TDX_KERNEL,
            Self::TdxUki => TDX_UKI,
            Self::ContainerImage => CONTAINER_IMAGE,
            Self::AiModel => AI_MODEL,
        }
    }
}

/// The family a measurement module entry extracts from. Posture and
/// transparency entries have no family of their own.
pub(super) fn family_of_module(module: &Module) -> Option<MeasurementFamily> {
    match module {
        Module::TdShim { .. } => Some(MeasurementFamily::TdxTdShim),
        Module::Ovmf { .. } => Some(MeasurementFamily::TdxOvmf),
        Module::Kernel { .. } => Some(MeasurementFamily::TdxKernel),
        Module::Uki { .. } => Some(MeasurementFamily::TdxUki),
        Module::ContainerImage { .. } => Some(MeasurementFamily::ContainerImage),
        Module::AiModel { .. } => Some(MeasurementFamily::AiModel),
        Module::Tdx(_) | Module::Nvidia(_) | Module::Gpu | Module::TransparencyLog(_) => None,
    }
}

/// The `actual_measurement` key for a measurement module entry. The two
/// Alibaba-coupled families drop their `com.alibabacloud.` prefix so the key
/// matches the transparency-log type spelling.
pub(super) fn measurement_key(module: &Module) -> Option<String> {
    match module {
        Module::TdShim { .. } => Some("tdx.td-shim".to_string()),
        Module::Ovmf { .. } => Some("tdx.ovmf".to_string()),
        Module::Kernel { .. } => Some("tdx.kernel".to_string()),
        Module::Uki { .. } => Some("tdx.uki".to_string()),
        Module::ContainerImage { repo, .. } => Some(format!("container.image.{repo}")),
        Module::AiModel { model_id, .. } => Some(format!("ai.model.{model_id}")),
        Module::Tdx(_) | Module::Nvidia(_) | Module::Gpu | Module::TransparencyLog(_) => None,
    }
}

/// The pinned value a measurement module entry compares against.
fn measurement_pin(module: &Module) -> Option<&str> {
    match module {
        Module::TdShim { value }
        | Module::Ovmf { value }
        | Module::Kernel { value }
        | Module::Uki { value } => Some(value),
        Module::ContainerImage { digest, .. } | Module::AiModel { digest, .. } => Some(digest),
        Module::Tdx(_) | Module::Nvidia(_) | Module::Gpu | Module::TransparencyLog(_) => None,
    }
}

/// The equality rule for a measurement module entry, or `None` for a posture
/// or transparency entry. The pinned value is spliced as a Rego string literal;
/// validation in the entry parser guarantees it contains no quoting hazard.
pub(super) fn predicate(module: &Module, pred: &str) -> Option<String> {
    let key = measurement_key(module)?;
    let pin = measurement_pin(module)?;
    Some(format!(
        "{pred} if {{\n\tactual_measurement({key:?}) == {pin:?}\n}}"
    ))
}

/// Map a transparency-log published type to its extraction family.
fn family_for_type(t: &str) -> Option<MeasurementFamily> {
    if t == "tdx.td-shim" {
        Some(MeasurementFamily::TdxTdShim)
    } else if t == "tdx.kernel" {
        Some(MeasurementFamily::TdxKernel)
    } else if t.starts_with("container.image.") {
        Some(MeasurementFamily::ContainerImage)
    } else {
        None
    }
}

const HAS_SHA384_DIGEST: &str = "\
has_sha384_digest(e) if {
\tsome d in e.digests
\td.alg == \"SHA-384\"
}";

const TDX_TD_SHIM: &str = "\
actual_measurement(\"tdx.td-shim\") := digest if {
\tdigest := input.tdx.quote.body.mr_td
}";

const TDX_OVMF: &str = "\
actual_measurement(\"tdx.ovmf\") := digest if {
\tdigest := input.tdx.quote.body.mr_td
}";

/// `td_payload` extends RTMR1, so every descriptor-matching event must sit at
/// register index 2. `not e.index == 2` also rejects an event with no index,
/// because the comparison is then undefined while the negation is true.
const TDX_KERNEL: &str = "\
actual_measurement(\"tdx.kernel\") := digest if {
\tevents := [e |
\t\tsome e in input.tdx.uefi_event_logs
\t\te.type_name == \"EV_EFI_PLATFORM_FIRMWARE_BLOB2\"
\t\te.details.string == \"td_payload\"
\t]
\tcount(events) > 0
\tbad_index := [e | some e in events; not e.index == 2]
\tcount(bad_index) == 0
\tevery e in events {
\t\thas_sha384_digest(e)
\t}
\tdigests := {d.digest |
\t\tsome e in events
\t\tsome d in e.digests
\t\td.alg == \"SHA-384\"
\t}
\tcount(digests) == 1
\tsome digest in digests
}";

const TDX_UKI: &str = "\
actual_measurement(\"tdx.uki\") := digest if {
\tevents := [e |
\t\tsome e in input.tdx.uefi_event_logs
\t\te.type_name == \"EV_EFI_BOOT_SERVICES_APPLICATION\"
\t]
\tcount(events) > 0
\tevery e in events {
\t\thas_sha384_digest(e)
\t}
\tdigests := {d.digest | some e in events; some d in e.digests; d.alg == \"SHA-384\"}
\tcount(digests) == 1
\tsome digest in digests
}";

const CONTAINER_IMAGE: &str = "\
actual_measurement(type) := digest if {
\tstartswith(type, \"container.image.\")
\trepo := trim_prefix(type, \"container.image.\")
\tevents := [e |
\t\tsome e in input.tdx.uefi_event_logs
\t\te.type_name == \"EV_EVENT_TAG\"
\t\te.details.unicode_name == \"AAEL\"
\t\te.details.data.domain == \"alibabacloud.com\"
\t\te.details.data.operation == \"kangaroo/pull-image\"
\t\timage_repo_name(e.details.data.content.reference) == repo
\t]
\tcount(events) > 0
\tevery e in events {
\t\te.details.data.content.digest
\t}
\tdigests := {e.details.data.content.digest | some e in events}
\tcount(digests) == 1
\tsome digest in digests
}";

const AI_MODEL: &str = "\
actual_measurement(type) := digest if {
\tstartswith(type, \"ai.model.\")
\tmodel_id := trim_prefix(type, \"ai.model.\")
\tevents := [e |
\t\tsome e in input.tdx.uefi_event_logs
\t\te.type_name == \"EV_EVENT_TAG\"
\t\te.details.unicode_name == \"AAEL\"
\t\te.details.data.domain == \"alibabacloud.com\"
\t\te.details.data.operation == \"pai/load-model\"
\t]
\tcount(events) > 0
\tevery e in events {
\t\te.details.data.content[\"model-id\"]
\t\te.details.data.content[\"hash\"]
\t}
\tmodel_ids := {e.details.data.content[\"model-id\"] | some e in events}
\tmodel_ids == {model_id}
\thashes := {e.details.data.content[\"hash\"] | some e in events}
\tcount(hashes) == 1
\tsome digest in hashes
}";

/// The repo tail of an image reference: last `/` segment, before any `:` tag or
/// `@` digest.
const IMAGE_REPO_NAME: &str = "\
image_repo_name(ref) := name if {
\tsegs := split(ref, \"/\")
\tlast := segs[count(segs) - 1]
\tname := split(split(last, \"@\")[0], \":\")[0]
}";

#[cfg(test)]
mod tests {
    use super::super::test_support::eval_policy_vector;
    use super::*;
    use serde_json::json;

    /// Wrap the selected rules in a minimal policy that affirms `executables`
    /// only when every `(key, expected)` binding holds.
    fn extraction_policy_for(families: &Families, bindings: &[(&str, &str)]) -> String {
        let mut body = String::new();
        for (key, expected) in bindings {
            body.push_str(&format!("\tactual_measurement({key:?}) == {expected:?}\n"));
        }
        format!(
            "package policy\n\nimport rego.v1\n\ndefault executables := 97\ndefault hardware := 2\ndefault configuration := 2\ndefault file_system := 2\n\n{}executables := 2 if {{\n{body}}}\n",
            families.rules()
        )
    }

    /// Wrap the selected rules in a minimal policy that affirms `executables`
    /// when `actual_measurement(key)` equals `expected`.
    fn extraction_policy(families: &Families, key: &str, expected: &str) -> String {
        extraction_policy_for(families, &[(key, expected)])
    }

    fn families(list: &[MeasurementFamily]) -> Families {
        let mut f = Families::default();
        for family in list {
            f.insert(*family);
        }
        f
    }

    fn tdx_input(events: &[serde_json::Value]) -> String {
        json!({
            "tdx": {
                "quote": {
                    "header": {"tee_type": "81000000", "vendor_id": "939a7233f79c4ca9940a0db3957f0607"},
                    "body": {"mr_td": "a".repeat(96)},
                },
                "uefi_event_logs": events,
            }
        })
        .to_string()
    }

    fn kernel_event(index: Option<i64>, digests: serde_json::Value) -> serde_json::Value {
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

    fn sha384(digest: &str) -> serde_json::Value {
        json!([{"alg": "SHA-384", "digest": digest}])
    }

    #[test]
    fn family_selection_drives_emission() {
        // No family: no extraction source at all.
        assert!(Families::default().rules().is_empty());

        // Static families need no helper.
        let shim = families(&[MeasurementFamily::TdxTdShim]).rules();
        assert!(shim.contains("actual_measurement(\"tdx.td-shim\") :="));
        assert!(!shim.contains("has_sha384_digest"));
        assert!(!shim.contains("image_repo_name"));

        // Kernel and uki share the digest helper, emitted once.
        let kernel_uki =
            families(&[MeasurementFamily::TdxKernel, MeasurementFamily::TdxUki]).rules();
        assert_eq!(kernel_uki.matches("has_sha384_digest(e) if {").count(), 1);
        assert_eq!(
            kernel_uki
                .matches("actual_measurement(\"tdx.kernel\")")
                .count(),
            1
        );
        assert_eq!(
            kernel_uki
                .matches("actual_measurement(\"tdx.uki\")")
                .count(),
            1
        );

        // The image family owns its repo-name helper, emitted once.
        let image = families(&[MeasurementFamily::ContainerImage]).rules();
        assert_eq!(image.matches("image_repo_name(ref) :=").count(), 1);
    }

    #[test]
    fn key_mapping_drops_the_vendor_prefix() {
        assert_eq!(
            MeasurementFamily::TdxKernel,
            family_of_module(&Module::Kernel {
                value: "a".repeat(96)
            })
            .unwrap()
        );
        let image = Module::ContainerImage {
            repo: "model-server".to_string(),
            digest: format!("sha256:{}", "c".repeat(64)),
        };
        assert_eq!(
            measurement_key(&image).unwrap(),
            "container.image.model-server"
        );
        let model = Module::AiModel {
            model_id: "Qwen/Qwen3.8-27B".to_string(),
            digest: "b".repeat(64),
        };
        assert_eq!(
            measurement_key(&model).unwrap(),
            "ai.model.Qwen/Qwen3.8-27B"
        );

        assert!(family_of_module(&Module::Gpu).is_none());
        assert!(measurement_key(&Module::Gpu).is_none());
        assert!(predicate(&Module::Gpu, "m_0_0").is_none());
    }

    #[test]
    fn predicate_is_a_single_equality() {
        let rule = predicate(
            &Module::Kernel {
                value: "a".repeat(96),
            },
            "m_0_1",
        )
        .unwrap();
        assert_eq!(
            rule,
            format!(
                "m_0_1 if {{\n\tactual_measurement(\"tdx.kernel\") == {:?}\n}}",
                "a".repeat(96)
            )
        );
    }

    #[tokio::test]
    async fn tdx_static_families_extract_mr_td() {
        for (family, key) in [
            (MeasurementFamily::TdxTdShim, "tdx.td-shim"),
            (MeasurementFamily::TdxOvmf, "tdx.ovmf"),
        ] {
            let pin = "a".repeat(96);
            let policy = extraction_policy(&families(&[family]), key, &pin);
            assert_eq!(
                eval_policy_vector(&policy, &tdx_input(&[])).await,
                (2, 2, 2, 2)
            );
            let missing = json!({"tdx": {"quote": {"header": {}, "body": {}}}}).to_string();
            assert_eq!(
                eval_policy_vector(&policy, &missing).await,
                (97, 2, 2, 2),
                "{key} must be undefined when mr_td is absent"
            );
        }
    }

    #[tokio::test]
    async fn kernel_positive_and_missing_fields() {
        let kernel = "a".repeat(96);
        let policy = extraction_policy(
            &families(&[MeasurementFamily::TdxKernel]),
            "tdx.kernel",
            &kernel,
        );

        let ok = tdx_input(&[kernel_event(Some(2), sha384(&kernel))]);
        assert_eq!(eval_policy_vector(&policy, &ok).await, (2, 2, 2, 2));

        let no_index = tdx_input(&[kernel_event(None, sha384(&kernel))]);
        assert_eq!(
            eval_policy_vector(&policy, &no_index).await,
            (97, 2, 2, 2),
            "a missing index must reject"
        );

        let bad_index = tdx_input(&[kernel_event(Some(1), sha384(&kernel))]);
        assert_eq!(
            eval_policy_vector(&policy, &bad_index).await,
            (97, 2, 2, 2),
            "a non-RTMR1 index must reject"
        );

        let missing_digest = tdx_input(&[kernel_event(
            Some(2),
            json!([{"alg": "SHA-256", "digest": "b".repeat(64)}]),
        )]);
        assert_eq!(
            eval_policy_vector(&policy, &missing_digest).await,
            (97, 2, 2, 2),
            "an event without a SHA-384 digest must reject"
        );

        let none = tdx_input(&[json!({"event": "ok"})]);
        assert_eq!(
            eval_policy_vector(&policy, &none).await,
            (97, 2, 2, 2),
            "no td_payload event must reject"
        );
    }

    #[tokio::test]
    async fn uki_positive_and_missing_digest() {
        let uki = "a".repeat(96);
        let policy = extraction_policy(&families(&[MeasurementFamily::TdxUki]), "tdx.uki", &uki);
        let event = |digests: serde_json::Value| {
            json!({
                "type_name": "EV_EFI_BOOT_SERVICES_APPLICATION",
                "digests": digests,
            })
        };

        let ok = tdx_input(&[event(sha384(&uki))]);
        assert_eq!(eval_policy_vector(&policy, &ok).await, (2, 2, 2, 2));

        let missing = tdx_input(&[event(json!([]))]);
        assert_eq!(
            eval_policy_vector(&policy, &missing).await,
            (97, 2, 2, 2),
            "an event without a SHA-384 digest must reject"
        );

        // One event carrying two SHA-384 digests is ambiguous even when one of
        // them matches the pin.
        let two_digests = tdx_input(&[event(json!([
            {"alg": "SHA-384", "digest": uki},
            {"alg": "SHA-384", "digest": "b".repeat(96)},
        ]))]);
        assert_eq!(
            eval_policy_vector(&policy, &two_digests).await,
            (97, 2, 2, 2),
            "one event with two SHA-384 digests must reject"
        );

        let empty = tdx_input(&[]);
        assert_eq!(
            eval_policy_vector(&policy, &empty).await,
            (97, 2, 2, 2),
            "no boot-application event must reject"
        );
    }

    #[tokio::test]
    async fn container_image_positive_and_untyped_event_rejected() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let policy = extraction_policy(
            &families(&[MeasurementFamily::ContainerImage]),
            "container.image.model-server",
            &digest,
        );
        let event = |type_name: Option<&str>, digest: &str| {
            let mut e = json!({
                "details": {
                    "unicode_name": "AAEL",
                    "data": {
                        "domain": "alibabacloud.com",
                        "operation": "kangaroo/pull-image",
                        "content": {
                            "reference": "registry.example.com/ns/model-server:latest",
                            "digest": digest,
                        },
                    },
                },
            });
            if let Some(type_name) = type_name {
                e["type_name"] = json!(type_name);
            }
            e
        };

        let ok = tdx_input(&[event(Some("EV_EVENT_TAG"), &digest)]);
        assert_eq!(eval_policy_vector(&policy, &ok).await, (2, 2, 2, 2));

        // Synthetic event without the EV_EVENT_TAG type no longer matches.
        let untyped = tdx_input(&[event(None, &digest)]);
        assert_eq!(
            eval_policy_vector(&policy, &untyped).await,
            (97, 2, 2, 2),
            "an AAEL event without EV_EVENT_TAG must not match"
        );

        let missing = tdx_input(&[json!({
            "type_name": "EV_EVENT_TAG",
            "details": {
                "unicode_name": "AAEL",
                "data": {
                    "domain": "alibabacloud.com",
                    "operation": "kangaroo/pull-image",
                    "content": {"reference": "registry.example.com/ns/model-server:latest"},
                },
            },
        })]);
        assert_eq!(
            eval_policy_vector(&policy, &missing).await,
            (97, 2, 2, 2),
            "an event without a digest must reject"
        );
    }

    #[tokio::test]
    async fn ai_model_positive_and_second_model_rejected() {
        let hash = "a".repeat(64);
        let policy = extraction_policy(
            &families(&[MeasurementFamily::AiModel]),
            "ai.model.Qwen/Qwen3.8-27B",
            &hash,
        );
        let event = |model_id: &str, hash: &str| {
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
        };

        let ok = tdx_input(&[event("Qwen/Qwen3.8-27B", &hash)]);
        assert_eq!(eval_policy_vector(&policy, &ok).await, (2, 2, 2, 2));

        let second_model = tdx_input(&[
            event("Qwen/Qwen3.8-27B", &hash),
            event("Qwen/Qwen3.8-14B", &hash),
        ]);
        assert_eq!(
            eval_policy_vector(&policy, &second_model).await,
            (97, 2, 2, 2),
            "a load event for another model must reject"
        );

        let missing_hash = tdx_input(&[json!({
            "type_name": "EV_EVENT_TAG",
            "details": {
                "unicode_name": "AAEL",
                "data": {
                    "domain": "alibabacloud.com",
                    "operation": "pai/load-model",
                    "content": {"model-id": "Qwen/Qwen3.8-27B"},
                },
            },
        })]);
        assert_eq!(
            eval_policy_vector(&policy, &missing_hash).await,
            (97, 2, 2, 2),
            "a load event without a hash must reject"
        );

        let missing_model_id = tdx_input(&[json!({
            "type_name": "EV_EVENT_TAG",
            "details": {
                "unicode_name": "AAEL",
                "data": {
                    "domain": "alibabacloud.com",
                    "operation": "pai/load-model",
                    "content": {"hash": hash},
                },
            },
        })]);
        assert_eq!(
            eval_policy_vector(&policy, &missing_model_id).await,
            (97, 2, 2, 2),
            "a load event without a model-id must reject"
        );
    }

    /// Both variable-key families can be selected at once: each rule binds to
    /// its own operation, and a model hash mismatch is not masked by the
    /// matching image rule.
    #[tokio::test]
    async fn container_image_and_ai_model_bind_independently() {
        let image_digest = format!("sha256:{}", "a".repeat(64));
        let model_hash = "b".repeat(64);
        let policy = extraction_policy_for(
            &families(&[
                MeasurementFamily::ContainerImage,
                MeasurementFamily::AiModel,
            ]),
            &[
                ("container.image.model-server", image_digest.as_str()),
                ("ai.model.Qwen/Qwen3.8-27B", model_hash.as_str()),
            ],
        );

        let image_event = json!({
            "type_name": "EV_EVENT_TAG",
            "details": {
                "unicode_name": "AAEL",
                "data": {
                    "domain": "alibabacloud.com",
                    "operation": "kangaroo/pull-image",
                    "content": {
                        "reference": "registry.example.com/ns/model-server:latest",
                        "digest": image_digest,
                    },
                },
            },
        });
        let model_event = |hash: &str| {
            json!({
                "type_name": "EV_EVENT_TAG",
                "details": {
                    "unicode_name": "AAEL",
                    "data": {
                        "domain": "alibabacloud.com",
                        "operation": "pai/load-model",
                        "content": {"model-id": "Qwen/Qwen3.8-27B", "hash": hash},
                    },
                },
            })
        };

        let ok = tdx_input(&[image_event.clone(), model_event(&model_hash)]);
        assert_eq!(eval_policy_vector(&policy, &ok).await, (2, 2, 2, 2));

        let wrong_model_hash = "c".repeat(64);
        let mismatch = tdx_input(&[image_event, model_event(&wrong_model_hash)]);
        assert_eq!(
            eval_policy_vector(&policy, &mismatch).await,
            (97, 2, 2, 2),
            "an ai.model hash mismatch must reject while the image rule still matches"
        );
    }
}

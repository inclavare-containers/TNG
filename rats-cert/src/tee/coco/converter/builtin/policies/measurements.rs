//! The shared `actual_measurement(type)` extraction rules.
//!
//! Both the `modules` measurement entries and `transparency_log` manifest
//! reconstruction read the same per-type value through these rules, so the two
//! policies cannot disagree about what the evidence measured. A rendered policy
//! emits only the families it uses, and each helper at most once.

use std::collections::BTreeSet;

use super::modules::{Dimension, Module};

/// One measurement-extraction family. Families are emitted independently; a
/// policy selects the ones its measurement entries and transparency-log
/// declared types need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum MeasurementFamily {
    TdxTdShim,
    TdxOvmf,
    TdxKernel,
    TdxUki,
    RootfsCc,
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
            Self::RootfsCc => ROOTFS_CC,
            Self::ContainerImage => CONTAINER_IMAGE,
            Self::AiModel => AI_MODEL,
        }
    }

    /// The AR4SI dimension a value extracted by this family describes. Rootfs
    /// integrity is a file-system property; every other family measures what
    /// the platform executes.
    fn dimension(self) -> Dimension {
        match self {
            Self::RootfsCc => Dimension::FileSystem,
            _ => Dimension::Executables,
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
        Module::RootfsCc { .. } => Some(MeasurementFamily::RootfsCc),
        Module::ContainerImage { .. } => Some(MeasurementFamily::ContainerImage),
        Module::AiModel { .. } => Some(MeasurementFamily::AiModel),
        Module::Tdx(_) | Module::Nvidia(_) | Module::Gpu | Module::TransparencyLog(_) => None,
    }
}

/// The `actual_measurement` key for a measurement module entry. The
/// vendor-prefixed families drop their `com.alibabacloud.` prefix so the key
/// matches the transparency-log type spelling.
pub(super) fn measurement_key(module: &Module) -> Option<String> {
    match module {
        Module::TdShim { .. } => Some("tdx.td-shim".to_string()),
        Module::Ovmf { .. } => Some("tdx.ovmf".to_string()),
        Module::Kernel { .. } => Some("tdx.kernel".to_string()),
        Module::Uki { .. } => Some("tdx.uki".to_string()),
        Module::RootfsCc { .. } => Some("rootfs.cc".to_string()),
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
        Module::RootfsCc { value } => Some(value),
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
    } else if t == "rootfs.cc" {
        Some(MeasurementFamily::RootfsCc)
    } else if t.starts_with("container.image.") {
        Some(MeasurementFamily::ContainerImage)
    } else {
        None
    }
}

/// The AR4SI dimension a transparency-log published type describes. A
/// transparency-log entry can publish several types; its predicate is
/// attributed to every dimension this maps them to.
pub(super) fn dimension_for_type(t: &str) -> Option<Dimension> {
    family_for_type(t).map(MeasurementFamily::dimension)
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

/// The dm-verity root hash of the confidential container root filesystem. The
/// evidence is the boot cmdline carried by `td_payload_info` platform-config
/// flags events, and every such event must sit at RTMR1 (index 2). The root
/// hash comes from the `verity-root` dm-mod.create mapping; every extracted
/// hash must be the same, and an event without the mapping is ignored.
const ROOTFS_CC: &str = "\
actual_measurement(\"rootfs.cc\") := digest if {
\tevents := [e |
\t\tsome e in input.tdx.uefi_event_logs
\t\te.type_name == \"EV_PLATFORM_CONFIG_FLAGS\"
\t\tstartswith(e.details.string, \"td_payload_info \")
\t]
\tcount(events) > 0
\tbad_index := [e | some e in events; not e.index == 2]
\tcount(bad_index) == 0
\tdigests := {m[1] |
\t\tsome e in events
\t\tsome m in regex.find_all_string_submatch_n(`(?:^|\\s)dm-mod\\.create=\"verity-root,,,ro,0 [0-9]+ verity [0-9]+ \\S+ \\S+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ sha256 ([0-9a-f]{64}) [0-9a-f]{64}[;\"]`, e.details.string, -1)
\t}
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

        // The rootfs family is static and shares no helper with the others.
        let rootfs = families(&[MeasurementFamily::RootfsCc]).rules();
        assert!(rootfs.contains("actual_measurement(\"rootfs.cc\") :="));
        assert!(!rootfs.contains("has_sha384_digest"));
        assert!(!rootfs.contains("image_repo_name"));
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
        let rootfs = Module::RootfsCc {
            value: "a".repeat(64),
        };
        assert_eq!(family_of_module(&rootfs), Some(MeasurementFamily::RootfsCc));
        assert_eq!(measurement_key(&rootfs).unwrap(), "rootfs.cc");

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

    const ROOTFS_ROOT: &str = "44f6a7c111eb0d9f4dcbace76e784689dde3436c08bf7dda8d86d9f8c0b02230";
    const OTHER_ROOT: &str = "54f6a7c111eb0d9f4dcbace76e784689dde3436c08bf7dda8d86d9f8c0b02230";

    fn rootfs_event(index: Option<i64>, details: &str) -> serde_json::Value {
        let mut e = json!({
            "type_name": "EV_PLATFORM_CONFIG_FLAGS",
            "details": {"string": details},
        });
        if let Some(index) = index {
            e["index"] = json!(index);
        }
        e
    }

    /// A `td_payload_info` cmdline carrying one `verity-root` dm-mod.create
    /// mapping whose root hash is `root`.
    fn rootfs_cmdline(root: &str) -> String {
        format!(
            "td_payload_info reboot=k root=/dev/vda1 dm-mod.create=\"verity-root,,,ro,0 1011712 verity 1 /dev/vda1 /dev/vda2 4096 4096 126464 0 sha256 {root} {tail};\"",
            tail = "0".repeat(64)
        )
    }

    fn rootfs_policy(pin: &str) -> String {
        extraction_policy(&families(&[MeasurementFamily::RootfsCc]), "rootfs.cc", pin)
    }

    #[tokio::test]
    async fn rootfs_cc_extraction_and_matching() {
        let policy = rootfs_policy(ROOTFS_ROOT);

        // A matching root hash affirms; a different pin rejects.
        let ok = tdx_input(&[rootfs_event(Some(2), &rootfs_cmdline(ROOTFS_ROOT))]);
        assert_eq!(eval_policy_vector(&policy, &ok).await, (2, 2, 2, 2));

        let mismatch = tdx_input(&[rootfs_event(Some(2), &rootfs_cmdline(OTHER_ROOT))]);
        assert_eq!(
            eval_policy_vector(&policy, &mismatch).await,
            (97, 2, 2, 2),
            "a different extracted root hash must reject"
        );

        // No td_payload_info event at all.
        let none = tdx_input(&[json!({"event": "ok"})]);
        assert_eq!(
            eval_policy_vector(&policy, &none).await,
            (97, 2, 2, 2),
            "no td_payload_info event must reject (fail-closed)"
        );

        // A td_payload_info event whose cmdline names no verity-root mapping.
        let no_table = tdx_input(&[rootfs_event(Some(2), "td_payload_info reboot=k")]);
        assert_eq!(
            eval_policy_vector(&policy, &no_table).await,
            (97, 2, 2, 2),
            "an event without a verity-root mapping must reject"
        );

        // One event with the mapping, one without: the latter is ignored.
        let mixed = tdx_input(&[
            rootfs_event(Some(2), &rootfs_cmdline(ROOTFS_ROOT)),
            rootfs_event(Some(2), "td_payload_info reboot=k"),
        ]);
        assert_eq!(
            eval_policy_vector(&policy, &mixed).await,
            (2, 2, 2, 2),
            "an event without a verity-root mapping must be ignored"
        );

        // An event at a non-RTMR1 index or without an index rejects.
        let bad_index = tdx_input(&[rootfs_event(Some(1), &rootfs_cmdline(ROOTFS_ROOT))]);
        assert_eq!(
            eval_policy_vector(&policy, &bad_index).await,
            (97, 2, 2, 2),
            "a td_payload_info event at a non-RTMR1 index must reject"
        );
        let no_index = tdx_input(&[rootfs_event(None, &rootfs_cmdline(ROOTFS_ROOT))]);
        assert_eq!(
            eval_policy_vector(&policy, &no_index).await,
            (97, 2, 2, 2),
            "a td_payload_info event without an index must reject"
        );

        // A different event type carrying the same cmdline is not selected.
        let wrong_type = tdx_input(&[json!({
            "type_name": "EV_EVENT_TAG",
            "details": {"string": rootfs_cmdline(ROOTFS_ROOT)},
            "index": 2,
        })]);
        assert_eq!(
            eval_policy_vector(&policy, &wrong_type).await,
            (97, 2, 2, 2),
            "the cmdline must come from an EV_PLATFORM_CONFIG_FLAGS event"
        );

        // Two events with the same root hash agree; different ones conflict.
        let same = tdx_input(&[
            rootfs_event(Some(2), &rootfs_cmdline(ROOTFS_ROOT)),
            rootfs_event(Some(2), &rootfs_cmdline(ROOTFS_ROOT)),
        ]);
        assert_eq!(eval_policy_vector(&policy, &same).await, (2, 2, 2, 2));
        let conflict = tdx_input(&[
            rootfs_event(Some(2), &rootfs_cmdline(ROOTFS_ROOT)),
            rootfs_event(Some(2), &rootfs_cmdline(OTHER_ROOT)),
        ]);
        assert_eq!(
            eval_policy_vector(&policy, &conflict).await,
            (97, 2, 2, 2),
            "two different root hashes must reject"
        );

        // One cmdline naming two different verity-root hashes is ambiguous.
        let two_in_one = format!(
            "{} {}",
            rootfs_cmdline(ROOTFS_ROOT),
            rootfs_cmdline(OTHER_ROOT)
        );
        let ambiguous = tdx_input(&[rootfs_event(Some(2), &two_in_one)]);
        assert_eq!(
            eval_policy_vector(&policy, &ambiguous).await,
            (97, 2, 2, 2),
            "two verity-root hashes in one cmdline must reject"
        );

        // Uppercase hex and a non-sha256 algorithm do not match.
        let uppercase = tdx_input(&[rootfs_event(
            Some(2),
            &rootfs_cmdline(&ROOTFS_ROOT.to_uppercase()),
        )]);
        assert_eq!(
            eval_policy_vector(&policy, &uppercase).await,
            (97, 2, 2, 2),
            "uppercase hex must not match"
        );
        let sha512 = tdx_input(&[rootfs_event(
            Some(2),
            &rootfs_cmdline(ROOTFS_ROOT).replace(" sha256 ", " sha512 "),
        )]);
        assert_eq!(
            eval_policy_vector(&policy, &sha512).await,
            (97, 2, 2, 2),
            "a non-sha256 verity algorithm must not match"
        );
    }

    /// The real PAI event log carries a `td_payload_info` cmdline at RTMR1
    /// whose `verity-root` mapping pins this root hash. The `verity-1` mapping
    /// in the same cmdline must not contribute a second digest.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn rootfs_cc_extracts_real_pai_event_log() {
        let policy = rootfs_policy(ROOTFS_ROOT);

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
                "header": {
                    "tee_type": "81000000",
                    "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                },
                "body": {"mr_td": "a".repeat(96)},
            }),
        );
        tdx.insert(
            "uefi_event_logs".to_string(),
            parsed["uefi_event_logs"].clone(),
        );
        let input = json!({"tdx": tdx}).to_string();

        assert_eq!(
            eval_policy_vector(&policy, &input).await,
            (2, 2, 2, 2),
            "the real PAI event log must extract the verity-root hash as the only digest"
        );

        let bad_policy = rootfs_policy(OTHER_ROOT);
        assert_eq!(
            eval_policy_vector(&bad_policy, &input).await,
            (97, 2, 2, 2),
            "a pin that differs from the real root hash must reject"
        );
    }
}

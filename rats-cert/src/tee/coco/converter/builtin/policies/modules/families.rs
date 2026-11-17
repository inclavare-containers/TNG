//! The measurement-family registry: one row per extraction family owning every
//! accepted spelling, the AR4SI dimension, the `actual_measurement` key, the
//! extraction rule, the shared Rego helpers, and whether a `transparency_log`
//! entry may publish it.
//!
//! Both the `modules` measurement entries and `transparency_log` manifest
//! reconstruction read the same per-type value through these rules, so the two
//! policies cannot disagree about what the evidence measured. A rendered policy
//! emits only the families it uses, and each helper at most once.

use std::collections::BTreeSet;

use super::super::super::policy_config::value_shape;
use super::{Dimension, Module};

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

/// The registry row for one family. A parameterized family's prefixes end in
/// `.` and take the entry name (repository or model id) as a suffix; a fixed
/// family's spellings are complete type strings.
struct FamilySpec {
    family: MeasurementFamily,
    /// Canonical module-entry spelling.
    canonical: &'static str,
    /// Permanent module-entry aliases. The vendor-prefixed spelling is
    /// canonical; the unprefixed one is accepted alongside it.
    aliases: &'static [&'static str],
    /// The `transparency_log.publishedMeasurements` spelling, if this family
    /// may be published. This is a stricter subset than module entries accept.
    published: Option<&'static str>,
    /// `actual_measurement` key, or prefix for a parameterized family.
    measurement_key: &'static str,
    dimension: Dimension,
    /// Rego helpers the extraction rule calls. Emitted once per policy.
    helpers: &'static [&'static str],
}

impl FamilySpec {
    fn parameterized(&self) -> bool {
        self.canonical.ends_with('.')
    }
}

const TD_SHIM: FamilySpec = FamilySpec {
    family: MeasurementFamily::TdxTdShim,
    canonical: "tdx.td-shim",
    aliases: &[],
    published: Some("tdx.td-shim"),
    measurement_key: "tdx.td-shim",
    dimension: Dimension::Executables,
    helpers: &[],
};

const OVMF: FamilySpec = FamilySpec {
    family: MeasurementFamily::TdxOvmf,
    canonical: "tdx.ovmf",
    aliases: &[],
    published: None,
    measurement_key: "tdx.ovmf",
    dimension: Dimension::Executables,
    helpers: &[],
};

const KERNEL: FamilySpec = FamilySpec {
    family: MeasurementFamily::TdxKernel,
    canonical: "tdx.kernel",
    aliases: &[],
    published: Some("tdx.kernel"),
    measurement_key: "tdx.kernel",
    dimension: Dimension::Executables,
    helpers: &[HAS_SHA384_DIGEST],
};

const UKI: FamilySpec = FamilySpec {
    family: MeasurementFamily::TdxUki,
    canonical: "tdx.uki",
    aliases: &[],
    published: None,
    measurement_key: "tdx.uki",
    dimension: Dimension::Executables,
    helpers: &[HAS_SHA384_DIGEST],
};

const ROOTFS_CC: FamilySpec = FamilySpec {
    family: MeasurementFamily::RootfsCc,
    canonical: "com.alibabacloud.rootfs.cc",
    aliases: &["rootfs.cc"],
    published: Some("rootfs.cc"),
    measurement_key: "rootfs.cc",
    dimension: Dimension::FileSystem,
    helpers: &[],
};

const CONTAINER_IMAGE: FamilySpec = FamilySpec {
    family: MeasurementFamily::ContainerImage,
    canonical: "com.alibabacloud.container.image.",
    aliases: &["container.image."],
    published: Some("container.image."),
    measurement_key: "container.image.",
    dimension: Dimension::Executables,
    helpers: &[IMAGE_REPO_NAME],
};

const AI_MODEL: FamilySpec = FamilySpec {
    family: MeasurementFamily::AiModel,
    canonical: "com.alibabacloud.ai.model.",
    aliases: &["ai.model."],
    published: None,
    measurement_key: "ai.model.",
    dimension: Dimension::Executables,
    helpers: &[],
};

/// Every family in deterministic emission order. Declaration order is the
/// order extraction rules render in.
const FAMILIES: &[&FamilySpec] = &[
    &TD_SHIM,
    &OVMF,
    &KERNEL,
    &UKI,
    &ROOTFS_CC,
    &CONTAINER_IMAGE,
    &AI_MODEL,
];

impl MeasurementFamily {
    fn spec(self) -> &'static FamilySpec {
        match self {
            Self::TdxTdShim => &TD_SHIM,
            Self::TdxOvmf => &OVMF,
            Self::TdxKernel => &KERNEL,
            Self::TdxUki => &UKI,
            Self::RootfsCc => &ROOTFS_CC,
            Self::ContainerImage => &CONTAINER_IMAGE,
            Self::AiModel => &AI_MODEL,
        }
    }

    /// The AR4SI dimension a value extracted by this family describes. Rootfs
    /// integrity is a file-system property; every other family measures what
    /// the platform executes.
    pub(super) fn dimension(self) -> Dimension {
        self.spec().dimension
    }

    /// The canonical type string for a module entry of this family. The name
    /// is empty for a fixed family.
    pub(super) fn canonical_spelling(self, name: &str) -> String {
        let spec = self.spec();
        if spec.parameterized() {
            format!("{}{name}", spec.canonical)
        } else {
            spec.canonical.to_string()
        }
    }

    /// The `actual_measurement` key for a module entry of this family. The
    /// vendor-prefixed families are recorded without their prefix so the key
    /// matches the transparency-log type spelling.
    pub(super) fn measurement_key(self, name: &str) -> String {
        let spec = self.spec();
        if spec.parameterized() {
            format!("{}{name}", spec.measurement_key)
        } else {
            spec.measurement_key.to_string()
        }
    }
}

/// Resolve a module-entry type spelling to its family and name. Accepts the
/// canonical spelling and every permanent alias; `None` means the type is a
/// posture or transparency entry, or unknown.
pub(super) fn parse_module_type(raw: &str) -> Option<(MeasurementFamily, &str)> {
    for spec in FAMILIES {
        if spec.parameterized() {
            if let Some(name) = raw.strip_prefix(spec.canonical) {
                return Some((spec.family, name));
            }
            for alias in spec.aliases {
                if let Some(name) = raw.strip_prefix(alias) {
                    return Some((spec.family, name));
                }
            }
        } else if raw == spec.canonical || spec.aliases.contains(&raw) {
            return Some((spec.family, ""));
        }
    }
    None
}

/// Resolve a `transparency_log.publishedMeasurements` type. Published types are
/// a stricter subset than module entries: only the unprefixed spellings are
/// recorded in a manifest, and a container image repository must be the single
/// extracted segment.
pub(super) fn parse_published_type(raw: &str) -> anyhow::Result<MeasurementFamily> {
    for spec in FAMILIES {
        let Some(published) = spec.published else {
            continue;
        };
        if spec.parameterized() {
            if let Some(repository_name) = raw.strip_prefix(published) {
                if !is_valid_image_repo_name(repository_name) {
                    anyhow::bail!(
                        "publishedMeasurements type {raw:?} has invalid container image repository {repository_name:?}; use ASCII letters, digits, '.', '_' and '-'"
                    );
                }
                return Ok(spec.family);
            }
        } else if raw == published {
            return Ok(spec.family);
        }
    }
    anyhow::bail!("unsupported publishedMeasurements type {raw}")
}

/// Validate a `transparency_log.publishedMeasurements` type where the caller
/// only needs acceptance, not the family it selects.
pub(crate) fn validate_published_type(raw: &str) -> anyhow::Result<()> {
    parse_published_type(raw).map(|_| ())
}

/// The family a published type selects, without re-checking its spelling. Used
/// to attribute a validated entry's dimensions and extraction rules.
pub(super) fn family_for_published_type(raw: &str) -> Option<MeasurementFamily> {
    FAMILIES.iter().find_map(|spec| {
        let published = spec.published?;
        if spec.parameterized() {
            raw.strip_prefix(published).map(|_| spec.family)
        } else if raw == published {
            Some(spec.family)
        } else {
            None
        }
    })
}

/// The AR4SI dimension a transparency-log published type describes. A
/// transparency-log entry can publish several types; its predicate is
/// attributed to every dimension this maps them to.
pub(super) fn dimension_for_published_type(raw: &str) -> Option<Dimension> {
    family_for_published_type(raw).map(MeasurementFamily::dimension)
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
        Module::Tdx(_) | Module::Nvidia(_) | Module::Gpu | Module::TransparencyLog { .. } => None,
    }
}

/// The per-entry name a family's key takes: the repository or model id for a
/// parameterized family, empty for a fixed one.
fn measurement_name(module: &Module) -> Option<&str> {
    match module {
        Module::ContainerImage { repo, .. } => Some(repo),
        Module::AiModel { model_id, .. } => Some(model_id),
        Module::TdShim { .. }
        | Module::Ovmf { .. }
        | Module::Kernel { .. }
        | Module::Uki { .. }
        | Module::RootfsCc { .. } => Some(""),
        Module::Tdx(_) | Module::Nvidia(_) | Module::Gpu | Module::TransparencyLog { .. } => None,
    }
}

/// The `actual_measurement` key for a measurement module entry.
pub(super) fn measurement_key(module: &Module) -> Option<String> {
    let family = family_of_module(module)?;
    let name = measurement_name(module)?;
    Some(family.measurement_key(name))
}

/// The pinned value a single-valued measurement module entry compares against.
fn measurement_pin(module: &Module) -> Option<&str> {
    match module {
        Module::TdShim { value }
        | Module::Ovmf { value }
        | Module::Kernel { value }
        | Module::Uki { value } => Some(value),
        Module::RootfsCc { value } => Some(value),
        Module::AiModel { digest, .. } => Some(digest),
        Module::ContainerImage { .. }
        | Module::Tdx(_)
        | Module::Nvidia(_)
        | Module::Gpu
        | Module::TransparencyLog { .. } => None,
    }
}

/// Build and validate one measurement module entry. The entry type was already
/// parsed into its family by the caller, so this only checks that `value` fits
/// that family.
pub(super) fn build_measurement_module(
    family: MeasurementFamily,
    name: &str,
    raw_type: &str,
    value: &serde_json::Value,
) -> anyhow::Result<Module> {
    let value_str = || match value {
        serde_json::Value::String(s) => Ok(s.as_str()),
        other => anyhow::bail!(
            "module type {raw_type:?} expects a string value, got {}",
            value_shape(other)
        ),
    };

    let fixed_hex = |len: usize| -> anyhow::Result<String> {
        let v = value_str()?;
        if !is_lower_hex(v, len) {
            anyhow::bail!("module type {raw_type:?} value must be {len} lowercase hex chars");
        }
        Ok(v.to_string())
    };

    match family {
        MeasurementFamily::TdxTdShim => Ok(Module::TdShim {
            value: fixed_hex(96)?,
        }),
        MeasurementFamily::TdxOvmf => Ok(Module::Ovmf {
            value: fixed_hex(96)?,
        }),
        MeasurementFamily::TdxKernel => Ok(Module::Kernel {
            value: fixed_hex(96)?,
        }),
        MeasurementFamily::TdxUki => Ok(Module::Uki {
            value: fixed_hex(96)?,
        }),
        MeasurementFamily::RootfsCc => Ok(Module::RootfsCc {
            value: fixed_hex(64)?,
        }),
        MeasurementFamily::ContainerImage => {
            if !is_valid_image_repo_name(name) {
                anyhow::bail!(
                    "container.image name {name:?} must be a single repository segment using only ASCII letters, digits, '.', '_' and '-'"
                );
            }
            let digest = value_str()?;
            if !is_sha256_digest(digest) {
                anyhow::bail!(
                    "com.alibabacloud.container.image.{name} value must be sha256:<64 lowercase hex>"
                );
            }
            Ok(Module::ContainerImage {
                repo: name.to_string(),
                digests: BTreeSet::from([digest.to_string()]),
            })
        }
        MeasurementFamily::AiModel => {
            if !is_valid_module_name(name) {
                anyhow::bail!("ai.model name {name:?} has an invalid character");
            }
            let digest = fixed_hex(64)?;
            Ok(Module::AiModel {
                model_id: name.to_string(),
                digest,
            })
        }
    }
}

/// The matching rule for a measurement module entry, or `None` for a posture
/// or transparency entry. A container image compares digest sets; every other
/// family compares a single pinned value. The pinned values are spliced as Rego
/// literals; validation in the entry parser guarantees they contain no quoting
/// hazard.
pub(super) fn predicate(module: &Module, pred: &str) -> Option<String> {
    if let Module::ContainerImage { repo, digests } = module {
        let key = format!("container.image.{repo}");
        let expected = digests
            .iter()
            .map(|digest| format!("{digest:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Some(format!(
            "{pred} if {{\n\tactual_measurement_set({key:?}) == {{{expected}}}\n}}"
        ));
    }
    let key = measurement_key(module)?;
    let pin = measurement_pin(module)?;
    Some(format!(
        "{pred} if {{\n\tactual_measurement({key:?}) == {pin:?}\n}}"
    ))
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
            if let Some(family) = family_for_published_type(t) {
                self.0.insert(family);
            }
        }
    }

    /// The Rego extraction source for the selected families, or an empty
    /// string when none are selected. Shared helpers come first, once each, in
    /// registry order; the extraction rules follow in the same order.
    pub(super) fn rules(&self) -> String {
        if self.0.is_empty() {
            return String::new();
        }
        let mut parts: Vec<&str> = Vec::new();
        for spec in FAMILIES {
            if !self.0.contains(&spec.family) {
                continue;
            }
            for helper in spec.helpers {
                if !parts.contains(helper) {
                    parts.push(*helper);
                }
            }
        }
        for spec in FAMILIES {
            if self.0.contains(&spec.family) {
                parts.push(spec.family.rule());
            }
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
            Self::RootfsCc => ROOTFS_CC_RULE,
            Self::ContainerImage => CONTAINER_IMAGE_RULE,
            Self::AiModel => AI_MODEL_RULE,
        }
    }
}

/// Name segment charset: letters, digits and `. _ / @ : + -`.
fn is_valid_module_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '@' | ':' | '+' | '-')
        })
}

/// The repository segment of an image reference that appraisal extracts:
/// the last '/'-separated path component, with any tag or digest stripped.
/// A name containing '/', '@', or ':' can never equal that segment, so it is
/// rejected at load instead of failing closed only at appraisal.
pub(super) fn is_valid_image_repo_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// A lowercase hex string of exactly `len` characters.
pub(super) fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A `sha256:<64 lowercase hex>` OCI manifest digest.
fn is_sha256_digest(s: &str) -> bool {
    match s.strip_prefix("sha256:") {
        Some(hex) => is_lower_hex(hex, 64),
        None => false,
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

/// The dm-verity root hash of the confidential container root filesystem. The
/// evidence is the boot cmdline carried by `td_payload_info` platform-config
/// flags events, and every such event must sit at RTMR1 (index 2). The root
/// hash comes from the `verity-root` dm-mod.create mapping; every extracted
/// hash must be the same, and an event without the mapping is ignored.
const ROOTFS_CC_RULE: &str = "\
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

/// A repo can be pulled at several versions inside one TD, so its AAEL events
/// carry several digests. The rule returns the set of every digest and leaves
/// the set-equality check to the caller; a repo with no matching event, or any
/// matching event missing its digest, is undefined.
const CONTAINER_IMAGE_RULE: &str = "\
actual_measurement_set(type) := digests if {
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
}";

const AI_MODEL_RULE: &str = "\
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
    #[cfg(feature = "crypto-rustcrypto")]
    use super::super::super::super::test_fixtures::{
        aael_event, aael_event_for_reference, hex64, hex96, manifest, pai_tdx_input,
        rekor_entry_value, rootfs_event as rootfs_hash_event, td_payload_event, tdx_quote_input,
        transparency_entry, TDX_VENDOR_ID,
    };
    #[cfg(feature = "crypto-rustcrypto")]
    use super::super::super::test_harness::{
        render_modules_json as render, render_rekor, resolved_from_manifest,
    };
    use serde_json::Value;

    use super::super::super::super::test_fixtures::{pai_event_log_events, tdx_input_with_body};
    use super::super::super::test_harness::eval_policy_vector;
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

    /// Wrap the selected rules in a minimal policy that affirms `executables`
    /// when `actual_measurement_set(key)` equals `expected`.
    fn extraction_set_policy(families: &Families, key: &str, expected: &[&str]) -> String {
        let values = expected
            .iter()
            .map(|value| format!("{value:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "package policy\n\nimport rego.v1\n\ndefault executables := 97\ndefault hardware := 2\ndefault configuration := 2\ndefault file_system := 2\n\n{}executables := 2 if {{\n\tactual_measurement_set({key:?}) == {{{values}}}\n}}\n",
            families.rules()
        )
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
    fn registry_owns_every_accepted_module_spelling() {
        for spec in FAMILIES {
            let (family, name) = parse_module_type(spec.canonical)
                .unwrap_or_else(|| panic!("canonical spelling {} must parse", spec.canonical));
            assert_eq!(family, spec.family);
            assert_eq!(name, "", "a canonical prefix carries no entry name");
            let expected_name = if spec.parameterized() { "busybox" } else { "" };
            assert_eq!(
                family.canonical_spelling(expected_name),
                format!("{}{}", spec.canonical, expected_name)
            );

            for alias in spec.aliases {
                let (alias_family, _) = parse_module_type(alias)
                    .unwrap_or_else(|| panic!("alias spelling {alias} must parse"));
                assert_eq!(alias_family, spec.family);
            }
        }

        // A fixed family is a name, not a namespace.
        assert!(parse_module_type("rootfs.").is_none());
        assert!(parse_module_type("rootfs.foo").is_none());
        assert!(parse_module_type("tdx.quote").is_none());
    }

    #[test]
    fn registry_published_subset_is_stricter_than_module_entries() {
        for measurement_type in [
            "tdx.td-shim",
            "tdx.kernel",
            "rootfs.cc",
            "container.image.busybox",
        ] {
            assert_eq!(
                parse_published_type(measurement_type).unwrap(),
                family_for_published_type(measurement_type).unwrap()
            );
            assert!(dimension_for_published_type(measurement_type).is_some());
        }

        // Accepted as module entries but not publishable.
        for measurement_type in [
            "tdx.ovmf",
            "tdx.uki",
            "ai.model.Qwen/Qwen3.8-27B",
            "com.alibabacloud.rootfs.cc",
            "com.alibabacloud.container.image.busybox",
            "rootfs.foo",
        ] {
            assert!(
                parse_published_type(measurement_type).is_err(),
                "{measurement_type} must not be a published type"
            );
            assert!(family_for_published_type(measurement_type).is_none());
        }

        for measurement_type in [
            "container.image.",
            "container.image.foo/bar",
            "container.image.foo@sha256",
            "container.image.foo:tag",
        ] {
            let error = parse_published_type(measurement_type).expect_err(measurement_type);
            assert!(
                format!("{error:#}").contains("invalid container image repository"),
                "{measurement_type}: {error:#}"
            );
        }
    }

    #[test]
    fn registry_dimensions_match_each_family() {
        assert_eq!(
            MeasurementFamily::RootfsCc.dimension(),
            Dimension::FileSystem
        );
        for family in [
            MeasurementFamily::TdxTdShim,
            MeasurementFamily::TdxOvmf,
            MeasurementFamily::TdxKernel,
            MeasurementFamily::TdxUki,
            MeasurementFamily::ContainerImage,
            MeasurementFamily::AiModel,
        ] {
            assert_eq!(family.dimension(), Dimension::Executables);
        }
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

        // The image family owns its repo-name helper and the multi-value
        // extraction rule, emitted once.
        let image = families(&[MeasurementFamily::ContainerImage]).rules();
        assert_eq!(image.matches("image_repo_name(ref) :=").count(), 1);
        assert_eq!(image.matches("actual_measurement_set(type) :=").count(), 1);
        assert!(!image.contains("actual_measurement(type) :="));

        // The rootfs family is static and shares no helper with the others.
        let rootfs = families(&[MeasurementFamily::RootfsCc]).rules();
        assert!(rootfs.contains("actual_measurement(\"rootfs.cc\") :="));
        assert!(!rootfs.contains("has_sha384_digest"));
        assert!(!rootfs.contains("image_repo_name"));

        // Helpers precede rules and follow registry order.
        let mixed = families(&[
            MeasurementFamily::AiModel,
            MeasurementFamily::ContainerImage,
            MeasurementFamily::TdxKernel,
        ])
        .rules();
        assert!(mixed.find("has_sha384_digest").unwrap() < mixed.find("image_repo_name").unwrap());
        assert!(
            mixed.find("image_repo_name(ref) :=").unwrap()
                < mixed.find("actual_measurement(\"tdx.kernel\")").unwrap()
        );
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
            digests: [format!("sha256:{}", "c".repeat(64))].into_iter().collect(),
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
    async fn container_image_extracts_and_matches_digest_set() {
        let digest_a = format!("sha256:{}", "a".repeat(64));
        let digest_b = format!("sha256:{}", "b".repeat(64));
        let family = families(&[MeasurementFamily::ContainerImage]);
        let single = extraction_set_policy(&family, "container.image.model-server", &[&digest_a]);
        let pair = extraction_set_policy(
            &family,
            "container.image.model-server",
            &[&digest_a, &digest_b],
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

        let ok = tdx_input(&[event(Some("EV_EVENT_TAG"), &digest_a)]);
        assert_eq!(eval_policy_vector(&single, &ok).await, (2, 2, 2, 2));

        // Every digest the repo was pulled with is part of the set; repeated
        // events for one digest contribute a single element.
        let two = tdx_input(&[
            event(Some("EV_EVENT_TAG"), &digest_a),
            event(Some("EV_EVENT_TAG"), &digest_b),
        ]);
        assert_eq!(
            eval_policy_vector(&pair, &two).await,
            (2, 2, 2, 2),
            "two digests must match the two-element expected set"
        );
        let duplicate = tdx_input(&[
            event(Some("EV_EVENT_TAG"), &digest_a),
            event(Some("EV_EVENT_TAG"), &digest_a),
        ]);
        assert_eq!(
            eval_policy_vector(&single, &duplicate).await,
            (2, 2, 2, 2),
            "repeated events for one digest must collapse to one element"
        );

        // Set equality, not containment: extra and missing digests both reject.
        assert_eq!(
            eval_policy_vector(&single, &two).await,
            (97, 2, 2, 2),
            "an extra observed digest must reject the single-element expectation"
        );
        assert_eq!(
            eval_policy_vector(&pair, &ok).await,
            (97, 2, 2, 2),
            "a missing observed digest must reject the two-element expectation"
        );

        // Synthetic event without the EV_EVENT_TAG type no longer matches.
        let untyped = tdx_input(&[event(None, &digest_a)]);
        assert_eq!(
            eval_policy_vector(&single, &untyped).await,
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
            eval_policy_vector(&single, &missing).await,
            (97, 2, 2, 2),
            "an event without a digest must reject"
        );

        let none = tdx_input(&[]);
        assert_eq!(
            eval_policy_vector(&single, &none).await,
            (97, 2, 2, 2),
            "a repo with no matching event must reject (fail-closed)"
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
        let policy = format!(
            "package policy\n\nimport rego.v1\n\ndefault executables := 97\ndefault hardware := 2\ndefault configuration := 2\ndefault file_system := 2\n\n{}executables := 2 if {{\n\tactual_measurement_set(\"container.image.model-server\") == {{{image_digest:?}}}\n\tactual_measurement(\"ai.model.Qwen/Qwen3.8-27B\") == {model_hash:?}\n}}\n",
            families(&[
                MeasurementFamily::ContainerImage,
                MeasurementFamily::AiModel,
            ])
            .rules()
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

        let input = tdx_input_with_body(json!({"mr_td": "a".repeat(96)}), &pai_event_log_events());

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

    #[test]
    fn published_measurement_type_parses_each_supported_family() {
        use super::super::families::MeasurementFamily;
        assert_eq!(
            parse_published_type("tdx.td-shim").unwrap(),
            MeasurementFamily::TdxTdShim
        );
        assert_eq!(
            parse_published_type("tdx.kernel").unwrap(),
            MeasurementFamily::TdxKernel
        );
        assert_eq!(
            parse_published_type("rootfs.cc").unwrap(),
            MeasurementFamily::RootfsCc
        );
        for repository_name in ["busybox", "my-app.v2"] {
            let measurement_type = format!("container.image.{repository_name}");
            assert_eq!(
                parse_published_type(&measurement_type).unwrap(),
                MeasurementFamily::ContainerImage,
                "expected container image for {measurement_type}"
            );
        }
    }

    #[test]
    fn published_measurement_type_rejects_invalid_container_repository() {
        for measurement_type in [
            "container.image.",
            "container.image.foo/bar",
            "container.image.foo@sha256",
            "container.image.foo:tag",
        ] {
            let error = parse_published_type(measurement_type).expect_err(measurement_type);
            assert!(
                format!("{error:#}").contains("invalid container image repository"),
                "{measurement_type}: {error:#}"
            );
        }
    }

    #[test]
    fn published_measurement_type_rejects_prefixed_alias() {
        let error = parse_published_type("com.alibabacloud.container.image.busybox")
            .expect_err("prefixed alias must be rejected");
        assert!(
            format!("{error:#}").contains("unsupported publishedMeasurements type"),
            "{error:#}"
        );
    }

    #[test]
    fn published_measurement_type_rejects_unsupported_type() {
        let error = parse_published_type("tdx.uki")
            .expect_err("tdx.uki is not a published measurement type");
        assert!(
            format!("{error:#}").contains("unsupported publishedMeasurements type"),
            "{error:#}"
        );
    }

    #[test]
    fn published_measurement_type_rejects_rootfs_spellings() {
        // `rootfs.cc` is a fixed type, not a `rootfs.<name>` namespace.
        for measurement_type in ["rootfs.foo", "rootfs."] {
            let error =
                parse_published_type(measurement_type).expect_err("only rootfs.cc is supported");
            assert!(
                format!("{error:#}").contains("unsupported publishedMeasurements type"),
                "{measurement_type}: {error:#}"
            );
        }

        // The vendor-prefixed spelling is not a published type; the manifest
        // records the unprefixed one.
        let error = parse_published_type("com.alibabacloud.rootfs.cc")
            .expect_err("prefixed rootfs alias must be rejected");
        assert!(
            format!("{error:#}").contains("unsupported publishedMeasurements type"),
            "{error:#}"
        );
    }

    #[test]
    fn published_measurement_types_all_map_to_dimensions() {
        // A published type that parses but has no extraction family would be
        // emitted with no dimension gating it, so the entry would not be
        // enforced. Keep the two allowlists in step.
        for measurement_type in [
            "tdx.td-shim",
            "tdx.kernel",
            "rootfs.cc",
            "container.image.busybox",
        ] {
            assert!(
                parse_published_type(measurement_type).is_ok(),
                "{measurement_type}"
            );
            assert!(
                dimension_for_published_type(measurement_type).is_some(),
                "{measurement_type} must map to an extraction family and dimension"
            );
        }
    }

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
    async fn transparency_log_rekor_multi_digest_manifest() {
        let digest_a = format!("sha256:{}", hex64('a'));
        let digest_b = format!("sha256:{}", hex64('b'));
        let digest_c = format!("sha256:{}", hex64('c'));
        let image = "container.image.cmaas-runtime";

        // The publisher records every observed digest, ascending.
        let logged = manifest(
            "1.0.0",
            &[(image, digest_a.as_str()), (image, digest_b.as_str())],
        );
        let policy = render_rekor(&[image], &resolved_from_manifest(&logged));

        let both = tdx_input(&[aael_event(&digest_a), aael_event(&digest_b)]);
        assert_eq!(
            eval_policy_vector(&policy, &both).await,
            (2, 2, 2, 2),
            "evidence with exactly the published digest set must affirm"
        );

        let missing = tdx_input(&[aael_event(&digest_a)]);
        assert_eq!(
            eval_policy_vector(&policy, &missing).await,
            (97, 2, 2, 2),
            "evidence missing one published digest must reject"
        );

        let extra = tdx_input(&[
            aael_event(&digest_a),
            aael_event(&digest_b),
            aael_event(&digest_c),
        ]);
        assert_eq!(
            eval_policy_vector(&policy, &extra).await,
            (97, 2, 2, 2),
            "evidence with an extra digest must reject"
        );

        // The publisher must write the digests ascending: an unsorted manifest
        // reconstructs to different bytes and fails payloadHash verification.
        let unsorted = manifest(
            "1.0.0",
            &[(image, digest_b.as_str()), (image, digest_a.as_str())],
        );
        let unsorted_policy = render_rekor(&[image], &resolved_from_manifest(&unsorted));
        assert_eq!(
            eval_policy_vector(&unsorted_policy, &both).await,
            (97, 2, 2, 2),
            "a manifest whose digests are not ascending must fail payloadHash"
        );

        // One digest remains byte-for-byte compatible with the previous
        // single-entry reconstruction.
        let single_logged = manifest("1.0.0", &[(image, digest_a.as_str())]);
        let single_policy = render_rekor(&[image], &resolved_from_manifest(&single_logged));
        let single_input = tdx_input(&[aael_event(&digest_a)]);
        assert_eq!(
            eval_policy_vector(&single_policy, &single_input).await,
            (2, 2, 2, 2),
            "a single published digest must still affirm"
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
    async fn transparency_log_rekor_td_kernel_accepts_any_blob_length() {
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

        // BlobLength is unauthenticated metadata and is not part of the
        // td_payload contract, so a non-32 MiB blob is accepted.
        let other_blob = tdx_input(&[td_payload_event(event_16mib, kernel, 2)]);
        assert_eq!(
            eval_policy_vector(&policy, &other_blob).await,
            (2, 2, 2, 2),
            "a non-32 MiB td_payload blob must affirm"
        );

        // The event payload is never parsed, so even a malformed value is
        // accepted as long as the digest agreement holds.
        let malformed = tdx_input(&[td_payload_event("AAAA", kernel, 2)]);
        assert_eq!(
            eval_policy_vector(&policy, &malformed).await,
            (2, 2, 2, 2),
            "the td_payload event body is not inspected"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_td_kernel_blob_length_is_not_a_conflict() {
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

        // Same digest, different blob lengths: the digests still agree, so
        // there is no conflict.
        let differing_blob = tdx_input(&[
            td_payload_event(event_32mib, kernel, 2),
            td_payload_event(event_16mib, kernel, 2),
        ]);
        assert_eq!(
            eval_policy_vector(&policy, &differing_blob).await,
            (2, 2, 2, 2),
            "32 MiB + 16 MiB td_payload events (same digest) must affirm"
        );

        // A digest disagreement is still a conflict.
        let conflict = tdx_input(&[
            td_payload_event(event_32mib, kernel, 2),
            td_payload_event(
                event_32mib,
                "b1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                2,
            ),
        ]);
        assert_eq!(
            eval_policy_vector(&policy, &conflict).await,
            (97, 2, 2, 2),
            "conflicting td_payload digests must reject"
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

        // A matching event with no index at all also rejects.
        let mut no_index = td_payload_event(event_32mib, kernel, 2);
        no_index.as_object_mut().unwrap().remove("index");
        let missing_index = tdx_input(&[no_index]);
        assert_eq!(
            eval_policy_vector(&policy, &missing_index).await,
            (97, 2, 2, 2),
            "descriptor-matching td_payload event without an index must reject"
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

        // Two events sharing the SAME `event` body, one without SHA-384: the
        // per-event check must not be deduplicated by the event body.
        let same_body = serde_json::to_string(&json!({
            "tdx": {
                "quote": {
                    "header": {"tee_type": "81000000", "vendor_id": TDX_VENDOR_ID},
                    "body": {"td_attributes": "0000001000000000"},
                },
                "uefi_event_logs": [
                    {
                        "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
                        "details": {"string": "td_payload"},
                        "event": event_32mib,
                        "digests": [{"alg": "SHA-384", "digest": kernel}],
                        "index": 2,
                    },
                    {
                        "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
                        "details": {"string": "td_payload"},
                        "event": event_32mib,
                        "digests": [{"alg": "SHA-256", "digest": hex64('0')}],
                        "index": 2,
                    },
                ],
            }
        }))
        .expect("serialize input");
        assert_eq!(
            eval_policy_vector(&policy, &same_body).await,
            (97, 2, 2, 2),
            "one of two same-body events without SHA-384 must reject"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_td_kernel_extracts_real_pai_event_log() {
        // The real PAI TD kernel measurement carried by the td_payload
        // firmware-blob2 event at RTMR1 in `tdx_CCEL_data_pai`.
        let kernel = "85619a9146b5c1409bf034bdabd6d93df26a5a23b41b43f92a7a4025760a1c4f110194ae75a2b9625b0de97f2b00fc8f";

        let input = pai_tdx_input();

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
    async fn transparency_log_rekor_rootfs_cc_matching_and_tamper() {
        const ROOT: &str = "44f6a7c111eb0d9f4dcbace76e784689dde3436c08bf7dda8d86d9f8c0b02230";
        const TAMPERED: &str = "54f6a7c111eb0d9f4dcbace76e784689dde3436c08bf7dda8d86d9f8c0b02230";

        let logged = manifest("1.0.0", &[("rootfs.cc", ROOT)]);
        let policy = render_rekor(&["rootfs.cc"], &resolved_from_manifest(&logged));

        let ok = tdx_input(&[rootfs_hash_event(Some(2), ROOT)]);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "a matching rootfs measurement must affirm file_system"
        );

        let bad = tdx_input(&[rootfs_hash_event(Some(2), TAMPERED)]);
        assert_eq!(
            eval_policy_vector(&policy, &bad).await,
            (2, 2, 2, 97),
            "a tampered root hash must reject file_system, not executables"
        );

        let none = tdx_input(&[]);
        assert_eq!(
            eval_policy_vector(&policy, &none).await,
            (2, 2, 2, 97),
            "a missing td_payload_info event must reject file_system (fail-closed)"
        );
    }

    /// A transparency-log entry gates every dimension its published types
    /// imply: `rootfs.cc` drives `file_system`, the kernel/image types drive
    /// `executables`, and a mixed entry constrains both.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_published_types_choose_their_dimensions() {
        let root = hex64('a');
        let kernel = hex96('b');
        let event_32mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAACAAAAAA==";

        // Rootfs only: the entry gates file_system alone.
        let rootfs_manifest = manifest("1.0.0", &[("rootfs.cc", root.as_str())]);
        let rootfs_policy = render_rekor(&["rootfs.cc"], &resolved_from_manifest(&rootfs_manifest));
        assert_eq!(
            eval_policy_vector(
                &rootfs_policy,
                &tdx_input(&[rootfs_hash_event(Some(2), &root)])
            )
            .await,
            (2, 2, 2, 2)
        );
        assert_eq!(
            eval_policy_vector(
                &rootfs_policy,
                &tdx_input(&[rootfs_hash_event(Some(2), &hex64('c'))])
            )
            .await,
            (2, 2, 2, 97),
            "a rootfs-only entry must not move executables"
        );

        // Rootfs + kernel in one entry: the entry gates both dimensions, so a
        // measurement it cannot reconstruct rejects both.
        let mixed_manifest = manifest(
            "1.0.0",
            &[
                ("rootfs.cc", root.as_str()),
                ("tdx.kernel", kernel.as_str()),
            ],
        );
        let mixed_policy = render_rekor(
            &["rootfs.cc", "tdx.kernel"],
            &resolved_from_manifest(&mixed_manifest),
        );

        let both = tdx_input(&[
            rootfs_hash_event(Some(2), &root),
            td_payload_event(event_32mib, &kernel, 2),
        ]);
        assert_eq!(
            eval_policy_vector(&mixed_policy, &both).await,
            (2, 2, 2, 2),
            "both published measurements matching must affirm"
        );

        let no_rootfs = tdx_input(&[td_payload_event(event_32mib, &kernel, 2)]);
        assert_eq!(
            eval_policy_vector(&mixed_policy, &no_rootfs).await,
            (97, 2, 2, 97),
            "a mixed entry that cannot reconstruct rootfs rejects both dimensions"
        );
        let no_kernel = tdx_input(&[rootfs_hash_event(Some(2), &root)]);
        assert_eq!(
            eval_policy_vector(&mixed_policy, &no_kernel).await,
            (97, 2, 2, 97),
            "a mixed entry that cannot reconstruct the kernel rejects both dimensions"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_container_image_extracts_real_pai_event_log() {
        // The real PAI AAEL pull-image event resolves to repo `busybox`, which
        // is the repository segment the logged manifest publishes, so the event
        // log is used as-is.
        let image_digest =
            "sha256:16ece118a36d152ed7562347741470b1bb0b0f7561ff1fe0049857a03d4fec5d";

        let input = pai_tdx_input();

        let logged = manifest("1.0.0", &[("container.image.busybox", image_digest)]);
        let policy = render_rekor(
            &["container.image.busybox"],
            &resolved_from_manifest(&logged),
        );
        assert_eq!(
            eval_policy_vector(&policy, &input).await,
            (2, 2, 2, 2),
            "real PAI event log must extract the real image measurement and affirm"
        );

        let tampered = "sha256:26ece118a36d152ed7562347741470b1bb0b0f7561ff1fe0049857a03d4fec5d";
        let bad_logged = manifest("1.0.0", &[("container.image.busybox", tampered)]);
        let bad_policy = render_rekor(
            &["container.image.busybox"],
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
    async fn transparency_log_rekor_accepts_dotted_repository_name() {
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let logged = manifest("1.0.0", &[("container.image.my-app.v2", digest)]);
        let policy = render_rekor(
            &["container.image.my-app.v2"],
            &resolved_from_manifest(&logged),
        );

        let ok = tdx_input(&[aael_event_for_reference(
            "registry.example.com/ns/my-app.v2:latest",
            digest,
        )]);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "a repository name carrying '.' and '-' must affirm"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_strips_only_one_container_image_prefix() {
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        // The repo tail itself starts with `container.image.`. Trimming exactly
        // one prefix leaves it intact; a global replace would reduce it to
        // `foo`, which never equals the extracted repo tail.
        let measurement_type = "container.image.container.image.foo";
        let logged = manifest("1.0.0", &[(measurement_type, digest)]);
        let policy = render_rekor(&[measurement_type], &resolved_from_manifest(&logged));

        let ok = tdx_input(&[aael_event_for_reference(
            "registry.example.com/ns/container.image.foo:v1",
            digest,
        )]);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "trim_prefix must strip exactly one container.image. prefix"
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

    /// The `modules` measurement entry and a `transparency_log` entry that
    /// publishes the same type read one extraction rule, so they agree on
    /// every evidence shape.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_and_modules_kernel_paths_agree() {
        let kernel = "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let conflict = "b1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let logged = manifest("1.0.0", &[("tdx.kernel", kernel)]);
        let transparency = render_rekor(&["tdx.kernel"], &resolved_from_manifest(&logged));
        let modules = render(json!([{"type": "tdx.kernel", "value": kernel}]), &[]);

        let event = |digest: &str, index: Option<i64>, alg: &str| {
            let mut e = json!({
                "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
                "details": {"string": "td_payload"},
                "event": "AAAA",
                "digests": [{"alg": alg, "digest": digest}],
            });
            if let Some(index) = index {
                e["index"] = json!(index);
            }
            e
        };

        let cases: [(&str, Vec<Value>, i8); 4] = [
            ("pass", vec![event(kernel, Some(2), "SHA-384")], 2),
            ("bad index", vec![event(kernel, Some(1), "SHA-384")], 97),
            (
                "missing SHA-384",
                vec![event(&hex64('0'), Some(2), "SHA-256")],
                97,
            ),
            (
                "digest conflict",
                vec![
                    event(kernel, Some(2), "SHA-384"),
                    event(conflict, Some(2), "SHA-384"),
                ],
                97,
            ),
        ];
        for (name, events, expected) in cases {
            let input = tdx_input(&events);
            let transparency_vector = eval_policy_vector(&transparency, &input).await;
            let modules_vector = eval_policy_vector(&modules, &input).await;
            assert_eq!(
                transparency_vector.0, expected,
                "transparency path on case {name:?}"
            );
            assert_eq!(modules_vector.0, expected, "modules path on case {name:?}");
            assert_eq!(
                transparency_vector.0, modules_vector.0,
                "the two kernel paths must agree on case {name:?}"
            );
        }
    }

    /// The same real PAI event log feeds both kernel paths to the same verdict.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_and_modules_agree_on_real_pai_event_log() {
        const REAL_KERNEL_DIGEST: &str =
            "85619a9146b5c1409bf034bdabd6d93df26a5a23b41b43f92a7a4025760a1c4f110194ae75a2b9625b0de97f2b00fc8f";

        let input = pai_tdx_input();

        let logged = manifest("1.0.0", &[("tdx.kernel", REAL_KERNEL_DIGEST)]);
        let transparency = render_rekor(&["tdx.kernel"], &resolved_from_manifest(&logged));
        let modules = render(
            json!([{"type": "tdx.kernel", "value": REAL_KERNEL_DIGEST}]),
            &[],
        );

        assert_eq!(
            eval_policy_vector(&transparency, &input).await,
            eval_policy_vector(&modules, &input).await,
            "the two kernel paths must agree on the real PAI event log"
        );
        assert_eq!(eval_policy_vector(&modules, &input).await, (2, 2, 2, 2));
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_compares_values_without_format_checks() {
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
            "the signed digest must affirm"
        );

        // Any value that differs from the signed one changes the reconstructed
        // manifest and rejects; no format regex is involved.
        for other in [
            "sha256:D42F6E1B2AAFB59383D0892824AEBF5E0A2E27DAD989A3FB26552A6E77E4BE46",
            "sha256:abc123",
            "d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
        ] {
            let bad = tdx_input(&[aael_event(other)]);
            assert_eq!(
                eval_policy_vector(&policy, &bad).await,
                (97, 2, 2, 2),
                "a digest {other:?} different from the signed value must reject"
            );
        }

        // The signed value is the only contract: a non-canonical digest the
        // publisher signed and the evidence reports is accepted unchanged.
        let non_canonical = "sha256:abc123";
        let logged = manifest("1.0.0", &[("container.image.cmaas-runtime", non_canonical)]);
        let policy = render_rekor(
            &["container.image.cmaas-runtime"],
            &resolved_from_manifest(&logged),
        );
        let matching = tdx_input(&[aael_event(non_canonical)]);
        assert_eq!(
            eval_policy_vector(&policy, &matching).await,
            (2, 2, 2, 2),
            "extraction does not impose a digest format the publisher did not"
        );
    }
}

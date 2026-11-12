# The `modules` Attestation Policy

`modules` is a builtin attestation policy type that expresses verification as a modular list of rules. Each entry is one typed check over one part of the evidence: a boot or workload measurement (guest firmware, kernel, UKI, root filesystem, container image, model), a GPU appraisal, the TDX platform attributes, or a measurement baseline anchored in a transparency log. The container image, model, and root filesystem types use the `com.alibabacloud.` vendor prefix as their canonical spelling. Container image and model evidence comes from Alibaba AAEL events, while `rootfs.cc` reads the `td_payload_info` platform config flags event. Measurement and platform-attribute entries pin their expected values inline, and the generated verification rule compares the evidence against those constants directly; a `transparency_log` entry instead anchors its baseline in a transparency log. Set it on the verify side under `as_type: "builtin"` in `attestation_policy`; placement and the other policy types are covered in [Remote Attestation](remote_attestation.md).

## Policy shape

Every entry is `{"type": "<type>", "value": <value>}`. Measurement types take a string value, the pinned digest; `tdx` and `nvidia` take an options object, `com.alibabacloud.gpu` takes an empty object, and `transparency_log` takes an options object describing the log-anchored baseline.

A flat list is one group:

```json
"attestation_policy": {
    "type": "modules",
    "modules": [
        { "type": "tdx",       "value": {} },
        { "type": "nvidia",    "value": {} },
        { "type": "tdx.ovmf",  "value": "19de6c23abcb441c128f7070a95bb75fed723ae6e3276c80e44367b03d543d48ed3377a954d21b32f8c5bc474e068fe5" },
        { "type": "tdx.kernel","value": "1f709fa8a1171ebafcdd70b74d40c6225e8e671555379e082a5636e3981ad61f98441c0f3369a22e5a74c63b0ac2f265" },
        { "type": "com.alibabacloud.container.image.model-server", "value": "sha256:c5945b51138c975fe3f0315a17a469b87f009ceaa6fc69ba461c5811fbb781a0" },
        { "type": "com.alibabacloud.ai.model.Qwen/Qwen3.8-27B",    "value": "c2d3b69b8fe371d95c80e3962669156810c0328c6165306b8decf843149184a9" }
    ]
}
```

Entries within one group AND when they belong to the same AR4SI dimension. A list of lists gives several groups, each an independent baseline: each dimension affirms when one of the groups carrying entries of that dimension passes in full, and groups without entries of that dimension do not constrain it. Groups are how you bind modules of one dimension to each other: if firmware A is approved only with kernel A, pin `{ovmf A, kernel A}` as one group and `{ovmf B, kernel B}` as the other; evidence mixing OVMF A with kernel B satisfies neither baseline's executable checks.

<details>
<summary>Example: two alternative baselines (nested groups)</summary>

```json
"attestation_policy": {
    "type": "modules",
    "modules": [
        [
            { "type": "tdx",       "value": {} },
            { "type": "tdx.ovmf",  "value": "19de6c23abcb441c128f7070a95bb75fed723ae6e3276c80e44367b03d543d48ed3377a954d21b32f8c5bc474e068fe5" },
            { "type": "tdx.kernel","value": "1f709fa8a1171ebafcdd70b74d40c6225e8e671555379e082a5636e3981ad61f98441c0f3369a22e5a74c63b0ac2f265" }
        ],
        [
            { "type": "tdx",        "value": {} },
            { "type": "tdx.td-shim","value": "04caf4fb18079198bec7cfcf4883dc3ae93f8deae6fa99b4d3af9e27ef69d71e2d4774551edb334abd05f871041c52a5" },
            { "type": "tdx.kernel", "value": "1f709fa8a1171ebafcdd70b74d40c6225e8e671555379e082a5636e3981ad61f98441c0f3369a22e5a74c63b0ac2f265" }
        ]
    ]
}
```

The first group accepts an OVMF-booted VM, the second a td-shim-booted confidential container.
</details>

An omitted or empty `modules` list (`{"type": "modules"}`, `[]`, or `[[]]`) is one empty group and asserts nothing: every dimension keeps its default, so `hardware` stays at 97 (non-affirming) whatever the evidence form. To assert hardware recognition, add a `tdx` entry or use the `hardware_only` policy.

Omitting a module type imposes nothing on that part of the evidence. Listing one is fail-closed: when the evidence lacks the measured value, or the value differs from the pinned baseline, the appraisal is non-affirming and TNG refuses the tunnel.

Baseline evidence checks run regardless of the policy: quote signature verification, replay of the event log against the quote's RTMR registers, and the report-data session binding (the fresh-quote anti-replay check) are properties of the verifier, not policy-configurable rules.

## Trustworthiness dimensions

Each module type gates one or more AR4SI trustworthiness dimensions:

| Module type | Dimension |
|---|---|
| `tdx.td-shim`, `tdx.ovmf`, `tdx.kernel`, `tdx.uki` | `executables` |
| `com.alibabacloud.container.image.<repo>` | `executables` |
| `com.alibabacloud.ai.model.<model-id>` | `executables` |
| `com.alibabacloud.rootfs.cc` | `file_system` |
| `transparency_log` | the dimensions of the types in its `publishedMeasurements` |
| `tdx` | `hardware` |
| `nvidia` | `hardware` |
| `com.alibabacloud.gpu` | `hardware` |

A dimension with no entries stays affirming (2). `configuration` has no module types and always stays affirming. `hardware` is the exception: once the policy has any entry, it requires the platform the entries' evidence comes from to be recognised. A modules policy recognises only TDX (quote header `tee_type` `81000000`, `vendor_id` `939a7233f79c4ca9940a0db3957f0607`); the CSV, TPM, and system recognition paths of `hardware_only` do not apply. A `tdx` entry adds attribute checks on top of recognition, so it fails closed on non-TDX evidence.

A `transparency_log` entry's dimensions come from the types in its `publishedMeasurements`; `fallbackPublishedMeasurements` is a subset and adds no dimension. An entry that fails affects only the dimensions it gates.

## Configuration errors

These are rejected when the policy loads, before any appraisal runs:

- an entry `type` outside the set listed below, including a mistyped family prefix; the `com.alibabacloud.` prefix is only legal on `container.image.`, `ai.model.`, `rootfs.cc`, and the exact type `gpu`, and unprefixed `gpu` is not a type;
- the same `type` twice within one group, including the canonical and alias spellings of one family (the same type in different groups is legal; the groups are independent baselines). `transparency_log` is the one exception: it may repeat within a group so several log-anchored baselines must all verify;
- a value in the wrong shape or format: wrong digest length or uppercase hex (all digests are lowercase), a `com.alibabacloud.container.image.*` value without the `sha256:` prefix, an object given where the type expects a string or the reverse;
- a `transparency_log` entry whose value violates the field constraints in the Transparency log section below. A `fallbackServices` list without `fallbackPublishedMeasurements` is accepted but has no effect;
- an unknown field inside a `tdx`, `nvidia`, or `com.alibabacloud.gpu` options object; the `com.alibabacloud.gpu` value must be the empty object `{}`;
- an `nvidia` entry whose `min_count` is below 1 (omit the entry to disable GPU appraisal);
- a `tdx` `collateral.min_tcb_date` that is not `YYYY-MM-DD`;
- a non-empty `reference_values` list supplied alongside a `modules` policy: the generated rules do not read reference values, so the list is refused at load. An empty list (`[]`) is accepted. Non-empty lists are accepted only by the `inline` and `path` policies, whose rules do consume reference values.

## Module types

| Type | Alias | Value shape | Measured against |
|---|---|---|
| `tdx.td-shim` | — | 96 lowercase hex | quote `mr_td`, TD booted through td-shim guest firmware |
| `tdx.ovmf` | — | 96 lowercase hex | quote `mr_td`, TD booted through OVMF firmware |
| `tdx.kernel` | — | 96 lowercase hex | the `td_payload` event in the UEFI event log, recorded in RTMR1 (SHA-384) |
| `tdx.uki` | — | 96 lowercase hex | the UKI boot-application event of the UEFI event log (SHA-384) |
| `com.alibabacloud.container.image.<repo>` | `container.image.<repo>` | `sha256:<64 lowercase hex>` | AAEL `kangaroo/pull-image` events for repo tail `<repo>` |
| `com.alibabacloud.ai.model.<model-id>` | `ai.model.<model-id>` | 64 lowercase hex | AAEL `pai/load-model` events for that model |
| `com.alibabacloud.rootfs.cc` | `rootfs.cc` | 64 lowercase hex | the `td_payload_info` event in the UEFI event log, dm-verity root hash of the root filesystem |
| `transparency_log` | — | options object | a ReleaseManifest recorded in a transparency log (rekor-v1 or artifact-server primary) |
| `tdx` | — | options object | quote attributes and event log (platform attribute checks) |
| `nvidia` | — | options object | appraised per-GPU claims (standard NVIDIA appraisal) |
| `com.alibabacloud.gpu` | — | empty object `{}` | AAEL `gpu/attestation` events and their result codes |

To see the exact Rego a configuration generates, run `tng tools policy export` (see [TNG Tools](tools.md#tng-tools-policy)).

### Guest firmware measurement: `tdx.td-shim`, `tdx.ovmf`

```json
{ "type": "tdx.ovmf", "value": "19de6c23abcb441c128f7070a95bb75fed723ae6e3276c80e44367b03d543d48ed3377a954d21b32f8c5bc474e068fe5" }
```

Pins the TD launch measurement, the `mr_td` field of the TDX quote. This is the SHA-384 value the hardware recorded for the initial TD image built from the guest firmware when the TD was created. The entry requires `mr_td` to equal the pinned value. A missing field or any other value fails it. `tdx.td-shim` and `tdx.ovmf` read the same field, so use the one that matches how the TD is booted.

### Kernel measurement: `tdx.kernel`

```json
{ "type": "tdx.kernel", "value": "1f709fa8a1171ebafcdd70b74d40c6225e8e671555379e082a5636e3981ad61f98441c0f3369a22e5a74c63b0ac2f265" }
```

Pins the kernel measurement taken at boot: the SHA-384 digest the firmware logged for the TD payload (kernel) blob. The entry reads the `td_payload` event in the UEFI event log. The event must be recorded in RTMR1 (register index 2), every matching event must carry a SHA-384 digest, and every SHA-384 digest across those events must be the same. No matching event, an event at another index or with no index, an event without a SHA-384 digest, or a digest mismatch fails the entry. The blob length in the event is not checked.

### UKI measurement: `tdx.uki`

```json
{ "type": "tdx.uki", "value": "5bee5bdf63538ba7aa5c60d4725193c88932aa17083276fe9d61e4963ab6f871cdf3b3dd5d99733169b8c87a5e8e62b3" }
```

Pins the unified kernel image (UKI) measurement. The firmware measures the UKI as an EFI boot application and logs an `EV_EFI_BOOT_SERVICES_APPLICATION` event. The entry needs at least one such event. Every event must carry a SHA-384 digest, and every SHA-384 digest across those events must be the same, equal to the pinned value. The entry has no device path selector, so it assumes a single boot application: an extra boot application with a different digest fails it. A deployment that does not boot a UKI has no such event, so configuring this entry fails it; use `tdx.kernel` for that boot path.

### Container image: `com.alibabacloud.container.image.<repo>`

```json
{ "type": "com.alibabacloud.container.image.model-server", "value": "sha256:c5945b51138c975fe3f0315a17a469b87f009ceaa6fc69ba461c5811fbb781a0" }
```

This entry is Alibaba-coupled: the evidence comes from AAEL `alibabacloud.com` events. It pins the OCI manifest digest of a workload image. The evidence is the AAEL `kangaroo/pull-image` event with event type `EV_EVENT_TAG`. The entry looks at the events whose repository name is `<repo>`. There must be at least one, each must carry a `digest`, and all must report the same digest, equal to the pinned `sha256:` value. `<repo>` is the last path segment of the image reference, after removing the registry host, path prefix, tag, and digest. Use only ASCII letters, digits, `.`, `_`, and `-`; a name with `/`, `@`, or `:` cannot match the reference and is rejected when the policy loads. When the same type appears in a `transparency_log` entry's `publishedMeasurements` or `fallbackPublishedMeasurements`, write it exactly as the log records it, usually the same last path segment. If no pull event matches, the entry fails.

### Model: `com.alibabacloud.ai.model.<model-id>`

```json
{ "type": "com.alibabacloud.ai.model.Qwen/Qwen3.8-27B", "value": "c2d3b69b8fe371d95c80e3962669156810c0328c6165306b8decf843149184a9" }
```

This entry is Alibaba-coupled: the evidence comes from AAEL `alibabacloud.com` events. It pins a model's measured integrity hash, 64 lowercase hex. The evidence is the AAEL `pai/load-model` event with event type `EV_EVENT_TAG`. `<model-id>` must match the model identifier in the event exactly (a modelscope-id style name is the convention); it may contain ASCII letters, digits, `.`, `_`, `/`, `@`, `:`, `+`, and `-`, and any other character is rejected at load. There must be at least one load event. Every event must carry both `model-id` and `hash`; all `model-id` values must equal `<model-id>`, and all `hash` values must equal the pinned value. A load event for another model fails the entry. Each model defines how its hash is computed, for example an fs-verity digest over the stored model.

### Root filesystem: `rootfs.cc`

```json
{ "type": "com.alibabacloud.rootfs.cc", "value": "44f6a7c111eb0d9f4dcbace76e784689dde3436c08bf7dda8d86d9f8c0b02230" }
```

This entry pins the dm-verity hash tree root hash of the confidential-container root filesystem, 64 lowercase hex without a `sha256:` prefix. The evidence is the `EV_PLATFORM_CONFIG_FLAGS` event in the UEFI event log whose `details.string` starts with `td_payload_info `. Every such event must be recorded in RTMR1 (register index 2); an event at another index or with no index fails the entry. The root hash is read from the `dm-mod.create="verity-root,..."` table in the event string: the device name must be `verity-root`, the algorithm `sha256`, and the hash lowercase hex. Other dm devices in the same string are not read. An event whose string has no `verity-root` table is ignored, at least one event must carry the table, and every extracted root hash must be identical and equal to the pinned value. No matching event, no `verity-root` table, or two different root hashes fails the entry.

In a `transparency_log` entry's `publishedMeasurements` or `fallbackPublishedMeasurements`, write `rootfs.cc`. The prefixed spelling is rejected there at load.

### Platform attributes: `tdx`

```json
{ "type": "tdx", "value": { "debug": "deny", "eventlog": "required" } }
```

Adding this entry checks the TDX quote's platform attributes. Each field defaults to its strictest value, so `{"type": "tdx", "value": {}}` applies the strict checks. `tcb` and `collateral` are opt-in; leaving them out imposes no requirement. There is no on/off switch: omit the entry to skip these checks.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `debug` | `"deny"` / `"allow"` | `"deny"` | `deny` refuses TDs with the debug attribute set |
| `sept_ve_disable` | `"require"` / `"allow"` | `"require"` | `require` demands the SEPT #VE-disable attribute is set, closing the #VE escape surface on pending pages |
| `perfmon` | `"deny"` / `"allow"` | `"deny"` | `deny` refuses TDs granted performance-counter access |
| `service_td` | `"deny"` / `"allow"` | `"deny"` | `deny` requires the Service TD measurement to be zero or absent (a v4 quote without the field counts as absent) |
| `tcb` | object | absent (no TCB gate) | TCB status and advisory gate, below |
| `collateral` | object | absent (no collateral gate) | TCB collateral freshness gate, below |
| `eventlog` | `"required"` / `"optional"` | `"required"` | `required` demands a non-empty UEFI event log |

`debug`, `sept_ve_disable`, and `perfmon` check attribute bits in the quote's TD attributes; `service_td` checks the Service TD measurement. `allow` skips the respective check.

`debug` set to `deny` rejects a TD booted with the debug attribute set (first byte of the quote's TD attributes odd, e.g. the attributes starting `01`) even when every other check passes. An otherwise valid production TD passes `{"type": "tdx", "value": {}}`.

**TCB gate (`tcb`).** Opt-in; absent means no TCB requirement, so deployments whose evidence carries no TCB evaluation appraise normally.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `min_status` | `"up_to_date"` / `"out_of_date"` | `"up_to_date"` | the lowest accepted TCB status; `up_to_date` also rejects the out-of-date ranks. A revoked TCB is always rejected once the gate is configured |
| `reject_advisories` | list of strings | `[]` | advisory IDs (e.g. `"INTEL-SA-00330"`) that reject the appraisal when the platform reports itself affected by them |
| `allow_advisories` | list of strings | `[]` | exemptions subtracted from `reject_advisories` |

**Collateral gate (`collateral`).** Opt-in; absent applies no collateral check.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `allow_expired` | boolean | `false` | accept expired TCB collateral |
| `min_tcb_date` | string `YYYY-MM-DD` | absent | require the platform's TCB level date at or after this date, i.e. not affected by TCB-level vulnerabilities disclosed before it |
| `max_collateral_age_days` | int | absent | require the collateral issued no more than N days before the appraisal |

```json
{ "type": "tdx", "value": {
    "tcb": { "min_status": "up_to_date", "reject_advisories": ["INTEL-SA-00001"], "allow_advisories": ["INTEL-SA-00002"] },
    "collateral": { "allow_expired": false, "min_tcb_date": "2026-06-01", "max_collateral_age_days": 30 }
} }
```

A debug TD, a revoked TCB, an advisory in `reject_advisories` that is not in `allow_advisories`, or expired collateral while `allow_expired` is `false` fails the entry when the corresponding check is enabled.

### GPU attestation event: `com.alibabacloud.gpu`

```json
{ "type": "com.alibabacloud.gpu", "value": {} }
```

This entry has no unprefixed alias, and its value is the empty object `{}`. It is Alibaba-coupled: the evidence is the attestation agent's AAEL `alibabacloud.com` `gpu/attestation` event. At least one such event must exist, and every such event must report zero for both `gpu-collect-evidence-result-code` and `gpu-attest-result-code`. The first code reports whether evidence collection succeeded; the second reports the GPU attestation result. Event-log replay keeps the codes from being tampered with after boot, but the codes themselves are guest-reported.

To appraise per-GPU device claims instead of the guest-reported codes, use `nvidia`.

### GPU appraisal: `nvidia`

Omitting the entry skips GPU appraisal entirely. Present, the entry appraises the per-GPU claims the verifier derives from GPU evidence carried in the attestation: identity, versions, CC mode, and measurement, checked against the fields below. Evidence that only passes the raw GPU attestation report through without per-GPU evaluation is rejected, and GPUs absent from the evidence fail the count checks. Appraisal therefore requires the attester to upload GPU evidence; a deployment that collects none fails the entry.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `require_cc_mode` | boolean | `true` | every enumerated GPU must report confidential-computing mode enabled |
| `require_report` | boolean | `true` | every GPU must carry an appraised attestation measurement |
| `min_count` | int | `1` | at least N GPUs must be enumerated |
| `allow_uuids` | list of strings | `[]` (no whitelist) | allowed GPU UUIDs, e.g. `"GPU-3f9c2a1b-88d4-4e17-9c2a-71f0d5a4b6e8"` |
| `allow_driver_versions` | list of strings | `[]` (no whitelist) | allowed driver versions, e.g. `"570.148.05"` |
| `allow_vbios_versions` | list of strings | `[]` (no whitelist) | allowed VBIOS versions, e.g. `"96.00.f4.00.07"` |
| `measurement_digest` | list of 96-char lowercase hex | `[]` (no whitelist) | allowed per-GPU measurement digests, SHA-384 over each GPU's measurements |

The whitelist fields compare exact strings; an empty list means no restriction. The checks cover only the GPUs the driver enumerates; a GPU hidden from enumeration escapes them.

```json
{ "type": "nvidia", "value": {
    "require_cc_mode": true,
    "min_count": 1,
    "allow_uuids": ["GPU-3f9c2a1b-88d4-4e17-9c2a-71f0d5a4b6e8"],
    "allow_driver_versions": ["570.148.05"],
    "allow_vbios_versions": ["96.00.f4.00.07"],
    "measurement_digest": ["7430ef5370b61ba48a61739b6ea4a038e6456924a0af6d3b757cbc4fe98b85a087ed4bca2df36543902377da0c673e8a"]
} }
```

**Current strength limit.** The appraisal compares the appraised device claims. Cryptographic verification of the GPU attestation report's signature, the GPU certificate chain, and the driver RIM file is verifier-side follow-up work; until it lands, appraisal reflects the claims recorded when the verifier parses the report, not the report's own authenticity.

### Transparency log: `transparency_log`

```json
{ "type": "transparency_log", "value": {
    "publishedMeasurements": ["tdx.td-shim", "container.image.cmaas-runtime"],
    "schemaVersion": "1.0.0",
    "services": [{ "type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 2310520944 }]
} }
```

Use this entry to keep the trusted measurement values in a release manifest recorded in a transparency log, instead of writing the digests into the policy. At appraisal, TNG compares the measurements in the current evidence with the recorded baseline, so the policy only points to the log entry. This is a `modules` entry type. The top-level `attestation_policy.type = "transparency_log"` form from earlier releases no longer exists.

**When it loads and when it appraises.** With a `rekor-v1` primary, TNG fetches and checks the log entry when the policy loads: it looks up the entry by `logIndex` and verifies the signed checkpoint, the Merkle inclusion proof, and the Signed Entry Timestamp. If `rekorPublicKeyPem` is omitted, TNG uses the well-known key for `rekor.sigstore.dev` / `rekor.openanolis.cn`; other logs must supply their own. Entries are fetched one by one, so a policy with several `rekor-v1` entries performs one lookup per entry. With an `artifact-server` primary, the policy loads without network access and the entry is resolved at appraisal.

**What it verifies.** The entry compares the measurements in the current TDX evidence with the baseline recorded in the transparency log. If the measurement types, any value, or the `schemaVersion` differ from the baseline, verification fails. The order of `publishedMeasurements` does not matter. If the evidence lacks any configured measurement, verification fails; TNG does not compare a baseline with that measurement left out. The publisher signature is always checked, with `publisherPublicKeyPem` when set and the built-in publisher key otherwise.

**Fallback.** The optional fallback is used only when the primary returns `fail`. `ok` never triggers it, and `deny` (a revoked measurement) is a hard rejection that never falls back. If the primary cannot be evaluated because a configured measurement is missing, that counts as `fail`, so the fallback baseline is still consulted. A failed primary with no fallback rejects.

**Relationship to `tdx`.** This entry only checks measurements. Platform attributes are a separate `tdx` entry.

**Several entries.** `transparency_log` may appear more than once in the same group. Entries in one group must all pass; entries in different groups are alternatives, so any one passing is enough. Use the first shape when several logs must agree, the second when any of several versions is acceptable.

```json
"modules": [
    { "type": "transparency_log", "value": { "publishedMeasurements": ["container.image.cmaas-runtime"], "services": [{ "type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 100 }] } },
    { "type": "transparency_log", "value": { "publishedMeasurements": ["container.image.cmaas-runtime"], "services": [{ "type": "rekor-v1", "logUrl": "https://rekor.openanolis.cn", "logIndex": 200 }] } }
]
```

```json
"modules": [
    [{ "type": "transparency_log", "value": { "publishedMeasurements": ["container.image.cmaas-runtime"], "services": [{ "type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 100 }] } }],
    [{ "type": "transparency_log", "value": { "publishedMeasurements": ["container.image.cmaas-runtime"], "services": [{ "type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 200 }] } }]
]
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `publishedMeasurements` | list of strings | — | (required) Non-empty measurement types; allowed values are `tdx.td-shim`, `tdx.kernel`, `rootfs.cc`, and any single-segment `container.image.<repo>`; a type may not repeat. Write the container image and `rootfs.cc` types exactly as the transparency log records them; the `com.alibabacloud.` aliases do not match the logged names and are rejected at load. Order does not matter |
| `schemaVersion` | string | `"1.0.0"` | Must equal the logged manifest's `schemaVersion` |
| `services` | list | — | (required) Exactly one service, either a `rekor-v1` or an `artifact-server` entry |
| `services[].type` | string | — | (required) `"rekor-v1"` or `"artifact-server"` |
| `services[].logUrl` | string | — | (required for `rekor-v1`) Rekor v1 log base URL |
| `services[].logIndex` | int | — | (required for `rekor-v1`) Rekor v1 entry index to fetch and authenticate; must be `>= 0` |
| `services[].rekorPublicKeyPem` | string | built-in | Optional log public key PEM (verifies checkpoint/SET); omit for the well-known `rekor.sigstore.dev` / `rekor.openanolis.cn` key, required for other logs |
| `services[].publisherPublicKeyPem` | string | built-in publisher key | Overrides the publisher key the DSSE signature is verified against |
| `services[].url` | string | — | (required for `artifact-server`) Artifact-server base URL |
| `services[].logServices` | list | — | (required for `artifact-server`) Non-empty list of `{"type": "rekor-v1", "url": "<rekor url>"}` entries, with distinct URLs |
| `fallbackPublishedMeasurements` | list of strings | absent | Measurement types used on the fallback path; non-empty and a subset of `publishedMeasurements`. The fallback takes effect only when both this field and `fallbackServices` are set; setting this field without `fallbackServices` is rejected |
| `fallbackServices` | list | absent | Non-empty list of `rekor-v1` services; only valid with an `artifact-server` primary. Only the first entry is used, and the fallback also requires `fallbackPublishedMeasurements`, so this field alone has no effect |

**Migrating from the top-level type.** Wrap the old policy value in a `modules` entry: `{"type": "modules", "modules": [{"type": "transparency_log", "value": <old value>}]}`. Add a `tdx` entry if the old non-debug and event-log checks are wanted (TDX recognition is automatic); with only the `transparency_log` entry, `hardware` reduces to that recognition. Delete any non-empty `reference_values`, which the new policy rejects at load.

## Migrating from the fixed policy types

| Removed type | `modules` equivalent |
|---|---|
| `transparency_log` (top-level `attestation_policy.type`) | a `modules` policy with a `transparency_log` entry, plus a `tdx` entry when the old platform checks are wanted; drop any non-empty `reference_values` |
| `hardware_with_reference_values` | boot-measurement entries (`tdx.td-shim`/`tdx.ovmf`, `tdx.kernel`, `tdx.uki`) with the expected digests pinned inline; or `transparency_log` for log-anchored baselines |
| `hardware_strict_with_reference_values` | the same entries plus `{"type": "tdx", "value": {"sept_ve_disable": "allow", "perfmon": "allow", "service_td": "allow"}}` to match the old strict checks on TDX evidence |
| `hardware_strict_with_measurements` | `com.alibabacloud.ai.model.<model-id>` and `com.alibabacloud.container.image.<repo>` entries pinning the same baselines inline, plus a `tdx` entry with `sept_ve_disable`, `perfmon`, and `service_td` set to `allow` to match the old strict checks on TDX evidence; the separate `reference_values` list is dropped |

On TDX evidence, `hardware_only_strict` is reproduced by a single `{"type": "tdx", "value": {}}` entry only after setting `sept_ve_disable`, `perfmon`, and `service_td` to `allow`: the `tdx` defaults also gate those three attributes, so the plain entry is stricter than `hardware_only_strict`. The equivalence is limited to TDX evidence, because the `tdx` entry fails on any other platform. An empty modules list is not equivalent to `hardware_only`: it asserts nothing and leaves `hardware` non-affirming.

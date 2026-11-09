# The `modules` Attestation Policy

`modules` is a builtin attestation policy type that expresses verification as a modular list of rules. Each entry is one typed check over one part of the evidence: a boot measurement (guest firmware, kernel, UKI, container image, model), a GPU appraisal, the TDX platform posture, or a measurement baseline anchored in a transparency log. Entry types whose evidence comes from Alibaba AAEL events carry the `com.alibabacloud.` vendor prefix; the two measurement families keep their unprefixed spellings as permanent aliases. Each entry pins its expected value inline, and the generated verification rule compares the evidence against that constant directly. Set it on the verify side under `as_type: "builtin"` in `attestation_policy`; placement and the other policy types are covered in [Remote Attestation](remote_attestation.md).

## Policy shape

Every entry is `{"type": "<type>", "value": <value>}`. Measurement types take a string value, the pinned digest; the posture types (`tdx`, `nvidia`) take an options object, `com.alibabacloud.gpu` takes an empty object, and `transparency_log` takes an options object describing the log-anchored baseline.

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

Each module type gates one AR4SI trustworthiness dimension:

| Module type | Dimension |
|---|---|
| `tdx.td-shim`, `tdx.ovmf`, `tdx.kernel`, `tdx.uki` | `executables` |
| `com.alibabacloud.container.image.<repo>` | `executables` |
| `com.alibabacloud.ai.model.<model-id>` | `executables` |
| `transparency_log` | `executables` |
| `tdx` | `hardware` |
| `nvidia` | `hardware` |
| `com.alibabacloud.gpu` | `hardware` |

Within one group, the entries of a dimension AND with each other, and each dimension is OR-ed over the groups that carry entries of it. A dimension with no entries of it stays affirming (2), with one exception: `hardware` depends on the platform the entries' evidence comes from. With at least one entry in the policy, `hardware` requires that platform to be recognised even when there are no posture entries; with no entries at all it stays non-affirming. `configuration` and `file_system` have no module types at all, so they always stay affirming. As a result a failing measurement moves `executables` only, while a failing posture entry moves `hardware` only and leaves `executables` affirming.

The `hardware` dimension is gated on the TEE platform every entry's evidence comes from. Every current entry reads evidence under `input.tdx` (the quote and event-log measurements, the AAEL event-log families, and the evaluated GPU claims), so a modules policy recognises only TDX: the quote header with the Intel quoting-enclave tee type `81000000` and vendor id `939a7233f79c4ca9940a0db3957f0607`. The CSV, TPM, and system recognition paths of `hardware_only` are not part of a modules policy, and their evidence is never consumed by an entry. Posture entries add constraints on top of recognition; they do not replace it. An entry such as `{"type": "tdx", "value": {}}` requires both a recognized TDX platform and the posture checks, so it fails closed on non-TDX evidence.

An empty module list declares no platform dependency, so no recognition rule is emitted: `executables`, `configuration`, and `file_system` affirm, while `hardware` stays at its non-affirming default (97). This differs from `hardware_only`, which recognises TDX and the legacy platforms; to assert hardware recognition with modules, add a `tdx` entry, or use the `hardware_only` policy directly.

## Configuration errors

These are rejected when the policy loads, before any appraisal runs:

- an entry `type` outside the set listed below, including a mistyped family prefix; the `com.alibabacloud.` prefix is only legal on `container.image.`, `ai.model.`, and the exact type `gpu`, and unprefixed `gpu` is not a type;
- the same `type` twice within one group, including the canonical and alias spellings of one family (the same type in different groups is legal; the groups are independent baselines). `transparency_log` is the one exception: it may repeat within a group so several log-anchored baselines must all verify;
- a value in the wrong shape or format: wrong digest length or uppercase hex (all digests are lowercase), a `com.alibabacloud.container.image.*` value without the `sha256:` prefix, an object given where the type expects a string or the reverse;
- a `transparency_log` entry whose value violates the entry schema: an empty or unsupported `publishedMeasurements` list, a duplicate measurement type, an empty `services` list or more than one service, an `artifact-server` primary that is not the only service, an unknown field in the value object, an unfilled fallback pairing, or a fallback that is empty, not `rekor-v1`, or not a subset of `publishedMeasurements` (see the entry section below);
- a name segment (`<repo>`, `<model-id>`) containing characters outside `[A-Za-z0-9._/@:+-]`;
- an unknown field inside a `tdx`, `nvidia`, or `com.alibabacloud.gpu` options object; the `com.alibabacloud.gpu` value must be the empty object `{}`;
- an `nvidia` entry whose `min_count` is below 1 (omit the entry to disable GPU appraisal);
- a `tdx` `collateral.min_tcb_date` that is not `YYYY-MM-DD`;
- a non-empty `reference_values` list supplied alongside a `modules` policy: the generated rules compare the evidence against the pinned constants and never read reference values, so the list is refused at load. An empty list (`[]`) is accepted. Non-empty lists are accepted only by the `inline` and `path` policies, whose rules do consume reference values.

## Module types

| Type | Value shape | Measured against |
|---|---|---|
| `tdx.td-shim` | 96 lowercase hex | quote `mr_td`, TD booted through td-shim guest firmware |
| `tdx.ovmf` | 96 lowercase hex | quote `mr_td`, TD booted through OVMF firmware |
| `tdx.kernel` | 96 lowercase hex | the `td_payload` event of the UEFI event log (SHA-384) |
| `tdx.uki` | 96 lowercase hex | the UKI boot-application event of the UEFI event log (SHA-384) |
| `com.alibabacloud.container.image.<repo>` | `sha256:<64 lowercase hex>` | AAEL `kangaroo/pull-image` events for repo tail `<repo>` |
| `com.alibabacloud.ai.model.<model-id>` | 64 lowercase hex | AAEL `pai/load-model` events for that model |
| `transparency_log` | options object | a ReleaseManifest recorded in a transparency log (rekor-v1 or artifact-server primary) |
| `tdx` | options object | quote attributes and event log (platform posture) |
| `nvidia` | options object | appraised per-GPU claims (standard NVIDIA appraisal) |
| `com.alibabacloud.gpu` | empty object `{}` | AAEL `gpu/attestation` events and their result codes |

`container.image.<repo>` and `ai.model.<model-id>` are permanent aliases of their `com.alibabacloud.` spellings and produce byte-identical policies. `com.alibabacloud.gpu` has no unprefixed alias.

`tdx.td-shim` and `tdx.ovmf` pin the same quote field; use whichever matches how the TD is booted. To see the exact Rego a configuration generates, run `tng tools policy export` (see [TNG Tools](tools.md#tng-tools-policy)).

### Guest firmware measurement: `tdx.td-shim`, `tdx.ovmf`

```json
{ "type": "tdx.ovmf", "value": "19de6c23abcb441c128f7070a95bb75fed723ae6e3276c80e44367b03d543d48ed3377a954d21b32f8c5bc474e068fe5" }
```

Pins the TD launch measurement, the `mr_td` field of the TDX quote: the SHA-384 digest the hardware recorded for the initial TD image built from the guest firmware at TD creation.

- Pass: the quote's `mr_td` equals the pinned value.
- Fail: any other `mr_td`, or non-TDX evidence (the value is absent, which fails closed).

### Kernel measurement: `tdx.kernel`

```json
{ "type": "tdx.kernel", "value": "1f709fa8a1171ebafcdd70b74d40c6225e8e671555379e082a5636e3981ad61f98441c0f3369a22e5a74c63b0ac2f265" }
```

Pins the kernel measurement taken at boot: the SHA-384 digest the firmware recorded in the event log's `td_payload` event for the TD payload (kernel) blob. If the log carries several `td_payload` events they must all report the same digest; conflicting events fail the entry.

- Pass: a `td_payload` event whose SHA-384 digest equals the pinned value.
- Fail: a different digest, or no `td_payload` event in the log.

### UKI measurement: `tdx.uki`

```json
{ "type": "tdx.uki", "value": "5bee5bdf63538ba7aa5c60d4725193c88932aa17083276fe9d61e4963ab6f871cdf3b3dd5d99733169b8c87a5e8e62b3" }
```

Pins the unified kernel image (UKI) measurement: firmware measures the UKI as an EFI boot application and logs it as a boot-services-application event; the entry matches the SHA-384 digest recorded on such an event. Every `EV_EFI_BOOT_SERVICES_APPLICATION` event in the log must carry the pinned SHA-384 digest, and at least one such event must exist. The entry has no device-path selector, so it assumes a single boot-application baseline: a deployment that logs another boot application with a different digest fails closed. Deployments that do not boot a UKI produce no such event, so configuring this entry fails them closed; use `tdx.kernel` for their boot path.

- Pass: every boot-services-application event carries the pinned SHA-384 digest.
- Fail: any such event with a different digest, or no such event in the log.

### Container image: `com.alibabacloud.container.image.<repo>`

```json
{ "type": "com.alibabacloud.container.image.model-server", "value": "sha256:c5945b51138c975fe3f0315a17a469b87f009ceaa6fc69ba461c5811fbb781a0" }
```

The unprefixed `container.image.<repo>` spelling is a permanent alias. This entry is Alibaba-coupled: the evidence comes from AAEL `alibabacloud.com` events. Pins the OCI manifest digest of a workload image. Every `kangaroo/pull-image` AAEL event whose image reference's repo tail equals `<repo>` must carry a `digest` equal to the pinned `sha256:` constant. `<repo>` is free-form (it is the repo tail of the image reference being pinned, the last path segment with registry host, path prefix, and tag/digest stripped); a pinned repo with no matching pull-image event rejects.

- Pass: the image was pulled and every pull of that repo reports the pinned digest.
- Fail: a pulled image whose digest differs, or a pinned repo with no pull event at all (fail-closed, not skipped).

### Model: `com.alibabacloud.ai.model.<model-id>`

```json
{ "type": "com.alibabacloud.ai.model.Qwen/Qwen3.8-27B", "value": "c2d3b69b8fe371d95c80e3962669156810c0328c6165306b8decf843149184a9" }
```

The unprefixed `ai.model.<model-id>` spelling is a permanent alias. This entry is Alibaba-coupled: the evidence comes from AAEL `alibabacloud.com` events. Pins a model's measured integrity hash, 64 lowercase hex. The hash comes from the measurement convention for that model (for example an fs-verity digest computed over the stored model). `<model-id>` matches the model identifier in the load event exactly (a modelscope-id style name is the convention). Every `alibabacloud.com` `pai/load-model` AAEL event must carry the pinned `<model-id>` in its `model-id` field and the pinned 64-hex constant in its `hash` field, and at least one load-model event must exist; a missing event rejects. The model id is part of the check, not just the hash: an extra load event for a different model fails the entry closed.

- Pass: the model was loaded and every load event names the pinned model with the pinned hash.
- Fail: any load event with a different model id or hash, or no load event at all.

### Platform posture: `tdx`

```json
{ "type": "tdx", "value": { "debug": "deny", "eventlog": "required" } }
```

Writing the entry imposes a platform-posture requirement on TDX evidence. The attribute and event-log fields default to their strictest choice, so `{"type": "tdx", "value": {}}` appraises the strict posture; the `tcb` and `collateral` gates are opt-in and impose nothing while absent. There is no on/off switch: to drop posture checks, omit the entry.

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

- Pass: a non-debug production TD with the attributes configured as required, an event log, and (when the gates are configured) a non-revoked, rank-acceptable TCB status whose advisory list avoids the rejected entries, with collateral fresh and dated past `min_tcb_date`.
- Fail: debug enabled; a revoked TCB; an advisory in `reject_advisories` and not in `allow_advisories`; expired collateral while `allow_expired` is `false`.

### GPU attestation event: `com.alibabacloud.gpu`

```json
{ "type": "com.alibabacloud.gpu", "value": {} }
```

This entry has no unprefixed alias, and its value is the empty object `{}`. It is Alibaba-coupled: the evidence is the attestation agent's AAEL `alibabacloud.com` `gpu/attestation` event. At least one such event must exist, and every such event must report zero for both `gpu-collect-evidence-result-code` and `gpu-attest-result-code`. The first code reports whether evidence collection succeeded; the second reports the GPU attestation result. Event-log replay keeps the codes from being tampered with after boot, but the codes themselves are guest-reported.

- Pass: at least one AAEL `gpu/attestation` event exists and every one of them reports both codes as zero.
- Fail: no such event, or any event with a non-zero collection or attestation code.

To appraise per-GPU device claims instead of the guest-reported codes, use `nvidia`.

### GPU appraisal: `nvidia`

Omitting the entry skips GPU appraisal entirely. Present, the entry appraises the per-GPU claims the verifier derives from GPU evidence carried in the attestation: identity, versions, CC mode, and measurement, checked against the fields below. Evidence that only passes the raw GPU attestation report through without per-GPU evaluation is rejected, and GPUs absent from the evidence fail the count checks. Appraisal therefore requires the attester to upload GPU evidence; a deployment that collects none fails closed.

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

- Pass: GPU evidence appraises at least one GPU, in CC mode, with the pinned UUID, driver version, VBIOS version, and measurement digest.
- Fail: fewer GPUs than `min_count`, a GPU off any configured whitelist, or evidence with no appraised GPU claims at all.

**Current strength limit.** The appraisal compares the appraised device claims. Cryptographic verification of the GPU attestation report's signature, the GPU certificate chain, and the driver RIM file is verifier-side follow-up work; until it lands, appraisal reflects the claims recorded when the verifier parses the report, not the report's own authenticity.

### Transparency log: `transparency_log`

```json
{ "type": "transparency_log", "value": {
    "publishedMeasurements": ["tdx.td-shim", "container.image.cmaas-runtime"],
    "schemaVersion": "1.0.0",
    "services": [{ "type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 2310520944 }]
} }
```

Anchors the trusted measurement set to a ReleaseManifest recorded in a transparency log instead of pinning the digests inline. At appraisal the entry reconstructs the manifest from the actual TDX measurement values and compares it to the logged reference, so the trusted baseline lives in the log and the policy carries only the pointer to it. This is a `modules` entry type; the top-level `attestation_policy.type = "transparency_log"` of earlier releases no longer exists.

**Load time and appraisal time.** With a `rekor-v1` primary the entry is fetched and authenticated when the policy loads: the log entry is looked up by `logIndex`, its signed checkpoint, Merkle inclusion proof, and Signed Entry Timestamp are verified, and the entry's `payloadHash` and DSSE publisher signature are baked into the generated rule. Omitting `rekorPublicKeyPem` uses the well-known key for `rekor.sigstore.dev` / `rekor.openanolis.cn`; other logs must supply their key. With an `artifact-server` primary the policy loads without network access and the entry is resolved at appraisal time. The optional fallback is consulted only when the primary returns `fail` (`ok` and `revoked` never trigger it), and a failed primary with no fallback rejects.

**What it verifies.** The entry extracts the actual measurement values from the TDX quote and the UEFI event log, reconstructs the manifest in the order given by `publishedMeasurements`, and compares its SHA-256 with the logged `payloadHash`. A mismatch (wrong type, wrong order, wrong value, or wrong `schemaVersion`) rejects. The DSSE publisher signature is always verified, against `publisherPublicKeyPem` when set and the built-in publisher key otherwise.

**Dimension and hardware.** The entry gates `executables` only. Platform posture stays a separate `tdx` entry: add `{"type": "tdx", "value": {"sept_ve_disable": "allow", "perfmon": "allow", "service_td": "allow"}}` to keep the old non-debug and event-log checks without imposing the newer attribute gates. TDX platform recognition is automatic. With only `transparency_log` entries, `hardware` requires that recognition alone.

**Repeat semantics.** `transparency_log` is the one entry type that may appear more than once in the same group. Two entries in one group AND, so both log-anchored baselines must verify; two entries in separate groups OR, so either baseline suffices. Use the first shape to require several logs, the second to accept any of several versions.

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
| `publishedMeasurements` | list of strings | — | (required) Non-empty measurement types in manifest order; allowed values are `tdx.td-shim`, `tdx.kernel`, and `container.image.cmaas-runtime`, and a type may not repeat |
| `schemaVersion` | string | `"1.0.0"` | Must equal the logged manifest's `schemaVersion` |
| `services` | list | — | (required) Exactly one service, either a `rekor-v1` or an `artifact-server` entry |
| `services[].type` | string | — | (required) `"rekor-v1"` or `"artifact-server"` |
| `services[].logUrl` | string | — | (required for `rekor-v1`) Rekor v1 log base URL |
| `services[].logIndex` | int | — | (required for `rekor-v1`) Rekor v1 entry index to fetch and authenticate; must be `>= 0` |
| `services[].rekorPublicKeyPem` | string | built-in | Optional log public key PEM (verifies checkpoint/SET); omit for the well-known `rekor.sigstore.dev` / `rekor.openanolis.cn` key, required for other logs |
| `services[].publisherPublicKeyPem` | string | built-in publisher key | Overrides the publisher key the DSSE signature is verified against |
| `services[].url` | string | — | (required for `artifact-server`) Artifact-server base URL |
| `services[].logServices` | list | — | (required for `artifact-server`) Non-empty list of `{"type": "rekor-v1", "url": "<rekor url>"}` entries, with distinct URLs |
| `fallbackPublishedMeasurements` | list of strings | absent | Measurement types used on the fallback path; required with `fallbackServices`, non-empty, and a subset of `publishedMeasurements` |
| `fallbackServices` | list | absent | Non-empty list of `rekor-v1` services; only valid with an `artifact-server` primary |

`publishedMeasurements` is narrower than the module measurement types: it accepts only the three types above, which is the shape the cmaas release manifest publishes. `tdx.ovmf`, `tdx.uki`, and arbitrary `container.image.<repo>` are not accepted.

The entry extracts measurements with the same rules the removed top-level policy used, which are not yet unified with the `tdx.*` and `container.image.*` measurement predicates of the other entries; for example, the `tdx.kernel` extraction also pins RTMR index 2 and the 32 MiB blob length. Unifying them is a separate change.

**Migrating from the top-level type.** Wrap the old policy value in a `modules` entry: `{"type": "modules", "modules": [{"type": "transparency_log", "value": <old value>}]}`. Add a `tdx` entry if the old non-debug and event-log checks are wanted (TDX recognition is automatic); with only the `transparency_log` entry, `hardware` reduces to that recognition. Delete any non-empty `reference_values`, which the new policy rejects at load.

## Migrating from the fixed policy types

| Removed type | `modules` equivalent |
|---|---|
| `transparency_log` (top-level `attestation_policy.type`) | a `modules` policy with a `transparency_log` entry, plus a `tdx` entry when the old platform checks are wanted; drop any non-empty `reference_values` |
| `hardware_with_reference_values` | boot-measurement entries (`tdx.td-shim`/`tdx.ovmf`, `tdx.kernel`, `tdx.uki`) with the expected digests pinned inline; or `transparency_log` for log-anchored baselines |
| `hardware_strict_with_reference_values` | the same entries plus `{"type": "tdx", "value": {"sept_ve_disable": "allow", "perfmon": "allow", "service_td": "allow"}}` to match the old strict posture on TDX evidence |
| `hardware_strict_with_measurements` | `com.alibabacloud.ai.model.<model-id>` and `com.alibabacloud.container.image.<repo>` entries pinning the same baselines inline, plus a `tdx` entry with `sept_ve_disable`, `perfmon`, and `service_td` set to `allow` to match the old strict posture on TDX evidence; the separate `reference_values` list is dropped |

On TDX evidence, `hardware_only_strict` is reproduced by a single `{"type": "tdx", "value": {}}` entry only after setting `sept_ve_disable`, `perfmon`, and `service_td` to `allow`: the `tdx` defaults also gate those three attributes, so the plain entry is stricter than `hardware_only_strict`. The equivalence is limited to TDX evidence, because the `tdx` entry fails closed on any other platform. An empty modules list is not equivalent to `hardware_only`: it asserts nothing and leaves `hardware` non-affirming.

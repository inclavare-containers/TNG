# TNG Tools

> `tng tools` is a group of operator-facing subcommands for inspecting and verifying the remote-attestation material that TNG uses on the wire: rats-tls certificates, ohttp key configs, builtin attestation policies, and the decentralized HPKE key ring.
>
> These commands do **not** run a tunnel. They reuse the same RA stack (Attestation Agent, Attestation Service, RA-TLS verifier) as a live TNG instance, so a cert or key config produced or verified by `tng tools` is byte-for-byte equivalent to what the tunnel would produce or accept.

## Table of Contents

- [Overview](#overview)
- [Service Dependencies](#service-dependencies)
- [Glossary](#glossary)
- [tng tools rats-tls](#tng-tools-rats-tls)
  - [rats-tls gen](#rats-tls-gen)
  - [rats-tls dump](#rats-tls-dump)
  - [rats-tls verify](#rats-tls-verify)
  - [AttestArgs and VerifyArgs JSON](#attestargs-and-verifyargs-json)
- [tng tools ohttp](#tng-tools-ohttp)
  - [ohttp dump](#ohttp-dump)
  - [ohttp verify](#ohttp-verify)
- [tng tools policy](#tng-tools-policy)
  - [policy export](#policy-export)
- [tng tools key-sync](#tng-tools-key-sync)
  - [key-sync Flags](#key-sync-flags)
  - [key-sync Output Format](#key-sync-output-format)
- [Platform Support](#platform-support)

---

## Overview

`tng tools` has four subcommand groups, one per kind of attested material:

| Group | Material | Needs AA | Needs AS | Typical use |
|---|---|---|---|---|
| `tng tools rats-tls` | rats-tls certificate (PEM) | gen / dump (mutual) | verify | Issue or check the cert carried in the RA-TLS handshake |
| `tng tools ohttp` | ohttp key-config response (JSON) | dump (mutual) | verify | Fetch and verify the HPKE key config an ohttp egress advertises |
| `tng tools policy` | builtin AS attestation policy (Rego) | no | no | Render the Rego a builtin AS loads from a config |
| `tng tools key-sync` | decentralized HPKE key ring (files) | yes | yes | Run a serf cluster that syncs and rotates the ohttp key ring to disk |

`gen` and `verify` are local operations against a flat RA JSON argument; `dump` reaches out to a live endpoint; `key-sync` is a long-running daemon. The flat JSON is parsed directly as `AttestArgs` / `VerifyArgs` (see [AttestArgs and VerifyArgs JSON](#attestargs-and-verifyargs-json)), so unlike a full TNG config block the model and provider tags must be spelled out explicitly.

---

## Service Dependencies

Several subcommands contact an Attestation Agent (AA) to collect evidence and/or an Attestation Service (AS) to verify it. Bring them up before running the command:

```bash
make test-dep-aa &   # AA on /run/confidential-containers/attestation-agent/attestation-agent.sock
make test-dep-as &   # AS on http://127.0.0.1:8080
```

If `make test-dep-as` is unavailable in your environment, start a standalone AS directly:

```bash
restful-as --socket 0.0.0.0:8080
```

The dependency per subcommand is listed in the [Overview](#overview) table and recalled in each section.

---

## Glossary

- **RA (Remote Attestation)**: cryptographically proving a system's runtime integrity to a remote party, per RATS RFC 9334.
- **AA (Attestation Agent)**: a proxy inside the TEE that collects hardware trust measurements and formats them into evidence.
- **AS (Attestation Service)**: the backend that verifies evidence; either TNG's built-in AS or an external one such as Trustee.
- **rats-tls**: a protocol that carries remote-attestation evidence inside the TLS 1.3 handshake; TNG's default transport.
- **ohttp (Oblivious HTTP)**: an application-layer encryption protocol TNG can use instead of rats-tls; it keys on HPKE.
- **HPKE**: Hybrid Public-Key Encryption; the primitive ohttp uses to wrap request/response bodies, keyed by a rotating X25519 key pair.
- **serf**: a gossip protocol (memberlist) used by `key-sync` to form a decentralized cluster of attested nodes that share an HPKE key ring over a RA-TLS QUIC transport.
- **PKCS#8 PEM**: the text envelope format `key-sync` writes for private key material; round-trippable by the file-based ohttp key manager.

---

## tng tools rats-tls

rats-tls certificate tools. `gen` issues a cert locally, `dump` captures a server cert from a live endpoint by completing the TLS handshake (no attestation verification), and `verify` runs full RA verification of a cert file.

### rats-tls gen

Generate a rats-tls certificate locally from an `AttestArgs` config. The cert and key are written as PEM. Needs the AA (the attester collects evidence on this machine).

```bash
tng tools rats-tls gen --attest '<json>' [--cert-out cert.pem] [--key-out key.pem]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--attest` | JSON string | — | Flat `AttestArgs` JSON the cert is built from (required) |
| `--cert-out` | PEM path | stdout | Write the certificate PEM to this file; print to stdout if omitted |
| `--key-out` | PEM path | stdout | Write the private key PEM to this file; print to stdout if omitted |

The cert is built with subject `CN=TNG,O=Inclavare Containers` over an ECDSA P-256 key, SHA-256, the same `CertBuilder` path a live RA-TLS server uses. Both Background Check and Passport models are supported; Passport additionally contacts the AS (via the converter) to mint the attestation-result token embedded in the cert.

<details>
<summary>Example: Background Check cert against a local AA</summary>

```bash
tng tools rats-tls gen \
  --attest '{"model":"background_check","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"}' \
  --cert-out server.pem --key-out server.key
```
</details>

<details>
<summary>Example: Passport cert (needs an AS to mint the token)</summary>

```bash
tng tools rats-tls gen \
  --attest '{"model":"passport","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}' \
  --cert-out server.pem --key-out server.key
```
</details>

### rats-tls dump

Capture a rats-tls server certificate from a live endpoint by completing the TLS 1.3 handshake, without running attestation verification. The handshake uses a capturing verifier that records the end-entity cert instead of verifying it, so it succeeds against any rats-tls server. Works against both `no_ra` and real-RA servers.

```bash
tng tools rats-tls dump --endpoint <host:port> [--attest '<json>'] [--cert-out cert.pem]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--endpoint` | `host:port` | — | rats-tls server address to connect to (required) |
| `--attest` | JSON string | — | Flat `AttestArgs` JSON for the client cert; needed only for mutual-RA servers that require a client certificate. Omit for `no_ra` servers. |
| `--cert-out` | PEM path | stdout | Write the captured certificate PEM to this file; print to stdout if omitted |

`--attest` drives a client cert via the same `CertManager` the live RA-TLS client uses, so it needs a unix target (the AA attester is unix-only). On a non-unix non-wasm target an explicit `--attest` is rejected rather than silently dropping into no-client-auth. No application data is exchanged; the connection is closed right after the handshake.

<details>
<summary>Example: capture a no_ra server cert</summary>

```bash
tng tools rats-tls dump --endpoint 127.0.0.1:8443 --cert-out captured.pem
```
</details>

<details>
<summary>Example: capture a mutual-RA server cert (client cert required)</summary>

```bash
tng tools rats-tls dump --endpoint 127.0.0.1:8443 \
  --attest '{"model":"background_check","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"}' \
  --cert-out captured.pem
```
</details>

### rats-tls verify

Run full RA verification of a certificate file against a `VerifyArgs` config. The cert may be PEM or raw DER. Verification reuses the same `LazyCertVerifier` a live RA-TLS handshake uses: Passport parses and verifies the AS token embedded in the cert; Background Check converts the embedded evidence via the AS and verifies the result. Needs the AS.

```bash
tng tools rats-tls verify --cert <file> --verify '<json>'
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--cert` | file path | — | Certificate file to verify, PEM or DER (required) |
| `--verify` | JSON string | — | Flat `VerifyArgs` JSON the cert is verified against (required) |

On success it prints `verified OK` followed by the pretty-printed `AttestationResult` (which serializes to the raw JWT token string).

<details>
<summary>Example: verify a cert in Background Check mode</summary>

```bash
tng tools rats-tls verify --cert captured.pem \
  --verify '{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}'
```
</details>

<details>
<summary>Example: verify a cert in Passport mode</summary>

In Passport mode the verifier checks the token signature; `as_addr` is optional (used to fetch AS trust roots when present).

```bash
tng tools rats-tls verify --cert captured.pem \
  --verify '{"model":"passport","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}'
```
</details>

### AttestArgs and VerifyArgs JSON

`--attest` and `--verify` take a **flat** JSON object parsed directly as `AttestArgs` / `VerifyArgs`, not a full TNG config block. Because the tools parse these structs directly (not through the config-level tag-default injection), the `model` discriminator and the provider/sub-type tags must all be spelled out explicitly. The full field reference is in [Remote Attestation Configuration](remote_attestation.md); the tables below list the flat keys the tools accept.

`--attest` (`AttestArgs`) flat keys:

| Key | Applies to | Default | Description |
|---|---|---|---|
| `model` | both | — | `background_check` or `passport` (required) |
| `aa_provider` | both | — | `coco` (or `coco_asr` / `ita` / `ita_asr`); selects the AA stack (required) |
| `aa_type` | both | — | `uds` for CoCo (required when `aa_provider` is `coco`) |
| `aa_addr` | both | — | AA address, e.g. `unix:///run/.../attestation-agent.sock` (required for `uds`) |
| `as_provider` | passport | — | `coco` (or `ita`); selects the AS stack the converter talks to |
| `as_type` | passport | — | `restful` / `grpc` / `builtin` for CoCo |
| `as_addr` | passport | — | AS address for the converter to mint the token |
| `policy_ids` | passport | — | AS policy IDs to evaluate evidence against |
| `as_headers` | passport | — | Extra HTTP headers sent to the AS |
| `refresh_interval` | both | `EVIDENCE_REFRESH_INTERVAL_SECOND` | Evidence refresh interval in seconds; `0` refreshes every time |

`--verify` (`VerifyArgs`) flat keys:

| Key | Applies to | Default | Description |
|---|---|---|---|
| `model` | both | — | `background_check` or `passport` (required) |
| `as_provider` | both | — | `coco` (or `ita`); selects the AS stack (required) |
| `as_type` | both | — | `restful` / `grpc` / `builtin` for CoCo (required when `as_provider` is `coco`) |
| `as_addr` | BC / passport | — | AS address. Required for Background Check (the verifier contacts the AS); optional for Passport (used to fetch AS trust roots) |
| `policy_ids` | both | — | AS policy IDs to evaluate evidence against |
| `as_headers` | both | — | Extra HTTP headers sent to the AS; cannot be set without `as_addr` |

---

## tng tools ohttp

ohttp key-config tools. `dump` fetches an ohttp egress's key-config response and writes the raw body plus derived artifacts (HPKE key, TDX quote, event log, attestation result, claims); `verify` re-verifies an already-dumped body offline; `decode` reproduces the derived artifacts from a dumped body without contacting the server or an AS.

### ohttp dump

POST a `KeyConfigRequest` to an ohttp server's key-config endpoint and write the returned `KeyConfigResponse` plus derived artifacts. Without `--verify`, the request is bare (no `attestation_info`) and dump writes only `raw.json`, `hpke.base64`, `hpke.json`. With `--verify <VerifyArgs json>`, dump builds the AS converter, mints the background-check challenge token (or sends `Passport` for the passport model), fetches the attested response, and runs `verify_keyconfig_attestation` inline to produce the attestation-result JWT and decoded claims; the bundle then also includes `quote.bin`, `eventlog.json` (background-check only), `attestation_result.jwt`, and `attestation_result.claims.json`.

Background-check freshness is bound to the AS instance that minted the nonce, so `dump --verify` runs the full live chain (mint, fetch, verify, decode) in one process, mirroring the ingress tunnel. Passport attestation carries no raw quote/event log (the server distills it into the signed token), so `quote.bin`/`eventlog.json` are omitted for passport.

```bash
tng tools ohttp dump --endpoint <url> [--verify '<VerifyArgs json>'] (--raw <file> | --out-dir <dir>)
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--endpoint` | URL | — | ohttp key-config endpoint URL (required) |
| `--verify` | JSON string | — | Flat `VerifyArgs` JSON. When set, dump mints the challenge token, fetches an attested key config, verifies it inline, and writes the attestation artifacts. Absent means a bare key config (no attestation artifacts) |
| `--raw` | file path | stdout | Write only the raw `KeyConfigResponse` body to this file (pretty JSON); print to stdout if neither `--raw` nor `--out-dir` is given |
| `--out-dir` | directory | — | Write the full artifact bundle to this directory (see the file table below). Mutually exclusive with `--raw` |

The request is sent with the `x-tng-ohttp-api: key_config` header, the same header the live ingress uses. The fetch uses its own reqwest client so it stays a standalone operator tool; only the attestation half reuses the live `verify_keyconfig_attestation`, so dump and tunnel verify byte-for-byte the same way.

Bundle files under `--out-dir`:

| File | Format | Always | Needs `--verify` | Background-check only |
|---|---|---|---|---|
| `raw.json` | JSON (raw `KeyConfigResponse` body) | yes | | |
| `hpke.base64` | base64 (`encoded_key_config_list`) | yes | | |
| `hpke.json` | JSON (RFC 9458: key_id/kem/public_key/suites/expire) | yes | | |
| `quote.bin` | binary (TDX quote) | | yes | yes |
| `eventlog.json` | JSON (parsed UEFI event log) | | yes | yes |
| `attestation_result.jwt` | JWT (AS-signed attestation result) | | yes | |
| `attestation_result.claims.json` | JSON (decoded JWT payload) | | yes | |

<details>
<summary>Example: fetch the bare key config (no attestation)</summary>

```bash
tng tools ohttp dump --endpoint http://127.0.0.1:8080/ohttp/key --out-dir bundle
```
</details>

<details>
<summary>Example: fetch a background-check key config, verify it, write the full bundle (builtin AS)</summary>

```bash
tng tools ohttp dump --endpoint http://127.0.0.1:8080/ohttp/key \
  --verify '{"model":"background_check","as_provider":"coco","as_type":"builtin","attestation_policy":{"type":"default"},"reference_values":[]}' \
  --out-dir bundle
```

The `bundle/` directory then holds `raw.json`, `hpke.base64`, `hpke.json`, `quote.bin`, `eventlog.json`, `attestation_result.jwt`, and `attestation_result.claims.json`. `attestation_result.claims.json` is the decoded attestation-result JWT payload: the EAR verdict (`submods.cpu0.ear.status`), the parsed TDX quote (`...tdx.quote.body.*`), `tcb_verification.tcb_status`, the UEFI event log, and the `runtime_data_claims` (challenge token + bound HPKE key config).
</details>

### ohttp verify

Re-verify the attestation in a dumped key-config body (`raw.json`) against a `VerifyArgs` config and print the attestation-result JWT and decoded claims. Reuses the ingress client's `verify_keyconfig_attestation`.

```bash
tng tools ohttp verify --raw <file> --verify '<json>'
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--raw` | file path | — | Dumped `KeyConfigResponse` JSON file to verify (required) |
| `--verify` | JSON string | — | Flat `VerifyArgs` JSON the attestation is verified against (required) |

`verify` re-verifies an already-dumped file offline, so it passes `challenge_token = None` and does not re-check anti-replay/freshness. It works for Passport evidence (self-contained token, no nonce) and external-AS background-check evidence (the external AS keeps state across processes). A builtin-AS background-check key config dumped by `dump --verify` CANNOT be re-verified here: the challenge token in the evidence was signed by the builtin AS instance that minted it, and a fresh builtin AS in this process uses a different per-process signing key, so `convert` rejects it. `verify` detects this config (builtin + background-check) and errors out with a clear message pointing at `dump --verify`. A body dumped without attestation (no `attestation_info`) errors with `no attestation_info`. On success `verify` prints `verified OK`, the raw attestation-result JWT, and a pretty-printed `claims:` block.

<details>
<summary>Example: verify a dumped key config</summary>

```bash
tng tools ohttp verify --raw bundle/raw.json \
  --verify '{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}'
```
</details>

### ohttp decode

Decode a dumped key-config body (`raw.json`) into derived artifacts without contacting the server or an AS (pure local decode, no signature verification). Writes `raw.json`, `hpke.base64`, `hpke.json`, and `quote.bin` (for background-check bodies). With `--attestation-result <jwt-file>`, also writes `attestation_result.claims.json` and `eventlog.json` decoded from the JWT payload.

```bash
tng tools ohttp decode --raw <file> [--attestation-result <jwt-file>] --out-dir <dir>
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--raw` | file path | — | Dumped `KeyConfigResponse` JSON file to decode (required) |
| `--attestation-result` | file path | — | `attestation_result.jwt` file from a prior `dump --verify`; when given, decode also writes `attestation_result.claims.json` and `eventlog.json` |
| `--out-dir` | directory | — | Output directory for the decoded artifacts (required) |

<details>
<summary>Example: re-decode a dumped bundle offline</summary>

```bash
tng tools ohttp decode --raw bundle/raw.json \
  --attestation-result bundle/attestation_result.jwt --out-dir decoded
```
</details>

---

## tng tools policy

Builtin AS attestation-policy tools. `export` renders the exact Rego a builtin AS loads, either from a full TNG config or from a bare `attestation_policy` value. It calls the same renderer the tunnel uses, so the output matches what the builtin AS loads at runtime byte for byte.

### policy export

Render the Rego for every builtin `attestation_policy` in a config, or for one standalone policy value. The command needs no AA or AS and does not evaluate any policy.

```bash
tng tools policy export (--config <FILE> | --attestation-policy <JSON>) [--out-dir <DIR>]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--config` | file path | — | Full TNG config file; `-` reads stdin. JSONC is accepted. Scans `add_ingress` then `add_egress` and exports one Rego per builtin `verify`. |
| `--attestation-policy` | JSON string | — | A bare `attestation_policy` value in strict JSON. |
| `--out-dir` | directory | stdout | Write one `<path>.rego` per policy into this directory. The directory is created if missing, and an existing file is overwritten. |

`--config` and `--attestation-policy` are mutually exclusive, and exactly one is required.

Output names come from the policy's position in the config:

| Input | File name |
|---|---|
| builtin policy on `add_ingress[0]` | `add_ingress.0.verify.attestation_policy.rego` |
| builtin policy on `add_egress[1]` | `add_egress.1.verify.attestation_policy.rego` |
| `--attestation-policy '<json>'` | `attestation_policy.rego` |

Levels are joined with dots and array indexes are decimal, so policies from one section sort together without shell escaping. Duplicate policies are not deduplicated; each is exported under its own path.

Without `--out-dir` the Rego goes to stdout. Every block starts with a `# <name>.rego` line, and a bare `---` line separates blocks. The header is emitted even for a single policy, so splitting on `---` always yields valid per-policy files. The combined output is not one loadable Rego module, because it carries several `package` statements.

```text
# add_ingress.0.verify.attestation_policy.rego
package policy
import rego.v1
...

---

# add_egress.0.verify.attestation_policy.rego
package policy
import rego.v1
...
```

With `--out-dir`, stdout stays empty and each written file prints `wrote <path>` to stderr.

Every policy type is supported:

| Policy type | Export behavior | Extra dependency |
|---|---|---|
| `hardware_only` (including omitted and `default`) | Reads the bundled template | none |
| `hardware_only_strict` | Reads the bundled template | none |
| `trust_all` | Reads the bundled template | none |
| `modules` | Generates the Rego from the module table | none |
| `inline` | Decodes the standard base64 content; the result must be UTF-8 text | none |
| `path` | Reads the file named in the config | the local file |
| `transparency_log`, artifact-server primary | Generates the Rego; the artifact server is resolved at appraisal time | none |
| `transparency_log`, rekor-v1 primary | Fetches and verifies the Rekor entry at export time | network and a trust anchor |

The tool renders the policy and does not validate that the whole config would start; a config the builtin converter rejects at startup still exports its Rego. `tng tools` writes its logs to stderr, so stdout carries only the command output.

---

## tng tools key-sync

A decentralized HPKE key-sync daemon. It runs a stateless serf cluster whose members mutually attest over RA-TLS QUIC, sync the HPKE key ring, rotate it on a schedule, and mirror the live cluster key set to disk so an external ohttp key manager (or any consumer) can consume rotating keys without joining the cluster. Needs both the AA and the AS (RA-TLS mutual attestation between nodes). The `key-sync` subcommand is feature-gated on `__egress-common`; it is not available on the wasm target and requires the AA+AS attest stack (the serf transport uses RA-TLS mutual attestation).

```bash
tng tools key-sync \
  --host 0.0.0.0 --port 8301 \
  --peer 10.0.0.2:8301 --peer 10.0.0.3:8301 \
  --rotation-interval 300 \
  --attest '<json>' --verify '<json>' \
  --out-dir /var/lib/tng/key-sync \
  [--ready-file /run/tng/key-sync.ready]
```

### key-sync Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--host` | address | `0.0.0.0` | serf listen address |
| `--port` | port | `8301` | serf UDP port |
| `--peer` | address | — | Initial peer (`IP:port` or `domain:port`); repeatable. A node with no peers bootstraps a standalone cluster. |
| `--peers-file` | path | — | JSON file for dynamic peer list updates; new peers discovered here are retried in the background until joined |
| `--rotation-interval` | seconds | `300` | HPKE key rotation interval |
| `--attest` | JSON string | — | Flat `AttestArgs` JSON this node attests with (required) |
| `--verify` | JSON string | — | Flat `VerifyArgs` JSON this node verifies peers with (required) |
| `--out-dir` | directory | — | Output directory for the key ring snapshot (required) |
| `--ready-file` | path | — | Touched (written `ready`) once the cluster is bootstrapped and exports are imminent, so an external supervisor can poll for readiness |

`--attest` and `--verify` are the same flat `AttestArgs`/`VerifyArgs` JSON as `rats-tls` (see [AttestArgs and VerifyArgs JSON](#attestargs-and-verifyargs-json)).

### key-sync Output Format

The daemon writes a partitioned snapshot of the cluster key set to `--out-dir`, re-exporting on every key-change notification and on a quarter-rotation poll fallback. Each role directory holds one key per file, named by the **public-key hex** (not `key_id`, because the serf engine assigns `key_id = 0` to every key; the public-key hex is the unique discriminator the cluster key set itself indexes by). Private key material is PKCS#8 PEM, the same format the file-based ohttp key manager loads.

| Path | Role | When present |
|---|---|---|
| `current/<pk_hex>.key` + `current/<pk_hex>.meta.json` | Active | always (the key in use) |
| `next/<pk_hex>.key` + `next/<pk_hex>.meta.json` | Pending | when a rotation is staged |
| `expired/<pk_hex>.key` + `expired/<pk_hex>.meta.json` | Stale | when a retired key has not yet expired |
| `cluster.json` | topology | always |

An empty role directory is removed (e.g. `next/` and `expired/` are absent when there is no pending or stale key). Writes are atomic (write to a sibling `.tmp` then rename) and diffed first so unchanged keys are not rewritten, which keeps readers from observing half-written files and avoids redundant disk churn. On Ctrl-C the daemon runs a graceful serf leave.

`<pk_hex>.meta.json` fields:

| Field | Type | Description |
|---|---|---|
| `key_id` | integer | HPKE key ID (always `0` for serf-generated keys) |
| `public_key` | hex string | X25519 public key, matches the file stem |
| `kem` | string | KEM algorithm |
| `suites` | array | KDF/AEAD suites, each `{ "kdf": ..., "aead": ... }` |
| `status` | string | `Active`, `Pending`, or `Stale` |
| `actived_at` | RFC 3339 | when the key became active |
| `stale_at` | RFC 3339 | when the key was retired |
| `expire_at` | RFC 3339 | when the key is dropped from the ring |

`cluster.json` fields:

| Field | Type | Description |
|---|---|---|
| `local_node_id` | string | this node's serf member id |
| `members` | array | live member list, each `{ "node_id": ..., "status": ... }` |

<details>
<summary>Example: two-node key-sync cluster</summary>

Start a bootstrap node, then a second node that joins it. Both need the AA and the AS for mutual RA-TLS.

```bash
# Node A (bootstrap)
tng tools key-sync --host 0.0.0.0 --port 8301 \
  --rotation-interval 300 \
  --attest '{"model":"background_check","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"}' \
  --verify '{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}' \
  --out-dir /var/lib/tng/key-sync --ready-file /run/tng/key-sync.ready

# Node B (joins A)
tng tools key-sync --host 0.0.0.0 --port 8301 \
  --peer 10.0.0.1:8301 --rotation-interval 300 \
  --attest '{"model":"background_check","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"}' \
  --verify '{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}' \
  --out-dir /var/lib/tng/key-sync --ready-file /run/tng/key-sync.ready
```

After convergence both nodes export the same active key under `current/`, and after a rotation cycle the active key changes on both. See [peer_shared.md](peer_shared.md) for the gossip protocol and join/rotation details.
</details>

---

## Platform Support

`tng tools` is part of the native `tng` binary; the wasm build does not include it. Within a native build, availability depends on the subcommand:

| Subcommand | Availability | Notes |
|---|---|---|
| `rats-tls gen` | unix | needs the AA attester (unix-only) |
| `rats-tls dump` | all native | `--attest` requires a unix target; omit it elsewhere |
| `rats-tls verify` | all native | verifies a cert against a verify config |
| `ohttp dump` | all native | uses reqwest and tokio fs |
| `ohttp verify` | all native | contacts the AS over reqwest |
| `policy export` | `__builtin-as` | renders locally; no AA or AS |
| `key-sync` | `__egress-common` | requires the AA+AS attest stack for the RA-TLS serf transport |

A subcommand that is unavailable in the current build either is not compiled in or bails at runtime with a clear message.

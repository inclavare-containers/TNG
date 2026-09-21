# TNG Tools

> `tng tools` is a group of operator-facing subcommands for inspecting and verifying the remote-attestation material that TNG uses on the wire: rats-tls certificates, ohttp key configs, and the decentralized HPKE key ring.
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
- [tng tools key-sync](#tng-tools-key-sync)
  - [key-sync Flags](#key-sync-flags)
  - [key-sync Output Format](#key-sync-output-format)
- [Platform Support](#platform-support)

---

## Overview

`tng tools` has three subcommand groups, one per kind of attested material:

| Group | Material | Needs AA | Needs AS | Typical use |
|---|---|---|---|---|
| `tng tools rats-tls` | rats-tls certificate (PEM) | gen / dump (mutual) | verify | Issue or check the cert carried in the RA-TLS handshake |
| `tng tools ohttp` | ohttp key-config response (JSON) | dump (mutual) | verify | Fetch and verify the HPKE key config an ohttp egress advertises |
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

ohttp key-config tools. `dump` fetches the key-config response JSON an ohttp egress advertises and, with `--verify`, drives the full attestation flow and verifies it inline; `verify` checks and decodes the attestation in an already-dumped key-config file.

### ohttp dump

POST a `KeyConfigRequest` to an ohttp server's key-config endpoint and write the returned `KeyConfigResponse` JSON. With `--verify`, `dump` builds the AS converter from the `VerifyArgs` JSON, mints the background-check challenge token via `converter.get_nonce()`, sends the request with that attestation so the response carries `attestation_info` (evidence), then verifies the attestation inline with the same converter that minted the token and decodes the attestation-result JWT claims. Passport model sends `Passport` (no nonce) and verifies the self-contained token inline. Without `--verify`, `dump` sends a bare request (no attestation) and only prints the key config.

Background-check freshness is bound to the AS instance that minted the nonce: the builtin AS rejects an evidence whose challenge token it did not issue, so a background-check key config dumped by one `dump` run cannot be re-verified in a separate `ohttp verify` call. `dump --verify` runs the full live chain (mint, fetch, verify, decode) in one process, mirroring the ingress tunnel. For offline re-verification use `ohttp verify`, which suits Passport evidence and external-AS-convertible background-check evidence.

```bash
tng tools ohttp dump --endpoint <url> [--verify '<VerifyArgs json>'] [--out keyconfig.json]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--endpoint` | URL | — | ohttp key-config endpoint URL (required) |
| `--verify` | JSON string | — | Flat `VerifyArgs` JSON. When set, `dump` mints the background-check challenge token, fetches a key config with `attestation_info`, verifies it inline, and decodes the attestation-result claims. Absent means a bare key config with no attestation and no verification |
| `--out` | JSON path | stdout | Write the `KeyConfigResponse` JSON to this file; print to stdout if omitted. When `--verify` is set, the key config goes to `--out` (or stdout) and the `verified OK` block with the decoded claims is printed to stdout |

The request is sent with the `x-tng-ohttp-api: key_config` header, the same header the live ingress uses. The fetch uses its own reqwest client so it stays a standalone operator tool; only the attestation half reuses the live `verify_keyconfig_attestation`, so dump and tunnel verify byte-for-byte the same way.

<details>
<summary>Example: fetch the bare key config (no attestation)</summary>

```bash
tng tools ohttp dump --endpoint http://127.0.0.1:8080/ohttp/key --out keyconfig.json
```
</details>

<details>
<summary>Example: fetch a background-check key config, verify it, decode the claims (builtin AS)</summary>

```bash
tng tools ohttp dump --endpoint http://127.0.0.1:8080/ohttp/key \
  --verify '{"model":"background_check","as_provider":"coco","as_type":"builtin","attestation_policy":{"type":"default"},"reference_values":[]}' \
  --out keyconfig.json
```

On success `dump` prints the key config (to `--out` or stdout) and then:

```
verified OK
attestation_result: eyJ0eXAi...
claims:
{ "eat_profile": "...", "iat": ..., "exp": ...,
  "submods.cpu0.ear.status": "...",
  "submods.cpu0.ear.veraison.annotated-evidence.tdx.quote.body.mr_config_id": "...",
  "submods.cpu0.ear.veraison.annotated-evidence.tdx.quote.body.rtmr_0": "...",
  "submods.cpu0.ear.veraison.annotated-evidence.tdx.tcb_verification.tcb_status": "UpToDate",
  "submods.cpu0.ear.veraison.annotated-evidence.runtime_data_claims.challenge_token": "...",
  "submods.cpu0.ear.veraison.annotated-evidence.runtime_data_claims.hpke_key_config.encoded_key_config_list": "..." }
```

The `runtime_data_claims` carry the challenge token and the bound HPKE key config, and `tcb_status` reports the TCB level. See the attestation-result JWT spec for the full claim set.
</details>

### ohttp verify

Verify the attestation embedded in a dumped key-config JSON against a `VerifyArgs` config and decode its claims. The attestation (a Passport token or Background Check evidence) is bound to the HPKE public key in the response, so verifying it proves the key config came from an attested egress. Needs the AS (or the builtin AS, which needs no external service).

```bash
tng tools ohttp verify --keyconfig <file> --verify '<json>'
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--keyconfig` | file path | — | Dumped `KeyConfigResponse` JSON file to verify (required) |
| `--verify` | JSON string | — | Flat `VerifyArgs` JSON the attestation is verified against (required) |

Verification reuses the ingress client's `verify_keyconfig_attestation`, so the tool and the live tunnel follow the exact same Passport/BackgroundCheck dispatch. `verify` re-verifies an already-dumped file offline, so it passes `challenge_token = None` and does not re-check anti-replay/freshness. It works for Passport evidence (self-contained token, no nonce) and external-AS background-check evidence (the external AS keeps state across processes). A builtin-AS background-check key config dumped by `dump --verify` CANNOT be re-verified here: the challenge token in the evidence was signed by the builtin AS instance that minted it in the `dump --verify` process, and a fresh builtin AS in this process uses a different per-process signing key, so `convert` rejects it. `verify` detects this config (builtin + background-check) and errors out with a clear message pointing at `dump --verify` rather than failing with a cryptic attestation error. A key config dumped without attestation (no `attestation_info`) errors with `no attestation_info`. On success `verify` prints `verified OK`, the raw attestation-result JWT, and a pretty-printed `claims:` block.

<details>
<summary>Example: verify a dumped key config</summary>

```bash
tng tools ohttp verify --keyconfig keyconfig.json \
  --verify '{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}'
```
</details>

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

The tools reuse platform-specific RA and TLS stacks, so availability varies by subcommand and target:

| Subcommand | Availability | Notes |
|---|---|---|
| `rats-tls gen` | unix | needs the AA attester (unix-only) |
| `rats-tls dump` | non-wasm | `--attest` requires a unix target; omit it on other non-wasm targets |
| `rats-tls verify` | non-wasm | the wasm TLS stack does not build the verifier |
| `ohttp dump` | non-wasm | uses reqwest and tokio fs |
| `ohttp verify` | non-wasm | contacts the AS over reqwest |
| `key-sync` | non-wasm (`__egress-common`) | requires the AA+AS attest stack for the RA-TLS serf transport |

On a target where a subcommand is unavailable it bails at runtime with a clear message rather than failing to compile.

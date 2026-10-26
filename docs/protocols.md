# TNG Tunnel Protocols and Remote Attestation Handshake

This document is for developers and anyone who wants to understand TNG in depth. It describes how two TNG endpoints establish mutual trust and exchange encrypted traffic: how the handshake combines with remote attestation, which messages the parties exchange, and the wire format of the outer HTTP layer. Configuration fields and deployment are out of scope: see the [Parameter Manual](configuration.md) for configuration, [Remote Attestation](remote_attestation.md) for RA configuration details, and [Core Concepts and Workflow](architecture.md) for the conceptual overview.

This document currently covers the **ohttp tunnel**; the rats-tls handshake will be added to the same document in a later revision.

Terminology: this document calls the two endpoints **TNG Ingress** (the tunnel entry, where business traffic enters) and **TNG Egress** (the tunnel exit, where business traffic leaves). In a one-directional attestation, the proven side is the RFC 9334 Attester and the verifying side is the Verifier (whose Relying Party role is played by TNG itself).

## Glossary

| Term | Meaning |
|---|---|
| AA (Attestation Agent) | A proxy running inside the TEE that collects hardware measurements and produces Evidence |
| AS (Attestation Service) | The backend service that verifies Evidence and issues the Attestation Result; either an external process (Trustee) or TNG's built-in one (`as_type: "builtin"`) |
| Attester | The side that produces Evidence (RFC 9334 role) |
| Verifier | The side that verifies Evidence (RFC 9334 role) |
| Evidence | The cryptographic material produced by the Attester describing its software and hardware environment |
| Attestation Result | The result token the AS issues after verifying Evidence; a JWT in TNG |
| Background-Check model | One of the RFC 9334 models: the Attester hands raw Evidence to the Verifier side, which has the AS verify it |
| Passport model | One of the RFC 9334 models: the Attester obtains an Attestation Result from the AS up front and presents the token as a "passport" |
| HPKE | RFC 9180 Hybrid Public-Key Encryption, the cryptographic basis of the ohttp encapsulation |
| KeyConfig | The HPKE public-key configuration defined by RFC 9458 that the egress distributes to the ingress for encryption |
| Metadata frame | A custom metadata blob TNG prepends to the ohttp ciphertext (see [Encapsulating the encrypted request](#encapsulating-the-encrypted-request)) |

## OHTTP Tunnel Protocol

### Roles and Protocol Layering

The ohttp tunnel collapses RFC 9458's three roles into two endpoints: the TNG Ingress acts as the protocol's oblivious client (encapsulating requests, decapsulating responses) while the TNG Egress acts as both the oblivious gateway and the resource server (decapsulating requests, forwarding to the real upstream, encapsulating responses). The protocol constraint falls on the hop between ingress and egress: messages on that hop are standard OHTTP encapsulations, and any L7 load balancer or relay in between only sees a fixed-shape outer POST, unable to decrypt or rewrite the business payload.

The outer transport is plain HTTP (HTTP/1.1 or HTTP/2, negotiated by the client), keeping the protocol's outward appearance HTTP for L7 gateway compatibility; the ingress can optionally set `ohttp.tls` to upgrade the outer POST to HTTPS. Unlike rats-tls's connection-level encryption, ohttp encrypts at the granularity of a **single HTTP request**: every request gets its own HPKE encapsulation with no dependency on prior session state. Requests are therefore 0-RTT, which fits stateless clusters and arbitrary L7 load balancing naturally.

Start with an overview diagram without remote attestation to build the overall picture (the `/tng/...` strings there are values of the `x-tng-ohttp-api` request header, not URL paths; see the next section):

```mermaid
sequenceDiagram
    autonumber
    participant C as App (plaintext HTTP)
    participant I as TNG Ingress (ohttp client)
    participant E as TNG Egress (ohttp server)
    participant S as Server (plaintext HTTP)
    Note over I,E: Fetch key configuration (cached until time(CX_a), refreshed every 300s by default)
    I->>E: POST outer path (x-tng-ohttp-api: /tng/key-config)
    E->>I: HpkeKeyConfig | time(CX_a)
    loop Every HTTP request (0-RTT)
        C->>I: HTTP request (plaintext)
        Note over I: body = [u32 length][Metadata{NoAuth, KeyConfigHint}]<br/>+ Enc(HTTP Request)
        Note right of I: time(OP2_r)
        I->>E: POST outer path (x-tng-ohttp-api: /tng/tunnel,<br/>Content-Type: message/ohttp-chunked-req)
        Note over E: Locate the key by KeyConfigHint,<br/>decrypt Metadata and request body, forward plaintext
        E->>S: HTTP request (plaintext)
        S->>E: HTTP response
        E-->>I: Enc(HTTP Response)<br/>(Content-Type: message/ohttp-chunked-res, streaming)
        I-->>C: HTTP response (plaintext)
    end
    Note over I,E: 422 (key unknown or expired) → the client drops the cache and refetches the KeyConfig
```

### Outer Request Routing

The egress does not select APIs by URL path: it does not match the outer path at all. All requests go to a single handler that dispatches on the **`x-tng-ohttp-api` request header**. The header's values are path-shaped constants such as `/tng/key-config`, but they are only API selectors and have nothing to do with the request's actual URL. A request without the header is rejected (403, `RejectNonTngRequest`).

The ingress POSTs every outer request to **the same URL** (`base_url`): the outer path comes from `path_rewrites` regex substitution, or from `path_default` (default `root`, meaning `/`; can be set to `original` to follow the business request path). Key-config fetches, tunnel requests, and RA forwarding all go to this URL and are distinguished solely by the `x-tng-ohttp-api` header.

| `x-tng-ohttp-api` header value | Actual client behavior | Request body | Description |
|---|---|---|---|
| `/tng/key-config` | POST (JSON) | `KeyConfigRequest` | Fetch the key configuration, [see below](#key-configuration-distribution) |
| `/tng/tunnel` | POST | Metadata frame + ohttp ciphertext | The encrypted business request, [see the encapsulation section](#encapsulating-the-encrypted-request) |
| `/tng/background-check/challenge` | GET | none | Fetch a challenge from the AS via the egress (Server-verifies-Client + Background-Check only) |
| `/tng/background-check/verify` | POST (JSON) | `AttestationVerifyRequest` | Submit Evidence to the AS via the egress to obtain an Attestation Result (same scenario) |

The egress does not validate the HTTP method; the table above describes what the ingress client actually does. Beyond these two headers there is a separate REST control plane for operators (`/status/egress/<id>/ohttp/keys` and friends), unrelated to the data-plane protocol; see [Control Interface](configuration.md#control-interface).

### Key Configuration Distribution

Before encrypting the first request, the ingress fetches the KeyConfig from the egress (1-RTT, response cached). Both request and response are JSON.

Request body `KeyConfigRequest`:

| Field | Type | Default | Description |
|---|---|---|---|
| `attestation_request` | object | — | Omitted to request no server attestation (`attestation_info` comes back null). Otherwise one of the `model`-tagged variants below |

The two `attestation_request` variants:

```json
{ "attestation_request": { "model": "passport" } }
```

```json
{ "attestation_request": { "model": "background_check", "challenge_token": "<challenge JWT obtained from the AS>" } }
```

Response body `KeyConfigResponse`:

| Field | Type | Default | Description |
|---|---|---|---|
| `hpke_key_config.expire_timestamp` | integer | — | When the configuration expires (Unix seconds); after this the egress no longer accepts requests sealed with the key |
| `hpke_key_config.encoded_key_config_list` | string | — | The RFC 9458 §3.1 KeyConfig encoding as a list, base64 as a whole; the current implementation always carries exactly one key |
| `attestation_info` | object / null | null | Server attestation information, one of the `model`-tagged variants below |

The two `attestation_info` variants:

```json
{ "model": "passport", "attestation_result": "<the egress's own Attestation Result JWT>", "as_provider": "coco" }
```

```json
{ "model": "background_check", "evidence": "<Evidence JSON produced by the egress>", "aa_provider": "coco" }
```

`as_provider` / `aa_provider` mark which provider the token/evidence belongs to (the same string values as the RA config providers, currently `coco` and `ita`), letting the peer pick the matching verification stack; they may be omitted for legacy clients.

The two models are mutually exclusive: requesting `passport` from a background-check server (or vice versa) returns an error. A server without RA configured returns `attestation_info: null`.

**Key lifecycle and rotation.** The egress's HPKE private keys come from three sources (`ohttp.key.source`): `self_generated` (default, automatic rotation, `rotation_interval` defaults to 300 seconds), `file` (loaded from an external file, hot-reloaded via inotify), and `peer_shared` (cluster-wide keys shared over the Serf gossip protocol, for stateless clusters). A key moves through Pending/Active/Stale states: when the rotation interval elapses, the current key becomes Stale (still decryptable) and a fresh Active key is generated; after another interval the old key expires for good. `expire_timestamp` is the key's final expiry time.

The ingress caches the key configuration. The cache's validity is the minimum of the key's `expire_timestamp` and the Attestation Result's JWT `exp`, refreshed automatically in the background (300-second cycle by default; when `attest` is configured it follows the attestation refresh strategy). When the egress receives a request sealed with a key that no longer exists it returns 422 (following the key-config mismatch semantics of RFC 9458 §6.4), upon which the ingress immediately drops its cache and refetches.

### Encapsulating the Encrypted Request

The request body for `x-tng-ohttp-api: /tng/tunnel` is not JSON. It is three concatenated binary sections:

```text
[4-byte big-endian length N][N bytes of prost-encoded Metadata][ohttp-chunked encrypted request body (streamable)]
```

The metadata section is defined in `tng/src/tunnel/ohttp/protocol/metadata.proto`:

```proto
message Metadata {
  oneof client_auth {
    NoAuth no_auth = 1;
    AttestedPublicKey attested_public_key = 2;
  }
  ServerKeyConfigHint key_config_hint = 3;
}

message NoAuth {}

message AttestedPublicKey {
  string attestation_result = 1;  // the client's Attestation Result (JWT)
  bytes pk_s = 2;                 // the client's HPKE sender-authentication public key
  string as_provider = 3;         // which AS provider issued attestation_result
}

message ServerKeyConfigHint {
  bytes public_key = 1;           // the server's raw HPKE public key, used for key lookup
}
```

Three points worth noting:

- `key_config_hint.public_key` is the raw bytes of the **server's** HPKE public key, carried in both client-auth modes. RFC 9458's KeyConfig only has a 1-byte key id, which is not unique enough at scale, so the egress looks the key up directly by public key. A request without the hint is rejected (400).
- `client_auth` picks one of two: `NoAuth` (the ingress does not attest itself, an anonymous client) or `AttestedPublicKey` (the ingress proves itself to the egress, see [Server verifies Client](#server-verifies-client)). The choice is not an explicit config knob: an ingress with `attest` configured automatically carries `AttestedPublicKey`, an egress with `verify` configured requires it, and a mismatch is rejected. The wasm ingress is always `NoAuth` due to platform constraints.
- The metadata frame is capped at 32 MiB (the Attestation Result token can be large; putting it in the body rather than an HTTP header is exactly to bypass header size limits). Exceeding it returns 413.

The ciphertext uses a chunked streaming encapsulation (chunked-ohttp style, defined by the ohttp fork TNG uses): the plaintext is split into chunks of at most 16 KiB, each chunk is AEAD-encrypted independently and prefixed with a varint-encoded length, and the stream ends with a zero-length terminating chunk with `final` as the additional authenticated data. The outer `Content-Type` is `message/ohttp-chunked-req`, enforced by the egress; anything else returns 400. Responses work the same way: HTTP 200, `Content-Type: message/ohttp-chunked-res`, with the ciphertext streamed back so the ingress decrypts as data arrives (this also covers SSE-style streaming responses). That content type is never compressed.

### Choosing an RA Model

The "client verifies server" and "server verifies client" directions each independently pick the background-check or passport model, controlled by the `model` field of the `attest`/`verify` config blocks (defaulting to `background_check` when omitted).

| Dimension | Background-Check (default) | Passport |
|---|---|---|
| Where Evidence is verified | The Verifier side receives Evidence and has the AS verify it | The Attester verifies with the AS up front and obtains a token |
| Who talks to the AS | The verifying side (the Verifier-side TNG) | The proven side (the Attester-side TNG) |
| Round trips per config fetch | Needed (fetch fresh Evidence carrying a challenge) | Not needed (the token ships with the config) |
| Freshness source | The AS challenge JWT (short validity) | The token's own exp |
| AS placement constraint | The AS must be reachable by the verifying side (in-process when `as_type: "builtin"`) | The AS must be reachable by the proven side |
| Typical scenario | The verifier can reach the AS and wants strong freshness | The attester is close to the AS, the verifier is network-isolated |

Two clarifications:

- `as_type: "builtin"` (the built-in AS) is not a third model. It is an AS implementation choice on the verify side of the background-check model: the verification logic is linked into the TNG process and runs in-process, with no external AS to deploy. The passport model's attest side does not support the builtin converter.
- In the server-verifies-client direction with the background-check model, the AS must be reachable from the egress. In a stateless cluster the ingress cannot assume which egress it will land on, so this direction offers a "forwarded via the egress" variant (below).

### Timestamp and Message Notation

The RA sequence diagrams below use a formal notation aligned with the event table of RFC 9334 Appendix A:

- `time(XX_y)` is the time event XX happens, where `y` is the involved party (`a`: Attester, `v`: Verifier, `r`: Relying Party).
- A form like `JWT{Nonce, time(NS_v), time(NX_v)}` describes the material a message carries together with its validity fields; `|` separates the parallel pieces of material inside one message; `Enc(x)` is `x` after HPKE encryption.
- Protocol objects in the diagrams use CamelCase consistently, mapped to the wire-format field names in the body sections: `Challenge` is the challenge token `JWT{Nonce, time(NS_v), time(NX_v)}` (wire field name `challenge_token`); `Claims` is the claim set the proven side binds into the Evidence, which the AS writes back into the token after verification (wire field name `runtime_data`), where "Claims covers {…}" is set inclusion (every expected key/value appears in the token); `Evidence{hash(…)}` means the Evidence binds the hash of the Claims in parentheses into the TEE report data (the AA hashes the canonical JSON of the Claims as a whole) while the plaintext Claims travel alongside the Evidence; `skS`/`pkS` are the client's HPKE sender-authentication key pair in the server-verifies-client direction; `HpkeKeyConfig` is the key configuration object (wire field name `hpke_key_config`).

How the diagram events map to the implementation:

| Event | Meaning | Implementation |
|---|---|---|
| NS / NR | challenge sent / received | challenge JWT issuance (`iat`) and arrival |
| NX | challenge expiry | the challenge JWT's `exp` |
| EG / ER | Evidence generated / received | the AA collecting hardware measurements and binding the claims / the peer receiving the Evidence |
| RG / RX | Attestation Result generated / expiry | the AS issuing the token / the token's `exp` |
| RA | Attestation Result accepted | the verifier's signature and claims-coverage check passing |
| CX | KeyConfig expiry | `hpke_key_config.expire_timestamp` |
| OP2 | cryptographic operation based on the verified result | the moment HPKE encryption/decryption runs after verification |

The diagrams express message contents with this formal notation; the concrete wire formats (JSON field names, the proto structure, Content-Types) are in [Key Configuration Distribution](#key-configuration-distribution) and [Encapsulating the Encrypted Request](#encapsulating-the-encrypted-request).

### Client Verifies Server

#### Background-Check Model (Default)

The ingress (Relying Party) obtains a challenge from the AS, uses it to fetch fresh Evidence from the egress (Attester), and has the AS verify it. Every key-config fetch gets fresh Evidence; freshness is guaranteed by the challenge JWT:

```mermaid
sequenceDiagram
    autonumber
    participant V as AS (Verifier)
    participant RP as TNG Ingress (Relying Party)
    participant AT as TNG Egress (Attester)
    Note right of AT: Generate the HPKE key pair,<br/>rotate periodically (default 300s)
    alt 1. Fetch the challenge (freshness source)
        RP->>V: request a challenge
        Note right of V: time(NS_v)
        V-->>RP: JWT{Nonce, time(NS_v), time(NX_v)}
        Note right of RP: time(NR_r)
    end
    alt 2. Request the key configuration carrying the challenge
        RP->>AT: JWT{Nonce, time(NS_v), time(NX_v)}
        Note right of AT: time(EG_a)
        Note right of AT: Claims{Challenge, HpkeKeyConfig}<br/>hashed into the TEE report via the AA
        AT-->>RP: HpkeKeyConfig | time(CX_a) |<br/>Evidence{hash(Challenge, HpkeKeyConfig)}
        Note right of RP: time(ER_r)
    end
    alt 3. Obtain and verify the Attestation Result
        RP->>V: Evidence{hash(Challenge, HpkeKeyConfig)} |<br/>Claims{Challenge, HpkeKeyConfig}
        Note right of V: time(RG_v)
        V-->>RP: Attestation Result{time(RG_v), time(RX_v),<br/>Claims covers {Challenge, HpkeKeyConfig}}
        Note right of RP: time(RA_r): signature + exp + Claims-coverage check
    end
    alt 4. Encrypted requests (0-RTT)
        Note right of RP: time(OP2_r)
        RP->>AT: Enc(HTTP Request)
        AT-->>RP: Enc(HTTP Response)
        Note right of RP: Cache validity = min(time(CX_a), time(RX_v))
    end
```

In step 3, if the ingress has `as_type: "builtin"` configured, the AS role runs inside the ingress process (the diagram's AS participant becomes an in-process component); the message semantics are unchanged.

#### Passport Model

The egress obtains its own Attestation Result up front and distributes it with the KeyConfig; the ingress only verifies the token and never touches raw Evidence:

```mermaid
sequenceDiagram
    autonumber
    participant RP as TNG Ingress (Relying Party)
    participant AT as TNG Egress (Attester)
    participant V as AS (Verifier)
    Note right of AT: Generate the HPKE key pair
    alt 1. The egress obtains the Attestation Result up front (refreshed per refresh_interval, default 600s)
        AT->>V: request a challenge
        Note right of V: time(NS_v)
        V-->>AT: JWT{Nonce, time(NS_v), time(NX_v)}
        Note right of AT: time(EG_a)
        Note right of AT: Claims{HpkeKeyConfig} (no challenge)<br/>hashed into the TEE report via the AA
        AT->>V: Evidence{hash(HpkeKeyConfig)} |<br/>Claims{HpkeKeyConfig}
        Note right of V: time(RG_v)
        V-->>AT: Attestation Result{time(RG_v), time(RX_v),<br/>Claims covers {HpkeKeyConfig}} (cached per public key)
    end
    alt 2. Distribute the key configuration with the Attestation Result
        RP->>AT: request the key configuration
        AT-->>RP: HpkeKeyConfig | time(CX_a) |<br/>Attestation Result{time(RG_v), time(RX_v), HpkeKeyConfig}
        Note right of RP: time(RA_r): signature + exp + Claims-coverage check
    end
    alt 3. Encrypted requests (0-RTT)
        Note right of RP: time(OP2_r)
        RP->>AT: Enc(HTTP Request)
        AT-->>RP: Enc(HTTP Response)
    end
```

The egress caches passport tokens per key generation: after a key rotation the old token is no longer distributed, and tokens refresh on the `refresh_interval`.

#### How the attested material binds the key configuration

The binding mechanism is the same in both models, and it is what "a verified KeyConfig" cryptographically means:

1. The proven side puts a claims object into the Evidence's runtime_data. In the client-verifies-server direction it is `ServerUserData{challenge_token, hpke_key_config}` (no challenge_token in the passport model); in the server-verifies-client direction it is `ClientUserData{challenge_token, pk_s}`. Note `hpke_key_config` is the **complete configuration object** (including the base64 key list), not a hash of it.
2. The AA hashes the canonical JSON serialization of the whole claims object (SHA-384 in the current implementation) into the TEE report data, so the hardware ties the claims to the Evidence inseparably.
3. After verifying the Evidence, the AS writes the same claims back into the Attestation Result's runtime_data.
4. The verifier checks the token: the signature trust chain (AS certificate or JWK), the validity window (JWT exp), and that the runtime_data **covers** the expected claims (a subset match: every expected key/value must appear in the token).

Together, the token the verifier receives proves both "the peer runs in a trusted environment" and "the key material the peer uses for this handshake comes from that environment"; the two are bound by the hardware measurement and cannot be forged separately.

### Server Verifies Client

#### Passport Model

The ingress generates an X25519 key pair (`skS`/`pkS`) for itself, obtains an Attestation Result from the AS with `pk_s` bound into the claims up front, and presents it on every request:

```mermaid
sequenceDiagram
    autonumber
    participant V as AS (Verifier)
    participant AT as TNG Ingress (Attester)
    participant RP as TNG Egress (Relying Party)
    Note right of AT: Generate an X25519 key pair (skS, pkS)<br/>as the HPKE sender-authentication key
    alt 1. The ingress obtains the Attestation Result up front
        AT->>V: request a challenge
        Note right of V: time(NS_v)
        V-->>AT: JWT{Nonce, time(NS_v), time(NX_v)}
        Note right of AT: time(EG_a)
        Note right of AT: Claims{Challenge, pkS}<br/>hashed into the TEE report via the AA
        AT->>V: Evidence{hash(Challenge, pkS)} |<br/>Claims{Challenge, pkS}
        Note right of V: time(RG_v)
        V-->>AT: Attestation Result{time(RG_v), time(RX_v),<br/>Claims covers {pkS}}
    end
    alt 2. Every encrypted request (0-RTT, carrying the client attestation)
        Note right of AT: time(OP2_a)
        AT->>RP: Attestation Result{time(RG_v), time(RX_v), pkS} |<br/>pkS | Enc(HTTP Request) (HPKE auth-mode encapsulation)
        Note right of RP: time(RA_r) + time(OP2_r): verify the token<br/>(Claims covers {pkS}) + auth-mode decryption success = proof of holding skS
        RP-->>AT: Enc(HTTP Response)
    end
```

The egress's verification has two layers, both required:

- **Token layer**: the metadata frame's `attestation_result` and `pk_s` go through the same subset check as the previous section (the expected claims are `{pk_s}`; the challenge token is not re-checked because the AS already checked it at issuance).
- **Cryptographic layer**: the client encapsulates the request in HPKE **sender-authenticated mode** (RFC 9180 auth mode, the `SetupAuthS` semantics), with the attested `skS` as the authentication key. The egress completes the auth-mode decapsulation using the `pk_s` from the metadata frame; successful decryption is the cryptographic proof that the sender holds `skS`. The token binds `pk_s`, the decryption proves `skS`, and together they tie "the trusted environment" to "the sender of this connection".

Without client attestation (`NoAuth`) the base HPKE mode is used. The wasm ingress does not support `attest` and is always `NoAuth` in this direction.

#### Background-Check Model (the forwarded variant)

A strict background-check model would have the egress go to the AS itself after receiving a request, but that would put verification latency on the business request path. TNG moves the exchange **up front** to handshake time and keeps the egress as a pure forwarder: the AS's challenge/attestation interfaces are forwarded verbatim through the egress, and the ingress completes its proof through them. The ingress therefore does not need to know which egress it will land on (friendly to stateless clusters), and the egress stays stateless:

```mermaid
sequenceDiagram
    autonumber
    participant V as AS (Verifier)
    participant AT as TNG Ingress (Attester)
    participant RP as TNG Egress (Relying Party)
    Note right of AT: Generate an X25519 key pair (skS, pkS)
    Note over AT,RP: The egress is only a forwarder to the AS here (stays stateless)
    alt 1. Fetch the challenge via the egress
        AT->>RP: request a challenge<br/>(x-tng-ohttp-api: /tng/background-check/challenge)
        RP->>V: request a challenge
        Note right of V: time(NS_v)
        V-->>RP: JWT{Nonce, time(NS_v), time(NX_v)}
        RP-->>AT: JWT{Nonce, time(NS_v), time(NX_v)}
    end
    alt 2. Obtain the Attestation Result via the egress
        Note right of AT: time(EG_a): Claims{Challenge, pkS}<br/>hashed into the TEE report via the AA
        AT->>RP: Evidence{hash(Challenge, pkS)} |<br/>Claims{Challenge, pkS}<br/>(x-tng-ohttp-api: /tng/background-check/verify)
        RP->>V: Evidence | Claims
        Note right of V: time(RG_v)
        V-->>RP: Attestation Result{time(RG_v), time(RX_v),<br/>Claims covers {pkS}}
        RP-->>AT: Attestation Result{time(RG_v), time(RX_v), pkS}
    end
    alt 3. Every encrypted request (0-RTT, carrying the client attestation)
        Note right of AT: time(OP2_a)
        AT->>RP: Attestation Result{time(RG_v), time(RX_v), pkS} |<br/>pkS | Enc(HTTP Request) (HPKE auth mode)
        Note right of RP: time(RA_r) + time(OP2_r): verify the token and decrypt in auth mode
        RP-->>AT: Enc(HTTP Response)
    end
```

When the egress is configured for the passport model these two forwarding endpoints return an error. The forwarded request/response fields map one-to-one to the AS interface (`AttestationChallengeResponse{challenge_token}`, `AttestationVerifyRequest{evidence, aa_provider}`, `AttestationVerifyResponse{attestation_result, as_provider}`).

### Bidirectional Verification

The two directions produce complementary artifacts: client-verifies-server yields "a verified KeyConfig", and server-verifies-client yields "an Attestation Result bound to `pk_s` plus proof of auth-mode key possession". They stack without interfering; configure `attest` + `verify` on both the ingress and the egress, with the model chosen independently on each side:

```mermaid
sequenceDiagram
    autonumber
    participant V as AS (Verifier)
    participant I as TNG Ingress
    participant E as TNG Egress
    Note over I,E: Both ingress and egress configure attest + verify, models are chosen independently
    Note over V,I: Server verifies client: the ingress holds<br/>Attestation Result{..., pkS} | pkS
    Note over V,E: Client verifies server: the egress distributes<br/>HpkeKeyConfig | time(CX_a) | Evidence or Attestation Result
    I->>E: request the key configuration (carrying what the server verification needs)
    E-->>I: HpkeKeyConfig | time(CX_a) | Evidence or Attestation Result
    Note over I: time(RA_r): verify the server's token or Evidence
    Note over I: time(OP2_r)
    I->>E: Attestation Result{time(RG_v), time(RX_v), pkS} |<br/>pkS | Enc(HTTP Request) (HPKE auth mode)
    Note over E: time(RA_r): verify the client token (pkS) + auth-mode decryption
    E-->>I: Enc(HTTP Response)
```

### Freshness and Replay

Every short-lived credential in the protocol has an explicit expiry semantics:

| Credential | Produced by | Validity | On expiry |
|---|---|---|---|
| Challenge JWT (wrapping the nonce) | AS | Set at issuance (the Trustee implementation uses 5 minutes) | The AS rejects the Evidence at verification, HTTP 401 |
| Server KeyConfig | egress | `expire_timestamp` (one and a half rotation intervals under auto-rotation) | 422, the client refetches |
| Attestation Result | AS | JWT `exp` | The verifier rejects it; the ingress cache expires early |

On replay, the implementation's strategy is:

- The challenge JWT is checked for signature and exp only; there is **no** server-side used-token list. The AS is therefore fully stateless (free to scale horizontally); replay protection relies on the short exp window plus the challenge being measured into the Evidence by the TEE.
- Encrypted requests are 0-RTT, so a replay window exists in theory (the same class of issue as TLS 1.3 0-RTT). The current implementation does not deduplicate request ciphertexts, following RFC 9458's stance on replay: requests should be idempotent or protected at the business layer. Response keys are derived from the request keys with a one-time nonce, so responses are not replayable.

### AS Interface

The interfaces below are what TNG uses to talk to an external restful AS in the background-check model (the passport model's interactions are identical; only the initiator is the proven side). They match Trustee's restful AS:

| Endpoint | Method | Request body | Response |
|---|---|---|---|
| `/challenge` | POST | `{}` | JSON `{nonce, extra-params: {jwt}}` |
| `/attestation` | POST | JSON (Evidence, runtime_data, policy_ids) | **the raw JWT string** (not JSON-wrapped) |
| `/certificate` | GET | none | The AS's token-signing certificate chain, used to bootstrap the verifier's trust |

Two notes:

- The `/attestation` request body follows Trustee's restful AS schema (the `verification_requests` array structure on newer versions, with automatic fallback to the flat structure for older AS deployments); its definition lives in Trustee's `attestation.proto` and is not restated here.
- The AS certificate can also be pinned instead of discovered via `/certificate`: list PEM files under `trusted_certs_paths` in the verify config.

An `as_type: "grpc"` AS does not support the challenge endpoint (the client falls back to a dummy nonce, degrading freshness); with `as_type: "builtin"` all of the above execute inside the TNG process with no network calls.

### Error Responses

On data-plane errors the egress returns a JSON body `{"code": "<machine-readable code>", "message": "<human-readable description>"}`. Common status codes:

| HTTP status | Trigger |
|---|---|
| 400 | Content-Type is not `message/ohttp-chunked-req`; metadata frame decoding failed; key_config_hint missing |
| 403 | The request lacks the `x-tng-ohttp-api` header |
| 413 | The metadata frame exceeds 32 MiB |
| 422 | The key pointed to by key_config_hint does not exist or has expired (RFC 9458 §6.4) |
| 500 / 502 / 504 | Internal error / upstream unreachable / upstream timeout |

A failed client attestation (the verify side's token check failing) flows through the same JSON error channel.

# cmaas-audit alignment report

## Date
2026-09-26

## Summary
Aligned `tng.resolve_artifact_server`'s host-await verification
(`rats-cert/src/tee/coco/converter/builtin/artifact_server.rs`,
`resolve_and_authenticate`) with cmaas-audit's `VerifyLogEntry`
response-key verification model. Previously the impl authenticated each
returned rekor entry with the BUILT-IN rekor key only (via
`resolve_rekor_key`'s logID-matching) and IGNORED the response
`entry_verifier` / `log_verifier` PEMs. It now USES those response keys,
mirroring cmaas's Go implementation, while keeping the built-in key as a
fallback and the §11 clean-deny contract.

## cmaas functions mirrored

Source: `/root/cmaas-pcc3p-delivery-20260126/source/pkg/transparency/rekorv1.go`.

- `VerifyLogEntry` (lines 163-201) — response-key path: builds a service from
  `entry.EntryVerifier.Content` + `entry.LogVerifier.PublicKeyPEM`, runs
  `verifyLogEntryWithConfiguredKeys`, then baseline-compares the response keys
  to the SDK built-in keys and WARNS (passes) if they differ.
- `verifyLogEntryWithConfiguredKeys` (lines 255-298) — `verifyRekorLogID` +
  `decodeRekorBody` + `verifyPayloadHash` + `verifyLogEntrySignature` +
  `verifyInclusionProof` + `verifyCheckpoint` + `verifySET`. The rekor-log /
  checkpoint / inclusion / SET pieces are reused via
  `rekor_v1::authenticate_entry` (keyed by the response `log_verifier`).
- `verifyLogEntrySignature` (lines 386-400) — DSSE publisher signature:
  `sig = base64(body.spec.signatures[0].signature)`;
  `pae = DSSEPAE(DSSEPayloadType, canonical_manifest)`;
  `h = sha256(pae)`;
  `ecdsa.VerifyASN1(logEntryPubKey, h, sig)`.

## What changed (in `resolve_and_authenticate`, per returned entry)

1. **Rekor key from response `log_verifier` (built-in fallback).**
   If `entry.log_verifier.public_key_pem` is non-empty, the rekor key is
   resolved via `rekor_v1::rekor_public_key(&entry.url, Some(pem))` and used
   for `authenticate_entry` (logID + checkpoint + inclusion + SET). Otherwise it
   falls back to the existing `resolve_rekor_key` (built-in hostname→logID
   match), which is retained.

2. **DSSE publisher signature verification with response `entry_verifier`**
   (NEW). When `entry.entry_verifier.type == "public_key"` and
   `content` is non-empty, `verify_entry_dsse_signature` parses the publisher
   key (`rekor_v1::parse_p256_public_key`), base64-decodes
   `body.spec.signatures[0].signature`, builds the DSSE PAE
   (`dsse_pae(DSSE_PAYLOAD_TYPE, canonical_manifest)`), and verifies the ECDSA
   P-256 DER signature over the PAE (`VerifyingKey::verify` hashes the PAE with
   SHA-256 internally, equivalent to Go's `VerifyASN1(pub, sha256(pae), sig)`).
   TNG is LENIENT where cmaas-audit requires both verifiers together: if
   `entry_verifier` is absent / unsupported type, DSSE verification is SKIPPED
   (not rejected) so the built-in-only fallback still works; a
   present-but-wrong key still fails closed.

3. **Baseline-compare + warn** (cmaas lines 195-200). After successful
   verification with the response key, the built-in key for the URL is
   resolved (`rekor_public_key(&entry.url, None)`, errors ignored) and its
   SPKI DER is compared to the response key's SPKI DER. On mismatch,
   `tracing::warn!` is emitted (NOT a reject). Best-effort: built-in
   resolution failure (proxy URL) is skipped silently.

The clean-deny contract is preserved: the closure still returns
`Ok(Bool(inner().await.unwrap_or(false)))`; all new steps propagate failure
via `?`/`Err` → `None` → `false`.

### DSSE PAE discrepancy note
The task brief stated the DSSE sig is "verified over
`sha256(canonical release manifest)`, NOT the DSSE PAE." The actual cmaas Go
code (`verifyLogEntrySignature`) computes `pae := DSSEPAE(...); h := sha256(pae)`.
Empirical verification against the fixture confirmed the signature verifies
over `sha256(DSSEPAE(canonical_manifest))`, NOT `sha256(canonical_manifest)`.
The implementation mirrors the authoritative Go code (PAE + sha256), which the
fixture's signature verifies against.

## Covering tests (`artifact_server.rs::tests`)

- `resolve_artifact_server_true_on_valid_entries` (positive) — now exercises
  the FULL cmaas-audit path: rekor sig via response `log_verifier` + DSSE sig
  via response `entry_verifier` + payloadHash → `Ok(Bool(true))`.
- `resolve_artifact_server_false_on_wrong_entry_verifier` (NEW negative) —
  wrong `entry_verifier.content` (a different valid P-256 PEM) → DSSE sig
  verification fails → `Ok(Bool(false))`.
- `resolve_artifact_server_false_on_wrong_log_verifier` (NEW negative) —
  wrong `log_verifier.public_key_pem` → rekor logID verification fails →
  `Ok(Bool(false))`.
- Existing: `false_on_network_error`, `false_on_payload_hash_mismatch`,
  `false_on_duplicate_entry`, `false_on_missing_requested_log_service`,
  `caches_success`.

Mock PEMs: `SIGSTORE_REKOR_V1_PUB_KEY_PEM` (cmaas
`SigstoreRekorV1PubKeyPEM`) and `LOG_ENTRY_PUB_KEY_PEM` (cmaas
`LogEntryPubKeyPEM`).

## Command
```
cargo test -p rats-cert --features builtin-as-tdx-rust resolve_artifact_server
```

## Output
- `resolve_artifact_server*`: 8 passed; 0 failed.
- `branch_b_*` + `fetch_rekor*` + `resolve_artifact_server*`: 14 passed.
- Full suite (`cargo test -p rats-cert --features builtin-as-tdx-rust`):
  173 passed; 5 failed (all pre-existing network/env — connection refused to
  local AS `127.0.0.1:8006`/`8080` and OCI registry `127.0.0.1:5000`; not
  introduced by this change).
- `cargo clippy -p rats-cert --features builtin-as-tdx-rust --tests`: clean for
  changed code (2 pre-existing warnings in untouched tests:
  `needless_borrows_for_generic_args` at line 673 and `disallowed_methods`
  `tokio::spawn` at mod.rs:3757).

## Commit
`58f0bc1a` — refactor(rats-cert): align artifact-server verify with
cmaas-audit (response log_verifier + entry_verifier DSSE)

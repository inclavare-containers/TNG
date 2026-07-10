# TODO: Clarify IP / CIDR / Domain

## Pending: Config `host` field naming consistency

**Context:** Across the TNG JSON config, the field name `host` is used with different
semantic meanings:

| Config location | Type | Actual meaning |
|-----------------|------|----------------|
| `netfilter.capture_dst[].host` | `Option<Ipv4Cidr>` | Target IP/CIDR to capture (filter condition) |
| `hook.capture_dst[].host` | `Option<Ipv4Cidr>` | Target IP/CIDR to capture (filter condition) |
| `egress hook.capture_listen[].host` | `Option<Ipv4Addr>` | Bind address to match |
| `mapping.rules[].in.host` | `Option<String>` → being changed to `Option<Ipv4Addr>` | Listen address |
| `mapping.rules[].out.host` | `Option<String>` → being changed to `Option<Ipv4Addr>` | Target forward address |
| `Endpoint.host` (admin_bind etc.) | `Option<String>` | Listen/bind address |
| `PeerSharedArgs.host` | `String` | Listen address |

**Why not fix now:** Renaming these fields (e.g. `host` → `ip`/`bind_addr`/`target_addr`)
would be a **breaking JSON config change** for every existing deployment. The serialization
format is part of the public API and subject to the version compatibility policy
(`docs/version_compatibility.md`).

**Proposed approach (future):** Introduce distinct field names per semantic domain
(e.g. `bind_addr` for listen endpoints, `target_addr` for forward destinations,
`capture_ip` / `capture_cidr` for netfilter/hook filters), add them alongside the old
`host` field with deprecation warnings, and remove `host` after a grace period.

**Related:** See the IP/CIDR/Domain type clarification work on branch
`clarify_ip_or_cidr_or_domain` — that branch fixes the *type-level* inconsistencies
(`String` vs `Ipv4Cidr` vs `Ipv4Addr`) but deliberately does NOT rename the `host` field
itself to preserve backward compatibility.

# TODO: tng-wasm GitHub Pages demo — deferred items

## Pending: COOP/COEP service-worker shim for the public Pages site

**Context:** The README states the SDK requires
`Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp` (it uses Web Workers /
`SharedArrayBuffer`). GitHub Pages cannot set custom HTTP response headers, so
the public demo site currently ships **without** cross-origin isolation.

**Why not fix now:** CI integration tests
(`tng-testsuite/src/task/app/browser_client.rs`) run the SDK from a plain static
server with no COOP/COEP headers and pass, which is strong evidence the
`tng_fetch` path does not actually require `SharedArrayBuffer`. We ship bare and
verify on real browsers first.

**Trigger to fix:** If a real (non-headless) browser reports
`SharedArrayBuffer is not defined` when using the demo, add a
`coi-serviceworker`-style service worker under `tng-wasm/www/` that injects the
two headers on the page response. First-visit reload quirk is acceptable.

## Pending: Automated tests for the www demo and SSE parser

**Context:** No automated test covers the `tng-wasm/www/` UI or `js/sse.js`.

**Why not fix now:** An end-to-end LLM streaming test needs a real streaming
inference endpoint that CI does not have. The general-demo path is already
covered by `tng-testsuite/tests/js_sdk_http.rs` at the SDK level.

**Manual path:** `make www-demo` builds and serves the site locally for manual
verification.

**Future approach if needed:** reuse the `browser_client` harness to serve
`tng-wasm/www/` and drive the general-demo form via chromedriver; add a
synthetic-ReadableStream unit test for `readSseStream`.

## Pending: External-service caveats for the public demo

**Context:** The public demo is a client-side playground; users point it at
their own backends. Two inherent limitations cannot be fixed in-repo:

- **Mixed content:** the Pages site is HTTPS, so `http://` backends are blocked.
  Users must use HTTPS endpoints (or `localhost`).
- **CORS:** the user's Attestation Service and inference backend must send CORS
  headers allowing the `https://inclavare-containers.github.io` origin.

**Action:** These are documented in the demo UI / `example/README*.md`. No
in-repo fix is possible; revisit only if the demo UX needs to surface a clearer
error.

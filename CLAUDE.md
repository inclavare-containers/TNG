# CLAUDE.md

## Default Branch

The default/main branch for this project is **`master`**, not `main`. When a branch is not specified (e.g., in git commands, PR targets, or CI references), assume `master`.

## Code Refactoring Rules

When refactoring or modifying code:

- **Always preserve existing comments** if the code is kept and the comment is still accurate. This is especially important for comments containing URLs, as they are often critical for debugging and tracing issues back to their source (e.g., GitHub issue links, documentation references, bug reports).
- Only remove or update a comment if the described behavior no longer exists or is incorrect.
- When moving code, carry its comments along.
- When replacing a code block, **carry over the comments from the original block** to the replacement unless they are no longer accurate. For example, if refactoring `if let Ok(duration) = earliest_time.duration_since(now)` into a chain expression, keep the "Calculate time until earliest event" comment.

## Git Commit Requirements

When creating or amending commits:

- **Author and committer** must always be taken from the local git config (`git config user.name` / `git config user.email`). Never use Claude's own identity.
- **Never** add `Co-Authored-By:` trailers of any kind.
- **Always** add an `Assisted-by:` trailer to every commit message that Claude authored or co-authored. The trailer is the *only* accepted form of AI attribution. Format:

  ```
  Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2] ...
  ```

  Where `AGENT_NAME` is the AI tool name (e.g. `Claude`), `MODEL_VERSION` is the specific model version used (e.g. `claude-opus-4-8`), and the optional bracketed `[TOOL]` entries are specialized analysis tools employed in producing the change (e.g. `coccinelle`, `sparse`, `smatch`, `clang-tidy`). Basic development tools (`git`, `gcc`, `make`, editors) must **not** be listed. Place the trailer as the last line(s) of the commit message body, separated by a blank line from the rest of the message. Example:

  ```
  Assisted-by: Claude:claude-opus-4-8 clang-tidy
  ```

  Only one `Assisted-by:` trailer per commit. If no specialized tool was used, omit the bracketed list entirely (`Assisted-by: Claude:claude-opus-4-8`).
- **Never** include any Claude session URLs, session IDs, or links to claude.ai in commit messages or PR descriptions. Commit messages should only describe the code changes.
- **Never** include "🤖 Generated with [Claude Code](https://claude.com/claude-code)" or similar AI attribution footers in PR descriptions or commit messages.
- **Always** use `--no-gpg-sign` to avoid GPG signing.
- **Never commit plan or spec files** (e.g. `docs/*-plan.md`, `docs/*-design.md`, `docs/*-spec.md`, or anything under `docs/superpowers/`). These should be gitignored (already covered by `.gitignore`) and kept local only.
- **Never commit any file that is already gitignored** — if a file matches `.gitignore`, it is intentionally local-only.
- **Never leak this machine's git/remote configuration anywhere in committed content** — not in skills, docs, commit messages, PR descriptions, or code comments. That includes remote names (e.g. the local alias you push to), remote URLs, and the existence of mirrors or secondary forges (e.g. a GitLab mirror, a second GitHub remote). Any reference to a remote or repo in committed content must be **derived at runtime** from the current branch's tracking config or `git remote get-url`, never typed by hand. Example: a skill that pushes to a PR must compute `REMOTE` from `git rev-parse --abbrev-ref '@{upstream}'` (falling back to `git ls-remote` over `git remote`) and `REPO` from that remote's URL — it must not list `gh → ...`, `ali → ...`, `cohere → ...` or any concrete remote. The public GitHub repo identity (`owner/repo`) is fine to reference; the local mapping of remote *names* to *URLs* is not.
- **Never hardcode proprietary infrastructure anywhere in committed content** — not in docs, scripts, code, commit messages, or PR descriptions. That includes PAI-EAS / inference endpoint domains, attestation-service and trustee IPs or domains, and any other deployed-service address private to a deployment. Such addresses must be injected at runtime via flags or environment variables (e.g. `--as-url`, `--completions-url`, `$TNG_TEST_AS_URL`); the committed artifact only ever carries placeholders (`http://inference.example.com/...`, `http://as.example.com:8081/api/as/`) or the flag/env names themselves. Public, stable identifiers (the GitHub `owner/repo`, well-known example domains) are fine; concrete proprietary hosts/IPs are not. Before committing a test or scenario, grep it for the endpoint host and AS host/IP and confirm zero hits.
- **Never manually edit version information in `trusted-network-gateway.spec`** — do not touch the `Version:` or `Release:` fields, and do not add version-stamped `%changelog` entries by hand. Version/release bumps across the whole repo (`Cargo.toml`, `Cargo.lock`, `APPLICATION/tng/buildspec.yml`, `tng-python/pyproject.toml`, and the RPM spec `Version` + `%changelog`) are produced at a specific release stage by `make bump-version-{major,minor,patch}`. That target regenerates the spec changelog from commit subjects since the last tag, so a hand-written entry would both carry a wrong release number and duplicate the auto-collected commits. Edit the spec only for packaging logic (e.g. `BuildRequires`/`Requires`, `%build` flags); leave versioning to `make bump-version-*`.

## Bilingual Documentation Convention

This project maintains paired English/Chinese documentation throughout the repo. Whenever you update any documentation, **update both the English and the Chinese counterpart together**:

- Each crate has a `README.md` paired with a `README_zh.md` (e.g. `tng-wasm/README.md` ↔ `tng-wasm/README_zh.md`, same for `tng-go`, `tng-hook`, `tng-python`).
- `docs/` files are paired as `*.md` ↔ `*_zh.md` (e.g. `docs/configuration.md` ↔ `docs/configuration_zh.md`, same for `architecture`, `developer`, `version_compatibility`, etc.).

Do not update one language and leave the other stale. If a section is added/removed on one side, mirror it on the other.

- **Do not hard-wrap prose lines in human-readable Markdown.** In `docs/*.md`, `*_zh.md`, and crate `README.md`/`README_zh.md`, keep each paragraph (and each list item / blockquote line) as a single unbounded line — do not insert manual line breaks at a fixed column (e.g. ~70 chars for EN, ~36 chars for ZH). Markdown reflows to the reader's viewport automatically; manual wrapping only produces noisy diffs, mismatched EN/ZH line counts, and awkward editing. One sentence may run as long as it needs. Code blocks, tables, and frontmatter are exempt (their line structure is semantic).

## Persistent Text Writing Style

Several kinds of text in this repo are read by future developers and users long after they are written: Markdown documentation (`docs/*.md`, `*_zh.md`, crate `README*.md`), commit messages, PR titles and descriptions, and code comments. All of these are **persistent text** and must read like a real person wrote it.

- **Write like a human, not a form.** Use plain, direct language. Prefer short sentences over clause-stuffed ones. No robotic openers ("This commit aims to...", "The purpose of this PR is to..."), no filler hedging, no bureaucratic tone. Get to the point in the first line.
- **Be concise.** Say what changed and why, then stop. A reader should understand the change from the first sentence; extra detail goes in a short bullet list, not a wall of prose.
- **Plain language over jargon soup.** Use the concrete term a working engineer uses. Don't stack acronyms and internal codenames without context; if a name isn't obvious, drop one phrase of context.
- **Commit messages and PR descriptions are in English.** Title in imperative mood ("log: stop writing secrets into logs"); body explains what and why in plain English. The bilingual convention above applies to documentation, not to commit/PR text.
- **Comments explain *why*, not *what*.** The code already shows what it does; a comment should explain the non-obvious reason, constraint, or gotcha. When carrying over an existing comment, preserve it verbatim unless it is no longer accurate (see Code Refactoring Rules).
- **No AI-affectation footers in persistent text.** Never add "🤖 Generated with [Claude Code]" or similar attribution to PR descriptions, commit messages, or docs. The only accepted AI attribution in commits is the `Assisted-by:` trailer (see Git Commit Requirements).
- **No em dashes in prose.** Do not use the em dash ("——" in Chinese, "—" in English) as punctuation in docs, commits, PR descriptions, or comments; use a period, comma, semicolon, colon, or restructure the sentence instead. The table-cell `—` meaning "no default value" is a column value, not prose, and is exempt. Prefer a colon over a "—" separator inside heading text too.
- **Persistent text must be self-contained.** Commit messages, code comments, PR descriptions, and documentation are read by people who were NOT in the conversation that produced them. Do not use session-internal numbering, shorthand, or references (e.g. "the #2 feature", "item #3", "approach A") that only make sense if you were in the discussion. Every label, number, or reference in persistent text must be understandable by a future reader with no conversation context. If you tracked items as "#1, #2, #3" in the conversation, write them out in plain English in the commit/comment ("the forward_client_ip feature", "the FC log switch", etc.). GitHub issue numbers like `#225` are real references, not session labels, and are fine.

These rules apply wherever text is meant to be read later. Ephemeral output (a one-off reply in this session, a `println!` debug line) does not need to follow them.

- **Never leak internal incident info into the repo.** Commit messages, code comments, PR descriptions, documentation, and tests must not carry details tied to a specific internal incident: no incident dates, no internal host or deployment identifiers, no customer or workload names (e.g. a specific service or a job/replica identifier), no internal ticket or dashboard links, and no incident-narrative framing. Describe the bug by its technical mechanism and observable behavior only ("a long-lived TLS 1.3 connection eventually fails with `PeerMisbehaved::TooManyKeyUpdateRequests` after 32 peer-initiated key updates"), never by when or where it happened. Public upstream facts (rustls issue/PR numbers, error-variant names like `TooManyKeyUpdateRequests`) are fine; the internal outage narrative is not. If a fix was driven by an incident, scrub the incident specifics before committing, and keep that context in the session instead.

### Comment & Documentation Discipline

The "Comments explain *why*, not *what*" rule above, made concrete. These apply to code comments, TOML/Cargo comment blocks, and reference docs alike. Most of them are corollaries of one test: *would deleting this comment let a future maintainer make a real mistake?* If yes, keep it, dense, free of version pins and upstream internals. If no, move it to the commit message.

1. **Comment the abnormal, not the normal.** Default, obvious, or cross-platform-consistent behavior stays silent; enabling a feature on every target needs no rationale. Only the surprise needs a comment: a feature that is *mandatory* on one target, a flag whose removal breaks a build, a value that looks wrong but is deliberate. A comment exists for exactly one reason: deleting it would let someone make a real mistake (an unexplained build break, a correct config "fixed" into a bug, a re-introduced regression). "Explains a non-obvious constraint" passes; "restates what the code does" or "tells a historical story" fails.
2. **Write why/constraint/gotcha, not what/mechanism.** The code shows what it does and the mechanism can be re-derived from source. A comment earns its place with the non-obvious: *why* a value is what it is, the *constraint* it satisfies, the *gotcha* it avoids, ideally naming the exact error a wrong choice produces. Don't restate the mechanism of another crate.
3. **No version-pinned assertions in comments.** "As of dep vX, feature Y pulls Z" rots on the next bump and is the first thing forgotten when editing. What a dep pulls today is answerable from cargo and the lockfile in real time; don't snapshot it in prose. Version-fragile facts belong in the commit message, which is dated and immutable.
4. **Don't explain another repo's internals.** `#[cfg(...)]` gates, internal function names, and `compile_error!` syntax of an upstream crate cannot be verified from this repo and rot when upstream refactors. State the observable contract at most ("upstream will not compile without it"), not the internal mechanism.
5. **Make each block self-contained; don't dedupe via cross-reference.** "See the block above for the full rationale" couples two sites that must be edited together and forces the reader to jump. A short reason is restated where needed; a long reason probably shouldn't be a comment at all (see rule 6).
6. **Constraints live in comments; rationale and history live in the commit message.** Separate the durable (a constraint the next editor must respect and that must stay true) from the transient (why we chose this in this commit). Commit messages are immutable, dated, and searchable, the right home for "why we decided X"; comments are for the live constraint.
7. **Write dense, not long.** Three lines stating three constraints beat nine lines stating one plus mechanism and history. Every line should carry a fact the maintainer would otherwise lack; cut any line that is re-derivable or rotting.
8. **Inheriting a bad style is not a reason to extend it.** When you arrive and existing comments are already verbose and stale, "carry over the accurate parts" does not mean "perpetuate the verbose pattern." If the pattern is the problem, fix the pattern (trim), don't append in kind.

## Documentation Structure & Craft

These lessons come from repeated remote-attestation doc reviews; apply them to any `docs/*.md` / `*_zh.md` reference doc, especially reader-facing config references.

- **Keep field-table column semantics consistent.** The "默认/Default" column holds a real default value; never overload it with required-flags (`是`/`否`/`Yes`/`No`). Use `—` for "no default" and put "(required)" / "（必填）" in the description. Apply the same convention across every table in the doc.
- **Verify doc claims against source.** When documenting config fields, enum values, or defaults, cross-check against the code (`tng/src/config/ra.rs`, `rats-cert`, …) before asserting. Reviews have caught real errors: an enum alias documented as the wrong policy, a `model` row missing from verify tables, a `refresh_interval` row missing from one attest table. Don't write "the default is X" without having seen it in code.
- **Example `<summary>` titles: mark only the distinction.** A title states what sets this example apart from its siblings in the same section; it does not restate the mode/provider/attest context the heading already carries. No long parenthetical asides. Use one consistent prefix ("示例：" / "Example:"); number sibling sub-examples (示例 3a/3b/3c).
- **Progressive disclosure, but not all-folded.** Fold advanced background and full field-reference tables in `<details>` so the main path stays scannable. But don't make every block a folded `<details>` — vary the presentation (unfold the canonical example; fold the variants) so readers can tell the blocks apart.
- **Respect the heading-depth ceiling.** GitHub renders at most `######` (h6); `#######` renders as plain text. Never exceed h6. If a section at h6 needs sub-parts, use **bold labels** for the sub-parts; to give sub-parts real headings, promote the parent section to h5 first.
- **Add a glossary for newcomer-facing docs.** When the audience may not know the acronyms (Rekor, Trustee, OPA/rego, SLSA, DSSE, PCCS, RATS-TLS), add a short "术语速查/Glossary" with one line per term. Define on first use, don't throw-and-go.
- **Lead multi-option sections with a comparison table.** When a section offers several strategies/modes/types, put a small ✅/❌ comparison table at the top so the reader can choose, then expand each option below.
- **Mermaid diagrams.** Mermaid is the repo's diagram convention. Keep node labels carrying the system name (e.g. "TNG Attester", "TNG Verifier"). For a side-by-side comparison use `flowchart LR` + `direction LR` inside each subgraph + an invisible edge (`~~~`) between subgraphs to force horizontal layout. Convey design differences, not operational ones, and don't imply a service is always a separate process (note in-process/built-in variants where relevant).
- **Bilingual structural parity is verifiable.** zh and en must keep the same heading levels, the same number of `<details>`/examples, and the same field-table rows. Before calling a doc change done, check: `grep -c '```'` is even in both files, `<details>`/`</details>` counts match, `grep -n '^#'` level sequences are identical zh↔en, and `grep -n '——'` finds no prose em dashes.
- **Internal links only to stable anchors.** Only link `](#…)` to h2/h3 headings (their GitHub auto-anchors are stable). Do not link to h6 sub-sections or bold-labeled blocks — their auto-anchors are fragile. Verify every internal link resolves.
- **Don't expose internal uncertainties to customers.** Customer-facing scenario docs and diagrams describe only externally committed behavior. Internal protocol/wire-format differences, unverified compatibility caveats, and implementation-level unknowns do not belong in `docs/`, READMEs, or diagrams. When you hit one while writing a doc, leave it out of the doc and diagram, and surface it to me **in the session** as an explicit next-step action item needing my decision — never bury it in a commit message or an internal tracker I cannot see. Concretely: avoid leaking internal wire-format terms (specific `message/ohttp-*` content-type strings, internal header names like `x-tng-ohttp-api`) into customer-facing prose; verify phrasing with a grep before calling the doc done.
- **Remote attestation in scenario docs uses the built-in AS.** When a scenario involves RA, configure `verify` with `"as_type": "builtin"` (built-in AS, the `__builtin-as` feature; the verified form lives in `tng/src/config/ra.rs`) and do not draw an AS as a separate topology node. Do not use external-AS placeholders like `"as_addr": "http://as.example.com:8080/"` in new scenarios — scenario 05 still has them and is the known exception to reconcile later. Point readers to `docs/remote_attestation.md` for the full attest/verify builtin setup (attestation policy, reference values).
- **Diagram file naming.** The `.drawio.svg` double extension is reserved for draw.io-exported SVGs that embed editable drawio XML. A hand-authored plain SVG must be named `.svg` (e.g. `diagram.svg` / `diagram_zh.svg`), never `.drawio.svg`, so the suffix does not claim editability the file does not have.
- **Adding a scenario under `docs/scenarios/`.** Before writing a new `NN-<slug>/` scenario, run `git fetch gh && git rebase gh/master`. Scenario numbers are incremental but can be claimed by a parallel agent's work, so confirm the target number is free (or coordinate with whoever is working in parallel) before using it.

## TODO.md Discipline

**Never add, remove, or edit entries in `TODO.md` automatically** — not as a "test coverage note", not to record deferred work, not for any reason — unless the user explicitly asks for it. `TODO.md` is a human-curated tracking file; auto-generated entries there are noise. If you discover deferred work or a coverage gap worth tracking, mention it in your reply and let the user decide whether to put it in `TODO.md`.

## GitHub Pages Demo Site

The `tng-wasm/www/` directory is the source for the live demo published at **<https://inclavare-containers.github.io/TNG/>** (it contains `index.html`, `js/`, and the built `tng_wasm_bg.wasm` / `tng_wasm.js`). When changing the JavaScript SDK or the demo page, remember this site is a published artifact — do not delete `www/`, and rebuild/sync the `.wasm` bundle there when the SDK changes so the live demo stays up to date.

## PR Requirements

When creating a pull request, always:

1. Update relevant documentation **in both languages** — the English file and its `*_zh.md` counterpart (see the Bilingual Documentation Convention above; this includes each crate's `README.md`/`README_zh.md` and `docs/*.md`/`docs/*_zh.md`, notably `docs/configuration.md` ↔ `docs/configuration_zh.md`). Only document what the user needs to know: new config options, new user-visible features, or breaking changes. Do not add documentation for internal optimizations that have no new config option or user-visible behavior change. Do not document standard protocol behaviors (e.g. TLS 1.3 ticket lifecycle, anti-replay rules) that the project follows without modification. Do not explain internal implementation details (e.g. how session resumption works, ticket consumption mechanics) in user-facing docs — those belong in commit messages or code comments.
2. Add or update integration tests for new features
3. Never mention "🤖 Generated with Claude Code" in the PR description

## Pre-Commit Checks

**Before creating any commit**, always run and ensure the following pass:

```bash
cargo fmt           # Format code
make clippy         # Rust lints (wraps cargo clippy)
cargo build         # Compilation
```

Fix any errors or warnings reported before proceeding with the commit.

> **Important:** Run `cargo fmt` and `make clippy` _before_ committing, not just as a final verification. The CI will fail if formatting or lints are incorrect — fix them locally first.

**When renaming a boolean variable or changing its meaning**, verify that all
if/else branches have been swapped accordingly. A common mistake is flipping
the condition (`is_raw_tls` → `is_h2`) without swapping the bodies of the
branches, which inverts the intended behavior. Always audit all callers of the
renamed function to confirm the passed boolean value matches the new semantics.

### Known Environment Limitations

The following failures are pre-existing environment issues, not caused by code changes:

- **`cargo build` fails with "COMPILER BUG DETECTED" from aws-lc-sys**: The system GCC 10.2.1
  triggers a false-positive bug detection in `aws-lc-sys` (GCC bug 95189).
  `.cargo/config.toml` sets `CC=clang` to work around this — do not remove it.

- **`clippy`/`rustfmt` not installed for active toolchain**: The active toolchain (e.g. `1.89.0-x86_64-unknown-linux-gnu`) may be missing components. Install them before running checks:
  ```bash
  rustup component add clippy
  rustup component add rustfmt
  ```

- **`make clippy` fails with 403 from crates.io**: Some crates (e.g. `alloc-no-stdlib`) fail to download due to network restrictions in the CI environment. This is an infrastructure issue; proceed if the code change does not touch the affected crates.

- **`cargo build` fails with "Could not find `protoc`"**: The `rats-cert` crate generates gRPC code at build time and requires the Protocol Buffers compiler. Install it before running checks:
  ```bash
  apt-get install protobuf-compiler
  ```

### builtin-as-tdx verify needs no TDX device

The builtin AS (used by a TNG *client* to verify a remote TDX server's quote)
does pure quote parsing plus Intel cert-chain crypto. It does **not** open
`/dev/tdx_guest` and does **not** require running inside a TDX guest. The
`/dev/tdx_guest` device is only for the *attester* (generating a local quote),
i.e. the server side. Do not skip or gate builtin-as-tdx on a client/verifier
box for lack of TDX hardware; `cargo build --release` already enables it via
the default features, and it verifies fine on a non-TDX host.

### Cross-Platform / Cross-Compile Verification

TNG is built for non-Linux targets in CI (macOS `aarch64`/`x86_64-apple-darwin`, Windows `x86_64-pc-windows-gnu`, and `wasm32-unknown-unknown`). Code that depends on Linux-only facilities — **netfilter / iptables / TPROXY / `SO_MARK` (`socket2::Socket::set_mark`) / raw `libc` recvmsg ancillary data (`IP_ORIGDSTADDR`)** — must be `#[cfg(target_os = "linux")]`-gated so the crate still compiles on macOS/Windows/wasm. The `netfilter`, `netfilter_udp`, and `utils/udp` (TPROXY) modules are already Linux-gated; when adding a new Linux-only mode, mirror that gating and use the runtime `#[cfg(not(target_os = "linux"))]` bail pattern (see `IngressMode::Netfilter`/`NetfilterUdp` arms in `tng/src/runtime.rs`) so enum `match`es stay exhaustive on every platform.

Do **not** use plain `cargo check --target <non-linux>` to verify these — `aws-lc-sys` runs a C build script that `cargo check` cannot cross-compile (no target sysroot for clang). Use the Makefile cross-compile targets, which drive the C toolchain through `zig` via `cargo-zigbuild`:

```bash
make mac-cross-build        # cargo zigbuild --target aarch64-apple-darwin
make windows-cross-build    # cargo zigbuild --target x86_64-pc-windows-gnu --release (runs install-windows-build-deps first)
make wasm-build-debug       # wasm-pack build --dev --target web ./tng-wasm
make wasm-build-release     # wasm-pack build --release --target web ./tng-wasm
```

Any change touching `cfg(target_os = ...)` gates, `socket2` usage, or the `netfilter_udp`/`utils/udp` modules should be verified with at least `make mac-cross-build` and `make windows-cross-build` before pushing — CI builds all of these on every PR.

### Mirroring Container Images

To sync an OCI image (including multi-arch manifest lists) from one registry to another, use the generic `make image-mirror` target — see `Makefile`. Both the source and destination refs are fully qualified by the caller; the target ships no built-in registry endpoints or credentials.

## Running Tests with Service Dependencies

Several integration tests require external services to be running. Before running `cargo test`, start the following in the background and wait for them to be ready:

```bash
make test-dep-aa &   # Attestation Agent (Unix socket at /run/confidential-containers/attestation-agent/attestation-agent.sock)
make test-dep-as &   # Attestation Service (HTTP on localhost:8080)
```

Wait until both services are ready before running tests. The e2E CoCo tests (`test_e2e_background_check_flow`, `test_e2e_passport_flow`, `test_e2e_builtin_flow`) and the SLSA/ReleaseManifest converter tests depend on these services.

The `test_e2e_asr_flow` test additionally requires an ASR (Attestation Service Router) HTTP proxy listening on `127.0.0.1:8006`, which is NOT started by the `make test-dep-*` targets. If ASR is not available, this test will fail with "Connection refused".

## Running Integration Tests

- **Always use `make run-test`** to run integration tests. Running individual `cargo test -p tng-testsuite --test <name>` commands manually is fine for debugging, but **do NOT run multiple tests in parallel** — they share iptables rules and network namespaces, so concurrent execution causes conflicts. `make run-test` runs tests sequentially to prevent this.
- If a test fails with "Connection refused" on a netfilter test, check for stale `TNG_EGRESS_*` iptables rules and clean them up before re-running.
- **Every test in an integration test binary that calls `run_test!` (or otherwise brings up the test netns) MUST be marked `#[serial]`** (from the `serial_test` crate, already a dependency). `run_test!` runs `init_bridge` (see `tng-testsuite/src/netns.rs`), which creates and tears down **host-global** iptables chains `TNG_TEST_NETNS_POSTROUTING` / `TNG_TEST_NETNS_FORWARD`. The cargo test harness runs the test functions inside one binary concurrently, so two un-serialised tests race on those chains: one's `iptables -N` hits `Chain already exists` (or `RULE_APPEND failed: No such file or directory` when the other's `Drop` deletes the chain mid-append), the bridge setup bails with `exit code: Some(1)`, and the test fails even though its logic is correct. `#[serial]` makes the harness run those tests one at a time within the binary. Every existing multi-test integration file (`ohttp.rs`, `mapping_udp.rs`, `netfilter/*`, ...) already does this — mirror it when adding a new test to any of them, and add `#[serial]` to every test in any new integration file that uses `run_test!`.

## Scenario Access-Method Harness (`docs/scenarios/05-vllm-ohttp-cluster/`)

`run.sh` and `access/*.sh` exercise the five TNG access methods (tng-launch, tng-exec, python-sdk, go-sdk, js-sdk) end-to-end. Each method's prerequisite build (the tng binary, libtng_hook.so, the wasm pkg, the python wheel, the go SDK) **MUST go through the Makefile targets** via the shared `_ensure_make_target FILE TARGET` helper in `run.sh`. Never invoke raw `cargo`, `wasm-pack`, or `pip` from these scripts — the Makefile sets the flags the raw commands miss:

| Artifact | Make target | Why the Makefile, not the raw command |
|---|---|---|
| tng binary | `make bin-build` | sets `RUSTFLAGS="--cfg tokio_unstable"` + default features incl `builtin-as-tdx` |
| libtng_hook.so | `make tng-hook-build` | `cargo build -p tng-hook-cdylib` via the canonical target |
| wasm pkg | `make wasm-build-debug` | nightly toolchain + `getrandom_backend="wasm_js"` + atomics/bulk-memory target features; raw `wasm-pack build` does NOT compile (getrandom fails on wasm32) |
| python wheel | `make python-wheel` | builds the tng binary first, then the wheel from source (matches the bundled binary + builtin AS) |
| go SDK | `make go-build` | `cd tng-go && go build ./...` via the target |

When a method finds a prerequisite missing, it builds it with the matching `make` target and only SKIPs if the build itself fails. A new access method or a new prerequisite must add a Makefile target and use `_ensure_make_target`, not a raw tool invocation.

## Pre-Push Checks

Before pushing, verify the following:

### 1. No forbidden commit trailers

```bash
for sha in $(git log --format="%H" origin/$(git rev-parse --abbrev-ref HEAD)..HEAD 2>/dev/null); do
    git cat-file -p "$sha" | grep -q "^gpgsig" && echo "ERROR: commit $sha has gpgsig — rewrite with filter-branch before pushing" && exit 1
    git cat-file -p "$sha" | grep -q "Co-Authored-By:" && echo "ERROR: commit $sha has Co-Authored-By trailer — rewrite with filter-branch before pushing" && exit 1
    git log -1 --format="%ce" "$sha" | grep -qi "anthropic" && echo "ERROR: commit $sha has Claude committer — rewrite with filter-branch before pushing" && exit 1
done
echo "Pre-push checks passed"
```

If any commit has a `Co-Authored-By` or gpgsig trailer, strip them with:

```bash
git filter-branch -f --msg-filter 'sed "/Co-Authored-By:/d"' --env-filter '
  if [ "$GIT_COMMITTER_EMAIL" = "noreply@anthropic.com" ]; then
    export GIT_COMMITTER_NAME="$(git config user.name)"
    export GIT_COMMITTER_EMAIL="$(git config user.email)"
  fi
' <base-commit>..HEAD
```

This rewrites `Co-Authored-By` trailers (forbidden) but **preserves** `Assisted-by:` trailers (expected) — the `sed` only deletes `Co-Authored-By:` lines, so `Assisted-by:` survives untouched. After rewriting, confirm every AI-authored commit still carries its `Assisted-by:` trailer before pushing.


## GitHub Actions Workflow Triggers

When creating or editing `.github/workflows/*.yml`, follow the repo-wide trigger convention: every workflow triggers on `push` to `master` (and tags `v*.*.*`) and on `pull_request` targeting `master` — **without** a `paths:` filter.

**Never add a `paths:` filter** to gate a workflow on a subset of changed files. A `paths` filter silently skips the job when a change lands outside the listed globs — and because tests transitively depend on files outside their own directory (e.g. the Go SDK tests run `cargo test --package tng-testsuite --features go-sdk`, so they also depend on `tng-testsuite/`, `rats-cert/`, the `tng` binary, etc.), a `paths` filter limited to `tng-go/**` lets a real regression ship undetected. Triggering on every push/PR to `master` costs more CI minutes but closes that gap — the tradeoff is intentional.

Do not add per-feature legacy branch triggers (e.g. `sdk-go`) either; `master` is the only branch these workflows target. The canonical `on:` block is:

```yaml
on:
  push:
    branches:
      - "master"
    tags:
      - "v*.*.*"
  pull_request:
    branches:
      - "master"
```


## API Compatibility

When designing public APIs (REST endpoints, config fields, trait methods, public structs/traits), always design the full namespace structure upfront — do not defer naming decisions. Retrofitting a namespace layer later (e.g. inserting `/ohttp/` into an existing path like `/status/egress/<id>/keys` → `/status/egress/<id>/ohttp/keys`) breaks backward compatibility and is extremely costly. If a category of resources might grow multiple sub-resources in the future, include that category's namespace from day one.

When a change breaks backward compatibility:
1. **Update `docs/version_compatibility.md` and `docs/version_compatibility_zh.md`** — add a new row to the compatibility table describing the breaking change and the version it was introduced.
2. **Do not silently remove or rename existing endpoints, config fields, or public struct fields** — either keep the old path working (with deprecation warnings) or ensure the version compatibility doc reflects the break.
3. **Consider additive-only changes first** — new endpoints alongside old ones, optional fields alongside required ones, new trait methods with default implementations.

### What counts as a compatibility change

`docs/version_compatibility{,_zh}.md` tracks changes that force existing, unmodified configs/clients to behave differently or stop working. Log a row only when a change is **breaking** — i.e. an existing valid config, request, or client integration no longer parses or behaves the same way without user action. Concretely:

- Removed or renamed REST endpoints, config fields, CLI flags, or public struct/trait members.
- A removed or replaced public API/field that existing configs or code can no longer use unchanged.
- A flipped default that invalidates existing configs (e.g. a default changing `true`→`false` where old configs relied on the old default).
- A wire-format/protocol change that is not interoperable with older clients or servers.

Do **not** log a row for additive or behavior-broadening changes, even if noticeable — document these in `docs/configuration{,_zh}.md` (and crate `README.md`/`README_zh.md` where relevant) instead:

- New, optional config fields with backward-compatible defaults (old configs parse unchanged).
- New endpoints, fields, or trait methods added alongside existing ones.
- A behavior broadening that only adds capability and does not break any previously-valid config, request, or response (e.g. answering a previously-rejected request, adding a response header).
- Bug-fix-like enhancements.

The test: **would an existing, unmodified config that worked before still work the same way after?** If yes, it is not a compatibility change — do not add a `version_compatibility` row. A change that merely lets users opt into new behavior (new fields defaulting off; previously-rejected requests now succeeding) is additive, not breaking.


## Error Handling

- **Never** discard error context by formatting errors into strings (e.g., `anyhow::anyhow!("[{}] {}", source, e)` or `format!("{}", e)`).
- Use `anyhow::Context::context()` or `anyhow::Context::with_context()` to attach labels while preserving the original error in the chain:
  ```rust
  // Good — original error is preserved via source()
  .map_err(|e| anyhow::Error::from(e).context("source label"))

  // Bad — original error type is lost, only Display string remains
  .map_err(|e| anyhow::anyhow!("[source] {}", e))
  ```
- When wrapping `io::Error` into `io::Error::other(anyhow::Error)`, convert with `anyhow::Error::from(e)` and use `.context()` for the label.
- When logging errors with `tracing::error!`, `tracing::warn!`, etc., **use `?error` structured logging** — rename the error variable to `error` and use the `?` formatter, not `{}`:
  ```rust
  // Good — error is logged as structured data with Debug display
  tracing::warn!(?error, "failed to parse config JSON");
  tracing::error!(?error, "connection failed");

  // Bad — error is formatted into the message string, losing error chain
  tracing::warn!("failed to parse config JSON: {}", e);
  tracing::error!("connection failed: {}", error);
  ```

## Logging Levels

`tracing` levels follow the data-path cost, not just severity. A log that fires on the main per-connection or per-request hot path must never be `info`, because `info` is enabled by default and would emit on every connection.

- **`info`** — coarse, infrequent, operator-relevant events: startup, config reload, a listener binding, a rare escalation. Never a per-connection or per-request step.
- **`debug`** — per-connection / per-request diagnostics an engineer would want while reproducing a problem (e.g. "entering cert verify"). It is off by default, so per-connection cost is acceptable.
- **`trace`** — the most frequent and most low-level fast-path details (e.g. a cache hit, a sub-step inside a per-connection flow). If an event fires on essentially every connection AND is a microscopic sub-step, prefer `trace` over `debug`.

Rule of thumb: would this line fire on every connection? If yes, `info` is forbidden. Then pick `debug` for a meaningful per-connection step, `trace` for a frequent/low-level detail inside that step.

## CLI & Output Design

User-facing CLIs and test/automation scripts should be both beautiful and practical, following Unix philosophy and modern CLI conventions. Apply to `docs/scenarios/*/run.sh`, the `tng` CLI, and any new script that prints results a human reads.

- **Machine-parseable result lines on stdout.** Each unit of work (a test method, a subcommand) prints exactly one greppable result line, e.g. `PASS\t<name>`, `FAIL\t<name>\t<reason>`, `SKIP\t<name>\t<reason>`. A consumer can `grep -E 'PASS|FAIL|SKIP'` and rely on one line per unit. Chatter, progress, diagnostics, log tails go to **stderr**, so stdout stays a clean record of outcomes.
- **Color on a TTY, plain text when piped.** Emit ANSI color only when the output fd is a terminal (`[ -t 1 ]` / `[ -t 2 ]`); strip color when piped or redirected so downstream `grep`/`awk`/CI logs stay clean. Never make color a precondition for parsing.
- **Short header, short summary.** Print a one-block header (what is under test: endpoint host, AS mode, model, binary path) and, for multi-unit runs, a one-line summary at the end (`X passed, Y failed, Z skipped`). Both go to stderr. The stdout contract (one line per unit) is unchanged.
- **Plain, direct language.** No robotic openers. Progress lines carry the specific thing waited on ("waiting for port 41000 (12/90s)") not "please wait". Failures surface the actionable cause and where to find the log.
- **Composable and exit-correct.** Non-zero exit on any failure. Prefer composable pieces (one function per access method, sourced helpers) over a monolithic script. `-h/--help` prints usage; unknown args exit non-zero.

## Testing New Features

When implementing a new feature or modifying existing behavior:

1. **Unit tests** — add tests for the new logic in the same module's `#[cfg(test)]` block. Cover:
   - Normal cases (expected input → expected output)
   - Boundary conditions (edge values, min/max, empty inputs)
   - Error cases (invalid input → correct error)
   - Backward compatibility (existing behavior unchanged)

2. **Integration tests** — add a test in `tng-testsuite/tests/` that exercises the feature end-to-end through the TNG tunnel. Follow these guidelines:
   - Use `no_ra: true` on both client and server to avoid external AA/AS service dependencies, unless RA is specifically being tested.
   - Register the test in `tng-testsuite/Cargo.toml` under a `[[test]]` section.
   - Name the test file descriptively (e.g., `http_proxy_port_end.rs` for the `port_end` feature).
   - Verify the test passes locally before committing.

3. **When to add integration tests**:
   - New configuration fields that affect routing/matching behavior
   - New ingress/egress modes or modifiers
   - Changes to protocol behavior or tunnel establishment
   - Changes that could break existing configs (regression testing)

## Testing Discipline

- **Never remove a failing test to make CI pass.** When a test fails, investigate the root cause — it's either a bug in the test (fix the test), a bug in the code (fix the code), or an infrastructure issue (document and work around). Deleting a failing test hides real problems.
- **Never hide a failing test behind `#[ignore]` to make CI green.** This is dishonest — CI reports "passed" but the test never ran. If stuck, leave the test as-is and tell the user explicitly: "Test X fails because of Y, I cannot fix it because Z."

## Commit Gardening

At the end of a development branch's implementation, before merging or opening a PR, invoke the `commit-gardening` skill (`.claude/skills/commit-gardening/SKILL.md`) to reorganize commits into clean, independently verifiable logical blocks. The skill runs a gradient-descent loop (analyze, snapshot, execute, verify, loop) and internally hands off to `superpowers:finishing-a-development-branch` as its terminal step. Do not call `finishing-a-development-branch` directly when `commit-gardening` is available.

## Subagent Transient API Failures

When a dispatched subagent aborts on a transient model API error (rate limit, overloaded, gateway timeout, mid-run disconnect), **do not fall back to "I'll do it myself"** and do not silently inline the work into the main session. Re-dispatch the task to a fresh subagent, passing along the accumulated context (prior findings, partial output, the exact sub-goal). The whole point of delegating is to keep that work out of the main context window; pulling it inline defeats the delegation and re-bloats context. Keep re-dispatching on successive transient failures.

Only after **multiple** re-dispatch attempts still fail with the same API error should you fall back to doing the work directly. When you do, state plainly that subagent dispatch was retried N times and kept hitting API errors, so you completed the task inline as a last resort. Report this to the user so the context-cost tradeoff is visible.

The trigger is a transient *infrastructure* error from the model API, not a subagent that returned a wrong answer or hit a code bug. A subagent that finished but produced bad output gets re-dispatched with a corrected prompt; a subagent that never finished because the API itself errored gets re-dispatched with the same intent and the prior context.

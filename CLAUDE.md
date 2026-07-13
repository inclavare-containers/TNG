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
- **Never** include any Claude session URLs, session IDs, or links to claude.ai in commit messages or PR descriptions. Commit messages should only describe the code changes.
- **Never** include "🤖 Generated with [Claude Code](https://claude.com/claude-code)" or similar AI attribution footers in PR descriptions or commit messages.
- **Always** use `--no-gpg-sign` to avoid GPG signing.
- **Never commit plan or spec files** (e.g. `docs/*-plan.md`, `docs/*-design.md`, `docs/*-spec.md`, or anything under `docs/superpowers/`). These should be gitignored (already covered by `.gitignore`) and kept local only.
- **Never commit any file that is already gitignored** — if a file matches `.gitignore`, it is intentionally local-only.
- **Never manually edit version information in `trusted-network-gateway.spec`** — do not touch the `Version:` or `Release:` fields, and do not add version-stamped `%changelog` entries by hand. Version/release bumps across the whole repo (`Cargo.toml`, `Cargo.lock`, `APPLICATION/tng/buildspec.yml`, `tng-python/pyproject.toml`, and the RPM spec `Version` + `%changelog`) are produced at a specific release stage by `make bump-version-{major,minor,patch}`. That target regenerates the spec changelog from commit subjects since the last tag, so a hand-written entry would both carry a wrong release number and duplicate the auto-collected commits. Edit the spec only for packaging logic (e.g. `BuildRequires`/`Requires`, `%build` flags); leave versioning to `make bump-version-*`.

## Bilingual Documentation Convention

This project maintains paired English/Chinese documentation throughout the repo. Whenever you update any documentation, **update both the English and the Chinese counterpart together**:

- Each crate has a `README.md` paired with a `README_zh.md` (e.g. `tng-wasm/README.md` ↔ `tng-wasm/README_zh.md`, same for `tng-go`, `tng-hook`, `tng-python`).
- `docs/` files are paired as `*.md` ↔ `*_zh.md` (e.g. `docs/configuration.md` ↔ `docs/configuration_zh.md`, same for `architecture`, `developer`, `version_compatibility`, etc.).

Do not update one language and leave the other stale. If a section is added/removed on one side, mirror it on the other.

## TODO.md Discipline

**Never add, remove, or edit entries in `TODO.md` automatically** — not as a "test coverage note", not to record deferred work, not for any reason — unless the user explicitly asks for it. `TODO.md` is a human-curated tracking file; auto-generated entries there are noise. If you discover deferred work or a coverage gap worth tracking, mention it in your reply and let the user decide whether to put it in `TODO.md`.

## GitHub Pages Demo Site

The `tng-wasm/www/` directory is the source for the live demo published at **<https://inclavare-containers.github.io/TNG/>** (it contains `index.html`, `js/`, and the built `tng_wasm_bg.wasm` / `tng_wasm.js`). When changing the JavaScript SDK or the demo page, remember this site is a published artifact — do not delete `www/`, and rebuild/sync the `.wasm` bundle there when the SDK changes so the live demo stays up to date.

## PR Requirements

When creating a pull request, always:

1. Update relevant documentation **in both languages** — the English file and its `*_zh.md` counterpart (see the Bilingual Documentation Convention above; this includes each crate's `README.md`/`README_zh.md` and `docs/*.md`/`docs/*_zh.md`, notably `docs/configuration.md` ↔ `docs/configuration_zh.md`).
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

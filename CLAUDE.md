# CLAUDE.md

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
- **Never commit plan or spec files** (e.g. `docs/*-plan.md`, `docs/*-design.md`, `docs/*-spec.md`). These should be gitignored and kept local only.

## PR Requirements

When creating a pull request, always:

1. Update relevant documentation (both `docs/configuration.md` and `docs/configuration_zh.md`)
2. Add or update integration tests for new features
3. Never mention "🤖 Generated with Claude Code" in the PR description

## Pre-Commit Checks

Before creating any commit, always run and ensure the following pass:

```bash
make clippy        # Rust lints (wraps cargo clippy)
cargo fmt --check  # Formatting check
cargo build        # Compilation
```

Fix any errors or warnings reported before proceeding with the commit.

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

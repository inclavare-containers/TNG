# CLAUDE.md

## Git Commit Requirements

When creating or amending commits:

- **Author and committer** must always be taken from the local git config (`git config user.name` / `git config user.email`). Never use Claude's own identity.
- **Never** add `Co-Authored-By:` trailers of any kind.
- **Never** include any Claude session URLs, session IDs, or links to claude.ai in commit messages or PR descriptions. Commit messages should only describe the code changes.
- **Always** use `--no-gpg-sign` to avoid GPG signing.

## Pre-Commit Checks

Before creating any commit, always run and ensure the following pass:

```bash
make clippy        # Rust lints (wraps cargo clippy)
cargo fmt --check  # Formatting check
cargo build        # Compilation
```

Fix any errors or warnings reported before proceeding with the commit.

### Known Environment Limitations

The following failures are pre-existing environment issues, not caused by code changes:

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

## Pre-Push Checks

Before pushing, verify that no commits in the push carry a gpgsig header or a Claude committer identity:

```bash
for sha in $(git log --format="%H" origin/$(git rev-parse --abbrev-ref HEAD)..HEAD 2>/dev/null); do
    git cat-file -p "$sha" | grep -q "^gpgsig" && echo "ERROR: commit $sha has gpgsig — rewrite with filter-branch before pushing" && exit 1
    git log -1 --format="%ce" "$sha" | grep -qi "anthropic" && echo "ERROR: commit $sha has Claude committer — rewrite with filter-branch before pushing" && exit 1
done
echo "Pre-push checks passed"
```

If any commit fails, rewrite the committer with:

```bash
git filter-branch -f --env-filter '
  if [ "$GIT_COMMITTER_EMAIL" = "noreply@anthropic.com" ]; then
    export GIT_COMMITTER_NAME="$(git config user.name)"
    export GIT_COMMITTER_EMAIL="$(git config user.email)"
  fi
' <base-commit>..HEAD
```

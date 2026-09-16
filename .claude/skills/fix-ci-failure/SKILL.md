---
name: fix-ci-failure
description: Use when a CI check on a TNG PR (or on master) fails and you need to decide whether your change caused it and fix it. Covers classifying the failure (PR-related vs pre-existing-on-master vs already-being-fixed-upstream), local reproduction, fixing in the right place (the PR branch vs a new wt worktree with a separate PR to gh/master), and tracking CI to green.
---

# Fix a TNG CI Failure

## Overview

When a CI check fails, don't reach for a fix until you know **who owns the break**. Classify first: is it caused by your PR, pre-existing on master, or already being fixed upstream? Then reproduce locally, fix the root cause, verify, push, and track CI to green. The classification decides *where* the fix goes and *whether* you should fix it at all.

## Inputs

A failing CI check: either a check name on your PR (`gh pr checks <N>`) or a run URL. Get the failing job's log first:

```bash
gh run view <run-id> --repo inclavare-containers/TNG --log-failed | grep -iE "FAILED|panicked|exit code|test result|has been running for over|error\["
```

## Remotes & conventions

- No `origin`. `gh` = GitHub (`inclavare-containers/TNG`), `ali` = GitLab. Default branch is **`master`**.
- `on-bin` tests (hook/`tng exec`) run only in `build-rpm.yml` (`make run-test-on-bin`); they are **skipped** by `test.yml` (`make run-test`, `on-source-code`).
- `wt` is the worktree CLI; the default branch for PRs is `master`.

## Error-type triage: when you may skip local reproduction

Reproducing locally is the default — but for some error classes the failure output itself specifies the exact fix with near-certainty, so a full local repro is wasted cycles. Classify the failure, then decide.

| Error type | Confidence the fix is correct without full repro | Local reproduce? | Minimum verification |
|---|---|---|---|
| `cargo fmt` / formatting check fail | very high (deterministic) | skip | `cargo fmt` then re-run the fmt check |
| clippy warning with a printed suggestion | high | skip | `make clippy` clean |
| Compile error with explicit location + suggested fix (`help: ...`) | high (compiler dictates the change) | skip the failing *test* run | `cargo build` (or `cargo build --tests`) green |
| Documented known-environment failure (protoc missing, crates.io 403, aws-lc-sys "COMPILER BUG") | high (infra, not code; listed in CLAUDE.md) | skip | confirm the error string matches the known issue; fix is install-component / `CC=clang` |
| Missing test service ("Connection refused" to AA/AS/ASR a test is *supposed* to start, or a test known to need `make test-dep-aa`/`-as`) | high (gating is the repo convention, e.g. commit `16ab3f2d`) | skip repro | `cargo build --tests` (config-only gating change) |
| CI-only timeout/OOM on a test that passes locally, and you can confirm it's resource-only (no assertion/panic) | medium-high | skip repro only if you've ruled out a logic bug in the log | bump the timeout / split the test; re-run on CI |
| Logic/assertion failure or panic in real code | **low** | **must reproduce** | full local repro + failing test green |
| Concurrency / flaky race / intermittent | **low** | **must reproduce** (multiple runs) | repro → fix → stress-run |
| Integration data-path failure (TLS/decode/forward errors) | **low** | **must reproduce** | full local repro + failing test green |

**Guardrails for skipping:**

- Skipping local reproduction **never** means skipping verification. You always run at least `cargo fmt && make clippy && cargo build`. If the specific failing test is cheap to run, run it — skipping is only for when it's slow/expensive and the fix is tool-reported.
- "High confidence" must be **tool-reported**, not a guess. The compiler/clippy/fmt must *print* the fix, or the error must match a documented known-issue string. If you'd be guessing the fix, you cannot skip — reproduce.
- If a skipped fix doesn't go green on the first CI re-run, you were not high-confidence after all: fall back to local reproduction immediately. Don't iterate blind on CI.
- Skipping reproduction never authorizes `#[ignore]`-ing or deleting the failing test (Testing Discipline). A gated test must still run in the context that owns its dependencies.

## The Flow

### 1. Classify the failure (decides where the fix goes)

Three questions, in order:

**a. Is it in code your PR touched?** Diff the failing test's crate/file against your branch: `git diff gh/master...HEAD -- <path>`. If the failure is in a file your PR changes, it's **PR-related** → fix on your PR branch.

**b. Does the same job fail on `master` without your PR?**
```bash
gh run list --repo inclavare-containers/TNG --workflow <wf>.yml --branch master --limit 5
```
If master's same workflow is `failure` → it's **pre-existing on master**, not your PR.

**c. If pre-existing on master, are maintainers already fixing it?** Check master's recent commits and in-progress runs:
```bash
git fetch gh master && git log --oneline gh/master -10
gh run list --repo inclavare-containers/TNG --workflow <wf>.yml --branch master --limit 6   # look for in_progress fix commits
```
If a fix commit (e.g. "gate ... test", "fix ...") is on master and CI is `in_progress` → **upstream-owned**. **Do NOT open a competing fix PR** (it races the maintainers and duplicates their gating decision). Instead: watch master until green, then rebase your PR onto master and re-push. Done.

Only if it's pre-existing on master AND **not** being fixed upstream → go to step 2 with a **new `wt` worktree** and a **separate PR to `gh/master`** (don't tangle it with your feature PR).

### 2. Reproduce locally

First check the **Error-type triage** table above — for the high-confidence classes (fmt/clippy/compile-with-suggestion, documented env failures, missing-test-service gating) you may skip full local reproduction and jump to step 4 with only the minimum verification listed there. For everything else (logic/panic/race/data-path), reproduce now.

Match the failing job exactly:
- on-source-code job: `make run-test` (sequential; **never** run TNG integration tests in parallel — shared netns/iptables).
- on-bin job: `make run-test-on-bin`, or one test: `cargo test --no-default-features --features on-bin --package tng-testsuite --test <name> -- --nocapture`.
- on-bin tests need a `tng` built with default features (has `__builtin-as`); if the test uses `as_type:"builtin"`/`trust_all`, set `TNG_BINARY=target/release/tng` (`cargo build --release -p tng`) — the pre-installed system binary may lack `__builtin-as`.

If you can't reproduce, suspect environment (protoc, crates.io 403, aws-lc-sys GCC bug → `CC=clang` per `.cargo/config.toml`) or flakiness (netns/iptables residue — clean stale `TNG_EGRESS_*` rules and retry once).

### 3. Fix the root cause

Fix the actual defect, not the symptom. **Never** delete a failing test or hide it behind `#[ignore]` to make CI green (CLAUDE.md Testing Discipline). If it's a genuinely bad test, fix the test; if it's a real bug, fix the code.

### 4. Verify locally

Re-run the failing test until green, then `cargo fmt` + `make clippy` + `cargo build`. Fix your own warnings; ignore the documented pre-existing environment failures.

### 5. Commit & PR

- Commit: `--no-gpg-sign`; `Assisted-by: Claude:claude-opus-5` trailer on its own line after a blank line; **no** `Co-Authored-By`, no AI footers/URLs. Never commit `docs/superpowers/` (gitignored).
- PR-related fix: push to your PR branch (force-with-lease if you rebased) — the existing PR re-runs CI.
- Non-PR fix: from the `wt` worktree, push a new branch and `gh pr create --repo inclavare-containers/TNG --base master --head <branch>`.

### 6. Track CI to green

```bash
gh pr checks <N> --repo inclavare-containers/TNG
```
Background-poll if long (each `gh pr checks` is a quick API call; poll ~every 50s, exit early on green or first `fail`). If a check fails, loop back to step 1 with the new failure. Do not declare done until the check you came to fix is `pass`.

## Common mistakes

| Mistake | Reality |
|---------|---------|
| "It's on my PR, must be mine" | A failing check runs against master's code too; verify the failing test is in code your PR touches before owning it. |
| Opening a fix PR for a master breakage maintainers are already fixing | Races their fix and duplicates their gating. Check master commits + in-progress runs first; if owned upstream, wait + rebase. |
| Fixing the symptom (gating/deleting the test) | That hides the bug. Fix root cause; only gate a test if it's genuinely environment-dependent and that's the maintainers' decision, not yours to sneak in. |
| Forgetting `TNG_BINARY=target/release/tng` for on-bin/`builtin` tests | The system `tng` may lack `__builtin-as`; `as_type:"builtin"` is rejected at config parse. |
| Running integration tests in parallel | Shared netns/iptables → flaky collisions. Always sequential. |
| Force-pushing `master` or a shared branch | Never. Only force-push your own PR branch, with `--force-with-lease`. |

## Red flags — stop and reconsider

- The same workflow is failing on `master` → almost certainly not your PR; don't rush to "fix" your branch.
- A fix commit you didn't author just landed on `master` for the same symptom → upstream owns it; watch and rebase, don't compete.
- You're about to `#[ignore]` or delete a failing test to go green → don't; that's the one move CLAUDE.md forbids.

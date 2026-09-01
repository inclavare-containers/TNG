---
name: release-version
description: Use when releasing a new TNG version (cutting a major, minor, or patch release). The caller MUST state the version level — major, minor, or patch. Covers the full sequence: make bump-version-{major,minor,patch}, PR to gh/master, immediate tag push, ostest-bot /build trigger, and waiting for CI + GitHub release vendored tarball + openanolis image build.
---

# Release a TNG Version

## Overview

Cut a TNG release end-to-end: bump version → PR to `gh/master` → **immediately** push the tag (do NOT wait for CI) → reply `/build` to trigger the openanolis image build → wait for three conditions → report to the caller. The caller merges the PR; you never merge.

## Inputs (REQUIRED)

The caller must explicitly state the **version level**: `major`, `minor`, or `patch`. If they did not, stop and ask before doing anything. Examples of valid invocation:

- "发布 2.9.0（minor）" / "cut a minor release"
- "发 patch 版本" / "patch release"

Derive the target version from the Makefile (`make bump-version-<level>` prints `2.8.0 -> 2.9.0`). Do not hardcode the version number — read it from `Cargo.toml`.

## Remotes

This repo has **no `origin`** remote. Use:
- `gh` → GitHub (`inclavare-containers/TNG`)
- `ali` → GitLab
- `cohere` → GitHub mirror

Default branch is **`master`** (not `main`). PRs target `master`.

## The Flow

### 1. Bump the version

```bash
make bump-version-minor   # or -major / -patch
```

This regenerates version info across **5 files**: `Cargo.toml`, `Cargo.lock`, `APPLICATION/tng/buildspec.yml`, `tng-python/pyproject.toml`, and the RPM spec (`Version:` + an auto-collected `%changelog` from commit subjects since the last tag). **Never hand-edit the RPM spec `Version:`/`Release:`/`%changelog`** — the Makefile owns it.

Verify all 5 changed and `Cargo.lock` carries the new `tng` version:
```bash
git status --short
grep -n '^name = "tng"' -A1 Cargo.lock   # should show new version
```

This is a version-only change — `cargo fmt`/`make clippy`/`cargo build` add no signal here and hit known infra failures (aws-lc-sys GCC bug, crates.io 403). Skip them for the version bump itself; CI on the PR will validate.

### 2. Commit

Per `CLAUDE.md`: author/committer from local git config, `Assisted-by:` trailer (the *only* accepted AI attribution), `--no-gpg-sign`, **never** `Co-Authored-By`.

```bash
git add Cargo.toml Cargo.lock APPLICATION/tng/buildspec.yml tng-python/pyproject.toml trusted-network-gateway.spec
git commit --no-gpg-sign -m "Bump minor version to <X.Y.Z>" \
  -m "Regenerate version info via make bump-version-minor." \
  -m "Assisted-by: Claude:<model-version>"
```

Run the pre-push trailer check from `CLAUDE.md` (no `gpgsig`, no `Co-Authored-By`, no anthropic committer email).

### 3. Push branch + open PR (do NOT merge)

```bash
git push gh bump-version-<X.Y.Z>
gh pr create --repo inclavare-containers/TNG --base master --head bump-version-<X.Y.Z> \
  --title "Bump minor version to <X.Y.Z>" --body "<summary>"
```

**Never merge the PR.** The caller merges. State this in your status report.

### 4. Push the tag — IMMEDIATELY, do not wait for CI

This is the key step agents get wrong. **Push the tag right after the PR is open**, not after CI goes green. Reason: the tag triggers a full second set of `push`-event workflows (the release pipeline) that build all release assets — running them in parallel with the PR's `pull_request` CI saves ~15 min. Waiting for CI first serializes the two for no benefit.

```bash
git tag -a v<X.Y.Z> -m "Bump minor version to <X.Y.Z>"
git push gh v<X.Y.Z>
```

The tag push triggers (separate from the PR checks):
- `Build Binary Executable`, `Build RPM Package`, `Build Python SDK`, `Build WASM SDK`, `Build Docker Image`, `Run Tests on Source Code`, `Cargo Clippy`, `Rust Format Check`, `Go SDK Tests`, `Shell Script Tests` — all on ref `v<X.Y.Z>`.

### 5. Trigger the openanolis image build (ostest-bot)

Shortly after the PR opens, the **`ostest-bot`** GitHub account comments, acknowledging the request and posting a table of images it will build (e.g. `tng` with tags `2.9.0、latest`) and the line: *"如已确认，请回复 ***/build*** 进行构建。"*

You must reply **`/build`** as a PR comment to confirm:
```bash
gh pr comment <PR-NUM> --repo inclavare-containers/TNG --body "/build"
```

Wait for the bot's confirmation reply, which looks like:
> @imlk0 ，您好，您的 PR 构建任务已提交，请前往 [镜像制作中心](https://cr.openanolis.cn/make_center/detail_info/<ID>?pr_type=github&tab_type=repo) 查看构建结果

That **镜像制作中心** URL is the openanolis build link you'll report to the caller. Save it.

### 6. Wait for three conditions

Wait until ALL three are satisfied before reporting:

1. **CI all passes** — both the PR `pull_request` checks AND the tag `push` workflows. Track via:
   ```bash
   gh pr checks <PR-NUM> --repo inclavare-containers/TNG --watch --interval 30   # PR-side
   gh run list --repo inclavare-containers/TNG --branch v<X.Y.Z> --limit 20      # tag-side
   ```
2. **GitHub release `v<X.Y.Z>` exists and contains the vendored source tarball** — asset named `trusted-network-gateway-<X.Y.Z>-vendored-source.tar.gz` (produced by the `Build RPM Package` workflow; reference the `v2.8.0` release for the full asset list):
   ```bash
   gh release view v<X.Y.Z> --repo inclavare-containers/TNG --json assets \
     --jq '.assets[].name'
   ```
3. **openanolis build triggered** — the ostest-bot replied with the 镜像制作中心 confirmation (step 5).

**Waiting strategy:** run `gh pr checks --watch` and a poll loop in the **background** (`run_in_background: true`); the harness re-invokes you on completion. Do not burn the prompt cache polling every few minutes. A single background poller that exits when all three conditions are met is ideal.

### 7. Report to the caller

Report these four items (the caller's checklist):
1. **PR link** — `https://github.com/inclavare-containers/TNG/pull/<NUM>`
2. **CI result** — all green (note any accepted known-infra failures, see below)
3. **Vendored tarball link** — `https://github.com/inclavare-containers/TNG/releases/download/v<X.Y.Z>/trusted-network-gateway-<X.Y.Z>-vendored-source.tar.gz`
4. **openanolis 镜像制作中心 link** — the URL from the bot's confirmation comment

Remind the caller: **PR is not merged — for you to merge.**

## Known infra failures (do NOT treat as blockers)

These recur on every release and are **not** regressions and **not** release blockers. Investigate once to confirm the cause, then accept and note them in the report — do not let them stall the release.

| Check | Cause | Action |
|---|---|---|
| `test (alinux3)` (one of several runs) | Docker registry image-pull timeout (`context deadline exceeded` reaching `*.cr.aliyuncs.com`); never reaches the test suite | Transient infra. The same `test (alinux3)` job passes in the other matrix runs. `gh run rerun <run> --failed` to clear the red X, but it is non-required (PR stays `MERGEABLE`/`UNSTABLE`). |
| `Deploy demo to GitHub Pages` (in `Build WASM SDK`) | Recurring GitHub Pages deploy issue — **failed on every `v2.8.0` tag push too** (runs `30332713812`, `31676250844`, `31680048478`). | Accept. The wasm build itself (`build-and-release`), npm, and GitHub Packages publishing all succeed; only the live demo-site deploy fails. Not a release blocker (release assets are unaffected). |

If **any other** check fails, investigate the root cause before reporting — do not silently call CI green. Per `CLAUDE.md` testing discipline: never hide a failing test; a flaky job gets rerun, a real failure gets fixed or surfaced.

## Common mistakes

| Mistake | Reality |
|---|---|
| "Wait for CI to pass, then push the tag" | No — push the tag **immediately** after the PR. The release pipeline must run in parallel with PR CI. |
| "Merge the PR once CI is green" | No — never merge. The caller merges. |
| "Hand-edit `trusted-network-gateway.spec` Version/changelog" | No — `make bump-version-*` owns all version info across the repo. Editing the spec by hand duplicates/wrong-numbers the auto-generated changelog. |
| "Pages deploy failed — release is blocked" | No — known recurring infra fail on every tag push. Accept it. |
| "Poll CI every 60s in the foreground" | Wastes prompt cache. Use a background `gh pr checks --watch` / poller; the harness notifies you on exit. |
| "Use `origin` remote" | No `origin` here. Push to `gh` (GitHub). |
| "Default branch is `main`" | It's `master`. |

## Red flags — STOP

- Pushing the tag only after CI went green → you serialized the release pipeline for nothing. Push immediately.
- Merging the PR → the caller merges, not you.
- Reporting "CI green" while a non-known check is failing → investigate first.
- Committing with `Co-Authored-By:` or a GPG signature → forbidden by `CLAUDE.md`; rewrite before pushing.

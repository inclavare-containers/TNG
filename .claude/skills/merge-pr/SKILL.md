---
name: merge-pr
description: Use when the user asks to merge, land, or fast-forward an already-open pull request into its target branch — usually the PR belonging to the current branch. Use when you need to ff-merge via direct `git push <remote> HEAD:<target>` instead of the GitHub merge button.
---

# Merge a PR by Fast-Forward Push

## Overview

Land an already-open PR into its target branch with a **true fast-forward** (no merge commit, no squash): determine the PR's remote and repo from the current branch's tracking config, check CI, fetch the target branch, rebase the current branch onto it if it has moved, push the rebased branch to the PR, then advance the target branch directly with `git push <remote> HEAD:<target>`.

The PR must already exist. This skill does not create PRs (use `commit-commands:commit-push-pr` for that) and does not cut releases (use `release-version`). You are the one who merges — there is no separate "merge approver" step.

## Setup: derive the remote and repo at runtime (never hardcode them)

Do not assume remote names or repo paths — derive them from the current branch so the skill is portable and does not leak any machine's remote layout.

```
HEAD_BRANCH=$(git branch --show-current)

# 1) Prefer the head branch's upstream tracking remote.
UPSTREAM=$(git rev-parse --abbrev-ref '@{upstream}' 2>/dev/null)   # e.g. <remote>/<head>
REMOTE=${UPSTREAM%%/*}

# 2) If no upstream is set (branch was pushed without -u), find the remote
#    that actually holds the head branch by querying each remote directly.
if [ -z "$REMOTE" ]; then
  for r in $(git remote); do
    if git ls-remote --exit-code --heads "$r" "$HEAD_BRANCH" >/dev/null 2>&1; then
      REMOTE=$r; break
    fi
  done
fi
```

- If `REMOTE` is still empty (no remote holds the head branch), stop: the current branch is not the PR's head branch, or it was never pushed. Ask the caller to switch to the pushed head branch before continuing.
- Derive the GitHub `owner/repo` from that remote's URL — never type the repo path by hand. Handle both SSH (`git@host:owner/repo.git`) and HTTPS (`https://host/owner/repo.git`) without hardcoding the host:
  ```
  URL=$(git remote get-url "$REMOTE")
  case "$URL" in
    *://*) REPO=${URL#*://}; REPO=${REPO#*/} ;;   # https://host/owner/repo.git -> owner/repo.git
    *:*)   REPO=${URL##*:}            ;;           # git@host:owner/repo.git   -> owner/repo.git
    *) REPO=$URL ;;
  esac
  REPO=${REPO%.git}                              # strip trailing .git
  REPO=${REPO%/}                                 # strip any trailing slash
  ```
  If `REPO` does not end up as `owner/repo` (no slash, or empty), stop and report — the PR is not on a GitHub remote this branch tracks.
- The target branch lives on the **same `$REMOTE`** as the head branch.

Use `$REMOTE` and `$REPO` in every command below. `$REMOTE` is the PR's remote; the target branch (`master`/`main`) is read from the PR in step 1, not assumed.

## Inputs

The target PR is normally **the open PR whose head branch equals the current branch**. If the caller did not name a PR:

1. `gh pr list --repo "$REPO" --head "$HEAD_BRANCH" --state open --json number,title,baseRefName,headRefName`
2. Exactly one match → that is the PR. Zero or many → stop and ask the caller; offer candidates with `gh pr list --repo "$REPO" --state open --json number,title,headRefName,author`.

The PR must already be open. If it does not exist, stop and tell the caller to open it first (or use `commit-commands:commit-push-pr`). Do not invent a PR number.

## The Flow

### 1. Read the PR

```
gh pr view <N> --repo "$REPO" --json headRefName,baseRefName
```

Record `head` (the PR's branch, must match `$HEAD_BRANCH`) and `target` (the base branch, e.g. `master`). If the current local branch is not `head`, switch to it (`git switch <head>`); you merge from the head branch.

### 2. Check CI — stop if not green, let the caller decide

```
gh pr checks <N> --repo "$REPO"
```

- **All pass** (only `pass` / `skipping` entries) → continue to step 3. `skipping` is fine (release/publish jobs skip on PRs).
- **Any `fail` or `pending`** → summarize for the caller: which checks, and for each failing one the root cause (fetch the failed log with `gh run view <run-id> --log-failed` and read it — do not guess). Distinguish **code failures** (a test panicked / build error) from **infra failures** (docker-pull timeout, runner OOM, "context deadline exceeded", service-startup timeout). Then ask the caller whether to (a) have you fix the code failures, (b) continue anyway, or (c) abort.
  - If the caller asks you to fix: fix, push to the head branch, **re-run `gh pr checks` until green** before re-entering this step. After fixing, ask the caller whether to continue before proceeding to step 3.
  - Never auto-continue past a red check without explicit caller consent.

Do not proceed past this step until the caller has consented (or all checks are green).

### 3. Fetch the target branch and rebase if it moved

```
git fetch "$REMOTE" "$target"
git rebase "$REMOTE/$target"
```

- If `git rebase` reports "Current branch is up to date" / nothing to replay → `$REMOTE/$target` is already an ancestor of HEAD; nothing to rebase. Continue.
- If it replays commits cleanly → continue.
- If it stops with **conflicts** → go to **Conflict Handling** below. Do not resolve unilaterally.

After a successful rebase, the local head branch has new commit hashes. It is now **diverged from the remote head branch**, so the next push must be a force-push (step 4).

### 4. Push the rebased head branch to the PR

```
git push --force-with-lease "$REMOTE" "$head"
```

Always use `--force-with-lease` here (never bare `--force`): after a rebase the history is rewritten, but if someone else pushed to the head branch in the meantime `--force-with-lease` will refuse instead of clobbering. If it was a no-op rebase, this push is a no-op ("Everything up-to-date") — harmless.

This push triggers a fresh CI run on the PR. **Do not wait for it.** The design is optimistic: you already verified CI green in step 2, and a clean rebase onto an already-green base cannot introduce a new failure. Proceed immediately to step 5.

### 5. Fast-forward the target branch to HEAD

```
git push "$REMOTE" HEAD:"$target"
```

This is the merge. It advances `<REMOTE>/<target>` to your current `HEAD`. It only works as a **fast-forward**: `<REMOTE>/<target>` must be an ancestor of `HEAD` — which step 3 guaranteed. The remote head branch is now an ancestor of `<REMOTE>/<target>`, so GitHub auto-closes the PR as merged.

- If the push is **rejected as non-fast-forward** (someone merged something to `<REMOTE>/<target>` between your fetch and now): re-run step 3 (`git fetch`, `git rebase`) and retry step 5. Do not force-push the target branch — that rewrites shared history.
- If the push is **rejected by branch protection** (e.g. "protected branch", "required status check", "cannot force-push"): `<REMOTE>/<target>` has a protection rule that forbids direct pushes. Stop and report to the caller; do **not** silently fall back to a merge-commit or squash without consent. The caller can either relax the protection or ask you to use `gh pr merge <N> --rebase` as a fallback.

### 6. Report

Confirm `<REMOTE>/<target>` now points at your HEAD:

```
git fetch "$REMOTE" "$target" --quiet
git rev-parse "$REMOTE/$target"   # compare to:
git rev-parse HEAD
```

Tell the caller: PR #N merged (ff) into `<target>` at `<short-sha>`. Optionally offer to delete the remote head branch (`git push "$REMOTE" --delete "$head"`); do not delete it without consent.

## Conflict Handling

When `git rebase <REMOTE>/<target>` stops with conflicts, **do not resolve unilaterally**. The caller owns conflict decisions. Do this instead:

1. List the conflicted files: `git status --short` (lines beginning with `U`/`AA`/`DD`).
2. **Assess complexity per file** and report it to the caller, classified as:
   - **Trivial textual** — disjoint line ranges, no semantic overlap (one side touched imports, the other touched a function body). Safe to resolve by taking both hunks.
   - **Same-line / semantic** — both sides edited the same lines (e.g. both renamed the same symbol). Needs a human decision on intent.
   - **Structural** — file renamed/moved/deleted on one side and edited on the other, or large hunk overlap. High risk.
3. Ask the caller whether they want you to resolve, and for which files. For **trivial textual** conflicts you may resolve and continue once the caller agrees. For **same-line/semantic** and **structural**, resolve only the specific hunks the caller directs, and show them each resolution before continuing.
4. **Never** run `git rebase --continue`/`git add` on a conflicted file unless either (a) git's `rerere`/`merge` tool auto-resolved it cleanly with no marker left, or (b) the caller has approved your specific resolution for that file. If you are unsure whether a resolution is correct, stop and ask — do not guess.

**Iron rule:** when git cannot auto-resolve a conflict, the decision belongs to the caller. Your job is to surface the conflict, classify its complexity, and execute the resolution the caller approves — not to pick a winner.

If the caller declines to resolve (or the conflicts are too risky), abort the rebase with `git rebase --abort` and report.

## Common Mistakes

| Mistake | Fix |
|---|---|
| Force-pushing the **target** branch (`git push --force <REMOTE> master`) | Never. Only ff-push `HEAD:<target>`. If non-ff, re-fetch + rebase. |
| Using bare `--force` on the head branch | Use `--force-with-lease`; refuses to clobber a concurrent push. |
| Waiting for CI after the step-4 push | Don't. The whole point is optimistic ff-merge. You verified green in step 2. |
| Merging past red CI without consent | Stop at step 2; summarize failures, let caller decide. |
| Resolving conflicts unilaterally | Don't. Classify, report, get per-file approval. |
| Inventing a PR number when none matches the branch | Stop; ask caller; offer open-PR candidates. |
| Hardcoding a remote name / repo path | Derive `$REMOTE` from the head branch's upstream and `$REPO` from that remote's URL; never type them by hand. |

## Quick Reference

```
HEAD_BRANCH=$(git branch --show-current)
UPSTREAM=$(git rev-parse --abbrev-ref '@{upstream}')   # e.g. <remote>/<head>
REMOTE=${UPSTREAM%%/*}                                  # PR's remote (if empty, ls-remote fallback, see Setup)
URL=$(git remote get-url "$REMOTE")                      # parse owner/repo for both SSH and HTTPS:
case "$URL" in *://*) REPO=${URL#*://}; REPO=${REPO#*/} ;; *:*) REPO=${URL##*:} ;; *) REPO=$URL ;; esac
REPO=${REPO%.git}
N=<PR number> ; head=<head branch> ; target=<base branch, e.g. master>
gh pr view   $N --repo "$REPO" --json headRefName,baseRefName
gh pr checks $N --repo "$REPO"                       # all green? else ask caller
git fetch     "$REMOTE" "$target"
git rebase    "$REMOTE/$target"                       # conflicts? -> Conflict Handling
git push --force-with-lease "$REMOTE" "$head"        # triggers CI; do NOT wait
git push      "$REMOTE" HEAD:"$target"               # the ff merge
git rev-parse "$REMOTE/$target"                      # confirm == HEAD
```

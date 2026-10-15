#!/usr/bin/env bash
# bench/run-ablation.sh - controller-side ablation runner. Part of the standard
# harness: every arm is built with record-build.py, deployed to both hosts,
# measured through the FULL client.sh/server.sh matrix (all workloads, all
# reference rows), and each consecutive arm pair is rendered by
# render-pr-reports.sh with the identical PR-level report format.
#
# Usage:
#   bash bench/run-ablation.sh <arms.tsv> <outdir> <client-host> <server-host>
#     <client-host>/<server-host>: ssh targets (user@host); the server host's
#     address is also what client.sh uses as SERVER_IP.
#
# arms.tsv (tab-separated, one per line; the FIRST arm is the baseline):
#   <name>\t<git-ref>
# The runner builds a detached worktree per arm, measures, and compares
# arm[i-1] vs arm[i]. Sub-report titles carry both compared refs.
#
# Requires the bench lock (artifacts/bench-lock.sh) for the whole measurement
# phase; hosts are cleaned between arms.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
LOCK_SH="$HERE/artifacts/bench-lock.sh"

[ $# -eq 4 ] || { echo "usage: $0 <arms.tsv> <outdir> <client-host> <server-host>" >&2; exit 2; }
ARMS="$1"; OUT="$2"; CLI_HOST="$3"; SRV_HOST="$4"

[ -f "$ARMS" ] || { echo "error: arms manifest not found: $ARMS" >&2; exit 2; }
[ -f "$LOCK_SH" ] || { echo "error: bench lock helper not found: $LOCK_SH" >&2; exit 2; }
command -v ssh >/dev/null || { echo "ssh not found" >&2; exit 2; }
command -v scp >/dev/null || { echo "scp not found" >&2; exit 2; }

mkdir -p "$OUT"
REMOTE_BENCH=/root/bench
REMOTE_TNG=/root/tng

WORKROOT="$(mktemp -d "$OUT/arms.XXXX")"
ARMS_LIST=()
NAMES=()
REFS=()
while IFS=$'\t' read -r name ref; do
  [ -n "${name:-}" ] || continue
  case "$name" in \#*) continue ;; esac
  NAMES+=("$name"); REFS+=("$ref"); ARMS_LIST+=("$name|$ref")
done < "$ARMS"
[ "${#ARMS_LIST[@]}" -ge 2 ] || { echo "error: need at least two arms (first is the baseline)" >&2; exit 2; }

# Deploy the harness tree (scripts + lib) to both hosts once.
for h in "$CLI_HOST" "$SRV_HOST"; do
  ssh "$h" "mkdir -p $REMOTE_BENCH" >/dev/null
  scp -q "$HERE"/{client.sh,server.sh,gen-report.sh,render-pr-reports.sh,record-build.py,report_support.py} "$h:$REMOTE_BENCH/" 2>/dev/null ||
    scp -q "$HERE"/client.sh "$HERE"/server.sh "$HERE"/gen-report.sh "$HERE"/render-pr-reports.sh "$HERE"/record-build.py "$HERE"/report_support.py "$h:$REMOTE_BENCH/"
  ssh "$h" "mkdir -p $REMOTE_BENCH/lib" >/dev/null
  scp -q "$HERE"/lib/*.sh "$h:$REMOTE_BENCH/lib/"
done

# Acquire the shared two-host bench lock for the whole measurement phase.
source "$LOCK_SH" acquire
trap 'source "$LOCK_SH" release 2>/dev/null || true' EXIT

# Build + measure each arm with the standard harness.
for i in "${!ARMS_LIST[@]}"; do
  name="${NAMES[$i]}"; ref="${REFS[$i]}"
  arm_dir="$OUT/$name"
  [ -d "$arm_dir" ] && { echo "error: arm output exists: $arm_dir" >&2; exit 2; }
  mkdir -p "$arm_dir"
  wt="$WORKROOT/$name"
  git -C "$REPO" worktree add --detach "$wt" "$ref" >/dev/null
  python3 "$HERE/record-build.py" --source "$wt" --binary tng/target/release/tng \
    --build-command 'cargo build --release -p tng' --output "$wt/tng.build.json" >/dev/null
  bin="$wt/tng/target/release/tng"
  for h in "$CLI_HOST" "$SRV_HOST"; do
    scp -q "$bin" "$h:$REMOTE_TNG"
    scp -q "$wt/tng.build.json" "$h:$REMOTE_TNG.build.json"
  done

  ssh "$SRV_HOST" "cd $REMOTE_BENCH && TNG_BIN=$REMOTE_TNG bash server.sh --output-dir /tmp/ablation-$name" &
  srv_pid=$!
  sleep 15
  ssh "$CLI_HOST" "cd $REMOTE_BENCH && TNG_BIN=$REMOTE_TNG bash client.sh $SRV_HOST --output-dir /tmp/ablation-$name"
  kill "$srv_pid" 2>/dev/null || true
  ssh "$SRV_HOST" "pkill -x tng 2>/dev/null || true" >/dev/null 2>&1 || true
  ssh "$CLI_HOST" "pkill -x tng 2>/dev/null || true" >/dev/null 2>&1 || true

  scp -q "$SRV_HOST:/tmp/ablation-$name/server-info.json" "$arm_dir/"
  scp -q "$CLI_HOST:/tmp/ablation-$name/client-info.json" "$arm_dir/"
  scp -q "$CLI_HOST:/tmp/ablation-$name/bench-results.json" "$arm_dir/"
  ssh "$SRV_HOST" "rm -rf /tmp/ablation-$name" >/dev/null
  ssh "$CLI_HOST" "rm -rf /tmp/ablation-$name" >/dev/null
  echo "measured arm $name ($ref)" >&2
  git -C "$REPO" worktree remove --force "$wt" >/dev/null
done
source "$LOCK_SH" release; trap - EXIT

# Render one sub-report per consecutive arm pair through the standard template.
MANIFEST="$OUT/manifest.tsv"; : > "$MANIFEST"
for ((i = 1; i < ${#ARMS_LIST[@]}; i++)); do
  prev="${NAMES[$((i-1))]}"; cur="${NAMES[$i]}"
  title="Experiment: ablation: $cur (${REFS[$((i-1))]} vs ${REFS[$i]})"
  printf '%s\t-\t%s/server-info.json\t%s/client-info.json\t%s/bench-results.json\t%s/server-info.json\t%s/client-info.json\t%s/bench-results.json\n' \
    "$title" "$OUT/$prev" "$OUT/$prev" "$OUT/$prev" "$OUT/$cur" "$OUT/$cur" "$OUT/$cur" >> "$MANIFEST"
done
bash "$HERE/render-pr-reports.sh" "$MANIFEST" "$OUT/ablation-reports.md"
echo "$OUT/ablation-reports.md"

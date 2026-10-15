#!/usr/bin/env bash
# bench/render-pr-reports.sh - render the full PR benchmark chapter: one chapter
# heading plus one sub-report per experiment, every sub-report produced by
# bench/gen-report.sh --compare with the identical report template.
#
# Usage: bash bench/render-pr-reports.sh <manifest.tsv> <output.md>
#
# The manifest is a tab-separated file, one experiment per line:
#   <sub-report title>\t<gen-report flags (may be empty)>\t<base-server-info>\t<base-client-info>\t<base-results>\t<exp-server-info>\t<exp-client-info>\t<exp-results>
#
# The main experiment uses a fixed title ("Experiment: overall"); each ablation
# sub-report title carries the two compared commit hashes. Lines starting with
# '#' and blank lines are ignored.
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <manifest.tsv> <output.md>" >&2; exit 2; }
MANIFEST="$1"
OUT="$2"
GEN="$(dirname "$0")/gen-report.sh"

[ -f "$MANIFEST" ] || { echo "error: manifest not found: $MANIFEST" >&2; exit 2; }

TMPDIR_RENDER="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_RENDER"' EXIT

n=0
{
  echo '# Benchmark reports'
  echo ''
} > "$OUT"

while IFS=$'\t' read -r title flags bsrv bcli bres esrv ecli eres; do
  [ -n "${title:-}" ] || continue
  case "$title" in \#*) continue ;; esac
  for f in "$bsrv" "$bcli" "$bres" "$esrv" "$ecli" "$eres"; do
    [ -f "$f" ] || { echo "error: input not found for '$title': $f" >&2; exit 2; }
  done
  n=$((n + 1))
  part="$TMPDIR_RENDER/part-$n.md"
  # shellcheck disable=SC2086
  bash "$GEN" --compare --title "$title" $flags \
    "$bsrv" "$bcli" "$bres" "$esrv" "$ecli" "$eres" "$part" >&2
  cat "$part" >> "$OUT"
  echo '' >> "$OUT"
done < "$MANIFEST"

[ "$n" -gt 0 ] || { echo "error: no experiments in manifest" >&2; exit 2; }
echo "$OUT"

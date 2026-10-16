#!/usr/bin/env bash
# bench/pr-report-comments.sh - maintain full benchmark reports as PR comments,
# updated in place. GitHub's PR body has a size limit that full comparison
# reports exceed, so the reports live in comments and the PR body links to
# them; each comment is identified by its FIRST LINE (the marker) and gets
# edited in place on every re-run, never duplicated.
#
# Usage:
#   bash bench/pr-report-comments.sh <pr-number> <repo> <comment-manifest.tsv>
#     <repo>: owner/name
#     manifest: one comment per line, just the path of its markdown file.
#       The file's first non-empty line is the marker (e.g. a compact
#       "## Full benchmark: <base>...<head>" title); all regeneration keeps
#       the marker stable so the comment is found and PATCHed.
# Output: one TSV line per comment: <marker><TAB>created|updated<TAB><comment-url>
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <pr-number> <repo> <comment-manifest.tsv>" >&2; exit 2; }
PR="$1"; REPO="$2"; MANIFEST="$3"

[ -f "$MANIFEST" ] || { echo "error: manifest not found: $MANIFEST" >&2; exit 2; }
command -v gh >/dev/null || { echo "gh not found" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Snapshot the existing comments once: id, url, and each comment's marker.
# Markers are the <summary> line of the comment's report fold (or its first
# heading line for plain reports).
gh api "repos/$REPO/issues/$PR/comments?per_page=100" --paginate > "$TMP/list.json" 2>/dev/null || true
python3 - "$TMP/list.json" > "$TMP/existing.tsv" <<'EOF'
import json, sys
def marker(body):
    for l in body.splitlines():
        l = l.strip()
        if l.startswith("<summary>"):
            t = l[len("<summary>"):]
            return t[:-len("</summary>")].strip() if t.endswith("</summary>") else t.strip()
    return next((l for l in body.splitlines() if l.strip().startswith("#")), "")
try:
    comments = json.load(open(sys.argv[1]))
except Exception:
    comments = []
for c in comments if isinstance(comments, list) else [comments]:
    print("%s\t%s\t%s" % (marker(c.get("body", "")), c["id"], c["html_url"]))
EOF

while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in \#*) continue ;; esac
  [ -f "$f" ] || { echo "error: comment file not found: $f" >&2; exit 2; }
  marker="$(python3 -c "import sys
for l in open(sys.argv[1]).read().splitlines():
    l = l.strip()
    if l.startswith('<summary>'):
        print(l[len('<summary>'):].rsplit('</summary>', 1)[0].strip()); break
    if l.startswith('#'):
        print(l); break" "$f")"
  [ -n "$marker" ] || { echo "error: $f has neither a <summary> line nor a heading to use as marker" >&2; exit 2; }
  cid=""; curl_=""
  while IFS=$'\t' read -r m id url; do
    if [ "$m" = "$marker" ]; then cid="$id"; curl_="$url"; fi
  done < "$TMP/existing.tsv"
  if [ -n "$cid" ]; then
    python3 - "$f" > "$TMP/payload.json" <<'EOF'
import json, sys
print(json.dumps({"body": open(sys.argv[1]).read()}))
EOF
    gh api "repos/$REPO/issues/comments/$cid" -X PATCH --input "$TMP/payload.json" > "$TMP/resp.json"
    url="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["html_url"])' "$TMP/resp.json")"
    action="updated"
  else
    url="$(gh pr comment "$PR" --repo "$REPO" --body-file "$f" | grep -o 'https://[^ )"]*comment[^ )"]*' | head -1)"
    action="created"
  fi
  printf '%s\t%s\t%s\n' "$marker" "$action" "$url"
done < "$MANIFEST"

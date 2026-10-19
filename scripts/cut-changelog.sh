#!/usr/bin/env bash
# Cut CHANGELOG.md's [Unreleased] section into a released version section:
# retitle it to "## [version] - today", insert a fresh empty
# "## [Unreleased]" above it, and maintain the bottom link references.
# Usage: cut-changelog.sh <version> <prev-tag> [file]
#   <version>  new version, e.g. 2.12.0
#   <prev-tag> previous release tag, e.g. v2.11.0 (feeds the compare link)
set -euo pipefail

version="$1"
prev_tag="$2"
file="${3:-CHANGELOG.md}"
repo="https://github.com/inclavare-containers/TNG"

[ -f "$file" ] || { echo "ERROR: $file not found" >&2; exit 1; }
grep -q '^## \[Unreleased\]$' "$file" || { echo "ERROR: no [Unreleased] section in $file" >&2; exit 1; }

date=$(LC_ALL=C date +%Y-%m-%d)
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

awk -v ver="$version" -v date="$date" '
  !cut && $0 == "## [Unreleased]" {
    print "## [Unreleased]"
    print ""
    print "## [" ver "] - " date
    cut = 1
    next
  }
  { print }
' "$file" > "$tmp"

unreleased_ref="[Unreleased]: ${repo}/compare/v${version}...HEAD"
version_ref="[${version}]: ${repo}/compare/${prev_tag}...v${version}"

if grep -q '^\[Unreleased\]:' "$tmp"; then
  sed -i -e "s|^\[Unreleased\]: .*|${unreleased_ref}|" "$tmp"
  sed -i "/^\[Unreleased\]: /a ${version_ref}" "$tmp"
else
  printf '\n%s\n%s\n' "$unreleased_ref" "$version_ref" >> "$tmp"
fi

mv "$tmp" "$file"

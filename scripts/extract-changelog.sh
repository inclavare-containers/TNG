#!/usr/bin/env bash
# Print a CHANGELOG.md section's body on stdout: everything after its
# "## [section]" heading up to the next "## [" heading, subsection headings
# (### Added etc.) and entry lines included.
# Usage: extract-changelog.sh <section> [file]
#   <section>  a version like 2.12.0, or "Unreleased"
# Exits 1 with a message on stderr when the section is missing.
set -euo pipefail

section="$1"
file="${2:-CHANGELOG.md}"

[ -f "$file" ] || { echo "ERROR: $file not found" >&2; exit 1; }

awk -v want="$section" '
  /^## \[/ {
    if (found) exit
    heading = $0
    sub(/^## \[/, "", heading)
    sub(/\].*/, "", heading)
    if (heading == want) found = 1
    next
  }
  found { print }
' "$file" | awk '
  # Trim leading and trailing blank lines so consumers (release notes, RPM
  # entries) do not inherit the blank line after the heading.
  NF && !first { first = NR }
  NF { last = NR }
  { lines[NR] = $0 }
  END { for (i = first; i <= last; i++) print lines[i] }
' || exit 1

if ! grep -qF "## [${section}]" "$file"; then
  echo "ERROR: section [${section}] not found in $file" >&2
  exit 1
fi

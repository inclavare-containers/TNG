#!/usr/bin/env bash
# Convert relative links in tng-python README files to absolute GitHub URLs
# for proper PyPI rendering. Run BEFORE `hatch build`.
#
# Converts:
#   ](docs/getting-started.md) → ](https://github.com/inclavare-containers/TNG/blob/master/tng-python/docs/getting-started.md)
#   ](README_zh.md) → ](https://github.com/inclavare-containers/TNG/blob/master/tng-python/README_zh.md)
#   [English](README.md) → [English](https://github.com/.../README.md)
#
# Leaves anchor links (#architecture), http/https links untouched.

set -euo pipefail

REPO="https://github.com/inclavare-containers/TNG"
BRANCH="master"
BASE="tng-python"

for readme in "${BASE}/README.md" "${BASE}/README_zh.md"; do
  [ -f "$readme" ] || continue

  # Replace ](docs/... links
  sed -i "s|](docs/|](${REPO}/blob/${BRANCH}/${BASE}/docs/|g" "$readme"

  # Replace ](README_... links (cross-language references)
  sed -i "s|](README_|](${REPO}/blob/${BRANCH}/${BASE}/README_|g" "$readme"
done

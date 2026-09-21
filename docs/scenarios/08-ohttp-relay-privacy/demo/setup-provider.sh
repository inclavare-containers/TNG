#!/usr/bin/env bash
# Build the inclavare-containers/terraform-provider-alicloud fork (branch
# feat/ecs-security-options) into a sibling dir and emit a Terraform CLI config
# that points Terraform at the built binary via dev_overrides. The fork adds the
# security_options block (TDX) that upstream does not have yet.
#
# The cloned repo + built binary live under ./terraform-provider-alicloud/ and
# are gitignored (NOT a TNG submodule). Idempotent: skips clone/build if the
# binary already exists. Requires `git` and `go` on PATH.
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd -P)"
FORK_DIR="$DEMO_DIR/terraform-provider-alicloud"
BINARY="$FORK_DIR/terraform-provider-alicloud"
TF_RC="$DEMO_DIR/.terraformrc"
FORK_REPO="https://github.com/inclavare-containers/terraform-provider-alicloud.git"
FORK_BRANCH="feat/ecs-security-options"

need() { command -v "$1" >/dev/null 2>&1 || { echo "setup-provider: '$1' not found on PATH" >&2; exit 1; }; }
need git
need go

if [ -x "$BINARY" ]; then
  echo "setup-provider: binary already built at $BINARY" >&2
else
  echo "setup-provider: cloning fork ($FORK_BRANCH) into $FORK_DIR" >&2
  rm -rf "$FORK_DIR"
  git clone --depth 1 --branch "$FORK_BRANCH" "$FORK_REPO" "$FORK_DIR" >&2
  echo "setup-provider: building (heavy, first time)..." >&2
  ( cd "$FORK_DIR" && go build -o terraform-provider-alicloud . ) >&2
fi

# dev_overrides needs an ABSOLUTE path to the dir holding the binary.
cat > "$TF_RC" <<EOF
provider_installation {
  dev_overrides {
    "aliyun/alicloud" = "$FORK_DIR"
  }
  direct {}
}
EOF

# Print the CLI config path so callers can `export TF_CLI_CONFIG_FILE=$(...)`.
echo "$TF_RC"

#!/bin/bash

# Helper script to run unit and integration tests.
# Supports optional coverage collection via cargo-llvm-cov.

set -euo pipefail

trap 'catch' ERR
catch() {
    echo "An error has occurred. Exiting..."
    exit 1
}

# Default options
ENABLE_COVERAGE=false
INSTALL_TOOL=true
GENERATE_REPORT=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --coverage)
            ENABLE_COVERAGE=true
            shift
            ;;
        --no-install)
            INSTALL_TOOL=false
            shift
            ;;
        --no-report)
            GENERATE_REPORT=false
            shift
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

project_root=$(dirname "$(realpath "$0")")/../
cd "$project_root"

export RUST_BACKTRACE=1

failed=0
test_result_msgs=""
tool_cmd="cargo test"

install_cargo_llvm_cov() {
    if command -v cargo-llvm-cov &>/dev/null; then
        echo "cargo-llvm-cov is already installed."
        return 0
    fi

    if ! $INSTALL_TOOL; then
        echo "cargo-llvm-cov is not installed and --no-install was specified. Exiting." >&2
        return 1
    fi

    echo "cargo-llvm-cov is not installed. Installing now..."

    # Install llvm-tools
    rustup component add llvm-tools

    # Get host target
    host=$(rustc -vV | grep '^host:' | cut -d' ' -f2)
    url="https://github.com/taiki-e/cargo-llvm-cov/releases/download/v0.6.16/cargo-llvm-cov-$host.tar.gz"

    mkdir -p "$HOME/.cargo/bin"
    export PATH="$HOME/.cargo/bin:$PATH"

    if curl --proto '=https' --tlsv1.2 -fsSL "$url" | tar xzf - -C "$HOME/.cargo/bin"; then
        echo "Successfully installed cargo-llvm-cov."
    else
        echo "Failed to download or extract cargo-llvm-cov from $url" >&2
        return 1
    fi

    # Verify installation
    if ! command -v cargo-llvm-cov &>/dev/null; then
        echo "Installation seemed successful but cargo-llvm-cov is still not found." >&2
        return 1
    fi
}

run_tests() {
    local args=("$@")
    if $ENABLE_COVERAGE; then
        cargo llvm-cov "${args[@]}"
    else
        cargo test "${args[@]#--no-report}"
    fi
}

# Prepare command
if $ENABLE_COVERAGE; then
    tool_cmd="cargo llvm-cov"
    install_cargo_llvm_cov || exit 1

    # Clean previous coverage data
    echo "Cleaning previous coverage artifacts..."
    cargo llvm-cov clean --workspace
fi

# Run unit tests
echo "============= Starting unit test ============="
test_result_msgs="${test_result_msgs}\n============= Unit tests ============="

unit_args=(
    --no-report
    --workspace
    --bins
    --lib
    --exclude tng-wasm
    --
    --nocapture
)

echo "$tool_cmd ${unit_args[*]}"
if run_tests "${unit_args[@]}"; then
    test_result_msgs="${test_result_msgs}\nunit test:\tPASS"
else
    test_result_msgs="${test_result_msgs}\nunit test:\tFAILED"
    failed=1
fi

# Run integration tests
test_cases=$(ls tng-testsuite/tests/ | grep -E '.*\.rs$' | sed 's/\.rs$//')
skipped_test_cases=""  # Add test names here to skip, space-separated

test_result_msgs="${test_result_msgs}\n============= Integration tests ============="

for case_name in $test_cases; do
    echo "============= Starting integration test case: $case_name ============="

    if [[ " $skipped_test_cases " =~ " $case_name " ]]; then
        test_result_msgs="${test_result_msgs}\n${case_name}:\tSKIP"
        continue
    fi

    integ_args=(
        --no-report
        --no-default-features
        --features on-source-code
        --package tng-testsuite
        --test "$case_name"
        --
        --nocapture
    )

    echo "$tool_cmd ${integ_args[*]}"
    if run_tests "${integ_args[@]}"; then
        test_result_msgs="${test_result_msgs}\n${case_name}:\tPASS"
    else
        test_result_msgs="${test_result_msgs}\n${case_name}:\tFAILED"
        failed=1
    fi
done

test_result_msgs="${test_result_msgs}\n============= All tests finished ============="

echo -e "$test_result_msgs"

# Generate coverage reports if enabled and requested
if $ENABLE_COVERAGE && $GENERATE_REPORT; then
    echo "Generating coverage reports..."

    # Summary report
    cargo llvm-cov report \
        --summary-only \
        --ignore-filename-regex 'deps/*'

    # Codecov format
    cargo llvm-cov report \
        --ignore-filename-regex 'deps/*' \
        --codecov \
        --output-path target/codecov.json

    echo "Coverage report generated at target/codecov.json"
fi

exit $failed

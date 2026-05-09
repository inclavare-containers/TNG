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
declare -a summary_lines=()
failed_tests=""

format_result() {
    local name="$1"
    local status="$2"
    printf "%-60s %s\n" "$name" "$status"
}

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
        echo "cargo llvm-cov ${args[*]}"
        # Run tests first, capture output and exit code
        cargo llvm-cov "${args[@]}" 2>&1 | tee /tmp/llvm-cov-output.log
        local test_exit=${PIPESTATUS[0]}
        # Filter out known spurious warnings that cause non-zero exit
        if [ "$test_exit" -ne 0 ]; then
            if grep -q "functions have mismatched data" /tmp/llvm-cov-output.log && \
               ! grep -qiE "test.*FAILED|error\[|thread.*panicked" /tmp/llvm-cov-output.log; then
                echo "Ignoring llvm-cov mismatched data warning (tests passed)"
                return 0
            fi
            return "$test_exit"
        fi
        return 0
    else
        echo "cargo test ${args[*]#--no-report}"
        cargo test "${args[@]#--no-report}"
    fi
}

# Prepare command
if $ENABLE_COVERAGE; then
    install_cargo_llvm_cov || exit 1

    # Clean previous coverage data
    echo "Cleaning previous coverage artifacts..."
    cargo llvm-cov clean --workspace
fi

# Pre-compile all test binaries before running tests (non-coverage only)
if ! $ENABLE_COVERAGE; then
    echo "============= Pre-compiling test binaries ============="
    cargo build --workspace --exclude tng-wasm
    cargo build --no-default-features --features on-source-code --package tng-testsuite
    echo "============= Pre-compilation finished ============="
fi

# Run unit tests
echo "============= Starting unit test ============="
summary_lines+=("$(format_result "Unit tests" "")")

unit_args=(
    --no-report
    --workspace
    --bins
    --lib
    --exclude tng-wasm
    --
    --nocapture
)

unit_output=$(run_tests "${unit_args[@]}" 2>&1) || unit_failed=true || true
echo "$unit_output"

if [[ "${unit_failed:-false}" == "true" ]]; then
    summary_lines+=("$(format_result "  unit test" "FAILED")")
    # Extract failed test names from cargo test output
    failed_unit_tests=$(echo "$unit_output" | grep -E '^test .* FAILED$' | sed 's/ --- FAILED$//' | sed 's/^test //')
    if [[ -n "$failed_unit_tests" ]]; then
        while IFS= read -r t; do
            summary_lines+=("$(format_result "    -> $t" "FAILED")")
            failed_tests="${failed_tests:+${failed_tests}, }unit:$t"
        done <<< "$failed_unit_tests"
    fi
else
    summary_lines+=("$(format_result "  unit test" "PASS")")
fi
echo "============= Finished unit test ============="

# Run integration tests
test_cases=$(ls tng-testsuite/tests/ | grep -E '.*\.rs$' | sed 's/\.rs$//')
skipped_test_cases=""  # Add test names here to skip, space-separated

summary_lines+=("$(format_result "Integration tests" "")")

for case_name in $test_cases; do
    echo "============= Starting integration test case: $case_name ============="

    if [[ " $skipped_test_cases " =~ " $case_name " ]]; then
        summary_lines+=("$(format_result "  $case_name" "SKIP")")
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

    if run_tests "${integ_args[@]}"; then
        summary_lines+=("$(format_result "  $case_name" "PASS")")
    else
        summary_lines+=("$(format_result "  $case_name" "FAILED")")
        failed=1
        failed_tests="${failed_tests:+${failed_tests}, }${case_name}"
    fi
done

summary_lines+=("$(format_result "" "")")
summary_lines+=("All tests finished")
if [[ -n "$failed_tests" ]]; then
    summary_lines+=("Failed: ${failed_tests}")
fi

echo ""
echo "============= Test Summary ============="
for line in "${summary_lines[@]}"; do
    echo "$line"
done
echo "========================================"

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

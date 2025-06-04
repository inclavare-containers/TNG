#!/bin/bash

# This is a helper script to run all unit tests and integration tests in the project. Although `cargo test` is ok, but this script provides more information of each test case.

set -e

trap 'catch' ERR
catch() {
    echo "An error has occurred. Exit now"
}

script_dir=$(dirname $(realpath "$0"))

export RUST_BACKTRACE=1

failed=0
test_result_msgs=""

install_cargo_llvm_cov() {
    export PATH="$HOME/.cargo/bin:$PATH"

    if ! command -v cargo-llvm-cov &> /dev/null; then
        echo "cargo-llvm-cov is not installed. Installing now..."
        # Get host target
        host=$(rustc -vV | grep '^host:' | cut -d' ' -f2)
        # Download binary and install to $HOME/.cargo/bin
        curl --proto '=https' --tlsv1.2 -fsSL "https://github.com/taiki-e/cargo-llvm-cov/releases/latest/download/cargo-llvm-cov-$host.tar.gz" \
        | tar xzf - -C "$HOME/.cargo/bin"
    fi

    export LLVM_COV=`command -v llvm-cov`
    export LLVM_PROFDATA=`command -v llvm-profdata`
}

install_cargo_llvm_cov

# remove artifacts that may affect the coverage results
cargo llvm-cov clean --workspace

# Run unit tests
echo "============= Starting unit test ============="
test_result_msgs="${test_result_msgs}\n============= Unit tests ============="
echo "cargo llvm-cov --no-report --bins --lib -- --nocapture"
if cargo llvm-cov --no-report --workspace --bins --lib -- --nocapture; then
    test_result_msgs="${test_result_msgs}\nunit test:\tPASS"
else
    test_result_msgs="${test_result_msgs}\nunit test:\tFAILED"
    failed=1
fi

# Run bin tests under 'tng-testsuite/tests/' dir
test_cases=$(ls ${script_dir}/../tng-testsuite/tests/ | grep -E ".*\.rs$" | sed 's/\.rs//g')
skipped_test_cases=""

test_result_msgs="${test_result_msgs}\n============= Integration tests ============="
for case_name in ${test_cases[@]}; do
    echo "============= Starting integration test case: $case_name ============="
    # skipped_test_cases
    if [[ "${skipped_test_cases}" =~ "${case_name}" ]]; then
        test_result_msgs="${test_result_msgs}\n${case_name}:\tSKIP"
        continue
    fi

    echo "cargo llvm-cov --no-report --package tng-testsuite --test $case_name -- test --exact --nocapture"
    if cargo llvm-cov --no-report --package tng-testsuite --test $case_name -- test --exact --nocapture; then
        test_result_msgs="${test_result_msgs}\n${case_name}:\tPASS"
    else
        test_result_msgs="${test_result_msgs}\n${case_name}:\tFAILED"
        failed=1
    fi
done
test_result_msgs="${test_result_msgs}\n============= All tests finished ============="

echo -e $test_result_msgs

# print coverage report
cargo llvm-cov report --summary-only --ignore-filename-regex 'deps/*'

# generate report for codecov
cargo llvm-cov report --ignore-filename-regex 'deps/*' --codecov --output-path target/codecov.json

[[ $failed -eq 0 ]]

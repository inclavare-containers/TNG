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

# Run unit tests
echo "============= Starting unit test ============="
test_result_msgs="${test_result_msgs}\n============= unit tests ============="
echo "cargo test --bins --lib -- --nocapture"
if cargo test --workspace --bins --lib -- --nocapture; then
    test_result_msgs="${test_result_msgs}\nunit test:\tPASS"
else
    test_result_msgs="${test_result_msgs}\nunit test:\tFAILED"
    failed=1
fi

# Run bin tests under 'tng-testsuite/tests/' dir
test_cases=$(ls ${script_dir}/../tng-testsuite/tests/ | grep -E ".*\.rs$" | sed 's/\.rs//g')
skipped_test_cases=""

test_result_msgs="${test_result_msgs}\n============= integration tests ============="
for case_name in ${test_cases[@]}; do
    echo "============= Starting integration test case: $case_name ============="
    echo "cargo test --package tng-testsuite --test $case_name -- test --exact --nocapture"
    # skipped_test_cases
    if [[ "${skipped_test_cases}" =~ "${case_name}" ]]; then
        test_result_msgs="${test_result_msgs}\n${case_name}:\tSKIP"
        continue
    fi

    if cargo test --package tng-testsuite --test $case_name -- test --exact --nocapture; then
        test_result_msgs="${test_result_msgs}\n${case_name}:\tPASS"
    else
        test_result_msgs="${test_result_msgs}\n${case_name}:\tFAILED"
        failed=1
    fi
done

echo -e $test_result_msgs

[[ $failed -eq 0 ]]

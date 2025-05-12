#!/bin/bash

set -e

trap 'catch' ERR
catch() {
    echo "An error has occurred. Exit now"
}

script_dir=$(dirname $(realpath "$0"))

echo "============= Starting unit tests for bin test suits ============="
echo "cargo test --test client_netfilter_server_netfilter -- common:: --nocapture"
if cargo test --test client_netfilter_server_netfilter -- common:: --nocapture; then
    test_result_msgs="${test_result_msgs}\nunit test (for bin test suits):\tPASS"
else
    test_result_msgs="${test_result_msgs}\nunit test (for bin test suits):\tFAILED"
    exit 1
fi

# Run bin tests under 'tests/' dir
test_cases=$(ls ${script_dir}/../tests/ | grep -E ".*\.rs$" | sed 's/\.rs//g')
skipped_test_cases="allow_non_tng_traffic"

export RUST_BACKTRACE=1

failed=0
test_result_msgs=""

test_result_msgs="${test_result_msgs}\n============= integration tests ============="
for case_name in ${test_cases[@]}; do
    echo "============= Starting integration test case: $case_name ============="
    echo "cargo test --test $case_name -- test --exact --nocapture"
    # skipped_test_cases
    if [[ "${skipped_test_cases}" =~ "${case_name}" ]]; then
        test_result_msgs="${test_result_msgs}\n${case_name}:\tSKIP"
        continue
    fi

    if cargo test --test $case_name -- test --exact --nocapture; then
        test_result_msgs="${test_result_msgs}\n${case_name}:\tPASS"
    else
        test_result_msgs="${test_result_msgs}\n${case_name}:\tFAILED"
        failed=1
    fi
done

# Run unit tests
echo "============= Starting unit test ============="
test_result_msgs="${test_result_msgs}\n============= unit tests ============="
echo "cargo test --bins --lib -- --nocapture"
if cargo test --bins --lib -- --nocapture; then
    test_result_msgs="${test_result_msgs}\nunit test:\tPASS"
else
    test_result_msgs="${test_result_msgs}\nunit test:\tFAILED"
    failed=1
fi

echo -e $test_result_msgs

[[ $failed -eq 0 ]]

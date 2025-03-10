#!/bin/bash

set -e

trap 'catch' ERR
catch() {
    echo "An error has occurred. Exit now"
}

script_dir=$(dirname `realpath "$0"`)

# Run tests under 'tests/' dir
# Note: we ignore tcp_two_way_ra_ingress_httpproxy_egress_netfilter here since the test for it is not finished 
test_cases=`ls ${script_dir}/../tests/ | grep -E ".*\.rs$" | sed 's/\.rs//g'`

failed=0
test_result_msgs=""

test_result_msgs="${test_result_msgs}\n============= integration tests ============="
for case_name in ${test_cases[@]}; do
    echo "============= Starting integration test case: $case_name ============="
    if cargo test --test $case_name ; then
        test_result_msgs="${test_result_msgs}\n${case_name}:\tPASS"
    else
        test_result_msgs="${test_result_msgs}\n${case_name}:\tFAILED"
        failed=1
    fi
done

# Run unit tests
echo "============= Starting unit test ============="
test_result_msgs="${test_result_msgs}\n============= unit tests ============="
if cargo test --bins --lib ; then
    test_result_msgs="${test_result_msgs}\nunit test:\tPASS"
else
    test_result_msgs="${test_result_msgs}\nunit test:\tFAILED"
    failed=1
fi

echo -e $test_result_msgs

[[ $failed -eq 0 ]]

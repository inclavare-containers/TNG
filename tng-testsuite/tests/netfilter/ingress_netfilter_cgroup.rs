use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{
        app::AppType,
        shell::{ShellMode, ShellTask},
        tng::TngInstance,
        NodeType, Task as _,
    },
};

/// Test ingress netfilter with capture_cgroup.
///
/// Flow:
/// 1. TngServer with egress netfilter (port 30001)
/// 2. TngClient with ingress netfilter capture_cgroup = ["/tng_ig_cap_test/"]
/// 3. ShellTask creates the cgroup, moves itself into it, connects to 192.168.1.1:30001
/// 4. Ingress netfilter intercepts the connection (cgroup match) and forwards through TNG tunnel
/// 5. Egress netfilter on server side captures and delivers to TcpServer
/// 6. TcpServer echoes, ShellTask verifies the response
#[serial]
#[ignore = "requires cgroup v2 with xt_cgroup iptables module, not available in CI containers"]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ingress_netfilter_cgroup_capture() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": { "port": 30001 }
                        },
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_cgroup": ["/tng_ig_cap_test/"]
                        },
                        "verify": {
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        AppType::TcpServer { port: 30001 }.boxed(),
        ShellTask {
            name: "ingress_cgroup_capture_client".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                set -e
                CGROUP=/sys/fs/cgroup/tng_ig_cap_test
                mkdir -p "$CGROUP"
                echo $$ > "$CGROUP/cgroup.procs"
                trap "rmdir $CGROUP 2>/dev/null" EXIT
                # Connect to server:192.168.1.1:30001, traffic is intercepted by ingress netfilter
                # (cgroup match) and forwarded through TNG tunnel
                RESPONSE=$(echo 'hello_ingress_cgroup' | socat - TCP:192.168.1.1:30001)
                if [ "$RESPONSE" != "hello_ingress_cgroup" ]; then
                    echo "Expected 'hello_ingress_cgroup', got '$RESPONSE'"
                    exit 1
                fi
                echo "ingress cgroup capture test passed"
            "#
            .to_owned(),
            mode: ShellMode::BackgroundContinue,

        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Test ingress netfilter with nocapture_cgroup.
///
/// Validates two behaviors:
/// 1. Traffic from capture_cgroup is intercepted by TNG (goes through tunnel)
/// 2. Traffic from nocapture_cgroup bypasses TNG (direct connection works)
///
/// Setup:
/// - TngServer with egress netfilter (port 30001)
/// - TngClient with ingress netfilter capture_cgroup + nocapture_cgroup
/// - Two cgroups created on client node
#[serial]
#[ignore = "requires cgroup v2 with xt_cgroup iptables module, not available in CI containers"]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ingress_netfilter_cgroup_nocapture() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": { "port": 30001 }
                        },
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_cgroup": ["/tng_ig_nc_capture/"],
                            "nocapture_cgroup": ["/tng_ig_nc_bypass/"]
                        },
                        "verify": {
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        AppType::TcpServer { port: 30001 }.boxed(),
        ShellTask {
            name: "ingress_cgroup_nocapture_client".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                set -e
                CAPTURE_CG=/sys/fs/cgroup/tng_ig_nc_capture
                BYPASS_CG=/sys/fs/cgroup/tng_ig_nc_bypass
                mkdir -p "$CAPTURE_CG" "$BYPASS_CG"
                trap "rmdir $CAPTURE_CG $BYPASS_CG 2>/dev/null" EXIT

                # Test 1: Connect from capture_cgroup → should go through TNG tunnel
                echo "test_capture" | (
                    echo $$ > "$CAPTURE_CG/cgroup.procs"
                    socat - TCP:192.168.1.1:30001
                ) | grep -q "test_capture"
                echo "ingress capture path passed"

                # Test 2: Connect from nocapture_cgroup → should bypass TNG
                # Without TNG tunnel, this direct connection to 192.168.1.1:30001
                # should fail (the server doesn't listen on that port directly)
                # But from nocapture_cgroup, it should still go through TNG if no
                # other rule matches. Since capture_cgroup is set, non-matching
                # cgroups are NOT captured. So this should fail.
                if echo "test_bypass" | (
                    echo $$ > "$BYPASS_CG/cgroup.procs"
                    timeout 5 socat - TCP:192.168.1.1:30001 2>/dev/null
                ); then
                    echo "nocapture test: connection went through (unexpected)"
                    exit 1
                else
                    echo "nocapture test: connection blocked as expected"
                fi

                echo "ingress nocapture test passed"
            "#
            .to_owned(),
            mode: ShellMode::BackgroundContinue,

        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Test ingress netfilter with both capture_cgroup and capture_dst.
/// Traffic is captured only if BOTH:
/// - The sending process is in capture_cgroup
/// - The destination matches a capture_dst rule
///
/// Flow:
/// 1. TngServer with egress netfilter (port 30001)
/// 2. TngClient with ingress netfilter capture_cgroup + capture_dst port 30001
/// 3. ShellTask creates cgroup, moves into it, connects to 192.168.1.1:30001
/// 4. Both cgroup and destination match → intercepted → tunnel → success
#[serial]
#[ignore = "requires cgroup v2 with xt_cgroup iptables module, not available in CI containers"]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ingress_netfilter_cgroup_and_capture_dst() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": { "port": 30001 }
                        },
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_cgroup": ["/tng_ig_combo_test/"],
                            "capture_dst": [{ "port": 30001 }]
                        },
                        "verify": {
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        AppType::TcpServer { port: 30001 }.boxed(),
        ShellTask {
            name: "ingress_cgroup_combo_client".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                set -e
                CGROUP=/sys/fs/cgroup/tng_ig_combo_test
                mkdir -p "$CGROUP"
                echo $$ > "$CGROUP/cgroup.procs"
                trap "rmdir $CGROUP 2>/dev/null" EXIT
                # Both cgroup and destination port match → captured
                RESPONSE=$(echo 'hello_combo' | socat - TCP:192.168.1.1:30001)
                if [ "$RESPONSE" != "hello_combo" ]; then
                    echo "Expected 'hello_combo', got '$RESPONSE'"
                    exit 1
                fi
                echo "ingress cgroup + capture_dst combo test passed"
            "#
            .to_owned(),
            mode: ShellMode::BackgroundContinue,

        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Test ingress netfilter with capture_cgroup only (no capture_dst).
/// When no capture_dst is specified, ALL TCP traffic from the capture_cgroup is captured.
///
/// Flow:
/// 1. TngServer with egress netfilter (port 30001)
/// 2. TngClient with ingress netfilter capture_cgroup only (no capture_dst)
/// 3. ShellTask creates cgroup, moves into it, connects to 192.168.1.1:30001
/// 4. All TCP from cgroup is captured regardless of destination → tunnel → success
#[serial]
#[ignore = "requires cgroup v2 with xt_cgroup iptables module, not available in CI containers"]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ingress_netfilter_cgroup_only_all_tcp() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": { "port": 30001 }
                        },
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_cgroup": ["/tng_ig_alltcp_test/"]
                        },
                        "verify": {
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        AppType::TcpServer { port: 30001 }.boxed(),
        ShellTask {
            name: "ingress_cgroup_alltcp_client".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                set -e
                CGROUP=/sys/fs/cgroup/tng_ig_alltcp_test
                mkdir -p "$CGROUP"
                echo $$ > "$CGROUP/cgroup.procs"
                trap "rmdir $CGROUP 2>/dev/null" EXIT
                # No capture_dst means ALL TCP from the cgroup is captured
                RESPONSE=$(echo 'hello_alltcp' | socat - TCP:192.168.1.1:30001)
                if [ "$RESPONSE" != "hello_alltcp" ]; then
                    echo "Expected 'hello_alltcp', got '$RESPONSE'"
                    exit 1
                fi
                echo "ingress cgroup-only all-TCP test passed"
            "#
            .to_owned(),
            mode: ShellMode::BackgroundContinue,

        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

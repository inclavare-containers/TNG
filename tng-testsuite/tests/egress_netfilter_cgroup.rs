use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{
        app::AppType,
        shell::{ShellMode, ShellTask},
        tng::TngInstance,
        NodeType, Task as _,
    },
};

const TCP_PAYLOAD: &str = "Hello World TCP!";

/// Test egress netfilter with capture_cgroup.
/// Processes in the capture_cgroup have their traffic captured by TNG.
///
/// Flow:
/// 1. Create cgroup /tng_cg_cap_test/ on Server node
/// 2. Run TNG with capture_cgroup = ["/tng_cg_cap_test/"]
/// 3. ShellTask moves itself into the cgroup, connects to 192.168.1.1:30001
/// 4. Traffic is captured by TNG (cgroup match) and forwarded via tunnel to TcpServer
/// 5. TcpServer echoes, ShellTask verifies response matches
#[serial_test::serial]
#[ignore = "requires cgroup v2 with xt_cgroup iptables module, not available in CI containers"]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_netfilter_cgroup_capture() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_cgroup": ["/tng_cg_cap_test/"],
                            "capture_local_traffic": true
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
                        "mapping": {
                            "in": {
                                "port": 10001
                            },
                            "out": {
                                "host": "192.168.1.1",
                                "port": 30001
                            }
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
            name: "cgroup_capture_client".to_owned(),
            node_type: NodeType::Server,
            script: format!(
                r#"
                set -e
                CGROUP=/sys/fs/cgroup/tng_cg_cap_test
                mkdir -p "$CGROUP"
                echo $$ > "$CGROUP/cgroup.procs"
                trap "rmdir $CGROUP 2>/dev/null" EXIT
                # Connect from within the capture_cgroup
                # Traffic to 192.168.1.1:30001 is captured by TNG (cgroup + port match)
                # TNG forwards via tunnel to TcpServer on port 30001
                RESPONSE=$(echo '{TCP_PAYLOAD}' | socat - TCP:192.168.1.1:30001)
                if [ "$RESPONSE" != "{TCP_PAYLOAD}" ]; then
                    echo "Expected '{TCP_PAYLOAD}', got '$RESPONSE'"
                    exit 1
                fi
                echo "cgroup capture test passed"
            "#
            ),
            mode: ShellMode::FireAndForget,

        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Test egress netfilter with nocapture_cgroup.
/// Traffic from processes in nocapture_cgroup is NOT captured by TNG,
/// while traffic from other cgroups IS captured.
///
/// This test validates both behaviors in one test:
/// - Capture path: client in capture_cgroup → TNG tunnel → socat on 30002 (success)
/// - Nocapture path: client in nocapture_cgroup → direct connection to socat on 30001 (success)
#[serial_test::serial]
#[ignore = "requires cgroup v2 with xt_cgroup iptables module, not available in CI containers"]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_netfilter_cgroup_nocapture() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_cgroup": ["/tng_cg_nc_capture/"],
                            "nocapture_cgroup": ["/tng_cg_nc_bypass/"],
                            "capture_local_traffic": true
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
                        "mapping": {
                            "in": {
                                "port": 10002
                            },
                            "out": {
                                "host": "192.168.1.1",
                                "port": 30002
                            }
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
        AppType::TcpServer { port: 30002 }.boxed(),
        ShellTask {
            name: "cgroup_nocapture_test".to_owned(),
            node_type: NodeType::Server,
            script: r#"
                set -e
                CAPTURE_CG=/sys/fs/cgroup/tng_cg_nc_capture
                BYPASS_CG=/sys/fs/cgroup/tng_cg_nc_bypass
                mkdir -p "$CAPTURE_CG" "$BYPASS_CG"
                trap "rmdir $CAPTURE_CG $BYPASS_CG 2>/dev/null" EXIT

                # Start a direct TCP server on port 30001 (no TNG involvement)
                socat TCP-LISTEN:30001,fork,reuseaddr EXEC:"cat" &
                DIRECT_PID=$!

                # Test 1: Connect from nocapture_cgroup (direct connection should work)
                echo "test_nocapture" | (
                    echo $$ > "$BYPASS_CG/cgroup.procs"
                    socat - TCP:127.0.0.1:30001
                ) | grep -q "test_nocapture"
                echo "nocapture test passed"

                # Test 2: Connect from capture_cgroup (should go through TNG tunnel)
                echo "test_capture" | (
                    echo $$ > "$CAPTURE_CG/cgroup.procs"
                    socat - TCP:127.0.0.1:10002
                ) | grep -q "test_capture"
                echo "capture test passed"

                kill $DIRECT_PID 2>/dev/null
                sleep 30
            "#
            .to_owned(),
            mode: ShellMode::FireAndForget,

        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Test egress netfilter with both capture_cgroup and capture_dst.
/// Traffic is captured only if BOTH the process is in capture_cgroup
/// AND the destination matches a capture_dst rule.
///
/// Flow:
/// 1. Create cgroup /tng_cg_combo_test/
/// 2. Run TNG with capture_cgroup + capture_dst (port 30002)
/// 3. ShellTask moves into cgroup, connects to 192.168.1.1:30002
/// 4. TNG captures (cgroup + port match) → forwards to TcpServer → success
#[serial_test::serial]
#[ignore = "requires cgroup v2 with xt_cgroup iptables module, not available in CI containers"]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_netfilter_cgroup_and_capture_dst() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_cgroup": ["/tng_cg_combo_test/"],
                            "capture_dst": [{ "port": 30002 }],
                            "capture_local_traffic": true
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
                        "mapping": {
                            "in": {
                                "port": 10002
                            },
                            "out": {
                                "host": "192.168.1.1",
                                "port": 30002
                            }
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
        AppType::TcpServer { port: 30002 }.boxed(),
        ShellTask {
            name: "cgroup_combo_client".to_owned(),
            node_type: NodeType::Server,
            script: format!(
                r#"
                set -e
                CGROUP=/sys/fs/cgroup/tng_cg_combo_test
                mkdir -p "$CGROUP"
                echo $$ > "$CGROUP/cgroup.procs"
                trap "rmdir $CGROUP 2>/dev/null" EXIT
                RESPONSE=$(echo '{TCP_PAYLOAD}' | socat - TCP:192.168.1.1:30002)
                if [ "$RESPONSE" != "{TCP_PAYLOAD}" ]; then
                    echo "Expected '{TCP_PAYLOAD}', got '$RESPONSE'"
                    exit 1
                fi
                echo "cgroup + capture_dst combo test passed"
            "#
            ),
            mode: ShellMode::FireAndForget,

        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Test egress netfilter with capture_cgroup only (no capture_dst).
/// When no capture_dst is specified, ALL TCP traffic from the capture_cgroup is captured.
///
/// Flow:
/// 1. Create cgroup /tng_cg_alltcp_test/
/// 2. Run TNG with capture_cgroup only (no capture_dst)
/// 3. ShellTask moves into cgroup, connects to 192.168.1.1:30099 (non-standard port)
/// 4. TNG captures all TCP from cgroup → forwards to TcpServer → success
#[serial_test::serial]
#[ignore = "requires cgroup v2 with xt_cgroup iptables module, not available in CI containers"]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_netfilter_cgroup_only_all_tcp() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_cgroup": ["/tng_cg_alltcp_test/"],
                            "capture_local_traffic": true
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
                        "mapping": {
                            "in": {
                                "port": 10099
                            },
                            "out": {
                                "host": "192.168.1.1",
                                "port": 30099
                            }
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
        AppType::TcpServer { port: 30099 }.boxed(),
        ShellTask {
            name: "cgroup_alltcp_client".to_owned(),
            node_type: NodeType::Server,
            script: format!(
                r#"
                set -e
                CGROUP=/sys/fs/cgroup/tng_cg_alltcp_test
                mkdir -p "$CGROUP"
                echo $$ > "$CGROUP/cgroup.procs"
                trap "rmdir $CGROUP 2>/dev/null" EXIT
                # Connect to a non-standard port — since no capture_dst is set, ALL TCP is captured
                RESPONSE=$(echo '{TCP_PAYLOAD}' | socat - TCP:192.168.1.1:30099)
                if [ "$RESPONSE" != "{TCP_PAYLOAD}" ]; then
                    echo "Expected '{TCP_PAYLOAD}', got '$RESPONSE'"
                    exit 1
                fi
                echo "cgroup-only all-TCP test passed"
            "#
            ),
            mode: ShellMode::FireAndForget,

        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

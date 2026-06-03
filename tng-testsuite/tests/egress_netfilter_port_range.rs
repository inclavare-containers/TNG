use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Test egress netfilter with port range (port_end) capture_dst.
///
/// Configures egress to capture port range 30000-30031.
/// Validates that TcpClient connecting to a port within the range (30015)
/// is successfully captured and forwarded through the TNG tunnel.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_netfilter_port_range() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": [
                                {
                                    "port": 30000,
                                    "port_end": 30031
                                }
                            ],
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
                                "port": 10015
                            },
                            "out": {
                                "host": "192.168.1.1",
                                "port": 30015
                            }
                        },
                        "verify": {
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": [
                                "default"
                            ]
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        AppType::TcpServer { port: 30015 }.boxed(),
        AppType::TcpClient {
            host: "127.0.0.1",
            port: 10015,
            http_proxy: None,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

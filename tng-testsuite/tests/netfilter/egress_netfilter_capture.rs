use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Test egress netfilter with the new array-based capture_dst format.
/// This validates backward compatibility of OneOrMany serialization.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_netfilter_array_format() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": [
                                { "port": 30001 }
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
        ).boxed(),
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
                            "policy_ids": [
                                "default"
                            ]
                        }
                    }
                ]
            }
            "#,
        ).boxed(),
        AppType::TcpServer { port: 30001 }.boxed(),
        AppType::TcpClient {
            host: "127.0.0.1",
            port: 10001,
            http_proxy: None,
        }.boxed(),
    ])
    .await?;

    Ok(())
}

/// Test egress netfilter with multiple capture_dst entries (port + host+port).
/// This validates that multiple capture rules work correctly together.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_netfilter_multiple_entries() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": [
                                { "port": 30001 },
                                { "host": "192.168.1.1", "port": 30002 }
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
        ).boxed(),
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
                            "policy_ids": [
                                "default"
                            ]
                        }
                    }
                ]
            }
            "#,
        ).boxed(),
        AppType::TcpServer { port: 30001 }.boxed(),
        AppType::TcpClient {
            host: "127.0.0.1",
            port: 10001,
            http_proxy: None,
        }.boxed(),
    ])
    .await?;

    Ok(())
}

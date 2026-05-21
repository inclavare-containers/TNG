use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, shell::ShellTask, tng::TngInstance, NodeType, Task as _},
};

const TNG_SERVER_INSTANCE: TngInstance = TngInstance::TngServer(
    r#"
    {
        "add_egress": [
            {
                "netfilter": {
                    "capture_dst": {
                        "port": 30001
                    }
                },
                "attest": {
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        ]
    }
    "#,
);

/// Ingress netfilter with port-only capture_dst.
/// Client connects to server:30001, ingress netfilter intercepts and forwards via TNG tunnel.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_port_only() -> Result<()> {
    run_test(vec![
        TNG_SERVER_INSTANCE.clone().boxed(),
        TngInstance::TngClient(
            r#"
                {
                    "add_ingress": [
                        {
                            "netfilter": {
                                "capture_dst": [
                                    {
                                        "port": 30001
                                    }
                                ],
                                "listen_port": 50000
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
        AppType::TcpServer { port: 30001 }.boxed(),
        AppType::TcpClient {
            host: "192.168.1.1",
            port: 30001,
            http_proxy: None,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Ingress netfilter with host CIDR + port capture_dst.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_host_and_port() -> Result<()> {
    run_test(vec![
        TNG_SERVER_INSTANCE.clone().boxed(),
        TngInstance::TngClient(
            r#"
                {
                    "add_ingress": [
                        {
                            "netfilter": {
                                "capture_dst": [
                                    {
                                        "host": "192.168.1.0/24",
                                        "port": 30001
                                    }
                                ],
                                "listen_port": 50000
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
        AppType::TcpServer { port: 30001 }.boxed(),
        AppType::TcpClient {
            host: "192.168.1.1",
            port: 30001,
            http_proxy: None,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Ingress netfilter with port range capture_dst.
/// Tests the port_end feature — captures all ports in [30000, 30031].
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_port_range() -> Result<()> {
    // Server egress must also capture the target port for the tunnel to work.
    // We use a wide port range on both sides to validate port_end.
    run_test(vec![
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
                            ]
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
                                "capture_dst": [
                                    {
                                        "port": 30000,
                                        "port_end": 30031
                                    }
                                ],
                                "listen_port": 50000
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
            host: "192.168.1.1",
            port: 30015,
            http_proxy: None,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Ingress netfilter with ipset + port capture_dst.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ipset_and_port() -> Result<()> {
    run_test(vec![
        ShellTask {
            name: "prepare_ipset".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                    ipset create myset hash:ip
                    ipset add myset 192.168.1.1
                    ipset list myset
                "#
            .to_owned(),
            stop_test_on_finish: false,
            run_in_foreground: false,
        }
        .boxed(),
        TNG_SERVER_INSTANCE.clone().boxed(),
        TngInstance::TngClient(
            r#"
                {
                    "add_ingress": [
                        {
                            "netfilter": {
                                "capture_dst": [
                                    {
                                        "ipset": "myset",
                                        "port": 30001
                                    }
                                ],
                                "listen_port": 50000
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
        AppType::TcpServer { port: 30001 }.boxed(),
        AppType::TcpClient {
            host: "192.168.1.1",
            port: 30001,
            http_proxy: None,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

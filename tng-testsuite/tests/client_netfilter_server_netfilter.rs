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

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_port_only() -> Result<()> {
    // Port only
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

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_host_and_port() -> Result<()> {
    // Host and Port
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

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_host_and_port_bad_case() -> Result<()> {
    // Host and Port (Bad case)
    assert!(run_test(vec![
        TNG_SERVER_INSTANCE.clone().boxed(),
        TngInstance::TngClient(
            r#"
                {
                    "add_ingress": [
                        {
                            "netfilter": {
                                "capture_dst": [
                                    {
                                        "host": "192.168.2.0/24",
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
                "#
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
    .await
    .is_err());

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_host_cidr_only() -> Result<()> {
    // Host(CIDR) only
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
                                                "host": "192.168.1.0/25"
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

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_host_cidr_only_bad_case() -> Result<()> {
    // Host(CIDR) only (Bad case)
    assert!(run_test(vec![
        TNG_SERVER_INSTANCE.clone().boxed(),
        TngInstance::TngClient(
            r#"
                    {
                        "add_ingress": [
                            {
                                "netfilter": {
                                    "capture_dst": [
                                        {
                                            "host": "192.168.2.0/24"
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
                    "#
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
    .await
    .is_err());

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ipset_and_port() -> Result<()> {
    // IpSet and Port
    run_test(vec![
        // Prepare ipset in client node
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

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ipset_and_port_bad_case() -> Result<()> {
    // IpSet and Port (Bad case)
    assert!(run_test(vec![
        ShellTask {
            name: "prepare_ipset".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                    ipset create myset hash:ip
                    ipset add myset 8.8.8.8
                    ipset list myset
                "#
            .to_owned(),
            stop_test_on_finish: false,
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
                "#
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
    .await
    .is_err());

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ipset_only() -> Result<()> {
    // IpSet only
    run_test(vec![
        // Prepare ipset in client node
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
                                        "ipset": "myset"
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

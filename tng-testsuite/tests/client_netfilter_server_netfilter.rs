use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{app::AppType, shell::ShellTask, tng::TngInstance, NodeType, Task as _},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    let tng_server = TngInstance::TngServer(
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

    // Port only
    run_test(vec![
        tng_server.clone().boxed(),
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

    // Host and Port
    run_test(vec![
        tng_server.clone().boxed(),
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

    // Host and Port (Bad case)
    assert!(run_test(vec![
        tng_server.clone().boxed(),
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

    // Host(CIDR) only
    run_test(vec![
        tng_server.clone().boxed(),
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

    // Host(CIDR) only (Bad case)
    assert!(run_test(vec![
        tng_server.clone().boxed(),
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

    // IpSet and Port
    run_test(vec![
        // Prepare ipset in client node
        ShellTask {
            name: "bad_client".to_owned(),
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
        tng_server.clone().boxed(),
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

    // IpSet and Port (Bad case)
    assert!(run_test(vec![
        ShellTask {
            name: "bad_client".to_owned(),
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
        tng_server.clone().boxed(),
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

    // IpSet only
    run_test(vec![
        // Prepare ipset in client node
        ShellTask {
            name: "bad_client".to_owned(),
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
        tng_server.clone().boxed(),
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

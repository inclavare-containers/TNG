use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Test mapping ingress/egress with multiple rules.
///
/// Configures two separate rules within one mapping entry on both client and server:
///   client ingress rule 1: in 10001 → out to server 20001
///   client ingress rule 2: in 10002 → out to server 20002
///   server egress rule 1:  in 20001 → out to app 30001
///   server egress rule 2:  in 20002 → out to app 30002
///
/// Validates that both rules work independently by sending TCP connections
/// to each ingress port and verifying they reach the correct backend.
/// Both client and server use no_ra mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_mapping_multi_rule() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "mapping": {
                            "rules": [
                                {
                                    "in": {
                                        "host": "0.0.0.0",
                                        "port": 20001
                                    },
                                    "out": {
                                        "host": "127.0.0.1",
                                        "port": 30001
                                    }
                                },
                                {
                                    "in": {
                                        "host": "0.0.0.0",
                                        "port": 20002
                                    },
                                    "out": {
                                        "host": "127.0.0.1",
                                        "port": 30002
                                    }
                                }
                            ]
                        },
                        "no_ra": true
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
                            "rules": [
                                {
                                    "in": {
                                        "host": "0.0.0.0",
                                        "port": 10001
                                    },
                                    "out": {
                                        "host": "192.168.1.1",
                                        "port": 20001
                                    }
                                },
                                {
                                    "in": {
                                        "host": "0.0.0.0",
                                        "port": 10002
                                    },
                                    "out": {
                                        "host": "192.168.1.1",
                                        "port": 20002
                                    }
                                }
                            ]
                        },
                        "no_ra": true
                    }
                ]
            }
            "#,
        )
        .boxed(),
        AppType::TcpServer { port: 30001 }.boxed(),
        AppType::TcpServer { port: 30002 }.boxed(),
        AppType::TcpClient {
            host: "127.0.0.1",
            port: 10001,
            http_proxy: None,
        }
        .boxed(),
        AppType::TcpClient {
            host: "127.0.0.1",
            port: 10002,
            http_proxy: None,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

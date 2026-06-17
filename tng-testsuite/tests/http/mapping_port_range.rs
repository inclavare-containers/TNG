use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Test mapping ingress/egress with port range (port_end).
///
/// Configures a port range mapping:
///   client ingress: in 10010-10015 → out to server 20010-20015
///   server egress:  in 20010-20015 → out to app 30010-30015
/// A TcpClient connects to port 10012, which should be forwarded to server
/// port 20012, then to app port 30012 (offset = 2).
/// Both client and server use no_ra mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_mapping_port_range() -> Result<()> {
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
                                        "port": 20010,
                                        "port_end": 20015
                                    },
                                    "out": {
                                        "host": "127.0.0.1",
                                        "port": 30010,
                                        "port_end": 30015
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
                                        "port": 10010,
                                        "port_end": 10015
                                    },
                                    "out": {
                                        "host": "192.168.1.1",
                                        "port": 20010,
                                        "port_end": 20015
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
        AppType::TcpServer { port: 30012 }.boxed(),
        AppType::TcpClient {
            host: "127.0.0.1",
            port: 10012,
            http_proxy: None,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

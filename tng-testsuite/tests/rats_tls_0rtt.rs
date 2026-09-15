use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Non-multiplex rats-tls tunnel with no RA. The TcpClient harness opens 5
/// sequential connections through the tunnel; connection 1 establishes a full
/// handshake and obtains a resumption ticket, connections 2-5 resume and send
/// their payload as 0-RTT early data. The server must drain and deliver that
/// early data, so every echo must match. A lossy or hanging 0-RTT path fails
/// an echo check on repeat 2+.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_rats_tls_0rtt_repeated_connections() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "mapping": {
                        "in": {
                            "host": "0.0.0.0",
                            "port": 20001
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30001
                        }
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
                        "in": {
                            "port": 10001
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 20001
                        }
                    },
                    "no_ra": true
                }
            ]
        }
        "#,
        )
        .boxed(),
        AppType::TcpServer { port: 30001 }.boxed(),
        AppType::TcpClient {
            host: "127.0.0.1",
            port: 10001,
            http_proxy: None,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

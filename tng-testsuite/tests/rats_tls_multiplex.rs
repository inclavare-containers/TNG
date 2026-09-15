use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Multiplex rats-tls (HTTP/2 CONNECT over one long-lived TLS connection) with
/// no RA. The TcpClient harness opens 5 downstream connections, all multiplexed
/// over the single upstream TLS session. This covers the multiplex att-flow
/// path (AttestationState carried through the hyper connection extension) which
/// the non-multiplex 0-RTT tests do not exercise.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
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
                    "no_ra": true,
                    "rats_tls": { "multiplex": true }
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
                    "no_ra": true,
                    "rats_tls": { "multiplex": true }
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

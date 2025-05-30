use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// both tng client and tng server are in non-tee env
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test(vec![
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

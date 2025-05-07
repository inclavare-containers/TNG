mod common;

use anyhow::Result;
use common::{
    run_test,
    task::{
        app::{AppType, HttpProxy},
        tng::TngInstance,
        Task as _,
    },
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
                                "port": 10001
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
                        "http_proxy": {
                            "proxy_listen": {
                                "host": "0.0.0.0",
                                "port": 41000
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
            host: "192.168.1.1",
            port: 10001,
            http_proxy: Some(HttpProxy {
                host: "127.0.0.1",
                port: 41000,
            }),
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

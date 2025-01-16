mod common;

use anyhow::Result;
use common::{
    run_test,
    task::app::{AppType, HttpProxy},
};

/// both tng client and tng server are in non-tee env
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test(
        &AppType::TcpServer { port: 30001 },
        &AppType::TcpClient {
            host: "127.0.0.1",
            port: 10001,
            http_proxy: Some(HttpProxy {
                host: "127.0.0.1",
                port: 41000,
            }),
        },
        r#"
        {
            "add_egress": [
                {
                    "mapping": {
                        "in": {
                            "host": "127.0.0.1",
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
    .await?;

    Ok(())
}

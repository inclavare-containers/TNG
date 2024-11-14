mod common;

use anyhow::Result;
use common::{run_test, task::app::AppType};

/// tng client as attester and tng server as verifier
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test(
        &AppType::TcpServer { port: 30001 },
        &AppType::TcpClient {
            host: "127.0.0.1",
            port: 10001,
            http_proxy: None,
        },
        r#"
        {
            "add_egress": [
                {
                    "mapping": {
                        "in": {
                            "host": "127.0.0.1",
                            "port": 20001
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30001
                        }
                    },
                    "verify": {
                        "as_addr": "http://127.0.0.1:8080/",
                        "policy_ids": [
                            "default"
                        ]
                    }
                }
            ]
        }
        "#,
        r#"
        {
            "add_ingress": [
                {
                    "mapping": {
                        "in": {
                            "port": 10001
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 20001
                        }
                    },
                    "attest": {
                        "aa_addr": "unix:///tmp/attestation.sock"
                    }
                }
            ]
        }
        "#,
    )
    .await?;

    Ok(())
}

use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{
        app::{AppType, HttpProxy},
        tng::TngInstance,
        Task as _,
    },
};

#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test(
        vec![
            TngInstance::TngServer (
                r#"
                {
                    "add_egress": [
                        {
                            "netfilter": {
                                "capture_dst": {
                                    "port": 30001
                                },
                                "capture_local_traffic": true
                            },
                            "attest": {
                                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                            }
                        }
                    ]
                }
                "#
            ).boxed(),
            TngInstance::TngServer (
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
            ).boxed(),
            AppType::TcpServer { port: 30001 }.boxed() ,
            AppType::TcpClient {
                host: "192.168.1.1",
                port: 30001,
                http_proxy: Some(HttpProxy {
                    host: "192.168.1.1",
                    port: 41000,
                }),
            }.boxed(),
        ]
    )
    .await?;

    Ok(())
}

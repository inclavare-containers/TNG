use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{
        app::{AppType, HttpProxy},
        tng::TngInstance,
        Task as _,
    },
};

/// Test http_proxy ingress with port_end in dst_filters.
///
/// Configures http_proxy to match destination ports in the range [30000, 30063].
/// A TcpClient connects via the http_proxy to a port within the range (30015),
/// validating that port range matching works correctly through the TNG tunnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_http_proxy_port_end() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": [
                                {
                                    "port": 30000,
                                    "port_end": 30063
                                }
                            ]
                        },
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
            "#
        ).boxed(),
        TngInstance::TngClient(r#"
            {
                "add_ingress": [
                    {
                        "http_proxy": {
                            "proxy_listen": {
                                "host": "0.0.0.0",
                                "port": 41000
                            },
                            "dst_filters": [
                                {
                                    "domain": "*",
                                    "port": 30000,
                                    "port_end": 30063
                                }
                            ]
                        },
                        "no_ra": true
                    }
                ]
            }
            "#
        ).boxed(),
        AppType::TcpServer { port: 30015 }.boxed(),
        AppType::TcpClient {
            host: "192.168.1.1",
            port: 30015,
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

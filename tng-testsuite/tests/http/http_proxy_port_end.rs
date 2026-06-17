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
/// An HttpClient sends a request to port 30015 (within the range) via the http_proxy,
/// validating that port range matching works correctly through the TNG tunnel.
/// Both client and server use no_ra mode to avoid external service dependencies.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_http_proxy_port_end() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
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
                        "no_ra": true
                    }
                ]
            }
            "#
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
        )
        .boxed(),
        AppType::HttpServer {
            port: 30015,
            expected_host_header: "192.168.1.1:30015",
            expected_path_and_query: "/test",
        }
        .boxed(),
        AppType::HttpClientWithReverseProxy {
            host_header: "192.168.1.1:30015",
            path_and_query: "/test",
            http_proxy: HttpProxy {
                host: "127.0.0.1",
                port: 41000,
            },
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

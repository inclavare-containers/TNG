use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Test mapping ingress/egress with port range (port_end).
///
/// Configures a port range mapping: in ports 10010-10020 → out ports 20010-20020.
/// An HttpClient sends a request to port 10015 (within the range), validating
/// that port range mapping with correct offset calculation works end-to-end.
/// Both client and server use no_ra mode to avoid external service dependencies.
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
                                        "port_end": 20020
                                    },
                                    "out": {
                                        "host": "127.0.0.1",
                                        "port": 30010,
                                        "port_end": 30020
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
                                        "port_end": 10020
                                    },
                                    "out": {
                                        "host": "192.168.1.252",
                                        "port": 20010,
                                        "port_end": 20020
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
        AppType::LoadBalancer {
            listen_port: 20015,
            upstream_servers: vec![("192.168.1.1".into(), 20015)],
            path_matcher: r"^/(.*)$",
            rewrite_to: r"/$1",
        }
        .boxed(),
        AppType::HttpServer {
            port: 30015,
            expected_host_header: "example.com",
            expected_path_and_query: "/test",
        }
        .boxed(),
        AppType::HttpClient {
            host: "127.0.0.1",
            port: 10015,
            host_header: "example.com",
            path_and_query: "/test",
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Test mapping ingress/egress with multiple rules.
///
/// Configures two separate rules within one mapping entry:
/// - Rule 1: in port 10001 → out port 20001
/// - Rule 2: in port 10002 → out port 20002
/// Validates that both rules work independently by sending HTTP requests
/// to each ingress port and verifying they reach the correct backend.
/// Both client and server use no_ra mode to avoid external service dependencies.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_mapping_multi_rule() -> Result<()> {
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
                                        "port": 20001
                                    },
                                    "out": {
                                        "host": "127.0.0.1",
                                        "port": 30001
                                    }
                                },
                                {
                                    "in": {
                                        "host": "0.0.0.0",
                                        "port": 20002
                                    },
                                    "out": {
                                        "host": "127.0.0.1",
                                        "port": 30002
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
                                        "port": 10001
                                    },
                                    "out": {
                                        "host": "192.168.1.252",
                                        "port": 20001
                                    }
                                },
                                {
                                    "in": {
                                        "host": "0.0.0.0",
                                        "port": 10002
                                    },
                                    "out": {
                                        "host": "192.168.1.252",
                                        "port": 20002
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
            listen_port: 20001,
            upstream_servers: vec![("192.168.1.1".into(), 20001)],
            path_matcher: r"^/(.*)$",
            rewrite_to: r"/$1",
        }
        .boxed(),
        AppType::LoadBalancer {
            listen_port: 20002,
            upstream_servers: vec![("192.168.1.1".into(), 20002)],
            path_matcher: r"^/(.*)$",
            rewrite_to: r"/$1",
        }
        .boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/rule1",
        }
        .boxed(),
        AppType::HttpServer {
            port: 30002,
            expected_host_header: "example.com",
            expected_path_and_query: "/rule2",
        }
        .boxed(),
        AppType::HttpClient {
            host: "127.0.0.1",
            port: 10001,
            host_header: "example.com",
            path_and_query: "/rule1",
        }
        .boxed(),
        AppType::HttpClient {
            host: "127.0.0.1",
            port: 10002,
            host_header: "example.com",
            path_and_query: "/rule2",
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

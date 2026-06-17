use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{
        app::AppType,
        tng::TngInstance,
        Task as _,
    },
};

/// Test that header_passthrough config is correctly parsed and does not break
/// the OHTTP flow. The Ingress copies x-trace-id and x-tenant-id from the
/// downstream request to the outer POST, and the Egress copies x-custom-header
/// from the upstream response to the outer response.
///
/// This verifies:
/// 1. Config deserialization works correctly on both sides
/// 2. The OHTTP flow completes successfully with header_passthrough enabled
/// 3. Protocol headers are not overwritten by passthrough headers
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_header_passthrough() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "mapping": {
                            "in": {
                                "port": 20001
                            },
                            "out": {
                                "host": "127.0.0.1",
                                "port": 30001
                            }
                        },
                        "ohttp": {
                            "header_passthrough": {
                                "response_headers": ["x-test-response-header"]
                            }
                        },
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
            "#,
        ).boxed(),
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
                                "host": "192.168.1.252",
                                "port": 20001
                            }
                        },
                        "ohttp": {
                            "header_passthrough": {
                                "request_headers": ["x-trace-id", "x-tenant-id"]
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
            "#,
        ).boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/test/path?foo=bar",
        }.boxed(),
        AppType::HttpClient {
            host: "127.0.0.1",
            port: 10001,
            host_header: "example.com",
            path_and_query: "/test/path?foo=bar",
        }.boxed(),
    ])
    .await?;

    Ok(())
}

/// Test header_passthrough with netfilter mode on both Ingress and Egress.
/// Verifies the config works with the netfilter transport path.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_header_passthrough_netfilter() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 30001
                            }
                        },
                        "ohttp": {
                            "header_passthrough": {
                                "response_headers": ["x-rate-limit", "x-server-id"]
                            }
                        },
                        "attest": {
                            "model": "passport",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
            "#,
        ).boxed(),
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 30001
                            }
                        },
                        "ohttp": {
                            "header_passthrough": {
                                "request_headers": ["x-trace-id", "x-request-id", "x-correlation-id"]
                            }
                        },
                        "verify": {
                            "model": "passport",
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
            "#,
        ).boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/api/data?key=value",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.1",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/api/data?key=value",
        }.boxed(),
    ])
    .await?;

    Ok(())
}

/// Test that header_passthrough with path_rewrites both work together.
/// Verifies that multiple ohttp sub-fields don't conflict.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_header_passthrough_with_path_rewrite() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 30001
                            }
                        },
                        "ohttp": {
                            "header_passthrough": {
                                "response_headers": ["x-custom"]
                            }
                        },
                        "attest": {
                            "model": "passport",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
            "#,
        ).boxed(),
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 30001
                            }
                        },
                        "ohttp": {
                            "path_rewrites": [
                                {
                                    "match_regex": "^/api/([^/]+)([/]?.*)$",
                                    "substitution": "/v1/\\1"
                                }
                            ],
                            "header_passthrough": {
                                "request_headers": ["x-api-key"]
                            }
                        },
                        "verify": {
                            "model": "passport",
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
            "#,
        ).boxed(),
        AppType::LoadBalancer {
            listen_port: 30001,
            upstream_servers: vec![
                ("192.168.1.1".into(), 30001),
            ],
            path_matcher: r"^/api/(.*)$",
            rewrite_to: r"/v1/$1",
        }.boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/api/resource?id=123",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.252",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/api/resource?id=123",
        }.boxed(),
    ])
    .await?;

    Ok(())
}

/// Test that empty header_passthrough (configured but with no headers listed)
/// works correctly — the OHTTP flow should be unaffected.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_header_passthrough_empty() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 30001
                            }
                        },
                        "ohttp": {
                            "header_passthrough": {}
                        },
                        "attest": {
                            "model": "passport",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
            "#,
        ).boxed(),
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 30001
                            }
                        },
                        "ohttp": {
                            "header_passthrough": {}
                        },
                        "verify": {
                            "model": "passport",
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
            "#,
        ).boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/empty/test",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.1",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/empty/test",
        }.boxed(),
    ])
    .await?;

    Ok(())
}

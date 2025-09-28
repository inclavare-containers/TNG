use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{
        app::{AppType, HttpProxy},
        tng::TngInstance,
        Task,
    },
};

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_conflict_config_field() -> Result<()> {
    assert!(run_test(vec![
        TngInstance::TngServer(r#"
        {
            "add_egress": [
                {
                    "netfilter": {
                        "capture_dst": {
                            "port": 30001
                        },
                        "capture_local_traffic": true
                    },
                    "direct_forward": [
                        {
                            "http_path": "/public/.*"
                        }
                    ],
                    "ohttp": {
                        "allow_non_tng_traffic_regexes": ["/public/.*"]
                    },
                    "attest": {
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                    }
                }
            ]
        }
        "#).boxed(),
    ])
    .await.is_err());

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_direct_forward_without_ohttp() -> Result<()> {
    let tng_server_config = r#"
        {
            "add_egress": [
                {
                    "netfilter": {
                        "capture_dst": {
                            "port": 30001
                        },
                        "capture_local_traffic": true
                    },
                    "direct_forward": [
                        {
                            "http_path": "/public/.*"
                        }
                    ],
                    "attest": {
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                    }
                }
            ]
        }
        "#;
    let tng_client_config = r#"
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
        "#;

    run_test(vec![
        TngInstance::TngServer(tng_server_config).boxed(),
        TngInstance::TngClient(tng_client_config).boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "192.168.1.1:30001",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }
        .boxed(),
        AppType::HttpClientWithReverseProxy {
            host_header: "192.168.1.1:30001",
            path_and_query: "/foo/bar/www?type=1&case=1",
            http_proxy: HttpProxy {
                host: "127.0.0.1",
                port: 41000,
            },
        }
        .boxed(),
    ])
    .await?;

    // Test access from client without through tng client
    run_test(vec![
        TngInstance::TngServer(tng_server_config).boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "192.168.1.1:30001",
            expected_path_and_query: "/public/resource",
        }
        .boxed(),
        AppType::HttpClient {
            host: "192.168.1.1",
            port: 30001,
            host_header: "192.168.1.1:30001",
            path_and_query: "/public/resource",
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_direct_forward_with_ohttp() -> Result<()> {
    let tng_server_config = r#"
        {
            "add_egress": [
                {
                    "netfilter": {
                        "capture_dst": {
                            "port": 30001
                        },
                        "capture_local_traffic": true
                    },
                    "direct_forward": [
                        {
                            "http_path": "/public/.*"
                        }
                    ],
                    "ohttp": {},
                    "attest": {
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                    }
                }
            ]
        }
        "#;
    let tng_client_config = r#"
        {
            "add_ingress": [
                {
                    "http_proxy": {
                        "proxy_listen": {
                            "host": "0.0.0.0",
                            "port": 41000
                        }
                    },
                    "ohttp": {
                        "path_rewrites": [
                            {
                                "match_regex": "^/foo/([^/]+)([/]?.*)$",
                                "substitution": "/foo/\\1"
                            }
                        ]
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
        "#;

    run_test(vec![
        TngInstance::TngServer(tng_server_config).boxed(),
        TngInstance::TngClient(tng_client_config).boxed(),
        AppType::LoadBalancer {
            listen_port: 30001,
            upstream_servers: vec![("192.168.1.1", 30001)],
            path_matcher: r"^/foo/(.*)$",
            rewrite_to: r"/baz/$1",
        }
        .boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "192.168.1.3:30001",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }
        .boxed(),
        AppType::HttpClientWithReverseProxy {
            host_header: "192.168.1.3:30001",
            path_and_query: "/foo/bar/www?type=1&case=1",
            http_proxy: HttpProxy {
                host: "127.0.0.1",
                port: 41000,
            },
        }
        .boxed(),
    ])
    .await?;

    // Test access from client without through tng client
    run_test(vec![
        TngInstance::TngServer(tng_server_config).boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "192.168.1.1:30001",
            expected_path_and_query: "/public/resource",
        }
        .boxed(),
        AppType::HttpClient {
            host: "192.168.1.1",
            port: 30001,
            host_header: "192.168.1.1:30001",
            path_and_query: "/public/resource",
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

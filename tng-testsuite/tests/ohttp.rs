use anyhow::{Context, Result};
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, shell::ShellTask, tng::TngInstance, NodeType, Task as _},
};

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ingress_mapping() -> Result<()> {
    run_test(vec![
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
                        "ohttp": {},
                        "attest": {
                            "model": "passport",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
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
                                "port": 30001
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
                            "model": "passport",
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
        AppType::LoadBalancer {
            listen_port: 30001,
            upstream_servers: vec![
                ("192.168.1.1".into(), 30001),
            ],
            path_matcher: r"^/foo/(.*)$",
            rewrite_to: r"/baz/$1",
        }.boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
        AppType::HttpClient {
            host: "127.0.0.1",
            port: 10001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
    ])
    .await?;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ingress_netfilter() -> Result<()> {
    run_test(vec![
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
                        "ohttp": {},
                        "attest": {
                            "model": "passport",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
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
                        "ohttp": {},
                        "verify": {
                            "model": "passport",
                            "policy_ids": [
                                "default"
                            ],
                            "as_addr": "http://192.168.1.254:8080/"
                        }
                    }
                ]
            }
            "#,
        ).boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.1",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
    ])
    .await?;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ingress_netfilter_server_attest_client_no_ra() -> Result<()> {
    run_test(vec![
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
                        "ohttp": {},
                        "attest": {
                            "model": "background_check",
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
                        "netfilter": {
                            "capture_dst": {
                                "port": 30001
                            }
                        },
                        "ohttp": {},
                        "no_ra": true
                    }
                ]
            }
            "#,
        ).boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.1",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
    ])
    .await?;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ingress_netfilter_with_load_balancer() -> Result<()> {
    run_test(vec![
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
                        "ohttp": {},
                        "attest": {
                            "model": "passport",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
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
                                    "match_regex": "^/foo/([^/]+)([/]?.*)$",
                                    "substitution": "/foo/\\1"
                                }
                            ]
                        },
                        "verify": {
                            "model": "passport",
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
        AppType::LoadBalancer {
            listen_port: 30001,
            upstream_servers: vec![
                ("192.168.1.1".into(), 30001),
            ],
            path_matcher: r"^/foo/(.*)$",
            rewrite_to: r"/baz/$1",
        }.boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.252",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
    ])
    .await?;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ra_model_matrix_server_attest_with_passport() -> Result<()> {
    run_test(vec![
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
                        "ohttp": {},
                        "attest": {
                            "model": "passport",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
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
                                    "match_regex": "^/foo/([^/]+)([/]?.*)$",
                                    "substitution": "/foo/\\1"
                                }
                            ]
                        },
                        "verify": {
                            "model": "passport",
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
        AppType::LoadBalancer {
            listen_port: 30001,
            upstream_servers: vec![
                ("192.168.1.1".into(), 30001),
            ],
            path_matcher: r"^/foo/(.*)$",
            rewrite_to: r"/baz/$1",
        }.boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.252",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
    ])
    .await?;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ra_model_matrix_server_attest_with_background_check() -> Result<()> {
    run_test(vec![
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
                        "ohttp": {},
                        "attest": {
                            "model": "background_check",
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
                        "netfilter": {
                            "capture_dst": {
                                "port": 30001
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
                            "model": "background_check",
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
        AppType::LoadBalancer {
            listen_port: 30001,
            upstream_servers: vec![
                ("192.168.1.1".into(), 30001),
            ],
            path_matcher: r"^/foo/(.*)$",
            rewrite_to: r"/baz/$1",
        }.boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.252",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
    ])
    .await?;
    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ra_model_matrix_client_attest_with_passport() -> Result<()> {
    run_test(vec![
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
                        "ohttp": {},
                        "verify": {
                            "model": "passport",
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
                                    "match_regex": "^/foo/([^/]+)([/]?.*)$",
                                    "substitution": "/foo/\\1"
                                }
                            ]
                        },
                        "attest": {
                            "model": "passport",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
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
        AppType::LoadBalancer {
            listen_port: 30001,
            upstream_servers: vec![
                ("192.168.1.1".into(), 30001),
            ],
            path_matcher: r"^/foo/(.*)$",
            rewrite_to: r"/baz/$1",
        }.boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.252",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
    ])
    .await?;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ra_model_matrix_client_attest_with_background_check() -> Result<()> {
    run_test(vec![
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
                        "ohttp": {},
                        "verify": {
                            "model": "background_check",
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
                                    "match_regex": "^/foo/([^/]+)([/]?.*)$",
                                    "substitution": "/foo/\\1"
                                }
                            ]
                        },
                        "attest": {
                            "model": "background_check",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
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
            path_matcher: r"^/foo/(.*)$",
            rewrite_to: r"/baz/$1",
        }.boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.252",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
    ])
    .await?;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_server_attest_passport_cache() -> Result<()> {
    run_test(vec![
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
                        "ohttp": {},
                        "attest": {
                            "model": "passport",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": [
                                "default"
                            ],
                            "refresh_interval": 3
                        }
                    }
                ]
            }
            "#,
        ).boxed(),
        ShellTask {
            name: "check_server_keyconfig_cached".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                # Reusable curl command
                call_api() {
                    curl -s -X POST http://192.168.1.1:30001 \
                        -H "x-tng-ohttp-api: /tng/key-config" \
                        -H "Content-Type: application/json" \
                        -H "Accept: */*" \
                        -H "User-Agent: tng/2.2.6" \
                        -d '{"attestation_request":{"model":"passport"}}'
                }

                echo "Request 1..."
                r1=$(call_api) || { echo "Error: Request 1 failed"; exit 1; }

                echo "Request 2..."
                r2=$(call_api) || { echo "Error: Request 2 failed"; exit 1; }

                [ "$r1" = "$r2" ] && echo "PASS: First two responses match" || { echo "FAIL: First two differ"; exit 1; }

                echo "Waiting 5s..."
                sleep 5

                echo "Request 3..."
                r3=$(call_api) || { echo "Error: Request 3 failed"; exit 1; }

                [ "$r3" != "$r1" ] && echo "PASS: Third response differs" || { echo "FAIL: Third response is same"; exit 1; }

                echo "SUCCESS: All tests passed"
            "#
            .to_owned(),
            stop_test_on_finish: true,
            run_in_foreground: false,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_server_attest_passport_rotation_interval() -> Result<()> {
    run_test(vec![
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
                            "key": {
                                "source": "self_generated",
                                "rotation_interval": 3
                            }
                        },
                        "attest": {
                            "model": "passport",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
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
        ShellTask {
            name: "check_key_rotation".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                # Reusable curl command
                call_api() {
                    curl -s -X POST http://192.168.1.1:30001 \
                        -H "x-tng-ohttp-api: /tng/key-config" \
                        -H "Content-Type: application/json" \
                        -H "Accept: */*" \
                        -H "User-Agent: tng/2.2.6" \
                        -d '{"attestation_request":{"model":"passport"}}'
                }

                echo "Request 1..."
                r1=$(call_api) || { echo "Error: Request 1 failed"; exit 1; }

                echo "Request 2..."
                r2=$(call_api) || { echo "Error: Request 2 failed"; exit 1; }

                [ "$r1" = "$r2" ] && echo "PASS: First two responses match" || { echo "FAIL: First two differ"; exit 1; }

                echo "Waiting 5s..."
                sleep 5

                echo "Request 3..."
                r3=$(call_api) || { echo "Error: Request 3 failed"; exit 1; }

                [ "$r3" != "$r1" ] && echo "PASS: Third response differs" || { echo "FAIL: Third response is same"; exit 1; }

                echo "SUCCESS: All tests passed"
            "#
            .to_owned(),
            stop_test_on_finish: true,
            run_in_foreground: false,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_server_attest_background_check_rotation_interval() -> Result<()> {
    run_test(vec![
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
                            "key": {
                                "source": "self_generated",
                                "rotation_interval": 3
                            }
                        },
                        "attest": {
                            "model": "background_check",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
            "#,
        ).boxed(),
        ShellTask {
            name: "check_key_rotation".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                # Reusable curl command
                call_api() {
                    curl -s -X POST http://192.168.1.1:30001 \
                        -H "x-tng-ohttp-api: /tng/key-config" \
                        -H "Content-Type: application/json" \
                        -H "Accept: */*" \
                        -H "User-Agent: tng/2.2.6" \
                        -d '{"attestation_request":{"model":"background_check","challenge_token":"dummy token"}}' | jq '.hpke_key_config.encoded_key_config_list'
                }

                echo "Request 1..."
                r1=$(call_api) || { echo "Error: Request 1 failed"; exit 1; }

                echo "Request 2..."
                r2=$(call_api) || { echo "Error: Request 2 failed"; exit 1; }

                [ "$r1" = "$r2" ] && echo "PASS: First two responses match" || { echo "FAIL: First two differ"; exit 1; }

                echo "Waiting 5s..."
                sleep 5

                echo "Request 3..."
                r3=$(call_api) || { echo "Error: Request 3 failed"; exit 1; }

                [ "$r3" != "$r1" ] && echo "PASS: Third response differs" || { echo "FAIL: Third response is same"; exit 1; }

                echo "SUCCESS: All tests passed"
            "#
            .to_owned(),
            stop_test_on_finish: true,
            run_in_foreground: false,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_server_attest_background_check_key_from_file() -> Result<()> {
    let key_dir = "/tmp/tng-test";
    let key_path = "/tmp/tng-test/ohttp-key.pem";

    tokio::fs::create_dir_all(key_dir)
        .await
        .context("Failed to create directory /tmp/tng-test")?;

    // Write initial private key to a temporary file
    let initial_key = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIOixlJE0Ykdc4ePwmaf2LLAea8Lfkfb+SARsKYmCBRpR
-----END PRIVATE KEY-----";

    tokio::fs::write(key_path, initial_key)
        .await
        .context("Failed to write initial key to /tmp/tng-test/ohttp-key.pem")?;

    run_test(vec![
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
                            "key": {
                                "source": "file",
                                "path": "/tmp/tng-test/ohttp-key.pem"
                            }
                        },
                        "attest": {
                            "model": "background_check",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
            "#
        ).boxed(),
        ShellTask {
            name: "check_key_rotation".to_owned(),
            node_type: NodeType::Client,
            script: {
                format!(
                    r#"
                    set -euo pipefail

                    KEY_PATH="{key_path}"

                    # Function to call the key config API
                    call_api() {{
                        curl -X POST http://192.168.1.1:30001 \
                            -H "x-tng-ohttp-api: /tng/key-config" \
                            -H "Content-Type: application/json" \
                            -H "Accept: */*" \
                            -H "User-Agent: tng/2.2.6" \
                            -d '{{"attestation_request":{{"model":"background_check","challenge_token":"dummy token"}}}}' | jq -c '.hpke_key_config.encoded_key_config_list'
                    }}

                    # Wait a moment for server to fully start
                    echo "Waiting 3 seconds for TNG to start..."
                    sleep 3

                    # ——————————————————————————————
                    # PHASE 1: Initial load – first two requests should match
                    # ——————————————————————————————
                    echo "PHASE 1: Initial key load"

                    echo "Request 1..."
                    r1=$(call_api) || {{ echo "Error: Request 1 failed"; exit 1; }}
                    echo "Response 1: $r1"

                    echo "Request 2..."
                    r2=$(call_api) || {{ echo "Error: Request 2 failed"; exit 1; }}
                    echo "Response 2: $r2"

                    if [ "$r1" = "$r2" ]; then
                        echo "PASS: First two responses match"
                    else
                        echo "FAIL: First two responses differ"
                        exit 1
                    fi

                    # ——————————————————————————————
                    # PHASE 2: Replace file with new key (via cat)
                    # ——————————————————————————————
                    echo "PHASE 2: Rotating key via file replacement"

                    echo "Replacing key file with new private key..."
                    cat > "$KEY_PATH" << 'EOF'
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIGA/SyKnQ6JfKjKrxdNxTzf0YaiaSDehWBG73u09kCFp
-----END PRIVATE KEY-----
EOF

                    echo "Waiting 2 seconds for key reload..."
                    sleep 2

                    echo "Request 3..."
                    r3=$(call_api) || {{ echo "Error: Request 3 failed"; exit 1; }}
                    echo "Response 3: $r3"

                    if [ "$r3" != "$r1" ]; then
                        echo "PASS: Third response differs from first"
                    else
                        echo "FAIL: Third response is same as first (expected change)"
                        exit 1
                    fi

                    echo "SUCCESS: Key change detected correctly"

                    # ——————————————————————————————
                    # PHASE 3: Delete the file and verify it becomes unavailable
                    # ——————————————————————————————
                    echo "PHASE 3: Deleting key file"

                    rm -f "$KEY_PATH"
                    echo "Key file deleted: $KEY_PATH"

                    echo "Waiting 2 seconds (expect transient failure possible)..."
                    sleep 2

                    # Try once after delete — return old key and system doesn't crash
                    echo "Probing after deletion..."
                    if r_after_del=$(call_api); then
                        echo "System still serving old key — acceptable"
                    fi

                    # ——————————————————————————————
                    # PHASE 4: Recreate file with another new key (via cat)
                    # ——————————————————————————————
                    echo "PHASE 4: Recreating file with third key"

                    cat > "$KEY_PATH" << 'EOF'
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIHjRocE5YrNmSK+eHQEhR3aO2Exp6K1jBLrkO6FIoDRq
-----END PRIVATE KEY-----
EOF

                    echo "New key written back to $KEY_PATH, waiting 3 seconds for TNG to detect and reload..."
                    sleep 3

                    echo "Request 4..."
                    r4=$(call_api) || {{ echo "Error: Request 4 failed"; exit 1; }}
                    echo "Response 4: $r4"

                    if [ -z "$r4" ]; then
                        echo "FAIL: Empty response after file recreation"
                        exit 1
                    fi

                    if [ "$r4" = "$r3" ]; then
                        echo "FAIL: Fourth response equals third — no change detected"
                        exit 1
                    elif [ "$r4" = "$r1" ]; then
                        echo "FAIL: Reverted to initial key unexpectedly"
                        exit 1
                    else
                        echo "PASS: Successfully loaded new key after recreate"
                    fi

                    # ——————————————————————————————
                    # PHASE 5: Replace key using `mv` (simulate atomic update)
                    # ——————————————————————————————
                    echo "PHASE 5: Replacing key via 'mv' (atomic replacement)"

                    TEMP_KEY="$(mktemp)"
                    echo "Creating temporary key file: $TEMP_KEY"
                    cat > "$TEMP_KEY" << 'EOF'
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIBg3c5YNL6uuhL0YqGdc1hJPBnReEMbTlrMZiHryomdL
-----END PRIVATE KEY-----
EOF

                    echo "Moving temp file to $KEY_PATH..."
                    mv "$TEMP_KEY" "$KEY_PATH"

                    echo "Waiting 3 seconds for TNG to detect and reload after mv..."
                    sleep 3

                    echo "Request 5..."
                    r5=$(call_api) || {{ echo "Error: Request 5 failed"; exit 1; }}
                    echo "Response 5: $r5"

                    if [ -z "$r5" ]; then
                        echo "FAIL: Empty response after mv-based update"
                        exit 1
                    fi

                    # It must be different from all previous keys
                    if [ "$r5" = "$r4" ] || [ "$r5" = "$r3" ] || [ "$r5" = "$r1" ]; then
                        echo "FAIL: Fifth response matches a previous key — expected new key"
                        exit 1
                    else
                        echo "PASS: Successfully detected key updated via 'mv'"
                    fi

                    echo "SUCCESS: All phases passed including mv-based rotation"
                    "#
                )
            },
            stop_test_on_finish: true,
            run_in_foreground: false,
        }
        .boxed(),
    ])
    .await?;

    // Optional: Clean up key file after test
    let _ = tokio::fs::remove_file(key_path).await;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_key_from_file() -> Result<()> {
    let key_dir = "/tmp/tng-test";
    let key_path = "/tmp/tng-test/ohttp-key.pem";

    tokio::fs::create_dir_all(key_dir)
        .await
        .context("Failed to create directory /tmp/tng-test")?;

    // Write initial private key to a temporary file
    let initial_key = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIOixlJE0Ykdc4ePwmaf2LLAea8Lfkfb+SARsKYmCBRpR
-----END PRIVATE KEY-----";

    tokio::fs::write(key_path, initial_key)
        .await
        .context("Failed to write initial key to /tmp/tng-test/ohttp-key.pem")?;

    run_test(vec![
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
                            "key": {
                                "source": "file",
                                "path": "/tmp/tng-test/ohttp-key.pem"
                            }
                        },
                        "attest": {
                            "model": "passport",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
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
                        "ohttp": {},
                        "verify": {
                            "model": "passport",
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
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.1",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
    ])
    .await?;

    // Optional: Clean up key file after test
    let _ = tokio::fs::remove_file(key_path).await;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_key_from_peer_shared_with_peers_file() -> Result<()> {
    let peers_file_path = "/tmp/tng-test/peers.json";
    let peers_dir = "/tmp/tng-test";

    // Create directory for peers file
    tokio::fs::create_dir_all(peers_dir)
        .await
        .context("Failed to create directory /tmp/tng-test")?;

    // Create initial peers file with addresses of nodes that will use peers_file
    let initial_peers = serde_json::json!(["192.168.1.1.nip.io:8301"]);
    tokio::fs::write(
        peers_file_path,
        serde_json::to_string_pretty(&initial_peers)?,
    )
    .await
    .context("Failed to write initial peers file")?;

    let mut tasks = Vec::default();

    // Create multiple TNG server instances using peers_file
    let (ips, tng_tasks, server_tasks):(Vec<_>,Vec<_>,Vec<_>) = itertools::multiunzip((1..=3).into_iter().map(|i|{
        let node_type = NodeType::Customized { host_num: i };

        (
            node_type.ip(),
            TngInstance::TngServer({
                if i == 1 {
                    // First node - use static peers to bootstrap the cluster
                    r#"{
                        "add_egress": [
                            {
                                "netfilter": {
                                    "capture_dst": {
                                        "port": 30001
                                    }
                                },
                                "ohttp": {
                                    "key": {
                                        "source": "peer_shared",
                                        "peers_file": "/tmp/tng-test/peers.json",
                                        "rotation_interval": 10,
                                        "attest": {
                                            "model": "background_check",
                                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                                        },
                                        "verify": {
                                            "model": "background_check",
                                            "as_addr": "http://192.168.1.254:8080/",
                                            "policy_ids": [
                                                "default"
                                            ]
                                        }
                                    }
                                },
                                "attest": {
                                    "model": "background_check",
                                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                                }
                            }
                        ]
                    }"#
                } else {
                    // Other nodes - no initial peers
                    r#"{
                        "add_egress": [
                            {
                                "netfilter": {
                                    "capture_dst": {
                                        "port": 30001
                                    }
                                },
                                "ohttp": {
                                    "key": {
                                        "source": "peer_shared",
                                        "peers": [],
                                        "rotation_interval": 10,
                                        "attest": {
                                            "model": "background_check",
                                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                                        },
                                        "verify": {
                                            "model": "background_check",
                                            "as_addr": "http://192.168.1.254:8080/",
                                            "policy_ids": [
                                                "default"
                                            ]
                                        }
                                    }
                                },
                                "attest": {
                                    "model": "background_check",
                                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                                }
                            }
                        ]
                    }"#
                }
            }).with_overwrite_node_type(node_type).boxed(),
            AppType::HttpServer {
                port: 30001,
                expected_host_header: "example.com",
                expected_path_and_query: "/foo/bar/www?type=1&case=1",
            }.with_overwrite_node_type(node_type).boxed(),
        )
    }));

    tasks.extend(tng_tasks);
    tasks.extend(server_tasks);

    tasks.extend(vec![
        ShellTask {
            name: "waiting for tng cluster keys sharing and peers file monitoring".to_owned(),
            node_type: NodeType::Client,
            script: {
                format!(
                    r#"
                    set -euo pipefail
                    
                    echo "Waiting 5 seconds for TNG cluster to establish and file watcher to start..."
                    sleep 3
                    
                    echo "Initial cluster setup complete"
                    "#
                )
            },
            stop_test_on_finish: false,
            run_in_foreground: true,
        }
        .boxed(),
        ShellTask {
            name: "update peers file and verify new peer joins".to_owned(),
            node_type: NodeType::Client,
            script: {
                format!(
                    r#"
                    set -euo pipefail
                    
                    PEERS_FILE="{}"
                    
                    echo "Updating peers file to add new peer..."
                    cat > "$PEERS_FILE" << 'EOF'
[
  "192.168.1.2.nip.io:8301",
  "192.168.1.3.nip.io:8301"
]
EOF
                    
                    echo "Waiting 3 seconds for file watcher to detect changes and join new peer..."
                    sleep 3
                    
                    echo "Peers file updated successfully"
                    "#,
                    peers_file_path
                )
            },
            stop_test_on_finish: false,
            run_in_foreground: true,
        }
        .boxed(),
        AppType::LoadBalancer {
            listen_port: 30001,
            upstream_servers: ips.into_iter().map(|ip| (ip, 30001)).collect(),
            path_matcher: r"^/foo/(.*)$",
            rewrite_to: r"/baz/$1",
        }
        .boxed(),
        TngInstance::TngClient(
            r#"{
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
                                    "match_regex": "^/foo/([^/]+)([/]?.*)$",
                                    "substitution": "/foo/\\1"
                                }
                            ]
                        },
                        "verify": {
                            "model": "background_check",
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": [
                                "default"
                            ]
                        }
                    }
                ]
            }"#
        )
        .boxed(),
        AppType::HttpClient {
            host: "192.168.1.252",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
        }
        .boxed(),
    ]);

    run_test(tasks).await?;

    // Clean up peers file
    let _ = tokio::fs::remove_file(peers_file_path).await;

    Ok(())
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_key_from_peer_shared() -> Result<()> {
    let mut tasks = Vec::default();

    let (ips,  tng_tasks,  server_tasks):(Vec<_>,Vec<_>,Vec<_>) = itertools::multiunzip((1..=10).into_iter().map(|i|{
            let node_type = NodeType::Customized { host_num: i };
            (
                node_type.ip(),
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
                                    "key": {
                                        "source": "peer_shared",
                                        "peers": [
                                            "192.168.1.1.nip.io:8301"
                                        ],
                                        "rotation_interval": 10,
                                        "attest": {
                                            "model": "background_check",
                                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                                        },
                                        "verify": {
                                            "model": "background_check",
                                            "as_addr": "http://192.168.1.254:8080/",
                                            "policy_ids": [
                                                "default"
                                            ]
                                        }
                                    }
                                },
                                "attest": {
                                    "model": "background_check",
                                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                                }
                            }
                        ]
                    }
                    "#,
                ).with_overwrite_node_type(node_type).boxed(),
                AppType::HttpServer {
                    port: 30001,
                    expected_host_header: "example.com",
                    expected_path_and_query: "/foo/bar/www?type=1&case=1",
                }.with_overwrite_node_type(node_type).boxed(),
            )
        }));

    tasks.extend(tng_tasks);
    tasks.extend(server_tasks);

    tasks.extend(vec![
        ShellTask {
            name: "waiting for tng cluster keys sharing".to_owned(),
            node_type: NodeType::Client,
            script: {
                format!(
                    r#"
                    set -euo pipefail
                    
                    sleep 3
                    "#
                )
            },
            stop_test_on_finish: false,
            run_in_foreground: true,
        }
        .boxed(),
        AppType::LoadBalancer {
            listen_port: 30001,
            upstream_servers: ips.into_iter().map(|ip| (ip, 30001)).collect(),
            path_matcher: r"^/foo/(.*)$",
            rewrite_to: r"/baz/$1",
        }
        .boxed(),
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
                                    "match_regex": "^/foo/([^/]+)([/]?.*)$",
                                    "substitution": "/foo/\\1"
                                }
                            ]
                        },
                        "verify": {
                            "model": "background_check",
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": [
                                "default"
                            ]
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        AppType::HttpClient {
            host: "192.168.1.252",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
        }
        .boxed(),
    ]);

    run_test(tasks).await?;

    Ok(())
}

mod common;

use anyhow::Result;
use common::{run_test, task::app::AppType};

/// tng client as verifier and tng server as attester, with "HTTP encapulation" enabled, while tng server is using `netfilter` mode instead of `mapping` mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test(
        &AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        },
        // TODO: add a HttpInspector for inspecting network traffic and check http body.
        &AppType::HttpClient {
            host: "127.0.0.1",
            port: 10001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
            http_proxy: None,
        },
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
                    "decap_from_http": {},
                    "attest": {
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
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
                            "port": 30001
                        }
                    },
                    "encap_in_http": {
                        "path_rewrites": [
                            {
                                "match_regex": "^/foo/([^/]+)([/]?.*)$",
                                "substitution": "/foo/\\1"
                            }
                        ]
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
    )
    .await?;

    Ok(())
}

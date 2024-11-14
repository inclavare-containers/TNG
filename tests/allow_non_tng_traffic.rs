mod common;

use anyhow::Result;
use common::{run_test, task::app::AppType};

/// tng client as verifier and tng server as attester, with "HTTP encapulation" enabled and `allow_non_tng_traffic_regexes` set, while tng server is using `netfilter` mode instead of `mapping` mode.
///
///
/// To test this, Launch a http server:
///
/// ```sh
/// python3 -m http.server 30001
/// ```
///
/// First, try to send request via tng client. It should work.
///
/// ```sh
/// all_proxy="http://127.0.0.1:41000" curl http://127.0.0.1:30001 -vvvvv
/// ```
///
/// Then, try to send non-tng traffic, it should be denied.
///
/// ```sh
/// curl http://127.0.0.1:30001 -vvvvv
/// ```
///
/// Finally, try to send non-tng traffic which is in the configed `allow_non_tng_traffic_regexes` option.
///
/// ```sh
/// # it should not work, since `/public` not matches `/public/.*`
/// curl http://127.0.0.1:30001/public
/// # it should work, since `/public/` matches `/public/.*`
/// curl http://127.0.0.1:30001/public/
/// # it should work, since `/public/abc` matches `/public/.*`
/// curl http://127.0.0.1:30001/public/abc
/// # it should work, since `/public/abc` matches `/public/.*`
/// curl -X POST http://127.0.0.1:30001/public/abc
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_access_via_tng() -> Result<()> {
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
                    "decap_from_http": {
                        "allow_non_tng_traffic_regexes": ["/public/.*"]
                    },
                    "attest": {
                        "aa_addr": "unix:///tmp/attestation.sock"
                    }
                }
            ]
        }
        "#;
    let tng_client_config = r#"
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
        "#;

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
        tng_server_config,
        tng_client_config,
    )
    .await?;

    run_test(
        &AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/public/resource",
        },
        &AppType::HttpClient {
            host: "127.0.0.1",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/public/resource",
            http_proxy: None,
        },
        tng_server_config,
        tng_client_config,
    )
    .await?;

    Ok(())
}

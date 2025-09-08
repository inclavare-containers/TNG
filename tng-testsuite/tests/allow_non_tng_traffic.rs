use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{
        app::{AppType, HttpProxy},
        tng::TngInstance,
        Task,
    },
};

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
/// all_proxy="http://127.0.0.1:41000" curl http://192.168.1.1:30001 -vvvvv
/// ```
///
/// Then, try to send non-tng traffic, it should be denied.
///
/// ```sh
/// curl http://192.168.1.1:30001 -vvvvv
/// ```
///
/// Finally, try to send non-tng traffic which is in the configed `allow_non_tng_traffic_regexes` option.
///
/// ```sh
/// # it should not work, since `/public` not matches `/public/.*`
/// curl http://192.168.1.1:30001/public
/// # it should work, since `/public/` matches `/public/.*`
/// curl http://192.168.1.1:30001/public/
/// # it should work, since `/public/abc` matches `/public/.*`
/// curl http://192.168.1.1:30001/public/abc
/// # it should work, since `/public/abc` matches `/public/.*`
/// curl -X POST http://192.168.1.1:30001/public/abc
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
                    "ohttp": {
                        "allow_non_tng_traffic_regexes": ["/public/.*"]
                    },
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

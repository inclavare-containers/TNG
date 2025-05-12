mod common;

use anyhow::Result;
use common::{
    run_test,
    task::{
        app::{AppType, HttpProxy},
        tng::TngInstance,
        Task as _,
    },
};

/// tng client as verifier and tng server as attester, with "HTTP encapulation" enabled, while tng server is using `netfilter` mode, and tng client is using `http_proxy` mode:
///
/// Here the http_proxy ingress only accept all domain `*` and any port (because `port` is not set).
///
/// To test this case, first setup a http server on 3001 port.
///
/// ```sh
/// python3 -m http.server 30001
/// ```
///
/// And then, send http request via proxy with `all_proxy` environment variable set.
///
/// ```sh
/// all_proxy="http://127.0.0.1:41000" curl http://192.168.1.1:30001 -vvvvv
/// ```
///
/// You will see the correct response.
///
/// And then, test sending request to target which is not matched by the `dst_filter` filter rule, for example, `http://www.baidu.com` and `https://www.baidu.com`.
///
/// ```sh
/// all_proxy="http://127.0.0.1:41000" curl http://www.baidu.com -vvvvv
/// all_proxy="http://127.0.0.1:41000" curl https://www.baidu.com -vvvvv
/// ```
///
/// You can see it also works since tng will not send these request via tng tunnel.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test(vec![
        TngInstance::TngServer(r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 30001
                            }
                        },
                        "decap_from_http": {},
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
            "#).boxed(),
        TngInstance::TngClient(r#"
            {
                "add_ingress": [
                    {
                        "http_proxy": {
                            "proxy_listen": {
                                "host": "0.0.0.0",
                                "port": 41000
                            },
                            "dst_filters": {
                                "domain": "*",
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
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": [
                                "default"
                            ]
                        }
                    }
                ]
            }
            "#).boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "192.168.1.1:30001",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
        AppType::HttpClientWithReverseProxy {
            host_header: "192.168.1.1:30001",
            path_and_query: "/foo/bar/www?type=1&case=1",
            http_proxy: HttpProxy {
                host: "127.0.0.1",
                port: 41000,
            },
        }.boxed(),
    ])
    .await?;

    Ok(())
}

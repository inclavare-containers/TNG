mod common;

use anyhow::Result;
use common::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// tng client as verifier and tng server as attester, with "HTTP encapulation" enabled.
///
///
/// You may test it by launch a python http server and connect it with curl via tng:
///
/// ```sh
/// python3 -m http.server 30001
/// ```
///
/// ```sh
/// curl --connect-to example.com:80:192.168.1.1:10001 http://example.com:80/foo/bar/www?type=1&case=1 -vvvv
/// ```
///
/// You can use tcpdump to observe the encapsulated HTTP traffic:
///
/// ```sh
/// tcpdump -n -vvvvvvvvvv -qns 0 -X -i any tcp port 20001
/// ```
///
/// You will see a POST request with `/foo/bar` as path and `tng` as one of the headers.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test(vec![
        TngInstance::TngServer(
            r#"
                {
                    "add_egress": [
                        {
                            "mapping": {
                                "in": {
                                    "host": "0.0.0.0",
                                    "port": 20001
                                },
                                "out": {
                                    "host": "127.0.0.1",
                                    "port": 30001
                                }
                            },
                            "decap_from_http": {},
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
                                "in": {
                                    "host": "0.0.0.0",
                                    "port": 10001
                                },
                                "out": {
                                    "host": "192.168.1.1",
                                    "port": 20001
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
                            "no_ra": true
                        }
                    ]
                }
                "#,
        )
        .boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }
        .boxed(),
        AppType::HttpClient {
            host: "127.0.0.1",
            port: 10001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

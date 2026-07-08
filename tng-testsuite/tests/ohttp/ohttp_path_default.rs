use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// With `path_default: "original"` and no `path_rewrites`, the outer OHTTP
/// POST path equals the inner request's original path (`/foo/bar/www`). The
/// LoadBalancer matches that path and forwards; the upstream HttpServer
/// receives the decrypted inner request unchanged. If the implementation
/// wrongly fell back to `/`, the LoadBalancer would 404 and this test fails.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_path_default_original() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "mapping": {
                            "in": { "host": "0.0.0.0", "port": 20001 },
                            "out": { "host": "127.0.0.1", "port": 30001 }
                        },
                        "ohttp": {},
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
                            "in": { "host": "0.0.0.0", "port": 10001 },
                            "out": { "host": "192.168.1.252", "port": 20001 }
                        },
                        "ohttp": {
                            "path_default": "original"
                        },
                        "no_ra": true
                    }
                ]
            }
            "#,
        )
        .boxed(),
        // LoadBalancer sits on the ingress->egress wire and observes the OUTER path.
        // path_default "original" => outer path = "/foo/bar/www" (matches).
        AppType::LoadBalancer {
            listen_port: 20001,
            upstream_servers: vec![("192.168.1.1".into(), 20001)],
            path_matcher: r"^/foo/bar/www$",
            rewrite_to: r"/foo/bar/www",
        }
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

/// With `path_default` unset (default "root"), the outer OHTTP POST path is
/// `/`. The LoadBalancer matches `^/$` and forwards. This pins the default
/// behavior so a future regression that changes the fallback is caught.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_path_default_root_default() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "mapping": {
                            "in": { "host": "0.0.0.0", "port": 20001 },
                            "out": { "host": "127.0.0.1", "port": 30001 }
                        },
                        "ohttp": {},
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
                            "in": { "host": "0.0.0.0", "port": 10001 },
                            "out": { "host": "192.168.1.252", "port": 20001 }
                        },
                        "ohttp": {},
                        "no_ra": true
                    }
                ]
            }
            "#,
        )
        .boxed(),
        // Outer path is "/" (default root). The matcher requires exactly "/".
        AppType::LoadBalancer {
            listen_port: 20001,
            upstream_servers: vec![("192.168.1.1".into(), 20001)],
            path_matcher: r"^/$",
            rewrite_to: r"/",
        }
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

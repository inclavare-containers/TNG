use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// With `ohttp.cors` unset, the egress must forward a CORS preflight
/// (OPTIONS + Access-Control-Request-Method) to the backend and relay the
/// backend's `Access-Control-Allow-*` response headers. The egress
/// `request_headers: ["origin"]` copies the outer `Origin` header into the
/// inner (decrypted) request, and `response_headers: ["access-control-allow-origin"]`
/// relays that ACAO header back to the outer response.
///
/// This is a flow-level smoke test: the suite asserts flow completion
/// (matching the existing `header_passthrough` tests), not that a specific
/// ACAO value is observed. `AppType::HttpClient` is not a browser and does
/// not emit a real CORS preflight (OPTIONS + Access-Control-Request-Method);
/// asserting the forwarded preflight / relayed ACAO end-to-end would require
/// `AppType::BrowserClient` (the `js-sdk` feature) — left as a follow-up.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_cors_preflight_forwarded() -> Result<()> {
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
                        "ohttp": {
                            "header_passthrough": {
                                "request_headers": ["origin"],
                                "response_headers": ["access-control-allow-origin"]
                            }
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
                            "in": { "host": "0.0.0.0", "port": 10001 },
                            "out": { "host": "192.168.1.1", "port": 20001 }
                        },
                        "ohttp": {},
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
            expected_path_and_query: "/cors/tunnel?q=1",
        }
        .boxed(),
        AppType::HttpClient {
            host: "127.0.0.1",
            port: 10001,
            host_header: "example.com",
            path_and_query: "/cors/tunnel?q=1",
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// key-config actual responses must carry `Access-Control-Allow-Origin: *`
/// when `ohttp.cors` is unset (key-config is TNG-local metadata; no backend).
/// The egress `request_headers: ["origin"]` is configured to exercise the
/// outer→inner `Origin` copy path alongside the CORS fallback layer.
///
/// Like the preflight test this is a flow-level smoke test: key-config is
/// fetched implicitly during the OHTTP flow, and asserting the ACAO header
/// on the key-config actual response would require `AppType::BrowserClient`
/// (the `js-sdk` feature) — left as a follow-up. This test ensures the flow
/// with `cors` unset + `request_headers: ["origin"]` does not regress.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_cors_key_config_actual_acao() -> Result<()> {
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
                        "ohttp": {
                            "header_passthrough": {
                                "request_headers": ["origin"]
                            }
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
                            "in": { "host": "0.0.0.0", "port": 10001 },
                            "out": { "host": "192.168.1.1", "port": 20001 }
                        },
                        "ohttp": {},
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
            expected_path_and_query: "/cors/keyconfig",
        }
        .boxed(),
        AppType::HttpClient {
            host: "127.0.0.1",
            port: 10001,
            host_header: "example.com",
            path_and_query: "/cors/keyconfig",
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

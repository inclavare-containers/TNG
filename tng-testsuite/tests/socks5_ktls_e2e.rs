use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{
        app::AppType,
        shell::{ShellMode, ShellTask},
        tng::TngInstance,
        NodeType, Task as _,
    },
};

/// End-to-end kTLS data plane through a **socks5** ingress. Topology mirrors
/// `tests/netfilter/client_socks5_server_netfilter.rs` (socks5 ingress + netfilter
/// egress) but uses `no_ra` on both sides (no AA/AS dependency) and adds
/// `rats_tls.ktls = "best-effort"` + `multiplex = false` on both sides.
///
/// # Byte-clean guard
///
/// The socks5 handshake reads fixed-length sub-protocol frames with
/// `read_exact!`. If that over-read consumed payload bytes (or under-read and
/// left handshake bytes in the application stream), the upstream would see a
/// corrupted request. To catch that, a `curl --socks5` client POSTs a fixed,
/// distinctive body with a distinctive query string through the tunnel:
/// - the `HttpServer` asserts the `Host` header and the full `path_and_query`
///   arrive **exactly** as sent (request-target byte-clean);
/// - the script asserts the response body is exactly `Hello World HTTP!`
///   (response byte-clean round-trip);
/// - the fixed POST body flows through the handshake as additional bytes, so a
///   handshake over-read that truncated `Content-Length` body bytes makes axum
///   reject/short the request → the server returns 500/`curl -f` fails.
///
/// On >= 5.16 the best-effort policy engages the kTLS splice path; on < 5.16
/// (5.10 dev box) it transparently falls back to rustls and the transfer still
/// succeeds — this test passes in both branches.
///
/// The `ktls_cx_active` gauge is not mechanically asserted here (tng exposes
/// metrics via a push-based OTel exporter, not an HTTP `/metrics` endpoint —
/// no readily-available in-test read path; same as `ktls_e2e.rs`). The
/// byte-clean round-trip is the enforceable proxy.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_socks5_ktls_e2e() -> Result<()> {
    if tng::config::ktls::kernel_splice_supported() {
        eprintln!("kernel >= 5.16: expecting the kTLS data plane (best-effort engages splice)");
    } else {
        eprintln!(
            "kernel < 5.16: asserting best-effort fallback (transfer still succeeds via rustls)"
        );
    }

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
                        "rats_tls": {
                            "ktls": "best-effort",
                            "multiplex": false
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
                        "socks5": {
                            "proxy_listen": {
                                "host": "0.0.0.0",
                                "port": 1080
                            }
                        },
                        "rats_tls": {
                            "ktls": "best-effort",
                            "multiplex": false
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
            expected_path_and_query: "/foo/bar?case=ktls&seq=9876543210",
        }
        .boxed(),
        ShellTask {
            name: "curl_via_socks5_byteclean".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                # POST a fixed, distinctive body through the socks5 tunnel.
                # -f fails on a non-2xx (server returns 500 if the request target
                # arrived corrupted). -s suppresses progress; the body must equal
                # exactly "Hello World HTTP!" (response byte-clean round-trip).
                resp=$(curl --socks5 127.0.0.1:1080 -f -s \
                    -X POST \
                    -H "Host: example.com" \
                    -d 'TNG_KTLS_SOCKS5_BYTECLEAN_0123456789abcdef' \
                    "http://192.168.1.1:30001/foo/bar?case=ktls&seq=9876543210")
                if [ "$resp" != "Hello World HTTP!" ]; then
                    echo "socks5 byte-clean mismatch: response body was '$resp'" >&2
                    exit 1
                fi
            "#
            .to_owned(),
            mode: ShellMode::ForegroundStop,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

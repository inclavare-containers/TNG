use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{
        app::{AppType, HttpProxy},
        tng::TngInstance,
        Task as _,
    },
};

/// End-to-end kTLS data plane through an **http_proxy CONNECT-tunnel** ingress.
/// Topology mirrors `tests/http/no_ra_ingress_httpproxy.rs` (http_proxy ingress
/// + mapping egress, `no_ra` both sides, a `TcpClient` that issues `CONNECT`
/// then speaks raw TCP) but adds `rats_tls.ktls = "best-effort"` +
/// `multiplex = false` on both sides.
///
/// After parsing the `CONNECT` request line, the http_proxy ingress downcasts
/// the upgraded HTTP/1 connection back to a raw `TcpStream`
/// (`hyper::upgrade::on` → `downcast_http1_upgraded`) and hands it to the kTLS
/// forward. The `TcpClient` issues `CONNECT`, then writes a fixed payload; the
/// `TcpServer` echoes it; the client asserts the echo is **byte-exact** — that
/// round-trip guards forward byte-integrity through the downcast + kTLS forward.
///
/// On >= 5.16 best-effort engages the kTLS splice path; on < 5.16 it
/// transparently falls back to rustls and the transfer still succeeds — this
/// test passes in both branches. The client speaks raw TCP rather than TLS
/// because the prelude flush is type-agnostic; a TLS handshake would add a
/// server+client pair for no extra coverage.
///
/// The `ktls_cx_active` gauge is not asserted here (tng exposes metrics via a
/// push-based OTel exporter, not an HTTP `/metrics` endpoint — same as
/// `ktls_e2e.rs`). The byte-exact echo is the enforceable proxy.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_http_proxy_connect_ktls_e2e() -> Result<()> {
    if tng::config::ktls::kernel_splice_supported() {
        eprintln!("kernel >= 5.16: expecting the kTLS data plane (best-effort engages splice)");
    } else {
        eprintln!(
            "kernel < 5.16: asserting best-effort fallback (CONNECT + transfer still succeed via rustls)"
        );
    }

    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "mapping": {
                            "in": {
                                "host": "0.0.0.0",
                                "port": 10001
                            },
                            "out": {
                                "host": "127.0.0.1",
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
                        "http_proxy": {
                            "proxy_listen": {
                                "host": "0.0.0.0",
                                "port": 41000
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
        AppType::TcpServer { port: 30001 }.boxed(),
        AppType::TcpClient {
            host: "192.168.1.1",
            port: 10001,
            http_proxy: Some(HttpProxy {
                host: "127.0.0.1",
                port: 41000,
            }),
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

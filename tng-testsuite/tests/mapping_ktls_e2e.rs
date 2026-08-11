use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// End-to-end kTLS data plane through a **mapping** ingress. Topology mirrors
/// `tests/basic/no_ra.rs`
/// (mapping ingress + mapping egress, `no_ra` both sides) but adds
/// `rats_tls.ktls = "best-effort"` + `multiplex = false` on both sides so each
/// end's tunnel socket is routed through the kTLS data plane.
///
/// A `TcpClient` sends a fixed payload (`TCP_PAYLOAD`) through the mapping
/// listener; the `TcpServer` echoes it; the client asserts the echo is
/// byte-exact. That round-trip is both the "transfer succeeds" assertion and a
/// byte-clean guard: a kTLS send/recv regression (or a fall back on 5.10) that
/// dropped or duplicated bytes would fail the echo comparison.
///
/// On >= 5.16 the best-effort policy engages the kTLS splice path; on < 5.16
/// (5.10 dev box) it transparently falls back to rustls and the transfer still
/// succeeds — this test passes in both branches, asserting the fallback path
/// rather than requiring the splice path.
///
/// The `ktls_cx_active` gauge is not mechanically asserted here, for the same
/// reason as `ktls_e2e.rs`: tng exposes metrics via a push-based OTel
/// exporter, not an HTTP `/metrics` endpoint, so there is no readily-available
/// in-test read path. The byte-exact echo is the enforceable proxy.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_mapping_ktls_e2e() -> Result<()> {
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
                        "mapping": {
                            "in": {
                                "port": 10001
                            },
                            "out": {
                                "host": "192.168.1.1",
                                "port": 20001
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
            host: "127.0.0.1",
            port: 10001,
            http_proxy: None,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

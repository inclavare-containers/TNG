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

/// `required`-mode companion to `http_proxy_connect_ktls_e2e.rs`: asserts the
/// http_proxy CONNECT tunnel + byte-exact echo **succeeds** under
/// `rats_tls.ktls = "required"` on >= 5.16 (the CONNECT downcast succeeds →
/// `IncomingStream::Raw` → kTLS engages → traffic flows).
///
/// This also guards the http_proxy CONNECT downcast: a failed downcast yields
/// `IncomingStream::Opaque`, and under `required` the Opaque arm bails the
/// connection (kTLS installs on a raw fd, which an erased stream has none), so
/// the echo would fail and this test would go red. Under `best-effort` the
/// same downcast break would silently fall back to rustls (the best-effort
/// companion would stay green), so the `required` tier is what makes the
/// downcast regression observable here.
///
/// `required` resolves at setup via `Ktls::resolve`: on < 5.16 the
/// `KernelSpliceUnsupported` constraint makes `required` bail →
/// `add_egress`/`add_ingress` return `Err` → `run_test!` fails. That is the
/// expected behavior on an older kernel, not a regression — so this test skips
/// on < 5.16 (returns `Ok(())` early) and only runs the assertion on >= 5.16.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_http_proxy_connect_ktls_required_e2e() -> Result<()> {
    if !tng::config::ktls::kernel_splice_supported() {
        // < 5.16: `required` bails at setup via KernelSpliceUnsupported — that
        // is expected, not a regression. Skip so the suite stays green on the
        // 5.10 dev box; the best-effort companion guards byte flow on all
        // kernels. This early return is NOT hiding a failure: on a capable
        // kernel (>= 5.16) the assertion below runs in full.
        #[cfg(target_os = "linux")]
        eprintln!(
            "skipping http_proxy_connect_ktls_required_e2e on kernel < 5.16 (required bails at setup via KernelSpliceUnsupported; expected)"
        );
        #[cfg(not(target_os = "linux"))]
        eprintln!(
            "skipping http_proxy_connect_ktls_required_e2e on non-Linux (kTLS is Linux-only; required bails at setup)"
        );
        return Ok(());
    }

    eprintln!(
        "kernel >= 5.16: asserting `required` http_proxy CONNECT downcast works (kTLS engaged, echo byte-exact)"
    );

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
                            "ktls": "required",
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
                            "ktls": "required",
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

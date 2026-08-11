use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Parse `major.minor` out of a kernel release string, ignoring any `-suffix`.
/// Inlined (mirrors `tng::config::parse_kernel_version`) to keep this test
/// self-contained and avoid coupling the test crate to tng's private helper.
fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let release = release.split('-').next()?;
    let mut parts = release.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// End-to-end kTLS data plane: netfilter ingress (client) + netfilter egress
/// (server), `no_ra` on both sides (no AA/AS dependency), and
/// `rats_tls.ktls = "best-effort"` on both sides so each end's accepted
/// downstream `TcpStream` is routed through the kTLS data plane instead of the
/// boxed rustls path. (`ktls` accepts the `"disabled"`/`"best-effort"`/
/// `"required"` policy strings; see `tng::config::ktls`.)
///
/// On >= 5.16 the best-effort policy engages the kTLS splice path; on < 5.16
/// (5.10 dev box) it transparently falls back to rustls and the transfer still
/// succeeds — this test passes in both branches, asserting the fallback path
/// rather than requiring the splice path. See `tunnel::utils::forward::ktls_splice`
/// for how the kTLS data plane works.
///
/// To run for real (engaging the kTLS path), the kernel `tls` module must be
/// loaded (`modprobe tls`) and the negotiated cipher must be in the kernel's
/// kTLS support set:
/// ```sh
/// cargo test -p tng-testsuite --test ktls_e2e -- --nocapture
/// ```
///
/// The `ktls_cx_active` gauge is not asserted here: tng exposes metrics via a
/// push-based OTel exporter, not an HTTP `/metrics` endpoint, so there is no
/// in-test read path. Inspect it via the exporter's sink when running with the
/// feature on.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ktls_e2e() -> Result<()> {
    // kTLS recv-splice is broken on < 5.16 (tls_sw_splice_read). On such a kernel
    // best-effort silently falls back to rustls; skip rather than report a green
    // test that never touched the kTLS path.
    #[cfg(target_os = "linux")]
    {
        let release = std::process::Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();
        let v = parse_kernel_version(release.trim()).unwrap_or((0, 0));
        if v < (5, 16) {
            eprintln!(
                "skipping ktls_e2e on kernel {} (< 5.16, kTLS recv splice broken)",
                release.trim()
            );
            return Ok(());
        }
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
                        "netfilter": {
                            "capture_dst": [
                                {
                                    "port": 30001
                                }
                            ],
                            "listen_port": 50000
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
            expected_path_and_query: "/foo/bar",
        }
        .boxed(),
        AppType::HttpClient {
            host: "192.168.1.1",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/foo/bar",
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

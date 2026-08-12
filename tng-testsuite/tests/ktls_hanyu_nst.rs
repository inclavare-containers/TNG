use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Parse `major.minor` out of a kernel release string, ignoring any `-suffix`.
fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let release = release.split('-').next()?;
    let mut parts = release.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Regression for the A2 NST contract (spec §5.1): a TLS 1.3 peer that sends a
/// `NewSessionTicket` post-handshake MUST NOT abort the kTLS splice
/// connection. The NST arrives as a control record -> splice EIO ->
/// `Context::handle_tls_control_message` -> `handle_new_session_ticket`; if
/// `Session::handle_new_session_ticket` returned Err, the splice drain loop
/// would fault and this HTTP request would fail/abort.
///
/// A single kTLS connection over a `best-effort` netfilter ingress (client) +
/// netfilter egress (server), `no_ra` both sides. The rustls TLS 1.3 server
/// sends its `NewSessionTicket` shortly after the handshake, independent of
/// request size — so one request over the kTLS tunnel is enough to exercise the
/// NST-control-record path during the splice loop. On < 5.16 the best-effort
/// policy falls back to rustls (which never hits the splice EIO path the NST
/// contract is about) — skip rather than report a green test that never touched
/// the kTLS path.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ktls_hanyu_nst_survives() -> Result<()> {
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
                "skipping ktls_hanyu_nst on kernel {} (< 5.16, kTLS recv splice broken)",
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
                                "port": 30010
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
                                    "port": 30010
                                }
                            ],
                            "listen_port": 50010
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
            port: 30010,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar",
        }
        .boxed(),
        AppType::HttpClient {
            host: "192.168.1.1",
            port: 30010,
            host_header: "example.com",
            path_and_query: "/foo/bar",
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

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

/// kTLS engages only on Linux >= 5.16; below that `best-effort` resolves to
/// `Disabled` (`engages() == false`). Returns whether the running kernel can
/// actually engage the kTLS arm (and thus exercise the `encrypted` gate).
fn ktls_engages_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        let release = std::process::Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();
        let v = parse_kernel_version(release.trim()).unwrap_or((0, 0));
        v >= (5, 16)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Regression test: a plaintext socks5 connection whose dst is not in
/// `dst_filters` must bypass the kTLS path.
///
/// socks5 ingress yields `IncomingStream::Raw` regardless of destination, and
/// `encrypted` is `should_forward_via_tunnel(&dst)` — `false` when the requested
/// dst is not in `dst_filters` (a non-empty filter that doesn't match the dst
/// yields `encrypted=false`). The ingress flow gates the kTLS path behind
/// `encrypted`: when `encrypted` is `false` the `Raw` stream is routed to the
/// unprotected stream manager before kTLS dispatch is reached. A regression that
/// dropped that gate would route a plaintext socks5 connection into a kTLS
/// handshake, which fails and drops the connection.
///
/// Topology (mirrors `socks5_ktls_e2e` + the `dst_filters` block of
/// `client_socks5_server_netfilter`): socks5 ingress with
/// `dst_filters: [{ "domain": "192.168.1.1", "port": 30001 }]` (matches only
/// 30001) + `rats_tls.ktls = "best-effort"` + `no_ra`; the client curls
/// `http://192.168.1.1:40001/...`, whose dst is NOT in `dst_filters`, so
/// `encrypted=false`. An `HttpServer` on 40001 receives the plaintext
/// direct-forward. The server also runs a netfilter egress capturing 30001
/// (unused by the 40001 plaintext request — the plaintext leg bypasses the
/// egress).
///
/// This test does NOT skip on < 5.16: on every kernel the plaintext transfer
/// must succeed (a non-regression guard). On < 5.16 `best-effort` resolves to
/// `Disabled` so the kTLS path is never reached even without the gate (the bug
/// is only mechanically enforced on >= 5.16, where the kTLS path would engage
/// and drop the plaintext connection if the gate were missing).
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_socks5_ktls_plaintext_bypass() -> Result<()> {
    if ktls_engages_supported() {
        eprintln!("kernel >= 5.16: ktls best-effort engages -> the encrypted gate is exercised");
    } else {
        eprintln!(
            "kernel < 5.16: ktls best-effort resolves to Disabled (engages=false) -> \
             non-regression guard only"
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
        // socks5 ingress with dst_filters matching ONLY 192.168.1.1:30001, so a
        // request to :40001 has encrypted=false. ktls: best-effort makes the
        // (now-gated) kTLS arm engage on Linux >= 5.16.
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
                    {
                        "socks5": {
                            "proxy_listen": {
                                "host": "0.0.0.0",
                                "port": 1080
                            },
                            "dst_filters": [
                                {
                                    "domain": "192.168.1.1",
                                    "port": 30001
                                }
                            ]
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
        // Plaintext direct-forward target: dst :40001 is NOT in dst_filters, so
        // encrypted=false. The server's egress captures only :30001, so this
        // plaintext leg is not intercepted.
        AppType::HttpServer {
            port: 40001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar?case=ktls_plaintext_bypass",
        }
        .boxed(),
        ShellTask {
            name: "curl_via_socks5_plaintext".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                # The dst :40001 is not in dst_filters -> encrypted=false.
                # -f fails on a non-2xx; with the bug on >= 5.16 the plaintext
                # connection is mis-routed into the kTLS arm and dropped (curl -f
                # fails). With the fix it unprotected-forwards to the HttpServer.
                resp=$(curl --socks5 127.0.0.1:1080 -f -s \
                    -H "Host: example.com" \
                    "http://192.168.1.1:40001/foo/bar?case=ktls_plaintext_bypass")
                if [ "$resp" != "Hello World HTTP!" ]; then
                    echo "plaintext bypass mismatch: response body was '$resp'" >&2
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

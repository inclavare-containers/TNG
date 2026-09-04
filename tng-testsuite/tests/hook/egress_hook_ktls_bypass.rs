use anyhow::Result;
use tng_testsuite::{run_test, task::tng::TngExecTask, task::NodeType, task::Task as _};

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

/// Regression test: a plaintext egress-hook connection must bypass the kTLS
/// path.
///
/// The egress hook yields `IncomingStream::Raw` unconditionally, while
/// `HookEgress::encrypted()` returns `false` for connections that don't match a
/// configured host/ifname rule — here a loopback peer with
/// `capture_local_traffic` defaulting to `false`. The egress flow gates the
/// trusted (kTLS/OHTTP) path behind `encrypted`: when `encrypted` is `false` the
/// connection takes the direct-forward arm and never reaches the kTLS handshake.
/// A regression that dropped that gate would route the plaintext loopback
/// connection into a server-side kTLS handshake, which fails and drops the
/// connection — the echo round-trip would then fail.
///
/// Architecture (mirrors `egress_hook_capture_local_traffic` + a `ktls` policy):
/// - Server side: `tng exec` with egress hook
///   `capture_listen: [{"host": "127.0.0.1", "port": 20001}]` (no
///   `capture_local_traffic` field -> defaults to `false`) AND
///   `rats_tls: {ktls: "best-effort", multiplex: false}` on the same egress,
///   wrapping a Python echo server bound to 127.0.0.1:20001. Inside the
///   wrapper, a local TCP client connects to 127.0.0.1:20001, sends a payload,
///   and verifies the echo response.
///
/// Expected result: because `127.0.0.1` is local and
/// `capture_local_traffic` defaults to `false`, `encrypted()` returns `false`
/// for the loopback connection, which direct-forwards and echoes successfully.
///
/// Kernel gate: kTLS recv-splice is broken on < 5.16, where `best-effort`
/// resolves to `Disabled` (`engages() == false`) so the kTLS path is never
/// reached — the test would pass even with the gate missing (false negative).
/// Skip on < 5.16 (and non-Linux) so the test only runs where it can exercise
/// the gated arm. This mirrors `ktls_e2e`.
///
/// This test requires `libtng_hook.so` installed alongside the `tng` binary, so
/// it only runs in `on-bin` mode (via `required-features`).
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    // kTLS engages only on Linux >= 5.16; below that `best-effort` resolves to
    // `Disabled` and the buggy arm is never reached (false negative). Skip.
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
                "skipping egress_hook_ktls_bypass on kernel {} (< 5.16, kTLS best-effort resolves to Disabled)",
                release.trim()
            );
            return Ok(());
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("skipping egress_hook_ktls_bypass on non-Linux (kTLS is Linux-only)");
        return Ok(());
    }

    run_test!(vec![
        // Server side: tng exec wrapping a Python echo server on 127.0.0.1:20001.
        // capture_listen: [{"host": "127.0.0.1", "port": 20001}] with NO
        // capture_local_traffic field -> defaults to false, so the loopback
        // connection has encrypted()==false. rats_tls.ktls = "best-effort" makes
        // the egress kTLS arm engage on Linux >= 5.16.
        //
        // With the bug, the loopback (encrypted=false) connection is mis-routed
        // into the kTLS arm and dropped -> echo fails. With the fix, it
        // direct-forwards -> echo succeeds.
        TngExecTask::new(
            r#"{"add_egress": [{"hook": {"capture_listen": [{"host": "127.0.0.1", "port": 20001}]}, "rats_tls": {"ktls": "best-effort", "multiplex": false}, "no_ra": true}]}"#.to_string(),
            vec![
                "sh".to_string(),
                "-c".to_string(),
                concat!(
                    "python3 -c '\n",
                    "import socket, threading, time\n",
                    "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
                    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
                    "s.bind((\"127.0.0.1\", 20001))\n",
                    "s.listen(5)\n",
                    "def handle():\n",
                    "    while True:\n",
                    "        c, a = s.accept()\n",
                    "        d = c.recv(4096)\n",
                    "        if d: c.sendall(d)\n",
                    "        c.close()\n",
                    "threading.Thread(target=handle, daemon=True).start()\n",
                    "time.sleep(1)\n",
                    "c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
                    "c.connect((\"127.0.0.1\", 20001))\n",
                    "c.sendall(b\"Hello from ktls bypass!\")\n",
                    "c.shutdown(socket.SHUT_WR)\n",
                    "d = c.recv(4096)\n",
                    "assert d == b\"Hello from ktls bypass!\", f\"Expected echo, got: {d}\"\n",
                    "c.close()\n",
                    "print(\"OK: egress hook ktls plaintext bypass verified\")\n",
                    "'",
                )
                .to_string(),
            ],
            false,
            NodeType::Server,
        )
        .boxed(),
    ])
    .await?;
    Ok(())
}

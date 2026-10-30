// Connection fairness + teardown-integrity benchmarks over the user's exact
// PD-separation hook config: rats-tls, non-multiplexed (`multiplex: false`, so
// every app connection gets its own tunnel connection), `no_ra: true` (no
// attestation). The two bench binaries under `fairness_bench/` are std-only and
// auto-built with rustc (see `ensure_bench_binary`).
//
// - `test_fairness_with_tng`: 64 bulk transfers through the tunnel, checks the
//   bandwidth split stays fair (Jain's index) and the orderly-close path
//   delivers every byte.
// - `test_fairness_abrupt_teardown`: same topology, but the wrapped server
//   process exits right after writing, regression-testing the `tng exec` drain
//   window (no stall, no truncation).
// - `test_fairness_baseline_no_tng`: direct TCP without TNG, the fairness
//   baseline of the link itself.
use std::path::PathBuf;
use std::process::Command as StdCommand;

use anyhow::{Context, Result};
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{
        shell::{ShellMode, ShellTask},
        tng::TngExecTask,
        NodeType, Task as _,
    },
};

// User-reported PD-separation config: per-rank KV-cache transfer over ports
// 30000-30063 (64 ranks), plus a control port 5600. `multiplex:false` => each
// app connection is a separate RATS-TLS tunnel connection; `no_ra:true` disables
// attestation. These two configs are the EXACT user config, used verbatim on
// the egress (server/Prefill) and ingress (client/Decode) sides respectively.
const EGRESS_CONFIG: &str = r#"{
    "add_egress": [
        {
            "hook": {
                "capture_listen": [
                    { "port": 5600 },
                    { "port": 30000, "port_end": 30063 }
                ]
            },
            "rats_tls": { "multiplex": false },
            "no_ra": true
        }
    ]
}"#;

const INGRESS_CONFIG: &str = r#"{
    "add_ingress": [
        {
            "hook": {
                "capture_dst": [
                    { "port": 5600 },
                    { "port": 30000, "port_end": 30063 }
                ]
            },
            "rats_tls": { "multiplex": false },
            "no_ra": true
        }
    ]
}"#;

/// Resolve (and auto-build with `rustc` when missing or older than the source)
/// one of the fairness measurement binaries. They are std-only and MUST stay
/// dynamically linked to libc: `tng exec` intercepts `bind()`/`connect()` via
/// an LD_PRELOAD hook, which cannot patch a statically linked binary. Building
/// them with plain rustc (no cargo target) keeps the test self-contained and
/// keeps the sources out of the crate's build graph. Sources live in
/// `tests/hook/fairness_bench/` (not a `[[test]]` target, so cargo never
/// compiles them as part of the suite); artifacts go to
/// `<workspace>/target/fairness-bench/`.
fn ensure_bench_binary(name: &str) -> Result<String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src = manifest_dir
        .join("tests")
        .join("hook")
        .join("fairness_bench")
        .join(format!("{name}.rs"));
    let out_dir = manifest_dir
        .join("..")
        .join("target")
        .join("fairness-bench");
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("create bench out dir {out_dir:?}"))?;
    let bin = out_dir.join(name);

    let src_mtime = std::fs::metadata(&src)
        .with_context(|| format!("bench source missing: {src:?}"))?
        .modified()?;
    let stale = match std::fs::metadata(&bin) {
        Ok(meta) => match meta.modified() {
            Ok(bin_mtime) => src_mtime > bin_mtime,
            Err(_) => true,
        },
        Err(_) => true, // no binary yet
    };
    if stale {
        // Build on demand: std-only, no deps, no network — ~1s with rustc.
        let status = StdCommand::new("rustc")
            .args(["-O", "--edition", "2021"])
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .status()
            .with_context(|| format!("failed to spawn rustc to build {name}"))?;
        if !status.success() {
            anyhow::bail!("rustc build of {name} failed (status {status})");
        }
    }
    let bin =
        std::fs::canonicalize(&bin).with_context(|| format!("canonicalize bench bin {bin:?}"))?;
    Ok(bin.to_string_lossy().into_owned())
}

/// Connection count and per-connection payload size, overridable via env for
/// scaling the benchmark without recompiling. Defaults: 64 connections × 64MB
/// (the full PD rank range 30000-30063, 4GB total) — large enough that
/// steady-state throughput dominates handshake/slow-start.
fn params() -> (u16, u64) {
    let count: u16 = std::env::var("TNG_FAIRNESS_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let size: u64 = std::env::var("TNG_FAIRNESS_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64 * 1024 * 1024);
    (count, size)
}

/// Test A — multi-connection bandwidth fairness THROUGH TNG, using the user's
/// exact PD-separation hook config on both sides (rats-tls, non-multiplexed,
/// `no_ra: true`).
///
/// Server (Prefill) node: `tng exec` egress hook wraps `fairness_server`, which
/// binds 30000+count ports (hook redirects each bind; tng binds the origin ports
/// for tunnel traffic) and streams `size` bytes per accepted connection.
///
/// Client (Decode) node: `tng exec` ingress hook wraps `fairness_client`, which
/// opens `count` concurrent connections to 192.168.1.1:30000+i (hook intercepts
/// each connect and tunnels it), receives `size` bytes per connection, and
/// prints a fairness report (per-conn MB/s, Jain's index, max/min ratio).
///
/// `stop_after_exit=true` on the client ends the test once measurement is done.
/// The server's `fairness_server` exits on its own after serving `count`
/// connections (bounded lifetime, no orphan leak).
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_fairness_with_tng() -> Result<()> {
    let server_bin = ensure_bench_binary("fairness_server")?;
    let client_bin = ensure_bench_binary("fairness_client")?;
    let (count, size) = params();
    let base = 30000u16;

    let server_cmd = format!("{server_bin} {base} {count} {size}");
    let client_cmd = format!("{client_bin} 192.168.1.1 {base} {count} {size}");

    run_test!(vec![
        // Egress (Prefill) side: user's exact config, wrapping the bench server.
        // stop_after_exit=false => the server task does not end the test; the
        // client's exit (stop_after_exit=true) cancels everything.
        TngExecTask::new(
            EGRESS_CONFIG.to_string(),
            vec!["sh".to_string(), "-c".to_string(), server_cmd],
            false,
            NodeType::Server,
        )
        .boxed(),
        // Ingress (Decode) side: user's exact config, wrapping the bench client.
        TngExecTask::new(
            INGRESS_CONFIG.to_string(),
            vec!["sh".to_string(), "-c".to_string(), client_cmd],
            true,
            NodeType::Client,
        )
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Test B — abrupt sender teardown THROUGH TNG: the same user PD config
/// (rats-tls, non-multiplexed, `no_ra: true`) and the same 64 transfers as
/// Test A, but `fairness_server` runs in `abrupt` mode: it exits the moment
/// its writes are handed to the app socket, without waiting for the client.
///
/// Guards the `tng exec` drain window: data the application wrote before
/// exiting must still be delivered through the tunnel before teardown, and the
/// receiver must reach EOF instead of hanging. The bench client exits nonzero
/// if any connection stalls (read timeout, no progress) or is truncated (clean
/// EOF short of the full payload), so the client's exit code — surfaced as a
/// failed `run_test!` — is the assertion.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_fairness_abrupt_teardown() -> Result<()> {
    let server_bin = ensure_bench_binary("fairness_server")?;
    let client_bin = ensure_bench_binary("fairness_client")?;
    let (count, size) = params();
    let base = 30000u16;

    let server_cmd = format!("{server_bin} {base} {count} {size} abrupt");
    let client_cmd = format!("{client_bin} 192.168.1.1 {base} {count} {size}");

    run_test!(vec![
        // Egress (Prefill) side: abrupt server; its `tng exec` must drain the
        // in-flight tails after the child exits.
        TngExecTask::new(
            EGRESS_CONFIG.to_string(),
            vec!["sh".to_string(), "-c".to_string(), server_cmd],
            false,
            NodeType::Server,
        )
        .boxed(),
        // Ingress (Decode) side: the client's exit code is the assertion.
        TngExecTask::new(
            INGRESS_CONFIG.to_string(),
            vec!["sh".to_string(), "-c".to_string(), client_cmd],
            true,
            NodeType::Client,
        )
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Test C — BASELINE: same topology and same measurement binaries, but with NO
/// TNG tunnel (the bench client connects directly to the bench server across
/// the netns veth). This isolates the fairness contribution of TCP/the link
/// itself from TNG's data plane.
///
/// Compare Test A vs Test C:
/// - A much less fair than C  => unfairness introduced by TNG's data plane.
/// - A and C similarly unfair => root cause is TCP/link-layer (multi-flow AIMD
///   sharing the bottleneck veth), not TNG.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_fairness_baseline_no_tng() -> Result<()> {
    let server_bin = ensure_bench_binary("fairness_server")?;
    let client_bin = ensure_bench_binary("fairness_client")?;
    let (count, size) = params();
    let base = 30000u16;

    // `exec` replaces the shell with the server so cancellation reliably
    // terminates it (no orphan). BackgroundContinue => launch returns at once,
    // staying clear of the 60s readiness timeout while the transfer runs.
    let server_script = format!("exec {server_bin} {base} {count} {size}");
    // BackgroundStop => the client's completion cancels the token (winds down
    // the background server), and launch returns immediately (no readiness
    // timeout). The client prints the fairness report to stdout.
    let client_script = format!("exec {client_bin} 192.168.1.1 {base} {count} {size}");

    run_test!(vec![
        ShellTask {
            name: "fairness_server_baseline".to_owned(),
            node_type: NodeType::Server,
            script: server_script,
            mode: ShellMode::BackgroundContinue,
        }
        .boxed(),
        ShellTask {
            name: "fairness_client_baseline".to_owned(),
            node_type: NodeType::Client,
            script: client_script,
            mode: ShellMode::BackgroundStop,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

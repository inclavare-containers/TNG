use anyhow::Result;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;
use tng_testsuite::{
    run_test,
    task::{
        shell::{ShellMode, ShellTask},
        tng::{TngExecTask, TngInstance},
        NodeType, Task,
    },
};

use serial_test::serial;

/// Marker the hook cdylib emits from its `#[ctor::ctor]` init.
const HOOK_INIT_MARKER: &str = "tng-hook: initialized";
/// Marker the hook emits per successful hooked connect.
const TUNNEL_MARKER: &str = "tunnel established";

/// Threaded echo server on `port` (Server node), backgrounded for the test.
fn echo_server(port: u16) -> Box<dyn Task> {
    let script = format!(
        r#"
python3 -c '
import socket, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {port}))
s.listen(16)
def handle(c):
    try:
        d = c.recv(4096)
        if d:
            c.sendall(d)
    finally:
        c.close()
while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
' &
sleep 120
"#
    );
    ShellTask {
        name: "echo server".to_owned(),
        node_type: NodeType::Server,
        script,
        mode: ShellMode::BackgroundContinue,
    }
    .boxed()
}

/// Rolling-under-tng-exec integration test: with `--log-rolling` and a tiny
/// `--log-max-size`, a run that produces enough hook + main log volume must
/// rotate the active `info.log.tng` into numbered backups (`info.log.tng.1`
/// .. `.N`, capped at `--log-max-backups`). The hook logs and the main
/// process's access-log lines merge into the SAME rolling appender the main
/// process owns (centralization + rolling together), so this also proves
/// centralization keeps working through a rotation.
///
/// Assertions (correct work + log-content sanity):
/// - The run completes exit-0 (the hook path still works under rolling).
/// - At least one numbered backup exists (rotation actually happened).
/// - No more than `max_backups` backups (the cap is enforced).
/// - Every file in the tempdir is `info.log.tng*` or `error.log.tng*` (no
///   pid-derived per-process files; centralization holds under rolling).
/// - The active `info.log` is non-empty, valid JSON, has no ERROR-level line
///   (disjoint), and no panic markers.
/// - `error.log` exists, is ERROR-only, and has no hook INFO leaked.
///
/// Requires `on-bin` (external tng binary + libtng_hook.so).
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
#[serial]
async fn hook_log_rolling_rotates_under_tng_exec() -> Result<()> {
    let dir = TempDir::new()?;
    let info = dir.path().join("info.log.tng");
    let error = dir.path().join("error.log.tng");
    const MAX_BACKUPS: usize = 5;

    let tasks: Vec<Box<dyn Task>> = vec![
        echo_server(30020),
        // Server side: egress forwards 0.0.0.0:20020 -> 127.0.0.1:30020 (echo).
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {"in": {"host": "0.0.0.0", "port": 20020},
                                 "out": {"host": "127.0.0.1", "port": 30020}},
                    "no_ra": true
                }]
            }"#,
        )
        .boxed(),
        // Client side: tng exec with ingress hook + rolling logs. A tiny
        // max-size forces rotation from a modest number of hook + main log
        // lines. The child loops 30 real hooked connects, each emitting a
        // tunnel-established (hook) + an ingress access-log (main) line, enough
        // to rotate several times. Each connect retries briefly to ride out
        // an echo-server readiness race.
        TngExecTask::new(
            r#"{
                "add_ingress": [{
                    "hook": {"capture_dst": [{"port": 20020}]},
                    "no_ra": true
                }]
            }"#
            .to_string(),
            vec![
                "sh".to_string(),
                "-c".to_string(),
                r#"
python3 -c '
import socket, time, sys
def one():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("192.168.1.1", 20020))
    s.sendall(b"ping")
    s.shutdown(socket.SHUT_WR)
    d = s.recv(4096)
    s.close()
    assert d == b"ping", f"expected ping, got: {d}"
for i in range(30):
    err = None
    for a in range(5):
        try:
            one()
            break
        except Exception as e:
            err = e
            time.sleep(0.3)
    else:
        print(f"FAIL iter {i}: {err}")
        sys.exit(1)
print("OK: 30 hooked connects echoed")
'
"#
                .to_string(),
            ],
            true,
            NodeType::Client,
        )
        .with_log_file(info.to_string_lossy().to_string())
        .with_log_format("json")
        .with_log_rolling(true)
        .with_log_max_size("1024")
        .with_log_max_backups(MAX_BACKUPS)
        .with_log_error_file(error.to_string_lossy().to_string())
        .boxed(),
    ];

    run_test!(tasks).await?;

    // Gather all info files (active info.log.tng + numbered backups
    // info.log.tng.1..N) and concat their content. Under rolling the hook +
    // main log lines are spread across the active file and the backups, so the
    // presence/panic checks apply to the combined content and the JSON/level
    // checks apply per file (each rotated fragment must still be valid JSON
    // and disjoint).
    let mut info_files: Vec<String> = fs::read_dir(dir.path())?
        .map(|e| e.unwrap().file_name().into_string().unwrap_or_default())
        .filter(|n| n == "info.log.tng" || n.starts_with("info.log.tng."))
        .collect();
    info_files.sort();
    let combined_info: String = info_files
        .iter()
        .map(|n| fs::read_to_string(dir.path().join(n)).unwrap_or_default())
        .collect();
    assert!(
        !combined_info.trim().is_empty(),
        "no info.log content across active + backups (flush on exit failed?)"
    );
    assert!(
        !combined_info.contains("panicked"),
        "panic marker found in info.log (active + backups):\n{}",
        combined_info
    );
    assert!(
        combined_info.contains(TUNNEL_MARKER),
        "info.log (active + backups) missing hook tunnel-established line; hook path broken under rolling"
    );
    for name in &info_files {
        let content = fs::read_to_string(dir.path().join(name)).unwrap_or_default();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let obj: Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("{name}: not JSON: {} — {}", e, line));
            let level = obj
                .get("level")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN");
            assert_ne!(
                level, "ERROR",
                "{name}: ERROR leaked into info.log (disjoint routing broken): {}",
                line
            );
        }
    }

    // error.log sanity: exists, ERROR-only, no hook INFO leaked, no panic.
    assert!(
        error.exists(),
        "error.log should be created when --log-error-file is set"
    );
    let error_contents = fs::read_to_string(&error).unwrap_or_default();
    assert!(
        !error_contents.contains("panicked"),
        "panic marker found in error.log:\n{}",
        error_contents
    );
    assert!(
        !error_contents.contains(HOOK_INIT_MARKER) && !error_contents.contains(TUNNEL_MARKER),
        "hook INFO leaked into error.log; level routing broken under rolling"
    );
    for line in error_contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let obj: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("error.log not JSON: {} — {}", e, line));
        let level = obj
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        assert_eq!(
            level, "ERROR",
            "non-ERROR line leaked into error.log (should be ERROR-only): {}",
            line
        );
    }

    // Rotation: at least one numbered backup must exist; no more than
    // max_backups; and every tempdir entry is info.log.tng* or error.log.tng*
    // (no per-pid files -> centralization holds under rolling).
    let mut names: Vec<String> = fs::read_dir(dir.path())?
        .map(|e| e.unwrap().file_name().into_string().unwrap_or_default())
        .collect();
    names.sort();
    let info_backups: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("info.log.tng."))
        .collect();
    assert!(
        !info_backups.is_empty(),
        "expected >=1 rolling backup (info.log.tng.N); rotation did not happen. entries: {:?}",
        names
    );
    assert!(
        info_backups.len() <= MAX_BACKUPS,
        "more than max_backups={MAX_BACKUPS} info backups: {:?}",
        info_backups
    );
    for n in &names {
        assert!(
            n.starts_with("info.log.tng") || n.starts_with("error.log.tng"),
            "unexpected file in tempdir (per-pid file? centralization broken under rolling): {}",
            n
        );
    }
    Ok(())
}

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

/// Marker the hook cdylib emits from its `#[ctor::ctor]` init. Finding it in
/// the main `info.log` proves a cdylib instance's logs flowed through the
/// collector (the `.so` is LD_PRELOAD'd only into the child, never the main
/// `tng` process).
const HOOK_INIT_MARKER: &str = "tng-hook: initialized";

/// Marker the hook emits per successful hooked connect (connect interception →
/// tunnel established). Finding it in `info.log` proves the connect
/// interception's INFO event flushed through the datagram sink (`libc::send`,
/// un-intercepted) to the collector without recursion or deadlock.
const TUNNEL_MARKER: &str = "tunnel established";

/// Threaded echo server on `port` (Server node), backgrounded for the test's
/// lifetime. One thread per connection so concurrent clients are handled in
/// parallel.
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

/// Assert centralization + anomaly invariants on `info` / `error` after a
/// `tng exec` run that exercises the hook:
///
/// - Both files are the only entries in the tempdir (no per-pid files).
/// - Every non-blank line in both files is valid JSON.
/// - Disjoint routing: `info.log` holds no ERROR-level record (ERROR+ goes to
///   `error.log` only); `error.log` holds only ERROR-level records.
/// - No panic/stack-trace markers leaked into either file.
/// - Hook INFO markers never leaked into `error.log`.
fn assert_logs_ok(dir: &TempDir, info: &std::path::Path, error: &std::path::Path) {
    let info_contents = fs::read_to_string(info).unwrap_or_else(|e| panic!("read info.log: {e}"));
    assert!(
        !info_contents.trim().is_empty(),
        "{:?} is empty (flush on exit failed?)",
        info
    );
    // No panic / stack-trace markers: a cdylib or main-process panic would
    // surface here as an anomaly.
    assert!(
        !info_contents.contains("panicked"),
        "panic marker found in info.log:\n{}",
        info_contents
    );
    for (i, line) in info_contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let obj: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("{:?}:{} not JSON: {} — {}", info, i, e, line));
        let level = obj
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        assert_ne!(
            level, "ERROR",
            "ERROR-level line leaked into info.log (disjoint routing broken): {}",
            line
        );
    }

    assert!(
        error.exists(),
        "error.log should be created when --log-error-file is set"
    );
    let error_contents = fs::read_to_string(error).unwrap_or_default();
    assert!(
        !error_contents.contains("panicked"),
        "panic marker found in error.log:\n{}",
        error_contents
    );
    // Hook INFO must never leak into the error file.
    assert!(
        !error_contents.contains(HOOK_INIT_MARKER),
        "hook INFO leaked into error.log; level routing broken"
    );
    assert!(
        !error_contents.contains(TUNNEL_MARKER),
        "hook tunnel-established INFO leaked into error.log; level routing broken"
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

    // No per-pid hook files: centralization means the cdylib never opens its
    // own pid-derived file, so the tempdir holds exactly the two merged logs.
    let mut names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap_or_default())
        .collect();
    names.sort();
    let mut expected = vec!["error.log.tng".to_string(), "info.log.tng".to_string()];
    expected.sort();
    assert_eq!(
        names, expected,
        "expected only merged info.log.tng + error.log.tng; per-pid files present: {:?}",
        names
    );
}

/// Recursion / no-deadlock smoke test: a shell-script target spawns ONE
/// subprocess (python — a grandchild of `tng exec`) that makes MANY real
/// hooked connects. Each connect runs the cdylib's `connect` interception,
/// which emits an INFO event that flushes via the datagram sink (`libc::send`)
/// to the collector. If the UDS path recursed into the hook's intercepted
/// `connect`/`sendto`, or deadlocked on the per-conn mutex, the very first
/// connect would hang or crash. Completing the run + finding the
/// tunnel-established marker in `info.log` proves the connect→trace→send path
/// is recursion-free over many iterations.
///
/// Requires `on-bin` (external tng binary + libtng_hook.so).
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
#[serial]
async fn hook_log_many_real_connects_no_recursion() -> Result<()> {
    let dir = TempDir::new()?;
    let info = dir.path().join("info.log.tng");
    let error = dir.path().join("error.log.tng");

    let tasks: Vec<Box<dyn Task>> = vec![
        echo_server(30010),
        // Server side: egress forwards 0.0.0.0:20010 -> 127.0.0.1:30010 (echo).
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {"in": {"host": "0.0.0.0", "port": 20010},
                                 "out": {"host": "127.0.0.1", "port": 30010}},
                    "no_ra": true
                }]
            }"#,
        )
        .boxed(),
        // Client side: tng exec with ingress hook + centralized logs. The
        // child is a shell script that runs one python (a grandchild of tng
        // exec) making 30 real hooked connects to the captured, non-local
        // 192.168.1.1:20010. Each connect retries briefly to ride out an
        // echo-server readiness race at startup; a recursion/deadlock would
        // hang past the per-task timeout regardless of retries.
        TngExecTask::new(
            r#"{
                "add_ingress": [{
                    "hook": {"capture_dst": [{"port": 20010}]},
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
    s.connect(("192.168.1.1", 20010))
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
        .with_log_error_file(error.to_string_lossy().to_string())
        .boxed(),
    ];

    run_test!(tasks).await?;

    // Completing the run is the no-recursion proof (a recursion/deadlock would
    // hang past the per-task timeout). The log content confirms the
    // connect→trace→send path delivered to the collector, repeatedly.
    let info_contents = fs::read_to_string(&info)?;
    let tunnel_count = info_contents.matches(TUNNEL_MARKER).count();
    assert!(
        tunnel_count >= 20,
        "expected >=20 '{}' lines in info.log (30 hooked connects), got {}; centralization or the hook send path is broken",
        TUNNEL_MARKER,
        tunnel_count
    );
    assert!(
        info_contents.contains(HOOK_INIT_MARKER),
        "info.log missing hook init line; centralization not wired"
    );
    assert_logs_ok(&dir, &info, &error);
    Ok(())
}

/// Fork / multi-producer test: a shell-script target spawns FIVE concurrent
/// subprocesses (fork+exec), each a grandchild of `tng exec`, each making a
/// real hooked connect. Each fork+exec'd subprocess reloads the cdylib
/// (`#[ctor::ctor]` re-runs), opens its OWN datagram socket to the single
/// collector, and sends its hook logs there. If the datagram collector broke
/// with multiple senders, or fork+exec didn't re-init the cdylib, the
/// subprocesses' logs would vanish or the run would hang. Finding >=5 init
/// lines + tunnel-established lines in `info.log` proves the 1-collector-fd,
/// N-producer datagram model works under fork.
///
/// Requires `on-bin` (external tng binary + libtng_hook.so).
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
#[serial]
async fn hook_log_forked_subprocesses_merge_into_collector() -> Result<()> {
    let dir = TempDir::new()?;
    let info = dir.path().join("info.log.tng");
    let error = dir.path().join("error.log.tng");

    let tasks: Vec<Box<dyn Task>> = vec![
        echo_server(30011),
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {"in": {"host": "0.0.0.0", "port": 20011},
                                 "out": {"host": "127.0.0.1", "port": 30011}},
                    "no_ra": true
                }]
            }"#,
        )
        .boxed(),
        // Client side: tng exec with ingress hook + centralized logs. The
        // child shell script spawns 5 concurrent python subprocesses
        // (grandchildren of tng exec), each making one hooked connect; it
        // waits for all and exits non-zero if any failed. Each python is
        // fork+exec'd, so the cdylib ctor re-runs and each connects its own
        // datagram socket to the collector.
        TngExecTask::new(
            r#"{
                "add_ingress": [{
                    "hook": {"capture_dst": [{"port": 20011}]},
                    "no_ra": true
                }]
            }"#
            .to_string(),
            vec![
                "sh".to_string(),
                "-c".to_string(),
                r#"
pids=""
for i in 1 2 3 4 5; do
  python3 -c '
import socket, time, sys
err = None
for a in range(5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("192.168.1.1", 20011))
        s.sendall(b"hello")
        s.shutdown(socket.SHUT_WR)
        d = s.recv(4096)
        s.close()
        assert d == b"hello", f"expected hello, got: {d}"
        print("OK")
        sys.exit(0)
    except Exception as e:
        err = e
        time.sleep(0.3)
print(f"FAIL: {err}")
sys.exit(1)
' &
  pids="$pids $!"
done
rc=0
for p in $pids; do wait "$p" || rc=1; done
exit $rc
"#
                .to_string(),
            ],
            true,
            NodeType::Client,
        )
        .with_log_file(info.to_string_lossy().to_string())
        .with_log_format("json")
        .with_log_error_file(error.to_string_lossy().to_string())
        .boxed(),
    ];

    run_test!(tasks).await?;

    // Completing the run (exit 0) proves no fork/deadlock failure. The log
    // content proves each fork+exec'd grandchild re-init'd the cdylib AND
    // reached the single collector through its own datagram socket.
    let info_contents = fs::read_to_string(&info)?;
    let init_count = info_contents.matches(HOOK_INIT_MARKER).count();
    // 5 python grandchildren + the sh parent each re-init the cdylib (>=5
    // proves multi-process; allows a lossy drop under the datagram lossy
    // contract).
    assert!(
        init_count >= 5,
        "expected >=5 '{}' lines in info.log (5 fork+exec'd grandchildren), got {}; fork+exec re-init or multi-producer collection is broken",
        HOOK_INIT_MARKER,
        init_count
    );
    assert!(
        info_contents.contains(TUNNEL_MARKER),
        "info.log missing hook tunnel-established line; centralization not wired under fork"
    );
    assert_logs_ok(&dir, &info, &error);
    Ok(())
}

/// Deep-nesting / great-grandchild test: verifies `LD_PRELOAD` + the hook-log
/// env contract propagate through TWO levels of fork+exec, and the
/// great-grandchild's cdylib re-inits and reaches the collector.
///
/// Process tree: `tng exec` → `sh` (child) → `python3` A (grandchild, writes
/// the connect script and spawns B) → `python3` B (great-grandchild, makes
/// the hooked connect). Each exec reloads `libtng_hook.so`, so B's `#[ctor]`
/// re-runs, opens its own datagram socket to the collector, and its init +
/// tunnel-established records must land in `info.log`.
///
/// Requires `on-bin` (external tng binary + libtng_hook.so).
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
#[serial]
async fn hook_log_great_grandchild_reaches_collector() -> Result<()> {
    let dir = TempDir::new()?;
    let info = dir.path().join("info.log.tng");
    let error = dir.path().join("error.log.tng");

    let tasks: Vec<Box<dyn Task>> = vec![
        echo_server(30012),
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {"in": {"host": "0.0.0.0", "port": 20012},
                                 "out": {"host": "127.0.0.1", "port": 30012}},
                    "no_ra": true
                }]
            }"#,
        )
        .boxed(),
        // Client side: tng exec with ingress hook + centralized logs. The
        // child shell script writes a connect script to a temp file, then
        // runs python3 A which spawns python3 B (great-grandchild of tng exec)
        // to run it. B makes the real hooked connect.
        TngExecTask::new(
            r#"{
                "add_ingress": [{
                    "hook": {"capture_dst": [{"port": 20012}]},
                    "no_ra": true
                }]
            }"#
            .to_string(),
            vec![
                "sh".to_string(),
                "-c".to_string(),
                r#"
cat > /tmp/tng_deep_conn.py <<'PYEOF'
import socket, time, sys
err = None
for a in range(5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("192.168.1.1", 20012))
        s.sendall(b"deep")
        s.shutdown(socket.SHUT_WR)
        d = s.recv(4096)
        s.close()
        assert d == b"deep", f"expected deep, got: {d}"
        print("OK deep")
        sys.exit(0)
    except Exception as e:
        err = e
        time.sleep(0.3)
print(f"FAIL deep: {err}")
sys.exit(1)
PYEOF
python3 -c 'import subprocess, sys; sys.exit(subprocess.run([sys.executable, "/tmp/tng_deep_conn.py"]).returncode)'
"#
                .to_string(),
            ],
            true,
            NodeType::Client,
        )
        .with_log_file(info.to_string_lossy().to_string())
        .with_log_format("json")
        .with_log_error_file(error.to_string_lossy().to_string())
        .boxed(),
    ];

    run_test!(tasks).await?;

    // The great-grandchild (python3 B) re-init'd the cdylib and reached the
    // collector. >=3 init lines = sh + python3 A + python3 B (allows a lossy
    // drop); the tunnel marker proves B's hooked connect flowed through.
    let info_contents = fs::read_to_string(&info)?;
    let init_count = info_contents.matches(HOOK_INIT_MARKER).count();
    assert!(
        init_count >= 3,
        "expected >=3 '{}' lines in info.log (sh + python A + python B great-grandchild), got {}; deep fork+exec propagation broken",
        HOOK_INIT_MARKER,
        init_count
    );
    assert!(
        info_contents.contains(TUNNEL_MARKER),
        "info.log missing hook tunnel-established line; great-grandchild connect did not reach the collector"
    );
    assert_logs_ok(&dir, &info, &error);
    Ok(())
}

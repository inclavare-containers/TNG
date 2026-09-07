use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use tempfile::TempDir;
use tng_testsuite::{
    run_test,
    task::{tng::TngExecTask, NodeType, Task as _},
};

/// Integration test for centralized hook log IPC: when `tng exec` spawns a
/// hook child with a regular `--log-file` (a real or creatable path), the
/// cdylib (LD_PRELOAD'd into the child) does NOT write per-pid files. Instead
/// it frames each log record and streams it over an auto-injected
/// abstract-namespace Unix domain socket to a collector in the `tng exec`
/// process, which merges hook records into the SAME `info.log`/`error.log`
/// the main process owns (the collector owns rolling; the cdylib owns none).
///
/// Part 1 (`centralized_hook_logs_merge_into_single_files`): a valid `tng
/// exec` run. The hook child's `#[ctor::ctor]` init emits the INFO line
/// `tng-hook: initialized`. `libtng_hook.so` is LD_PRELOAD'd only into the
/// child, never into the main `tng` process, so that line can only have
/// reached the main `info.log` through the collector, the smoking gun for
/// centralization. ERROR events are disjoint from INFO: `error.log` is
/// created but carries no INFO, and the hook INFO never leaks into it. No
/// per-pid `info.log.<pid>.tng` file is left behind; the tempdir holds only
/// the two merged logs.
///
/// Part 2 (`non_regular_log_path_does_not_hang`): `--log-file /dev/null`
/// is a character device, so `path_supports_rolling` is false and the
/// collector is not started. The cdylib opens /dev/null directly and appends;
/// no collector, no abstract socket, no per-pid file, and the run must not
/// hang. `run_test!` enforces a per-task timeout, so completing within it
/// proves the direct path does not stall waiting for a collector that was
/// never bound. The test cannot read /dev/null back, so it asserts only the
/// no-hang property, not centralization.
///
/// Requires `on-bin` (external tng binary + libtng_hook.so).

/// The hook child emits this INFO line from its `#[ctor::ctor]` init. Because
/// `libtng_hook.so` is LD_PRELOAD'd only into the child (never the main `tng`
/// process), finding this line in the main `info.log` proves the child's logs
/// flowed through the collector into the merged file.
const HOOK_INIT_MARKER: &str = "tng-hook: initialized";

/// Part 1: valid run → hook child INFO merged into info.log; error.log
/// disjoint (created, no INFO leaked); no per-pid files.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn centralized_hook_logs_merge_into_single_files() -> Result<()> {
    let dir = TempDir::new()?;
    let info = dir.path().join("info.log.tng");
    let error = dir.path().join("error.log.tng");

    let task = TngExecTask::new(
        r#"{"add_ingress": [{"hook": {"capture_dst": [{"port": 9999}]}, "no_ra": true}]}"#
            .to_string(),
        vec![
            "python3".to_string(),
            "-c".to_string(),
            concat!(
                "import socket, errno, sys\n",
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
                "try:\n",
                "    s.connect(('0.0.0.0', 9999))\n",
                "    print('FAIL: connect to 0.0.0.0 should have failed')\n",
                "    sys.exit(1)\n",
                "except OSError as e:\n",
                "    if e.errno == errno.ECONNREFUSED:\n",
                "        print('OK')\n",
                "    else:\n",
                "        sys.exit(1)\n",
                "finally:\n",
                "    s.close()\n",
            )
            .to_string(),
        ],
        true,
        NodeType::Client,
    )
    .with_log_file(info.to_string_lossy().to_string())
    .with_log_format("json")
    .with_log_error_file(error.to_string_lossy().to_string())
    .boxed();

    run_test!(vec![task]).await?;

    // info.log: non-empty JSON Lines.
    let info_contents = fs::read_to_string(&info)?;
    assert!(
        !info_contents.trim().is_empty(),
        "{:?} is empty (flush on exit failed?)",
        info
    );
    // The hook child's ctor INFO line can only land here via the collector.
    assert!(
        info_contents.contains(HOOK_INIT_MARKER),
        "info.log missing hook child init line {:?}; centralization not wired",
        HOOK_INIT_MARKER
    );
    // Every non-blank line is valid JSON (both main and hook records merge
    // into the same JSON Lines stream).
    for (i, line) in info_contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        serde_json::from_str::<Value>(line)
            .with_context(|| format!("{:?}:{} not JSON: {}", info, i, line))?;
    }

    // error.log: created (disjoint routing), but no INFO leaked into it.
    assert!(
        error.exists(),
        "error.log should be created when --log-error-file is set"
    );
    let error_contents = fs::read_to_string(&error)?;
    assert!(
        !error_contents.contains(HOOK_INIT_MARKER),
        "hook INFO leaked into error.log; level routing broken"
    );
    for line in error_contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let obj: Value = serde_json::from_str(line)?;
        let level = obj
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        assert_ne!(level, "INFO", "INFO line leaked into error.log: {}", line);
    }

    // No per-pid hook files: centralization means the cdylib never opens its
    // own pid-derived file, so the tempdir must hold exactly the two merged
    // logs and nothing else.
    let mut names: Vec<String> = fs::read_dir(dir.path())?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().into_string().unwrap_or_default())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["error.log.tng".to_string(), "info.log.tng".to_string()],
        "expected only merged info.log.tng + error.log.tng; per-pid files present: {:?}",
        names
    );

    Ok(())
}

/// Part 2: `--log-file /dev/null` (char device) → not centralized. The
/// collector is never started and the cdylib writes directly to /dev/null; the
/// run must complete without hanging (no collector socket to stall on). The
/// test cannot read /dev/null back, so it asserts only the no-hang property
/// via the `run_test!` per-task timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn non_regular_log_path_does_not_hang() -> Result<()> {
    let task = TngExecTask::new(
        r#"{"add_ingress": [{"hook": {"capture_dst": [{"port": 9999}]}, "no_ra": true}]}"#
            .to_string(),
        vec![
            "python3".to_string(),
            "-c".to_string(),
            concat!(
                "import socket, errno, sys\n",
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
                "try:\n",
                "    s.connect(('0.0.0.0', 9999))\n",
                "    print('FAIL: connect to 0.0.0.0 should have failed')\n",
                "    sys.exit(1)\n",
                "except OSError as e:\n",
                "    if e.errno == errno.ECONNREFUSED:\n",
                "        print('OK')\n",
                "    else:\n",
                "        sys.exit(1)\n",
                "finally:\n",
                "    s.close()\n",
            )
            .to_string(),
        ],
        true,
        NodeType::Client,
    )
    .with_log_file("/dev/null".to_string())
    .with_log_format("json")
    .boxed();

    // run_test! enforces a per-task timeout; completing within it proves the
    // cdylib's direct /dev/null path does not stall on a missing collector.
    run_test!(vec![task]).await?;
    Ok(())
}

use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use tempfile::TempDir;
use tng_testsuite::{
    run_test,
    task::{tng::TngExecTask, NodeType, Task as _},
};

/// Integration test for the log pipeline: JSON format + size-based rolling +
/// the hook's per-pid separate file + flush-on-exit.
///
/// Runs `tng exec --log-format json --log-file <tmp>/info.log.tng \
///   --log-rolling --log-max-size 50 --log-max-backups 3` with a child that
/// connects to 0.0.0.0:9999 (rejected by the hook) and exits 0. After exit:
///   1. the main active log is JSON Lines (non-empty → main flushed on exit
///      via the WorkerGuard drop);
///   2. at least one rotation backup `info.log.tng.<N>` exists (max-size 50
///      forces rotation, since the banner alone exceeds it) and is JSON;
///   3. the hook wrote a SEPARATE pid-derived file `info.log.<pid>.tng`
///      (not the parent's file), non-empty + JSON (proves per-pid file +
///      the `#[ctor::dtor]` flush).
///
/// Mirrors `connect_reject_null_ip.rs` for the hook config + child; adds the
/// log flags via the `with_log_*` builders on `TngExecTask`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test() -> Result<()> {
    let dir = TempDir::new()?;
    let log_path = dir.path().join("info.log.tng");

    let task = TngExecTask::new(
        // Minimal ingress hook capture rule — just enough to load the hook.
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
                "        print('OK: connect to 0.0.0.0 correctly rejected with ECONNREFUSED')\n",
                "    else:\n",
                "        print(f'FAIL: expected ECONNREFUSED (111), got errno={e.errno}')\n",
                "        sys.exit(1)\n",
                "finally:\n",
                "    s.close()\n",
            )
            .to_string(),
        ],
        true, // stop_after_exit: test is complete once the child exits
        NodeType::Client,
    )
    .with_log_file(log_path.to_string_lossy().to_string())
    .with_log_format("json")
    .with_log_rolling(true)
    .with_log_max_size("50")
    .with_log_max_backups(3)
    .boxed();

    run_test!(vec![task]).await?;

    // --- Post-exit assertions ---

    // 1. Main active log: exists, non-empty, JSON Lines.
    let active = dir.path().join("info.log.tng");
    assert_json_lines(&active).with_context(|| format!("main active log {active:?}"))?;

    // 2. Rotation: at least one info.log.tng.<N> backup exists and is JSON.
    let mut backups: Vec<String> = entry_names(dir.path())?
        .into_iter()
        .filter(|n| {
            n.starts_with("info.log.tng.")
                && n.as_bytes()
                    .last()
                    .map(|b| b.is_ascii_digit())
                    .unwrap_or(false)
        })
        .collect();
    backups.sort();
    assert!(
        !backups.is_empty(),
        "expected at least one rotation backup (info.log.tng.<N>); dir contents: {:?}",
        entry_names(dir.path())?
    );
    for b in &backups {
        assert_json_lines(&dir.path().join(b)).with_context(|| format!("rotation backup {b:?}"))?;
    }

    // 3. Hook pid-derived file: info.log.<pid>.tng (NOT the active file, NOT a
    //    main backup), non-empty + JSON — proves the separate per-pid file and
    //    the #[ctor::dtor] flush on exit.
    let hook_files: Vec<String> = entry_names(dir.path())?
        .into_iter()
        .filter(|n| {
            n.starts_with("info.log.")
                && n.ends_with(".tng")
                && n != "info.log.tng"
                && !n.starts_with("info.log.tng.")
        })
        .collect();
    assert!(
        !hook_files.is_empty(),
        "expected a hook pid-derived file info.log.<pid>.tng; dir contents: {:?}",
        entry_names(dir.path())?
    );
    for h in &hook_files {
        assert_json_lines(&dir.path().join(h)).with_context(|| format!("hook pid file {h:?}"))?;
    }

    Ok(())
}

/// Assert `path` exists, is non-empty, and every non-blank line is valid JSON.
fn assert_json_lines(path: &std::path::Path) -> Result<()> {
    let content = fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
    assert!(
        !content.trim().is_empty(),
        "{path:?} is empty (flush on exit failed?)"
    );
    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        serde_json::from_str::<Value>(line)
            .with_context(|| format!("{path:?}:{i} not JSON: {line:?}"))?;
    }
    Ok(())
}

/// Sorted file names in a directory (non-recursive).
fn entry_names(dir: &std::path::Path) -> Result<Vec<String>> {
    let mut names: Vec<String> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().into_string().unwrap_or_default())
        .collect();
    names.sort();
    Ok(names)
}

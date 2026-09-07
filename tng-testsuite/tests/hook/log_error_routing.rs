use anyhow::Result;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;
use tng_testsuite::{
    run_test,
    task::{tng::binary_locator::resolve_tng_binary, tng::TngExecTask, NodeType, Task as _},
};

/// Integration test for `--log-error-file`: ERROR+ events go to the error
/// file ONLY; non-error events go to the info file ONLY (disjoint).
///
/// Part 1 (`test_non_error_routes_to_info`): a valid `tng exec` run (child
/// exits 0) — INFO events land in info.log, error.log is created but empty
/// (no ERROR events in a clean run).
///
/// Part 2 (`test_error_routes_to_error_file`): `tng exec --config-content
/// '{}'` bails with an ERROR ("requires at least one hook-mode entry") — the
/// ERROR lands in error.log, the INFO banner lands in info.log. Disjoint.
///
/// Requires `on-bin` (external tng binary + libtng_hook.so).

/// Part 1: valid run → INFO in info.log, error.log empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_non_error_routes_to_info() -> Result<()> {
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

    // info.log: non-empty, all non-ERROR JSON lines.
    assert_json_lines_level(&info, false)?;
    // error.log: created (exists) but empty (no ERROR events in a clean run).
    assert!(
        error.exists(),
        "error.log should be created when --log-error-file is set"
    );
    assert!(
        fs::read_to_string(&error)?.trim().is_empty(),
        "error.log should be empty (no ERROR events in a clean run)"
    );
    Ok(())
}

/// Part 2: `{}` config bails with ERROR → ERROR in error.log, INFO in info.log.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_error_routes_to_error_file() -> Result<()> {
    let dir = TempDir::new()?;
    let info = dir.path().join("info.log.tng");
    let error = dir.path().join("error.log.tng");

    let tng_bin = resolve_tng_binary()?;
    // `tng exec --config-content '{}'` bails "requires at least one hook-mode
    // entry" → exits non-zero. We don't care about the exit code; we check the
    // log files written before the bail.
    let _output = tokio::process::Command::new(&tng_bin)
        .arg("exec")
        .arg("--config-content")
        .arg("{}")
        .arg("--log-format")
        .arg("json")
        .arg("--log-file")
        .arg(&info)
        .arg("--log-error-file")
        .arg(&error)
        .arg("--")
        .arg("echo")
        .arg("hi")
        .output()
        .await?;

    // The process exited (non-zero expected — {} config bails).
    // The tracing subscriber was initialized before the bail, so both files
    // should have content flushed via the WorkerGuard drop.

    // info.log: has INFO events (banner etc.), NO ERROR.
    assert_json_lines_level(&info, false)?;
    // error.log: has the ERROR event, NO INFO.
    assert_json_lines_level(&error, true)?;
    Ok(())
}

/// Assert every non-blank line in `path` is valid JSON and matches the
/// expected error-ness: `expect_error=true` → all lines are ERROR level;
/// `expect_error=false` → no line is ERROR level.
fn assert_json_lines_level(path: &std::path::Path, expect_error: bool) -> Result<()> {
    let content = fs::read_to_string(path)?;
    assert!(
        !content.trim().is_empty(),
        "{:?} is empty (flush on exit failed?)",
        path
    );
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let obj: Value = serde_json::from_str(line)
            .map_err(|e| anyhow::anyhow!("{:?}:{} not JSON: {} — {}", path, i, e, line))?;
        let level = obj
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        let is_error = level == "ERROR";
        assert!(
            is_error == expect_error,
            "{:?}:{} level={} expected_error={}",
            path,
            i,
            level,
            expect_error
        );
    }
    Ok(())
}

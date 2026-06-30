use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{tng::TngExecTask, Task as _},
};

/// Test that the connect hook rejects connections to 0.0.0.0 (NULL IP).
///
/// Connecting to the unspecified address 0.0.0.0 is often an application bug
/// and should not be routed through the proxy. This mirrors proxychains-ng's
/// behavior (src/libproxychains.c:702-705).
///
/// The test runs a Python script inside `tng exec` (which loads libtng_hook.so
/// via LD_PRELOAD) that attempts to connect to 0.0.0.0:9999 and verifies that
/// the connect fails with errno ECONNREFUSED (111).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test() -> Result<()> {
    run_test!(vec![TngExecTask::new(
        // Minimal config: a dummy ingress hook capture rule — just enough to load the hook.
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
        true, // stop_after_exit: test is complete once this exits
    )
    .boxed(),])
    .await?;
    Ok(())
}

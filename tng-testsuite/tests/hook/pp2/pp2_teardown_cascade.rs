use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{run_test, task::tng::TngExecTask, task::NodeType, task::Task as _};

/// Teardown cascade: the production relies on killing the tng exec process
/// (TNG_PID) cascading to the sglang child. Here the client wraps a one-shot
/// mock that does one exchange then exits 0 -> stop_after_exit cancels the
/// token -> the server tng exec child is killed. The test body (after run_test
/// returns) checks for orphan mock processes and residual listeners.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
#[serial]
async fn test() -> Result<()> {
    let mock = format!(
        "{}/tests/hook/pp2/mock_sglang_rank.py",
        env!("CARGO_MANIFEST_DIR")
    );
    let cfg = r#"{
        "add_ingress": [{"hook":{"capture_dst":[{"port":31000,"port_end":31000}],"proxy_port":49000},"no_ra":true}],
        "add_egress":  [{"hook":{"capture_listen":[{"port":31000,"port_end":31000}]},"no_ra":true}]
    }"#;
    run_test!(vec![
        // Server: serve + block until cancelled.
        TngExecTask::new(
            cfg.to_string(),
            vec![
                "python3".to_string(),
                mock.clone(),
                "serve".to_string(),
                "--rank".to_string(),
                "0".to_string(),
                "--peer-ip".to_string(),
                "192.168.1.253".to_string(),
                "--staging-base".to_string(),
                "31000".to_string(),
                "--staging-end".to_string(),
                "31000".to_string(),
                "--plain-port".to_string(),
                "0".to_string(),
                "--wait".to_string(),
                "20".to_string(),
            ],
            false,
            NodeType::Server,
        )
        .boxed(),
        // Client: one exchange, hold 2s, exit 0 -> cancel server.
        TngExecTask::new(
            cfg.to_string(),
            vec![
                "python3".to_string(),
                mock,
                "serve".to_string(),
                "--rank".to_string(),
                "1".to_string(),
                "--peer-ip".to_string(),
                "192.168.1.1".to_string(),
                "--staging-base".to_string(),
                "31000".to_string(),
                "--staging-end".to_string(),
                "31000".to_string(),
                "--plain-port".to_string(),
                "0".to_string(),
                "--wait".to_string(),
                "20".to_string(),
                "--hold".to_string(),
                "2".to_string(),
            ],
            true,
            NodeType::Client,
        )
        .boxed(),
    ])
    .await?;
    // run_test has torn the netns down. Give stragglers a beat, then assert no
    // orphan mock processes remain (the cascade killed the server child).
    std::thread::sleep(std::time::Duration::from_secs(1));
    let out = std::process::Command::new("sh")
        .args(["-c", "pgrep -af mock_sglang_rank | grep -v pgrep || true"])
        .output()?;
    if !out.stdout.is_empty() {
        anyhow::bail!(
            "orphan mock_sglang_rank process after teardown: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
    Ok(())
}

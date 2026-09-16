use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{run_test, task::tng::TngExecTask, task::NodeType, task::Task as _};

/// Stress-correctness under large sustained transfers (simulating PP layer
/// activation handoff, MB-scale). Verifies data integrity (no truncation,
/// reordering, or corruption) over the hook tunnel under load. Throughput and
/// latency are printed for observation but are NOT pass/fail thresholds (CI
/// throughput is too noisy to gate on).
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    let mock = format!(
        "{}/tests/hook/pp2/mock_sglang_rank.py",
        env!("CARGO_MANIFEST_DIR")
    );
    let cfg = r#"{
        "add_ingress": [{"hook":{"capture_dst":[{"port":31000,"port_end":31002}],"proxy_port":49000},"no_ra":true}],
        "add_egress":  [{"hook":{"capture_listen":[{"port":31000,"port_end":31002}]},"no_ra":true}]
    }"#;
    run_test!(vec![
        TngExecTask::new(
            cfg.to_string(),
            vec![
                "python3".to_string(),
                mock.clone(),
                "bench".to_string(),
                "--rank".to_string(),
                "0".to_string(),
                "--peer-ip".to_string(),
                "192.168.1.253".to_string(),
                // Match the client's staging range so the server only binds
                // capture_listen ports 31000-31002 instead of the default
                // 31000-31005 (the extra binds are uncaptured/unused).
                "--staging-base".to_string(),
                "31000".to_string(),
                "--staging-end".to_string(),
                "31002".to_string(),
            ],
            false,
            NodeType::Server,
        )
        .boxed(),
        // 1 MiB frames, 4 conns/port over 3 ports, 8s sustained; integrity
        // checked per frame; throughput printed.
        TngExecTask::new(
            cfg.to_string(),
            vec![
                "python3".to_string(),
                mock,
                "bench".to_string(),
                "--rank".to_string(),
                "1".to_string(),
                "--peer-ip".to_string(),
                "192.168.1.1".to_string(),
                "--staging-base".to_string(),
                "31000".to_string(),
                "--staging-end".to_string(),
                "31002".to_string(),
                "--payload-size".to_string(),
                "1048576".to_string(),
                "--concurrency".to_string(),
                "4".to_string(),
                "--duration".to_string(),
                "8".to_string(),
            ],
            true,
            NodeType::Client,
        )
        .boxed(),
    ])
    .await?;
    Ok(())
}

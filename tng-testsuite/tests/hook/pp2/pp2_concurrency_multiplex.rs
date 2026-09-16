use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{run_test, task::tng::TngExecTask, task::NodeType, task::Task as _};

/// multiplex:false means one TLS tunnel per connection. With 6 staging ports x
/// N concurrent connections, all tunnels must coexist without cross-talk,
/// corruption, or resource exhaustion. Each connection's echoed payload carries
/// a per-connection id verified on receipt.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    let mock = format!(
        "{}/tests/hook/pp2/mock_sglang_rank.py",
        env!("CARGO_MANIFEST_DIR")
    );
    let cfg = r#"{
        "add_ingress": [{"hook":{"capture_dst":[{"port":31000,"port_end":31005}],"proxy_port":49000},"no_ra":true,"rats_tls":{"multiplex":false}}],
        "add_egress":  [{"hook":{"capture_listen":[{"port":31000,"port_end":31005}]},"no_ra":true,"rats_tls":{"multiplex":false}}]
    }"#;
    run_test!(vec![
        // rank0: bind+echo all staging ports, block.
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
            ],
            false,
            NodeType::Server,
        )
        .boxed(),
        // rank1: 6 ports x 8 conns = 48 concurrent tunnels, 256B frames,
        // 6s of sustained exchange; verify integrity (no cross-talk).
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
                "--payload-size".to_string(),
                "256".to_string(),
                "--concurrency".to_string(),
                "8".to_string(),
                "--duration".to_string(),
                "6".to_string(),
            ],
            true,
            NodeType::Client,
        )
        .boxed(),
    ])
    .await?;
    Ok(())
}

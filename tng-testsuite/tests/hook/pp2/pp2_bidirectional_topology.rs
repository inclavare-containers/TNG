use anyhow::Result;
use tng_testsuite::{run_test, task::tng::TngExecTask, task::NodeType, task::Task as _};

/// Bidirectional pp2 hook topology + port-range capture + out-of-range non-capture.
///
/// Both nodes run `tng exec` with the production-shaped config: ingress
/// `capture_dst` over the 31000-31005 range (+ `proxy_port:49000`) AND egress
/// `capture_listen` over the same range, `multiplex:false`, `no_ra:true`. Each
/// side wraps the mock sglang rank. The mock binds the staging range (captured
/// by egress) and connects to the peer's staging range (captured by ingress),
/// so traffic flows both ways through the tunnel. An out-of-range plain port
/// (31010) is bound directly and must be reachable directly (NOT captured),
/// proving no over-capture that would silently leak plaintext.
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
        // Server (rank0): bind staging range + plain port, connect to peer,
        // verify, then block (stop_after_exit=false) until cancelled.
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
                "--wait".to_string(),
                "30".to_string(),
            ],
            false,
            NodeType::Server,
        )
        .boxed(),
        // Client (rank1): bind staging range + plain port, connect to peer,
        // verify, hold briefly so the peer's exchange lands, then exit 0 ->
        // stop_after_exit cancels the test.
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
                "--wait".to_string(),
                "30".to_string(),
                "--hold".to_string(),
                "3".to_string(),
            ],
            true,
            NodeType::Client,
        )
        .boxed(),
    ])
    .await?;
    Ok(())
}

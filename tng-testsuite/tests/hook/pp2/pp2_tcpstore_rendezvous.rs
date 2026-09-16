use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{run_test, task::tng::TngExecTask, task::NodeType, task::Task as _};

/// TCPStore rendezvous: rank0 captures 32000 in BOTH ingress capture_dst AND
/// egress capture_listen (so its local TP ranks connecting to the local store
/// also go through the tunnel, keeping plaintext off the hijacked listener);
/// rank1 captures 32000 only in ingress capture_dst. Verifies cross-node
/// rendezvous and that rank0's local connect to 32000 does not break under
/// capture_local_traffic=true (loopback-through-tunnel) and =false (direct).
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    let mock = format!(
        "{}/tests/hook/pp2/mock_sglang_rank.py",
        env!("CARGO_MANIFEST_DIR")
    );
    // rank0: 32000 captured on both sides (production shape).
    let cfg0 = r#"{
        "add_ingress": [{"hook":{"capture_dst":[{"port":32000}],"proxy_port":49000},"no_ra":true}],
        "add_egress":  [{"hook":{"capture_listen":[{"port":32000}]},"no_ra":true}]
    }"#;
    // rank1: 32000 captured only on ingress (connect side).
    let cfg1 = r#"{
        "add_ingress": [{"hook":{"capture_dst":[{"port":32000}],"proxy_port":49000},"no_ra":true}]
    }"#;
    run_test!(vec![
        // rank0 hosts the TCPStore (bind 32000, captured by egress). rank0 does
        // NOT pass --connect-store: its peer (rank1) hosts no store, so a
        // connect would only fail. Local TP-rank-to-store traffic is a separate
        // concern not modeled here; the egress capture_listen already routes
        // such loopback through the tunnel.
        TngExecTask::new(
            cfg0.to_string(),
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
                "--store-server".to_string(),
                "--plain-port".to_string(),
                "0".to_string(),
                "--wait".to_string(),
                "30".to_string(),
            ],
            false,
            NodeType::Server,
        )
        .boxed(),
        // rank1 connects to rank0's store (rendezvous).
        TngExecTask::new(
            cfg1.to_string(),
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
                "--store-port".to_string(),
                "32000".to_string(),
                "--connect-store".to_string(),
                "--plain-port".to_string(),
                "0".to_string(),
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

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_capture_local_traffic_true() -> Result<()> {
    let mock = format!(
        "{}/tests/hook/pp2/mock_sglang_rank.py",
        env!("CARGO_MANIFEST_DIR")
    );
    let cfg0 = r#"{
        "add_ingress": [{"hook":{"capture_dst":[{"port":32000}],"proxy_port":49000},"no_ra":true}],
        "add_egress":  [{"hook":{"capture_listen":[{"port":32000}],"capture_local_traffic":true},"no_ra":true}]
    }"#;
    let cfg1 = r#"{
        "add_ingress": [{"hook":{"capture_dst":[{"port":32000}],"proxy_port":49000},"no_ra":true}]
    }"#;
    run_test!(vec![
        TngExecTask::new(
            cfg0.to_string(),
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
                "--store-server".to_string(),
                "--plain-port".to_string(),
                "0".to_string(),
                "--wait".to_string(),
                "30".to_string()
            ],
            false,
            NodeType::Server,
        )
        .boxed(),
        TngExecTask::new(
            cfg1.to_string(),
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
                "--store-port".to_string(),
                "32000".to_string(),
                "--connect-store".to_string(),
                "--plain-port".to_string(),
                "0".to_string(),
                "--wait".to_string(),
                "30".to_string(),
                "--hold".to_string(),
                "3".to_string()
            ],
            true,
            NodeType::Client,
        )
        .boxed(),
    ])
    .await?;
    Ok(())
}

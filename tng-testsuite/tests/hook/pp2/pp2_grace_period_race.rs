use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{run_test, task::tng::TngExecTask, task::NodeType, task::Task as _};

/// Startup race: TNG's ingress proxy listener (49000) is up before rank0's
/// TCPStore backend binds 32000. A connect in that window must fail cleanly
/// within a bounded timeout (no infinite hang), and a connect after the bind
/// must succeed. This is the root cause the production grace period works
/// around; the test pins TNG's own behavior in the race window.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    let mock = format!(
        "{}/tests/hook/pp2/mock_sglang_rank.py",
        env!("CARGO_MANIFEST_DIR")
    );
    // rank0 delays binding 32000 by 6s; its tng exec + hook are up first.
    let cfg0 = r#"{
        "add_egress": [{"hook":{"capture_listen":[{"port":32000}]},"no_ra":true}]
    }"#;
    let cfg1 = r#"{
        "add_ingress": [{"hook":{"capture_dst":[{"port":32000}],"proxy_port":49000},"no_ra":true}]
    }"#;
    run_test!(vec![
        // rank0: host store but delay the bind to open the race window. Pass an
        // EMPTY staging range (31000..30999) so the server does no staging
        // bind/connect: rank1 is a connect-once probe that hosts no staging
        // servers, so any staging connect from rank0 would only retry for the
        // full --wait window and could fail the test on exit code 2 if the
        // client ever ran past 20s. With an empty range, --wait is irrelevant.
        TngExecTask::new(
            cfg0.to_string(),
            vec![
                "python3".to_string(), mock.clone(),
                "serve".to_string(), "--rank".to_string(), "0".to_string(),
                "--peer-ip".to_string(), "192.168.1.253".to_string(),
                "--staging-base".to_string(), "31000".to_string(),
                "--staging-end".to_string(), "30999".to_string(),
                "--store-server".to_string(),
                "--delay-store-bind".to_string(), "6".to_string(),
                "--plain-port".to_string(), "0".to_string(),
                "--wait".to_string(), "20".to_string(),
            ],
            false,
            NodeType::Server,
        ).boxed(),
        // rank1: probe 32000 during the window (expect clean fail), then wait
        // for the bind and probe again (expect success), then exit.
        TngExecTask::new(
            cfg1.to_string(),
            vec![
                "sh".to_string(), "-c".to_string(),
                format!(
                    "M={mock} && \
                     python3 \"$M\" connect-once --peer-ip 192.168.1.1 --port 32000 --timeout 5 --expect-fail && \
                     sleep 7 && \
                     python3 \"$M\" connect-once --peer-ip 192.168.1.1 --port 32000 --timeout 10"
                ),
            ],
            true,
            NodeType::Client,
        ).boxed(),
    ])
    .await?;
    Ok(())
}

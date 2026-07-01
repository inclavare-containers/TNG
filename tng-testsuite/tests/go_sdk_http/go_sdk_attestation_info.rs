use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{
        app::AppType,
        shell::{ShellMode, ShellTask},
        tng::{binary_locator, TngInstance},
        NodeType, Task as _,
    },
};

#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    let test_dir = env!("CARGO_MANIFEST_DIR").to_string() + "/tests/go_sdk_http/go-programs";
    let tng_bin = binary_locator::resolve_tng_binary()?;

    run_test!(vec![
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {
                        "in": { "host": "0.0.0.0", "port": 20001 },
                        "out": { "host": "127.0.0.1", "port": 30001 }
                    },
                    "ohttp": {},
                    "no_ra": true
                }]
            }"#,
        )
        .boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "192.168.1.1:20001",
            expected_path_and_query: "/api/data",
        }
        .boxed(),
        ShellTask {
            name: "go_attestation_info".to_string(),
            node_type: NodeType::Client,
            script: format!(
                "cd {}/attestation_info && \
                 go build -o /tmp/go_sdk_attestation_info_$$ . && \
                 TNG_BINARY={} /tmp/go_sdk_attestation_info_$$; \
                 rm -f /tmp/go_sdk_attestation_info_$$",
                test_dir,
                tng_bin.display()
            ),
            mode: ShellMode::ForegroundStop,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

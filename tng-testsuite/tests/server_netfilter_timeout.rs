use anyhow::{bail, Result};
use tng_testsuite::{
    run_test,
    task::{function::FunctionTask, tng::TngInstance, NodeType, Task as _},
};
use tokio::{io::AsyncReadExt, net::TcpStream, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test(
        vec![
            TngInstance::TngServer (
                r#"
                {
                    "add_egress": [
                        {
                            "netfilter": {
                                "capture_dst": {
                                    "port": 30001
                                }
                            },
                            "attest": {
                                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                            }
                        }
                    ]
                }
                "#
            ).boxed(),
            FunctionTask {
                name: "bad_client".to_owned(),
                node_type: NodeType::Client,
                func: Box::new(function_call),
            }
            .boxed(),
        ]
    )
    .await?;

    Ok(())
}

fn function_call(token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();

        let mut tcp_stream = TcpStream::connect("192.168.1.1:30001").await?;

        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                bail!("timeout testing")
            }
            read_res = tcp_stream.read_u8() => {
                match read_res {
                    Ok(_) => {bail!("Should be failed due to cancelled by tng server")},
                    Err(_) => {
                        /* Ok */
                        tracing::info!("The connection is canceled by tng server, which is expected")
                    },
                }
            }
        }
        Ok(())
    }))
}

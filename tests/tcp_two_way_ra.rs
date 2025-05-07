mod common;

use anyhow::Result;
use common::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// tng client as verifier and tng server as attester, while tng server is using `netfilter` mode instead of `mapping` mode
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
					{
						"mapping": {
							"in": {
								"host": "0.0.0.0",
								"port": 20001
							},
							"out": {
								"host": "127.0.0.1",
								"port": 30001
							}
						},
						"attest": {
							"aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
						},
						"verify": {
							"as_addr": "http://192.168.1.254:8080/",
							"policy_ids": [
								"default"
							]
						}
					}
                ]
            }
            "#,
        )
        .boxed(),
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
					{
						"mapping": {
							"in": {
								"port": 10001
							},
							"out": {
								"host": "192.168.1.1",
								"port": 20001
							}
						},
						"attest": {
							"aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
						},
						"verify": {
							"as_addr": "http://192.168.1.254:8080/",
							"policy_ids": [
								"default"
							]
						}
					}
                ]
            }
            "#,
        )
        .boxed(),
        AppType::TcpServer { port: 30001 }.boxed(),
        AppType::TcpClient {
            host: "127.0.0.1",
            port: 10001,
            http_proxy: None,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

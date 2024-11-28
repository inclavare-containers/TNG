mod common;

use anyhow::Result;
use common::{
    run_test,
    task::app::{AppType, HttpProxy},
};

/// The serf case, where both tng client and tng server are verifier and attester, while tng client is using `http_proxy` mode, and tng server is using `netfilter` mode:
///
/// To test this, launch a netcat TCP listener instance to act as a serf node
///
/// ```sh
/// nc -l -v 9991
/// ```
///
/// and launch a netcat client instance to act as another serf node, who connects other p2p nodes (127.0.0.1 9991) via a http_proxy endpoint (127.0.0.1:41000)
///
/// ```sh
/// nc -X connect -x 127.0.0.1:41000 -v 127.0.0.1 9991
/// ```
///
/// You can take a look at the encrypted rats-tls traffic
/// ```sh
/// tcpdump -n -vvvvvvvvvv -qns 0 -X -i any tcp port 40000
/// ```
/// where `40000` is the value of `listen_port` of `add_egress.netfilter`.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test(
        &AppType::TcpServer { port: 9991 },
        &AppType::TcpClient {
            host: "127.0.0.1",
            port: 9991,
            http_proxy: Some(HttpProxy {
                host: "127.0.0.1",
                port: 41000,
            }),
        },
        r#"
        {
            "add_egress": [
				{
					"netfilter": {
						"capture_dst": {
							"port": 9991
						},
						"capture_local_traffic": true
					},
					"attest": {
						"aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
					},
					"verify": {
						"as_addr": "http://127.0.0.1:8080/",
						"policy_ids": [
							"default"
						]
					}
				}
            ]
        }
        "#,
        r#"
        {
            "add_ingress": [
				{
					"http_proxy": {
						"proxy_listen": {
							"host": "0.0.0.0",
							"port": 41000
						},
						"dst_filters": {
							"domain": "*",
							"port": 9991
						}
					},
					"attest": {
						"aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
					},
					"verify": {
						"as_addr": "http://127.0.0.1:8080/",
						"policy_ids": [
							"default"
						]
					}
				}
            ]
        }
        "#,
    )
    .await?;

    Ok(())
}

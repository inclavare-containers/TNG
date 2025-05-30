use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{
        app::{AppType, HttpProxy},
        tng::TngInstance,
        Task as _,
    },
};

/// The serf case, where both tng client and tng server are verifier and attester, while tng client is using `http_proxy` mode, and tng server is using `netfilter` mode:
///
/// To test this, launch a netcat TCP listener instance to act as a serf node
///
/// ```sh
/// nc -l -v 9991
/// ```
///
/// and launch a netcat client instance to act as another serf node, who connects other p2p nodes (192.168.1.1 9991) via a http_proxy endpoint (127.0.0.1:41000)
///
/// ```sh
/// nc -X connect -x 127.0.0.1:41000 -v 192.168.1.1 9991
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
        vec![
            TngInstance::TngServer(
                r#"
                {
                    "add_egress": [
                        {
                            "netfilter": {
                                "capture_dst": {
                                    "port": 9991
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
                "#
            ).boxed(),
            TngInstance::TngClient(
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
                                "as_addr": "http://192.168.1.254:8080/",
                                "policy_ids": [
                                    "default"
                                ]
                            }
                        }
                    ]
                }
                "#
            ).boxed(),
            AppType::TcpServer { port: 9991 }.boxed(),
            AppType::TcpClient {
                host: "192.168.1.1",
                port: 9991,
                http_proxy: Some(HttpProxy {
                    host: "127.0.0.1",
                    port: 41000,
                }),
            }.boxed(),
        ]
    )
    .await?;

    Ok(())
}

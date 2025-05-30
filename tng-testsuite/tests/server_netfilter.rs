use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// tng client as verifier and tng server as attester
///
/// tng will generate iptables rules like the following, before running envoy:
///
/// ```sh
/// iptables -t nat -N TNG_ENGRESS
/// iptables -t nat -A TNG_ENGRESS -p tcp -m mark --mark 565 -j RETURN
/// iptables -t nat -A TNG_ENGRESS -p tcp -m addrtype --dst-type LOCAL --dport 30001 -j REDIRECT --to-ports 30000
/// # Or with specific dst ip address if capture_dst.host is provided in tng config file:
/// # iptables -t nat -A TNG_ENGRESS -p tcp --dst 127.0.0.1/32 --dport 30001 -j REDIRECT --to-ports 30000
/// iptables -t nat -A PREROUTING -p tcp -j TNG_ENGRESS
/// iptables -t nat -A OUTPUT -p tcp -j TNG_ENGRESS ;
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 30001
                            },
                            "capture_local_traffic": true
                        },
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
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
                        "mapping": {
                            "in": {
                                "port": 10001
                            },
                            "out": {
                                "host": "192.168.1.1",
                                "port": 30001
                            }
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
        AppType::TcpServer { port: 30001 }.boxed(),
        AppType::TcpClient {
            host: "127.0.0.1",
            port: 10001,
            http_proxy: None,
        }.boxed(),
    ])
    .await?;

    Ok(())
}

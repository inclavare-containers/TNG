use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// RA-mode (client-cert) session resumption over the non-multiplex Rats-TLS tunnel.
///
/// Both sides run two-way RA (`attest` + `verify`). The `AppType::TcpClient`
/// harness opens 5 sequential downstream connections through the tunnel.
///
/// Connection 1 is a full TLS handshake: the client presents its attestation
/// cert and the peer cert is RA-verified post-handshake. Connections 2-5 resume
/// from the ticket obtained on connection 1.
///
/// The cert verifier is a shared, stateless no-op: the rustls callback returns
/// Ok without storing anything, so it can be one Arc per generator and rustls
/// allows resume (its `Weak::ptr_eq` resume gating sees the same verifier). The
/// `ResolvesClientCert` resolver is shared the same way. The peer cert is
/// fetched post-handshake via `peer_certificates()` and RA-verified with
/// `verify_cert`. On a resumed handshake rustls presents no peer cert, so
/// verify is skipped and the connection is marked `AttestationState::Resumed`:
/// the original handshake's attestation is trusted via the PSK binding, not
/// re-derived.
///
/// Proves RA-mode resume works end-to-end: conn 1 full handshake, conns 2-5
/// resume, the cert is NOT re-sent on resume, all 5 echo correctly, and no
/// resumed connection is rejected.
///
/// Requires the Attestation Agent (`make test-dep-aa`) and Attestation Service
/// (`make test-dep-as`) to be running. A "Failed to connect to Attestation
/// Agent ttrpc endpoint" or policy/manifest error here is an environment issue,
/// not a code regression.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_rats_tls_resumption_ra() -> Result<()> {
    run_test!(vec![
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

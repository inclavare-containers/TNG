use anyhow::Result;
use tng_testsuite::{
    capture_logs, run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Cross-connection cert-verify cache hit.
///
/// The verifier (TngClient ingress) and attester (TngServer egress) are configured with
/// builtin-AS verification (no external AS needed; the attester still sources evidence from the
/// remote Attestation Agent via `aa_addr`). The `TcpClient` app repeats 5 sequential TLS
/// connections through the same TngClient ingress. The attester reuses its cert for a refresh
/// window, so connections 2-5 present the identical cert DER; with the per-`TlsConfigGenerator`
/// shared cache they must hit the verdict cached on connection 1 instead of re-running the full
/// RA appraisal.
///
/// The assertion is on the verifier's `trace!("rats-tls cert verify cache hit")` log: a hit is
/// only emitted when a verdict cached on connection N is still visible to connection N+1, i.e.
/// the cache outlives a single per-connection verifier. If the cache ever regresses back onto
/// the per-connection verifier (the original bug this test guards against), every connection
/// misses and no "cache hit" line is ever captured.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_tcp_one_way_ra_verify_cache_hit() -> Result<()> {
    // Install the log-capture layer before run_test launches any in-process TNG runtime.
    let logs = capture_logs().await;

    run_test!(
        vec![
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
                                    "port": 20001
                                }
                            },
                            "verify": {
                                "model": "background_check",
                                "as_provider": "coco",
                                "as_type": "builtin",
                                "attestation_policy": {
                                    "type": "trust_all"
                                },
                                "reference_values": []
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
        ]
    )
    .await?;

    // 5 sequential TLS connections from the same attester: the first is a cache miss (full
    // verify), connections 2-5 must hit the shared verdict. At least one "cache hit" proves the
    // cache is shared across per-connection verifiers rather than recreated per handshake.
    let captured = logs.lock().expect("capture buffer poisoned");
    let hits = captured
        .iter()
        .filter(|line| line.contains("rats-tls cert verify cache hit"))
        .count();
    assert!(
        hits >= 1,
        "expected at least one cert-verify cache hit across the 5 repeated TLS connections, \
         but captured logs contained none (the per-config shared cache is not being hit). \
         {} log lines were captured.",
        captured.len()
    );

    Ok(())
}

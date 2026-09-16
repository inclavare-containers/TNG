use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{run_test, task::tng::TngExecTask, task::NodeType, task::Task as _};

/// Full-fidelity bidirectional RA on the pp2 hook topology. Same bidirectional
/// hook config (ingress capture_dst + egress capture_listen over 31000-31005,
/// multiplex:false) as the no_ra baseline (pp2_bidirectional_topology) but with
/// no_ra replaced by bidirectional background_check RA both ways: attest via the
/// in-VM attestation-agent (UDS), verify with the builtin converter + trust_all
/// policy (local appraisal, no external AS needed for the verify side).
///
/// This mirrors the production attest/verify shape injected by
/// tng_configure_ra.py but swaps the production transparency_log policy for
/// trust_all, since CI has no real TEE/artifacts to appraise. The builtin
/// verify shape needs a tng binary built with the `__builtin-as` cargo feature;
/// the repo's default features provide it via `builtin-as-tdx-rust` (which
/// auto-enables `__builtin-as`), so a source-built tng (incl. CI's
/// `make run-test-on-bin`, which builds from source) supports it. The attest
/// side still needs the attestation-agent to generate evidence, so keep
/// test-dep-aa running; the builtin verify appraises locally, so test-dep-as is
/// not required. Verifies the RA handshake completes and encrypted data still
/// flows both ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
#[serial]
async fn test() -> Result<()> {
    let mock = format!(
        "{}/tests/hook/pp2/mock_sglang_rank.py",
        env!("CARGO_MANIFEST_DIR")
    );
    // no_ra:true replaced by bidirectional attest+verify, same hook config.
    // verify uses the builtin converter + trust_all policy (local appraisal).
    let cfg = r#"{
        "add_ingress": [{"hook":{"capture_dst":[{"port":31000,"port_end":31005}],"proxy_port":49000},
            "attest":{"model":"background_check","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"},
            "verify":{"model":"background_check","as_type":"builtin","attestation_policy":{"type":"trust_all"}}}],
        "add_egress":  [{"hook":{"capture_listen":[{"port":31000,"port_end":31005}]},
            "attest":{"model":"background_check","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"},
            "verify":{"model":"background_check","as_type":"builtin","attestation_policy":{"type":"trust_all"}}}]
    }"#;
    run_test!(vec![
        TngExecTask::new(
            cfg.to_string(),
            vec![
                "python3".to_string(),
                mock.clone(),
                "serve".to_string(),
                "--rank".to_string(),
                "0".to_string(),
                "--peer-ip".to_string(),
                "192.168.1.253".to_string(),
                "--wait".to_string(),
                "40".to_string(),
            ],
            false,
            NodeType::Server,
        )
        .boxed(),
        TngExecTask::new(
            cfg.to_string(),
            vec![
                "python3".to_string(),
                mock,
                "serve".to_string(),
                "--rank".to_string(),
                "1".to_string(),
                "--peer-ip".to_string(),
                "192.168.1.1".to_string(),
                "--wait".to_string(),
                "40".to_string(),
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

use anyhow::Result;
use serial_test::serial;
use tng::tools::cli::RatsTlsCommand;
use tng::tools::rats_tls;

/// `rats-tls gen` builds a rats-tls cert locally from a background_check attest
/// config. Needs the Attestation Agent at the standard CoCo UDS path, started
/// by `make test-dep-aa`.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rats_tls_gen_produces_pem() -> Result<()> {
    // Direct AttestArgs JSON parse (no RaArgsUnchecked tag injection), so every
    // discriminator tag must be explicit: model, aa_provider, aa_type.
    let attest = r#"{"model":"background_check","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"}"#;
    let dir = tempfile::tempdir()?;
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    rats_tls::run(RatsTlsCommand::Gen {
        attest: attest.to_string(),
        cert_out: Some(cert_path.clone()),
        key_out: Some(key_path.clone()),
    })
    .await?;

    let cert = std::fs::read_to_string(&cert_path)?;
    let key = std::fs::read_to_string(&key_path)?;
    assert!(
        cert.contains("BEGIN CERTIFICATE"),
        "cert PEM missing certificate header: {cert}"
    );
    assert!(
        key.contains("BEGIN PRIVATE KEY"),
        "key PEM missing PKCS8 private key header: {key}"
    );
    Ok(())
}

/// `rats-tls gen` then `rats-tls verify` is self-consistent: a cert produced by
/// `gen` (background_check, via the AA at the standard CoCo UDS path) verifies
/// cleanly against a background_check verify config pointing at a live
/// Attestation Service (started by `make test-dep-as`). Needs AA + AS.
///
/// VerifyArgs is flat (`#[serde(tag = "model", flatten)]`), so the converter
/// and verifier share one `as_provider`/`as_type`/`as_addr`/`policy_ids`/
/// `as_headers` object; the converter's required `as_addr` becomes the
/// verifier's `as_addr` too (it fetches the AS cert for token verification).
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rats_tls_gen_then_verify_background_check() -> Result<()> {
    let attest = r#"{"model":"background_check","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"}"#;
    let verify = r#"{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}"#;
    let dir = tempfile::tempdir()?;
    let cert_path = dir.path().join("cert.pem");

    rats_tls::run(RatsTlsCommand::Gen {
        attest: attest.to_string(),
        cert_out: Some(cert_path.clone()),
        key_out: None,
    })
    .await?;

    rats_tls::run(RatsTlsCommand::Verify {
        cert: cert_path,
        verify: verify.to_string(),
    })
    .await?;

    Ok(())
}

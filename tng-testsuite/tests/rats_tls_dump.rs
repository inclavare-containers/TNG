use anyhow::{Context, Result};
use tng::tools::cli::RatsTlsCommand;
use tng::tools::rats_tls;
use tng_testsuite::{
    run_test,
    task::{app::AppType, function::FunctionTask, tng::TngInstance, NodeType, Task as _},
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// `rats-tls dump` completes the rats-tls handshake against a no_ra tng server
/// (no `--attest` needed: a no_ra server does not require a client cert) and
/// captures the server's end-entity cert as PEM. The server here is an egress
/// `rats_tls`/`no_ra` instance listening on 20001; the dump client runs in
/// the client node and connects to 192.168.1.1:20001.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn rats_tls_dump_captures_no_ra_server_cert() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"{
                    "add_egress": [{
                        "mapping": {
                            "in": { "host": "0.0.0.0", "port": 20001 },
                            "out": { "host": "127.0.0.1", "port": 30001 }
                        },
                        "rats_tls": {},
                        "no_ra": true
                    }]
                }"#,
        )
        .boxed(),
        AppType::TcpServer { port: 30001 }.boxed(),
        FunctionTask {
            name: "rats_tls_dump".to_owned(),
            node_type: NodeType::Client,
            func: Box::new(rats_tls_dump_client),
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// `rats-tls dump --attest` completes the handshake against a mutual-RA
/// rats-tls server (an egress `rats_tls` instance that both presents its own
/// attest cert and requires a client cert via `verify`) and captures the
/// server's end-entity cert as PEM. The `--attest` JSON drives the client cert
/// through CertManager/DynamicCertResolver, mirroring the live ingress client.
/// The server's `LazyClientCertVerifier` accepts any presented client cert
/// during the handshake (RA verification runs lazily afterwards), so the
/// handshake completes once the client presents a cert and the server cert is
/// recorded. Requires AA (CoCo UDS) and AS (192.168.1.254:8080) to be up: AA
/// builds the client cert, AS backs the server's verify context.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn rats_tls_dump_captures_mutual_ra_server_cert() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"{
                    "add_egress": [{
                        "mapping": {
                            "in": { "host": "0.0.0.0", "port": 20002 },
                            "out": { "host": "127.0.0.1", "port": 30002 }
                        },
                        "rats_tls": {},
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        },
                        "verify": {
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }]
                }"#,
        )
        .boxed(),
        AppType::TcpServer { port: 30002 }.boxed(),
        FunctionTask {
            name: "rats_tls_dump_attest".to_owned(),
            node_type: NodeType::Client,
            func: Box::new(rats_tls_dump_attest_client),
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

fn rats_tls_dump_client(token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        // Drop guard cancels the test token on completion, tearing the
        // server down so the framework's join loop drains.
        let _drop_guard = token.drop_guard();

        let dir = tempfile::tempdir()?;
        let cert_path = dir.path().join("dumped.pem");
        rats_tls::run(RatsTlsCommand::Dump {
            endpoint: "192.168.1.1:20001".to_string(),
            attest: None,
            cert_out: Some(cert_path.clone()),
        })
        .await
        .context("rats-tls dump failed")?;

        let cert = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("read dumped cert {}", cert_path.display()))?;
        assert!(
            cert.contains("BEGIN CERTIFICATE"),
            "dumped PEM missing certificate header: {cert}"
        );
        assert!(
            cert.contains("END CERTIFICATE"),
            "dumped PEM missing certificate footer: {cert}"
        );
        Ok(())
    }))
}

fn rats_tls_dump_attest_client(token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();

        let dir = tempfile::tempdir()?;
        let cert_path = dir.path().join("dumped.pem");
        // Flat AttestArgs JSON parsed directly by the dump tool (no config
        // tag injection), so model/aa_provider/aa_type are explicit. The AA
        // at the CoCo UDS backs the background_check attester.
        let attest = r#"{"model":"background_check","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"}"#;
        rats_tls::run(RatsTlsCommand::Dump {
            endpoint: "192.168.1.1:20002".to_string(),
            attest: Some(attest.to_string()),
            cert_out: Some(cert_path.clone()),
        })
        .await
        .context("rats-tls dump --attest failed")?;

        let cert = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("read dumped cert {}", cert_path.display()))?;
        assert!(
            cert.contains("BEGIN CERTIFICATE"),
            "dumped PEM missing certificate header: {cert}"
        );
        assert!(
            cert.contains("END CERTIFICATE"),
            "dumped PEM missing certificate footer: {cert}"
        );
        Ok(())
    }))
}

use anyhow::{Context, Result};
use serial_test::serial;
use tng::tools::cli::OhttpCommand;
use tng::tools::ohttp;
use tng_testsuite::{
    run_test,
    task::{function::FunctionTask, tng::TngInstance, NodeType, Task as _},
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// `ohttp dump` POSTs a `KeyConfigRequest` (no attestation) to a no_ra ohttp
/// server's key-config endpoint and writes the returned `KeyConfigResponse`
/// JSON. The server here is a no_ra egress mapping + ohttp instance on port
/// 20001; the dump client runs in the client node and posts to
/// http://192.168.1.1:20001. The dumped JSON must carry `hpke_key_config`.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn ohttp_dump_writes_key_config() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"{
                    "add_egress": [{
                        "mapping": {
                            "in": { "host": "0.0.0.0", "port": 20001 },
                            "out": { "host": "127.0.0.1", "port": 30001 }
                        },
                        "ohttp": {},
                        "no_ra": true
                    }]
                }"#,
        )
        .boxed(),
        FunctionTask {
            name: "ohttp_dump".to_owned(),
            node_type: NodeType::Client,
            func: Box::new(ohttp_dump_client),
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

fn ohttp_dump_client(token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        // Drop guard cancels the test token on completion, tearing the
        // server down so the framework's join loop drains.
        let _drop_guard = token.drop_guard();

        let dir = tempfile::tempdir()?;
        let out_path = dir.path().join("keyconfig.json");
        ohttp::run(OhttpCommand::Dump {
            endpoint: "http://192.168.1.1:20001".to_string(),
            attest_request: Some("none".to_string()),
            out: Some(out_path.clone()),
        })
        .await
        .context("ohttp dump failed")?;

        let body = std::fs::read_to_string(&out_path)
            .with_context(|| format!("read dumped keyconfig {}", out_path.display()))?;
        assert!(
            body.contains("hpke_key_config"),
            "dumped key config missing hpke_key_config: {body}"
        );
        Ok(())
    }))
}

/// `ohttp verify` on a no_ra dump must fail with "no attestation_info",
/// because a no_ra key-config response carries no attestation. The verify
/// context uses a Passport verifier with `skip_as_token_cert_verify` so it
/// builds without contacting an AS; the helper rejects the response before
/// the verifier is used. No AA/AS services are required for this test.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn ohttp_verify_rejects_no_ra_dump() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {
                        "in": { "host": "0.0.0.0", "port": 20010 },
                        "out": { "host": "127.0.0.1", "port": 30010 }
                    },
                    "ohttp": {},
                    "no_ra": true
                }]
            }"#,
        )
        .boxed(),
        FunctionTask {
            name: "ohttp_verify_no_ra".to_string(),
            node_type: NodeType::Client,
            func: Box::new(ohttp_verify_no_ra_client),
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

fn ohttp_verify_no_ra_client(token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();

        let dir = tempfile::tempdir()?;
        let out_path = dir.path().join("keyconfig.json");
        ohttp::run(OhttpCommand::Dump {
            endpoint: "http://192.168.1.1:20010".to_string(),
            attest_request: Some("none".to_string()),
            out: Some(out_path.clone()),
        })
        .await
        .context("ohttp dump failed")?;

        // Passport verifier with skip_as_token_cert_verify builds without an
        // AS, so this test does not depend on AS being up. The helper errors
        // on the missing attestation_info before the verifier is consulted.
        let verify_json = r#"{"model":"passport","as_provider":"coco","as_type":"restful","policy_ids":["default"],"skip_as_token_cert_verify":true}"#;
        let err = ohttp::run(OhttpCommand::Verify {
            keyconfig: out_path.clone(),
            verify: verify_json.to_string(),
        })
        .await
        .err()
        .expect("ohttp verify on a no_ra dump should error");

        let msg = format!("{err:#}");
        assert!(
            msg.contains("no attestation_info"),
            "expected 'no attestation_info' error, got: {msg}"
        );
        Ok(())
    }))
}

/// End-to-end `ohttp dump` (passport) then `ohttp verify` against a passport
/// verify config. The ohttp egress carries a passport attest context, so the
/// dumped key config carries a Passport attestation_result; `ohttp verify`
/// re-runs the same Passport verify dispatch the ingress client uses and must
/// succeed. Requires the Attestation Agent (AA) and Attestation Service (AS)
/// to be running; without them it will fail at the attest/convert step.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn ohttp_dump_then_verify_passport() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {
                        "in": { "host": "0.0.0.0", "port": 20011 },
                        "out": { "host": "127.0.0.1", "port": 30011 }
                    },
                    "ohttp": {},
                    "attest": {
                        "model": "passport",
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                        "as_addr": "http://192.168.1.254:8080/",
                        "policy_ids": ["default"]
                    }
                }]
            }"#,
        )
        .boxed(),
        FunctionTask {
            name: "ohttp_dump_verify_passport".to_string(),
            node_type: NodeType::Client,
            func: Box::new(ohttp_dump_verify_passport_client),
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

fn ohttp_dump_verify_passport_client(token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();

        let dir = tempfile::tempdir()?;
        let out_path = dir.path().join("keyconfig.json");
        ohttp::run(OhttpCommand::Dump {
            endpoint: "http://192.168.1.1:20011".to_string(),
            attest_request: Some("passport".to_string()),
            out: Some(out_path.clone()),
        })
        .await
        .context("ohttp dump (passport) failed")?;

        let body = std::fs::read_to_string(&out_path)
            .with_context(|| format!("read dumped keyconfig {}", out_path.display()))?;
        assert!(
            body.contains("attestation_info"),
            "dumped passport key config missing attestation_info: {body}"
        );

        let verify_json = r#"{"model":"passport","as_provider":"coco","as_type":"restful","as_addr":"http://192.168.1.254:8080/","policy_ids":["default"]}"#;
        ohttp::run(OhttpCommand::Verify {
            keyconfig: out_path.clone(),
            verify: verify_json.to_string(),
        })
        .await
        .context("ohttp verify (passport) failed")?;
        Ok(())
    }))
}

/// End-to-end `ohttp dump` (background_check) then `ohttp verify` against a
/// background_check verify config. The ohttp egress carries a background_check
/// attest context (AA only; the converter lives on the verify side), so the
/// dumped key config carries raw evidence; `ohttp verify` converts it via the
/// AS and verifies the resulting token. This exercises the BackgroundCheck arm
/// of `verify_keyconfig_attestation`, confirming the subset-based report_data
/// check accepts the hpke_key_config binding even though the dumped file
/// carries no challenge_token (the helper passes challenge_token: None).
/// Requires AA and AS to be running.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn ohttp_dump_then_verify_background_check() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {
                        "in": { "host": "0.0.0.0", "port": 20012 },
                        "out": { "host": "127.0.0.1", "port": 30012 }
                    },
                    "ohttp": {},
                    "attest": {
                        "model": "background_check",
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                    }
                }]
            }"#,
        )
        .boxed(),
        FunctionTask {
            name: "ohttp_dump_verify_bc".to_string(),
            node_type: NodeType::Client,
            func: Box::new(ohttp_dump_verify_bc_client),
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

fn ohttp_dump_verify_bc_client(token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();

        // Obtain a challenge token from the AS, mirroring converter.get_nonce()
        // (POST {as_addr}/challenge -> extra-params.jwt). The dump tool takes
        // the token via --attest-request backgroundcheck:<token>; the live
        // ingress client obtains it the same way from the AS.
        let challenge = reqwest::Client::new()
            .post("http://192.168.1.254:8080/challenge")
            .json(&serde_json::json!({}))
            .send()
            .await
            .context("request AS challenge token")?
            .text()
            .await
            .context("read AS challenge response")?;
        let challenge_value: serde_json::Value =
            serde_json::from_str(&challenge).context("parse AS challenge response")?;
        let challenge_token = challenge_value["extra-params"]["jwt"]
            .as_str()
            .context("challenge response missing extra-params.jwt")?
            .to_string();

        let dir = tempfile::tempdir()?;
        let out_path = dir.path().join("keyconfig.json");
        ohttp::run(OhttpCommand::Dump {
            endpoint: "http://192.168.1.1:20012".to_string(),
            attest_request: Some(format!("backgroundcheck:{challenge_token}")),
            out: Some(out_path.clone()),
        })
        .await
        .context("ohttp dump (background_check) failed")?;

        let body = std::fs::read_to_string(&out_path)
            .with_context(|| format!("read dumped keyconfig {}", out_path.display()))?;
        assert!(
            body.contains("attestation_info"),
            "dumped background_check key config missing attestation_info: {body}"
        );

        let verify_json = r#"{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://192.168.1.254:8080/","policy_ids":["default"]}"#;
        ohttp::run(OhttpCommand::Verify {
            keyconfig: out_path.clone(),
            verify: verify_json.to_string(),
        })
        .await
        .context("ohttp verify (background_check) failed")?;
        Ok(())
    }))
}

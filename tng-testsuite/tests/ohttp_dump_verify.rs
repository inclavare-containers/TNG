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
            verify: None,
            raw: Some(out_path.clone()),
            out_dir: None,
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
            verify: None,
            raw: Some(out_path.clone()),
            out_dir: None,
        })
        .await
        .context("ohttp dump failed")?;

        // Passport verifier with skip_as_token_cert_verify builds without an
        // AS, so this test does not depend on AS being up. The helper errors
        // on the missing attestation_info before the verifier is consulted.
        let verify_json = r#"{"model":"passport","as_provider":"coco","as_type":"restful","policy_ids":["default"],"skip_as_token_cert_verify":true}"#;
        let err = ohttp::run(OhttpCommand::Verify {
            raw: out_path.clone(),
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

/// End-to-end `ohttp dump --verify` (passport) then `ohttp verify` against a
/// passport verify config. The ohttp egress carries a passport attest context,
/// so the dumped key config carries a Passport attestation_result. `dump
/// --verify` mints no nonce (passport is self-contained) and verifies the
/// attestation inline; `ohttp verify` then re-runs the same Passport verify
/// dispatch the ingress client uses and must also succeed (a passport token
/// carries its own AS-signed attestation result, so it re-verifies offline).
/// Requires the Attestation Agent (AA) and Attestation Service (AS) to be
/// running; without them it will fail at the attest/convert step.
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
        // dump --verify (passport) fetches the key config with a Passport
        // attestation and verifies it inline; the same config re-verifies the
        // dumped file below.
        let verify_json = r#"{"model":"passport","as_provider":"coco","as_type":"restful","as_addr":"http://192.168.1.254:8080/","policy_ids":["default"]}"#;
        ohttp::run(OhttpCommand::Dump {
            endpoint: "http://192.168.1.1:20011".to_string(),
            verify: Some(verify_json.to_string()),
            raw: Some(out_path.clone()),
            out_dir: None,
        })
        .await
        .context("ohttp dump (passport) failed")?;

        let body = std::fs::read_to_string(&out_path)
            .with_context(|| format!("read dumped keyconfig {}", out_path.display()))?;
        assert!(
            body.contains("attestation_info"),
            "dumped passport key config missing attestation_info: {body}"
        );

        ohttp::run(OhttpCommand::Verify {
            raw: out_path.clone(),
            verify: verify_json.to_string(),
        })
        .await
        .context("ohttp verify (passport) failed")?;
        Ok(())
    }))
}

/// End-to-end `ohttp dump --verify` (background_check) then `ohttp verify`
/// against a background_check verify config. The ohttp egress carries a
/// background_check attest context (AA only; the converter lives on the
/// verify side), so the dumped key config carries raw evidence. `dump --verify`
/// mints the challenge token via `converter.get_nonce()` and verifies inline
/// (freshness holds, same converter); `ohttp verify` then re-converts the
/// evidence against the same external AS, which is stateful across processes
/// and re-validates the challenge token it issued. (A builtin AS would NOT
/// re-verify in a separate process, and `verify` errors with a clear pointer
/// to `dump --verify` in that case; this test uses the external restful AS.)
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

        let dir = tempfile::tempdir()?;
        let bundle = dir.path().join("bundle");
        // dump --verify --out-dir (background_check) mints the challenge token
        // via converter.get_nonce(), fetches the key config with the evidence,
        // verifies it inline, and writes the full bundle: raw.json, hpke.*,
        // quote.bin, eventlog.json, attestation_result.jwt,
        // attestation_result.claims.json. The same config re-verifies the dumped
        // body below against the same external AS.
        let verify_json = r#"{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://192.168.1.254:8080/","policy_ids":["default"]}"#;
        ohttp::run(OhttpCommand::Dump {
            endpoint: "http://192.168.1.1:20012".to_string(),
            verify: Some(verify_json.to_string()),
            raw: None,
            out_dir: Some(bundle.clone()),
        })
        .await
        .context("ohttp dump --out-dir (background_check) failed")?;

        let raw_path = bundle.join("raw.json");
        let body = std::fs::read_to_string(&raw_path)
            .with_context(|| format!("read {}", raw_path.display()))?;
        assert!(
            body.contains("attestation_info"),
            "bc bundle raw missing attestation_info: {body}"
        );
        // attestation_result + claims are produced for any attested model.
        // quote.bin/eventlog.json are TDX-specific (the CI AA uses sample TEE,
        // so they are not asserted here).
        for name in ["attestation_result.jwt", "attestation_result.claims.json"] {
            assert!(bundle.join(name).exists(), "bc bundle missing {name}");
        }

        // decode the bundle offline (no server/AS) from the raw body + the
        // saved attestation-result JWT.
        let decoded = dir.path().join("decoded");
        ohttp::run(OhttpCommand::Decode {
            raw: raw_path.clone(),
            attestation_result: Some(bundle.join("attestation_result.jwt")),
            out_dir: decoded.clone(),
        })
        .await
        .context("ohttp decode (attested bc) failed")?;
        assert!(
            decoded.join("attestation_result.claims.json").exists(),
            "decode missing attestation_result.claims.json"
        );

        ohttp::run(OhttpCommand::Verify {
            raw: raw_path.clone(),
            verify: verify_json.to_string(),
        })
        .await
        .context("ohttp verify (background_check) failed")?;
        Ok(())
    }))
}

/// `ohttp dump --out-dir` (bare, no_ra) writes the artifact bundle: `raw.json`,
/// `hpke.base64`, `hpke.json`. No attestation is present, so no quote/eventlog/
/// attestation_result files. No AA/AS services required.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn ohttp_dump_bundle_no_ra() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {
                        "in": { "host": "0.0.0.0", "port": 20020 },
                        "out": { "host": "127.0.0.1", "port": 30020 }
                    },
                    "ohttp": {},
                    "no_ra": true
                }]
            }"#,
        )
        .boxed(),
        FunctionTask {
            name: "ohttp_dump_bundle".to_string(),
            node_type: NodeType::Client,
            func: Box::new(ohttp_dump_bundle_client),
        }
        .boxed(),
    ])
    .await?;
    Ok(())
}

fn ohttp_dump_bundle_client(token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();
        let dir = tempfile::tempdir()?;
        let bundle = dir.path().join("bundle");
        ohttp::run(OhttpCommand::Dump {
            endpoint: "http://192.168.1.1:20020".to_string(),
            verify: None,
            raw: None,
            out_dir: Some(bundle.clone()),
        })
        .await
        .context("ohttp dump --out-dir failed")?;

        for name in ["raw.json", "hpke.base64", "hpke.json"] {
            let p = bundle.join(name);
            assert!(p.exists(), "bundle missing {name}");
        }
        assert!(!bundle.join("attestation_result.jwt").exists());
        assert!(!bundle.join("quote.bin").exists());

        let hpke: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(bundle.join("hpke.json"))?)?;
        assert!(
            hpke["configs"].is_array(),
            "hpke.json missing configs array"
        );
        assert!(
            hpke["configs"][0]["kem"].is_string(),
            "hpke.json missing kem"
        );
        Ok(())
    }))
}

/// `ohttp decode --raw --out-dir` reproduces the hpke artifacts from a dumped
/// raw body without contacting the server or an AS. No AA/AS required.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn ohttp_decode_no_ra() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {
                        "in": { "host": "0.0.0.0", "port": 20021 },
                        "out": { "host": "127.0.0.1", "port": 30021 }
                    },
                    "ohttp": {},
                    "no_ra": true
                }]
            }"#,
        )
        .boxed(),
        FunctionTask {
            name: "ohttp_decode".to_string(),
            node_type: NodeType::Client,
            func: Box::new(ohttp_decode_client),
        }
        .boxed(),
    ])
    .await?;
    Ok(())
}

fn ohttp_decode_client(token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();
        let dir = tempfile::tempdir()?;
        let raw_path = dir.path().join("raw.json");
        ohttp::run(OhttpCommand::Dump {
            endpoint: "http://192.168.1.1:20021".to_string(),
            verify: None,
            raw: Some(raw_path.clone()),
            out_dir: None,
        })
        .await
        .context("ohttp dump --raw failed")?;

        let out = dir.path().join("decoded");
        ohttp::run(OhttpCommand::Decode {
            raw: raw_path.clone(),
            attestation_result: None,
            out_dir: out.clone(),
        })
        .await
        .context("ohttp decode failed")?;

        for name in ["raw.json", "hpke.base64", "hpke.json"] {
            assert!(out.join(name).exists(), "decode missing {name}");
        }
        assert!(!out.join("attestation_result.claims.json").exists());
        Ok(())
    }))
}

/// `ohttp dump` with neither `--raw` nor `--out-dir` prints the raw body to
/// stdout. No AA/AS services required.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn ohttp_dump_stdout_no_ra() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {
                        "in": { "host": "0.0.0.0", "port": 20022 },
                        "out": { "host": "127.0.0.1", "port": 30022 }
                    },
                    "ohttp": {},
                    "no_ra": true
                }]
            }"#,
        )
        .boxed(),
        FunctionTask {
            name: "ohttp_dump_stdout".to_string(),
            node_type: NodeType::Client,
            func: Box::new(ohttp_dump_stdout_client),
        }
        .boxed(),
    ])
    .await?;
    Ok(())
}

fn ohttp_dump_stdout_client(token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();
        let dir = tempfile::tempdir()?;
        // Neither --raw nor --out-dir: dump prints the raw body to stdout and
        // writes no files.
        ohttp::run(OhttpCommand::Dump {
            endpoint: "http://192.168.1.1:20022".to_string(),
            verify: None,
            raw: None,
            out_dir: None,
        })
        .await
        .context("ohttp dump (stdout) failed")?;
        assert!(
            dir.path().read_dir()?.next().is_none(),
            "stdout dump wrote files"
        );
        Ok(())
    }))
}

/// `--raw` and `--out-dir` are mutually exclusive. No AA/AS required.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn ohttp_dump_rejects_raw_and_out_dir() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {
                        "in": { "host": "0.0.0.0", "port": 20023 },
                        "out": { "host": "127.0.0.1", "port": 30023 }
                    },
                    "ohttp": {},
                    "no_ra": true
                }]
            }"#,
        )
        .boxed(),
        FunctionTask {
            name: "ohttp_dump_mutual_exclusive".to_string(),
            node_type: NodeType::Client,
            func: Box::new(ohttp_dump_mutual_exclusive_client),
        }
        .boxed(),
    ])
    .await?;
    Ok(())
}

fn ohttp_dump_mutual_exclusive_client(token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();
        let dir = tempfile::tempdir()?;
        let err = ohttp::run(OhttpCommand::Dump {
            endpoint: "http://192.168.1.1:20023".to_string(),
            verify: None,
            raw: Some(dir.path().join("raw.json")),
            out_dir: Some(dir.path().join("bundle")),
        })
        .await
        .err()
        .expect("dump with both --raw and --out-dir should error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("mutually exclusive"),
            "expected 'mutually exclusive' error, got: {msg}"
        );
        Ok(())
    }))
}

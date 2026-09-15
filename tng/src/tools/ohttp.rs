use anyhow::Context;
use anyhow::Result;

use std::path::PathBuf;

use crate::tunnel::ohttp::protocol::header::OhttpApi;
use crate::tunnel::ohttp::protocol::{AttestationRequest, KeyConfigRequest, KeyConfigResponse};

use crate::config::ra::VerifyArgs;
use crate::tunnel::ingress::protocol::ohttp::security::client::verify_keyconfig_attestation;
use crate::tunnel::ra_context::VerifyContext;
use std::path::Path;

pub async fn run(cmd: super::cli::OhttpCommand) -> Result<()> {
    match cmd {
        super::cli::OhttpCommand::Dump {
            endpoint,
            attest_request,
            out,
        } => dump(&endpoint, attest_request.as_deref(), out).await,
        super::cli::OhttpCommand::Verify { keyconfig, verify } => {
            verify_cmd(&keyconfig, &verify).await
        }
    }
}

/// POST a `KeyConfigRequest` to an ohttp server's key-config endpoint and write
/// the returned `KeyConfigResponse` JSON (pretty) to `--out` or stdout. dump
/// does not verify attestation; that is `ohttp verify`'s job on the dumped
/// file. Uses its own reqwest client (not the ingress verify-coupled fetch) so
/// it stays a standalone operator tool.
async fn dump(endpoint: &str, attest_request: Option<&str>, out: Option<PathBuf>) -> Result<()> {
    let req = KeyConfigRequest {
        attestation_request: parse_attest_request(attest_request)?,
    };
    let resp = reqwest::Client::new()
        .post(endpoint)
        .header(OhttpApi::HEADER_NAME, OhttpApi::KEY_CONFIG)
        .json(&req)
        .send()
        .await
        .context("fetch ohttp key config")?
        .error_for_status()
        .context("ohttp key-config endpoint returned error status")?
        .json::<KeyConfigResponse>()
        .await
        .context("parse KeyConfigResponse")?;
    let pretty = serde_json::to_string_pretty(&resp).context("serialize KeyConfigResponse")?;
    match out {
        Some(p) => tokio::fs::write(&p, &pretty)
            .await
            .with_context(|| format!("write {}", p.display())),
        None => {
            println!("{pretty}");
            Ok(())
        }
    }
}

/// Verify the attestation in a dumped ohttp key-config JSON against a flat
/// `VerifyArgs` JSON. Reuses the ingress client's `verify_keyconfig_attestation`
/// so the dump and the live tunnel follow the exact same Passport/BackgroundCheck
/// dispatch.
async fn verify_cmd(keyconfig: &Path, verify_json: &str) -> Result<()> {
    let verify_args: VerifyArgs =
        serde_json::from_str(verify_json).context("parse --verify as VerifyArgs JSON")?;
    let verify_ctx = VerifyContext::from_verify_args(&verify_args)
        .await
        .context("build verify context")?;

    let raw = std::fs::read_to_string(keyconfig)
        .with_context(|| format!("read keyconfig {}", keyconfig.display()))?;
    let resp: KeyConfigResponse = serde_json::from_str(&raw).context("parse KeyConfigResponse")?;

    let result = verify_keyconfig_attestation(&resp, &verify_ctx, None)
        .await
        .context("verify ohttp key-config attestation")?;

    // AttestationResult serializes to the raw JWT token string.
    let value = serde_json::to_value(&result).context("serialize attestation result")?;
    let pretty =
        serde_json::to_string_pretty(&value).context("format attestation result as pretty JSON")?;
    println!("verified OK\n{pretty}");
    Ok(())
}

/// Parse `--attest-request`: `passport` → Passport,
/// `backgroundcheck:<token>` → BackgroundCheck { challenge_token }, `none` or
/// absent → None (server returns the bare hpke_key_config with no attestation).
fn parse_attest_request(s: Option<&str>) -> Result<Option<AttestationRequest>> {
    match s {
        None | Some("none") => Ok(None),
        Some("passport") => Ok(Some(AttestationRequest::Passport)),
        Some(other) if other.starts_with("backgroundcheck:") => {
            let token = other.trim_start_matches("backgroundcheck:").to_string();
            Ok(Some(AttestationRequest::BackgroundCheck {
                challenge_token: token,
            }))
        }
        Some(other) => anyhow::bail!(
            "--attest-request must be none|passport|backgroundcheck:<token>, got {other}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_and_absent_yield_no_request() {
        assert!(parse_attest_request(None).unwrap().is_none());
        assert!(parse_attest_request(Some("none")).unwrap().is_none());
    }

    #[test]
    fn passport_parses() {
        match parse_attest_request(Some("passport")).unwrap().unwrap() {
            AttestationRequest::Passport => {}
            other => panic!("expected Passport, got {other:?}"),
        }
    }

    #[test]
    fn background_check_token_parses() {
        match parse_attest_request(Some("backgroundcheck:abc.def"))
            .unwrap()
            .unwrap()
        {
            AttestationRequest::BackgroundCheck { challenge_token } => {
                assert_eq!(challenge_token, "abc.def");
            }
            other => panic!("expected BackgroundCheck, got {other:?}"),
        }
    }

    #[test]
    fn unknown_value_is_rejected() {
        assert!(parse_attest_request(Some("bogus")).is_err());
    }
}

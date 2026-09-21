use anyhow::Context;
use anyhow::Result;

use std::path::PathBuf;

use rats_cert::tee::GenericConverter;

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
            verify,
            out,
        } => dump(&endpoint, verify.as_deref(), out).await,
        super::cli::OhttpCommand::Verify { keyconfig, verify } => {
            verify_cmd(&keyconfig, &verify).await
        }
    }
}

/// POST a `KeyConfigRequest` to an ohttp server's key-config endpoint and write
/// the returned `KeyConfigResponse` JSON (pretty) to `--out` or stdout. With
/// `--verify`, dump builds the AS converter from the `VerifyArgs` JSON, mints
/// the background-check challenge token via `converter.get_nonce()`, sends the
/// request with that attestation so the response carries `attestation_info`
/// (evidence), AND verifies the attestation inline with the same converter that
/// minted the token, then decodes and prints the attestation-result JWT claims.
/// Passport model sends `Passport` (no nonce) and verifies the self-contained
/// token inline. Without `--verify`, sends a bare request (no attestation, no
/// verification).
///
/// Background-check freshness is bound to the AS instance that minted the
/// nonce: the builtin AS rejects an evidence whose challenge token it did not
/// issue, so a dumped background-check file cannot be re-verified in a separate
/// `ohttp verify` invocation. `dump --verify` runs the full live chain (mint ->
/// fetch -> verify -> decode) in one process, mirroring the ingress tunnel.
/// `ohttp verify` is for offline passport/external-AS evidence. Uses its own
/// reqwest client (not the ingress verify-coupled fetch) so the fetch itself
/// stays a standalone operator tool; only the attestation half reuses the live
/// `verify_keyconfig_attestation`.
async fn dump(endpoint: &str, verify: Option<&str>, out: Option<PathBuf>) -> Result<()> {
    let plan = build_verify_plan(verify).await?;
    let req = KeyConfigRequest {
        attestation_request: plan.attestation_request,
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
            .with_context(|| format!("write {}", p.display()))?,
        None => println!("{pretty}"),
    }

    if let Some(verify_ctx) = plan.verify_ctx {
        let result = verify_keyconfig_attestation(&resp, &verify_ctx, plan.challenge_token)
            .await
            .context("verify ohttp key-config attestation")?;
        let claims = result
            .claims()
            .context("decode attestation-result JWT claims")?;
        let claims_pretty = serde_json::to_string_pretty(&claims)
            .context("format attestation claims as pretty JSON")?;
        println!("verified OK");
        println!("attestation_result: {}", result.token_str());
        println!("claims:");
        println!("{claims_pretty}");
    }
    Ok(())
}

/// What `--verify` resolved to for a dump: the attestation request to send,
/// plus (for inline verification) the verify context and the challenge token to
/// bind into the report_data check. `verify_ctx` is None when `--verify` is
/// absent, so dump fetches a bare key config and skips verification.
#[derive(Default)]
struct VerifyPlan {
    attestation_request: Option<AttestationRequest>,
    verify_ctx: Option<VerifyContext>,
    challenge_token: Option<String>,
}

/// Resolve `--verify` into the attestation request to send plus (for inline
/// verification) the verify context and the challenge token to bind. None ->
/// bare key config, no verification. The attestation model comes from the
/// `VerifyArgs` `model` discriminator: background-check mints a challenge token
/// via the AS converter and reuses it for inline verification; passport sends
/// `Passport` with no token.
async fn build_verify_plan(verify: Option<&str>) -> Result<VerifyPlan> {
    let Some(json) = verify else {
        return Ok(VerifyPlan::default());
    };
    let verify_args: VerifyArgs =
        serde_json::from_str(json).context("parse --verify as VerifyArgs JSON")?;
    let verify_ctx = VerifyContext::from_verify_args(&verify_args)
        .await
        .context("build verify context")?;
    Ok(match verify_ctx {
        ctx @ VerifyContext::BackgroundCheck { .. } => {
            // Borrow the converter to mint the nonce, then move the whole
            // context into the plan for inline verification.
            let nonce = match &ctx {
                VerifyContext::BackgroundCheck { converter, .. } => {
                    converter.get_nonce().await.with_context(|| {
                        format!("request challenge token from AS at {}", converter.as_addr())
                    })?
                }
                _ => unreachable!(),
            };
            VerifyPlan {
                attestation_request: Some(AttestationRequest::BackgroundCheck {
                    challenge_token: nonce.clone(),
                }),
                verify_ctx: Some(ctx),
                challenge_token: Some(nonce),
            }
        }
        ctx @ VerifyContext::Passport { .. } => VerifyPlan {
            attestation_request: Some(AttestationRequest::Passport),
            verify_ctx: Some(ctx),
            challenge_token: None,
        },
    })
}

/// Verify the attestation in a dumped ohttp key-config JSON against a flat
/// `VerifyArgs` JSON, then decode and print the attestation-result JWT claims.
/// Reuses the ingress client's `verify_keyconfig_attestation` so the dump and
/// the live tunnel follow the exact same Passport/BackgroundCheck dispatch.
///
/// Works for Passport evidence (self-contained token, no nonce) and external-AS
/// background-check evidence (the external AS keeps state across processes). A
/// builtin-AS background-check key config dumped by `dump --verify` CANNOT be
/// re-verified here: the challenge token embedded in the evidence was signed
/// by the builtin AS instance that minted it (in the `dump --verify` process),
/// and a fresh builtin AS in this process uses a different per-process signing
/// key, so `converter.convert` -> AS `evaluate` rejects it. That check is
/// coupled to producing the attestation-result JWT (which carries the claims),
/// so it cannot be skipped from here; `dump --verify` runs the full live chain
/// (mint, fetch, verify, decode) in one process instead.
async fn verify_cmd(keyconfig: &Path, verify_json: &str) -> Result<()> {
    let verify_args: VerifyArgs =
        serde_json::from_str(verify_json).context("parse --verify as VerifyArgs JSON")?;

    // Builtin AS + background-check cannot be re-verified offline; see the
    // function doc. Bail before building the AS / hitting the network.
    #[cfg(feature = "__builtin-as")]
    if matches!(
        &verify_args,
        VerifyArgs::BackgroundCheck {
            converter: crate::config::ra::ConverterArgs::Coco(
                crate::config::ra::CocoConverterArgs::Builtin { .. },
            ),
            ..
        }
    ) {
        anyhow::bail!(
            "standalone `ohttp verify` cannot re-verify a builtin-AS background-check key \
             config: the challenge token in the evidence was signed by the builtin AS instance \
             that minted it during `dump --verify`, and a fresh AS in this process cannot \
             validate it. Run `tng tools ohttp dump --verify ...` for the full live chain (it \
             mints and verifies the token in one process and decodes the claims)."
        );
    }

    let verify_ctx = VerifyContext::from_verify_args(&verify_args)
        .await
        .context("build verify context")?;

    let raw = std::fs::read_to_string(keyconfig)
        .with_context(|| format!("read keyconfig {}", keyconfig.display()))?;
    let resp: KeyConfigResponse = serde_json::from_str(&raw).context("parse KeyConfigResponse")?;

    let result = verify_keyconfig_attestation(&resp, &verify_ctx, None)
        .await
        .context("verify ohttp key-config attestation")?;

    let claims = result
        .claims()
        .context("decode attestation-result JWT claims")?;
    let claims_pretty = serde_json::to_string_pretty(&claims)
        .context("format attestation claims as pretty JSON")?;
    println!("verified OK");
    println!("attestation_result: {}", result.token_str());
    println!("claims:");
    println!("{claims_pretty}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The None arm is the only pure branch of build_verify_plan; the Some arm
    // builds a VerifyContext and talks to an AS, so it is exercised by the live
    // scenario harness rather than a unit test.
    #[tokio::test]
    async fn no_verify_yields_bare_plan() {
        let plan = build_verify_plan(None).await.unwrap();
        assert!(plan.attestation_request.is_none());
        assert!(plan.verify_ctx.is_none());
        assert!(plan.challenge_token.is_none());
    }
}

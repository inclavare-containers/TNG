use anyhow::Context;
use anyhow::Result;

use std::path::{Path, PathBuf};

use base64::Engine;
use rats_cert::tee::GenericConverter;

use crate::tunnel::ohttp::protocol::header::OhttpApi;
use crate::tunnel::ohttp::protocol::{
    AttestationRequest, HpkeKeyConfig, KeyConfigRequest, KeyConfigResponse, ServerAttestationInfo,
};

use crate::config::ra::VerifyArgs;
use crate::tunnel::ingress::protocol::ohttp::security::client::verify_keyconfig_attestation;
use crate::tunnel::ra_context::VerifyContext;

pub async fn run(cmd: super::cli::OhttpCommand) -> Result<()> {
    match cmd {
        super::cli::OhttpCommand::Dump {
            endpoint,
            verify,
            raw,
            out_dir,
        } => dump(&endpoint, verify.as_deref(), raw, out_dir).await,
        super::cli::OhttpCommand::Verify { raw, verify } => verify_cmd(&raw, &verify).await,
        super::cli::OhttpCommand::Decode {
            raw,
            attestation_result,
            out_dir,
        } => decode(&raw, attestation_result.as_deref(), &out_dir).await,
    }
}

/// POST a `KeyConfigRequest` to an ohttp server's key-config endpoint and write
/// the returned `KeyConfigResponse` plus derived artifacts.
///
/// Output modes (mutually exclusive): `--raw <file>` writes only the raw body;
/// `--out-dir <dir>` writes the full bundle; neither prints the raw body to
/// stdout (and, with `--verify`, the attestation-result JWT and claims).
///
/// `--verify <VerifyArgs json>` makes dump build the AS converter, mint the
/// background-check challenge token, send the attested request (so the response
/// carries `attestation_info`), and run `verify_keyconfig_attestation` to
/// produce the attestation-result JWT and decoded claims. Background-check
/// freshness is bound to the AS instance that minted the nonce, so the verify
/// runs inline in this process, mirroring the ingress tunnel. Without
/// `--verify` the request is bare and no attestation artifacts are produced.
///
/// Bundle contents (under `--out-dir`): `raw.json` and `hpke.base64`/`hpke.json`
/// always; with `--verify`, background-check also yields `quote.bin` (the TDX
/// quote) and `eventlog.json` (parsed UEFI event log), and every attested
/// model yields `attestation_result.jwt` and `attestation_result.claims.json`.
/// Passport attestation carries no raw quote/event log (the server distills it
/// into the signed token), so those two files are omitted for passport.
async fn dump(
    endpoint: &str,
    verify: Option<&str>,
    raw: Option<PathBuf>,
    out_dir: Option<PathBuf>,
) -> Result<()> {
    if raw.is_some() && out_dir.is_some() {
        anyhow::bail!("--raw and --out-dir are mutually exclusive");
    }
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
    let attestation = if let Some(verify_ctx) = plan.verify_ctx {
        let result = verify_keyconfig_attestation(&resp, &verify_ctx, plan.challenge_token)
            .await
            .context("verify ohttp key-config attestation")?;
        Some(result)
    } else {
        None
    };

    match (raw, out_dir) {
        (Some(p), None) => {
            tokio::fs::write(&p, &pretty)
                .await
                .with_context(|| format!("write {}", p.display()))?;
        }
        (None, Some(dir)) => {
            write_bundle(&dir, &pretty, &resp, attestation.as_ref()).await?;
        }
        (None, None) => {
            println!("{pretty}");
            if let Some(result) = attestation {
                let claims = decode_jwt_payload(result.token_str())
                    .context("decode attestation-result JWT payload")?;
                let claims_pretty = serde_json::to_string_pretty(&claims)
                    .context("format attestation claims as pretty JSON")?;
                println!("verified OK");
                println!("attestation_result: {}", result.token_str());
                println!("claims:");
                println!("{claims_pretty}");
            }
        }
        _ => unreachable!("mutually exclusive flags checked above"),
    }
    Ok(())
}

/// Write the full artifact bundle to `dir`: `raw.json`, `hpke.base64`,
/// `hpke.json`, and (when `attestation` is present) `quote.bin`,
/// `eventlog.json`, `attestation_result.jwt`, `attestation_result.claims.json`.
async fn write_bundle(
    dir: &Path,
    raw_pretty: &str,
    resp: &KeyConfigResponse,
    attestation: Option<&crate::tunnel::attestation_result::AttestationResult>,
) -> Result<()> {
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("create {}", dir.display()))?;
    write_file(dir, "raw.json", raw_pretty).await?;
    let (hpke_b64, hpke_json) = decode_hpke(&resp.hpke_key_config)?;
    write_file(dir, "hpke.base64", &hpke_b64).await?;
    write_file(dir, "hpke.json", &hpke_json).await?;

    if let Some(result) = attestation {
        let jwt = result.token_str();
        write_file(dir, "attestation_result.jwt", jwt).await?;
        let claims = decode_jwt_payload(jwt).context("decode attestation-result JWT payload")?;
        let claims_pretty =
            serde_json::to_string_pretty(&claims).context("format attestation claims")?;
        write_file(dir, "attestation_result.claims.json", &claims_pretty).await?;
        if let Some(eventlog) = extract_eventlog(&claims) {
            let eventlog_pretty =
                serde_json::to_string_pretty(&eventlog).context("format event log")?;
            write_file(dir, "eventlog.json", &eventlog_pretty).await?;
        }
    }
    // quote.bin comes from attestation_info.evidence, which is only present
    // for an attested (background-check) body; bare bodies have none.
    if let Some(quote) = extract_quote_bin(resp) {
        write_bin(dir, "quote.bin", &quote).await?;
    }
    Ok(())
}

/// Verify the attestation in a dumped ohttp key-config JSON against a flat
/// `VerifyArgs` JSON, then print the attestation-result JWT and decoded
/// claims. Reuses the ingress client's `verify_keyconfig_attestation`.
///
/// Works for Passport evidence (self-contained token, no nonce) and external-AS
/// background-check evidence (the external AS keeps state across processes). A
/// builtin-AS background-check key config dumped by `dump --verify` CANNOT be
/// re-verified here: the challenge token embedded in the evidence was signed
/// by the builtin AS instance that minted it, and a fresh builtin AS in this
/// process uses a different per-process signing key, so `convert` rejects it.
/// That check is coupled to producing the attestation-result JWT, so it cannot
/// be skipped; `dump --verify` runs the full live chain in one process instead.
async fn verify_cmd(raw: &Path, verify_json: &str) -> Result<()> {
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
             validate it. Run `tng tools ohttp dump --verify ... --out-dir <dir>` for the full \
             live chain (it mints and verifies the token in one process and writes the bundle)."
        );
    }

    let verify_ctx = VerifyContext::from_verify_args(&verify_args)
        .await
        .context("build verify context")?;

    let raw_body = std::fs::read_to_string(raw)
        .with_context(|| format!("read raw key config {}", raw.display()))?;
    let resp: KeyConfigResponse =
        serde_json::from_str(&raw_body).context("parse KeyConfigResponse")?;

    let result = verify_keyconfig_attestation(&resp, &verify_ctx, None)
        .await
        .context("verify ohttp key-config attestation")?;

    let claims =
        decode_jwt_payload(result.token_str()).context("decode attestation-result JWT payload")?;
    let claims_pretty = serde_json::to_string_pretty(&claims)
        .context("format attestation claims as pretty JSON")?;
    println!("verified OK");
    println!("attestation_result: {}", result.token_str());
    println!("claims:");
    println!("{claims_pretty}");
    Ok(())
}

/// Decode a dumped ohttp key-config JSON into derived artifacts without
/// contacting the server or an AS. Writes `hpke.base64`, `hpke.json`, and
/// `quote.bin` (for background-check bodies) to `--out-dir`. When
/// `--attestation-result <jwt-file>` is given, also writes
/// `attestation_result.claims.json` and `eventlog.json` decoded from the JWT
/// payload. This is a pure local decode; it does not verify signatures.
async fn decode(raw: &Path, attestation_result: Option<&Path>, out_dir: &Path) -> Result<()> {
    let raw_body = std::fs::read_to_string(raw)
        .with_context(|| format!("read raw key config {}", raw.display()))?;
    let resp: KeyConfigResponse =
        serde_json::from_str(&raw_body).context("parse KeyConfigResponse")?;

    tokio::fs::create_dir_all(out_dir)
        .await
        .with_context(|| format!("create {}", out_dir.display()))?;
    write_file(out_dir, "raw.json", &raw_body).await?;
    let (hpke_b64, hpke_json) = decode_hpke(&resp.hpke_key_config)?;
    write_file(out_dir, "hpke.base64", &hpke_b64).await?;
    write_file(out_dir, "hpke.json", &hpke_json).await?;
    if let Some(quote) = extract_quote_bin(&resp) {
        write_bin(out_dir, "quote.bin", &quote).await?;
    }

    if let Some(jwt_path) = attestation_result {
        let jwt = std::fs::read_to_string(jwt_path)
            .with_context(|| format!("read attestation-result {}", jwt_path.display()))?;
        let claims =
            decode_jwt_payload(jwt.trim()).context("decode attestation-result JWT payload")?;
        let claims_pretty =
            serde_json::to_string_pretty(&claims).context("format attestation claims")?;
        write_file(out_dir, "attestation_result.claims.json", &claims_pretty).await?;
        if let Some(eventlog) = extract_eventlog(&claims) {
            let eventlog_pretty =
                serde_json::to_string_pretty(&eventlog).context("format event log")?;
            write_file(out_dir, "eventlog.json", &eventlog_pretty).await?;
        }
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

/// Decode `hpke_key_config` into the raw base64 `encoded_key_config_list` and a
/// pretty JSON view of the RFC 9458 key configs (key_id, kem, public_key hex,
/// symmetric suites, expire_timestamp). Uses the ohttp crate's
/// `KeyConfig::decode_list`, the same parser the live tunnel uses.
fn decode_hpke(hk: &HpkeKeyConfig) -> Result<(String, String)> {
    let b64 = hk.encoded_key_config_list.clone();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .context("decode encoded_key_config_list base64")?;
    let configs = ohttp::KeyConfig::decode_list(&raw)
        .map_err(|e| anyhow::anyhow!("decode RFC 9458 key config list: {e:?}"))?;
    let configs_json: Vec<serde_json::Value> = configs
        .iter()
        .map(|c| {
            let suites: Vec<String> = c
                .symmetric()
                .iter()
                .map(|s| format!("{:?}+{:?}", s.kdf(), s.aead()))
                .collect();
            serde_json::json!({
                "key_id": c.key_id(),
                "kem": format!("{:?}", c.kem()),
                "public_key": hex::encode(c.pk_data().unwrap_or_default()),
                "symmetric_suites": suites,
            })
        })
        .collect();
    let view = serde_json::json!({
        "expire_timestamp": hk.expire_timestamp,
        "configs": configs_json,
    });
    let pretty = serde_json::to_string_pretty(&view).context("serialize hpke view")?;
    Ok((b64, pretty))
}

/// Extract the raw TDX quote bytes from a background-check key config's
/// `attestation_info.evidence.aa_evidence` (base64-of-JSON -> `quote` field ->
/// base64-decoded binary). None for passport or bare bodies.
fn extract_quote_bin(resp: &KeyConfigResponse) -> Option<Vec<u8>> {
    let ServerAttestationInfo::BackgroundCheck { evidence, .. } = resp.attestation_info.as_ref()?
    else {
        return None;
    };
    let aa_evidence = evidence.get("aa_evidence")?.as_str()?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(aa_evidence)
        .ok()?;
    let obj: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let quote_b64 = obj.get("quote")?.as_str()?;
    base64::engine::general_purpose::STANDARD
        .decode(quote_b64)
        .ok()
}

/// Decode a JWT's payload (the middle base64url segment) into a JSON value,
/// without verifying the signature. Used for `attestation_result.claims.json`
/// and `eventlog.json`.
fn decode_jwt_payload(jwt: &str) -> Result<serde_json::Value> {
    // A JWT is header.payload.signature; require all three so a truncated
    // two-segment string is rejected, not silently parsed.
    let mut parts = jwt.split('.');
    let header = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("attestation-result JWT has no header segment"))?;
    let payload = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("attestation-result JWT has no payload segment"))?;
    let _signature = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("attestation-result JWT has no signature segment"))?;
    let _ = header;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(payload))
        .context("decode attestation-result JWT payload base64")?;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .context("parse attestation-result JWT payload JSON")
}

/// Extract the parsed UEFI event log from the attestation-result claims. The
/// JWT payload nests `submods.cpu0` then uses a dotted key
/// `ear.veraison.annotated-evidence` (the EAR appraiser's namespace), under
/// which `tdx.uefi_event_logs` is the parsed event array.
fn extract_eventlog(claims: &serde_json::Value) -> Option<serde_json::Value> {
    claims
        .get("submods")?
        .get("cpu0")?
        .get("ear.veraison.annotated-evidence")?
        .get("tdx")?
        .get("uefi_event_logs")
        .cloned()
}

async fn write_file(dir: &Path, name: &str, body: &str) -> Result<()> {
    let p = dir.join(name);
    tokio::fs::write(&p, body.as_bytes())
        .await
        .with_context(|| format!("write {}", p.display()))
}

async fn write_bin(dir: &Path, name: &str, body: &[u8]) -> Result<()> {
    let p = dir.join(name);
    tokio::fs::write(&p, body)
        .await
        .with_context(|| format!("write {}", p.display()))
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

    #[test]
    fn decode_jwt_payload_parses_three_part_jwt() {
        // header.payload.signature (payload = {"a":1,"b":"x"})
        let jwt = "eyJhbGciOiJub25lIn0.eyJhIjoxLCJiIjoieCJ9.sig";
        let v = decode_jwt_payload(jwt).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"], "x");
    }

    #[test]
    fn decode_jwt_payload_rejects_two_part_jwt() {
        let jwt = "eyJhbGciOiJub25lIn0.eyJhIjoxfQ";
        assert!(decode_jwt_payload(jwt).is_err());
    }
}

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use kbs_types::Tee;
use sha2::{Digest, Sha256, Sha512};

use crate::errors::*;
use crate::tee::coco::attester::AaClient;
use crate::tee::{
    serialize_canon_json, wrap_runtime_data_as_structed, GenericAttester, ReportData,
};

use super::evidence::{ItaEvidence, ItaNonce, ItaNvgpuEvidence};

/// GPU device evidence as returned by CoCo AA's `get_additional_evidence()`.
///
/// AA returns a JSON map keyed by [`kbs_types::Tee`] variant, e.g.:
/// ```json
/// { "nvidia": { "device_evidence_list": [{ "evidence": "<b64>", "certificate": "<pem>", "arch": "hopper" }] } }
/// ```
#[derive(serde::Deserialize)]
struct AaGpuDeviceList {
    device_evidence_list: Vec<AaGpuDevice>,
}

#[derive(serde::Deserialize)]
struct AaGpuDevice {
    evidence: String,
    certificate: String,
    arch: String,
}

/// ITA-specific attester wrapping the shared [`AaClient`].
///
/// Although evidence for ITA can be collected using the same CoCo Attestation Agent
/// as [`CocoAttester`], the Intel Trust Authority service requires runtime data and nonce
/// to be hashed and embedded into the evidence differently:
///   - **Hash algorithm**: SHA-512 (vs SHA-384 for CoCo).
///   - **Nonce binding**: `SHA-512(nonce.val || nonce.iat || runtime_data)` — components of
///     the ITA nonce and runtime_data mixed into evidence so the verifier can prove freshness.
///   - **GPU evidence binding**: The nonce must also be featured in the GPU evidence with
///     hash `SHA-256(nonce.val || nonce.iat)`. We also fold the resulting GPU evidence blob
///     into the runtime_data for primary evidence, creating a cross-device binding
///     (though this isn't required by ITA).
///
/// This attester also parses AA-specific response formats (e.g. the
/// `device_evidence_list` blob from `get_additional_evidence`) into the
/// AA-agnostic [`ItaEvidence`] / [`ItaNvgpuEvidence`] types that
/// [`ItaConverter`] consumes, keeping the converter independent of any
/// particular evidence source.
pub struct ItaAttester {
    aa: AaClient,
}

impl ItaAttester {
    pub fn new(aa_addr: &str) -> Result<Self> {
        Ok(Self {
            aa: AaClient::new(aa_addr)?,
        })
    }

    pub fn new_with_timeout_nano(aa_addr: &str, timeout_nano: i64) -> Result<Self> {
        Ok(Self {
            aa: AaClient::new_with_timeout(aa_addr, timeout_nano)?,
        })
    }
}

/// Parse CoCo AA's additional_evidence blob into an [`ItaNvgpuEvidence`].
///
/// Returns `Ok(None)` when the blob contains no NVIDIA GPU device evidence.
fn parse_aa_gpu_evidence(
    aa_blob: &[u8],
    runtime_data_hash: [u8; 32],
) -> Result<Option<ItaNvgpuEvidence>> {
    let tee_map: HashMap<Tee, serde_json::Value> =
        serde_json::from_slice(aa_blob).map_err(Error::ParseAdditionalEvidenceJsonFailed)?;

    let nvidia_value = match tee_map.get(&Tee::Nvidia) {
        Some(v) => v.clone(),
        None => {
            tracing::debug!("No Nvidia key in additional evidence; skipping GPU attestation");
            return Ok(None);
        }
    };

    let gpu_list: AaGpuDeviceList =
        serde_json::from_value(nvidia_value).map_err(Error::ParseAdditionalEvidenceJsonFailed)?;

    let device = match gpu_list.device_evidence_list.into_iter().next() {
        Some(d) => d,
        None => {
            tracing::warn!("nvidia device_evidence_list is empty; skipping GPU attestation");
            return Ok(None);
        }
    };

    // ITA expects evidence as base64(hex(raw_bytes)), while AA provides base64(raw_bytes).
    let raw = BASE64
        .decode(&device.evidence)
        .map_err(Error::Base64DecodeFailed)?;
    let reencoded_evidence = BASE64.encode(hex::encode(&raw).as_bytes());

    Ok(Some(ItaNvgpuEvidence {
        evidence: reencoded_evidence,
        certificate: device.certificate,
        arch: device.arch,
        runtime_data_hash,
    }))
}

/// Derive `SHA-256(decode(nonce.val) || decode(nonce.iat))` for additonal evidence collection
/// (used in GPU evidence collection).
fn derive_additional_evidence_runtime_data_hash(nonce: &ItaNonce) -> Result<[u8; 32]> {
    let val_bytes = BASE64
        .decode(&nonce.val)
        .map_err(Error::Base64DecodeFailed)?;
    let iat_bytes = BASE64
        .decode(&nonce.iat)
        .map_err(Error::Base64DecodeFailed)?;
    let mut hasher = Sha256::new();
    hasher.update(&val_bytes);
    hasher.update(&iat_bytes);
    Ok(hasher.finalize().into())
}

/// Derive runtime data hash according to ITA expectations.
/// With nonce: `SHA-512(decode(nonce.val) || decode(nonce.iat) || runtime_data_bytes)`
/// Without nonce (RA-TLS): `SHA-512(runtime_data_bytes)`
fn derive_runtime_data_hash(
    nonce: Option<&ItaNonce>,
    runtime_data_bytes: &[u8],
) -> Result<Vec<u8>> {
    let mut hasher = Sha512::new();
    if let Some(nonce) = nonce {
        let val_bytes = BASE64
            .decode(&nonce.val)
            .map_err(Error::Base64DecodeFailed)?;
        let iat_bytes = BASE64
            .decode(&nonce.iat)
            .map_err(Error::Base64DecodeFailed)?;
        hasher.update(&val_bytes);
        hasher.update(&iat_bytes);
    }
    hasher.update(runtime_data_bytes);
    Ok(hasher.finalize().to_vec())
}

#[async_trait::async_trait]
impl GenericAttester for ItaAttester {
    type Evidence = ItaEvidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<ItaEvidence> {
        let mut runtime_data_value = wrap_runtime_data_as_structed(report_data)?;

        // Nonce is optional: present in OHTTP flows (converter fetches it and puts
        // it into challenge_token), currently absent in RA-TLS cert generation.
        let nonce: Option<ItaNonce> = runtime_data_value
            .get("challenge_token")
            .and_then(|v| v.as_str())
            .map(|ct| {
                serde_json::from_str(ct).map_err(|e| {
                    Error::ItaError(format!("Failed to parse challenge_token as ITA nonce: {e}"))
                })
            })
            .transpose()?;

        // Collect additional evidence FIRST (order reversed from CoCo).
        // When a nonce is present (OHTTP flow), derive appropriate runtime data hash.
        // Without a nonce (RA-TLS), pass empty runtime data (still want additional evidence).
        let ae_runtime_data_hash = match nonce {
            Some(ref n) => Some(derive_additional_evidence_runtime_data_hash(n)?),
            None => None,
        };

        let aa_additional_evidence = self.aa.get_additional_evidence(
            ae_runtime_data_hash
                .map(|rd| rd.to_vec())
                .unwrap_or_default(),
        );

        // Parse AA's blob into structured NVGPU evidence (if present).
        let nvgpu_evidence = match (&aa_additional_evidence, ae_runtime_data_hash) {
            (Some(blob), Some(hash)) => parse_aa_gpu_evidence(blob, hash)?,
            _ => None,
        };

        // If additional evidence is present, embed it into the runtime_data
        // for primary evidence for cryptographic binding of devices.
        if let Some(ref ev) = aa_additional_evidence {
            if let Some(obj) = runtime_data_value.as_object_mut() {
                obj.insert(
                    "additional_evidence".to_string(),
                    serde_json::Value::String(BASE64.encode(ev)),
                );
            }
        }

        let runtime_data_bytes = serialize_canon_json(&runtime_data_value)?;

        let runtime_data_hash = derive_runtime_data_hash(nonce.as_ref(), &runtime_data_bytes)?;

        let evidence_raw = self
            .aa
            .get_evidence(runtime_data_hash)
            .map_err(|e| Error::ItaError(format!("Failed to get primary evidence from AA: {e}")))?;

        // AA returns evidence as a JSON object (e.g. {"cc_eventlog":"...", "quote":"..."}).
        let aa_evidence: serde_json::Value =
            serde_json::from_slice(&evidence_raw).map_err(Error::ParseEvidenceFromBytesFailed)?;
        let tdx_quote_b64 = aa_evidence
            .get("quote")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::ItaError("AA evidence JSON missing 'quote' field".to_string()))?;
        let tdx_quote = BASE64
            .decode(tdx_quote_b64)
            .map_err(Error::Base64DecodeFailed)?;

        Ok(ItaEvidence::new(
            tdx_quote,
            nonce,
            runtime_data_bytes,
            nvgpu_evidence,
        ))
    }
}

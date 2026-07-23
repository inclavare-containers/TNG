use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::errors::*;
use crate::tee::coco::attester::AaClient;
use crate::tee::{
    serialize_canon_json, wrap_runtime_data_as_structed, GenericAttester, ReportData,
};

use super::attester_common::{
    derive_additional_evidence_runtime_data_hash, derive_runtime_data_hash, parse_gpu_evidence,
};
use super::evidence::{ItaEvidence, ItaNonce};

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

#[cfg_attr(wasm, async_trait::async_trait(?Send))]
#[cfg_attr(not(wasm), async_trait::async_trait)]
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
        // When a nonce is present (OHTTP flow), derive the hash from the nonce.
        // Without a nonce (RA-TLS), generate a random gpu nonce — ITA requires
        // a non-empty gpu_nonce whenever nvgpu evidence is included, matching
        // the Go client's behaviour for the GPU-only / no-verifier-nonce case.
        let ae_runtime_data_hash = match nonce {
            Some(ref n) => derive_additional_evidence_runtime_data_hash(n)?,
            None => {
                let mut random_bytes = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut random_bytes);
                Sha256::digest(random_bytes).into()
            }
        };

        let aa_additional_evidence = self
            .aa
            .get_additional_evidence(ae_runtime_data_hash.to_vec());

        // Parse AA's blob into structured NVGPU evidence (if present).
        let nvgpu_evidence = match &aa_additional_evidence {
            Some(blob) => parse_gpu_evidence(blob, ae_runtime_data_hash)?,
            None => None,
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

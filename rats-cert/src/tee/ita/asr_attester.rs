use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::errors::*;
use crate::tee::coco::asr_attester::asr_client::AsrClient;
use crate::tee::{
    serialize_canon_json, wrap_runtime_data_as_structed, GenericAttester, ReportData,
};

use super::attester_common::{
    derive_additional_evidence_runtime_data_hash, derive_runtime_data_hash, parse_gpu_evidence,
};
use super::evidence::{ItaEvidence, ItaNonce};

/// ITA-specific attester that fetches evidence via the API Server Rest (ASR)
/// HTTP interface instead of talking to the Attestation Agent over ttrpc.
///
/// Produces the same [`ItaEvidence`] as [`ItaAttester`], so downstream
/// converters and verifiers are unaffected. The runtime-data hashing,
/// nonce binding, and GPU evidence parsing logic is identical.
pub struct ItaAsrAttester {
    asr: AsrClient,
}

impl ItaAsrAttester {
    pub fn new(asr_addr: &str) -> Result<Self> {
        Ok(Self {
            asr: AsrClient::new(asr_addr)?,
        })
    }
}

#[async_trait::async_trait]
impl GenericAttester for ItaAsrAttester {
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

        let asr_additional_evidence = self
            .asr
            .get_additional_evidence(ae_runtime_data_hash.to_vec())
            .await;

        // Parse ASR's blob into structured NVGPU evidence (if present).
        let nvgpu_evidence = match &asr_additional_evidence {
            Some(blob) => parse_gpu_evidence(blob, ae_runtime_data_hash)?,
            None => None,
        };

        // If additional evidence is present, embed it into the runtime_data
        // for primary evidence for cryptographic binding of devices.
        if let Some(ref ev) = asr_additional_evidence {
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
            .asr
            .get_evidence(runtime_data_hash)
            .await
            .map_err(|e| {
                Error::ItaError(format!("Failed to get primary evidence from ASR: {e}"))
            })?;

        // ASR returns evidence as a JSON object (e.g. {"cc_eventlog":"...", "quote":"..."}).
        let asr_evidence: serde_json::Value =
            serde_json::from_slice(&evidence_raw).map_err(Error::ParseEvidenceFromBytesFailed)?;
        let tdx_quote_b64 = asr_evidence
            .get("quote")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::ItaError("ASR evidence JSON missing 'quote' field".to_string())
            })?;
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

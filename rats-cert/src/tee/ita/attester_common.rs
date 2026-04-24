use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use kbs_types::Tee;
use sha2::{Digest, Sha256, Sha512};

use crate::errors::*;

use super::evidence::{ItaNonce, ItaNvgpuEvidence};

/// GPU device evidence as returned by the CoCo AA / ASR `get_additional_evidence()`.
///
/// The response is a JSON map keyed by [`kbs_types::Tee`] variant, e.g.:
/// ```json
/// { "nvidia": { "device_evidence_list": [{ "evidence": "<b64>", "certificate": "<pem>", "arch": "hopper" }] } }
/// ```
#[derive(serde::Deserialize)]
struct GpuDeviceList {
    device_evidence_list: Vec<GpuDevice>,
}

#[derive(serde::Deserialize)]
struct GpuDevice {
    evidence: String,
    certificate: String,
    arch: String,
}

/// Parse an additional_evidence blob into an [`ItaNvgpuEvidence`].
///
/// Returns `Ok(None)` when the blob contains no NVIDIA GPU device evidence.
pub(crate) fn parse_gpu_evidence(
    blob: &[u8],
    runtime_data_hash: [u8; 32],
) -> Result<Option<ItaNvgpuEvidence>> {
    let tee_map: HashMap<Tee, serde_json::Value> =
        serde_json::from_slice(blob).map_err(Error::ParseAdditionalEvidenceJsonFailed)?;

    let nvidia_value = match tee_map.get(&Tee::Nvidia) {
        Some(v) => v.clone(),
        None => {
            tracing::debug!("No Nvidia key in additional evidence; skipping GPU attestation");
            return Ok(None);
        }
    };

    let gpu_list: GpuDeviceList =
        serde_json::from_value(nvidia_value).map_err(Error::ParseAdditionalEvidenceJsonFailed)?;

    let device = match gpu_list.device_evidence_list.into_iter().next() {
        Some(d) => d,
        None => {
            tracing::warn!("nvidia device_evidence_list is empty; skipping GPU attestation");
            return Ok(None);
        }
    };

    // ITA expects evidence as base64(hex(raw_bytes)), while AA/ASR provides base64(raw_bytes).
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

/// Derive `SHA-256(decode(nonce.val) || decode(nonce.iat))` for additional evidence collection
/// (used in GPU evidence collection).
pub(crate) fn derive_additional_evidence_runtime_data_hash(nonce: &ItaNonce) -> Result<[u8; 32]> {
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
pub(crate) fn derive_runtime_data_hash(
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

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RUNTIME_DATA: &[u8] = br#"{"a":"12","b":"34","c":"56"}"#;

    fn sample_nonce() -> ItaNonce {
        ItaNonce {
            val: "aGVsbG8=".into(), // base64("hello")
            iat: "d29ybGQ=".into(), // base64("world")
            signature: "dGVzdC1zaWc=".into(),
        }
    }

    fn bad_nonce() -> ItaNonce {
        ItaNonce {
            val: "!!!not-base64!!!".into(),
            iat: "d29ybGQ=".into(),
            signature: "sig".into(),
        }
    }

    // -- parse_gpu_evidence --

    #[test]
    fn parse_gpu_evidence_valid_nvidia_blob() {
        let raw_bytes = vec![1u8, 2, 3];
        let input_b64 = BASE64.encode(&raw_bytes);
        let cert = "test-cert-pem";
        let arch = "hopper";
        let blob = serde_json::json!({
            "nvidia": {
                "device_evidence_list": [{
                    "evidence": input_b64,
                    "certificate": cert,
                    "arch": arch
                }]
            }
        });
        let hash = [0xABu8; 32];
        let result =
            parse_gpu_evidence(serde_json::to_vec(&blob).unwrap().as_slice(), hash).unwrap();

        let gpu = result.expect("should return Some for valid nvidia blob");
        assert_eq!(gpu.certificate, cert);
        assert_eq!(gpu.arch, arch);
        assert_eq!(gpu.runtime_data_hash, hash);
        let expected_evidence = BASE64.encode(hex::encode(&raw_bytes).as_bytes());
        assert_eq!(gpu.evidence, expected_evidence);
    }

    #[test]
    fn parse_gpu_evidence_no_nvidia_key() {
        let blob = serde_json::json!({"sample": {}});
        let result =
            parse_gpu_evidence(serde_json::to_vec(&blob).unwrap().as_slice(), [0u8; 32]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_gpu_evidence_empty_device_list() {
        let blob = serde_json::json!({
            "nvidia": {"device_evidence_list": []}
        });
        let result =
            parse_gpu_evidence(serde_json::to_vec(&blob).unwrap().as_slice(), [0u8; 32]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_gpu_evidence_invalid_json() {
        assert!(parse_gpu_evidence(b"not json", [0u8; 32]).is_err());
    }

    // -- derive_additional_evidence_runtime_data_hash --

    #[test]
    fn additional_evidence_hash_known_answer() {
        let hash = derive_additional_evidence_runtime_data_hash(&sample_nonce()).unwrap();
        // SHA-256("hello" || "world")
        assert_eq!(
            hex::encode(hash),
            "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af"
        );
    }

    #[test]
    fn additional_evidence_hash_invalid_base64() {
        assert!(derive_additional_evidence_runtime_data_hash(&bad_nonce()).is_err());
    }

    // -- derive_runtime_data_hash --

    #[test]
    fn runtime_data_hash_with_nonce_known_answer() {
        let nonce = sample_nonce();
        let hash = derive_runtime_data_hash(Some(&nonce), SAMPLE_RUNTIME_DATA).unwrap();
        // SHA-512("hello" || "world" || SAMPLE_RUNTIME_DATA)
        assert_eq!(
            hex::encode(&hash),
            "c2bd195b9104a139a2aa82584870446c7efb0fa6d4f4fb0c5db668382bde9710\
             e874010639b54b49adfd56f2f98e687f04dbcff7bf32f7f8fa7c1001c846e05c"
        );
    }

    #[test]
    fn runtime_data_hash_without_nonce_known_answer() {
        let hash = derive_runtime_data_hash(None, SAMPLE_RUNTIME_DATA).unwrap();
        // SHA-512(SAMPLE_RUNTIME_DATA)
        assert_eq!(
            hex::encode(&hash),
            "e01416f798823156a9241bfd0d9da76b3f8dd3c2313cd91bcf4021e4b7519ecc\
             f68e454bf1198d71ddfcedfc6ad153dd697f1fa740e2ef78629cff3e3fd4d43c"
        );
    }

    #[test]
    fn runtime_data_hash_nonce_participates() {
        let nonce = sample_nonce();
        let with = derive_runtime_data_hash(Some(&nonce), SAMPLE_RUNTIME_DATA).unwrap();
        let without = derive_runtime_data_hash(None, SAMPLE_RUNTIME_DATA).unwrap();
        assert_ne!(with, without);
    }

    #[test]
    fn runtime_data_hash_invalid_base64_nonce() {
        assert!(derive_runtime_data_hash(Some(&bad_nonce()), SAMPLE_RUNTIME_DATA).is_err());
    }
}

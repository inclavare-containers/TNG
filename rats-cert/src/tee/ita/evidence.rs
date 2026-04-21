use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::cert::dice::cbor::OCBR_TAG_EVIDENCE_ITA_EVIDENCE;
use crate::errors::*;
use crate::tee::claims::Claims;
use crate::tee::{DiceParseEvidenceOutput, GenericEvidence};

/// Signed nonce from ITA's `GET /appraisal/v2/nonce` endpoint.
/// Carried verbatim from the converter (which fetched it) through the attester
/// and back into the converter's attest request as `verifier_nonce`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItaNonce {
    pub val: String,
    pub iat: String,
    pub signature: String,
}

/// Parsed Nvidia GPU device evidence ready for the ITAConverter.
///
/// The attester is responsible for extracting this from whatever evidence
/// source it uses (e.g. CoCo AA's `get_additional_evidence()` blob).
/// The converter consumes these fields directly without knowing the
/// attester's evidence source format.
#[derive(Clone)]
pub struct ItaNvgpuEvidence {
    /// GPU attestation evidence, already re-encoded as `base64(hex(raw_bytes))`
    /// per ITA's expected format.
    pub(crate) evidence: String,
    /// PEM certificate chain for the GPU device.
    pub(crate) certificate: String,
    /// GPU architecture identifier (e.g. "hopper").
    pub(crate) arch: String,
    /// Hash of the runtime data used during GPU evidence collection:
    /// `SHA-256(decode(nonce.val) || decode(nonce.iat))`.
    pub(crate) runtime_data_hash: [u8; 32],
}

/// Evidence produced by an ITA-compatible attester and consumed by `ItaConverter`.
///
/// Contains all fields needed to build the ITA `/appraisal/v2/attest` request.
/// Transmitted over the wire (JSON-serialized) between attester and converter
/// when they run on different TNG instances (background-check model).
#[derive(Clone)]
pub struct ItaEvidence {
    pub(crate) tdx_quote: Vec<u8>,
    /// `None` in the no-nonce flow; `Some` in the OHTTP flow
    /// where the converter fetches a nonce from ITA before evidence collection.
    pub(crate) nonce: Option<ItaNonce>,
    /// `canonical_json(runtime_data_claims)` -- deterministic serialization of
    /// runtime_data claims. These exact bytes are hashed into evidence and
    /// sent to ITA in the attest request.
    pub(crate) runtime_data: Vec<u8>,
    /// Parsed GPU device evidence, if present. `None` when the platform has
    /// no NVIDIA GPU or no additional evidence was collected.
    pub(crate) nvgpu_evidence: Option<ItaNvgpuEvidence>,
}

impl ItaEvidence {
    #[allow(unused)]
    pub fn new(
        tdx_quote: Vec<u8>,
        nonce: Option<ItaNonce>,
        runtime_data: Vec<u8>,
        nvgpu_evidence: Option<ItaNvgpuEvidence>,
    ) -> Self {
        Self {
            tdx_quote,
            nonce,
            runtime_data,
            nvgpu_evidence,
        }
    }

    pub fn serialize_to_json(&self) -> serde_json::Result<serde_json::Value> {
        serde_json::to_value(self.to_json_helper())
    }

    pub fn deserialize_from_json(value: serde_json::Value) -> Result<Self> {
        Self::from_json_helper(
            serde_json::from_value::<ItaEvidenceJsonHelper>(value)
                .map_err(Error::DeserializeEvidenceFromJsonFailed)?,
        )
    }
}

impl GenericEvidence for ItaEvidence {
    fn get_dice_cbor_tag(&self) -> u64 {
        OCBR_TAG_EVIDENCE_ITA_EVIDENCE
    }

    fn get_dice_raw_evidence(&self) -> Result<Vec<u8>> {
        let mut res = vec![];
        ciborium::into_writer(&self.to_cbor_helper(), &mut res)
            .map_err(Error::CborSerializationFailed)?;
        Ok(res)
    }

    fn get_claims(&self) -> Result<Claims> {
        Ok(Claims::default())
    }

    fn create_evidence_from_dice(
        cbor_tag: u64,
        raw_evidence: &[u8],
    ) -> DiceParseEvidenceOutput<Self> {
        if cbor_tag == OCBR_TAG_EVIDENCE_ITA_EVIDENCE {
            match ciborium::from_reader::<ItaEvidenceCborHelper, _>(raw_evidence)
                .map_err(Error::CborDeserializationFailed)
                .and_then(Self::from_cbor_helper)
            {
                Ok(v) => DiceParseEvidenceOutput::Ok(v),
                Err(e) => DiceParseEvidenceOutput::MatchButInvalid(e),
            }
        } else {
            DiceParseEvidenceOutput::NotMatch
        }
    }
}

// ---------------------------------------------------------------------------
// CBOR serialization helpers (for DICE cert embedding)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ItaNvgpuEvidenceCborHelper {
    evidence: String,
    certificate: String,
    arch: String,
    runtime_data_hash: ByteBuf,
}

#[derive(Serialize, Deserialize)]
struct ItaEvidenceCborHelper {
    tdx_quote: ByteBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<ItaNonce>,
    runtime_data: ByteBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nvgpu_evidence: Option<ItaNvgpuEvidenceCborHelper>,
}

impl ItaEvidence {
    fn to_cbor_helper(&self) -> ItaEvidenceCborHelper {
        ItaEvidenceCborHelper {
            tdx_quote: ByteBuf::from(self.tdx_quote.clone()),
            nonce: self.nonce.clone(),
            runtime_data: ByteBuf::from(self.runtime_data.clone()),
            nvgpu_evidence: self
                .nvgpu_evidence
                .as_ref()
                .map(|g| ItaNvgpuEvidenceCborHelper {
                    evidence: g.evidence.clone(),
                    certificate: g.certificate.clone(),
                    arch: g.arch.clone(),
                    runtime_data_hash: ByteBuf::from(g.runtime_data_hash.to_vec()),
                }),
        }
    }

    fn from_cbor_helper(helper: ItaEvidenceCborHelper) -> Result<Self> {
        let nvgpu_evidence = match helper.nvgpu_evidence {
            Some(g) => {
                let hash: [u8; 32] =
                    g.runtime_data_hash
                        .into_vec()
                        .try_into()
                        .map_err(|v: Vec<u8>| {
                            Error::ItaError(format!(
                                "nvgpu runtime_data_hash must be 32 bytes, got {}",
                                v.len()
                            ))
                        })?;
                Some(ItaNvgpuEvidence {
                    evidence: g.evidence,
                    certificate: g.certificate,
                    arch: g.arch,
                    runtime_data_hash: hash,
                })
            }
            None => None,
        };
        Ok(Self {
            tdx_quote: helper.tdx_quote.into_vec(),
            nonce: helper.nonce,
            runtime_data: helper.runtime_data.into_vec(),
            nvgpu_evidence,
        })
    }
}

// ---------------------------------------------------------------------------
// JSON serialization helpers (for wire transport between TNG instances)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ItaNvgpuEvidenceJsonHelper {
    evidence: String,
    certificate: String,
    arch: String,
    runtime_data_hash: String,
}

#[derive(Serialize, Deserialize)]
struct ItaEvidenceJsonHelper {
    tdx_quote: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<ItaNonce>,
    runtime_data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nvgpu_evidence: Option<ItaNvgpuEvidenceJsonHelper>,
}

impl ItaEvidence {
    fn to_json_helper(&self) -> ItaEvidenceJsonHelper {
        ItaEvidenceJsonHelper {
            tdx_quote: BASE64_STANDARD.encode(&self.tdx_quote),
            nonce: self.nonce.clone(),
            runtime_data: BASE64_STANDARD.encode(&self.runtime_data),
            nvgpu_evidence: self
                .nvgpu_evidence
                .as_ref()
                .map(|g| ItaNvgpuEvidenceJsonHelper {
                    evidence: g.evidence.clone(),
                    certificate: g.certificate.clone(),
                    arch: g.arch.clone(),
                    runtime_data_hash: hex::encode(g.runtime_data_hash),
                }),
        }
    }

    fn from_json_helper(helper: ItaEvidenceJsonHelper) -> Result<Self> {
        let nvgpu_evidence = match helper.nvgpu_evidence {
            Some(g) => {
                let bytes = hex::decode(&g.runtime_data_hash).map_err(|e| {
                    Error::ItaError(format!("Failed to decode nvgpu runtime_data_hash hex: {e}"))
                })?;
                let hash: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                    Error::ItaError(format!(
                        "nvgpu runtime_data_hash must be 32 bytes, got {}",
                        v.len()
                    ))
                })?;
                Some(ItaNvgpuEvidence {
                    evidence: g.evidence,
                    certificate: g.certificate,
                    arch: g.arch,
                    runtime_data_hash: hash,
                })
            }
            None => None,
        };
        Ok(Self {
            tdx_quote: BASE64_STANDARD
                .decode(&helper.tdx_quote)
                .map_err(Error::Base64DecodeFailed)?,
            nonce: helper.nonce,
            runtime_data: BASE64_STANDARD
                .decode(&helper.runtime_data)
                .map_err(Error::Base64DecodeFailed)?,
            nvgpu_evidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_evidence(with_nonce: bool) -> ItaEvidence {
        ItaEvidence {
            tdx_quote: b"fake-quote".to_vec(),
            nonce: if with_nonce {
                Some(ItaNonce {
                    val: "nonce-val".into(),
                    iat: "nonce-iat".into(),
                    signature: "nonce-sig".into(),
                })
            } else {
                None
            },
            runtime_data: b"{}".to_vec(),
            nvgpu_evidence: None,
        }
    }

    #[test]
    fn json_round_trip_without_nonce() {
        let ev = sample_evidence(false);
        let json = ev.serialize_to_json().unwrap();
        let back = ItaEvidence::deserialize_from_json(json).unwrap();
        assert_eq!(back.tdx_quote, ev.tdx_quote);
        assert!(back.nonce.is_none());
    }

    #[test]
    fn json_round_trip_with_nonce() {
        let ev = sample_evidence(true);
        let json = ev.serialize_to_json().unwrap();
        let back = ItaEvidence::deserialize_from_json(json).unwrap();
        let orig = ev.nonce.as_ref().unwrap();
        let back_nonce = back.nonce.as_ref().unwrap();
        assert_eq!(back_nonce.val, orig.val);
        assert_eq!(back_nonce.iat, orig.iat);
        assert_eq!(back_nonce.signature, orig.signature);
    }

    #[test]
    fn cbor_round_trip_via_dice() {
        let ev = sample_evidence(true);
        assert_eq!(ev.get_dice_cbor_tag(), OCBR_TAG_EVIDENCE_ITA_EVIDENCE);

        let raw = ev.get_dice_raw_evidence().unwrap();
        let DiceParseEvidenceOutput::Ok(back) =
            ItaEvidence::create_evidence_from_dice(OCBR_TAG_EVIDENCE_ITA_EVIDENCE, &raw)
        else {
            panic!("expected DiceParseEvidenceOutput::Ok");
        };
        assert_eq!(back.tdx_quote, ev.tdx_quote);
        assert_eq!(back.runtime_data, ev.runtime_data);
    }

    #[test]
    fn wrong_cbor_tag_is_not_match() {
        let raw = b"anything";
        assert!(matches!(
            ItaEvidence::create_evidence_from_dice(0xDEAD, raw),
            DiceParseEvidenceOutput::NotMatch
        ));
    }

    #[test]
    fn json_with_nvgpu_round_trips() {
        let ev = ItaEvidence {
            tdx_quote: b"q".to_vec(),
            nonce: None,
            runtime_data: b"rt".to_vec(),
            nvgpu_evidence: Some(ItaNvgpuEvidence {
                evidence: "gpu-ev".into(),
                certificate: "gpu-cert".into(),
                arch: "hopper".into(),
                runtime_data_hash: [0xAB; 32],
            }),
        };
        let json = ev.serialize_to_json().unwrap();
        let back = ItaEvidence::deserialize_from_json(json).unwrap();
        let orig = ev.nvgpu_evidence.as_ref().unwrap();
        let gpu = back.nvgpu_evidence.unwrap();
        assert_eq!(gpu.arch, orig.arch);
        assert_eq!(gpu.runtime_data_hash, orig.runtime_data_hash);
    }
}

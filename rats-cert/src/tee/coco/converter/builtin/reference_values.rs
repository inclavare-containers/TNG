//! RVPS reference-value loading for the builtin converter.

use attestation_service::AttestationService;
use base64::Engine;
use reference_value_provider_service::rv_list::ReferenceValueListPayload;
use serde::Serialize;

use super::policy_config::{
    ReferenceValueConfig, SampleProvenancePayloadConfig, SlsaReferenceValuePayloadConfig,
};
use crate::errors::*;

/// Load reference values from configuration
pub(crate) async fn load_reference_values(
    attestation_service: &mut AttestationService,
    reference_values: &[ReferenceValueConfig],
) -> Result<()> {
    for rv in reference_values {
        match rv {
            ReferenceValueConfig::Sample { payload } => {
                let provenance = match payload {
                    SampleProvenancePayloadConfig::Inline { content } => Ok(content.clone()),
                    #[cfg(not(wasm))]
                    SampleProvenancePayloadConfig::Path { path } => {
                        let content_str = tokio::fs::read_to_string(path).await.map_err(|e| {
                            Error::ReadReferenceValueFileFailed {
                                path: path.clone(),
                                source: e,
                            }
                        })?;
                        serde_json::from_str(&content_str).map_err(|e| {
                            Error::ParseReferenceValuePayloadFailed {
                                path: path.clone(),
                                source: e,
                            }
                        })
                    }
                }?;
                let provenance_base64 = base64::engine::general_purpose::STANDARD.encode(
                    serde_json::to_vec(&provenance).map_err(Error::SerializeProvenanceFailed)?,
                );

                #[derive(Serialize)]
                struct RvpsMessage<'a> {
                    #[serde(skip_serializing_if = "Option::is_none")]
                    version: Option<&'a str>,
                    #[serde(rename = "type")]
                    provenance_type: &'a str,
                    payload: String,
                }

                let message = RvpsMessage {
                    version: Some("0.1.0"),
                    provenance_type: "sample",
                    payload: provenance_base64,
                };
                let rvps_message = serde_json::to_string(&message)
                    .map_err(Error::SerializeReferenceValueMessageFailed)?;
                attestation_service
                    .register_reference_value(&rvps_message)
                    .await
                    .map_err(Error::RegisterSampleReferenceValueFailed)?;
            }
            ReferenceValueConfig::Slsa { payload } => {
                let payload_value = match payload {
                    SlsaReferenceValuePayloadConfig::Inline { content } => content.clone(),
                    #[cfg(not(wasm))]
                    SlsaReferenceValuePayloadConfig::Path { path } => {
                        let content_str = tokio::fs::read_to_string(path).await.map_err(|e| {
                            Error::ReadReferenceValueFileFailed {
                                path: path.clone(),
                                source: e,
                            }
                        })?;
                        serde_json::from_str::<ReferenceValueListPayload>(&content_str).map_err(
                            |e| Error::ParseReferenceValuePayloadFailed {
                                path: path.clone(),
                                source: e,
                            },
                        )?
                    }
                };

                let payload_str = serde_json::to_string(&payload_value)
                    .map_err(Error::SerializeSlsaReferenceValueListFailed)?;
                attestation_service
                    .set_reference_value_list(&payload_str)
                    .await
                    .map_err(Error::SetSlsaReferenceValueListFailed)?;
            }
            ReferenceValueConfig::ReleaseManifest { payload } => {
                let payload_value = match payload {
                    SlsaReferenceValuePayloadConfig::Inline { content } => content.clone(),
                    #[cfg(not(wasm))]
                    SlsaReferenceValuePayloadConfig::Path { path } => {
                        let content_str = tokio::fs::read_to_string(path).await.map_err(|e| {
                            Error::ReadReferenceValueFileFailed {
                                path: path.clone(),
                                source: e,
                            }
                        })?;
                        serde_json::from_str::<ReferenceValueListPayload>(&content_str).map_err(
                            |e| Error::ParseReferenceValuePayloadFailed {
                                path: path.clone(),
                                source: e,
                            },
                        )?
                    }
                };

                let payload_str = serde_json::to_string(&payload_value)
                    .map_err(Error::SerializeSlsaReferenceValueListFailed)?;
                attestation_service
                    .set_reference_value_list(&payload_str)
                    .await
                    .map_err(Error::SetSlsaReferenceValueListFailed)?;
            }
        }
    }
    Ok(())
}

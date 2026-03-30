use anyhow::{bail, Result};
use axum::Json;
use rats_cert::tee::coco::evidence::CocoEvidence;
use rats_cert::tee::GenericConverter;

use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::ohttp::protocol::{
    AttestationChallengeResponse, AttestationVerifyRequest, AttestationVerifyResponse,
};
use crate::tunnel::ra_context::VerifyContext;

#[cfg(feature = "__builtin-as")]
use rats_cert::tee::coco::converter::CoCoNonce;

impl OhttpServerApi {
    /// Interface 3: Attestation Forward - Get Challenge
    /// x-tng-ohttp-api: /tng/background-check/challenge
    ///
    /// This endpoint is a forwarder for the AS (Attestation Service) challenge endpoint.
    /// It is used specifically in the "Server verification Client + background check model" scenario.
    pub async fn get_attestation_challenge(
        &self,
    ) -> Result<Json<AttestationChallengeResponse>, TngError> {
        async {
            match self.ra_context.verify_context() {
                Some(verify_ctx) => match verify_ctx {
                    VerifyContext::Passport { .. } => {
                        bail!("Passport model is expected but got background check attestation from client")
                    }
                    VerifyContext::BackgroundCheck { converter, .. } => {
                        // Forward the request to the actual AS challenge endpoint
                        let CoCoNonce::Jwt(challenge_token) = converter.get_nonce().await?;
                        Ok(Json(AttestationChallengeResponse { challenge_token }))
                    }
                    #[cfg(feature = "__builtin-as")]
                    VerifyContext::Builtin { converter, .. } => {
                        // For builtin mode, generate a local challenge
                        let challenge_token = converter
                            .generate_challenge()
                            .await
                            .map_err(|e| anyhow::anyhow!("Failed to generate challenge: {:?}", e))?;
                        Ok(Json(AttestationChallengeResponse { challenge_token }))
                    }
                },
                None => bail!("client attestation is not required"),
            }
        }
        .await
        .map_err(TngError::ServerVerifyClientGetChallengeTokenFailed)
    }

    /// Interface 3: Attestation Forward - Verify Evidence
    /// x-tng-ohttp-api: /tng/background-check/verify
    ///
    /// This endpoint is a forwarder for the AS (Attestation Service) verification endpoint.
    /// It is used specifically in the "Server verification Client + background check model" scenario.
    pub async fn verify_attestation(
        &self,
        Json(payload): Json<AttestationVerifyRequest>,
    ) -> Result<Json<AttestationVerifyResponse>, TngError> {
        async {
            match self.ra_context.verify_context() {
                Some(verify_ctx) => match verify_ctx {
                    VerifyContext::Passport { .. } => {
                        bail!("Passport model is expected but got background check attestation from client")
                    }
                    VerifyContext::BackgroundCheck { converter, .. } => {
                        let coco_evidence = CocoEvidence::deserialize_from_json(payload.evidence)?;
                        let token = converter.convert(&coco_evidence).await?;
                        Ok(Json(AttestationVerifyResponse {
                            attestation_result: token.into_str(),
                        }))
                    }
                    #[cfg(feature = "__builtin-as")]
                    VerifyContext::Builtin { converter, .. } => {
                        let coco_evidence = CocoEvidence::deserialize_from_json(payload.evidence)
                            .map_err(|e| anyhow::anyhow!("Failed to parse evidence: {:?}", e))?;
                        let token = converter
                            .convert(&coco_evidence)
                            .await
                            .map_err(|e| anyhow::anyhow!("Builtin AS verification failed: {:?}", e))?;
                        Ok(Json(AttestationVerifyResponse {
                            attestation_result: token.into_str(),
                        }))
                    }
                },
                None => bail!("client attestation is not required"),
            }
        }
        .await
        .map_err(TngError::ServerVerifyClientEvidenceFailed)
    }
}

use anyhow::{bail, Result};
use axum::Json;
use rats_cert::tee::GenericConverter;

use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::ohttp::protocol::{
    AttestationChallengeResponse, AttestationVerifyRequest, AttestationVerifyResponse,
};
use crate::tunnel::provider::TngEvidence;
use crate::tunnel::ra_context::VerifyContext;

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
                        let challenge_token = converter.get_nonce().await?;
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
                        let evidence = TngEvidence::deserialize_from_json(payload.evidence)?;
                        let token = converter.convert(&evidence).await?;
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

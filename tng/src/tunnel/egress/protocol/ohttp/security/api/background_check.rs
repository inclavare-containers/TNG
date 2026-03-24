use anyhow::{bail, Result};
use axum::Json;
use rats_cert::tee::GenericConverter as _;

use crate::config::ra::{RaArgs, VerifyArgs};
use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::ohttp::protocol::{
    AttestationChallengeResponse, AttestationVerifyRequest, AttestationVerifyResponse,
};
use crate::tunnel::provider::{create_converter, TngEvidence};

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
            match self.ra_args.as_ref() {
                RaArgs::VerifyOnly(verify) | RaArgs::AttestAndVerify(.., verify) => match verify {
                    VerifyArgs::Passport { .. } => {
                        bail!("Passport model is expected but got background check attestation from client")
                    }
                    VerifyArgs::BackgroundCheck {
                        converter: converter_config,
                        ..
                    } => {
                        let converter = create_converter(converter_config)?;

                        let challenge_token = converter.get_nonce().await?;

                        Ok(Json(AttestationChallengeResponse {
                            challenge_token,
                        }))

                    }
                },
                RaArgs::AttestOnly(..) | RaArgs::NoRa => {
                    bail!("client attestation is not required")
                }
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
            match self.ra_args.as_ref() {
                RaArgs::VerifyOnly(verify) | RaArgs::AttestAndVerify(.., verify) => match verify {
                    VerifyArgs::Passport { .. } => {
                        bail!("Passport model is expected but got background check attestation from client")
                    }
                    VerifyArgs::BackgroundCheck {
                        converter: converter_config,
                        ..
                    } => {
                        let tng_evidence = TngEvidence::deserialize_from_json(payload.evidence)?;

                        let converter = create_converter(converter_config)?;

                        let token = converter.convert(&tng_evidence).await?;

                        let provider = token.provider_type().to_string();
                        let response = AttestationVerifyResponse {
                            attestation_result: token.into_str(),
                            provider,
                        };
                        Ok(Json(response))

                    }
                },
                RaArgs::AttestOnly(..) | RaArgs::NoRa => {
                    bail!("client attestation is not required")
                }
            }
        }
        .await
        .map_err(TngError::ServerVerifyClientEvidenceFailed)
    }
}

use anyhow::{bail, Result};
use axum::Json;
use rats_cert::tee::coco::converter::{CoCoNonce, CocoConverter};
use rats_cert::tee::coco::evidence::CocoEvidence;
use rats_cert::tee::GenericConverter;

use crate::config::ra::{RaArgs, VerifyArgs};
use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::ohttp::protocol::{
    AttestationChallengeResponse, AttestationVerifyRequest, AttestationVerifyResponse,
};

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
                    VerifyArgs::Passport { token_verify: _ } => {
                        bail!("Passport model is expected but got background check attestation from client")
                    }
                    VerifyArgs::BackgroundCheck {
                        as_args,
                    } => {
                        // Forward the request to the actual AS challenge endpoint. Return the challenge token received from the AS
                        let coco_converter = CocoConverter::new(
                            &as_args.as_addr,
                            &as_args.token_verify.policy_ids,
                            as_args.as_is_grpc,
                            &as_args.as_headers,
                        )?;

                        let CoCoNonce::Jwt(challenge_token) = coco_converter.get_nonce().await?;

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
                    VerifyArgs::Passport { token_verify: _ } => {
                        bail!("Passport model is expected but got background check attestation from client")
                    }
                    VerifyArgs::BackgroundCheck {
                        as_args,
                    } => {
                        let coco_evidence = CocoEvidence::deserialize_from_json(payload.evidence)?;

                        let coco_converter = CocoConverter::new(
                            &as_args.as_addr,
                            &as_args.token_verify.policy_ids,
                            as_args.as_is_grpc,
                            &as_args.as_headers,
                        )?;

                        let token  = coco_converter.convert(&coco_evidence).await?;

                        let response = AttestationVerifyResponse {
                            attestation_result: token.into_str(),
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

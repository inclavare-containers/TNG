use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use ohttp::KeyConfig;
use rats_cert::tee::coco::attester::CocoAttester;
use rats_cert::tee::coco::converter::{CoCoNonce, CocoConverter};
use rats_cert::tee::{AttesterPipeline, GenericAttester as _, ReportData};

use crate::config::ra::{AttestArgs, RaArgs};
use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::context::TngStreamContext;
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::ohttp::protocol::userdata::ServerUserData;
use crate::tunnel::ohttp::protocol::{
    AttestationRequest, AttestationResultJwt, HpkeKeyConfig, KeyConfigRequest, KeyConfigResponse,
    ServerAttestationInfo,
};
use crate::tunnel::utils::maybe_cached::{Expire, MaybeCached, RefreshStrategy};

const DEFAULT_KEY_CONFIG_EXPIRE_SECOND: u64 = 5 * 60; // 5 minutes

impl OhttpServerApi {
    /// Interface 1: Get HPKE Configuration
    /// x-tng-ohttp-api: /tng/key-config
    ///
    /// This endpoint is used by TNG Clients to obtain the public key configuration needed
    /// to establish an encrypted channel and verify the server's identity.
    ///
    /// The client accesses this path before connecting to the TNG Server to obtain the
    /// server's public key and Evidence or Attestation Result (if needed).
    ///
    /// This endpoint only needs to be accessed once. Before hpke_key_config.expire_timestamp or
    /// attestation_result expiration, the configuration needs to be refreshed in the background.
    pub async fn get_hpke_configuration(
        &self,
        payload: Option<Json<KeyConfigRequest>>,
        context: TngStreamContext,
    ) -> Result<Response, TngError> {
        match (self.ra_args.as_ref(), &payload) {
            // If the server is set to be a attester with passport mode, and the client is requesting a passport response, we cache it and return the cached response
            (
                RaArgs::AttestOnly(AttestArgs::Passport { aa_args, .. })
                | RaArgs::AttestAndVerify(AttestArgs::Passport { aa_args, .. }, ..),
                Some(Json(KeyConfigRequest {
                    attestation_request: Some(AttestationRequest::Passport),
                })),
            ) => self
                .passport_cache
                .get_or_try_init(|| async {
                    let ra_args = self.ra_args.clone();
                    let ohttp = self.ohttp.clone();
                    let payload = Arc::new(payload);

                    let refresh_strategy = aa_args.refresh_strategy();

                    MaybeCached::new(context.runtime.clone(), refresh_strategy, move || {
                        Box::pin({
                            let ra_args = ra_args.clone();
                            let ohttp = ohttp.clone();
                            let payload = payload.clone();

                            async move {
                                let (response, expire_time) =
                                    Self::get_hpke_configuration_internal(
                                        &ra_args,
                                        &ohttp,
                                        payload.as_ref().clone(),
                                    )
                                    .await?;

                                Ok((response, Expire::ExpireAt(expire_time)))
                            }
                        }) as Pin<Box<_>>
                    })
                    .await
                })
                .await?
                .get_latest()
                .await
                .map(|response: Arc<KeyConfigResponse>| {
                    IntoResponse::into_response(Json(response))
                }),
            // Otherwise, we generate a new response
            _ => Self::get_hpke_configuration_internal(&self.ra_args, &self.ohttp, payload)
                .await
                .map(|(response, _): (KeyConfigResponse, _)| {
                    IntoResponse::into_response(Json(response))
                }),
        }
    }

    async fn get_hpke_configuration_internal(
        ra_args: &RaArgs,
        ohttp: &ohttp::Server,
        payload: Option<Json<KeyConfigRequest>>,
    ) -> Result<(KeyConfigResponse, SystemTime), TngError> {
        let key_config_list = vec![ohttp.config()];

        let encoded_key_config_list = BASE64_STANDARD
            .encode(KeyConfig::encode_list(&key_config_list).map_err(TngError::from)?);

        let (expire_time, expire_timestamp) = {
            // Set expiration timestamp accroding to the attestation configuration (aa_args.refresh_interval). Or we will use the default value.
            let refresh_strategy = match &ra_args {
                RaArgs::AttestOnly(attest) | RaArgs::AttestAndVerify(attest, ..) => match &attest {
                    AttestArgs::Passport { aa_args, .. }
                    | AttestArgs::BackgroundCheck { aa_args } => aa_args.refresh_strategy(),
                },
                RaArgs::VerifyOnly(..) | RaArgs::NoRa => RefreshStrategy::Always,
            };

            let expire_duration_second = match refresh_strategy {
                RefreshStrategy::Periodically { interval } => interval,
                RefreshStrategy::Always => DEFAULT_KEY_CONFIG_EXPIRE_SECOND,
            };

            let expire_time = std::time::SystemTime::now()
                .checked_add(Duration::from_secs(expire_duration_second))
                .with_context(|| {
                    format!(
                    "the expire duration is too far in the future to be represented: {expire_duration_second}s"
                )
                })
                .map_err(TngError::GenServerHpkeConfigurationFailed)?;

            (
                expire_time,
                expire_time
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(TngError::from)?
                    .as_secs(),
            )
        };

        let hpke_key_config = HpkeKeyConfig {
            expire_timestamp,
            encoded_key_config_list,
        };

        let attestation_request = payload
            .map(|Json(payload)| payload.attestation_request)
            .flatten();

        let response = async {
            Ok(match &ra_args {
                RaArgs::AttestOnly(attest) | RaArgs::AttestAndVerify(attest, ..) => {
                    match (attestation_request, attest) {
                        (
                            Some(AttestationRequest::Passport),
                            AttestArgs::Passport { aa_args, as_args },
                        ) => {
                            let coco_attester = CocoAttester::new(&aa_args.aa_addr)?;
                            let coco_converter = CocoConverter::new(
                                &as_args.as_addr,
                                &as_args.token_verify.policy_ids,
                                as_args.as_is_grpc,
                            )?;
                            // fetch a challenge token from attestation service
                            let CoCoNonce::Jwt(challenge_token) = coco_converter.get_nonce().await?;

                            let attester_pipeline =
                                AttesterPipeline::new(coco_attester, coco_converter);

                            let userdata = ServerUserData {
                                challenge_token: Some(challenge_token),
                                hpke_key_config: hpke_key_config.clone(),
                            }.to_claims()?;

                            let token = attester_pipeline
                                .get_evidence(&ReportData::Claims(userdata))
                                .await?;
                            KeyConfigResponse {
                                hpke_key_config,
                                attestation_info: Some(ServerAttestationInfo::Passport {
                                    attestation_result: AttestationResultJwt(token.into_str()),
                                }),
                            }
                        }
                        (
                            Some(AttestationRequest::BackgroundCheck { challenge_token }),
                            AttestArgs::BackgroundCheck { aa_args },
                        ) => {
                            let coco_attester = CocoAttester::new(&aa_args.aa_addr)?;

                            let userdata = ServerUserData {
                                challenge_token: Some(challenge_token),
                                hpke_key_config: hpke_key_config.clone(),
                            }.to_claims()?;

                            let evidence = coco_attester
                                .get_evidence(&ReportData::Claims(userdata))
                                .await?.serialize_to_json()?;

                            KeyConfigResponse {
                                hpke_key_config,
                                attestation_info: Some(ServerAttestationInfo::BackgroundCheck {
                                    evidence,
                                }),
                            }
                        }
                        (
                            Some(AttestationRequest::Passport { .. }),
                            AttestArgs::BackgroundCheck { .. },
                        ) => bail!("Background check model is expected but passport attestation is requested"),
                        (
                            Some(AttestationRequest::BackgroundCheck { .. }),
                            AttestArgs::Passport { .. },
                        ) => bail!("Passport model is expected but background check attestation is requested"),
                        (None, _) => {
                            // Just return the key config when no attestation_request sent from client. This can happens when the server is 'attest' while client is 'no_ra'
                            KeyConfigResponse {
                                hpke_key_config,
                                attestation_info: None,
                            }
                        },
                    }
                }
                RaArgs::VerifyOnly(..) | RaArgs::NoRa => {
                    // No remote attestaion
                    KeyConfigResponse {
                        hpke_key_config,
                        attestation_info: None,
                    }
                }
            })
        }
        .await
        .map_err(TngError::GenServerHpkeConfigurationFailed)?;

        Ok((response, expire_time))
    }
}

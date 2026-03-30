use std::pin::Pin;
use std::sync::Arc;

use anyhow::{bail, Result};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use itertools::Itertools;
use ohttp::KeyConfig;
use rats_cert::tee::coco::converter::CoCoNonce;
use rats_cert::tee::{AttesterPipeline, GenericAttester as _, ReportData};

use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::egress::protocol::ohttp::security::context::TngStreamContext;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::KeyManager;
use crate::tunnel::ohttp::protocol::userdata::ServerUserData;
use crate::tunnel::ohttp::protocol::{
    AttestationRequest, AttestationResultJwt, HpkeKeyConfig, KeyConfigRequest, KeyConfigResponse,
    ServerAttestationInfo,
};
use crate::tunnel::ra_context::{AttestContext, RaContext};
use crate::tunnel::utils::maybe_cached::{Expire, MaybeCached};

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
        // Check if hit the cache
        match (self.ra_context.attest_context(), &payload) {
            // If the server is set to be a attester with passport mode, and the client is requesting a passport response, we cache it and return the cached response
            (
                Some(attest_ctx @ AttestContext::Passport { .. }),
                Some(Json(KeyConfigRequest {
                    attestation_request: Some(AttestationRequest::Passport),
                })),
            ) => self
                .passport_cache
                .read()
                .await
                .get_or_try_init(|| async {
                    let ra_context = self.ra_context.clone();
                    let key_manager = Arc::clone(&self.key_manager);
                    let payload = Arc::new(payload);

                    let refresh_strategy = attest_ctx.refresh_strategy();

                    MaybeCached::new(context.runtime.clone(), refresh_strategy, move || {
                        Box::pin({
                            tracing::info!("Regenerating passport response");

                            let ra_context = ra_context.clone();
                            let key_manager = key_manager.clone();
                            let payload = payload.clone();

                            async move {
                                let response = Self::get_hpke_configuration_internal(
                                    &ra_context,
                                    key_manager.as_ref(),
                                    payload.as_ref().clone(),
                                )
                                .await?;

                                Ok((response, Expire::NoExpire))
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
            _ => Self::get_hpke_configuration_internal(
                &self.ra_context,
                self.key_manager.as_ref(),
                payload,
            )
            .await
            .map(|response: KeyConfigResponse| IntoResponse::into_response(Json(response))),
        }
    }

    async fn get_hpke_configuration_internal(
        ra_context: &RaContext,
        key_manager: &dyn KeyManager,
        payload: Option<Json<KeyConfigRequest>>,
    ) -> Result<KeyConfigResponse, TngError> {
        // Collect all client visible keys, and create encoded_key_config_list
        let all_keys = key_manager.get_client_visible_keys().await?;
        let keys_expire_time = all_keys
            .iter()
            .map(|key_info| key_info.expire_at)
            .min()
            .ok_or_else(|| TngError::NoActiveKey)?;

        let key_config_list = all_keys
            .into_iter()
            .sorted_by_key(|key_info| key_info.key_config.key_id())
            .map(|key_info| key_info.key_config)
            .collect_vec();

        let encoded_key_config_list = BASE64_STANDARD
            .encode(KeyConfig::encode_list(&key_config_list).map_err(TngError::from)?);

        let keys_expire_timestamp = keys_expire_time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(TngError::from)?
            .as_secs();

        // Generate final HpkeKeyConfig
        let hpke_key_config = HpkeKeyConfig {
            expire_timestamp: keys_expire_timestamp,
            encoded_key_config_list,
        };

        let attestation_request = payload.and_then(|Json(payload)| payload.attestation_request);

        let response = async {
            Ok(match ra_context.attest_context() {
                Some(attest_ctx) => match (attestation_request, attest_ctx) {
                    (Some(AttestationRequest::Passport), AttestContext::Passport { attester, converter, .. }) => {
                        // fetch a challenge token from attestation service
                        let CoCoNonce::Jwt(challenge_token) = converter.get_nonce().await?;

                        let attester_pipeline = AttesterPipeline::new(attester, converter);

                        let userdata = ServerUserData {
                            challenge_token: Some(challenge_token),
                            hpke_key_config: hpke_key_config.clone(),
                        }
                        .to_claims()?;

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
                        AttestContext::BackgroundCheck { attester, .. },
                    ) => {
                        let userdata = ServerUserData {
                            challenge_token: Some(challenge_token),
                            hpke_key_config: hpke_key_config.clone(),
                        }
                        .to_claims()?;

                        let evidence = attester
                            .get_evidence(&ReportData::Claims(userdata))
                            .await?
                            .serialize_to_json()?;

                        KeyConfigResponse {
                            hpke_key_config,
                            attestation_info: Some(ServerAttestationInfo::BackgroundCheck {
                                evidence,
                            }),
                        }
                    }
                    (Some(AttestationRequest::Passport), AttestContext::BackgroundCheck { .. }) => {
                        bail!("Background check model is expected but passport attestation is requested")
                    }
                    (Some(AttestationRequest::BackgroundCheck { .. }), AttestContext::Passport { .. }) => {
                        bail!("Passport model is expected but background check attestation is requested")
                    }
                    (None, _) => {

                            // Just return the key config when no attestation_request sent from client. This can happens when the server is 'attest' while client is 'no_ra'
                        KeyConfigResponse {
                            hpke_key_config,
                            attestation_info: None,
                        }
                    }
                },
                None => {
                    // No attestation required (VerifyOnly or NoRa)
                    KeyConfigResponse {
                        hpke_key_config,
                        attestation_info: None,
                    }
                }
            })
        }
        .await
        .map_err(TngError::GenServerHpkeConfigurationResponseFailed)?;

        Ok(response)
    }
}

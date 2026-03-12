#[cfg(unix)]
use anyhow::bail;
use anyhow::Result;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;

use ohttp::KeyConfig;
#[cfg(unix)]
use rats_cert::tee::{AttesterPipeline, GenericAttester as _, GenericConverter as _, ReportData};
#[cfg(unix)]
use std::pin::Pin;
#[cfg(unix)]
use std::sync::Arc;

use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::egress::protocol::ohttp::security::context::TngStreamContext;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::KeyInfo;
#[cfg(unix)]
use crate::tunnel::ohttp::key_config::{KeyConfigExtend, PublicKeyData};
#[cfg(unix)]
use crate::tunnel::ohttp::protocol::userdata::ServerUserData;
#[cfg(unix)]
use crate::tunnel::ohttp::protocol::{AttestationRequest, ServerAttestationInfo};
use crate::tunnel::ohttp::protocol::{HpkeKeyConfig, KeyConfigRequest, KeyConfigResponse};
#[cfg(unix)]
use crate::tunnel::ra_context::AttestContext;
use crate::tunnel::ra_context::RaContext;
#[cfg(unix)]
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
    #[allow(unused_variables)]
    pub async fn get_hpke_configuration(
        &self,
        payload: Option<Json<KeyConfigRequest>>,
        context: TngStreamContext,
    ) -> Result<Response, TngError> {
        // Get the client visible key
        let client_visible_key = self.key_manager.get_client_visible_key().await?;

        // Check if hit the cache
        #[cfg(unix)]
        let response = match (self.ra_context.attest_context(), &payload) {
            // If the server is set to be a attester with passport mode, and the client is requesting a passport response, we cache it and return the cached response
            (
                Some(attest_ctx @ AttestContext::Passport { .. }),
                Some(Json(KeyConfigRequest {
                    attestation_request: Some(AttestationRequest::Passport),
                })),
            ) => {
                // Check if cache exists and is up-to-date
                let expected_public_key = client_visible_key.key_config.public_key()?;

                async fn check_cache_valid(
                    cache_ref: &Option<MaybeCached<(PublicKeyData, KeyConfigResponse), TngError>>,
                    expected_public_key: &PublicKeyData,
                ) -> Result<Option<Arc<(PublicKeyData, KeyConfigResponse)>>, TngError>
                {
                    Ok(match cache_ref {
                        Some(cached) => {
                            let latest_cache = cached.get_latest().await?;
                            let (public_key, _response) = latest_cache.as_ref();
                            if expected_public_key != public_key {
                                // The cache is outdated, regenerate the response
                                None
                            } else {
                                Some(latest_cache)
                            }
                        }
                        None => None,
                    })
                }

                let valid_cache = {
                    let cache_guard = self.passport_cache.read().await;
                    check_cache_valid(&cache_guard, &expected_public_key).await?
                };

                let latest_cache = match valid_cache {
                    Some(latest_cache) => latest_cache,
                    None => {
                        // Cache doesn't exist, create new cache entry
                        let mut cache_guard = self.passport_cache.write().await;

                        // Double-check after acquiring write lock
                        let double_check_valid_cache =
                            check_cache_valid(&cache_guard, &expected_public_key).await?;
                        match double_check_valid_cache {
                            Some(latest_cache) => latest_cache,
                            None => {
                                tracing::info!("Creating new passport cache entry");

                                let ra_context = self.ra_context.clone();
                                let key_manager = Arc::clone(&self.key_manager);
                                let payload = Arc::new(payload);
                                let refresh_strategy = attest_ctx.refresh_strategy();

                                let maybe_cached = MaybeCached::new(
                                    context.runtime.clone(),
                                    refresh_strategy,
                                    move || {
                                        Box::pin({
                                            tracing::info!("Regenerating passport response");

                                            let ra_context = ra_context.clone();
                                            let key_manager = key_manager.clone();
                                            let payload = payload.clone();

                                            async move {
                                                // Get current key and its fingerprint
                                                let current_client_visible_key =
                                                    key_manager.get_client_visible_key().await?;
                                                let current_public_key = current_client_visible_key
                                                    .key_config
                                                    .public_key()?;

                                                let response =
                                                    Self::get_hpke_configuration_internal(
                                                        &ra_context,
                                                        current_client_visible_key,
                                                        payload.as_ref().clone(),
                                                    )
                                                    .await?;

                                                Ok((
                                                    (current_public_key, response),
                                                    Expire::NoExpire,
                                                ))
                                            }
                                        }) as Pin<Box<_>>
                                    },
                                )
                                .await?;

                                let latest_cache = maybe_cached.get_latest().await?;
                                *cache_guard = Some(maybe_cached);

                                latest_cache
                            }
                        }
                    }
                };

                Ok(IntoResponse::into_response(Json(
                    &latest_cache.as_ref().1 as &KeyConfigResponse,
                )))
            }
            // Otherwise, we generate a new response
            _ => {
                Self::get_hpke_configuration_internal(&self.ra_context, client_visible_key, payload)
                    .await
                    .map(|response: KeyConfigResponse| IntoResponse::into_response(Json(response)))
            }
        };

        #[cfg(not(unix))]
        let response =
            Self::get_hpke_configuration_internal(&self.ra_context, client_visible_key, payload)
                .await
                .map(|response: KeyConfigResponse| IntoResponse::into_response(Json(response)));

        response
    }

    #[allow(unused_variables)]
    async fn get_hpke_configuration_internal(
        ra_context: &RaContext,
        client_visible_key: KeyInfo,
        payload: Option<Json<KeyConfigRequest>>,
    ) -> Result<KeyConfigResponse, TngError> {
        // Create encoded_key_config based on the client visible key
        let keys_expire_time = client_visible_key.expire_at;

        let key_config_list = vec![client_visible_key.key_config];

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
            #[cfg(unix)]
            {
                Ok(match ra_context.attest_context() {
                    Some(attest_ctx) => match (attestation_request, attest_ctx) {
                        (Some(AttestationRequest::Passport), AttestContext::Passport { attester, converter, .. }) => {
                            // fetch a challenge token from attestation service
                            let challenge_token = converter.get_nonce().await?;

                            let attester_pipeline = AttesterPipeline::new(attester, converter);

                            let userdata = ServerUserData {
                                challenge_token: Some(challenge_token),
                                hpke_key_config: hpke_key_config.clone(),
                            }
                            .to_claims()?;

                            let token = attester_pipeline
                                .get_evidence(&ReportData::Claims(userdata))
                                .await?;
                            let as_provider = token.provider_type();
                            KeyConfigResponse {
                                hpke_key_config,
                                attestation_info: Some(ServerAttestationInfo::Passport {
                                    attestation_result: token.into_str(),
                                    as_provider: Some(as_provider),
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

                            let tng_evidence = attester
                                .get_evidence(&ReportData::Claims(userdata))
                                .await?;
                            let aa_provider = tng_evidence.provider_type();
                            let evidence = tng_evidence.serialize_to_json()?;

                            KeyConfigResponse {
                                hpke_key_config,
                                attestation_info: Some(ServerAttestationInfo::BackgroundCheck {
                                    evidence,
                                    aa_provider: Some(aa_provider),
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

            #[cfg(not(unix))]
            {
                let _ = attestation_request;
                Ok(KeyConfigResponse {
                    hpke_key_config,
                    attestation_info: None,
                })
            }
        }
        .await
        .map_err(TngError::GenServerHpkeConfigurationResponseFailed)?;

        Ok(response)
    }
}

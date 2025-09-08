use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use axum::response::IntoResponse;
use tracing::Instrument;

use crate::tunnel::ingress::protocol::ohttp::security::OHttpSecurityLayer;
use crate::tunnel::ingress::stream_manager::TngEndpoint;
use crate::tunnel::utils;
use crate::TokioIo;
use crate::{
    config::ingress::CommonArgs,
    tunnel::{
        attestation_result::AttestationResult,
        ingress::protocol::rats_tls::security::RatsTlsSecurityLayer, utils::runtime::TokioRuntime,
    },
};

use super::StreamManager;

pub struct TrustedStreamManager {
    security_layer: SecurityLayer,

    #[allow(unused)]
    runtime: TokioRuntime,
}

impl TrustedStreamManager {
    pub async fn new(
        common_args: &CommonArgs,
        transport_so_mark: Option<u32>,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        if common_args.web_page_inject {
            bail!("The `web_page_inject` field is not supported")
        }

        let ra_args = common_args.ra_args.clone().into_checked()?;

        Ok(Self {
            security_layer: {
                match &common_args.ohttp {
                    Some(ohttp_args) => SecurityLayer::OHttp(Arc::new(
                        OHttpSecurityLayer::new(
                            transport_so_mark,
                            ohttp_args,
                            ra_args,
                            runtime.clone(),
                        )
                        .await?,
                    )),
                    None => SecurityLayer::RatsTls(Arc::new(
                        RatsTlsSecurityLayer::new(transport_so_mark, ra_args, runtime.clone())
                            .await?,
                    )),
                }
            },
            runtime,
        })
    }
}

impl StreamManager for TrustedStreamManager {
    async fn prepare(&self) -> Result<()> {
        match &self.security_layer {
            SecurityLayer::RatsTls(security_layer) => security_layer.prepare().await,
            SecurityLayer::OHttp(security_layer) => security_layer.prepare().await,
        }
    }

    async fn forward_stream<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        downstream: impl tokio::io::AsyncRead
            + tokio::io::AsyncWrite
            + std::marker::Unpin
            + std::marker::Send
            + 'static,
    ) -> Result<(
        Pin<Box<dyn Future<Output = Result<()>> + std::marker::Send + 'static>>,
        Option<AttestationResult>,
    )> {
        match &self.security_layer {
            SecurityLayer::RatsTls(security_layer) => {
                let (upstream, attestation_result) = security_layer
                    .allocate_secured_stream(endpoint.clone())
                    .await?;
                Ok((
                    Box::pin(async { utils::forward::forward_stream(upstream, downstream).await })
                        as Pin<Box<_>>,
                    attestation_result,
                ))
            }
            SecurityLayer::OHttp(security_layer) => {
                async {
                    let endpoint = Arc::new(endpoint.clone());
                    let security_layer = security_layer.clone();

                    let hyper_service = hyper::service::service_fn(
                        move |request: http::Request<hyper::body::Incoming>| {
                            let security_layer = security_layer.clone();
                            let endpoint = endpoint.clone();
                            async move {
                                Ok::<_, Infallible>(
                                    match security_layer
                                        .forward_http_request(
                                            &endpoint,
                                            request.map(axum::body::Body::new),
                                        )
                                        .await
                                    {
                                        Ok((response, _attestation_result)) => response,
                                        Err(error) => error.into_response(),
                                    },
                                )
                            }
                        },
                    );

                    let runtime = self.runtime.clone();

                    Ok((
                        Box::pin(async move {
                            hyper_util::server::conn::auto::Builder::new(runtime)
                                .serve_connection_with_upgrades(
                                    TokioIo::new(downstream),
                                    hyper_service,
                                )
                                .await
                                .map_err(|error| anyhow!("failed to serve connection: {error:?}"))
                        }) as Pin<Box<_>>,
                        None,
                    ))
                }
                .instrument(tracing::info_span!("security"))
                .await
            }
        }
    }

    async fn is_forward_http_request_supported() -> bool {
        true
    }

    async fn forward_http_request<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        request: axum::extract::Request,
    ) -> Result<(axum::response::Response, Option<AttestationResult>)> {
        match &self.security_layer {
            SecurityLayer::RatsTls(..) => Err::<(_, _), anyhow::Error>(anyhow!("unsupported")),
            SecurityLayer::OHttp(security_layer) => Ok(security_layer
                .forward_http_request(&endpoint, request.map(axum::body::Body::new))
                .await?),
        }
    }
}

pub enum SecurityLayer {
    RatsTls(Arc<RatsTlsSecurityLayer>),
    OHttp(Arc<OHttpSecurityLayer>),
}

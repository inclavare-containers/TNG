pub mod security;

#[cfg(unix)]
pub use unix_specific_module::*;
#[cfg(unix)]
mod unix_specific_module {

    use std::{convert::Infallible, pin::Pin, sync::Arc};

    use crate::{
        config::{ingress::OHttpArgs, ra::RaArgs},
        tunnel::{
            endpoint::TngEndpoint,
            ingress::protocol::{
                ohttp::security::OHttpSecurityLayer, ProtocolStreamForwarder,
                ProtocolStreamForwarderOutput,
            },
        },
        CommonStreamTrait, TokioIo, TokioRuntime,
    };

    use anyhow::{anyhow, Result};
    use async_trait::async_trait;
    use axum::response::IntoResponse as _;
    use tracing::Instrument;

    pub struct OHttpStreamForwarder {
        security_layer: Arc<OHttpSecurityLayer>,
        runtime: TokioRuntime,
    }

    impl OHttpStreamForwarder {
        pub async fn new(
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            transport_so_mark: Option<u32>,
            ohttp_args: &OHttpArgs,
            ra_args: RaArgs,
            runtime: TokioRuntime,
        ) -> Result<Self> {
            Ok(Self {
                security_layer: Arc::new(
                    OHttpSecurityLayer::new(
                        #[cfg(any(
                            target_os = "android",
                            target_os = "fuchsia",
                            target_os = "linux"
                        ))]
                        transport_so_mark,
                        ohttp_args,
                        ra_args,
                        runtime.clone(),
                    )
                    .await?,
                ),
                runtime,
            })
        }
    }

    #[async_trait]
    impl ProtocolStreamForwarder for OHttpStreamForwarder {
        async fn forward_stream<'a>(
            &self,
            endpoint: &'a TngEndpoint,
            downstream: Box<dyn CommonStreamTrait + 'static>,
        ) -> Result<ProtocolStreamForwarderOutput> {
            async {
                let endpoint = Arc::new(endpoint.clone());
                let security_layer = self.security_layer.clone();

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
                            .serve_connection_with_upgrades(TokioIo::new(downstream), hyper_service)
                            .await
                            .map_err(|error| anyhow!("failed to serve connection: {error:?}"))
                    }) as Pin<Box<_>>,
                    // TODO: ohttp always return None attestation result in stream level, which may cause misunderstanding when user is reading the logs.
                    None,
                ))
            }
            .instrument(tracing::info_span!("security"))
            .await
        }
    }
}

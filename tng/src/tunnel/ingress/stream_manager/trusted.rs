use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{bail, Result};

use crate::tunnel::ingress::protocol::ohttp::OHttpStreamForwarder;
use crate::tunnel::ingress::protocol::rats_tls::RatsTlsStreamForwarder;
use crate::tunnel::ingress::protocol::ProtocolStreamForwarder;
use crate::tunnel::ingress::stream_manager::TngEndpoint;
use crate::tunnel::ra_context::RaContext;
use crate::CommonStreamTrait;
use crate::{
    config::ingress::CommonArgs,
    tunnel::{attestation_result::AttestationResult, utils::runtime::TokioRuntime},
};

use super::StreamManager;

pub struct TrustedStreamManager {
    stream_forwarder: Box<dyn ProtocolStreamForwarder + Send + Sync + 'static>,

    #[allow(unused)]
    runtime: TokioRuntime,
}

impl TrustedStreamManager {
    pub async fn new(
        common_args: &CommonArgs,
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        parent_runtime: TokioRuntime,
    ) -> Result<Self> {
        if common_args.web_page_inject {
            bail!("The `web_page_inject` field is not supported")
        }

        if common_args.ohttp.is_some() && common_args.rats_tls.is_some() {
            bail!("Cannot specify both `ohttp` and `rats_tls` — they are mutually exclusive");
        }

        // Use a standalone runtime for ohttp and H2 multiplex scenarios to avoid
        // contention with the traffic capture module. For raw-tls (multiplex=false),
        // share the parent runtime since there is no H2 task scheduling overhead.
        let is_h2_or_ohttp = common_args.ohttp.is_some()
            || common_args
                .rats_tls
                .as_ref()
                .map(|a| a.multiplex)
                .unwrap_or(true);
        let runtime = if is_h2_or_ohttp {
            #[cfg(unix)]
            {
                TokioRuntime::new_multi_thread(parent_runtime.shutdown_guard().clone())?
            }
            #[cfg(wasm)]
            {
                TokioRuntime::wasm_main_thread(parent_runtime.shutdown_guard().clone())?
            }
        } else {
            #[cfg(unix)]
            {
                TokioRuntime::current(parent_runtime.shutdown_guard().clone())?
            }
            #[cfg(wasm)]
            {
                TokioRuntime::wasm_main_thread(parent_runtime.shutdown_guard().clone())?
            }
        };

        let ra_args = common_args.ra_args.clone().into_checked()?;
        let ra_context = Arc::new(RaContext::from_ra_args(&ra_args).await?);

        Ok(Self {
            stream_forwarder: {
                match &common_args.ohttp {
                    Some(ohttp_args) => Box::new(
                        OHttpStreamForwarder::new(
                            #[cfg(any(
                                target_os = "android",
                                target_os = "fuchsia",
                                target_os = "linux"
                            ))]
                            transport_so_mark,
                            ohttp_args,
                            ra_context,
                            runtime.clone(),
                        )
                        .await?,
                    ),

                    None => {
                        let multiplex = common_args
                            .rats_tls
                            .as_ref()
                            .map(|a| a.multiplex)
                            .unwrap_or(true);
                        Box::new(
                            RatsTlsStreamForwarder::new(
                                #[cfg(any(
                                    target_os = "android",
                                    target_os = "fuchsia",
                                    target_os = "linux"
                                ))]
                                transport_so_mark,
                                ra_context,
                                runtime.clone(),
                                !multiplex,
                            )
                            .await?,
                        )
                    }
                }
            },
            runtime,
        })
    }
}

impl StreamManager for TrustedStreamManager {
    async fn forward_stream<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        downstream: Box<dyn CommonStreamTrait + 'static>,
    ) -> Result<(
        Pin<Box<dyn Future<Output = Result<()>> + std::marker::Send + 'static>>,
        Option<AttestationResult>,
        /* upstream_local */ Option<SocketAddr>,
    )> {
        self.stream_forwarder
            .forward_stream(endpoint, downstream)
            .await
    }
}

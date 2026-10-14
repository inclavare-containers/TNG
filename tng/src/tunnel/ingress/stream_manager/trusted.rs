use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{bail, Result};
use async_trait::async_trait;

use crate::error::TngError;
use crate::status::{StatusProvider, StatusQueryResult};
use crate::tunnel::ingress::protocol::ohttp::OHttpStreamForwarder;
use crate::tunnel::ingress::protocol::rats_tls::RatsTlsStreamForwarder;
use crate::tunnel::ingress::protocol::ProtocolStreamForwarder;
use crate::tunnel::ingress::stream_manager::TngEndpoint;
use crate::tunnel::ra_context::RaContext;
use crate::CommonStreamTrait;
use crate::{config::ingress::CommonArgs, tunnel::utils::runtime::TokioRuntime, AttestationState};

use super::StreamManager;

/// Which protocol forwarder this manager routes to, so the status tree only
/// advertises the subtree that actually exists.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ForwarderKind {
    OHttp,
    RatsTls,
}

impl ForwarderKind {
    fn segment(&self) -> &'static str {
        match self {
            ForwarderKind::OHttp => "ohttp",
            ForwarderKind::RatsTls => "rats_tls",
        }
    }
}

pub struct TrustedStreamManager {
    stream_forwarder: Box<dyn ProtocolStreamForwarder + Send + Sync + 'static>,
    forwarder_kind: ForwarderKind,

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

        if let Some(rats_tls) = &common_args.rats_tls {
            if (rats_tls.multiplex_max_streams_per_connection.is_some()
                || rats_tls.multiplex_max_connections.is_some())
                && !rats_tls.multiplex
            {
                bail!("`multiplex_max_streams_per_connection` and `multiplex_max_connections` require `rats_tls.multiplex: true`");
            }
        }

        // Use a standalone runtime for ohttp and H2 multiplex scenarios to avoid
        // contention with the traffic capture module. For multiplex=false (single TLS
        // per stream), share the parent runtime since there is no H2 task scheduling overhead.
        let is_h2_or_ohttp = common_args.ohttp.is_some()
            || common_args
                .rats_tls
                .as_ref()
                .unwrap_or(&Default::default())
                .multiplex;
        let runtime = if is_h2_or_ohttp {
            #[cfg(not(wasm))]
            {
                TokioRuntime::new_multi_thread(parent_runtime.shutdown_guard().clone())?
            }
            #[cfg(wasm)]
            {
                TokioRuntime::wasm_main_thread(parent_runtime.shutdown_guard().clone())?
            }
        } else {
            #[cfg(not(wasm))]
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
                        let rats_tls = common_args.rats_tls.as_ref().cloned().unwrap_or_default();
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
                                rats_tls.multiplex,
                                rats_tls.multiplex_max_streams_per_connection,
                                rats_tls.multiplex_max_connections,
                            )
                            .await?,
                        )
                    }
                }
            },
            forwarder_kind: if common_args.ohttp.is_some() {
                ForwarderKind::OHttp
            } else {
                ForwarderKind::RatsTls
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
        AttestationState,
        /* upstream_local */ Option<SocketAddr>,
    )> {
        self.stream_forwarder
            .forward_stream(endpoint, downstream)
            .await
    }
}

#[async_trait]
impl StatusProvider for TrustedStreamManager {
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError> {
        match path {
            [] => Ok(StatusQueryResult::Subtree(vec![self
                .forwarder_kind
                .segment()
                .into()])),
            [segment, rest @ ..] if *segment == self.forwarder_kind.segment() => {
                self.stream_forwarder.query_status(rest).await
            }
            _ => Err(TngError::StatusPathNotFound),
        }
    }
}

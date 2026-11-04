use std::sync::Arc;

use crate::error::TngError;
use crate::status::{StatusProvider, StatusQueryResult};
use crate::{
    config::egress::CommonArgs,
    tunnel::{
        egress::protocol::{
            common::transport::{MaybeDirectlyForward, TransportLayer},
            ohttp::security::OHttpSecurityLayer,
            rats_tls::RatsTlsStreamDecoder,
        },
        ra_context::RaContext,
        stream::CommonStreamTrait,
        upstream::UpstreamConnector,
        utils::runtime::TokioRuntime,
    },
};
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;

/// The protocol this egress terminates, decided once from the config. Each
/// accepted connection is claimed by exactly one of these handlers for its
/// whole lifetime, and each protocol owns its upstream data path: OHTTP
/// serves the outer HTTP and dials a backend connection per decrypted
/// request, RATS-TLS decodes the TLS connection and dials one backend
/// connection (multiplex=false) or one per CONNECT stream (multiplex=true).
/// Both dial through the connection's `UpstreamConnector`.
enum EgressProtocol {
    OHttp(Arc<OHttpSecurityLayer>),
    RatsTls(Box<RatsTlsStreamDecoder>),
}

impl EgressProtocol {
    /// The segment this protocol's status subtree lives under, matching the
    /// config field that selected it.
    fn segment(&self) -> &'static str {
        match self {
            EgressProtocol::OHttp(_) => "ohttp",
            EgressProtocol::RatsTls(_) => "rats_tls",
        }
    }
}

pub struct TrustedStreamManager {
    transport_layer: TransportLayer,

    protocol: EgressProtocol,

    runtime: TokioRuntime,
}

impl TrustedStreamManager {
    pub async fn new(common_args: &CommonArgs, parent_runtime: TokioRuntime) -> Result<Self> {
        if common_args.ohttp.is_some() && common_args.rats_tls.is_some() {
            bail!("Cannot specify both `ohttp` and `rats_tls` — they are mutually exclusive");
        }
        if common_args.rats_tls.as_ref().is_some_and(|args| args.http1)
            && (common_args
                .rats_tls
                .as_ref()
                .is_some_and(|args| args.multiplex)
                || common_args.quic.is_some()
                || common_args.direct_forward.is_some()
                || common_args.ra_args.no_ra
                || common_args.ra_args.attest.is_none()
                || common_args.ra_args.verify.is_some())
        {
            bail!("rats_tls.http1 requires attest-only TCP mode without multiplex, quic or direct_forward");
        }

        let ra_args = common_args.ra_args.clone().into_checked()?;
        let ra_context = Arc::new(RaContext::from_ra_args(&ra_args).await?);

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

        let protocol = match &common_args.ohttp {
            Some(ohttp_args) => EgressProtocol::OHttp(Arc::new(
                OHttpSecurityLayer::new(ra_context, ohttp_args.clone(), runtime.clone()).await?,
            )),
            None => {
                let args = common_args.rats_tls.clone().unwrap_or_default();
                EgressProtocol::RatsTls(Box::new(
                    RatsTlsStreamDecoder::new(
                        ra_context,
                        runtime.clone(),
                        args.multiplex,
                        args.http1,
                    )
                    .await?,
                ))
            }
        };

        Ok(Self {
            transport_layer: TransportLayer::new(
                common_args.direct_forward.clone(),
                &common_args.ohttp,
            )?,
            protocol,
            runtime,
        })
    }

    /// Claims an accepted encrypted connection. The first bytes decide
    /// between a protocol-level direct forward and the configured TNG
    /// protocol; either way the connection is owned from here on by the
    /// handler it was dispatched to, together with every backend leg it
    /// dials through `connector`. The call returns when the connection is
    /// fully handled: a direct forward is pumped inline on this task;
    /// OHTTP runs on `self.runtime`, the protocol's dedicated runtime,
    /// spawned there and awaited here; the RATS-TLS handshake runs on this
    /// task while each decoded leg is pumped from a per-leg task on
    /// `forward_runtime`, the runtime the egress flow uses for the legs of
    /// this connection.
    pub async fn handle_connection(
        &self,
        in_stream: Box<dyn CommonStreamTrait + Sync + 'static>,
        peer: Option<std::net::SocketAddr>,
        connector: Arc<UpstreamConnector>,
        forward_runtime: TokioRuntime,
    ) -> Result<()> {
        let maybe_direct_forward = self
            .transport_layer
            .check_direct_forward(in_stream, self.runtime.clone())
            .await
            .context("Failed to decode stream")?;

        match maybe_direct_forward {
            MaybeDirectlyForward::ContinueAsTngTraffic(stream) => match &self.protocol {
                // OHTTP claims the whole connection at the same level as a
                // direct-forward match claims its plain stream: the security
                // layer serves the outer HTTP and forwards each decrypted
                // request to the backend itself, dialling through
                // `connector`.
                EgressProtocol::OHttp(security_layer) => {
                    let security_layer = security_layer.clone();
                    let handle = self.runtime.spawn_supervised_task(async move {
                        if let Err(error) =
                            security_layer.handle_stream(stream, connector, peer).await
                        {
                            tracing::error!(?error, "Failed to handle OHTTP stream")
                        }
                    });
                    // Isolation stays on the dedicated runtime; awaiting the
                    // task is what makes the dispatch own the connection for
                    // its whole lifetime. A cancelled or panicked handler has
                    // nothing left to report: its errors were logged inside.
                    let _ = handle.await;
                    Ok(())
                }
                EgressProtocol::RatsTls(handler) => {
                    handler
                        .handle_stream(stream, peer, connector, forward_runtime)
                        .await
                }
            },
            MaybeDirectlyForward::DirectlyForward(stream) => {
                // Protocol-level direct forward: determined by TransportLayer.
                // The first bytes of the stream are inspected as HTTP; if the
                // path matches a configured direct_forward regex
                // (common_args.direct_forward_rules), the request bypasses
                // OHTTP decryption entirely and is forwarded as plain HTTP to
                // upstream.
                //
                // This is a per-request decision, distinct from the
                // transport-level decision in the flow. A connection can pass
                // the transport-level IP/ifname check (encrypted=true,
                // entering the trusted path) yet still have its first bytes
                // match a direct_forward rule and be pumped as-is here.
                if let Err(error) = connector
                    .connect_and_forward_bytes(stream, false, false)
                    .await
                {
                    tracing::error!(?error, "Failed to forward stream");
                }
                Ok(())
            }
        }
    }
}

#[async_trait]
impl StatusProvider for TrustedStreamManager {
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError> {
        match path {
            [] => Ok(StatusQueryResult::Subtree(vec![self
                .protocol
                .segment()
                .into()])),
            [segment, rest @ ..] if *segment == self.protocol.segment() => match &self.protocol {
                EgressProtocol::OHttp(security_layer) => security_layer.query_status(rest).await,
                EgressProtocol::RatsTls(handler) => handler.query_status(rest).await,
            },
            _ => Err(TngError::StatusPathNotFound),
        }
    }
}

#[cfg(all(test, unix))]
mod browser_mode_tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn http1_rejects_unsafe_modes_before_contacting_the_attester() -> Result<()> {
        crate::tests::run_test_with_tokio_runtime(|runtime| async move {
            let base = json!({"rats_tls":{"http1":true},"attest":{"aa_provider":"coco_asr","asr_addr":"http://127.0.0.1:1"}});
            let mut modes = Vec::new();
            let mut v=base.clone(); v["rats_tls"]["multiplex"]=json!(true); modes.push(v);
            let mut v=base.clone(); v["no_ra"]=json!(true); modes.push(v);
            let mut v=base.clone(); v.as_object_mut().context("config object")?.remove("attest"); modes.push(v);
            let mut v=base.clone(); v["direct_forward"]=json!([{ "http_path":"/.*" }]); modes.push(v);
            let mut v=base; v["quic"]=json!({}); modes.push(v);
            for value in modes {
                let args: CommonArgs=serde_json::from_value(value)?;
                let result=TrustedStreamManager::new(&args,runtime.clone()).await;
                let error=match result { Ok(_) => anyhow::bail!("unsafe browser configuration accepted"), Err(error)=>error };
                assert!(error.to_string().contains("requires attest-only TCP mode"), "unexpected error: {error:?}");
            }
            Ok(())
        }).await
    }
}

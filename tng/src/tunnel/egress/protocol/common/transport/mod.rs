use std::time::Duration;

use crate::{
    config::egress::{DirectForwardRules, OHttpArgs},
    tunnel::{
        egress::flow::IncomingStream,
        stream::{FirstByteReadTimeoutStream, PreludedStream},
        utils::{
            http_inspector::{HttpRequestInspector, InspectionResult},
            runtime::TokioRuntime,
        },
    },
};

use anyhow::{bail, Context as _, Result};
use direct_forward::DirectForwardTrafficDetector;
use tokio::net::TcpStream;
use tracing::Instrument;

mod direct_forward;

/// Timeout before we receive first byte from peer, This is essential to make it fasts fail quickly when a none tng client is connected to tng server unexpectedly.
const TRANSPORT_LAYER_READ_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct TransportLayer {
    direct_forward_traffic_detector: Option<DirectForwardTrafficDetector>,
}

impl TransportLayer {
    pub fn new(
        direct_forward: Option<DirectForwardRules>,
        ohttp: &Option<OHttpArgs>,
    ) -> Result<Self> {
        // For compatibility with older versions
        let direct_forward = if let Some(ohttp_args) = ohttp {
            match (
                direct_forward,
                ohttp_args.allow_non_tng_traffic_regexes.clone(),
            ) {
                (Some(_), Some(_)) => {
                    bail!("Cannot specify both `direct_forward` and `allow_non_tng_traffic_regexes`. The later is deprecated, please use `direct_forward` instead.");
                }
                (None, Some(allow_non_tng_traffic_regexes)) => {
                    tracing::warn!("`allow_non_tng_traffic_regexes` is deprecated, please use `direct_forward` instead.");
                    Some(DirectForwardRules::from(allow_non_tng_traffic_regexes))
                }
                (direct_forward, None) => direct_forward,
            }
        } else {
            direct_forward
        };

        let direct_forward_traffic_detector = match direct_forward {
            Some(direct_forward) => Some(DirectForwardTrafficDetector::new(direct_forward)?),
            None => None,
        };

        Ok(Self {
            direct_forward_traffic_detector,
        })
    }
}

impl TransportLayer {
    pub async fn check_direct_forward(
        &self,
        in_stream: IncomingStream,
        _runtime: TokioRuntime,
    ) -> Result<MaybeDirectlyForward> {
        let span = tracing::info_span!("transport");

        let IncomingStream::Raw(in_stream) = in_stream;
        // Set timeout for underlying tcp stream, so that we can fail quickly if the peer does not
        // send any byte to us. This may happen when a none tng client is connected to tng server
        // unexpectedly but waiting for tng server to send data first (e.g. the JDBC driver client).
        let in_stream =
            FirstByteReadTimeoutStream::new(in_stream, TRANSPORT_LAYER_READ_FIRST_BYTE_TIMEOUT);

        async {
            tracing::debug!(
                direct_forward_detect_enabled = self.direct_forward_traffic_detector.is_some(),
                "Decoding the underlying connection from downstream"
            );

            let state = if let Some(direct_forward_traffic_detector) =
                &self.direct_forward_traffic_detector
            {
                // First, we need to detect if it is a HTTP connection or a HTTP/2 connection.
                let InspectionResult {
                    inspected_stream,
                    result,
                } = HttpRequestInspector::inspect_stream(in_stream).await;
                let request_info =
                    result.context("Failed during inspecting http request from downstream")?;

                // In this case, the stream is already read by the HttpRequestInspector, so we can
                // unbox it (from FirstByteReadTimeoutStream) to get the underlying stream;
                let inspected_stream = {
                    let PreludedStream {
                        stream,
                        prelude,
                        prelude_pos,
                    } = inspected_stream;
                    PreludedStream {
                        stream: stream.assume_first_byte_completed(),
                        prelude,
                        prelude_pos,
                    }
                };

                // If it should be forwarded directly, we just do that.
                if direct_forward_traffic_detector.should_forward_directly(&request_info) {
                    // Bypass the security layer and wrapping layer, forward the stream to upstream directly.
                    tracing::debug!("Forwarding directly");
                    MaybeDirectlyForward::DirectlyForward(inspected_stream)
                } else {
                    tracing::debug!("Try to decode as TNG traffic");
                    // If not, we try to treat it as tng traffic, it is determined by the configuration of transport layer.
                    MaybeDirectlyForward::ContinueAsTngTraffic(TngTransportStream::Inspected(
                        inspected_stream,
                    ))
                }
            } else {
                // Treat it as a valid tng traffic and try to decode from it.
                MaybeDirectlyForward::ContinueAsTngTraffic(TngTransportStream::Uninspected(
                    in_stream,
                ))
            };

            Ok(state)
        }
        .instrument(span)
        .await
    }
}

pub enum MaybeDirectlyForward {
    DirectlyForward(PreludedStream<TcpStream>),
    ContinueAsTngTraffic(TngTransportStream),
}

pub enum TngTransportStream {
    Inspected(PreludedStream<TcpStream>),
    Uninspected(FirstByteReadTimeoutStream<TcpStream>),
}

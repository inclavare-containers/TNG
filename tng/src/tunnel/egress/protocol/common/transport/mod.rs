use std::time::Duration;

use crate::{
    config::egress::{DecapFromHttp, DirectForwardRules},
    tunnel::{
        stream::CommonStreamTrait,
        utils::{
            http_inspector::{HttpRequestInspector, InspectionResult},
            runtime::TokioRuntime,
        },
    },
};

use anyhow::{bail, Context as _, Result};
use direct_forward::DirectForwardTrafficDetector;
use timeout::FirstByteReadTimeoutStream;
use tracing::Instrument;

mod direct_forward;
mod timeout;

/// Timeout before we receive first byte from peer, This is essential to make it fasts fail quickly when a none tng client is connected to tng server unexpectedly.
const TRANSPORT_LAYER_READ_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct TransportLayer {
    direct_forward_traffic_detector: Option<DirectForwardTrafficDetector>,
}

impl TransportLayer {
    pub fn new(
        direct_forward: Option<DirectForwardRules>,
        decap_from_http: Option<DecapFromHttp>,
    ) -> Result<Self> {
        // For compatibility with older versions
        let direct_forward = if let Some(decap_from_http) = decap_from_http {
            match (
                direct_forward,
                decap_from_http.allow_non_tng_traffic_regexes,
            ) {
                (Some(_), Some(_)) => {
                    bail!("Cannot specify both `direct_forward` and `decap_from_http.allow_non_tng_traffic_regexes`. The later is deprecated, please use `direct_forward` instead.");
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
    pub async fn decode(
        &self,
        in_stream: Box<dyn CommonStreamTrait>,
        _runtime: TokioRuntime,
    ) -> Result<DecodeResult> {
        let span = tracing::info_span!("transport");

        // Set timeout for underly tcp stream
        let in_stream = {
            Box::pin(FirstByteReadTimeoutStream::new(
                in_stream,
                TRANSPORT_LAYER_READ_FIRST_BYTE_TIMEOUT,
            ))
        };

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
                    unmodified_stream,
                    result,
                } = HttpRequestInspector::inspect_stream(in_stream).await;
                let request_info =
                    result.context("Failed during inspecting http request from downstream")?;

                let unmodified_stream = Box::new(unmodified_stream) as Box<dyn CommonStreamTrait>;

                // If it should be forwarded directly, we just do that.
                if direct_forward_traffic_detector.should_forward_directly(&request_info) {
                    // Bypass the security layer and wrapping layer, forward the stream to upstream directly.
                    tracing::debug!("Forwarding directly");
                    DecodeResult::DirectlyForward(unmodified_stream)
                } else {
                    tracing::debug!("Try to decode as TNG traffic");
                    // If not, we try to treat it as tng traffic, it is determined by the configuration of transport layer.
                    DecodeResult::ContinueAsTngTraffic(unmodified_stream)
                }
            } else {
                // Treat it as a valid tng traffic and try to decode from it.
                DecodeResult::ContinueAsTngTraffic(Box::new(in_stream) as Box<dyn CommonStreamTrait>)
            };

            Ok(state)
        }
        .instrument(span)
        .await
    }
}

pub enum DecodeResult {
    ContinueAsTngTraffic(Box<dyn CommonStreamTrait>),
    DirectlyForward(Box<dyn CommonStreamTrait>),
}

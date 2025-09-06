use axum::response::IntoResponse;

use crate::{
    error::TngError, tunnel::egress::stream_manager::trusted::StreamType, AttestationResult,
    TokioIo, TokioRuntime,
};

#[derive(Clone)]
pub struct OhttpServerState {
    pub runtime: TokioRuntime,
    pub sender: tokio::sync::mpsc::UnboundedSender<(StreamType, Option<AttestationResult>)>,
}

impl OhttpServerState {
    pub async fn forward_request<B>(
        &self,
        req: http::Request<B>,
        attestation_request: Option<AttestationResult>,
    ) -> Result<axum::response::Response, TngError>
    where
        B: http_body::Body + 'static,
        B: std::marker::Send,
        <B as http_body::Body>::Data: std::marker::Send,
        <B as http_body::Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        // TODO: maybe adjust forward the request to the upstream server with reqwest?

        let (s1, s2) = tokio::io::duplex(4096);

        self.sender
            .send((StreamType::SecuredStream(Box::new(s2)), attestation_request))
            .map_err(|_| TngError::ConnectUpstreamFailed)?;

        // TODO: support send both http1 and http2 payload
        let (mut send_request, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s1))
            .await
            .map_err(TngError::HttpPlainTextForwardError)?;

        self.runtime.spawn_supervised_task_current_span(async move {
            if let Err(e) = conn.await {
                tracing::error!(?e, "The HTTP connection with upstream is broken");
            }
        });

        tracing::debug!("Forwarding HTTP request to upstream now");
        send_request
            .send_request(req)
            .await
            .map(|resopnse| axum::response::Response::into_response(resopnse))
            .map_err(TngError::HttpPlainTextForwardError)
    }
}

mod pool;
mod verifier;

use anyhow::{bail, Context as _, Result};
use http::{Request, StatusCode, Version};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tracing::Instrument;

use crate::tunnel::ingress::core::TngEndpoint;

use self::pool::ClientPool;

use super::stream_manager::StreamManager;

pub struct TrustedStreamManager {
    pool: ClientPool,
}

impl TrustedStreamManager {
    pub fn new() -> Self {
        Self {
            pool: Default::default(),
        }
    }
}

impl StreamManager for TrustedStreamManager {
    type StreamType = TokioIo<Upgraded>;

    async fn new_stream(&self, endpoint: &TngEndpoint) -> Result<Self::StreamType> {
        let client = self.pool.get_client(endpoint).await?;

        let fut = async {
            let req = Request::connect("https://tng.internal/")
                .version(Version::HTTP_2)
                .body(axum::body::Body::empty())
                .unwrap();

            tracing::debug!("Send HTTP/2 CONNECT request via rats-tls session");
            let mut resp = client
                .hyper
                .request(req)
                .await
                .context("Failed to send HTTP/2 CONNECT request")?;

            if resp.status() != StatusCode::OK {
                bail!(
                    "Failed to send HTTP/2 CONNECT request, bad status '{}', got: {:?}",
                    resp.status(),
                    resp
                );
            }
            let upgraded = hyper::upgrade::on(&mut resp).await.with_context(|| {
                format!(
                    "Failed to establish HTTP/2 CONNECT tunnel with '{}'",
                    endpoint
                )
            })?;

            tracing::debug!("Trusted tunnel is enstablished");

            Ok(upgraded)
        };

        let upgraded = fut
            .instrument(tracing::info_span!(
                "trust_tunnel",
                rats_tls_session_id = client.id
            ))
            .await?;

        Ok(TokioIo::new(upgraded))
    }
}

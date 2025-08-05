use anyhow::{bail, Context as _, Result};
use http::{Request, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use hyper::upgrade::Upgraded;

use crate::tunnel::{attestation_result::AttestationResult, utils::tokio::TokioIo};

use super::security::RatsTlsClient;

pub struct TcpWrappingLayer {}

impl TcpWrappingLayer {
    pub async fn create_stream_from_hyper(
        client: &RatsTlsClient,
    ) -> Result<(TokioIo<Upgraded>, Option<AttestationResult>)> {
        let req = Request::connect("https://tng.internal/")
            .version(Version::HTTP_2)
            // .version(Version::HTTP_11)
            .body(BoxBody::new(http_body_util::Empty::new()))?;

        tracing::debug!("Establishing the wrapping layer");

        let mut resp = client
            .hyper
            .request(req)
            .await
            .context("Failed to send HTTP/2 CONNECT request")?;

        let attestation_result = resp
            .extensions()
            .get::<Option<AttestationResult>>()
            .context("Can not find attestation result")?
            .clone();

        if resp.status() != StatusCode::OK {
            bail!(
                "Failed to send HTTP/2 CONNECT request, bad status '{}', got: {:?}",
                resp.status(),
                resp
            );
        }
        let upgraded = hyper::upgrade::on(&mut resp)
            .await
            .context("Failed to establish HTTP/2 CONNECT tunnel")?;

        tracing::debug!("Trusted tunnel established");

        Ok((TokioIo::new(upgraded), attestation_result))
    }
}

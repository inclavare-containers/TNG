use std::net::SocketAddr;

use anyhow::{bail, Context as _, Result};
use http::{Request, StatusCode, Version};
use http_body_util::combinators::BoxBody;

use crate::{
    tunnel::{
        attestation_result::AttestationResult,
        utils::{self},
    },
    CommonStreamTrait,
};

use super::security::RatsTlsClient;

pub struct RatsTlsWrappingLayer {}

impl RatsTlsWrappingLayer {
    pub async fn create_stream_from_hyper(
        client: &RatsTlsClient,
    ) -> Result<(
        impl CommonStreamTrait + Sync,
        /* local_addr */ SocketAddr,
        Option<AttestationResult>,
    )> {
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

        let local_addr = resp
            .extensions()
            .get::<hyper_util::client::legacy::connect::HttpInfo>()
            .context("Can not get local addr")?
            .local_addr();

        let upgraded = hyper::upgrade::on(&mut resp)
            .await
            .context("Failed to establish HTTP/2 CONNECT tunnel")?;

        let Ok(stream) = utils::hyper::downcast_h2upgraded(upgraded) else {
            bail!("failed to downcast to inner stream");
        };

        tracing::debug!("Trusted tunnel established");

        Ok((stream, local_addr, attestation_result))
    }
}

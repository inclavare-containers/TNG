use std::net::SocketAddr;

use anyhow::{bail, Context as _, Result};
use http::{Request, StatusCode, Version};
use http_body_util::combinators::BoxBody;

use super::security::RatsTlsClient;
use crate::{
    tunnel::{attestation_result::AttestationState, utils},
    CommonStreamTrait,
};

pub struct RatsTlsWrappingLayer {}

impl RatsTlsWrappingLayer {
    pub async fn create_stream_from_hyper(
        client: &RatsTlsClient,
    ) -> Result<(
        impl CommonStreamTrait + Sync,
        /* local_addr */ Option<SocketAddr>,
        AttestationState,
        /* session_id */ u64,
    )> {
        let req = Request::connect("https://tng.internal/")
            .version(Version::HTTP_2)
            .body(BoxBody::new(http_body_util::Empty::new()))?;

        tracing::debug!(
            session_id = client.id,
            "Establishing the wrapping layer (H2 CONNECT)"
        );

        let mut resp = client
            .hyper
            .request(req)
            .await
            .context("Failed to send HTTP/2 CONNECT request")?;

        tracing::debug!(session_id = client.id, "H2 CONNECT response received");

        let attestation_state = resp
            .extensions()
            .get::<AttestationState>()
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

        tracing::debug!(
            session_id = client.id,
            "Trusted tunnel established (H2 upgrade OK)"
        );

        Ok((stream, Some(local_addr), attestation_state, client.id))
    }
}

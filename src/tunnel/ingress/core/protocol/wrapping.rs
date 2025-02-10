use anyhow::{bail, Context as _, Result};
use http::{Request, StatusCode, Version};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;

use super::security::RatsTlsClient;

pub async fn create_stream_from_hyper(client: &RatsTlsClient) -> Result<TokioIo<Upgraded>> {
    let req = Request::connect("https://tng.internal/")
        .version(Version::HTTP_2)
        .body(axum::body::Body::empty())
        .unwrap();

    tracing::debug!("Establish the wrapping layer");
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
    let upgraded = hyper::upgrade::on(&mut resp)
        .await
        .with_context(|| format!("Failed to establish HTTP/2 CONNECT tunnel"))?;

    tracing::debug!("Trusted tunnel established, now transporting application data stream.");

    Ok(TokioIo::new(upgraded))
}

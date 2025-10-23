pub mod client;
mod path_rewrite;

use std::{collections::HashMap, sync::Arc};

#[cfg(unix)]
use crate::tunnel::utils::socket::{
    TCP_KEEPALIVE_IDLE_SECS, TCP_KEEPALIVE_INTERVAL_SECS, TCP_KEEPALIVE_PROBE_COUNT,
};
use crate::{
    config::{ingress::OHttpArgs, ra::RaArgs},
    error::TngError,
    tunnel::{
        endpoint::TngEndpoint,
        ingress::protocol::ohttp::security::{client::OHttpClient, path_rewrite::PathRewriteGroup},
    },
    AttestationResult, TokioRuntime, HTTP_REQUEST_USER_AGENT_HEADER,
};
use anyhow::{Context, Result};
use http::HeaderValue;
use tokio::sync::{OnceCell, RwLock};
use url::Url;

pub struct OHttpSecurityLayer {
    ra_args: RaArgs,
    http_client: Arc<reqwest::Client>,
    ohttp_clients: RwLock<HashMap<Url, Arc<OnceCell<Arc<OHttpClient>>>>>,
    path_rewrite_group: PathRewriteGroup,
    runtime: TokioRuntime,
}

impl OHttpSecurityLayer {
    pub async fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        ohttp_args: &OHttpArgs,
        ra_args: RaArgs,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let http_client = {
            let mut builder = reqwest::Client::builder();
            builder = builder.default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    http::header::USER_AGENT,
                    HeaderValue::from_static(HTTP_REQUEST_USER_AGENT_HEADER),
                );
                headers
            });

            #[cfg(unix)]
            {
                use std::time::Duration;
                builder =
                    builder.tcp_keepalive(Duration::from_secs(TCP_KEEPALIVE_IDLE_SECS as u64));
                builder = builder.tcp_keepalive_interval(Duration::from_secs(
                    TCP_KEEPALIVE_INTERVAL_SECS as u64,
                ));
                builder = builder.tcp_keepalive_retries(TCP_KEEPALIVE_PROBE_COUNT);
                // TODO: update reqwest and hyper-util version to support tcp_user_timeout()
                // builder = builder.tcp_user_timeout(Duration::from_secs(TCP_USER_TIMEOUT_SECS as u64));
            }

            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            {
                builder = builder.tcp_mark(transport_so_mark);
            }
            builder.build()?
        };

        Ok(Self {
            ra_args,
            http_client: Arc::new(http_client),
            ohttp_clients: Default::default(),
            path_rewrite_group: PathRewriteGroup::new(&ohttp_args.path_rewrites)?,
            runtime,
        })
    }

    pub async fn forward_http_request<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        request: axum::extract::Request,
    ) -> Result<(axum::response::Response, Option<AttestationResult>), TngError> {
        async {
            let base_url = self.construct_base_url(endpoint, &request)?;

            let ohttp_client = self.get_or_create_ohttp_client(base_url).await?;

            ohttp_client.forward_request(request).await
        }
        .await
        .map_err(|error| {
            tracing::error!(?error, "Failed to forward HTTP request");
            error
        })
    }

    fn construct_base_url(
        &self,
        endpoint: &TngEndpoint,
        request: &axum::extract::Request,
    ) -> Result<Url, TngError> {
        let old_uri = request.uri();
        let base_url = {
            let original_path = old_uri.path();
            let mut rewrited_path = self
                .path_rewrite_group
                .rewrite(original_path)
                .unwrap_or_else(|| "/".to_string());

            if !rewrited_path.starts_with("/") {
                rewrited_path.insert(0, '/');
            }

            tracing::debug!(original_path, rewrited_path, "path is rewrited");

            let url = format!(
                "http://{}:{}{rewrited_path}",
                endpoint.host(),
                endpoint.port()
            );
            let url = url
                .parse::<Url>()
                .with_context(|| format!("Not a valid URL: {}", url))
                .map_err(TngError::CreateOHttpClientFailed)?;

            url
        };
        Ok(base_url)
    }

    async fn get_or_create_ohttp_client<'a>(
        &self,
        base_url: Url,
    ) -> Result<Arc<OHttpClient>, TngError> {
        // Try to read the ohttp client entry.
        let cell = {
            let read = self.ohttp_clients.read().await;
            read.get(&base_url).map(|v| v.clone())
        };

        // If no entry exists, create one with uninitialized value.
        let cell = match cell {
            Some(cell) => cell,
            _ => self
                .ohttp_clients
                .write()
                .await
                .entry(base_url.clone())
                .or_default()
                .clone(),
        };

        // read from the cell
        cell.get_or_try_init(|| async {
            Ok(Arc::new(
                OHttpClient::new(
                    self.ra_args.clone(),
                    self.http_client.clone(),
                    base_url,
                    self.runtime.clone(),
                )
                .await
                .map_err(TngError::CreateOHttpClientFailed)?,
            ))
        })
        .await
        .cloned()
    }
}

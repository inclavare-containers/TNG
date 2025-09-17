pub mod client;
mod path_rewrite;

use std::{collections::HashMap, sync::Arc};

use crate::{
    config::{ingress::OHttpArgs, ra::RaArgs},
    error::TngError,
    tunnel::{endpoint::TngEndpoint, ingress::protocol::ohttp::security::client::OHttpClient},
    AttestationResult, TokioRuntime, HTTP_REQUEST_USER_AGENT_HEADER,
};
use anyhow::Result;
use http::HeaderValue;
use tokio::sync::{OnceCell, RwLock};

pub struct OHttpSecurityLayer {
    ohttp_args: OHttpArgs,
    ra_args: RaArgs,
    http_client: Arc<reqwest::Client>,
    ohttp_clients: RwLock<HashMap<TngEndpoint, Arc<OnceCell<Arc<OHttpClient>>>>>,
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
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            {
                builder = builder.tcp_mark(transport_so_mark);
            }
            builder.build()?
        };

        Ok(Self {
            ohttp_args: ohttp_args.clone(),
            ra_args,
            http_client: Arc::new(http_client),
            ohttp_clients: Default::default(),
            runtime,
        })
    }

    pub async fn forward_http_request<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        request: axum::extract::Request,
    ) -> Result<(axum::response::Response, Option<AttestationResult>), TngError> {
        let ohttp_client = self.get_or_create_ohttp_client(endpoint).await?;

        ohttp_client
            .forward_request(request)
            .await
            .map_err(|error| {
                tracing::error!(?error, "Failed to forward HTTP request");
                error
            })
    }

    async fn get_or_create_ohttp_client<'a>(
        &self,
        endpoint: &'a TngEndpoint,
    ) -> Result<Arc<OHttpClient>, TngError> {
        // Try to read the ohttp client entry.
        let cell = {
            let read = self.ohttp_clients.read().await;
            read.get(&endpoint).map(|v| v.clone())
        };

        // If no entry exists, create one with uninitialized value.
        let cell = match cell {
            Some(cell) => cell,
            _ => self
                .ohttp_clients
                .write()
                .await
                .entry(endpoint.clone())
                .or_default()
                .clone(),
        };

        // read from the cell
        cell.get_or_try_init(|| async {
            Ok(Arc::new(
                OHttpClient::new(
                    &self.ohttp_args,
                    self.ra_args.clone(),
                    self.http_client.clone(),
                    endpoint.clone(),
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

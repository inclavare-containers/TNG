pub mod client;
mod path_rewrite;

use std::{collections::HashMap, sync::Arc};

#[cfg(not(wasm))]
use crate::status::{StatusProvider, StatusQueryResult};
#[cfg(unix)]
use crate::tunnel::utils::socket::{
    TCP_KEEPALIVE_IDLE_SECS, TCP_KEEPALIVE_INTERVAL_SECS, TCP_KEEPALIVE_PROBE_COUNT,
};
use crate::{
    config::ingress::OHttpArgs,
    error::TngError,
    tunnel::{
        endpoint::TngEndpoint,
        ingress::protocol::ohttp::security::{
            client::{OHttpClient, ServerStatusEntry},
            path_rewrite::PathRewriteGroup,
        },
        ra_context::RaContext,
    },
    AttestationResult, TokioRuntime, HTTP_REQUEST_USER_AGENT_HEADER,
};
use anyhow::{Context, Result};
#[cfg(not(wasm))]
use async_trait::async_trait;
use http::HeaderValue;
use serde::Serialize;
use tokio::sync::{OnceCell, RwLock};
use url::Url;

/// Cached OHTTP client per base URL, lazily initialized on first use.
type OhttpClientCache = RwLock<HashMap<Url, Arc<OnceCell<Arc<OHttpClient>>>>>;

/// Root status response for /status/.../ohttp/keys.
#[derive(Serialize)]
struct ServersStatus {
    servers: Vec<ServerStatusEntry>,
}

pub struct OHttpSecurityLayer {
    ra_context: Arc<RaContext>,
    http_client: Arc<reqwest::Client>,
    ohttp_clients: OhttpClientCache,
    path_rewrite_group: PathRewriteGroup,
    runtime: TokioRuntime,
}

impl OHttpSecurityLayer {
    pub async fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        ohttp_args: &OHttpArgs,
        ra_context: Arc<RaContext>,
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
            }

            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            {
                builder = builder.tcp_mark(transport_so_mark);
            }
            builder.build()?
        };

        let ohttp_clients: OhttpClientCache = Default::default();

        Ok(Self {
            ra_context,
            http_client: Arc::new(http_client),
            ohttp_clients,
            path_rewrite_group: PathRewriteGroup::new(&ohttp_args.path_rewrites)?,
            runtime,
        })
    }

    pub async fn forward_http_request(
        &self,
        endpoint: &TngEndpoint,
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

            if !rewrited_path.starts_with('/') {
                rewrited_path.insert(0, '/');
            }

            tracing::debug!(original_path, rewrited_path, "path is rewrited");

            let url = format!(
                "http://{}:{}{rewrited_path}",
                endpoint.host(),
                endpoint.port()
            );

            url.parse::<Url>()
                .with_context(|| format!("Not a valid URL: {url}"))
                .map_err(TngError::CreateOHttpClientFailed)?
        };
        Ok(base_url)
    }

    async fn get_or_create_ohttp_client(
        &self,
        base_url: Url,
    ) -> Result<Arc<OHttpClient>, TngError> {
        // Try to read the ohttp client entry.
        let cell = {
            let read = self.ohttp_clients.read().await;
            read.get(&base_url).cloned()
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
                    self.ra_context.clone(),
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

#[cfg(not(wasm))]
#[async_trait]
impl StatusProvider for OHttpSecurityLayer {
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError> {
        match path {
            [] => Ok(StatusQueryResult::Subtree(vec!["keys".into()])),
            ["keys"] => {
                let map = self.ohttp_clients.read().await;
                let mut servers = Vec::with_capacity(map.len());
                for cell in map.values() {
                    if let Some(client) = cell.get() {
                        if let Some(entry) = client.server_status().await {
                            servers.push(entry);
                        }
                    }
                }
                let status = ServersStatus { servers };
                serde_json::to_value(&status)
                    .map(StatusQueryResult::Value)
                    .map_err(|e| {
                        tracing::error!(?e, "Failed to serialise server status");
                        TngError::StatusPathNotFound
                    })
            }
            _ => Err(TngError::StatusPathNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::client::ServerStatusEntry;
    use super::ServersStatus;

    #[test]
    fn test_servers_status_collection() {
        let status = ServersStatus {
            servers: vec![
                ServerStatusEntry {
                    url: "http://a.com".to_string(),
                    server_public_key: Some("key1".to_string()),
                    server_attestation: None,
                },
                ServerStatusEntry {
                    url: "http://b.com".to_string(),
                    server_public_key: Some("key2".to_string()),
                    server_attestation: Some("jwt2".to_string()),
                },
            ],
        };
        let value = serde_json::to_value(&status).unwrap();
        let servers = value["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0]["url"], "http://a.com");
        assert_eq!(servers[0]["server_public_key"], "key1");
        assert!(servers[0].get("server_attestation").is_none());
        assert_eq!(servers[1]["url"], "http://b.com");
        assert_eq!(servers[1]["server_attestation"], "jwt2");
    }

    #[test]
    fn test_servers_status_empty() {
        let status = ServersStatus { servers: vec![] };
        let value = serde_json::to_value(&status).unwrap();
        let servers = value["servers"].as_array().unwrap();
        assert!(servers.is_empty());
    }
}

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
    config::ingress::{OHttpArgs, PathDefault},
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

/// Compute the outer OHTTP POST path used when no `path_rewrites` rule matches
/// (or `path_rewrites` is unset/empty). The caller is responsible for ensuring
/// the result starts with `/` (see `construct_base_url`).
fn fallback_outer_path(path_default: PathDefault, original_path: &str) -> String {
    match path_default {
        PathDefault::Root => "/".to_string(),
        PathDefault::Original => original_path.to_string(),
    }
}

/// Root status response for /status/.../ohttp/keys.
#[derive(Serialize)]
#[cfg_attr(wasm, allow(dead_code))]
struct ServersStatus {
    servers: Vec<ServerStatusEntry>,
}

/// Derive the URL scheme for the outer OHTTP POST from the `tls` config flag.
/// `Some(true)` ⇒ `https`, anything else ⇒ `http` (the default, pre-feature behavior).
fn scheme_from_tls(tls: Option<bool>) -> &'static str {
    match tls {
        Some(true) => "https",
        _ => "http",
    }
}

/// Build the reqwest client used to forward OHTTP POSTs to the upstream.
///
/// On non-wasm targets this honors `ohttp_args.tls_ca_certs` (each file may be a
/// single cert or a PEM bundle) by adding them as trusted roots. On wasm the
/// browser performs TLS and controls trust; `tls_ca_certs` does not exist there
/// (see `OHttpArgs`), and the `https://` URL scheme alone drives browser TLS.
#[cfg(not(wasm))]
fn build_ohttp_http_client(
    ohttp_args: &OHttpArgs,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    transport_so_mark: Option<u32>,
) -> Result<reqwest::Client> {
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
        builder = builder.tcp_keepalive(Duration::from_secs(TCP_KEEPALIVE_IDLE_SECS as u64));
        builder =
            builder.tcp_keepalive_interval(Duration::from_secs(TCP_KEEPALIVE_INTERVAL_SECS as u64));
        builder = builder.tcp_keepalive_retries(TCP_KEEPALIVE_PROBE_COUNT);
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    {
        builder = builder.tcp_mark(transport_so_mark);
    }

    for path in &ohttp_args.tls_ca_certs {
        let pem =
            std::fs::read(path).with_context(|| format!("Failed to read TLS CA cert: {path}"))?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .with_context(|| format!("Failed to parse TLS CA cert bundle: {path}"))?;
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }

    if !ohttp_args.tls_ca_certs.is_empty() && ohttp_args.tls != Some(true) {
        tracing::warn!(
            paths = ?ohttp_args.tls_ca_certs,
            "tls_ca_certs are configured but `tls` is not enabled; \
             the CA list is ignored because OHTTP is forwarded over plain HTTP"
        );
    }

    Ok(builder.build()?)
}

/// wasm build of the OHTTP reqwest client. The browser controls TLS and the
/// trust store, so no CA configuration is applied here; the `https://` URL
/// scheme (driven by `scheme_from_tls`) is what engages browser TLS. Takes no
/// `ohttp_args` because `tls_ca_certs` does not exist on wasm.
#[cfg(wasm)]
fn build_ohttp_http_client() -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    builder = builder.default_headers({
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            HeaderValue::from_static(HTTP_REQUEST_USER_AGENT_HEADER),
        );
        headers
    });
    Ok(builder.build()?)
}

pub struct OHttpSecurityLayer {
    ra_context: Arc<RaContext>,
    http_client: Arc<reqwest::Client>,
    ohttp_clients: OhttpClientCache,
    path_rewrite_group: PathRewriteGroup,
    path_default: PathDefault,
    /// Outer-POST URL scheme: `"http"` (default) or `"https"` when `ohttp.tls` is enabled.
    scheme: &'static str,
    runtime: TokioRuntime,
    /// Headers to copy from the inner (plaintext) request to the outer (ciphertext) POST.
    passthrough_request_headers: Arc<crate::config::header_passthrough::HeaderPassthroughSpec>,
    /// Headers to copy from the outer (ciphertext) response to the inner (plaintext) response.
    passthrough_response_headers: Arc<crate::config::header_passthrough::HeaderPassthroughSpec>,
}

impl OHttpSecurityLayer {
    pub async fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        ohttp_args: &OHttpArgs,
        ra_context: Arc<RaContext>,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let scheme = scheme_from_tls(ohttp_args.tls);

        let http_client = {
            #[cfg(not(wasm))]
            {
                build_ohttp_http_client(
                    ohttp_args,
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    transport_so_mark,
                )?
            }
            #[cfg(wasm)]
            {
                build_ohttp_http_client()?
            }
        };

        let ohttp_clients: OhttpClientCache = Default::default();

        let passthrough_request_headers = Arc::new(
            ohttp_args
                .header_passthrough
                .as_ref()
                .map(|hp| hp.request_headers.clone())
                .unwrap_or_default(),
        );

        let passthrough_response_headers = Arc::new(
            ohttp_args
                .header_passthrough
                .as_ref()
                .map(|hp| hp.response_headers.clone())
                .unwrap_or_default(),
        );

        Ok(Self {
            ra_context,
            http_client: Arc::new(http_client),
            ohttp_clients,
            path_rewrite_group: PathRewriteGroup::new(&ohttp_args.path_rewrites)?,
            path_default: ohttp_args.path_default,
            scheme,
            runtime,
            passthrough_request_headers,
            passthrough_response_headers,
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
            // When no path_rewrite rule matches (path_rewrites unset/empty or
            // no regex hit), fall back according to `path_default`: `/` (Root,
            // the historical default) or the inner request's original path.
            let mut rewrited_path = self
                .path_rewrite_group
                .rewrite(original_path)
                .unwrap_or_else(|| fallback_outer_path(self.path_default, original_path));

            if !rewrited_path.starts_with('/') {
                rewrited_path.insert(0, '/');
            }

            tracing::debug!(original_path, rewrited_path, "path is rewrited");

            let url = format!(
                "{}://{}{rewrited_path}",
                self.scheme,
                endpoint.http_authority()
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
                    self.passthrough_request_headers.clone(),
                    self.passthrough_response_headers.clone(),
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
    use super::{fallback_outer_path, ServersStatus};
    use crate::config::ingress::{OHttpArgs, PathDefault};
    use anyhow::Result;

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

    #[test]
    fn test_fallback_outer_path_root() {
        assert_eq!(fallback_outer_path(PathDefault::Root, "/foo/bar"), "/");
    }

    #[test]
    fn test_fallback_outer_path_root_ignores_original() {
        // Root always yields "/" regardless of the original path.
        assert_eq!(
            fallback_outer_path(PathDefault::Root, "/deeply/nested/path"),
            "/"
        );
    }

    #[test]
    fn test_fallback_outer_path_original() {
        assert_eq!(
            fallback_outer_path(PathDefault::Original, "/foo/bar"),
            "/foo/bar"
        );
    }

    #[test]
    fn scheme_from_tls_maps_correctly() {
        assert_eq!(super::scheme_from_tls(None), "http");
        assert_eq!(super::scheme_from_tls(Some(false)), "http");
        assert_eq!(super::scheme_from_tls(Some(true)), "https");
    }

    #[cfg(not(wasm))]
    #[test]
    fn build_client_with_valid_ca_bundle_succeeds() -> Result<()> {
        // A self-signed CA cert (PEM). `from_pem_bundle` parses it; adding it as
        // a root must not error.
        const CA_PEM: &[u8] = include_bytes!("tls_test_ca.pem");
        let dir = tempfile::tempdir()?;
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, CA_PEM)?;

        let ohttp_args = OHttpArgs {
            tls: Some(true),
            tls_ca_certs: vec![ca_path.to_string_lossy().to_string()],
            ..Default::default()
        };

        let _client = super::build_ohttp_http_client(
            &ohttp_args,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
        )?;
        Ok(())
    }

    #[cfg(not(wasm))]
    #[test]
    fn build_client_missing_ca_path_errors_with_context() {
        let ohttp_args = OHttpArgs {
            tls: Some(true),
            tls_ca_certs: vec!["/definitely/does/not/exist/ca.pem".to_string()],
            ..Default::default()
        };

        let error = super::build_ohttp_http_client(
            &ohttp_args,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
        )
        .unwrap_err();

        // The label must mention the path AND preserve a source (io::Error) in the chain.
        let msg = format!("{:#}", error);
        assert!(
            msg.contains("/definitely/does/not/exist/ca.pem"),
            "missing path label: {msg}"
        );
        assert!(
            error.source().is_some(),
            "error source chain dropped: {error:?}"
        );
    }

    #[cfg(not(wasm))]
    #[test]
    fn build_client_malformed_pem_errors_with_context() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let bad = dir.path().join("bad.pem");
        // A PEM block with valid CERTIFICATE markers but an invalid base64 body
        // is rejected by `from_pem_bundle` — exercising the parse-error context.
        std::fs::write(
            &bad,
            b"-----BEGIN CERTIFICATE-----\n!!!not valid base64!!!\n-----END CERTIFICATE-----\n",
        )?;

        let ohttp_args = OHttpArgs {
            tls: Some(true),
            tls_ca_certs: vec![bad.to_string_lossy().to_string()],
            ..Default::default()
        };

        let error = super::build_ohttp_http_client(
            &ohttp_args,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
        )
        .unwrap_err();
        let msg = format!("{:#}", error);
        assert!(
            msg.contains("Failed to parse TLS CA cert bundle"),
            "missing parse label: {msg}"
        );
        Ok(())
    }

    #[cfg(not(wasm))]
    #[test]
    fn build_client_no_ca_uses_webpki_roots() -> Result<()> {
        // No tls_ca_certs → must not attempt any file reads; builds fine.
        let ohttp_args = OHttpArgs::default();
        let _client = super::build_ohttp_http_client(
            &ohttp_args,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
        )?;
        Ok(())
    }
}

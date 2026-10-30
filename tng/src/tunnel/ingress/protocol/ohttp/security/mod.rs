pub mod client;
mod path_rewrite;

use std::{borrow::Cow, collections::HashMap, sync::Arc};

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
        ohttp::timing::{IngressLatency, Timer},
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

/// Cached OHTTP client per (endpoint, outer-POST path), lazily initialized
/// on first use. The steady-state lookup borrows both parts -- hashing the
/// endpoint and the request path directly -- instead of building the
/// concatenated URL string per request; the concatenation now happens once
/// per client creation, and `OHttpClient::new` parses it into a `Url` there.
/// Two equivalent-but-differently-spelled paths get two entries (as with the
/// previous plain-URL-string key), and the same `host:port` configured once
/// as an IPv4 and once as a domain gets two entries because the endpoint
/// types differ; the bounded cost is an extra client creation (one key-config
/// fetch), never a routing difference: each client posts its own URL.
type OhttpClientCache =
    RwLock<HashMap<TngEndpoint, HashMap<String, Arc<OnceCell<Arc<OHttpClient>>>>>>;

/// Outer-POST path: the `path_rewrites` result when a rule matches, otherwise
/// `path_default` (`/` for Root, the request's original path for Original).
/// The returned `Cow` borrows the request path whenever possible so a
/// keep-alive request does not copy it; the owned variants are only built by
/// a rewrite hit or when the path needs a leading `/` prepended.
fn outer_path<'a>(
    path_rewrite_group: &PathRewriteGroup,
    path_default: PathDefault,
    request: &'a axum::extract::Request,
) -> Cow<'a, str> {
    let original_path = request.uri().path();
    // When no path_rewrite rule matches (path_rewrites unset/empty or
    // no regex hit), fall back according to `path_default`: `/` (Root,
    // the historical default) or the inner request's original path.
    let mut rewrited_path = path_rewrite_group.rewrite(original_path).map_or_else(
        || match path_default {
            PathDefault::Root => Cow::Borrowed("/"),
            PathDefault::Original => Cow::Borrowed(original_path),
        },
        Cow::Owned,
    );

    if !rewrited_path.starts_with('/') {
        rewrited_path = Cow::Owned(format!("/{rewrited_path}"));
    }

    tracing::debug!(original_path, rewrited_path = ?rewrited_path, "path is rewrited");

    rewrited_path
}

/// Root status response for /status/.../ohttp/keys.
#[derive(Serialize)]
#[cfg_attr(wasm, allow(dead_code))]
struct ServersStatus {
    servers: Vec<ServerStatusEntry>,
}

/// Derive the URL scheme for the outer OHTTP POST from the `tls` config flag
/// (native ingress only). `Some(true)` ⇒ `https`, anything else ⇒ `http`
/// (the default, pre-feature behavior).
#[cfg(not(wasm))]
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
/// scheme (driven by `OHttpSecurityLayer::scheme_from_url` from the fetch URL,
/// NOT from a config field) is what engages browser TLS. Takes no `ohttp_args`
/// because neither `tls` nor `tls_ca_certs` exists on wasm.
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
    /// Outer-POST URL scheme: `"http"` (default) or `"https"`. On native this is
    /// derived from `ohttp.tls`; on wasm it mirrors the fetch URL's scheme
    /// (see `scheme_from_url`).
    scheme: &'static str,
    runtime: TokioRuntime,
    /// Headers to copy from the inner (plaintext) request to the outer (ciphertext) POST.
    passthrough_request_headers: Arc<crate::config::header_passthrough::HeaderPassthroughSpec>,
    /// Headers to copy from the outer (ciphertext) response to the inner (plaintext) response.
    passthrough_response_headers: Arc<crate::config::header_passthrough::HeaderPassthroughSpec>,
    /// Per-phase request latency histograms, served at `.../ohttp/latency`.
    latency: Arc<IngressLatency>,
}

impl OHttpSecurityLayer {
    pub async fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        ohttp_args: &OHttpArgs,
        // Outer OHTTP POST scheme already normalized via
        // `OHttpSecurityLayer::scheme_from_url` from the URL the caller passed
        // to the wasm `fetch` interface. Native builds ignore this and derive
        // the scheme from `ohttp.tls` instead. (Plain `//`, not `///`: doc
        // comments are not allowed on function parameters.)
        #[cfg(wasm)] url_scheme: &'static str,
        ra_context: Arc<RaContext>,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let scheme = {
            #[cfg(not(wasm))]
            {
                scheme_from_tls(ohttp_args.tls)
            }
            #[cfg(wasm)]
            {
                url_scheme
            }
        };

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
            latency: Arc::new(IngressLatency::new()),
        })
    }

    /// Derive the URL scheme for the outer OHTTP POST from the scheme of the URL
    /// the caller passed to the wasm `fetch` interface. `Some("https")` ⇒ `https`,
    /// anything else (a non-`https` scheme or `None`) ⇒ `http`.
    ///
    /// On wasm the browser performs TLS once the outer URL is `https://`; the
    /// scheme is taken verbatim from the fetch URL, so no `tls` config exists
    /// there. Cfg-agnostic (no `#[cfg(wasm)]`) so it can be unit-tested on the
    /// native test target AND called from the wasm fetch path. Returns a
    /// `&'static str` literal — NO allocation, and the result does NOT borrow
    /// the (temporary) input, so it can outlive the parsed URI it was derived
    /// from.
    pub fn scheme_from_url(scheme: Option<&str>) -> &'static str {
        match scheme {
            Some("https") => "https",
            _ => "http",
        }
    }

    pub async fn forward_http_request(
        &self,
        endpoint: &TngEndpoint,
        request: axum::extract::Request,
    ) -> Result<(axum::response::Response, Option<AttestationResult>), TngError> {
        async {
            let timer = Timer::start();
            let outer_path = outer_path(&self.path_rewrite_group, self.path_default, &request);

            let ohttp_client = self
                .get_or_create_ohttp_client(endpoint, &outer_path)
                .await?;

            self.latency.route_lookup.record(timer.elapsed());

            ohttp_client.forward_request(request).await
        }
        .await
        .map_err(|error| {
            tracing::error!(?error, "Failed to forward HTTP request");
            error
        })
    }

    /// Look up the cached client for `(endpoint, outer_path)`, creating it on
    /// first use. The hit path borrows the endpoint and the path as keys and
    /// never builds the outer-POST URL string; the URL (`scheme://host:port`
    /// plus path, normalized by the client's one-time `Url` parse) is
    /// concatenated only in the cold path, replacing the per-request parse
    /// that showed up in the keep-alive profile.
    async fn get_or_create_ohttp_client(
        &self,
        endpoint: &TngEndpoint,
        outer_path: &str,
    ) -> Result<Arc<OHttpClient>, TngError> {
        // Try to read the ohttp client entry.
        let entry = {
            let read = self.ohttp_clients.read().await;
            read.get(endpoint)
                .and_then(|clients| clients.get(outer_path))
                .cloned()
        };

        // If no entry exists, create one with uninitialized value.
        let entry = match entry {
            Some(entry) => entry,
            _ => {
                let mut write = self.ohttp_clients.write().await;
                write
                    .entry(endpoint.clone())
                    .or_default()
                    .entry(outer_path.to_owned())
                    .or_default()
                    .clone()
            }
        };

        // Steady state: the cell is already initialized; hand out the client
        // without touching the cold-path URL construction below.
        if let Some(client) = entry.get() {
            return Ok(client.clone());
        }

        let base_url = format!(
            "{}://{}{}",
            self.scheme,
            endpoint.http_authority(),
            outer_path
        );

        // read from the cell
        entry
            .get_or_try_init(|| async {
                Ok(Arc::new(
                    OHttpClient::new(
                        self.ra_context.clone(),
                        self.http_client.clone(),
                        base_url,
                        self.runtime.clone(),
                        self.passthrough_request_headers.clone(),
                        self.passthrough_response_headers.clone(),
                        self.latency.clone(),
                    )
                    .await
                    .map_err(TngError::CreateOHttpClientFailed)?,
                ))
            })
            .await
            .cloned()
    }

    /// Latency histograms for the status endpoint and the writeback timing
    /// in the stream forwarder's service_fn.
    #[cfg_attr(wasm, allow(dead_code))] // the forwarder and status node are native-only
    pub(crate) fn latency(&self) -> Arc<IngressLatency> {
        self.latency.clone()
    }
}

#[cfg(not(wasm))]
#[async_trait]
impl StatusProvider for OHttpSecurityLayer {
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError> {
        match path {
            [] => Ok(StatusQueryResult::Subtree(vec![
                "keys".into(),
                "latency".into(),
            ])),
            ["latency"] => Ok(StatusQueryResult::Value(self.latency.snapshot())),
            ["keys"] => {
                let map = self.ohttp_clients.read().await;
                let mut servers =
                    Vec::with_capacity(map.values().map(|clients| clients.len()).sum());
                for clients in map.values() {
                    for cell in clients.values() {
                        if let Some(client) = cell.get() {
                            if let Some(entry) = client.server_status().await {
                                servers.push(entry);
                            }
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
    use super::{outer_path, ServersStatus};
    use crate::config::ingress::{OHttpArgs, PathDefault, PathRewrite};
    use crate::tunnel::ingress::protocol::ohttp::security::PathRewriteGroup;
    use anyhow::Result;

    fn request_with_path(path: &str) -> axum::extract::Request {
        let mut request = axum::extract::Request::new(axum::body::Body::empty());
        *request.uri_mut() = path.parse().expect("valid uri path");
        request
    }

    #[test]
    fn outer_path_root_falls_back_to_slash() {
        let rewrites = PathRewriteGroup::new(&[]).expect("empty group");
        let request = request_with_path("/foo/bar");
        assert_eq!(
            outer_path(&rewrites, PathDefault::Root, &request).as_ref(),
            "/"
        );
    }

    #[test]
    fn outer_path_original_falls_back_to_request_path() {
        let rewrites = PathRewriteGroup::new(&[]).expect("empty group");
        let request = request_with_path("/foo/bar");
        assert_eq!(
            outer_path(&rewrites, PathDefault::Original, &request).as_ref(),
            "/foo/bar"
        );
    }

    #[test]
    fn outer_path_prepends_missing_leading_slash() {
        // A rewrite substitution that lacks the leading '/' gets one.
        let rules = [PathRewrite {
            match_regex: "^/foo$".to_string(),
            substitution: "fooslash".to_string(),
        }];
        let rewrites = PathRewriteGroup::new(&rules).expect("group builds");
        let request = request_with_path("/foo");
        assert_eq!(
            outer_path(&rewrites, PathDefault::Root, &request).as_ref(),
            "/fooslash"
        );
        // An already-absolute substitution is left untouched.
        let rules = [PathRewrite {
            match_regex: "^/foo$".to_string(),
            substitution: "/fooslash".to_string(),
        }];
        let rewrites = PathRewriteGroup::new(&rules).expect("group builds");
        let request = request_with_path("/foo");
        assert_eq!(
            outer_path(&rewrites, PathDefault::Root, &request).as_ref(),
            "/fooslash"
        );
    }

    #[test]
    fn outer_path_rewrite_hit_wins_over_default() {
        let rules = [PathRewrite {
            match_regex: "^/foo/bar/([^/]+)([/]?.*)$".to_string(),
            substitution: "/foo/bar/$1".to_string(),
        }];
        let rewrites = PathRewriteGroup::new(&rules).expect("group builds");
        let request = request_with_path("/foo/bar/user/id123/info");
        assert_eq!(
            outer_path(&rewrites, PathDefault::Root, &request).as_ref(),
            "/foo/bar/user"
        );
        // A non-matching path keeps the default behavior.
        let request = request_with_path("/other");
        assert_eq!(
            outer_path(&rewrites, PathDefault::Root, &request).as_ref(),
            "/"
        );
        assert_eq!(
            outer_path(&rewrites, PathDefault::Original, &request).as_ref(),
            "/other"
        );
    }

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

    // scheme_from_tls is native-only (#[cfg(not(wasm))]); gate this test to match.
    #[cfg(not(wasm))]
    #[test]
    fn scheme_from_tls_maps_correctly() {
        assert_eq!(super::scheme_from_tls(None), "http");
        assert_eq!(super::scheme_from_tls(Some(false)), "http");
        assert_eq!(super::scheme_from_tls(Some(true)), "https");
    }

    #[test]
    fn scheme_from_url_maps_correctly() {
        // The outer OHTTP POST scheme mirrors the fetch URL's scheme.
        use super::OHttpSecurityLayer;
        assert_eq!(OHttpSecurityLayer::scheme_from_url(Some("https")), "https");
        assert_eq!(OHttpSecurityLayer::scheme_from_url(Some("http")), "http");
        assert_eq!(
            OHttpSecurityLayer::scheme_from_url(Some("HTTPS")),
            "http",
            "only lowercase https engages TLS"
        );
        assert_eq!(OHttpSecurityLayer::scheme_from_url(None), "http");
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
    fn build_client_no_ca_builds_without_file_reads() -> Result<()> {
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

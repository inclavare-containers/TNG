use anyhow::{bail, Context as _, Result};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::{IntoResponse as _, Response},
    Router,
};
use http::HeaderValue;
use regex::Regex;
use reqwest::Client;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing;

use std::sync::{Arc, Mutex};

/// A simple thread-safe round-robin load balancer for upstream servers.
pub struct UpstreamBalancer {
    servers: Vec<String>, // formatted as "host:port"
    index: usize,
}

impl UpstreamBalancer {
    /// Create a new balancer from a list of (host, port) tuples.
    pub fn new(upstreams: Vec<(&'static str, u16)>) -> Self {
        let servers = upstreams
            .into_iter()
            .map(|(host, port)| format!("{}:{}", host, port))
            .collect();

        Self { servers, index: 0 }
    }

    /// Pick the next upstream server using round-robin strategy.
    pub fn pick(&mut self) -> Option<&str> {
        if self.servers.is_empty() {
            return None;
        }
        let server = &self.servers[self.index];
        self.index = (self.index + 1) % self.servers.len();
        Some(server)
    }
}

/// Launch a load balancer with regex-based path matching and rewriting.
///
/// Requests whose path matches `path_matcher` will have their path rewritten using `rewrite_to`
/// (like sed-style $1, $2), then forwarded to upstream servers in round-robin fashion.
///
/// Non-matching requests return 404.
///
/// # Arguments
///
/// * `token` - Cancellation token for graceful shutdown
/// * `listen_port` - Port to bind (e.g., 8080)
/// * `upstream_servers` - List of (host, port) upstreams
/// * `path_matcher` - Regex to match incoming path (should cover full path)
/// * `rewrite_to` - Replacement string, e.g., "/api/$1"

pub async fn launch_load_balancer(
    token: CancellationToken,
    listen_port: u16,
    upstream_servers: Vec<(&'static str, u16)>,
    path_matcher: &'static str,
    rewrite_to: &'static str,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let path_matcher = Regex::new(path_matcher).context("Invalid regex")?;

    if upstream_servers.is_empty() {
        bail!("At least one upstream server must be provided");
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(%listen_port, "Load balancer listening on 0.0.0.0");

    // Use a Round-Robin Balancer
    let balancer = Arc::new(Mutex::new(UpstreamBalancer::new(upstream_servers)));

    // Shared HTTP client
    let client = Client::builder()
        .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
        .pool_max_idle_per_host(10)
        .build()
        .context("Failed to build HTTP client")?;

    // Move captured variables into closure
    let path_matcher = std::sync::Arc::new(path_matcher);

    let app = Router::new()
        .fallback(move |request: Request<Body>| {
            let balancer = balancer.clone();
            let client = client.clone();
            let path_matcher = path_matcher.clone();

            async move {
                handle_request_with_rewrite(request, balancer, client, path_matcher, &rewrite_to)
                    .await
            }
        })
        .layer(axum::middleware::from_fn(add_server_header));

    let server = axum::serve(listener, app);

    let handle = tokio::task::spawn(async move {
        tokio::select! {
            _ = token.cancelled() => {
                tracing::info!("Shutdown signal received, stopping load balancer...");
            }
            result = server => match result {
                Ok(_) => tracing::info!("Server exited normally"),
                Err(e) => tracing::error!(error = %e, "Server error"),
            }
        }

        Ok(())
    });

    Ok(handle)
}

/// Handle incoming request: try to match and rewrite path, then proxy.
async fn handle_request_with_rewrite(
    request: Request<Body>,
    balancer: Arc<Mutex<UpstreamBalancer>>,
    client: Client,
    path_matcher: Arc<Regex>,
    rewrite_to: &str,
) -> Response<Body> {
    let uri = request.uri();
    let original_path = uri.path();

    if path_matcher.captures(original_path).is_none() {
        tracing::debug!(path = %original_path, "Path does not match regex");
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    };

    let rewritten_path = path_matcher
        .replacen(original_path, 1, rewrite_to)
        .to_string();

    let final_path = match uri.query() {
        Some(query) => format!("{}?{}", rewritten_path, query),
        None => rewritten_path,
    };

    let backend = {
        let mut guard = balancer.lock().expect("Lock poisoned");
        match guard.pick() {
            Some(server) => server.to_string(),
            None => {
                tracing::error!("No upstream available");
                return (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response();
            }
        }
    };

    let upstream_url = format!(
        "http://{}/{}",
        backend,
        final_path.strip_prefix('/').unwrap_or(&final_path)
    );
    tracing::debug!(url = %upstream_url, "Forwarding request to upstream");

    let mut req = reqwest::Request::new(request.method().clone(), upstream_url.parse().unwrap());
    *req.headers_mut() = request.headers().clone();

    *req.body_mut() = Some(reqwest::Body::wrap_stream(
        request.into_body().into_data_stream(),
    ));

    let response = match client.execute(req).await {
        Ok(res) => res,
        Err(_) => return (StatusCode::GATEWAY_TIMEOUT, "Upstream unreachable").into_response(),
    };

    let mut resp_builder = Response::builder().status(response.status());
    *resp_builder.headers_mut().unwrap() = response.headers().clone();

    tracing::debug!(
        status = ?response.status(),
        "Forwarding response to downstream"
    );

    resp_builder
        .body(Body::from_stream(response.bytes_stream()))
        .unwrap_or_else(|error| {
            tracing::debug!(?error, "Failed to set body");
            (StatusCode::INTERNAL_SERVER_ERROR, "Response build failed").into_response()
        })
}

async fn add_server_header(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, std::convert::Infallible> {
    let mut res = next.run(req).await;
    res.headers_mut().insert(
        "Server",
        HeaderValue::from_static("tng-testsuite-loadbalancer"),
    );
    Ok(res)
}

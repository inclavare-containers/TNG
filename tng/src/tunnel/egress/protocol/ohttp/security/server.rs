use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
    routing::{get, post},
    Router,
};
use http::HeaderValue;
use std::{convert::Infallible, sync::Arc};

use crate::{
    tunnel::egress::protocol::ohttp::security::{
        keystore::ServerKeyStore, state::OhttpServerState,
    },
    HTTP_RESPONSE_SERVER_HEADER,
};

/// TNG OHTTP Server implementation
///
/// This struct represents a TNG OHTTP server instance that handles the three required TNG server interfaces:
/// 1. Get HPKE Configuration (/tng/key-config)
/// 2. Process Encrypted Request (/tng/tunnel)
/// 3. Attestation Forward (/tng/background-check/*)
#[derive(Clone)]
pub struct OhttpServer {
    /// The key store instance used for cryptographic operations
    key_store: Arc<ServerKeyStore>,
}

impl OhttpServer {
    /// Create a new TNG HTTP server instance
    pub fn new(key_store: ServerKeyStore) -> Self {
        Self {
            key_store: Arc::new(key_store),
        }
    }

    /// Create the TNG HTTP routes with the server instance
    ///
    /// This method sets up all the required TNG server interfaces:
    /// - POST /tng/key-config: Get HPKE configuration
    /// - POST /tng/tunnel: Process encrypted requests
    /// - GET /tng/background-check/challenge: Get attestation challenge
    /// - POST /tng/background-check/verify: Verify attestation evidence
    pub fn create_routes(&self) -> Router<OhttpServerState> {
        // TODO:
        // - /tng/* to return 404
        // - fallback to /tng/tunnel for all other requests

        Router::new()
            // Interface 1: Get HPKE Configuration
            // POST /tng/key-config
            .route(
                "/tng/key-config",
                post({
                    let key_store = Arc::clone(&self.key_store);
                    move |payload| async move { key_store.get_hpke_configuration(payload).await }
                }),
            )
            // Interface 2: Process Encrypted Request
            // POST /tng/tunnel (or user specified path via path_rewrites)
            .route(
                "/tng/tunnel",
                post({
                    let key_store = Arc::clone(&self.key_store);
                    move |State(state): State<OhttpServerState>, payload| async move {
                        key_store
                            .process_encrypted_request(payload, state)
                            .await
                            .map_err(|error| {
                                tracing::error!(?error, "Failed to process received OHTTP request");
                                error
                            })
                    }
                }),
            )
            // Interface 3: Attestation Forward
            // GET /tng/background-check/challenge
            .route(
                "/tng/background-check/challenge",
                get({
                    let key_store = Arc::clone(&self.key_store);
                    move || async move { key_store.get_attestation_challenge().await }
                }),
            )
            // POST /tng/background-check/verify
            .route(
                "/tng/background-check/verify",
                post({
                    let key_store = Arc::clone(&self.key_store);
                    move |payload| async move { key_store.verify_attestation(payload).await }
                }),
            )
            .layer(axum::middleware::from_fn(add_server_header))
            .layer(axum::middleware::from_fn(log_request))
        // .layer(ServiceBuilder::new().layer(axum::middleware::from_fn(add_server_header)))
    }
}

async fn add_server_header(req: Request, next: Next) -> Result<Response, Infallible> {
    let mut res = next.run(req).await;
    res.headers_mut().insert(
        "Server",
        HeaderValue::from_static(HTTP_RESPONSE_SERVER_HEADER),
    );
    Ok(res)
}

pub async fn log_request(
    req: Request,
    next: Next,
) -> Result<Response, (axum::http::StatusCode, String)> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();
    let start = std::time::Instant::now();

    let res = next.run(req).await;

    let duration = start.elapsed();
    let status = res.status();
    let content_length = res
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.parse::<u64>().ok())
        .flatten()
        .unwrap_or(0);

    tracing::info!(
        "\"{method} {uri} {version:?}\" {status} {content_length} {:.2}ms",
        duration.as_secs_f64() * 1000.0
    );

    Ok(res)
}

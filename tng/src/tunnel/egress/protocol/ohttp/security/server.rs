use anyhow::{Context, Result};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use std::{convert::Infallible, str::FromStr as _, sync::Arc};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer, ExposeHeaders};

use crate::config::egress::{CorsConfig, OHttpArgs};
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
    /// The configuration for the CORS
    cors_layer: Option<CorsLayer>,
}

impl OhttpServer {
    /// Create a new TNG HTTP server instance
    pub fn new(key_store: ServerKeyStore, ohttp_args: OHttpArgs) -> Result<Self> {
        let cors_layer = match &ohttp_args.cors {
            Some(cors_config) => Some(Self::construct_cors_layer(cors_config)?),
            None => None,
        };

        Ok(Self {
            key_store: Arc::new(key_store),
            cors_layer,
        })
    }

    fn construct_cors_layer(cors_config: &CorsConfig) -> Result<CorsLayer> {
        let mut cors = CorsLayer::new();

        // Access-Control-Allow-Origin
        if cors_config.allow_origins.contains(&"*".to_string()) {
            cors = cors.allow_origin(AllowOrigin::any());
        } else {
            let origins = cors_config
                .allow_origins
                .iter()
                .map(|origin| {
                    origin
                        .parse::<HeaderValue>()
                        .with_context(|| format!("Invalid origin '{}'", origin))
                })
                .collect::<Result<Vec<_>, _>>()?;
            cors = cors.allow_origin(AllowOrigin::list(origins));
        }

        // Access-Control-Allow-Methods
        if cors_config.allow_methods.contains(&"*".to_string()) {
            cors = cors.allow_methods(AllowMethods::any());
        } else {
            let methods = cors_config
                .allow_methods
                .iter()
                .map(|m| {
                    Method::from_str(m).with_context(|| format!("Invalid HTTP method '{}'", m))
                })
                .collect::<Result<Vec<_>, _>>()?;
            cors = cors.allow_methods(AllowMethods::list(methods));
        }

        // Access-Control-Allow-Headers
        if cors_config.allow_headers.contains(&"*".to_string()) {
            cors = cors.allow_headers(AllowHeaders::any());
        } else {
            let headers = cors_config
                .allow_headers
                .iter()
                .map(|h| {
                    HeaderName::from_str(h).with_context(|| format!("Invalid header name '{}'", h))
                })
                .collect::<Result<Vec<_>, _>>()?;
            cors = cors.allow_headers(AllowHeaders::list(headers));
        }

        // Access-Control-Expose-Headers
        if cors_config.expose_headers.contains(&"*".to_string()) {
            cors = cors.expose_headers(ExposeHeaders::any());
        } else {
            let headers = cors_config
                .expose_headers
                .iter()
                .map(|h| {
                    HeaderName::from_str(h)
                        .with_context(|| format!("Invalid expose header name '{}'", h))
                })
                .collect::<Result<Vec<_>, _>>()?;
            cors = cors.expose_headers(ExposeHeaders::list(headers));
        }

        // Access-Control-Allow-Credentials
        if cors_config.allow_credentials {
            cors = cors.allow_credentials(true);
        }

        Ok(cors)
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

        let router = Router::new()
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
            .fallback({
                let key_store = Arc::clone(&self.key_store);
                move |State(state): State<OhttpServerState>, req| {
                    fallback_handler(state, key_store.clone(), req)
                }
            })
            .layer(axum::middleware::from_fn(add_server_header));

        let router = if let Some(cors) = &self.cors_layer {
            router.layer(cors.clone())
        } else {
            router
        };

        router.layer(axum::middleware::from_fn(log_request))
    }
}

async fn fallback_handler(
    state: OhttpServerState,
    key_store: Arc<ServerKeyStore>,
    payload: Request<axum::body::Body>,
) -> Result<Response, Response> {
    let path = payload.uri().path();

    if path.starts_with("/tng") {
        // It may be a request from newer TNG version, so we should return NOT_FOUND
        return Err(StatusCode::NOT_FOUND.into_response());
    }

    key_store
        .process_encrypted_request(payload, state)
        .await
        .map_err(|error| {
            tracing::error!(?error, "Failed to process received OHTTP request");
            error.into_response()
        })
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

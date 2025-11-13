use anyhow::{Context, Result};
use axum::{
    extract::{FromRequest, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Json, Router,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use std::{convert::Infallible, str::FromStr as _, sync::Arc};
use tower_http::{
    compression::{
        predicate::NotForContentType, CompressionLayer, DefaultPredicate, Predicate as _,
    },
    cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer, ExposeHeaders},
};

use crate::{
    config::{
        egress::{CorsConfig, OHttpArgs},
        ra::{AttestArgs, RaArgs},
    },
    error::TngError,
    tunnel::ohttp::protocol::{
        header::{OhttpApi, OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE},
        AttestationVerifyRequest, KeyConfigRequest,
    },
    TokioRuntime,
};
use crate::{
    tunnel::egress::protocol::ohttp::security::{api::OhttpServerApi, context::TngStreamContext},
    HTTP_RESPONSE_SERVER_HEADER,
};

/// TNG OHTTP Server implementation
///
/// This struct represents a TNG OHTTP server instance that handles the required TNG server interfaces
#[derive(Clone)]
pub struct OhttpServer {
    /// The API handler instance used for for processing TNG server interfaces
    api: Arc<OhttpServerApi>,
    /// The configuration for the CORS
    cors_layer: Option<CorsLayer>,
}

impl OhttpServer {
    /// Create a new TNG HTTP server instance
    pub async fn new(
        ra_args: RaArgs,
        ohttp_args: OHttpArgs,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        if let RaArgs::AttestOnly(AttestArgs::BackgroundCheck { aa_args })
        | RaArgs::AttestAndVerify(AttestArgs::BackgroundCheck { aa_args }, ..) = &ra_args
        {
            if aa_args.refresh_interval.is_some() {
                tracing::warn!(
                    "`refresh_interval` in your configuration is set but will be ignored for background check"
                );
            }
        }

        Ok(Self {
            api: Arc::new(OhttpServerApi::new(ra_args, ohttp_args.key, runtime).await?),
            cors_layer: match &ohttp_args.cors {
                Some(cors_config) => Some(Self::construct_cors_layer(cors_config)?),
                None => None,
            },
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
    pub fn create_routes(&self) -> Router<TngStreamContext> {
        let router = Router::new().fallback({
            let api = Arc::clone(&self.api);
            move |State(state): State<TngStreamContext>, req| handler(state, api.clone(), req)
        });

        let router = if let Some(cors) = &self.cors_layer {
            router.layer(cors.clone())
        } else {
            router
        };

        router
            .layer(
                CompressionLayer::new().compress_when(
                    DefaultPredicate::new()
                        .and(NotForContentType::new(OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE)), // Don't compress responses who's `content-type` ohttp chunked response`
                ),
            )
            .layer(axum::middleware::from_fn(add_server_header))
            .layer(axum::middleware::from_fn(log_request))
    }
}

async fn handler(
    context: TngStreamContext,
    api: Arc<OhttpServerApi>,
    request: Request,
) -> Result<Response, TngError> {
    let ohttp_api = parse_ohttp_api_from_request(&request)?;

    match ohttp_api {
        OhttpApi::KeyConfig => {
            api.get_hpke_configuration(
                <Option<Json<KeyConfigRequest>> as FromRequest<()>>::from_request(request, &())
                    .await
                    .map_err(TngError::InvalidRequestPayload)?,
                context,
            )
            .await
        }
        OhttpApi::Tunnel => api
            .process_encrypted_request(request, context)
            .await
            .map_err(|error| {
                tracing::error!(?error, "Failed to process received OHTTP request");
                error
            }),
        OhttpApi::BackgroundCheckChallenge => api
            .get_attestation_challenge()
            .await
            .map(IntoResponse::into_response),
        OhttpApi::BackgroundCheckVerify => api
            .verify_attestation(
                <Json<AttestationVerifyRequest> as FromRequest<()>>::from_request(request, &())
                    .await
                    .map_err(TngError::InvalidRequestPayload)?,
            )
            .await
            .map(IntoResponse::into_response),
    }
}

fn parse_ohttp_api_from_request(req: &Request) -> Result<OhttpApi, TngError> {
    let headers: &HeaderMap = req.headers();

    let api_value = headers
        .get(OhttpApi::HEADER_NAME)
        .ok_or(TngError::RejectNonTngRequest)?
        .to_str()
        .map_err(|_| TngError::InvalidOhttpApiHeaderValue)?;

    let api = match api_value {
        OhttpApi::KEY_CONFIG => OhttpApi::KeyConfig,
        OhttpApi::TUNNEL => OhttpApi::Tunnel,
        OhttpApi::BACKGROUND_CHECK_CHALLENGE => OhttpApi::BackgroundCheckChallenge,
        OhttpApi::BACKGROUND_CHECK_VERIFY => OhttpApi::BackgroundCheckVerify,
        _ => return Err(TngError::InvalidOhttpApiHeaderValue),
    };

    Ok(api)
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

    let ohttp_api = req
        .headers()
        .get(OhttpApi::HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_owned();

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
        "\"{method} {uri} ({ohttp_api}) {version:?}\" {status} {content_length} {:.2}ms",
        duration.as_secs_f64() * 1000.0
    );

    Ok(res)
}

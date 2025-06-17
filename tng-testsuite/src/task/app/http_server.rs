use std::net::SocketAddr;

use anyhow::{bail, Result};
use axum::{body::Body, extract::Request, routing::get, Router};
use axum_extra::extract::Host;
use http::StatusCode;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::task::app::HTTP_RESPONSE_BODY;

pub async fn launch_http_server(
    token: CancellationToken,
    port: u16,
    expected_host_header: &str,
    expected_path_and_query: &str,
) -> Result<JoinHandle<Result<()>>> {
    let expected_host_header = expected_host_header.to_owned();
    let expected_path_and_query = expected_path_and_query.to_owned();

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Listening on 0.0.0.0:{port} and waiting for connection from client");

    Ok(tokio::task::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            get(|Host(hostname): Host, request: Request<Body>| async move {
                (|| -> Result<_> {
                    if hostname != expected_host_header {
                        bail!("Got hostname `{hostname}`, but `{expected_host_header}` is expected");
                    }

                    if request.uri().scheme().is_some() {
                        bail!("The request URI should not contain scheme, but got {:?}", request.uri().scheme())
                    }

                    if request.uri().authority().is_some() {
                        bail!("The request URI should not contain authority, but got {:?}", request.uri().authority())
                    }

                    let path_and_query = request.uri().path_and_query();
                    if path_and_query.map(|t| t.as_str()) != Some(&expected_path_and_query) {
                        bail!("Got path and query `{path_and_query:?}`, but `{expected_path_and_query}` is expected");
                    }

                    tracing::info!("Got request from client, now sending response to client");
                    Ok((StatusCode::OK, HTTP_RESPONSE_BODY.to_owned()))
                })()
                .unwrap_or_else(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Something went wrong: {e}"),
                    )
                })
            }),
        );
        let server = axum::serve(listener, app);

        tokio::select! {
            _ = token.cancelled() => {}
            res = server => {
                res?;
            }
        }

        tracing::info!("The HTTP server task normally exit now");
        Ok(())
    }))
}

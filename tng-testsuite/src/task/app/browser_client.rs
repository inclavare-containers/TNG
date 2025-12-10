use again::RetryPolicy;
use anyhow::{bail, Context, Result};
use axum::Router;
use chromedriver_manager::{loglevel::LogLevel, manager::Handler};
use scopeguard::defer;
use thirtyfour::prelude::*;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tower_http::services::ServeDir;
use tower_http::trace::DefaultMakeSpan;
use tower_http::trace::DefaultOnResponse;
use tower_http::trace::TraceLayer;
use tracing::Level;

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

pub async fn launch_browser_client(
    token: CancellationToken,
    js: String,
) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::task::spawn(async move {
        let _drop_guard = token.drop_guard();

        let js_sdk_file_path = locate_tng_js_sdk_file()?;
        let listen_port = portpicker::pick_unused_port()
            .context("Failed to pick a free port for js sdk http server")?;
        let static_file_server_task =
            launch_tng_js_sdk_file_static_file_server(&js_sdk_file_path, listen_port).await?;

        let test_task = async {
            // Create Chrome capabilities
            let mut caps = DesiredCapabilities::chrome();
            caps.set_headless()?;
            caps.set_no_sandbox()?; // We need to run with root user
            caps.add_arg("--disable-web-security")?; // enable this to allow cross-origin requests

            // Launch chromedriver on port 9515
            let driver_port = portpicker::pick_unused_port()
                .context("Failed to pick a free port for chromedriver")?;
            let (log_level, log_level_all) =
                match std::env::var("TNG_WASM_TEST_CHROMEDRIVER_LOG_ALL")
                    .ok()
                    .as_deref()
                {
                    Some("true") | Some("True") | Some("TRUE") => (LogLevel::All, true),
                    _ => (LogLevel::Warning, false),
                };

            let mut chromedriver = Handler::new()
                .launch_chromedriver(&mut caps, &driver_port.to_string(), log_level)
                .await
                .context("Failed to launch chromedriver")?;

            defer! {
                let _ = chromedriver.kill();
            }

            // Wait for chromedriver to be ready
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Connect to chrome on the same`` port
            let driver = WebDriver::new(format!("http://127.0.0.1:{driver_port}"), caps)
                .await
                .context(if log_level_all { "Failed to connect to chromedriver" } else {"Failed to connect to chromedriver. Set TNG_WASM_TEST_CHROMEDRIVER_LOG_ALL=true to see all chromedriver logs"})?;

            let res = async {
                for i in 1..6 {
                    // repeat 5 times
                    tracing::info!(
                        "Browser client test repeat {i}, sending http request via tng js sdk"
                    );

                    let () = RetryPolicy::fixed(Duration::from_secs(1))
                        .with_max_retries(5)
                        .retry(|| async {
                            let load_sdk = format!(r#"
                                const {{ default: tng_init, fetch: tng_fetch }} = await import("http://127.0.0.1:{listen_port}/tng_wasm.js");
                            "#);

                            let common_functions = r#"
                                async function common_check_response(response, passport_mode) {
                                    if (!response.ok) {
                                        let errorMessage = `Response status: ${response.status} ${response.statusText}`;
                                        try {
                                            const responseBody = await response.text();
                                            if (responseBody) {
                                                errorMessage += `\nResponse body: ${responseBody.trim()}`;
                                            }
                                        } catch (err) {
                                            errorMessage += `\nFailed to read response body: ${err.message}`;
                                        }
                                        throw new Error(errorMessage);
                                    }

                                    if (!(response.attest_info !== undefined && response.attest_info !== null)) {
                                        throw new Error('attest_info not exist');
                                    }

                                    if (!passport_mode) {
                                        if (!(response.attest_info.as_addr !== undefined && response.attest_info.as_addr !== null)) {
                                            throw new Error('attest_info.as_addr not exist');
                                        }
                                    }

                                    if (!(response.attest_info.policy_ids !== undefined && response.attest_info.policy_ids !== null)) {
                                        throw new Error('attest_info.policy_ids not exist');
                                    }

                                    if (!Array.isArray(response.attest_info.policy_ids)) {
                                        throw new Error(`attest_info.policy_ids should be a array but got ${response.attest_info.policy_ids}`);
                                    }

                                    if (!(response.attest_info.attestation_result !== undefined && response.attest_info.attestation_result !== null)) {
                                        throw new Error('attest_info.attestation_result not exist');
                                    }
                                }
                                "#;
                            let _ret = driver
                                .execute_async(
                                    format!(r#"
                                        {load_sdk}
                                        {common_functions}
                                        {js}
                                        arguments[0](true)
                                        "#),
                                    Vec::new()
                                )
                                .await?;

                            Ok::<_, anyhow::Error>(())
                        })
                        .await?;
                }

                Ok::<_, anyhow::Error>(())
            }.await;

            tracing::info!("Test finished, closing the chromedriver session");
            driver.quit().await?;

            // check response
            res?;

            Ok::<_, anyhow::Error>(())
        };

        tokio::select! {
            result = static_file_server_task => {
                bail!("static file server task exited unexpectedly: {result:?}")
            },
            result = test_task => {
                let () = result?;
            }
        }

        tracing::info!("The browser client task normally exit now");
        Ok(())
    }))
}

fn locate_tng_js_sdk_file() -> Result<PathBuf> {
    // Find the js sdk files, which is on <project root>/tng-wasm/pkg/tng_wasm.js
    let js_sdk_file_path = std::env::current_dir()?.join("../tng-wasm/pkg/tng_wasm.js");
    if js_sdk_file_path.exists() {
        tracing::info!(?js_sdk_file_path, "Found js sdk file");
    } else {
        bail!("Cannot find js sdk file at {js_sdk_file_path:?}, maybe you need to build the js sdk with `make wasm-pack-debug`")
    }
    Ok(js_sdk_file_path)
}

async fn launch_tng_js_sdk_file_static_file_server(
    js_sdk_file_path: &Path,
    listen_port: u16,
) -> Result<impl Future<Output = Result<()>>> {
    let static_dir = js_sdk_file_path.parent().with_context(|| {
        format!("Cannot find parent directory of js sdk file: {js_sdk_file_path:?}")
    })?;
    let app = Router::new()
        .fallback_service(ServeDir::new(&static_dir).append_index_html_on_directories(true))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        );

    let addr = SocketAddr::from(([127, 0, 0, 1], listen_port));
    tracing::info!(
        "Static file server running at http://{}, serving directory: {:?}",
        addr,
        static_dir
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;

    Ok(async { Ok(axum::serve(listener, app.into_make_service()).await?) })
}

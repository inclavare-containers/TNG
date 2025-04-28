pub mod task;

use self::task::tng::launch_tng;
use anyhow::{bail, Context, Result};
use futures::StreamExt as _;
use task::app::AppType;
use tng::runtime::TracingReloadHandle;
use tokio::{
    sync::OnceCell,
    task::{JoinError, JoinHandle},
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

static BIN_TEST_LOG_RELOAD_HANDLE: OnceCell<TracingReloadHandle> = OnceCell::const_new();

pub async fn run_test(
    server: &AppType,
    client: &AppType,
    tng_server_config: &str,
    tng_client_config: &str,
) -> Result<()> {
    BIN_TEST_LOG_RELOAD_HANDLE
        .get_or_init(|| async {
            // Initialize rustls crypto provider
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("Failed to install rustls crypto provider");

            // Initialize log tracing
            let pending_tracing_layers = vec![tracing_subscriber::fmt::layer()
                .with_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                        format!(
                            "info,tng=debug,{}=debug",
                            std::module_path!().split("::").next().unwrap()
                        )
                        .into()
                    }),
                )
                .boxed()];
            let (pending_tracing_layers, reload_handle) =
                tracing_subscriber::reload::Layer::new(pending_tracing_layers);
            tracing_subscriber::registry()
                .with(pending_tracing_layers)
                // .with(console_subscriber::spawn()) // Initialize tokio console
                .init();

            reload_handle
        })
        .await;

    let token = CancellationToken::new();

    let tng_server = launch_tng(token.clone(), "tng_server", tng_server_config).await?;
    let tng_client = launch_tng(token.clone(), "tng_client", tng_client_config).await?;
    let app_server = server.launch(token.clone()).await?;
    let app_client = client.launch(token.clone()).await?;

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    let mut sub_tasks = futures::stream::FuturesUnordered::new();

    sub_tasks.push(wrap_with_name("app_client", app_client));
    sub_tasks.push(wrap_with_name("app_server", app_server));
    sub_tasks.push(wrap_with_name("tng_client", tng_client));
    sub_tasks.push(wrap_with_name("tng_server", tng_server));

    loop {
        tokio::select! {
            _ = sigint.recv() => {
                token.cancel();
                bail!("We got SIGINT, cancel now");
            }
            _ = sigterm.recv() => {
                token.cancel();
                bail!("We got SIGTERM, cancel now");
            }
            next = sub_tasks.next() => {
                match next{
                    Some(res)  =>{
                        let (task_name, res) = match res {
                            Ok((s,t)) => {(s, Ok(t))},
                            Err((s,e)) => {(s, Err(e))},
                        };

                        res.with_context(||format!("The {task_name} task paniced"))?.with_context(||format!("Error in the {task_name} task"))?;
                    },
                    None =>{
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn wrap_with_name<T>(
    name: &str,
    join_handle: JoinHandle<T>,
) -> core::result::Result<(&str, T), (&str, JoinError)> {
    join_handle.await.map(|t| (name, t)).map_err(|e| (name, e))
}

pub mod netns;
pub mod task;

use std::{collections::HashMap, time::Duration};

use anyhow::{bail, Context, Result};
use futures::StreamExt as _;
use netns::BridgeNetwork;
use task::Task;
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

static BIN_TEST_LOG_RELOAD_HANDLE: OnceCell<
    tracing_subscriber::reload::Handle<
        Vec<Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>>,
        tracing_subscriber::Registry,
    >,
> = OnceCell::const_new();

/// This is a common function to run bin tests. For each test, it will create many virtual nodes under
/// a bridge network (192.168.1.0/24), at least there will be one node act as the server side, the other act as
/// the client side. And the attestation service will be at `http://192.168.1.254:8080`.
/// And all the test will be run in those two virtual nodes one by one.
pub async fn run_test(tasks: Vec<Box<dyn Task>>) -> Result<()> {
    let token = CancellationToken::new();

    let test_future = async {
        BIN_TEST_LOG_RELOAD_HANDLE
            .get_or_init(|| async {
                // Initialize rustls crypto provider
                rustls::crypto::ring::default_provider()
                    .install_default()
                    .expect("Failed to install rustls crypto provider");

                // Initialize log tracing
                let pending_tracing_layers = vec![];
                let (pending_tracing_layers, reload_handle) =
                    tracing_subscriber::reload::Layer::new(pending_tracing_layers);
                tracing_subscriber::registry()
                    .with(pending_tracing_layers.with_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(
                            |_| "info,tokio_graceful=off,rats_cert=trace,tng=trace".into(),
                        ),
                    ))
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_ansi(atty::is(atty::Stream::Stdout))
                            .with_filter(
                                tracing_subscriber::EnvFilter::try_from_default_env()
                                    .unwrap_or_else(|_| {
                                        format!(
                                    "info,tokio_graceful=off,rats_cert=debug,tng=debug,{}=debug",
                                    std::module_path!().split("::").next().unwrap()
                                )
                                        .into()
                                    }),
                            ),
                    )
                    // .with(console_subscriber::spawn()) // Initialize tokio console
                    .init();

                reload_handle
            })
            .await;

        // Create a virtual network with two nodes connected to a bridge
        let network = BridgeNetwork::new("192.168.1.254", 24).await?;

        let mut ip_to_nodes = HashMap::new();

        // Launch all tasks in order and get the join handles
        let mut sub_tasks = futures::stream::FuturesUnordered::new();
        for task in tasks {
            sub_tasks.push({
                let task_name = task.name();

                let task_result = {
                    let task_name = task_name.clone();

                    let ip = task.node_type().ip();
                    if !ip_to_nodes.contains_key(&ip) {
                        let new_node = network.new_node(&ip).await?;
                        ip_to_nodes.insert(ip.clone(), new_node);
                    }
                    let node = ip_to_nodes.get(&ip).unwrap();

                    let token = token.clone();
                    node.run(async move {
                        // Timeout is 1 minute.
                        let timeout = tokio::time::sleep(Duration::from_secs(60));

                        tokio::select! {
                            _ = timeout => {
                                bail!("Timeout waiting for task {task_name} to be ready");
                            },
                            res = task.launch(token) => res
                        }
                    })
                    .await
                    .and_then(|r| r)?
                };

                async {
                    (
                        task_name,
                        task_result
                            .await
                            .map_err(anyhow::Error::from)
                            .and_then(|r| r),
                    )
                }
            });
        }

        let mut first_error = None;

        loop {
            match sub_tasks.next().await {
                Some((task_name, res)) => {
                    if let Err(e) = res.with_context(|| format!("Error in the {task_name} task")) {
                        tracing::error!(error=?e, "Got error in task");
                        if first_error.is_none() {
                            first_error = Some(e);
                        }
                    }
                }
                None => {
                    break;
                }
            }
        }

        if let Some(e) = first_error {
            return Err(e);
        }

        Ok::<_, anyhow::Error>(())
    };

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        _ = sigint.recv() => {
            token.cancel();
            bail!("We got SIGINT, cancel now");
        }
        _ = sigterm.recv() => {
            token.cancel();
            bail!("We got SIGTERM, cancel now");
        }
        res = test_future => {
            res?;
        }
    }

    Ok(())
}

pub mod netns;
pub mod task;
pub mod test_context;

use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use futures::StreamExt as _;
use netns::BridgeNetwork;
use task::Task;
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
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
///
/// The `name` parameter identifies this test for structured logging (e.g. `function_name!()` or a
/// string literal like `"no_ra"`).
pub async fn run_test(name: &str, tasks: Vec<Box<dyn Task>>) -> Result<()> {
    let token = CancellationToken::new();

    let result = {
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

            // Log test start with task topology
            let task_refs: Vec<&dyn Task> = tasks.iter().map(|t| t.as_ref()).collect();
            test_context::log_test_start(name, &task_refs);

            // Create a virtual network with two nodes connected to a bridge
            let network = BridgeNetwork::new("192.168.1.254", 24).await?;

            // Create required Node for each task
            let mut ip_to_nodes = HashMap::new();
            let mut tasks_with_nodes = vec![];
            for task in tasks {
                let ip = task.node_type().ip();
                if !ip_to_nodes.contains_key(&ip) {
                    let new_node = Arc::new(network.new_node(&ip).await?);
                    ip_to_nodes.insert(ip.clone(), Arc::clone(&new_node));
                }
                let node = ip_to_nodes.get(&ip).unwrap();

                tasks_with_nodes.push((task, Arc::clone(node)));
            }

            // Launch all tasks in order and get the join handles
            let mut sub_tasks = futures::stream::FuturesUnordered::new();
            for (task, node) in tasks_with_nodes {
                let display_name = test_context::display_name_for_task(task.as_ref());
                sub_tasks.push({
                    let task_name = display_name.clone();

                    let task_result = {
                        let task_name_inner = task_name.clone();
                        let token = token.clone();
                        let task_span = tracing::info_span!("task", task = %display_name);
                        node.run(
                            async move {
                                // Timeout is 1 minute.
                                let timeout = tokio::time::sleep(Duration::from_secs(60));

                                tokio::select! {
                                    _ = timeout => {
                                        bail!("Timeout waiting for task {task_name_inner} to be ready");
                                    },
                                    res = task.launch(token) => res
                                }
                            }
                            .instrument(task_span),
                        )
                        .await
                        .and_then(|r| r)?
                    };

                    async move {
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
                        if let Err(e) =
                            res.with_context(|| format!("Error in the {task_name} task"))
                        {
                            tracing::error!("[{name}] Error in task {task_name}: {e:?}");
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
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

        tokio::select! {
            _ = sigint.recv() => {
                token.cancel();
                Err(anyhow::anyhow!("We got SIGINT, cancel now"))
            }
            _ = sigterm.recv() => {
                token.cancel();
                Err(anyhow::anyhow!("We got SIGTERM, cancel now"))
            }
            res = test_future => res,
        }
    };

    test_context::log_test_end(name, &result);
    result
}

/// Convenience macro that calls [`run_test`] with a name automatically derived from
/// the source location (`file!():line!()`).  This avoids boilerplate in every test function.
///
/// ```ignore
/// #[tokio::test]
/// async fn my_test() -> Result<()> {
///     run_test!(vec![
///         TngInstance::TngServer(r#"..."#).boxed(),
///         // ...
///     ])
///     .await
/// }
/// ```
///
/// The generated name looks like `"no_ra.rs:10"` which uniquely identifies the call site.
#[macro_export]
macro_rules! run_test {
    ($tasks:expr) => {
        $crate::run_test(concat!(file!(), ":", line!()), $tasks)
    };
}

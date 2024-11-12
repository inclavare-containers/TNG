use std::{net::SocketAddr, time::Duration};

use again::RetryPolicy;
use anyhow::{anyhow, bail, Context, Result};
use axum::{routing::get, Router};
use futures::{StreamExt as _, TryStreamExt as _};
use log::info;
use netns_rs::NetNs;
use tng::TngBuilder;
use tokio::{net::TcpListener, runtime::Builder, task::JoinHandle};
use tokio_util::sync::CancellationToken;

const HTTP_RESPONSE_BODY: &str = "Hello World!";

async fn axum_path_handler() -> &'static str {
    HTTP_RESPONSE_BODY
}

async fn launch_http_server(token: CancellationToken, port: u16) -> Result<JoinHandle<Result<()>>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on 127.0.0.1:{port} and waiting for connection from client");

    Ok(tokio::spawn(async move {
        let app = Router::new().route("/", get(axum_path_handler));
        let server = axum::serve(listener, app);

        tokio::select! {
            _ = token.cancelled() => {
                // The token was cancelled, task can shut down
            }
            res = server => {
                // Long work has completed
                res?;
            }
        }

        info!("The http_server task normally exit now");
        Ok(())
    }))
}

async fn launch_http_client(
    token: CancellationToken,
    ip: &str,
    port: u16,
) -> Result<JoinHandle<Result<()>>> {
    let ip = ip.to_owned();

    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();

        info!("Send http request to {ip}:{port}");
        let resp = RetryPolicy::fixed(Duration::from_secs(1))
            .with_max_retries(5)
            .retry(|| async {
                let res = reqwest::get(format!("http:///{ip}:{port}"))
                    .await?
                    .text()
                    .await;
                res
            })
            .await?;

        if resp != HTTP_RESPONSE_BODY {
            bail!("The response body should be `{HTTP_RESPONSE_BODY}`, but got `{resp}`")
        } else {
            info!("Success! The response matchs expected value.");
        }

        info!("The http_client task normally exit now");
        Ok(())
    }))
}

async fn launch_tng(
    token: CancellationToken,
    task_name: &str,
    config_json: &str,
) -> Result<JoinHandle<Result<()>>> {
    let config_json = config_json.to_owned();

    let task_name = task_name.to_owned();
    let join_handle = tokio::task::spawn_blocking(move || -> Result<()> {
        let config: tng::config::TngConfig = serde_json::from_str(&config_json)?;
        let mut instance = TngBuilder::new(config).launch()?;
        {
            let task_name = task_name.to_owned();
            let stopper = instance.stopper();
            std::thread::spawn(move || {
                let rt = Builder::new_current_thread().enable_all().build().unwrap();
                rt.block_on(async move { token.cancelled().await });
                info!("{task_name}: stopping the tng instance now");
                stopper
                    .stop()
                    .with_context(|| {
                        format!("Failed to call stop() on tng instance in {task_name}")
                    })
                    .unwrap();
            });
        }

        instance.wait()?;
        instance.clean_up()?;

        info!("The {task_name} task normally exit now");
        Ok(())
    });

    // TODO: better way to checking readiness of envoy
    tokio::time::sleep(Duration::from_secs(3)).await;

    return Ok(join_handle);
}

#[test]
fn it_adds_two() -> Result<()> {
    // console_subscriber::init();

    env_logger::Builder::from_env(
        env_logger::Env::default()
            .filter_or("TNG_LOG_LEVEL", "debug")
            .write_style_or("TNG_LOG_STYLE", "always"),
    )
    .is_test(true)
    .init();

    // Run tests in standalone network namespace
    let ns = NetNs::new("my_netns")?;
    let res = ns.run(|_ns| -> Result<()> {
        let rt = Builder::new_multi_thread()
            .worker_threads(10)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            // Set lo interface to UP status
            {
                let (connection, handle, _) = rtnetlink::new_connection()?;
                let join_handle = tokio::spawn(connection);

                // Equals to ip link set lo up
                let mut links = handle.link().get().match_name("lo".to_owned()).execute();
                let link = links
                    .try_next()
                    .await?
                    .ok_or(anyhow!("Failed to find interface with name `lo`"))?;
                handle.link().set(link.header.index).up().execute().await?;
                
                drop(handle);
                join_handle.await?;
                info!("Setting up interfaces in new network namespace finished")
            }

            let token = CancellationToken::new();

                        let tng_server = launch_tng(
                            token.clone(),
                            "tng_server",
                            r#"
            {
              "add_egress": [
                {
                  "mapping": {
                    "in": {
                      "host": "127.0.0.1",
                      "port": 20001
                    },
                    "out": {
                      "host": "127.0.0.1",
                      "port": 30001
                    }
                  },
                  "attest": {
                    "aa_addr": "unix:///tmp/attestation.sock"
                  }
                }
              ]
            }
            "#,
                        )
                        .await?;

                        let tng_client = launch_tng(
                            token.clone(),
                            "tng_client",
                            r#"
            {
              "add_ingress": [
                {
                  "mapping": {
                    "in": {
                      "port": 10001
                    },
                    "out": {
                      "host": "127.0.0.1",
                      "port": 20001
                    }
                  },
                  "verify": {
                    "as_addr": "http://127.0.0.1:8080/",
                    "policy_ids": [
                      "default"
                    ]
                  }
                }
              ]
            }
            "#,
                        )
                        .await?;

            let app_server = launch_http_server(token.clone(), 30001).await?;

            let app_client = launch_http_client(token.clone(), "127.0.0.1", 10001).await?;

            let mut sigint =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

            let mut sub_tasks = futures::stream::FuturesUnordered::new();

            sub_tasks.push(app_client);
            sub_tasks.push(app_server);
            sub_tasks.push(tng_client);
            sub_tasks.push(tng_server);

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
                                res.context("The tng server task paniced")?.context("Error in tng server")?;
                            },
                            None =>{
                                break;
                            }
                        }
                    }
                }
            }

            Ok(())
        })?;

        Ok(())
    });

    // Anyway, we shoule remove netns first.
    ns.remove()?;

    res??;

    Ok(())
}

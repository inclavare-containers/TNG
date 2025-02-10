use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use socket2::SockRef;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_graceful::ShutdownGuard;
use tracing::Instrument;

use crate::{
    config::egress::{CommonArgs, EgressNetfilterArgs},
    executor::iptables::IpTablesAction,
    tunnel::{
        egress::core::stream_manager::{trusted::TrustedStreamManager, StreamManager},
        utils, RegistedService,
    },
};

const NETFILTER_LISTEN_PORT_BEGIN_DEFAULT: u16 = 40000;
const NETFILTER_SO_MARK_DEFAULT: u32 = 565;

pub struct NetfilterEgress {
    listen_port: u16,
    so_mark: u32,
    common_args: CommonArgs,
}

impl NetfilterEgress {
    pub fn new(
        netfilter_args: &EgressNetfilterArgs,
        common_args: &CommonArgs,
        id: usize,
        iptables_actions: &mut Vec<IpTablesAction>,
    ) -> Result<Self> {
        let listen_port = netfilter_args
            .listen_port
            .unwrap_or(NETFILTER_LISTEN_PORT_BEGIN_DEFAULT + (id as u16));
        let so_mark = netfilter_args.so_mark.unwrap_or(NETFILTER_SO_MARK_DEFAULT);

        iptables_actions.push(IpTablesAction::Redirect {
            capture_dst: netfilter_args.capture_dst.clone(),
            capture_local_traffic: netfilter_args.capture_local_traffic,
            listen_port,
            so_mark,
        });

        Ok(Self {
            listen_port,
            so_mark,
            common_args: common_args.clone(),
        })
    }
}

#[async_trait]
impl RegistedService for NetfilterEgress {
    async fn serve(&self, shutdown_guard: ShutdownGuard) -> Result<()> {
        let trusted_stream_manager =
            Arc::new(TrustedStreamManager::new(&self.common_args, shutdown_guard.clone()).await?);

        let listen_addr = format!("127.0.0.1:{}", self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        let listener = TcpListener::bind(listen_addr).await.unwrap();
        // TODO: ENVOY_LISTENER_SOCKET_OPTIONS

        let so_mark = self.so_mark;

        loop {
            let (downstream, _) = tokio::select! {
                res = listener.accept() => res.unwrap(),
                _ = shutdown_guard.cancelled() => {
                    tracing::debug!("Shutdown signal received, stop accepting new connections");
                    break;
                }
            };
            let peer_addr = downstream.peer_addr().unwrap();

            let socket_ref = SockRef::from(&downstream);
            let orig_dst = socket_ref
                .original_dst()?
                .as_socket()
                .context("should be a tcp socket")?;

            let trusted_stream_manager = trusted_stream_manager.clone();

            let span = tracing::info_span!("serve", client=?peer_addr);
            shutdown_guard.spawn_task_fn(move |shutdown_guard| {
                async move {
                    tracing::debug!("Start serving connection from client");

                    let (sender, mut receiver) = mpsc::unbounded_channel();

                    shutdown_guard.spawn_task(
                        async move {
                            while let Some(stream) = receiver.recv().await {
                                let fut = async {
                                    let upstream = TcpStream::connect(orig_dst).await?;

                                    let socket_ref = SockRef::from(&upstream);
                                    socket_ref.set_mark(so_mark)?;

                                    utils::forward_stream(upstream, TokioIo::new(stream)).await
                                };

                                if let Err(e) = fut.await {
                                    tracing::error!(error=?e, "Failed to forward stream");
                                }
                            }
                        }
                        .in_current_span(),
                    );

                    // Consume streams come from downstream
                    match trusted_stream_manager
                        .consume_stream(downstream, sender, shutdown_guard)
                        .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            let error = format!("{e:#}");
                            tracing::error!(error, "Failed to consume stream from client");
                        }
                    }
                }
                .instrument(span)
            });
        }

        Ok(())
    }
}

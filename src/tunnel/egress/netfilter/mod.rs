use std::sync::Arc;

use anyhow::{Context, Result};
use hyper_util::rt::TokioIo;
use socket2::SockRef;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tracing::Instrument;

use crate::{
    config::egress::{CommonArgs, EgressNetfilterArgs},
    executor::iptables::IpTablesAction,
    tunnel::{
        egress::core::stream_manager::{trusted::TrustedStreamManager, StreamManager},
        ingress::core::TngEndpoint,
        utils,
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

    pub async fn serve(&self) -> Result<()> {
        let trusted_stream_manager = Arc::new(TrustedStreamManager::new(&self.common_args).await?);

        let listen_addr = format!("127.0.0.1:{}", self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        let listener = TcpListener::bind(listen_addr).await.unwrap();
        // TODO: ENVOY_LISTENER_SOCKET_OPTIONS

        let so_mark = self.so_mark;

        loop {
            let (downstream, _) = listener.accept().await.unwrap();
            let peer_addr = downstream.peer_addr().unwrap();

            let socket_ref = SockRef::from(&downstream);
            let orig_dst = socket_ref
                .original_dst()?
                .as_socket()
                .context("should be a tcp socket")?;

            let dst = TngEndpoint::new(orig_dst.ip().to_string(), orig_dst.port());

            let trusted_stream_manager = trusted_stream_manager.clone();

            tokio::task::spawn(
                async move {
                    tracing::debug!("Start serving connection from client");

                    let (sender, mut receiver) = mpsc::unbounded_channel();

                    tokio::task::spawn(
                        async move {
                            while let Some(stream) = receiver.recv().await {
                                let fut = async {
                                    let upstream = TcpStream::connect(orig_dst).await?;

                                    let socket_ref = SockRef::from(&upstream);
                                    socket_ref.set_mark(so_mark)?;

                                    utils::forward_stream(TokioIo::new(stream), upstream).await
                                };

                                if let Err(e) = fut.await {
                                    tracing::error!(error=?e, "Failed to forward stream");
                                }
                            }
                        }
                        .instrument(tracing::info_span!("forward_upstream")),
                    );

                    // Consume streams come from downstream
                    match trusted_stream_manager
                        .consume_stream(downstream, sender)
                        .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            let error = format!("{e:#}");
                            tracing::error!(error, "Failed to consume stream from client");
                        }
                    }
                }
                .instrument(tracing::info_span!("serve", client=?peer_addr, %dst)),
            );
        }
    }
}

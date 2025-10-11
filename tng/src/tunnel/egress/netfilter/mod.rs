use anyhow::{Context, Result};
use async_stream::stream;
use async_trait::async_trait;
use futures::StreamExt;
use indexmap::IndexMap;
use socket2::SockRef;
use tokio::net::TcpListener;

use crate::{
    config::{egress::EgressNetfilterArgs, Endpoint},
    tunnel::{
        egress::flow::AcceptedStream,
        endpoint::TngEndpoint,
        utils::{
            iptables::IptablesExecutor,
            runtime::TokioRuntime,
            socket::{SetListenerSockOpts, TCP_CONNECT_SO_MARK_DEFAULT},
        },
    },
};

use super::flow::{EgressTrait, Incomming};

mod iptables;

pub struct NetfilterEgress {
    id: usize,
    capture_dst: Endpoint,
    capture_local_traffic: bool,
    listen_port: u16,
    so_mark: u32,
}

impl NetfilterEgress {
    pub async fn new(id: usize, netfilter_args: &EgressNetfilterArgs) -> Result<Self> {
        let listen_port = match netfilter_args.listen_port {
            Some(p) => p,
            None => portpicker::pick_unused_port().context("Failed to pick a free port")?,
        };

        let so_mark = netfilter_args
            .so_mark
            .unwrap_or(TCP_CONNECT_SO_MARK_DEFAULT);

        Ok(Self {
            id,
            capture_dst: netfilter_args.capture_dst.clone(),
            capture_local_traffic: netfilter_args.capture_local_traffic,
            listen_port,
            so_mark,
        })
    }
}

#[async_trait]
impl EgressTrait for NetfilterEgress {
    /// egress_type=netfilter,egress_id={id},egress_listen_port={listen_port}
    fn metric_attributes(&self) -> IndexMap<String, String> {
        [
            ("egress_type".to_owned(), "netfilter".to_owned()),
            ("egress_id".to_owned(), self.id.to_string()),
            (
                "egress_listen_port".to_owned(),
                self.listen_port.to_string(),
            ),
        ]
        .into()
    }

    fn transport_so_mark(&self) -> Option<u32> {
        Some(self.so_mark)
    }

    async fn accept(&self, _runtime: TokioRuntime) -> Result<Incomming> {
        // We have to listen on 0.0.0.0 to capture all traffic been redirected from any interface.
        // See REDIRECT section on https://ipset.netfilter.org/iptables-extensions.man.html
        let listen_addr = format!("0.0.0.0:{}", self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        // Setup iptables
        let iptables_guard = IptablesExecutor::setup(self).await?;

        let listener = TcpListener::bind(listen_addr).await?;
        listener.set_listener_common_sock_opts()?;

        Ok(Box::new(
            stream! {
                let _iptables_guard = iptables_guard; // Move iptables guard to here to keep it alive
                loop {
                    yield listener.accept_with_common_sock_opts().await
                }
            }
            .map(move |res| {
                let (stream, peer_addr) = res?;
                let socket_ref = SockRef::from(&stream);
                let orig_dst = socket_ref
                    .original_dst()
                    .context("failed to get original destination")?
                    .as_socket()
                    .context("should be a ip address")?;

                // TODO: replace TngEndpoint with a enum type, so that no need to call sock_addr.ip().to_string()
                let dst = TngEndpoint::new(orig_dst.ip().to_string(), orig_dst.port());

                Ok(AcceptedStream {
                    stream: Box::new(stream),
                    src: peer_addr,
                    dst,
                })
            }),
        ))
    }
}

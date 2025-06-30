use anyhow::{anyhow, bail, Context, Result};
use async_stream::stream;
use async_trait::async_trait;
use futures::StreamExt;
use indexmap::IndexMap;
use socket2::SockRef;
use tokio::net::TcpListener;
use tokio_graceful::ShutdownGuard;

use crate::config::ingress::IngressNetfilterArgs;
use crate::config::ingress::IngressNetfilterCaptureDst;
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::ingress::flow::AcceptedStream;
use crate::tunnel::utils::iptables::IptablesExecutor;
use crate::tunnel::utils::socket::SetListenerSockOpts;
use crate::tunnel::utils::socket::TCP_CONNECT_SO_MARK_DEFAULT;

use super::flow::Incomming;
use super::flow::IngressTrait;

mod iptables;

pub struct NetfilterIngress {
    id: usize,
    capture_dst: Vec<IngressNetfilterCaptureDst>,
    capture_cgroup: Vec<String>,
    nocapture_cgroup: Vec<String>,
    listen_port: u16,
    so_mark: u32,
}

impl NetfilterIngress {
    pub async fn new(id: usize, netfilter_args: &IngressNetfilterArgs) -> Result<Self> {
        let listen_port = match netfilter_args.listen_port {
            Some(p) => p,
            None => portpicker::pick_unused_port().context("Failed to pick a free port")?,
        };

        if netfilter_args.capture_dst.is_empty() && netfilter_args.capture_cgroup.is_empty() {
            bail!("At least one of capture_dst, capture_cgroup must be set and not empty");
        }

        let capture_dst = netfilter_args
            .capture_dst
            .iter()
            .map(Clone::clone)
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>>>()?;

        let so_mark = netfilter_args
            .so_mark
            .unwrap_or(TCP_CONNECT_SO_MARK_DEFAULT);

        Ok(Self {
            id,
            capture_dst,
            capture_cgroup: netfilter_args.capture_cgroup.clone(),
            nocapture_cgroup: netfilter_args.nocapture_cgroup.clone(),
            listen_port,
            so_mark,
        })
    }
}

#[async_trait]
impl IngressTrait for NetfilterIngress {
    /// ingress_type=netfilter,ingress_id={id},ingress_listen_port={listen_port}
    fn metric_attributes(&self) -> IndexMap<String, String> {
        [
            ("ingress_type".to_owned(), "netfilter".to_owned()),
            ("ingress_id".to_owned(), self.id.to_string()),
            (
                "ingress_listen_port".to_owned(),
                self.listen_port.to_string(),
            ),
        ]
        .into()
    }

    fn transport_so_mark(&self) -> Option<u32> {
        Some(self.so_mark)
    }

    async fn accept(&self, _shutdown_guard: ShutdownGuard) -> Result<Incomming> {
        let listen_addr = format!("127.0.0.1:{}", self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        // Setup iptables
        let iptables_guard = IptablesExecutor::setup(self).await?;

        let listener = TcpListener::bind(listen_addr).await?;
        listener.set_listener_common_sock_opts()?;
        listener.set_listener_tproxy_sock_opts()?;

        let listen_addr = listener.local_addr()?;

        Ok(Box::new(
            stream!{
                let _iptables_guard = iptables_guard; // Move iptables guard to here to keep it alive
                loop {
                    yield listener.accept().await
                }
            }
            .map(move |res| {
                let (stream, peer_addr) = res?;

                let socket_ref = SockRef::from(&stream);
                // Note here since we are using TPROXY, the original destination is recorded in the local address.
                let orig_dst = socket_ref
                    .local_addr()
                    .context("failed to get original destination")?
                    .as_socket()
                    .context("should be a ip address")?;

                // Check if the original destination is the same as the listener port to prevert from the recursion.
                if listen_addr.port() == orig_dst.port() && orig_dst.ip().is_loopback() {
                    Err(anyhow!("The original destination is the same as the listener port, recursion is detected"))?
                }

                let orig_dst = TngEndpoint::new(orig_dst.ip().to_string(), orig_dst.port());

                Ok::<_, anyhow::Error>(AcceptedStream{
                    stream: Box::new(stream),
                    src: peer_addr,
                    dst: orig_dst,
                    via_tunnel: true,
                })
            })
        ))
    }
}

use anyhow::{anyhow, Context, Result};
use async_stream::stream;
use async_trait::async_trait;
use indexmap::IndexMap;
use tokio::net::TcpListener;
use tokio_graceful::ShutdownGuard;

use crate::config::ingress::IngressMappingArgs;
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::ingress::flow::AcceptedStream;
use crate::tunnel::utils::socket::SetListenerSockOpts;

use super::flow::{Incomming, IngressTrait};

pub struct MappingIngress {
    id: usize,
    listen_addr: String,
    listen_port: u16,
    upstream_addr: String,
    upstream_port: u16,
}

impl MappingIngress {
    pub async fn new(id: usize, mapping_args: &IngressMappingArgs) -> Result<Self> {
        let listen_addr = mapping_args
            .r#in
            .host
            .as_deref()
            .unwrap_or("0.0.0.0")
            .to_owned();
        let listen_port = mapping_args.r#in.port;

        let upstream_addr = mapping_args
            .out
            .host
            .as_deref()
            .context("'host' of 'out' field must be set")?
            .to_owned();
        let upstream_port = mapping_args.out.port;

        Ok(Self {
            id,
            listen_addr,
            listen_port,
            upstream_addr,
            upstream_port,
        })
    }
}

#[async_trait]
impl IngressTrait for MappingIngress {
    /// ingress_type=mapping,ingress_id={id},ingress_in={in.host}:{in.port},ingress_out={out.host}:{out.port}
    fn metric_attributes(&self) -> IndexMap<String, String> {
        [
            ("ingress_type".to_owned(), "mapping".to_owned()),
            ("ingress_id".to_owned(), self.id.to_string()),
            (
                "ingress_in".to_owned(),
                format!("{}:{}", self.listen_addr, self.listen_port),
            ),
            (
                "ingress_out".to_owned(),
                format!("{}:{}", self.upstream_addr, self.upstream_port),
            ),
        ]
        .into()
    }

    fn transport_so_mark(&self) -> Option<u32> {
        None
    }

    async fn accept(&self, _shutdown_guard: ShutdownGuard) -> Result<Incomming> {
        let listen_addr = format!("{}:{}", self.listen_addr, self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        let listener = TcpListener::bind(listen_addr).await?;
        listener.set_listener_common_sock_opts()?;

        Ok(Box::new(stream! {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => yield Ok(AcceptedStream{
                        stream: Box::new(stream),
                        src: peer_addr,
                        dst: TngEndpoint::new(self.upstream_addr.clone(), self.upstream_port),
                        via_tunnel: true,
                    }),
                    Err(e) => yield Err(anyhow!(e)),
                };
            }
        }))
    }
}

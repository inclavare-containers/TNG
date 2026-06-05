use anyhow::{anyhow, Context, Result};
use async_stream::stream;
use async_trait::async_trait;
use indexmap::IndexMap;
use tokio::net::TcpListener;

use crate::{
    config::egress::EgressMappingArgs,
    tunnel::access_log::EgressMode,
    tunnel::{
        egress::flow::AcceptedStream, endpoint::TngEndpoint, utils::runtime::TokioRuntime,
        utils::socket::SetListenerSockOpts,
    },
};

use super::flow::{EgressTrait, Incomming};

pub struct MappingEgress {
    id: usize,
    listen_addr: String,
    listen_port: u16,
    upstream_addr: String,
    upstream_port: u16,
}

impl MappingEgress {
    pub async fn new(id: usize, mapping_args: &EgressMappingArgs) -> Result<Self> {
        Ok(Self {
            id,
            listen_addr: mapping_args
                .r#in
                .host
                .as_deref()
                .unwrap_or("0.0.0.0")
                .to_owned(),
            listen_port: mapping_args.r#in.port,

            upstream_addr: mapping_args
                .out
                .host
                .as_deref()
                .context("'host' of 'out' field must be set")?
                .to_owned(),
            upstream_port: mapping_args.out.port,
        })
    }
}

#[async_trait]
impl EgressTrait for MappingEgress {
    /// egress_type=netfilter,egress_id={id},egress_in={in.host}:{in.port},egress_out={out.host}:{out.port}
    fn metric_attributes(&self) -> IndexMap<String, String> {
        [
            ("egress_type".to_owned(), "mapping".to_owned()),
            ("egress_id".to_owned(), self.id.to_string()),
            (
                "egress_in".to_owned(),
                format!("{}:{}", self.listen_addr, self.listen_port),
            ),
            (
                "egress_out".to_owned(),
                format!("{}:{}", self.upstream_addr, self.upstream_port),
            ),
        ]
        .into()
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn transport_so_mark(&self) -> Option<u32> {
        None
    }

    async fn accept(&self, _runtime: TokioRuntime) -> Result<Incomming> {
        let listen_addr = format!("{}:{}", self.listen_addr, self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        let listener = TcpListener::bind(listen_addr).await?;
        listener.set_listener_common_sock_opts()?;

        let listen_addr = listener.local_addr()?;

        Ok(Box::new(stream! {
            loop {
                match listener.accept_with_common_sock_opts().await {
                    Ok((stream, peer_addr)) => yield Ok(AcceptedStream{
                        stream: Box::new(crate::ContextualStream::new(stream, "egress-mapping")),
                        src: peer_addr,
                        dst: TngEndpoint::new(self.upstream_addr.clone(), self.upstream_port),
                        listener_addr: listen_addr,
                        egress_mode: EgressMode::Mapping,
                    }),
                    Err(e) => yield Err(anyhow!(e)),
                }
            }
        }))
    }
}

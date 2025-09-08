use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_stream::stream;
use async_trait::async_trait;
use fast_socks5::server::Socks5ServerProtocol;
use futures::StreamExt;
use indexmap::IndexMap;
use tokio::net::{TcpListener, TcpStream};

use crate::config::ingress::{IngressSocks5Args, Socks5AuthArgs};
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::ingress::flow::AcceptedStream;
use crate::tunnel::utils::endpoint_matcher::EndpointMatcher;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::socket::SetListenerSockOpts;

use super::flow::stream_router::StreamRouter;
use super::flow::{Incomming, IngressTrait};

/// Define the maximum concurrency of socks5 session which is in handshake stage.
const MAX_CONCURRENCY_HANDSHAKE_SOCKS5_SESSION: usize = 1024;

pub struct Socks5Ingress {
    id: usize,
    listen_addr: String,
    listen_port: u16,
    auth: Arc<Option<Socks5AuthArgs>>,
    stream_router: Arc<StreamRouter>,
}

impl Socks5Ingress {
    pub async fn new(id: usize, socks5_args: &IngressSocks5Args) -> Result<Self> {
        let listen_addr = socks5_args
            .proxy_listen
            .host
            .as_deref()
            .unwrap_or("0.0.0.0")
            .to_owned();
        let listen_port = socks5_args.proxy_listen.port;

        let stream_router = Arc::new(StreamRouter::with_endpoint_matcher(EndpointMatcher::new(
            &socks5_args.dst_filters,
        )?));

        Ok(Self {
            id,
            listen_addr,
            listen_port,
            auth: Arc::new(socks5_args.auth.clone()),
            stream_router,
        })
    }
}

async fn serve_socks5(
    in_stream: TcpStream,
    auth: Arc<Option<Socks5AuthArgs>>,
) -> Result<(TcpStream, TngEndpoint)> {
    tracing::trace!("Start serving stream as socks5 connection");

    let proto = match auth.as_ref() {
        Some(Socks5AuthArgs { username, password }) => {
            let (proto, check_result) =
                Socks5ServerProtocol::accept_password_auth(in_stream, |user, pass| {
                    user == *username && pass == *password
                })
                .await?;
            if !check_result {
                bail!("invalid username or password");
            }
            proto
        }
        None => Socks5ServerProtocol::accept_no_auth(in_stream).await?,
    };

    let (proto, cmd, target_addr) = proto.read_command().await?;

    let empty_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
    let empty_sockaddr = std::net::SocketAddr::new(empty_ip, 0);

    match cmd {
        fast_socks5::Socks5Command::TCPConnect => {
            let inner = proto.reply_success(empty_sockaddr).await?;

            let dst = match target_addr {
                fast_socks5::util::target_addr::TargetAddr::Ip(sock_addr) => {
                    // TODO: replace TngEndpoint with a enum type, so that no need to call sock_addr.ip().to_string()
                    TngEndpoint::new(sock_addr.ip().to_string(), sock_addr.port())
                }
                fast_socks5::util::target_addr::TargetAddr::Domain(domain, port) => {
                    TngEndpoint::new(domain, port)
                }
            };

            Ok((inner, dst))
        }
        fast_socks5::Socks5Command::TCPBind | fast_socks5::Socks5Command::UDPAssociate => {
            proto
                .reply_error(&fast_socks5::ReplyError::CommandNotSupported)
                .await?;
            Err(fast_socks5::ReplyError::CommandNotSupported.into())
        }
    }
}

#[async_trait]
impl IngressTrait for Socks5Ingress {
    /// ingress_type=socks5,ingress_id={id},ingress_proxy_listen={proxy_listen.host}:{proxy_listen.port}
    fn metric_attributes(&self) -> IndexMap<String, String> {
        [
            ("ingress_type".to_owned(), "socks5".to_owned()),
            ("ingress_id".to_owned(), self.id.to_string()),
            (
                "ingress_proxy_listen".to_owned(),
                format!("{}:{}", self.listen_addr, self.listen_port),
            ),
        ]
        .into()
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn transport_so_mark(&self) -> Option<u32> {
        None
    }

    async fn accept(&self, runtime: TokioRuntime) -> Result<Incomming> {
        let listen_addr = format!("{}:{}", self.listen_addr, self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        let listener = TcpListener::bind(listen_addr).await?;
        listener.set_listener_common_sock_opts()?;

        Ok(Box::new(
            stream! {
                loop {
                    yield listener.accept().await
                }
            }
            .map(move |res| {
                let runtime = runtime.clone();
                async move {
                    let (stream, peer_addr) = res?;

                    let auth = self.auth.clone();

                    // Run socks5 protocol in a separate task to add parallelism with multi-cpu
                    let (stream, dst) = runtime
                        .spawn_supervised_task_current_span(async move {
                            serve_socks5(stream, auth)
                                .await
                                .context("Failed to serve socks5 connection")
                        })
                        .await?
                        .assume_finished()??;

                    tracing::debug!(src = ?peer_addr, %dst, "Accepted socks5 connection");

                    let via_tunnel = self.stream_router.should_forward_via_tunnel(&dst);

                    Ok(AcceptedStream {
                        stream: Box::new(stream),
                        src: peer_addr,
                        dst,
                        via_tunnel,
                    })
                }
            })
            .buffer_unordered(MAX_CONCURRENCY_HANDSHAKE_SOCKS5_SESSION), // To parallelism the tcp accept and socks5 handshake process
        ))
    }
}

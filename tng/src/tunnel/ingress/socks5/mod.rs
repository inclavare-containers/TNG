use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use fast_socks5::server::Socks5ServerProtocol;
use opentelemetry::metrics::MeterProvider;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;
use tokio_graceful::ShutdownGuard;

use crate::config::ingress::CommonArgs;
use crate::config::ingress::{IngressSocks5Args, Socks5AuthArgs};
use crate::observability::trace::shutdown_guard_ext::ShutdownGuardExt;
use crate::service::RegistedService;
use crate::tunnel::access_log::AccessLog;
use crate::tunnel::ingress::core::stream_manager::trusted::TrustedStreamManager;
use crate::tunnel::ingress::core::stream_manager::StreamManager;
use crate::tunnel::ingress::core::TngEndpoint;
use crate::tunnel::service_metrics::ServiceMetrics;
use crate::tunnel::utils::socket::SetListenerSockOpts;

pub struct Socks5Ingress {
    listen_addr: String,
    listen_port: u16,
    auth: Option<Socks5AuthArgs>,
    metrics: ServiceMetrics,
    trusted_stream_manager: Arc<TrustedStreamManager>,
}

impl Socks5Ingress {
    pub async fn new(
        id: usize,
        socks5_args: &IngressSocks5Args,
        common_args: &CommonArgs,
        meter_provider: Arc<dyn MeterProvider + Send + Sync>,
    ) -> Result<Self> {
        let listen_addr = socks5_args
            .proxy_listen
            .host
            .as_deref()
            .unwrap_or("0.0.0.0")
            .to_owned();
        let listen_port = socks5_args.proxy_listen.port;

        // ingress_type=socks5,ingress_id={id},ingress_proxy_listen={proxy_listen.host}:{proxy_listen.port}
        let metrics = ServiceMetrics::new(
            meter_provider,
            [
                ("ingress_type".to_owned(), "socks5".to_owned()),
                ("ingress_id".to_owned(), id.to_string()),
                (
                    "ingress_proxy_listen".to_owned(),
                    format!("{}:{}", listen_addr, listen_port),
                ),
            ],
        );

        let trusted_stream_manager = Arc::new(TrustedStreamManager::new(common_args, None).await?);

        Ok(Self {
            listen_addr,
            listen_port,
            auth: socks5_args.auth.clone(),
            metrics,
            trusted_stream_manager,
        })
    }
}

async fn serve_socks5(
    in_stream: TcpStream,
    auth: &Option<Socks5AuthArgs>,
) -> Result<(TcpStream, TngEndpoint)> {
    tracing::trace!("Start serving stream as socks5 connection");

    let proto = match auth {
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
impl RegistedService for Socks5Ingress {
    async fn serve(&self, shutdown_guard: ShutdownGuard, ready: Sender<()>) -> Result<()> {
        self.trusted_stream_manager
            .prepare(shutdown_guard.clone())
            .await?;

        let listen_addr = format!("{}:{}", self.listen_addr, self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        let listener = TcpListener::bind(listen_addr).await?;
        listener.set_listener_common_sock_opts()?;

        ready.send(()).await?;

        loop {
            async {
                    let (downstream, peer_addr) = listener.accept().await?;


                    let trusted_stream_manager = self.trusted_stream_manager.clone();

                    self.metrics.cx_total.add(1);
                    let metrics = self.metrics.clone();

                    let auth = self.auth.clone();

                    let task = shutdown_guard.spawn_supervised_task_fn_with_span(
                        tracing::info_span!("serve", client=?peer_addr),
                        move |shutdown_guard| async move {
                            let fut = async move {
                                tracing::trace!("Start serving new connection from client");

                                let (downstream, dst) = serve_socks5(downstream, &auth).await.context("Failed to serve socks5 connection")?;

                                // Forward via trusted tunnel
                                match trusted_stream_manager
                                    .forward_stream(&dst, downstream, shutdown_guard, metrics)
                                    .await
                                {
                                    Ok((forward_stream_task, attestation_result)) => {
                                        // Print access log
                                        let access_log = AccessLog::Ingress {
                                            downstream: peer_addr,
                                            upstream: dst.clone(),
                                            to_trusted_tunnel: true,
                                            peer_attested: attestation_result,
                                        };
                                        tracing::info!(?access_log);

                                        if let Err(e) = forward_stream_task.await {
                                            let error = format!("{e:#}");
                                            tracing::error!(
                                                %dst,
                                                error,
                                                "Failed during forwarding to upstream via trusted tunnel"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        let error = format!("{e:#}");
                                        tracing::error!(
                                            %dst,
                                            error,
                                            "Failed to connect to upstream via trusted tunnel"
                                        );
                                    }
                                };

                                Ok::<(), anyhow::Error>(())
                            };

                            if let Err(e) = fut.await {
                                tracing::error!(error=?e, "Failed to forward stream");
                            }
                        },
                    );

                    // Spawn a task to trace the connection status.
                    shutdown_guard.spawn_supervised_task_current_span({
                        let cx_active = self.metrics.cx_active.clone();
                        let cx_failed = self.metrics.cx_failed.clone();
                        async move {
                            cx_active.add(1);
                            if !matches!(task.await, Ok(())) {
                                cx_failed.add(1);
                            }
                            cx_active.add(-1);
                        }
                    });
                    Ok::<_, anyhow::Error>(())
                }.await.unwrap_or_else(|e| {
                    tracing::error!(error=?e, "Failed to serve incoming connection from client");
                })
        }
    }
}

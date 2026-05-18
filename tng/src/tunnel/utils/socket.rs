use std::os::fd::AsFd;

use anyhow::{anyhow, Context, Result};
use nix::sys::socket::setsockopt;
use tokio::net::TcpStream;

#[allow(dead_code)]
pub const TCP_KEEPALIVE_IDLE_SECS: u32 = 10;
#[allow(dead_code)]
pub const TCP_KEEPALIVE_INTERVAL_SECS: u32 = 10;
#[allow(dead_code)]
pub const TCP_KEEPALIVE_PROBE_COUNT: u32 = 3;
#[allow(dead_code)]
pub const TCP_CONNECT_SO_MARK_DEFAULT: u32 = 0x235; // 565

pub trait SetListenerSockOpts {
    fn set_listener_common_sock_opts(&self) -> Result<()>;

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_listener_tproxy_sock_opts(&self) -> Result<()>;

    async fn accept_with_common_sock_opts(
        &self,
    ) -> std::io::Result<(TcpStream, std::net::SocketAddr)>;
}

impl SetListenerSockOpts for tokio::net::TcpListener {
    fn set_listener_common_sock_opts(&self) -> Result<()> {
        set_tcp_common_sock_opts(self)
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_listener_tproxy_sock_opts(&self) -> Result<()> {
        let fd = self.as_fd();
        setsockopt(&fd, nix::sys::socket::sockopt::IpTransparent, &true)?;

        Ok(())
    }

    async fn accept_with_common_sock_opts(
        &self,
    ) -> std::io::Result<(TcpStream, std::net::SocketAddr)> {
        self.accept().await.and_then(|(conn, addr)| {
            // Disable Nagle algorithm
            conn.set_nodelay(true)?;

            Ok((conn, addr))
        })
    }
}

pub fn set_tcp_common_sock_opts(as_fs: impl AsFd) -> Result<()> {
    let fd = as_fs.as_fd();

    // Enable SO_KEEPALIVE
    if let Err(error) = setsockopt(&fd, nix::sys::socket::sockopt::KeepAlive, &true) {
        tracing::warn!(?error, "set SO_KEEPALIVE failed")
    }
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Err(error) = setsockopt(
        &fd,
        nix::sys::socket::sockopt::TcpKeepIdle,
        &TCP_KEEPALIVE_IDLE_SECS,
    ) {
        tracing::warn!(?error, "set TCP_KEEPIDLE failed")
    };
    if let Err(error) = setsockopt(
        &fd,
        nix::sys::socket::sockopt::TcpKeepInterval,
        &TCP_KEEPALIVE_INTERVAL_SECS,
    ) {
        tracing::warn!(?error, "set TCP_KEEPINTVL failed")
    };
    if let Err(error) = setsockopt(
        &fd,
        nix::sys::socket::sockopt::TcpKeepCount,
        &TCP_KEEPALIVE_PROBE_COUNT,
    ) {
        tracing::warn!(?error, "set TCP_KEEPCNT failed")
    };

    // Note: TCP_USER_TIMEOUT is intentionally NOT set here.
    // Per https://blog.cloudflare.com/when-tcp-sockets-refuse-to-die/, this socket option
    // forces connection teardown when unacked data exceeds the timeout threshold.
    // For a transparent proxy, availability takes priority — a prematurely torn-down
    // connection is far worse than a temporarily stalled one. Let the kernel's keepalive
    // mechanism handle dead connection detection instead.

    Ok(())
}

pub async fn tcp_connect<T>(
    host: T,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[rustfmt::skip]
    so_mark: Option<u32>,
) -> Result<TcpStream>
where
    T: tokio::net::ToSocketAddrs,
{
    let addrs = tokio::net::lookup_host(host)
        .await
        .context("Failed to resolve via dns")?;

    let mut last_result = None;
    for addr in addrs {
        tracing::debug!("Trying to tcp connect to {addr:?}");
        let socket = {
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
                .context("Failed to create socket")?;
            socket
                .set_nonblocking(true)
                .context("Failed to set nonblocking on socket")?;
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            if let Some(so_mark) = so_mark {
                socket.set_mark(so_mark)?; // Prevent from been redirected by iptables
            }

            set_tcp_common_sock_opts(&socket)?;

            tokio::net::TcpSocket::from_std_stream(socket.into())
        };

        let result = socket
            .connect(addr)
            .await
            .map_err(anyhow::Error::from)
            .with_context(|| format!("Failed to connect to {addr:?}"));
        if let Ok(ref stream) = result {
            stream.set_nodelay(true)?;
            last_result = Some(result);
            break;
        }
        last_result = Some(result);
    }

    last_result.unwrap_or_else(|| Err(anyhow!("No address resolved")))
}

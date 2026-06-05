#[allow(dead_code)]
pub const TCP_KEEPALIVE_IDLE_SECS: u32 = 10;
#[allow(dead_code)]
pub const TCP_KEEPALIVE_INTERVAL_SECS: u32 = 10;
#[allow(dead_code)]
pub const TCP_KEEPALIVE_PROBE_COUNT: u32 = 3;
#[allow(dead_code)]
pub const TCP_CONNECT_SO_MARK_DEFAULT: u32 = 0x235; // 565

#[cfg(not(wasm))]
use anyhow::{Context, Result};
#[cfg(not(wasm))]
use tokio::net::TcpStream;

#[cfg(not(wasm))]
pub trait SetListenerSockOpts {
    fn set_listener_common_sock_opts(&self) -> Result<()>;

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_listener_tproxy_sock_opts(&self) -> Result<()>;

    async fn accept_with_common_sock_opts(
        &self,
    ) -> std::io::Result<(TcpStream, std::net::SocketAddr)>;
}

#[cfg(not(wasm))]
impl SetListenerSockOpts for tokio::net::TcpListener {
    #[cfg(unix)]
    fn set_listener_common_sock_opts(&self) -> Result<()> {
        set_tcp_common_sock_opts(self)
    }

    #[cfg(windows)]
    fn set_listener_common_sock_opts(&self) -> Result<()> {
        use std::os::windows::io::{AsRawSocket, FromRawSocket};

        let raw_socket = self.as_raw_socket();
        let socket = unsafe { socket2::Socket::from_raw_socket(raw_socket) };
        let _ = socket.set_keepalive(true).map_err(|e| {
            tracing::warn!(error = ?e, "set SO_KEEPALIVE failed");
            e
        });
        std::mem::forget(socket);

        Ok(())
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_listener_tproxy_sock_opts(&self) -> Result<()> {
        use std::os::fd::AsFd;

        let fd = self.as_fd();
        nix::sys::socket::setsockopt(&fd, nix::sys::socket::sockopt::IpTransparent, &true)?;

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

#[cfg(unix)]
pub fn set_tcp_common_sock_opts(as_fs: impl std::os::fd::AsFd) -> Result<()> {
    let fd = as_fs.as_fd();

    // Enable SO_KEEPALIVE
    if let Err(error) =
        nix::sys::socket::setsockopt(&fd, nix::sys::socket::sockopt::KeepAlive, &true)
    {
        tracing::warn!(?error, "set SO_KEEPALIVE failed")
    }
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Err(error) = nix::sys::socket::setsockopt(
        &fd,
        nix::sys::socket::sockopt::TcpKeepIdle,
        &TCP_KEEPALIVE_IDLE_SECS,
    ) {
        tracing::warn!(?error, "set TCP_KEEPIDLE failed")
    };
    if let Err(error) = nix::sys::socket::setsockopt(
        &fd,
        nix::sys::socket::sockopt::TcpKeepInterval,
        &TCP_KEEPALIVE_INTERVAL_SECS,
    ) {
        tracing::warn!(?error, "set TCP_KEEPINTVL failed")
    };
    if let Err(error) = nix::sys::socket::setsockopt(
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

#[cfg(windows)]
pub fn set_tcp_common_sock_opts(socket: &socket2::Socket) -> Result<()> {
    socket.set_keepalive(true).unwrap_or_else(|e| {
        tracing::warn!(error = ?e, "set SO_KEEPALIVE failed");
    });

    // Note: detailed keepalive params (idle/interval/count) are not set on Windows
    // to avoid platform-specific socket option dependencies.

    Ok(())
}

#[cfg(not(wasm))]
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

    last_result.unwrap_or_else(|| Err(anyhow::anyhow!("No address resolved")))
}

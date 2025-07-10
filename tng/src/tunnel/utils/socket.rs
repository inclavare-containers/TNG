use std::os::fd::AsFd;

use anyhow::{anyhow, Context, Result};
use nix::sys::socket::setsockopt;
use tokio::net::TcpStream;

#[allow(dead_code)]
pub const TCP_CONNECT_SO_MARK_DEFAULT: u32 = 0x235; // 565

pub trait SetListenerSockOpts {
    fn set_listener_common_sock_opts(&self) -> Result<()>;

    #[cfg(not(target_os = "macos"))]
    fn set_listener_tproxy_sock_opts(&self) -> Result<()>;
}

impl SetListenerSockOpts for tokio::net::TcpListener {
    fn set_listener_common_sock_opts(&self) -> Result<()> {
        let fd = self.as_fd();
        setsockopt(&fd, nix::sys::socket::sockopt::KeepAlive, &true)?;
        #[cfg(not(target_os = "macos"))]
        setsockopt(&fd, nix::sys::socket::sockopt::TcpKeepIdle, &30)?;
        setsockopt(&fd, nix::sys::socket::sockopt::TcpKeepInterval, &10)?;
        setsockopt(&fd, nix::sys::socket::sockopt::TcpKeepCount, &5)?;

        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn set_listener_tproxy_sock_opts(&self) -> Result<()> {
        let fd = self.as_fd();
        setsockopt(&fd, nix::sys::socket::sockopt::IpTransparent, &true)?;

        Ok(())
    }
}

pub async fn tcp_connect_with_so_mark<T>(host: T, so_mark: Option<u32>) -> Result<TcpStream>
where
    T: tokio::net::ToSocketAddrs,
{
    let addrs = tokio::net::lookup_host(host)
        .await
        .context("Failed to resolve via dns")?;

    let mut last_result = None;
    for addr in addrs {
        tracing::debug!("Trying to tcp connect to {addr:?}");
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
            .context("Failed to create socket")?;
        socket
            .set_nonblocking(true)
            .context("Failed to set nonblocking on socket")?;
        #[cfg(target_os = "macos")]
        let _ = so_mark;
        #[cfg(not(target_os = "macos"))]
        {
            if let Some(so_mark) = so_mark {
                socket.set_mark(so_mark)?; // Prevent from been redirected by iptables
            }
        }
        let socket = tokio::net::TcpSocket::from_std_stream(socket.into());

        let result = socket
            .connect(addr)
            .await
            .map_err(anyhow::Error::from)
            .with_context(|| format!("Failed to connect to {addr:?}"));
        if result.is_ok() {
            last_result = Some(result);
            break;
        }
        last_result = Some(result);
    }

    last_result.unwrap_or_else(|| Err(anyhow!("No address resolved")))
}

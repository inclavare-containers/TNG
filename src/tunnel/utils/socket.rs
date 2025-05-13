use std::os::fd::AsFd;

use anyhow::{anyhow, Result};
use nix::sys::socket::setsockopt;
use tokio::net::TcpStream;

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

pub async fn tcp_connect_with_so_mark<T>(host: T, so_mark: u32) -> Result<TcpStream>
where
    T: tokio::net::ToSocketAddrs,
{
    let addrs = tokio::net::lookup_host(host).await?;

    let mut last_result = None;
    for addr in addrs {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        #[cfg(not(target_os = "macos"))]
        {
            let _ = so_mark;
            socket.set_mark(so_mark)?; // Prevent from been redirected by iptables
        }
        let socket = tokio::net::TcpSocket::from_std_stream(socket.into());

        let result = socket.connect(addr).await.map_err(anyhow::Error::from);
        if result.is_ok() {
            last_result = Some(result);
            break;
        }
        last_result = Some(result);
    }

    last_result.unwrap_or_else(|| Err(anyhow!("No address resolved")))
}

use std::os::fd::AsFd;

use anyhow::Result;
use nix::sys::socket::setsockopt;

pub const TCP_CONNECT_SO_MARK_DEFAULT: u32 = 0x235; // 565

pub trait SetListenerSockOpts {
    fn set_listener_common_sock_opts(&self) -> Result<()>;

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

    fn set_listener_tproxy_sock_opts(&self) -> Result<()> {
        let fd = self.as_fd();
        #[cfg(not(target_os = "macos"))]
        setsockopt(&fd, nix::sys::socket::sockopt::IpTransparent, &true)?;

        Ok(())
    }
}

use std::os::fd::AsFd;

use anyhow::Result;
use nix::sys::socket::setsockopt;

pub trait SetListenerCommonSockOpts {
    fn set_listener_common_sock_opts(&self) -> Result<()>;
}

impl SetListenerCommonSockOpts for tokio::net::TcpListener {
    fn set_listener_common_sock_opts(&self) -> Result<()> {
        let fd = self.as_fd();
        setsockopt(&fd, nix::sys::socket::sockopt::KeepAlive, &true)?;
        #[cfg(not(target_os = "macos"))]
        setsockopt(&fd, nix::sys::socket::sockopt::TcpKeepIdle, &30)?;
        setsockopt(&fd, nix::sys::socket::sockopt::TcpKeepInterval, &10)?;
        setsockopt(&fd, nix::sys::socket::sockopt::TcpKeepCount, &5)?;

        Ok(())
    }
}

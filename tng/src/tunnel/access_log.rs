use std::fmt::Display;
use std::net::SocketAddr;

// --- Mode enums (kept as-is, re-exported alongside new structs) ---

/// The type of ingress that accepted the downstream connection.
#[derive(Debug, Clone, Copy)]
pub enum IngressMode {
    Mapping,
    #[cfg(all(feature = "ingress-netfilter", target_os = "linux"))]
    Netfilter,
    Socks5,
    HttpProxy,
}

impl Display for IngressMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngressMode::Mapping => write!(f, "mapping"),
            #[cfg(all(feature = "ingress-netfilter", target_os = "linux"))]
            IngressMode::Netfilter => write!(f, "netfilter"),
            IngressMode::Socks5 => write!(f, "socks5"),
            IngressMode::HttpProxy => write!(f, "http_proxy"),
        }
    }
}

/// The type of egress that accepted the downstream connection.
#[derive(Debug, Clone, Copy)]
pub enum EgressMode {
    Mapping,
    #[cfg(all(feature = "egress-netfilter", target_os = "linux"))]
    Netfilter,
    Hook,
}

impl Display for EgressMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EgressMode::Mapping => write!(f, "mapping"),
            #[cfg(all(feature = "egress-netfilter", target_os = "linux"))]
            EgressMode::Netfilter => write!(f, "netfilter"),
            EgressMode::Hook => write!(f, "hook"),
        }
    }
}

// --- Unified mode wrapper for Display purposes ---

#[derive(Clone, Copy)]
enum AccessMode {
    Ingress(IngressMode),
    Egress(EgressMode),
}

impl Display for AccessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessMode::Ingress(m) => write!(f, "{m}"),
            AccessMode::Egress(m) => write!(f, "{m}"),
        }
    }
}

// --- State 1: AccessAccepted ---

/// Downstream connection accepted, but routing to upstream not yet determined.
/// Drop logs at ERROR level.
pub struct AccessAccepted {
    downstream_remote: SocketAddr,
    downstream_local: SocketAddr,
    mode: AccessMode,
}

impl AccessAccepted {
    pub fn new_ingress(
        downstream_remote: SocketAddr,
        downstream_local: SocketAddr,
        mode: IngressMode,
    ) -> Self {
        Self {
            downstream_remote,
            downstream_local,
            mode: AccessMode::Ingress(mode),
        }
    }

    pub fn new_egress(
        downstream_remote: SocketAddr,
        downstream_local: SocketAddr,
        mode: EgressMode,
    ) -> Self {
        Self {
            downstream_remote,
            downstream_local,
            mode: AccessMode::Egress(mode),
        }
    }

    /// Returns the downstream remote address for recreating AccessAccepted
    /// in egress flow's inner loop.
    pub fn downstream_remote_addr(&self) -> SocketAddr {
        self.downstream_remote
    }

    /// Returns the downstream local address for recreating AccessAccepted
    /// in egress flow's inner loop.
    pub fn downstream_local_addr(&self) -> SocketAddr {
        self.downstream_local
    }

    /// Returns the egress mode, or None if this is an ingress AccessAccepted.
    pub fn egress_mode(&self) -> Option<EgressMode> {
        match self.mode {
            AccessMode::Egress(m) => Some(m),
            AccessMode::Ingress(_) => None,
        }
    }

    /// Transition to AccessRouted. Consumes self.
    pub fn into_routed(self, upstream_remote: impl Display, tunnel: bool) -> AccessRouted {
        AccessRouted {
            downstream_remote: self.downstream_remote,
            downstream_local: self.downstream_local,
            mode: self.mode,
            upstream_remote: upstream_remote.to_string(),
            tunnel,
        }
    }
}

impl Display for AccessAccepted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "downstream_remote={} -> downstream_local={}({}) — accepted only",
            self.downstream_remote, self.downstream_local, self.mode
        )
    }
}

impl Drop for AccessAccepted {
    fn drop(&mut self) {
        tracing::error!("{}", self);
    }
}

// --- State 2: AccessRouted ---

/// Upstream target determined, but TCP connection not yet established.
/// Drop logs at ERROR level.
#[allow(dead_code)]
pub struct AccessRouted {
    downstream_remote: SocketAddr,
    downstream_local: SocketAddr,
    mode: AccessMode,
    upstream_remote: String,
    tunnel: bool,
}

#[allow(dead_code)]
impl AccessRouted {
    /// Transition to AccessEstablished. Consumes self.
    pub fn into_established(
        self,
        upstream_local: Option<SocketAddr>,
        attested: bool,
    ) -> AccessEstablished {
        AccessEstablished {
            downstream_remote: self.downstream_remote,
            downstream_local: self.downstream_local,
            mode: self.mode,
            upstream_remote: self.upstream_remote.clone(),
            upstream_local,
            tunnel: self.tunnel,
            attested,
        }
    }
}

impl Display for AccessRouted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "downstream_remote={} -> downstream_local={}({}) -> upstream_remote={} — not connected tunnel={}",
            self.downstream_remote, self.downstream_local, self.mode, self.upstream_remote, self.tunnel
        )
    }
}

impl Drop for AccessRouted {
    fn drop(&mut self) {
        tracing::error!("{}", self);
    }
}

// --- State 3: AccessEstablished ---

/// Upstream TCP connected, ready to forward.
/// Drop logs at INFO level.
pub struct AccessEstablished {
    downstream_remote: SocketAddr,
    downstream_local: SocketAddr,
    mode: AccessMode,
    upstream_remote: String,
    upstream_local: Option<SocketAddr>,
    tunnel: bool,
    attested: bool,
}

impl AccessEstablished {}

impl Display for AccessEstablished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "downstream_remote={} -> downstream_local={}({}) -> upstream_remote={}",
            self.downstream_remote, self.downstream_local, self.mode, self.upstream_remote
        )?;
        if let Some(local) = self.upstream_local {
            write!(f, " -> upstream_local={}", local)?;
        }
        write!(f, " — tunnel={}", self.tunnel)?;
        // Only print attested if tunnel is true (meaningful only with tunnel)
        // Actually per spec, always print attested in established state
        write!(f, " attested={}", self.attested)?;
        Ok(())
    }
}

impl Drop for AccessEstablished {
    fn drop(&mut self) {
        tracing::info!("{}", self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_accepted_display() {
        let accepted = AccessAccepted::new_egress(
            "10.0.0.1:54321".parse().unwrap(),
            "0.0.0.0:8080".parse().unwrap(),
            EgressMode::Hook,
        );
        assert_eq!(
            format!("{accepted}"),
            "downstream_remote=10.0.0.1:54321 -> downstream_local=0.0.0.0:8080(hook) — accepted only"
        );
        std::mem::forget(accepted); // suppress Drop log in test
    }

    #[test]
    fn test_access_routed_display() {
        let accepted = AccessAccepted::new_egress(
            "10.0.0.1:54321".parse().unwrap(),
            "0.0.0.0:8080".parse().unwrap(),
            EgressMode::Hook,
        );
        let routed = accepted.into_routed("10.0.0.2:443", false);
        assert_eq!(
            format!("{routed}"),
            "downstream_remote=10.0.0.1:54321 -> downstream_local=0.0.0.0:8080(hook) -> upstream_remote=10.0.0.2:443 — not connected tunnel=false"
        );
        std::mem::forget(routed);
    }

    #[test]
    fn test_access_established_display_no_local() {
        let accepted = AccessAccepted::new_egress(
            "10.0.0.1:54321".parse().unwrap(),
            "0.0.0.0:8080".parse().unwrap(),
            EgressMode::Hook,
        );
        let routed = accepted.into_routed("10.0.0.2:443", false);
        let established = routed.into_established(None, false);
        assert_eq!(
            format!("{established}"),
            "downstream_remote=10.0.0.1:54321 -> downstream_local=0.0.0.0:8080(hook) -> upstream_remote=10.0.0.2:443 — tunnel=false attested=false"
        );
        std::mem::forget(established);
    }

    #[test]
    fn test_access_established_display_with_local() {
        let accepted = AccessAccepted::new_ingress(
            "10.0.0.1:54321".parse().unwrap(),
            "0.0.0.0:8080".parse().unwrap(),
            IngressMode::Mapping,
        );
        let routed = accepted.into_routed("10.0.0.2:443", true);
        let established = routed.into_established(Some("10.0.0.1:54322".parse().unwrap()), true);
        assert_eq!(
            format!("{established}"),
            "downstream_remote=10.0.0.1:54321 -> downstream_local=0.0.0.0:8080(mapping) -> upstream_remote=10.0.0.2:443 -> upstream_local=10.0.0.1:54322 — tunnel=true attested=true"
        );
        std::mem::forget(established);
    }

    #[test]
    fn test_ingress_mode_display() {
        assert_eq!(format!("{}", IngressMode::Mapping), "mapping");
        assert_eq!(format!("{}", IngressMode::Socks5), "socks5");
        assert_eq!(format!("{}", IngressMode::HttpProxy), "http_proxy");
    }

    #[test]
    fn test_egress_mode_display() {
        assert_eq!(format!("{}", EgressMode::Mapping), "mapping");
        assert_eq!(format!("{}", EgressMode::Hook), "hook");
    }
}

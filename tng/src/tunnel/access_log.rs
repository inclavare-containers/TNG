use std::fmt::Display;
use std::net::SocketAddr;

use crate::tunnel::connection_fault::ConnectionFault;

/// The type of ingress that accepted the downstream connection.
#[derive(Debug, Clone, Copy)]
pub enum IngressAccessMode {
    Mapping,
    Netfilter,
    Socks5,
    HttpProxy,
    Hook,
    MappingUdp,
    NetfilterUdp,
}

impl Display for IngressAccessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngressAccessMode::Mapping => write!(f, "mapping"),
            IngressAccessMode::Netfilter => write!(f, "netfilter"),
            IngressAccessMode::Socks5 => write!(f, "socks5"),
            IngressAccessMode::HttpProxy => write!(f, "http_proxy"),
            IngressAccessMode::Hook => write!(f, "hook"),
            IngressAccessMode::MappingUdp => write!(f, "mapping_udp"),
            IngressAccessMode::NetfilterUdp => write!(f, "netfilter_udp"),
        }
    }
}

/// The type of egress that accepted the downstream connection.
#[derive(Debug, Clone, Copy)]
pub enum EgressAccessMode {
    Mapping,
    Netfilter,
    Hook,
    MappingUdp,
    NetfilterUdp,
}

impl Display for EgressAccessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EgressAccessMode::Mapping => write!(f, "mapping"),
            EgressAccessMode::Netfilter => write!(f, "netfilter"),
            EgressAccessMode::Hook => write!(f, "hook"),
            EgressAccessMode::MappingUdp => write!(f, "mapping_udp"),
            EgressAccessMode::NetfilterUdp => write!(f, "netfilter_udp"),
        }
    }
}

// --- Unified mode wrapper for Display purposes ---

#[derive(Clone, Copy)]
#[cfg_attr(wasm, allow(dead_code))]
enum AccessMode {
    Ingress(IngressAccessMode),
    Egress(EgressAccessMode),
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

/// Downstream connection accepted, routing to an upstream not yet determined.
///
/// Dropping this state emits the connection's access-log line, always one line
/// per connection. The level depends on how the connection ended:
///
/// - ERROR when it became a session but never dialled any backend. That is the
///   anomaly this state exists to surface.
/// - DEBUG when the protocol handshake with the downstream never completed
///   because the peer went away or stayed silent. That connection never became
///   a session: a health-check probe or an aborted client, a per-connection
///   event rather than a tunnel fault.
///
/// `need_print` is cleared on every transition and on each multiplexed clone,
/// so only the handle that owns the end of this state logs.
#[cfg_attr(wasm, allow(dead_code))]
pub struct AccessAccepted {
    downstream_remote: SocketAddr,
    downstream_local: SocketAddr,
    mode: AccessMode,
    need_print: bool,
    /// Set by the egress flow when a classified downstream setup failure ended
    /// this connection before the protocol handshake completed. `None` keeps
    /// the default ERROR level.
    fault: Option<ConnectionFault>,
}

#[cfg_attr(wasm, allow(dead_code))]
impl AccessAccepted {
    pub fn new_ingress(
        downstream_remote: SocketAddr,
        downstream_local: SocketAddr,
        mode: IngressAccessMode,
    ) -> Self {
        Self {
            downstream_remote,
            downstream_local,
            mode: AccessMode::Ingress(mode),
            need_print: true,
            fault: None,
        }
    }

    pub fn new_egress(
        downstream_remote: SocketAddr,
        downstream_local: SocketAddr,
        mode: EgressAccessMode,
    ) -> Self {
        Self {
            downstream_remote,
            downstream_local,
            mode: AccessMode::Egress(mode),
            need_print: true,
            fault: None,
        }
    }

    /// Transition to AccessRouted. Consumes self.
    pub fn into_routed(mut self, upstream_remote: impl Display, encrypted: bool) -> AccessRouted {
        self.need_print = false;
        AccessRouted {
            downstream_remote: self.downstream_remote,
            downstream_local: self.downstream_local,
            mode: self.mode,
            upstream_remote: upstream_remote.to_string(),
            encrypted,
            need_print: true,
        }
    }

    pub fn clone_for_multiplexing(&mut self) -> Self {
        self.need_print = false;
        Self {
            downstream_remote: self.downstream_remote,
            downstream_local: self.downstream_local,
            mode: self.mode,
            need_print: true,
            fault: None,
        }
    }

    /// Record the failure that ended the connection before it became a TNG
    /// session. Only the level of this state's drop line follows it; the line
    /// itself is always emitted.
    pub fn record_fault(&mut self, fault: ConnectionFault) {
        self.fault = Some(fault);
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
        if !self.need_print {
            return;
        }
        if self
            .fault
            .is_some_and(ConnectionFault::ended_without_verdict)
        {
            tracing::debug!("{}", self);
        } else {
            tracing::error!("{}", self);
        }
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
    encrypted: bool,
    need_print: bool,
}

#[allow(dead_code)]
impl AccessRouted {
    /// Transition to AccessEstablished. Consumes self.
    pub fn into_established(
        mut self,
        upstream_local: Option<SocketAddr>,
        attested: bool,
    ) -> AccessEstablished {
        self.need_print = false;
        AccessEstablished {
            downstream_remote: self.downstream_remote,
            downstream_local: self.downstream_local,
            mode: self.mode,
            upstream_remote: self.upstream_remote.clone(),
            upstream_local,
            encrypted: self.encrypted,
            attested,
            need_print: true,
        }
    }
}

impl Display for AccessRouted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "downstream_remote={} -> downstream_local={}({}) -> (..) -> upstream_remote={} — not connected encrypted={}",
            self.downstream_remote, self.downstream_local, self.mode, self.upstream_remote, self.encrypted
        )
    }
}

impl Drop for AccessRouted {
    fn drop(&mut self) {
        if self.need_print {
            tracing::error!("{}", self);
        }
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
    encrypted: bool,
    attested: bool,
    need_print: bool,
}

impl AccessEstablished {}

impl Display for AccessEstablished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "downstream_remote={} -> downstream_local={}({})",
            self.downstream_remote, self.downstream_local, self.mode
        )?;
        if let Some(local) = self.upstream_local {
            write!(f, " -> upstream_local={}", local)?;
        }
        write!(f, " -> upstream_remote={}", self.upstream_remote)?;
        write!(f, " — encrypted={}", self.encrypted)?;
        // Only print attested if encrypted is true (meaningful only with tunnel)
        // Actually per spec, always print attested in established state
        write!(f, " attested={}", self.attested)?;
        Ok(())
    }
}

impl Drop for AccessEstablished {
    fn drop(&mut self) {
        if self.need_print {
            tracing::info!("{}", self);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn test_access_accepted_display() {
        let accepted = AccessAccepted::new_egress(
            "10.0.0.1:54321".parse().unwrap(),
            "0.0.0.0:8080".parse().unwrap(),
            EgressAccessMode::Hook,
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
            EgressAccessMode::Hook,
        );
        let routed = accepted.into_routed("10.0.0.2:443", false);
        assert_eq!(
            format!("{routed}"),
            "downstream_remote=10.0.0.1:54321 -> downstream_local=0.0.0.0:8080(hook) -> (..) -> upstream_remote=10.0.0.2:443 — not connected encrypted=false"
        );
        std::mem::forget(routed);
    }

    #[test]
    fn test_access_established_display_no_local() {
        let accepted = AccessAccepted::new_egress(
            "10.0.0.1:54321".parse().unwrap(),
            "0.0.0.0:8080".parse().unwrap(),
            EgressAccessMode::Hook,
        );
        let routed = accepted.into_routed("10.0.0.2:443", false);
        let established = routed.into_established(None, false);
        assert_eq!(
            format!("{established}"),
            "downstream_remote=10.0.0.1:54321 -> downstream_local=0.0.0.0:8080(hook) -> upstream_remote=10.0.0.2:443 — encrypted=false attested=false"
        );
        std::mem::forget(established);
    }

    #[test]
    fn test_access_established_display_with_local() {
        let accepted = AccessAccepted::new_ingress(
            "10.0.0.1:54321".parse().unwrap(),
            "0.0.0.0:8080".parse().unwrap(),
            IngressAccessMode::Mapping,
        );
        let routed = accepted.into_routed("10.0.0.2:443", true);
        let established = routed.into_established(Some("10.0.0.1:54322".parse().unwrap()), true);
        assert_eq!(
            format!("{established}"),
            "downstream_remote=10.0.0.1:54321 -> downstream_local=0.0.0.0:8080(mapping) -> upstream_local=10.0.0.1:54322 -> upstream_remote=10.0.0.2:443 — encrypted=true attested=true"
        );
        std::mem::forget(established);
    }

    #[test]
    fn test_ingress_mode_display() {
        assert_eq!(format!("{}", IngressAccessMode::Mapping), "mapping");
        assert_eq!(format!("{}", IngressAccessMode::Socks5), "socks5");
        assert_eq!(format!("{}", IngressAccessMode::HttpProxy), "http_proxy");
    }

    #[test]
    fn test_egress_mode_display() {
        assert_eq!(format!("{}", EgressAccessMode::Mapping), "mapping");
        assert_eq!(format!("{}", EgressAccessMode::Hook), "hook");
    }

    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Drop `accepted` under a private subscriber and return the formatted
    /// access-log line. A thread-local default keeps the crate's global test
    /// subscriber out of the way.
    fn captured_drop(accepted: AccessAccepted) -> String {
        let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(CaptureWriter(buffer.clone()))
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        tracing::subscriber::with_default(subscriber, || drop(accepted));
        let guard = buffer.lock().unwrap();
        String::from_utf8(guard.clone()).unwrap()
    }

    fn accepted() -> AccessAccepted {
        AccessAccepted::new_egress(
            "10.0.0.1:54321".parse().unwrap(),
            "0.0.0.0:8080".parse().unwrap(),
            EgressAccessMode::Mapping,
        )
    }

    #[test]
    fn peer_vanished_drops_at_debug() {
        let mut accepted = accepted();
        accepted.record_fault(ConnectionFault::PeerVanished);
        let line = captured_drop(accepted);
        assert!(line.contains("DEBUG"), "expected a DEBUG line, got: {line}");
        assert!(line.contains("accepted only"), "unexpected line: {line}");
    }

    #[test]
    fn silent_peer_drops_at_debug() {
        let mut accepted = accepted();
        accepted.record_fault(ConnectionFault::SilentPeer);
        let line = captured_drop(accepted);
        assert!(line.contains("DEBUG"), "expected a DEBUG line, got: {line}");
    }

    #[test]
    fn protocol_violation_stays_error() {
        let mut accepted = accepted();
        accepted.record_fault(ConnectionFault::ProtocolViolation);
        let line = captured_drop(accepted);
        assert!(
            line.contains("ERROR"),
            "expected an ERROR line, got: {line}"
        );
    }

    #[test]
    fn unrecorded_fault_stays_error() {
        let line = captured_drop(accepted());
        assert!(
            line.contains("ERROR"),
            "expected an ERROR line, got: {line}"
        );
    }

    #[test]
    fn transitioned_state_does_not_log() {
        let mut accepted = accepted();
        let _clone = accepted.clone_for_multiplexing();
        let line = captured_drop(accepted);
        assert!(line.is_empty(), "expected no line, got: {line}");
    }
}

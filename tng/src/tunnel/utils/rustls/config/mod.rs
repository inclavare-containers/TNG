pub mod alpn;
pub mod client;
#[cfg(not(wasm))]
pub mod server;

use std::sync::Arc;

use crate::tunnel::ra_context::{RaContext, VerifyContext};
#[cfg(unix)]
use crate::tunnel::utils::cert_manager::CertManager;
use crate::tunnel::utils::runtime::TokioRuntime;
use anyhow::Result;

/// The RA mode that selects the verifier/cert-resolver used for a handshake.
/// Kept separate from the shared session stores so the stores can be cloned
/// into every per-handshake config regardless of mode.
pub enum TlsConfigGeneratorMode {
    NoRa,
    Verify(Arc<VerifyContext>),
    #[cfg(unix)]
    Attest(Arc<CertManager>),
    #[cfg(unix)]
    AttestAndVerify(Arc<CertManager>, Arc<VerifyContext>),
}

/// Long-lived, shared TLS config source for one security layer. Built once per
/// `RatsTlsSecurityLayer` and `Arc`-cloned per handshake. The session stores and
/// the cert verifiers/resolvers are all shared across handshakes: rustls gates
/// TLS 1.3 client resumption on `Weak::ptr_eq` of BOTH the `ServerCertVerifier`
/// and the `ResolvesClientCert`, so the verifier/resolver Arcs built here must be
/// the same instance on every handshake or resumption (and 0-RTT) stays inert.
pub struct TlsConfigGenerator {
    pub mode: TlsConfigGeneratorMode,
    /// Shared client session store (resumption tickets). One per generator so
    /// a ticket obtained on connection N is reusable on connection N+1.
    #[cfg(not(wasm))]
    pub client_session_store: Arc<rustls::client::ClientSessionMemoryCache>,
    /// Shared server session store (resumption secrets keyed by ticket id).
    /// Must be the same instance across handshakes: connection A stores the
    /// secret, connection B looks it up to accept 0-RTT.
    #[cfg(not(wasm))]
    pub server_session_store: Arc<rustls::server::ServerSessionMemoryCache>,
    /// Shared client-facing server-cert verifier (set via `set_certificate_verifier`).
    /// Built once per generator so it is ptr-stable across handshakes; rustls
    /// requires this for TLS 1.3 client resumption. `DummyServerCertVerifier`
    /// for NoRa/Attest, `LazyServerCertVerifier` for Verify/AttestAndVerify.
    #[cfg(not(wasm))]
    pub client_server_cert_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    /// Shared client cert resolver (set via `with_client_cert_resolver`). Built
    /// once per generator for the same ptr-stability reason as the verifier.
    /// `NoClientCertResolver` for NoRa/Verify, `DynamicCertResolver` for
    /// Attest/AttestAndVerify. Using `with_no_client_auth()` instead would build
    /// a fresh `FailResolveClientCert` per handshake and block resumption.
    #[cfg(not(wasm))]
    pub client_cert_resolver: Arc<dyn rustls::client::ResolvesClientCert>,
    /// Handle to the stateless lazy server verifier, for post-handshake verify
    /// (client path). `Some` only in Verify/AttestAndVerify; the same allocation
    /// as `client_server_cert_verifier` so the verdict cache is shared.
    #[cfg(not(wasm))]
    pub client_lazy_server_verifier:
        Option<Arc<crate::tunnel::utils::rustls::ra::server_cert_verifier::LazyServerCertVerifier>>,
    /// Shared server-facing client-cert verifier. `NoClientAuth` for NoRa/Attest,
    /// `LazyClientCertVerifier` for Verify/AttestAndVerify. The server side does
    /// not ptr-check the verifier for resumption, but sharing keeps the verdict
    /// cache uniform across connections.
    #[cfg(not(wasm))]
    pub server_client_cert_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    /// Handle to the stateless lazy client verifier, for post-handshake verify
    /// (server path). `Some` only in Verify/AttestAndVerify.
    #[cfg(not(wasm))]
    pub server_lazy_client_verifier:
        Option<Arc<crate::tunnel::utils::rustls::ra::client_cert_verifier::LazyClientCertVerifier>>,
}

impl TlsConfigGenerator {
    #[allow(unused_variables)]
    pub async fn new(ra_context: Arc<RaContext>, runtime: TokioRuntime) -> Result<Self> {
        let mode = match ra_context.as_ref() {
            #[cfg(unix)]
            RaContext::AttestOnly(attest_ctx) => TlsConfigGeneratorMode::Attest(Arc::new(
                CertManager::new(attest_ctx.clone(), runtime).await?,
            )),
            RaContext::VerifyOnly(verify_ctx) => TlsConfigGeneratorMode::Verify(verify_ctx.clone()),
            #[cfg(unix)]
            RaContext::AttestAndVerify { attest, verify } => {
                TlsConfigGeneratorMode::AttestAndVerify(
                    Arc::new(CertManager::new(attest.clone(), runtime).await?),
                    verify.clone(),
                )
            }
            RaContext::NoRa => TlsConfigGeneratorMode::NoRa,
        };

        // Build the shared verifier/resolver Arcs once (not per handshake) so
        // rustls's resumption ptr-eq check passes across handshakes.
        #[cfg(not(wasm))]
        let (
            client_server_cert_verifier,
            client_cert_resolver,
            client_lazy_server_verifier,
            server_client_cert_verifier,
            server_lazy_client_verifier,
        ) = Self::build_shared_verifiers(&mode).await?;

        Ok(Self {
            mode,
            #[cfg(not(wasm))]
            client_session_store: Arc::new(rustls::client::ClientSessionMemoryCache::new(256)),
            #[cfg(not(wasm))]
            server_session_store: rustls::server::ServerSessionMemoryCache::new(256),
            #[cfg(not(wasm))]
            client_server_cert_verifier,
            #[cfg(not(wasm))]
            client_cert_resolver,
            #[cfg(not(wasm))]
            client_lazy_server_verifier,
            #[cfg(not(wasm))]
            server_client_cert_verifier,
            #[cfg(not(wasm))]
            server_lazy_client_verifier,
        })
    }

    /// Build the per-generator shared verifier/resolver Arcs. Each is cloned into
    /// every per-handshake config from this generator, so the same `Arc` (same
    /// allocation) backs every handshake, satisfying rustls's resumption ptr-eq.
    #[cfg(not(wasm))]
    async fn build_shared_verifiers(
        mode: &TlsConfigGeneratorMode,
    ) -> Result<(
        Arc<dyn rustls::client::danger::ServerCertVerifier>,
        Arc<dyn rustls::client::ResolvesClientCert>,
        Option<Arc<crate::tunnel::utils::rustls::ra::server_cert_verifier::LazyServerCertVerifier>>,
        Arc<dyn rustls::server::danger::ClientCertVerifier>,
        Option<Arc<crate::tunnel::utils::rustls::ra::client_cert_verifier::LazyClientCertVerifier>>,
    )> {
        #[cfg(unix)]
        use crate::tunnel::utils::cert_manager::DynamicCertResolver;
        use crate::tunnel::utils::rustls::{
            dummy::verifier::{DummyServerCertVerifier, NoClientCertResolver},
            ra::client_cert_verifier::LazyClientCertVerifier,
            ra::server_cert_verifier::LazyServerCertVerifier,
        };

        match mode {
            TlsConfigGeneratorMode::NoRa => {
                let client_server_cert_verifier: Arc<
                    dyn rustls::client::danger::ServerCertVerifier,
                > = Arc::new(DummyServerCertVerifier::new()?);
                let client_cert_resolver: Arc<dyn rustls::client::ResolvesClientCert> =
                    Arc::new(NoClientCertResolver);
                let server_client_cert_verifier: Arc<
                    dyn rustls::server::danger::ClientCertVerifier,
                > = Arc::new(rustls::server::NoClientAuth);
                Ok((
                    client_server_cert_verifier,
                    client_cert_resolver,
                    None,
                    server_client_cert_verifier,
                    None,
                ))
            }
            TlsConfigGeneratorMode::Verify(verify_ctx) => {
                let lazy_server = Arc::new(LazyServerCertVerifier::new(verify_ctx.clone())?);
                let client_server_cert_verifier: Arc<
                    dyn rustls::client::danger::ServerCertVerifier,
                > = lazy_server.clone();
                let client_lazy_server_verifier = Some(lazy_server);
                let client_cert_resolver: Arc<dyn rustls::client::ResolvesClientCert> =
                    Arc::new(NoClientCertResolver);
                let lazy_client = Arc::new(LazyClientCertVerifier::new(verify_ctx.clone())?);
                let server_client_cert_verifier: Arc<
                    dyn rustls::server::danger::ClientCertVerifier,
                > = lazy_client.clone();
                let server_lazy_client_verifier = Some(lazy_client);
                Ok((
                    client_server_cert_verifier,
                    client_cert_resolver,
                    client_lazy_server_verifier,
                    server_client_cert_verifier,
                    server_lazy_client_verifier,
                ))
            }
            #[cfg(unix)]
            TlsConfigGeneratorMode::Attest(cert_manager) => {
                let client_server_cert_verifier: Arc<
                    dyn rustls::client::danger::ServerCertVerifier,
                > = Arc::new(DummyServerCertVerifier::new()?);
                let client_cert_resolver: Arc<dyn rustls::client::ResolvesClientCert> =
                    Arc::new(DynamicCertResolver::new(cert_manager.clone()));
                let server_client_cert_verifier: Arc<
                    dyn rustls::server::danger::ClientCertVerifier,
                > = Arc::new(rustls::server::NoClientAuth);
                Ok((
                    client_server_cert_verifier,
                    client_cert_resolver,
                    None,
                    server_client_cert_verifier,
                    None,
                ))
            }
            #[cfg(unix)]
            TlsConfigGeneratorMode::AttestAndVerify(cert_manager, verify_ctx) => {
                let lazy_server = Arc::new(LazyServerCertVerifier::new(verify_ctx.clone())?);
                let client_server_cert_verifier: Arc<
                    dyn rustls::client::danger::ServerCertVerifier,
                > = lazy_server.clone();
                let client_lazy_server_verifier = Some(lazy_server);
                let client_cert_resolver: Arc<dyn rustls::client::ResolvesClientCert> =
                    Arc::new(DynamicCertResolver::new(cert_manager.clone()));
                let lazy_client = Arc::new(LazyClientCertVerifier::new(verify_ctx.clone())?);
                let server_client_cert_verifier: Arc<
                    dyn rustls::server::danger::ClientCertVerifier,
                > = lazy_client.clone();
                let server_lazy_client_verifier = Some(lazy_client);
                Ok((
                    client_server_cert_verifier,
                    client_cert_resolver,
                    client_lazy_server_verifier,
                    server_client_cert_verifier,
                    server_lazy_client_verifier,
                ))
            }
        }
    }
}

#[cfg(all(test, not(wasm)))]
mod resumption_tests {
    use super::alpn::Alpn;
    use super::{TlsConfigGenerator, TlsConfigGeneratorMode};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Prove TLS 1.3 session resumption actually happens with the real
    /// `TlsConfigGenerator` builders: connection 2 to the same server must
    /// resume from a PSK obtained via the NewSessionTicket issued on
    /// connection 1, not perform a full handshake. The shared client/server
    /// session stores injected into both configs are what let the ticket
    /// survive across handshakes.
    ///
    /// Resumption is detected with zero instrumentation: rustls sets
    /// `received_resumption_data` on the server connection only when the
    /// client offered a valid PSK (full handshake leaves it `None`). The
    /// connector is plain (no `.early_data(true)`) so the test isolates PSK
    /// resumption from 0-RTT early data; the configs still carry
    /// `enable_early_data` (the real builder sets it), so the test exercises
    /// the production config shape, but no 0-RTT data is sent and no
    /// `EndOfEarlyData` is emitted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rats_tls_session_resumption() {
        use crate::tunnel::utils::rustls::dummy::verifier::{
            DummyServerCertVerifier, NoClientCertResolver,
        };
        // One generator shared by both connections so the session stores are
        // the same instance. Struct literal bypasses `TlsConfigGenerator::new`
        // (NoRa never uses the TokioRuntime it would build). The shared
        // verifier/resolver Arcs are the point of Fix 6: they must be one Arc
        // across handshakes or rustls refuses resumption. NoRa uses a shared
        // DummyServerCertVerifier + NoClientCertResolver here.
        let client_server_cert_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            Arc::new(DummyServerCertVerifier::new().unwrap());
        let client_cert_resolver: Arc<dyn rustls::client::ResolvesClientCert> =
            Arc::new(NoClientCertResolver);
        let server_client_cert_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
            Arc::new(rustls::server::NoClientAuth);
        let generator = TlsConfigGenerator {
            mode: TlsConfigGeneratorMode::NoRa,
            client_session_store: Arc::new(rustls::client::ClientSessionMemoryCache::new(256)),
            server_session_store: rustls::server::ServerSessionMemoryCache::new(256),
            client_server_cert_verifier,
            client_cert_resolver,
            client_lazy_server_verifier: None,
            server_client_cert_verifier,
            server_lazy_client_verifier: None,
        };

        let server_cfg: Arc<rustls::ServerConfig> = Arc::new(
            generator
                .get_lazy_one_time_rustls_server_config(Alpn::RatsTls)
                .await
                .unwrap()
                .0,
        );
        let client_cfg: Arc<rustls::ClientConfig> = Arc::new(
            generator
                .get_lazy_one_time_rustls_client_config(Alpn::RatsTls)
                .await
                .unwrap()
                .0,
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let name = rustls::pki_types::ServerName::from(std::net::Ipv4Addr::new(127, 0, 0, 1));

        // Server side: accept two connections sequentially. For each, capture
        // the resumption flag then write b"ok" so the client's first read
        // returns app data and, on connection 1, drives the post-handshake
        // NewSessionTicket into the shared client store.
        let server = async {
            let mut resumed = [false; 2];
            for slot in resumed.iter_mut() {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut tls = tokio_rustls::TlsAcceptor::from(server_cfg.clone())
                    .accept(tcp)
                    .await
                    .unwrap();
                // Set while parsing the ClientHello: Some iff the client
                // offered a valid PSK (resumed), None on a full handshake.
                *slot = tls.get_mut().1.received_resumption_data().is_some();
                tls.write_all(b"ok").await.unwrap();
                tls.flush().await.unwrap();
            }
            resumed
        };

        // Client side: two sequential connections to the same address. The
        // first read processes the NewSessionTicket and stores the ticket in
        // the shared client store (keyed by this server name); the second
        // connection offers that PSK so the server resumes.
        let client = async {
            let mut buf = [0u8; 2];
            // Connection 1: full handshake.
            let tcp1 = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut conn1 = tokio_rustls::TlsConnector::from(client_cfg.clone())
                .connect(name.clone(), tcp1)
                .await
                .unwrap();
            let n = conn1.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ok");
            drop(conn1);

            // Connection 2: offers the PSK from the shared store; same server
            // name so the store lookup hits.
            let tcp2 = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut conn2 = tokio_rustls::TlsConnector::from(client_cfg.clone())
                .connect(name, tcp2)
                .await
                .unwrap();
            let n2 = conn2.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n2], b"ok");
            drop(conn2);
        };

        // Run both sides concurrently on this task; tokio::join! polls them
        // cooperatively so the server's accept does not block the client's
        // connect. (tokio::spawn is repo-disallowed outside TokioRuntime.)
        let (resumed, ()) = tokio::join!(server, client);

        assert!(!resumed[0], "connection 1 must be a full handshake");
        assert!(
            resumed[1],
            "connection 2 must resume from the connection-1 ticket"
        );
    }
}

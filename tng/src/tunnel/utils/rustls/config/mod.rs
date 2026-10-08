pub mod alpn;
#[cfg(not(wasm))]
pub mod blocking;
pub mod client;
#[cfg(not(wasm))]
pub mod resolver;
#[cfg(not(wasm))]
pub mod server;

use std::sync::Arc;

use crate::tunnel::ra_context::{RaContext, VerifyContext};
#[cfg(unix)]
use crate::tunnel::utils::cert_manager::CertManager;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::rustls::ra::cert_cache::CertVerifyCache;
use anyhow::Result;

/// The RA mode that selects the verifier/cert-resolver used for a handshake.
/// Kept separate from the shared session stores so the stores can be cloned
/// into every per-handshake config regardless of mode.
pub enum TlsConfigGeneratorMode {
    NoRa,
    Verify(Arc<VerifyContext>, Arc<CertVerifyCache>),
    #[cfg(unix)]
    Attest(Arc<CertManager>),
    #[cfg(unix)]
    AttestAndVerify(Arc<CertManager>, Arc<VerifyContext>, Arc<CertVerifyCache>),
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
    /// `NoClientCertResolver` for NoRa/Verify, `SwappableClientCertResolver`
    /// for Attest/AttestAndVerify. Using `with_no_client_auth()` instead would
    /// build a fresh `FailResolveClientCert` per handshake and block
    /// resumption.
    #[cfg(not(wasm))]
    pub client_cert_resolver: Arc<dyn rustls::client::ResolvesClientCert>,
    /// Concrete handle to the `client_cert_resolver` allocation in
    /// Attest/AttestAndVerify modes (the same `Arc`), used by the lazy client
    /// builder to publish the awaited cert before each handshake. `None` for
    /// NoRa/Verify, which never present a cert.
    #[cfg(unix)]
    pub client_cert_cell: Option<Arc<resolver::SwappableClientCertResolver>>,
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
    /// Shared RFC 8879 cert-compression cache for server configs built from
    /// this generator. One per generator so the brotli LRU survives across
    /// handshakes; a per-handshake rebuild gave each config a fresh empty
    /// cache and forced a quality-11 brotli recompression of the server cert
    /// each time. The cache key is (algorithm, cert-chain encoding), so cert
    /// rotation auto-misses (new encoding) without snapshotting the cert.
    /// The lazy client-cert verifiers are stateless (only shared
    /// `VerifyContext` + `CertVerifyCache` Arcs), so one shared compression
    /// Arc is safe across concurrent handshakes.
    #[cfg(not(wasm))]
    pub server_cert_compression_cache: Arc<rustls::compress::CompressionCache>,
    /// Shared RFC 8879 cert-compression cache for client configs built from
    /// this generator. Same rationale as `server_cert_compression_cache`;
    /// matters for Attest/AttestAndVerify where the client presents a cert.
    #[cfg(not(wasm))]
    pub client_cert_compression_cache: Arc<rustls::compress::CompressionCache>,
}

impl TlsConfigGenerator {
    #[allow(unused_variables)]
    pub async fn new(ra_context: Arc<RaContext>, runtime: TokioRuntime) -> Result<Self> {
        let mode = match ra_context.as_ref() {
            #[cfg(unix)]
            RaContext::AttestOnly(attest_ctx) => TlsConfigGeneratorMode::Attest(Arc::new(
                CertManager::new(attest_ctx.clone(), runtime).await?,
            )),
            RaContext::VerifyOnly(verify_ctx) => TlsConfigGeneratorMode::Verify(
                verify_ctx.clone(),
                Arc::new(CertVerifyCache::default_sized()),
            ),
            #[cfg(unix)]
            RaContext::AttestAndVerify { attest, verify } => {
                TlsConfigGeneratorMode::AttestAndVerify(
                    Arc::new(CertManager::new(attest.clone(), runtime).await?),
                    verify.clone(),
                    Arc::new(CertVerifyCache::default_sized()),
                )
            }
            RaContext::NoRa => TlsConfigGeneratorMode::NoRa,
        };

        // Build the shared verifier/resolver Arcs once (not per handshake) so
        // rustls's resumption ptr-eq check passes across handshakes.
        #[cfg(not(wasm))]
        let shared = Self::build_shared_verifiers(&mode).await?;

        Ok(Self {
            mode,
            #[cfg(not(wasm))]
            client_session_store: Arc::new(rustls::client::ClientSessionMemoryCache::new(256)),
            #[cfg(not(wasm))]
            server_session_store: rustls::server::ServerSessionMemoryCache::new(256),
            #[cfg(not(wasm))]
            client_server_cert_verifier: shared.0,
            #[cfg(not(wasm))]
            client_cert_resolver: shared.1,
            #[cfg(unix)]
            client_cert_cell: shared.2,
            #[cfg(not(wasm))]
            client_lazy_server_verifier: shared.3,
            #[cfg(not(wasm))]
            server_client_cert_verifier: shared.4,
            #[cfg(not(wasm))]
            server_lazy_client_verifier: shared.5,
            #[cfg(not(wasm))]
            server_cert_compression_cache: Arc::new(rustls::compress::CompressionCache::default()),
            #[cfg(not(wasm))]
            client_cert_compression_cache: Arc::new(rustls::compress::CompressionCache::default()),
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
        Option<Arc<resolver::SwappableClientCertResolver>>,
        Option<Arc<crate::tunnel::utils::rustls::ra::server_cert_verifier::LazyServerCertVerifier>>,
        Arc<dyn rustls::server::danger::ClientCertVerifier>,
        Option<Arc<crate::tunnel::utils::rustls::ra::client_cert_verifier::LazyClientCertVerifier>>,
    )> {
        #[cfg(unix)]
        use crate::tunnel::utils::rustls::config::resolver::SwappableClientCertResolver;
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
                    None,
                    server_client_cert_verifier,
                    None,
                ))
            }
            TlsConfigGeneratorMode::Verify(verify_ctx, cache) => {
                let lazy_server = Arc::new(LazyServerCertVerifier::new(
                    verify_ctx.clone(),
                    cache.clone(),
                )?);
                let client_server_cert_verifier: Arc<
                    dyn rustls::client::danger::ServerCertVerifier,
                > = lazy_server.clone();
                let client_lazy_server_verifier = Some(lazy_server);
                let client_cert_resolver: Arc<dyn rustls::client::ResolvesClientCert> =
                    Arc::new(NoClientCertResolver);
                let lazy_client = Arc::new(LazyClientCertVerifier::new(
                    verify_ctx.clone(),
                    cache.clone(),
                )?);
                let server_client_cert_verifier: Arc<
                    dyn rustls::server::danger::ClientCertVerifier,
                > = lazy_client.clone();
                let server_lazy_client_verifier = Some(lazy_client);
                Ok((
                    client_server_cert_verifier,
                    client_cert_resolver,
                    None,
                    client_lazy_server_verifier,
                    server_client_cert_verifier,
                    server_lazy_client_verifier,
                ))
            }
            #[cfg(unix)]
            TlsConfigGeneratorMode::Attest(_) => {
                let client_server_cert_verifier: Arc<
                    dyn rustls::client::danger::ServerCertVerifier,
                > = Arc::new(DummyServerCertVerifier::new()?);
                // The shared lazy-path resolver: one `Arc` for the generator's
                // lifetime (rustls ptr-checks it for client resumption), value
                // swapped per handshake by the lazy client builder. It must be
                // the same allocation as `client_cert_resolver` below.
                let cell = Arc::new(SwappableClientCertResolver::default());
                let client_cert_resolver: Arc<dyn rustls::client::ResolvesClientCert> =
                    cell.clone();
                let server_client_cert_verifier: Arc<
                    dyn rustls::server::danger::ClientCertVerifier,
                > = Arc::new(rustls::server::NoClientAuth);
                Ok((
                    client_server_cert_verifier,
                    client_cert_resolver,
                    Some(cell),
                    None,
                    server_client_cert_verifier,
                    None,
                ))
            }
            #[cfg(unix)]
            TlsConfigGeneratorMode::AttestAndVerify(_, verify_ctx, cache) => {
                let lazy_server = Arc::new(LazyServerCertVerifier::new(
                    verify_ctx.clone(),
                    cache.clone(),
                )?);
                let client_server_cert_verifier: Arc<
                    dyn rustls::client::danger::ServerCertVerifier,
                > = lazy_server.clone();
                let client_lazy_server_verifier = Some(lazy_server);
                let cell = Arc::new(SwappableClientCertResolver::default());
                let client_cert_resolver: Arc<dyn rustls::client::ResolvesClientCert> =
                    cell.clone();
                let lazy_client = Arc::new(LazyClientCertVerifier::new(
                    verify_ctx.clone(),
                    cache.clone(),
                )?);
                let server_client_cert_verifier: Arc<
                    dyn rustls::server::danger::ClientCertVerifier,
                > = lazy_client.clone();
                let server_lazy_client_verifier = Some(lazy_client);
                Ok((
                    client_server_cert_verifier,
                    client_cert_resolver,
                    Some(cell),
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
            #[cfg(unix)]
            client_cert_cell: None,
            client_lazy_server_verifier: None,
            server_client_cert_verifier,
            server_lazy_client_verifier: None,
            server_cert_compression_cache: Arc::new(rustls::compress::CompressionCache::default()),
            client_cert_compression_cache: Arc::new(rustls::compress::CompressionCache::default()),
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

    /// Same resumption contract as `rats_tls_session_resumption`, but with the
    /// real RA verifier types (`LazyServerCertVerifier` +
    /// `LazyClientCertVerifier`) instead of the NoRa dummies. The point is to
    /// prove the stateless lazy verifiers satisfy rustls's `Weak::ptr_eq`
    /// resumption gate exactly as the dummies do: one shared `Arc` across
    /// handshakes on both the client server-cert verifier and the server
    /// client-cert verifier.
    ///
    /// Hermeticity: `LazyServerCertVerifier::new` / `LazyClientCertVerifier::new`
    /// only store the `VerifyContext` and build a webpki verifier off the bundled
    /// dummy cert; they never contact an AS. The `VerifyContext` itself is built
    /// from a `BackgroundCheck` restful config pointing at a dummy AS address
    /// with `skip_as_token_cert_verify = true`, so `TokenVerifier::from_config`
    /// skips all cert loading and network fetches. The test drives raw TLS only
    /// (no `verify_cert` post-handshake call), so no AA/AS is ever contacted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rats_tls_session_resumption_ra_verifier_types() {
        use crate::config::ra::{
            CocoConverterArgs, CocoVerifierArgs, ConverterArgs, VerifierArgs, VerifyArgs,
        };
        use crate::tunnel::ra_context::VerifyContext;
        use crate::tunnel::utils::rustls::ra::client_cert_verifier::LazyClientCertVerifier;
        use crate::tunnel::utils::rustls::ra::server_cert_verifier::LazyServerCertVerifier;
        use std::collections::HashMap;

        // Build a VerifyContext offline. skip_as_token_cert_verify = true makes
        // TokenVerifier::from_config skip cert loading and AS fetches, so the
        // dummy as_addr / absent trusted_certs_paths never cause network or file
        // access. The AS is never contacted anyway (raw TLS, no verify_cert).
        let verify_args = VerifyArgs::BackgroundCheck {
            converter: ConverterArgs::Coco(CocoConverterArgs::Restful {
                as_addr: "http://localhost:1/".to_string(),
                policy_ids: vec!["default".to_string()],
                as_headers: HashMap::new(),
            }),
            verifier: VerifierArgs::Coco(CocoVerifierArgs::Restful {
                as_addr: None,
                policy_ids: vec!["default".to_string()],
                as_headers: HashMap::new(),
                trusted_certs_paths: None,
                verify_signer_transparency: false,
                skip_as_token_cert_verify: true,
            }),
        };
        let verify_ctx = Arc::new(VerifyContext::from_verify_args(&verify_args).await.unwrap());
        let cache = Arc::new(
            crate::tunnel::utils::rustls::ra::cert_cache::CertVerifyCache::default_sized(),
        );

        // One shared lazy server verifier across both handshakes (client side).
        // The same allocation backs client_server_cert_verifier and
        // client_lazy_server_verifier so the verdict cache is shared and rustls
        // sees one ptr for the ServerCertVerifier across handshakes.
        let lazy_server =
            Arc::new(LazyServerCertVerifier::new(verify_ctx.clone(), cache.clone()).unwrap());
        let client_server_cert_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            lazy_server.clone();
        // The server side is wired with `LazyClientCertVerifier` (via
        // `with_client_cert_verifier`), which is mandatory client auth: rustls
        // rejects an empty client cert list with `NoCertificatesPresented` before
        // `verify_client_cert` ever runs. So the client must present a cert.
        // Use the bundled dummy cert as a shared client cert resolver; the
        // server's `verify_client_cert` is a no-op, so no chain/EKU/expiry check
        // runs and only the CertificateVerify signature is checked, which the
        // matching dummy key/cert pair satisfies. One shared Arc across
        // handshakes: rustls ptr-checks the resolver for resumption too.
        let dummy_client_cert =
            crate::tunnel::utils::rustls::dummy::RustlsDummyCert::new_rustls_cert().unwrap();
        let client_cert_resolver: Arc<dyn rustls::client::ResolvesClientCert> =
            dummy_client_cert.clone();
        // One shared lazy client verifier across both handshakes (server side).
        let lazy_client =
            Arc::new(LazyClientCertVerifier::new(verify_ctx.clone(), cache.clone()).unwrap());
        let server_client_cert_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
            lazy_client.clone();
        let generator = TlsConfigGenerator {
            mode: TlsConfigGeneratorMode::Verify(verify_ctx.clone(), cache.clone()),
            client_session_store: Arc::new(rustls::client::ClientSessionMemoryCache::new(256)),
            server_session_store: rustls::server::ServerSessionMemoryCache::new(256),
            client_server_cert_verifier,
            client_cert_resolver,
            #[cfg(unix)]
            client_cert_cell: None,
            client_lazy_server_verifier: Some(lazy_server),
            server_client_cert_verifier,
            server_lazy_client_verifier: Some(lazy_client),
            server_cert_compression_cache: Arc::new(rustls::compress::CompressionCache::default()),
            client_cert_compression_cache: Arc::new(rustls::compress::CompressionCache::default()),
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

        let server = async {
            let mut resumed = [false; 2];
            for slot in resumed.iter_mut() {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut tls = tokio_rustls::TlsAcceptor::from(server_cfg.clone())
                    .accept(tcp)
                    .await
                    .unwrap();
                *slot = tls.get_mut().1.received_resumption_data().is_some();
                tls.write_all(b"ok").await.unwrap();
                tls.flush().await.unwrap();
            }
            resumed
        };

        let client = async {
            let mut buf = [0u8; 2];
            let tcp1 = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut conn1 = tokio_rustls::TlsConnector::from(client_cfg.clone())
                .connect(name.clone(), tcp1)
                .await
                .unwrap();
            let n = conn1.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ok");
            drop(conn1);

            let tcp2 = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut conn2 = tokio_rustls::TlsConnector::from(client_cfg.clone())
                .connect(name, tcp2)
                .await
                .unwrap();
            let n2 = conn2.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n2], b"ok");
            drop(conn2);
        };

        let (resumed, ()) = tokio::join!(server, client);

        assert!(!resumed[0], "connection 1 must be a full handshake");
        assert!(
            resumed[1],
            "connection 2 must resume from the connection-1 ticket"
        );
    }

    /// The brotli cert-compression cache must be shared across handshakes for
    /// the previously-uncached arms (Verify server, Verify client) so rustls's
    /// RFC 8879 LRU survives and a cert is not recompressed every handshake.
    /// Asserts `Arc::ptr_eq` of `cert_compression_cache` across two configs
    /// built from one generator. Uses the Verify-mode generator (the arm the
    /// partial fix left uncached) and its client config.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rats_tls_compression_cache_shared_across_handshakes() {
        use crate::config::ra::{
            CocoConverterArgs, CocoVerifierArgs, ConverterArgs, VerifierArgs, VerifyArgs,
        };
        use crate::tunnel::ra_context::VerifyContext;
        use crate::tunnel::utils::rustls::ra::client_cert_verifier::LazyClientCertVerifier;
        use crate::tunnel::utils::rustls::ra::server_cert_verifier::LazyServerCertVerifier;
        use crate::tunnel::utils::rustls::{
            config::alpn::Alpn, dummy::verifier::NoClientCertResolver,
        };
        use std::collections::HashMap;

        // Hermetic VerifyContext: skip_as_token_cert_verify = true means no
        // AS contact, no cert loading (see the resumption RA test above).
        let verify_args = VerifyArgs::BackgroundCheck {
            converter: ConverterArgs::Coco(CocoConverterArgs::Restful {
                as_addr: "http://localhost:1/".to_string(),
                policy_ids: vec!["default".to_string()],
                as_headers: HashMap::new(),
            }),
            verifier: VerifierArgs::Coco(CocoVerifierArgs::Restful {
                as_addr: None,
                policy_ids: vec!["default".to_string()],
                as_headers: HashMap::new(),
                trusted_certs_paths: None,
                verify_signer_transparency: false,
                skip_as_token_cert_verify: true,
            }),
        };
        let verify_ctx = Arc::new(VerifyContext::from_verify_args(&verify_args).await.unwrap());
        let cache = Arc::new(
            crate::tunnel::utils::rustls::ra::cert_cache::CertVerifyCache::default_sized(),
        );

        let lazy_server =
            Arc::new(LazyServerCertVerifier::new(verify_ctx.clone(), cache.clone()).unwrap());
        let client_server_cert_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            lazy_server.clone();
        let lazy_client =
            Arc::new(LazyClientCertVerifier::new(verify_ctx.clone(), cache.clone()).unwrap());
        let server_client_cert_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
            lazy_client.clone();

        let generator = TlsConfigGenerator {
            mode: TlsConfigGeneratorMode::Verify(verify_ctx.clone(), cache.clone()),
            client_session_store: Arc::new(rustls::client::ClientSessionMemoryCache::new(256)),
            server_session_store: rustls::server::ServerSessionMemoryCache::new(256),
            client_server_cert_verifier,
            client_cert_resolver: Arc::new(NoClientCertResolver),
            #[cfg(unix)]
            client_cert_cell: None,
            client_lazy_server_verifier: Some(lazy_server),
            server_client_cert_verifier,
            server_lazy_client_verifier: Some(lazy_client),
            server_cert_compression_cache: Arc::new(rustls::compress::CompressionCache::default()),
            client_cert_compression_cache: Arc::new(rustls::compress::CompressionCache::default()),
        };

        // Two server configs from the same generator share one cache Arc.
        let server_cfg_1 = generator
            .get_lazy_one_time_rustls_server_config(Alpn::RatsTls)
            .await
            .unwrap()
            .0;
        let server_cfg_2 = generator
            .get_lazy_one_time_rustls_server_config(Alpn::RatsTls)
            .await
            .unwrap()
            .0;
        assert!(
            Arc::ptr_eq(
                &server_cfg_1.cert_compression_cache,
                &server_cfg_2.cert_compression_cache,
            ),
            "server compression cache must be shared across handshakes"
        );

        // Two client configs from the same generator share one cache Arc.
        let client_cfg_1 = generator
            .get_lazy_one_time_rustls_client_config(Alpn::RatsTls)
            .await
            .unwrap()
            .0;
        let client_cfg_2 = generator
            .get_lazy_one_time_rustls_client_config(Alpn::RatsTls)
            .await
            .unwrap()
            .0;
        assert!(
            Arc::ptr_eq(
                &client_cfg_1.cert_compression_cache,
                &client_cfg_2.cert_compression_cache,
            ),
            "client compression cache must be shared across handshakes"
        );

        // Server and client use separate caches (different cert chains).
        assert!(
            !Arc::ptr_eq(
                &server_cfg_1.cert_compression_cache,
                &client_cfg_1.cert_compression_cache,
            ),
            "server and client compression caches must be distinct"
        );
    }

    /// The blocking (QUIC/UDP) builders inject the generator-shared brotli
    /// cache in code separate from the lazy TCP builders, so
    /// `rats_tls_compression_cache_shared_across_handshakes` does not cover
    /// them. Pin `Arc::ptr_eq` on two configs from each blocking builder and
    /// against the generator's own cache fields: a blocking-only refactor that
    /// drops the injection would otherwise silently reintroduce per-handshake
    /// brotli recompression with no test failing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rats_tls_compression_cache_shared_across_handshakes_blocking() {
        use crate::config::ra::{
            CocoConverterArgs, CocoVerifierArgs, ConverterArgs, VerifierArgs, VerifyArgs,
        };
        use crate::tunnel::ra_context::VerifyContext;
        use crate::tunnel::utils::rustls::dummy::verifier::NoClientCertResolver;
        use crate::tunnel::utils::rustls::ra::client_cert_verifier::LazyClientCertVerifier;
        use crate::tunnel::utils::rustls::ra::server_cert_verifier::LazyServerCertVerifier;
        use std::collections::HashMap;

        // Hermetic VerifyContext: skip_as_token_cert_verify = true means no
        // AS contact and no cert loading. The blocking builders only store
        // this context in their verifiers; no handshake is driven here.
        let verify_args = VerifyArgs::BackgroundCheck {
            converter: ConverterArgs::Coco(CocoConverterArgs::Restful {
                as_addr: "http://localhost:1/".to_string(),
                policy_ids: vec!["default".to_string()],
                as_headers: HashMap::new(),
            }),
            verifier: VerifierArgs::Coco(CocoVerifierArgs::Restful {
                as_addr: None,
                policy_ids: vec!["default".to_string()],
                as_headers: HashMap::new(),
                trusted_certs_paths: None,
                verify_signer_transparency: false,
                skip_as_token_cert_verify: true,
            }),
        };
        let verify_ctx = Arc::new(VerifyContext::from_verify_args(&verify_args).await.unwrap());
        let cache = Arc::new(
            crate::tunnel::utils::rustls::ra::cert_cache::CertVerifyCache::default_sized(),
        );

        let lazy_server =
            Arc::new(LazyServerCertVerifier::new(verify_ctx.clone(), cache.clone()).unwrap());
        let client_server_cert_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            lazy_server.clone();
        let lazy_client =
            Arc::new(LazyClientCertVerifier::new(verify_ctx.clone(), cache.clone()).unwrap());
        let server_client_cert_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
            lazy_client.clone();

        let generator = TlsConfigGenerator {
            mode: TlsConfigGeneratorMode::Verify(verify_ctx.clone(), cache.clone()),
            client_session_store: Arc::new(rustls::client::ClientSessionMemoryCache::new(256)),
            server_session_store: rustls::server::ServerSessionMemoryCache::new(256),
            client_server_cert_verifier,
            client_cert_resolver: Arc::new(NoClientCertResolver),
            #[cfg(unix)]
            client_cert_cell: None,
            client_lazy_server_verifier: Some(lazy_server),
            server_client_cert_verifier,
            server_lazy_client_verifier: Some(lazy_client),
            server_cert_compression_cache: Arc::new(rustls::compress::CompressionCache::default()),
            client_cert_compression_cache: Arc::new(rustls::compress::CompressionCache::default()),
        };

        // Two blocking server configs from the same generator share one cache
        // Arc, and it is the generator's own server cache (the same Arc the
        // lazy path injects, since ptr-eq is transitive).
        let server_cfg_1 = generator
            .get_blocking_one_time_rustls_server_config(Alpn::RatsTls)
            .await
            .unwrap()
            .0;
        let server_cfg_2 = generator
            .get_blocking_one_time_rustls_server_config(Alpn::RatsTls)
            .await
            .unwrap()
            .0;
        assert!(
            Arc::ptr_eq(
                &server_cfg_1.cert_compression_cache,
                &server_cfg_2.cert_compression_cache,
            ),
            "blocking server configs must share one compression cache across handshakes"
        );
        assert!(
            Arc::ptr_eq(
                &server_cfg_1.cert_compression_cache,
                &generator.server_cert_compression_cache,
            ),
            "blocking server config must carry the generator's server cache"
        );

        // Same for the blocking client builder.
        let client_cfg_1 = generator
            .get_blocking_one_time_rustls_client_config(Alpn::RatsTls)
            .await
            .unwrap()
            .0;
        let client_cfg_2 = generator
            .get_blocking_one_time_rustls_client_config(Alpn::RatsTls)
            .await
            .unwrap()
            .0;
        assert!(
            Arc::ptr_eq(
                &client_cfg_1.cert_compression_cache,
                &client_cfg_2.cert_compression_cache,
            ),
            "blocking client configs must share one compression cache across handshakes"
        );
        assert!(
            Arc::ptr_eq(
                &client_cfg_1.cert_compression_cache,
                &generator.client_cert_compression_cache,
            ),
            "blocking client config must carry the generator's client cache"
        );

        // Server and client keep separate caches on the blocking path too.
        assert!(
            !Arc::ptr_eq(
                &server_cfg_1.cert_compression_cache,
                &client_cfg_1.cert_compression_cache,
            ),
            "server and client blocking compression caches must be distinct"
        );
    }
}

/// The lazy TCP rats-tls handshake must never touch tokio's blocking
/// machinery under **any** `RefreshStrategy` — including `Always`
/// (`refresh_interval: 0`), where each handshake performs a real attestation
/// round trip. These tests run on a `current_thread` runtime, where
/// `block_in_place` panics: a green handshake is direct proof the lazy path
/// only awaits. Requires AA (the Always cert fetches go through it); AS is
/// not contacted (raw handshake, no post-handshake `verify_cert`).
#[cfg(all(test, unix))]
mod lazy_always_tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use anyhow::{Context as _, Result};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::alpn::Alpn;
    use super::TlsConfigGenerator;
    use crate::config::ra::{
        AttestArgs, AttesterArgs, CocoAttesterArgs, CocoConverterArgs, CocoVerifierArgs,
        ConverterArgs, VerifierArgs, VerifyArgs,
    };
    use crate::tests::run_test_with_tokio_runtime;
    use crate::tunnel::ra_context::{AttestContext, RaContext, VerifyContext};

    const AA_UDS: &str =
        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

    fn attest_always() -> AttestArgs {
        AttestArgs::BackgroundCheck {
            attester: AttesterArgs::Coco(CocoAttesterArgs::Uds {
                aa_addr: AA_UDS.to_owned(),
            }),
            refresh_interval: Some(0),
        }
    }

    /// Hermetic `VerifyArgs`: `skip_as_token_cert_verify` makes the token
    /// verifier load nothing and call no AS (see the resumption RA tests).
    fn verify_hermetic() -> VerifyArgs {
        VerifyArgs::BackgroundCheck {
            converter: ConverterArgs::Coco(CocoConverterArgs::Restful {
                as_addr: "http://localhost:1/".to_string(),
                policy_ids: vec!["default".to_string()],
                as_headers: HashMap::new(),
            }),
            verifier: VerifierArgs::Coco(CocoVerifierArgs::Restful {
                as_addr: None,
                policy_ids: vec!["default".to_string()],
                as_headers: HashMap::new(),
                trusted_certs_paths: None,
                verify_signer_transparency: false,
                skip_as_token_cert_verify: true,
            }),
        }
    }

    /// One full lazy handshake between an AttestAndVerify server (snapshot
    /// server cert + mandatory client auth) and an AttestOnly client (swapped
    /// client cert via the shared resolver cell), both generators on `Always`
    /// refresh. Exercises the awaited fetches in `get_lazy_one_time_rustls_*`
    /// and both `resolve()` implementations, then checks each side actually
    /// saw the peer's cert — if a resolver returned None the handshake would
    /// not complete.
    #[tokio::test(flavor = "current_thread")]
    async fn lazy_always_refresh_handshake_without_block_in_place() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let attest_ctx = Arc::new(AttestContext::from_attest_args(&attest_always()).await?);
            let verify_ctx = Arc::new(VerifyContext::from_verify_args(&verify_hermetic()).await?);

            let server_gen = Arc::new(
                TlsConfigGenerator::new(
                    Arc::new(RaContext::AttestAndVerify {
                        attest: attest_ctx.clone(),
                        verify: verify_ctx.clone(),
                    }),
                    runtime.clone(),
                )
                .await
                .context("build AttestAndVerify generator")?,
            );
            let client_gen = Arc::new(
                TlsConfigGenerator::new(
                    Arc::new(RaContext::AttestOnly(attest_ctx.clone())),
                    runtime.clone(),
                )
                .await
                .context("build AttestOnly generator")?,
            );

            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let name = rustls::pki_types::ServerName::from(std::net::Ipv4Addr::new(127, 0, 0, 1));

            // Two sequential handshakes: under `Always` each side's config
            // build runs its own attestation round trip, both as genuine
            // awaits. Any `block_in_place` in the chain panics this runtime.
            for round in 0..2u32 {
                let server_gen = server_gen.clone();
                let listener = &listener;
                let server = async move {
                    let (tcp, _) = listener.accept().await.context("server accept")?;
                    let cfg = server_gen
                        .get_lazy_one_time_rustls_server_config(Alpn::RatsTls)
                        .await
                        .with_context(|| format!("server lazy config (round {round})"))?;
                    let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(cfg.0))
                        .accept(tcp)
                        .await
                        .with_context(|| format!("server TLS accept (round {round})"))?;
                    if round == 0 {
                        // Full handshake: the client presented its attest cert
                        // (served by the swappable resolver during the
                        // handshake). On a resumed handshake rustls presents
                        // no peer cert, so only round 0 asserts this.
                        let peer = tls.get_mut().1.peer_certificates().with_context(|| {
                            format!("server saw no client cert (round {round})")
                        })?;
                        assert!(!peer.is_empty(), "client cert chain must be non-empty");
                    }
                    tls.write_all(b"ok").await?;
                    tls.flush().await?;
                    Ok::<(), anyhow::Error>(())
                };
                let client = async {
                    let tcp = tokio::net::TcpStream::connect(addr).await?;
                    let cfg = client_gen
                        .get_lazy_one_time_rustls_client_config(Alpn::RatsTls)
                        .await
                        .with_context(|| format!("client lazy config (round {round})"))?;
                    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg.0))
                        .connect(name.clone(), tcp)
                        .await
                        .with_context(|| format!("client TLS connect (round {round})"))?;
                    if round == 0 {
                        let peer = tls.get_ref().1.peer_certificates().with_context(|| {
                            format!("client saw no server cert (round {round})")
                        })?;
                        assert!(!peer.is_empty(), "server cert chain must be non-empty");
                    }
                    let mut buf = [0u8; 2];
                    tls.read_exact(&mut buf).await?;
                    assert_eq!(&buf, b"ok");
                    Ok::<(), anyhow::Error>(())
                };
                tokio::try_join!(server, client)
                    .with_context(|| format!("lazy Always handshake failed (round {round})"))?;
            }
            Ok(())
        })
        .await
    }
}

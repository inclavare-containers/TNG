use anyhow::Context;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(any(unix, test))]
use crate::config::ra::AttestArgs;
use crate::config::ra::VerifyArgs;
#[cfg(unix)]
use crate::tunnel::ra_context::AttestContext;
use crate::tunnel::ra_context::VerifyContext;
use crate::tunnel::utils::rustls::ra::cert_cache::CertVerifyCache;
use crate::tunnel::utils::rustls::ra::common::LazyCertVerifier;
#[cfg(unix)]
use rats_cert::{
    cert::create::CertBuilder,
    crypto::{AsymmetricAlgo, HashAlgo},
    tee::AttesterPipeline,
};

use crate::tunnel::utils::rustls::config::alpn::Alpn;

pub async fn run(cmd: super::cli::RatsTlsCommand) -> Result<()> {
    match cmd {
        super::cli::RatsTlsCommand::Gen {
            attest,
            cert_out,
            key_out,
        } => {
            #[cfg(unix)]
            {
                gen(&attest, cert_out, key_out).await
            }
            #[cfg(not(unix))]
            {
                let _ = (attest, cert_out, key_out);
                anyhow::bail!("rats-tls gen is only supported on unix targets")
            }
        }
        super::cli::RatsTlsCommand::Dump {
            endpoint,
            attest,
            cert_out,
        } => dump(&endpoint, attest.as_deref(), cert_out).await,
        super::cli::RatsTlsCommand::Verify { cert, verify } => verify_cmd(&cert, &verify).await,
    }
}

#[cfg(unix)]
async fn gen(attest_json: &str, cert_out: Option<PathBuf>, key_out: Option<PathBuf>) -> Result<()> {
    let attest_args: AttestArgs =
        serde_json::from_str(attest_json).context("parse --attest as AttestArgs JSON")?;
    let attest_ctx = AttestContext::from_attest_args(&attest_args)
        .await
        .context("build attest context")?;

    let (cert_pem, key_pem) = match attest_ctx {
        AttestContext::Passport {
            attester,
            converter,
            ..
        } => {
            let pipeline = AttesterPipeline::new(attester, converter);
            let bundle = CertBuilder::new(pipeline, HashAlgo::Sha256)
                .with_subject("CN=TNG,O=Inclavare Containers")
                .build(AsymmetricAlgo::P256)
                .await
                .context("build rats-tls cert")?;
            (
                bundle.cert_to_pem().context("encode cert to PEM")?,
                bundle
                    .private_key()
                    .to_pkcs8_pem()
                    .context("encode private key to PKCS#8 PEM")?,
            )
        }
        AttestContext::BackgroundCheck { attester, .. } => {
            let bundle = CertBuilder::new(attester, HashAlgo::Sha256)
                .with_subject("CN=TNG,O=Inclavare Containers")
                .build(AsymmetricAlgo::P256)
                .await
                .context("build rats-tls cert")?;
            (
                bundle.cert_to_pem().context("encode cert to PEM")?,
                bundle
                    .private_key()
                    .to_pkcs8_pem()
                    .context("encode private key to PKCS#8 PEM")?,
            )
        }
    };

    // The cert PEM is public; the key PEM is a private key, so write it
    // owner-only (0600) when going to a file. stdout stays default.
    write_or_stdout(cert_pem.as_bytes(), cert_out).await?;
    match key_out {
        Some(p) => write_secret_file(&p, key_pem.as_bytes()).await?,
        None => write_or_stdout(key_pem.as_bytes(), None).await?,
    }
    Ok(())
}

/// Create the key file owner-only (0600) so the PKCS#8 private key is not
/// world-readable. `gen` is `#[cfg(unix)]`-only, so this is unix-gated too.
#[cfg(unix)]
async fn write_secret_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open secret key-out {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("write secret key-out {}", path.display()))?;
    Ok(())
}

async fn write_or_stdout(data: &[u8], path: Option<PathBuf>) -> Result<()> {
    match path {
        Some(p) => tokio::fs::write(&p, data)
            .await
            .with_context(|| format!("write {}", p.display())),
        None => {
            use std::io::Write;
            let mut out = std::io::stdout();
            out.write_all(data).context("write to stdout")?;
            Ok(())
        }
    }
}

/// Verify a rats-tls cert against a flat `VerifyArgs` JSON.
///
/// The verify path is cross-platform (it does not touch the unix-only AA
/// attester), so unlike `gen` this is not `#[cfg(unix)]`-gated. Reuses the
/// same `LazyCertVerifier` the TLS handshake uses: pass the cert directly to
/// `verify_cert`, which runs the verify engine (Passport: parse+verify AS
/// token; BackgroundCheck: convert via AS, verify).
async fn verify_cmd(cert_path: &std::path::Path, verify_json: &str) -> Result<()> {
    let verify_args: VerifyArgs =
        serde_json::from_str(verify_json).context("parse --verify as VerifyArgs JSON")?;
    let verify_ctx = std::sync::Arc::new(
        VerifyContext::from_verify_args(&verify_args)
            .await
            .context("build verify context")?,
    );

    let raw =
        std::fs::read(cert_path).with_context(|| format!("read cert {}", cert_path.display()))?;
    let cert_der = pem_or_der_to_der(&raw)?;

    // Reuse the same stateless LazyCertVerifier the TLS handshake uses: pass
    // the cert directly to verify_cert (Passport: parse+verify AS token;
    // BackgroundCheck: convert via AS, verify).
    let verifier = LazyCertVerifier::new(verify_ctx, Arc::new(CertVerifyCache::default_sized()));
    let result = verifier
        .verify_cert(cert_der)
        .await
        .context("verify rats-tls cert")?;

    // AttestationResult serializes to the raw JWT token string.
    let value = serde_json::to_value(&result).context("serialize attestation result")?;
    let pretty =
        serde_json::to_string_pretty(&value).context("format attestation result as pretty JSON")?;
    println!("verified OK\n{pretty}");
    Ok(())
}

/// Parse a PEM cert (input containing a `-----` fence) to the first DER
/// certificate; otherwise return the raw bytes as-is, treating them as DER.
fn pem_or_der_to_der(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.windows(5).any(|w| w == b"-----") {
        let s = std::str::from_utf8(raw).context("cert pem utf8")?;
        let mut chain = rustls_pemfile::certs(&mut s.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .context("parse pem cert")?;
        if chain.is_empty() {
            return Err(anyhow::anyhow!("no certificate found in PEM input"));
        }
        Ok(chain.swap_remove(0).to_vec())
    } else {
        Ok(raw.to_vec())
    }
}

/// Capture a rats-tls server certificate from a live endpoint by completing
/// the TLS handshake, without running attestation verification.
///
/// Unlike `verify`, this does not touch `VerifyContext`/`LazyCertVerifier`: it
/// builds a TLS1.3 client config (ALPN `rats-tls`) that injects a
/// [`capture::CapturingServerCertVerifier`] in place of the RA verifier. The
/// handshake therefore succeeds against any server (a no_ra server needs no
/// `--attest`; a server that requires a client cert needs `--attest`), and the
/// end-entity cert is recorded during the handshake. Once the handshake
/// completes the captured DER is written as PEM and the connection is closed,
/// without sending any application data.
async fn dump(endpoint: &str, attest_json: Option<&str>, cert_out: Option<PathBuf>) -> Result<()> {
    let capture = Arc::new(capture::CapturingServerCertVerifier::new()?);

    // `--attest` drives a client cert via CertManager/DynamicCertResolver
    // (mirror of the Attest arm in get_lazy_one_time_rustls_client_config).
    // CertManager is unix-only (it needs the AA attester), so on a non-unix
    // target (e.g. windows) an explicit --attest is rejected here
    // rather than silently dropping into no-client-auth.
    #[cfg(not(unix))]
    if attest_json.is_some() {
        anyhow::bail!("--attest for rats-tls dump requires a unix target (AA attester)");
    }

    let mut tls_client_config = match attest_json {
        #[cfg(unix)]
        Some(json) => {
            use crate::tunnel::utils::cert_manager::{CertManager, DynamicCertResolver};
            use crate::tunnel::utils::runtime::TokioRuntime;

            let attest_args: AttestArgs =
                serde_json::from_str(json).context("parse --attest as AttestArgs JSON")?;
            let attest_ctx = AttestContext::from_attest_args(&attest_args)
                .await
                .context("build attest context from --attest")?;
            // CertManager spawns a refresh task on a TokioRuntime; reuse the
            // current runtime handle so dump stays a one-shot in-process call.
            let shutdown = tokio_graceful::Shutdown::new(async {});
            let runtime = TokioRuntime::current(shutdown.guard())
                .context("acquire tokio runtime for cert manager")?;
            let cert_manager = CertManager::new(Arc::new(attest_ctx), runtime)
                .await
                .context("build cert manager from --attest")?;

            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_client_cert_resolver(Arc::new(DynamicCertResolver::new(Arc::new(
                    cert_manager,
                ))))
        }
        _ => rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
    };
    // Inject the capturing verifier in place of the RA verifier: the server
    // cert is recorded, no attestation verification is performed.
    tls_client_config
        .dangerous()
        .set_certificate_verifier(capture.clone());
    tls_client_config.alpn_protocols = vec![Alpn::RatsTls.as_bytes().to_vec()];

    let (host, port) = split_host_port(endpoint)?;
    let tcp_stream = tokio::net::TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connect to rats-tls endpoint {endpoint}"))?;
    let server_name = server_name_for_host(host)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_client_config));
    // The handshake presents the server cert; no app data is exchanged. Drop
    // the stream immediately after handshake (an orderly close is sent when
    // the TlsStream is dropped).
    let _tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .context("rats-tls handshake failed")?;

    let cert_der = capture
        .take()
        .context("no server cert captured during handshake")?;
    let pem = der_to_pem(&cert_der);
    write_or_stdout(pem.as_bytes(), cert_out).await?;
    Ok(())
}

fn split_host_port(endpoint: &str) -> Result<(&str, u16)> {
    let (host, port) = endpoint
        .rsplit_once(':')
        .with_context(|| format!("expected host:port endpoint, got {endpoint}"))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("parse port from endpoint {endpoint}"))?;
    Ok((host, port))
}

fn server_name_for_host(host: &str) -> Result<rustls::pki_types::ServerName<'static>> {
    use rustls::pki_types::{DnsName, IpAddr, ServerName};
    // Build a borrowing ServerName (Ipv4 is Copy; DnsName borrows host) then
    // lift to ServerName<'static> via to_owned, mirroring the egress client
    // handshake path. The owned lift clones the DNS name so it outlives host.
    let server_name = if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        ServerName::IpAddress(IpAddr::V4(ip.into()))
    } else {
        ServerName::DnsName(
            DnsName::try_from(host)
                .with_context(|| format!("invalid server name for TLS handshake ({host})"))?,
        )
    };
    Ok(server_name.to_owned())
}

/// Wrap a DER cert in a single-cert PEM block.
fn der_to_pem(der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let b64 = STANDARD.encode(der);
    // base64 output is pure ASCII, so byte offsets are char boundaries and the
    // slices are valid &str without a from_utf8 check.
    let mut out = String::with_capacity(b64.len() + 40);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    let mut start = 0;
    while start < b64.len() {
        let end = (start + 64).min(b64.len());
        out.push_str(&b64[start..end]);
        out.push('\n');
        start = end;
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

mod capture {
    use std::sync::Mutex;

    use anyhow::Result;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

    use crate::tunnel::utils::rustls::dummy::verifier::DummyServerCertVerifier;

    /// A `ServerCertVerifier` that records the server end-entity cert during
    /// the handshake and otherwise delegates signature/scheme handling to a
    /// [`DummyServerCertVerifier`] (which backs the no_ra client path). No
    /// attestation verification runs here; that is `rats-tls verify`'s job on the
    /// captured file. Delegating `verify_tls13_signature` /
    /// `supported_verify_schemes` to the dummy verifier mirrors the proven
    /// no_ra client handshake path so dump completes a handshake against the
    /// same servers a no_ra client can.
    #[derive(Debug)]
    pub struct CapturingServerCertVerifier {
        inner: DummyServerCertVerifier,
        captured: Mutex<Option<Vec<u8>>>,
    }

    impl CapturingServerCertVerifier {
        pub fn new() -> Result<Self> {
            Ok(Self {
                inner: DummyServerCertVerifier::new()?,
                captured: Mutex::new(None),
            })
        }

        /// Take the captured end-entity DER cert, if one was presented.
        // A poisoned lock only happens if a panic occurred mid-capture; in
        // that case there is nothing useful to capture, so return None and
        // let the caller fail with "no cert captured" rather than panicking.
        pub fn take(&self) -> Option<Vec<u8>> {
            self.captured.lock().ok().and_then(|mut g| g.take())
        }
    }

    impl ServerCertVerifier for CapturingServerCertVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            if let Ok(mut guard) = self.captured.lock() {
                *guard = Some(end_entity.to_vec());
            }
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            self.inner
                .verify_tls12_signature(message, cert, dss)
                .map_err(|error| {
                    tracing::debug!(?error, "rats-tls dump: tls12 signature check failed");
                    error
                })
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            self.inner
                .verify_tls13_signature(message, cert, dss)
                .map_err(|error| {
                    tracing::debug!(?error, "rats-tls dump: tls13 signature check failed");
                    error
                })
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use anyhow::Context as _;

        /// `verify_server_cert` stores the end-entity DER and asserts; `take`
        /// then returns it once.
        #[test]
        fn captures_end_entity_cert() -> Result<()> {
            let v = CapturingServerCertVerifier::new()?;
            assert!(v.take().is_none(), "no cert captured before handshake");

            let der: rustls::pki_types::CertificateDer<'static> =
                rustls::pki_types::CertificateDer::from(vec![1, 2, 3, 4]);
            v.verify_server_cert(
                &der,
                &[],
                &rustls::pki_types::ServerName::IpAddress(rustls::pki_types::IpAddr::from(
                    std::net::Ipv4Addr::LOCALHOST,
                )),
                &[],
                rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::ZERO),
            )?;
            let captured = v.take().context("cert captured after verify_server_cert")?;
            assert_eq!(captured, vec![1, 2, 3, 4]);
            assert!(v.take().is_none(), "take clears the captured cert");
            Ok(())
        }

        /// `der_to_pem` (tested via the parent module) is exercised by the
        /// integration test; this just guards the accessor surface.
        #[test]
        fn supported_schemes_nonempty() -> Result<()> {
            let v = CapturingServerCertVerifier::new()?;
            assert!(!v.supported_verify_schemes().is_empty());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    /// Direct `AttestArgs` JSON parse (no `RaArgsUnchecked` tag injection), so
    /// every discriminator tag must be explicit: `model`, `aa_provider`, `aa_type`.
    #[test]
    fn parse_attest_json_background_check() {
        let json = r#"{"model":"background_check","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock","refresh_interval":3600}"#;
        let args: super::AttestArgs = match serde_json::from_str(json) {
            Ok(a) => a,
            Err(error) => panic!("parse AttestArgs JSON failed: {error:?}"),
        };
        use crate::config::ra::{AttesterArgs, CocoAttesterArgs};
        match args {
            crate::config::ra::AttestArgs::BackgroundCheck {
                attester,
                refresh_interval,
            } => {
                assert_eq!(refresh_interval, Some(3600));
                match attester {
                    AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }) => {
                        assert_eq!(
                            aa_addr,
                            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        );
                    }
                    other => panic!("expected Coco/Uds attester, got {other:?}"),
                }
            }
            other => panic!("expected BackgroundCheck, got {other:?}"),
        }
    }

    /// Direct `VerifyArgs` JSON parse. Like AttestArgs, VerifyArgs is
    /// `#[serde(tag = "model", flatten)]`, so converter and verifier share one
    /// flat `as_provider`/`as_type`/`as_addr`/`policy_ids`/`as_headers` object
    /// rather than nesting under `converter`/`verifier` keys.
    #[test]
    fn parse_verify_json_background_check() {
        let json = r#"{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}"#;
        let args: super::VerifyArgs = match serde_json::from_str(json) {
            Ok(a) => a,
            Err(error) => panic!("parse VerifyArgs JSON failed: {error:?}"),
        };
        use crate::config::ra::{CocoConverterArgs, CocoVerifierArgs, ConverterArgs, VerifierArgs};
        match args {
            crate::config::ra::VerifyArgs::BackgroundCheck {
                converter,
                verifier,
            } => {
                match converter {
                    ConverterArgs::Coco(CocoConverterArgs::Restful {
                        as_addr,
                        policy_ids,
                        ..
                    }) => {
                        assert_eq!(as_addr, "http://127.0.0.1:8080");
                        assert_eq!(policy_ids, vec!["default".to_string()]);
                    }
                    other => panic!("expected Coco/Restful converter, got {other:?}"),
                }
                match verifier {
                    VerifierArgs::Coco(CocoVerifierArgs::Restful {
                        as_addr,
                        policy_ids,
                        ..
                    }) => {
                        assert_eq!(as_addr, Some("http://127.0.0.1:8080".to_string()));
                        assert_eq!(policy_ids, vec!["default".to_string()]);
                    }
                    other => panic!("expected Coco/Restful verifier, got {other:?}"),
                }
            }
            other => panic!("expected BackgroundCheck, got {other:?}"),
        }
    }
}

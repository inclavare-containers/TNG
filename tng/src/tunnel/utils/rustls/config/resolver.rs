use std::sync::Arc;

use parking_lot::RwLock;

/// A rustls cert resolver that serves one fixed [`rustls::sign::CertifiedKey`]
/// snapshot.
///
/// Used on the lazy TCP rats-tls path: the handshake orchestration awaits the
/// freshest cert *before* building the config, so `resolve()` is a pure Arc
/// clone and never touches tokio's blocking machinery. Server resumption keys
/// on the shared `session_storage`, not on resolver identity, so a fresh
/// instance per handshake is safe.
#[cfg(unix)]
#[derive(Debug)]
pub struct SnapshotCertResolver {
    certified_key: Arc<rustls::sign::CertifiedKey>,
}

#[cfg(unix)]
impl SnapshotCertResolver {
    pub fn new(certified_key: Arc<rustls::sign::CertifiedKey>) -> Self {
        Self { certified_key }
    }
}

#[cfg(unix)]
impl rustls::server::ResolvesServerCert for SnapshotCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.certified_key.clone())
    }
}

#[cfg(unix)]
impl rustls::client::ResolvesClientCert for SnapshotCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.certified_key.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// The lazy TCP client's shared cert resolver: one instance per
/// `TlsConfigGenerator`, with the presented cert swapped in per handshake.
///
/// rustls gates TLS 1.3 client resumption on `Weak::ptr_eq` of the
/// `ResolvesClientCert` Arc across handshakes (`ClientSessionCommon::
/// compatible_config`), so the resolver identity must stay stable while its
/// value must stay fresh. `resolve()` runs synchronously inside the handshake,
/// which the lazy TCP path must never block (`block_in_place`), so the value
/// is published ahead of time: each handshake awaits the freshest cert and
/// calls [`Self::store`] before `connect()`.
///
/// Concurrent handshakes may overwrite each other's stored cert; under
/// `RefreshStrategy::Always` every stored value was just fetched, so whichever
/// one a `resolve()` sees is equally fresh.
#[derive(Debug, Default)]
pub struct SwappableClientCertResolver {
    current: RwLock<Option<Arc<rustls::sign::CertifiedKey>>>,
}

#[cfg(unix)]
impl SwappableClientCertResolver {
    /// Publish the cert that the next handshakes should present.
    pub fn store(&self, certified_key: Arc<rustls::sign::CertifiedKey>) {
        *self.current.write() = Some(certified_key);
    }
}

impl rustls::client::ResolvesClientCert for SwappableClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.current.read().clone()
    }

    fn has_certs(&self) -> bool {
        self.current.read().is_some()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use anyhow::{Context as _, Result};
    use rustls::client::ResolvesClientCert as _;

    use crate::tunnel::utils::rustls::dummy::{TNG_DUMMY_CERT, TNG_DUMMY_KEY};

    fn dummy_certified_key() -> Result<Arc<rustls::sign::CertifiedKey>> {
        let cert_chain =
            rustls_pemfile::certs(&mut TNG_DUMMY_CERT.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        let key_der = rustls_pemfile::private_key(&mut TNG_DUMMY_KEY.as_bytes())?
            .context("No private key found")?;
        let provider = rustls::crypto::CryptoProvider::get_default()
            .context("rustls crypto provider not installed")?;
        Ok(Arc::new(rustls::sign::CertifiedKey::from_der(
            cert_chain, key_der, provider,
        )?))
    }

    /// The snapshot resolver hands out exactly the cert it was built with,
    /// and the client trait path (the one the `rats-tls dump` tool uses)
    /// always reports it as present.
    #[test]
    fn snapshot_resolver_serves_its_cert() -> Result<()> {
        let key = dummy_certified_key()?;
        let resolver = SnapshotCertResolver::new(key.clone());

        assert!(resolver.has_certs());
        let resolved = rustls::client::ResolvesClientCert::resolve(&resolver, &[], &[])
            .context("snapshot resolver must always resolve a cert")?;
        assert!(
            Arc::ptr_eq(&key, &resolved),
            "the resolver must hand out the same allocation it was built with"
        );
        Ok(())
    }

    /// Before the first `store` the resolver presents nothing; after each
    /// `store` it presents exactly that cert.
    #[test]
    fn swappable_resolver_tracks_stored_cert() -> Result<()> {
        let resolver = SwappableClientCertResolver::default();
        assert!(!resolver.has_certs());
        assert!(
            rustls::client::ResolvesClientCert::resolve(&resolver, &[], &[]).is_none(),
            "empty cell must resolve to None"
        );

        let key1 = dummy_certified_key()?;
        resolver.store(key1.clone());
        assert!(resolver.has_certs());
        let resolved = rustls::client::ResolvesClientCert::resolve(&resolver, &[], &[])
            .context("cert after first store")?;
        assert!(Arc::ptr_eq(&key1, &resolved));

        let key2 = dummy_certified_key()?;
        resolver.store(key2.clone());
        let resolved2 = rustls::client::ResolvesClientCert::resolve(&resolver, &[], &[])
            .context("cert after second store")?;
        assert!(
            Arc::ptr_eq(&key2, &resolved2),
            "a later store must replace the published cert"
        );
        Ok(())
    }
}

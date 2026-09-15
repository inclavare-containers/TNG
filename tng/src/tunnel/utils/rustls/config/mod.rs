pub mod alpn;
pub mod client;
#[cfg(not(wasm))]
pub mod server;

use std::sync::Arc;

use crate::tunnel::ra_context::{RaContext, VerifyContext};
#[cfg(unix)]
use crate::tunnel::utils::cert_manager::CertManager;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::rustls::ra::cert_cache::CertVerifyCache;
use anyhow::Result;

/// Per-config cert-verification verdict cache, shared across every connection a
/// `TlsConfigGenerator` produces. Held here (not on the per-connection verifier) because the
/// generator outlives any single connection, so a verdict cached on connection N is still valid
/// for connection N+1 as long as it stays within the TTL.
pub enum TlsConfigGenerator {
    NoRa,
    Verify(Arc<VerifyContext>, Arc<CertVerifyCache>),
    #[cfg(unix)]
    Attest(Arc<CertManager>),
    #[cfg(unix)]
    AttestAndVerify(Arc<CertManager>, Arc<VerifyContext>, Arc<CertVerifyCache>),
}

impl TlsConfigGenerator {
    #[allow(unused_variables)]
    pub async fn new(ra_context: Arc<RaContext>, runtime: TokioRuntime) -> Result<Self> {
        Ok(match ra_context.as_ref() {
            #[cfg(unix)]
            RaContext::AttestOnly(attest_ctx) => Self::Attest(Arc::new(
                CertManager::new(attest_ctx.clone(), runtime).await?,
            )),
            RaContext::VerifyOnly(verify_ctx) => Self::Verify(
                verify_ctx.clone(),
                Arc::new(CertVerifyCache::default_sized()),
            ),
            #[cfg(unix)]
            RaContext::AttestAndVerify { attest, verify } => Self::AttestAndVerify(
                Arc::new(CertManager::new(attest.clone(), runtime).await?),
                verify.clone(),
                Arc::new(CertVerifyCache::default_sized()),
            ),
            RaContext::NoRa => Self::NoRa,
        })
    }
}

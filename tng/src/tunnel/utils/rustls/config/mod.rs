pub mod alpn;
pub mod client;
pub mod server;

use std::sync::Arc;

use crate::tunnel::ra_context::{RaContext, VerifyContext};
use crate::tunnel::utils::{cert_manager::CertManager, runtime::TokioRuntime};
use anyhow::Result;

pub enum TlsConfigGenerator {
    NoRa,
    Verify(Arc<VerifyContext>),
    #[cfg(unix)]
    Attest(Arc<CertManager>),
    #[cfg(unix)]
    AttestAndVerify(Arc<CertManager>, Arc<VerifyContext>),
}

impl TlsConfigGenerator {
    pub async fn new(ra_context: Arc<RaContext>, runtime: TokioRuntime) -> Result<Self> {
        Ok(match ra_context.as_ref() {
            RaContext::AttestOnly(attest_ctx) => Self::Attest(Arc::new(
                CertManager::new(attest_ctx.clone(), runtime).await?,
            )),
            RaContext::VerifyOnly(verify_ctx) => Self::Verify(verify_ctx.clone()),
            RaContext::AttestAndVerify { attest, verify } => Self::AttestAndVerify(
                Arc::new(CertManager::new(attest.clone(), runtime).await?),
                verify.clone(),
            ),
            RaContext::NoRa => Self::NoRa,
        })
    }
}

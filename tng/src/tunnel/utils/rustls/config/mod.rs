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

pub enum TlsConfigGenerator {
    NoRa,
    Verify(Arc<VerifyContext>),
    #[cfg(unix)]
    Attest(Arc<CertManager>),
    #[cfg(unix)]
    AttestAndVerify(Arc<CertManager>, Arc<VerifyContext>),
}

impl TlsConfigGenerator {
    #[allow(unused_variables)]
    pub async fn new(ra_context: Arc<RaContext>, runtime: TokioRuntime) -> Result<Self> {
        Ok(match ra_context.as_ref() {
            #[cfg(unix)]
            RaContext::AttestOnly(attest_ctx) => Self::Attest(Arc::new(
                CertManager::new(attest_ctx.clone(), runtime).await?,
            )),
            RaContext::VerifyOnly(verify_ctx) => Self::Verify(verify_ctx.clone()),
            #[cfg(unix)]
            RaContext::AttestAndVerify { attest, verify } => Self::AttestAndVerify(
                Arc::new(CertManager::new(attest.clone(), runtime).await?),
                verify.clone(),
            ),
            RaContext::NoRa => Self::NoRa,
        })
    }
}

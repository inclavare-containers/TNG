use rats_cert::{
    cert::create::CertBuilder,
    crypto::{AsymmetricAlgo, HashAlgo},
    tee::coco::attester::CocoAttester,
};
use rustls::client::ResolvesClientCert;

use crate::config::ra::AttestArgs;

#[derive(Debug)]
pub struct CoCoClientCertResolver {
    attest_args: AttestArgs,
}

impl CoCoClientCertResolver {
    pub fn new(attest_args: AttestArgs) -> Self {
        Self { attest_args }
    }
}

impl ResolvesClientCert for CoCoClientCertResolver {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        // let coco_attester = CocoAttester::new(&self.attest_args.aa_addr)?;

        // let cert = CertBuilder::new(coco_attester, HashAlgo::Sha256).with_subject("CN=TNG,O=Inclavare Containers")
        //     .build(AsymmetricAlgo::P256)
        //     .await?;

        // let pem_cert = cert_bundle.cert_to_pem()?;
        // let privkey = cert_bundle.private_key().to_pkcs8_pem()?;
        // (pem_cert, privkey);

        todo!()
    }

    fn has_certs(&self) -> bool {
        true
    }
}

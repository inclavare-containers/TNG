use std::sync::Arc;

use anyhow::Result;
use rats_cert::{
    cert::verify::{CertVerifier, ClaimsCheck, CocoVerifyMode, VerifyPolicy, VerifyPolicyOutput},
    tee::claims::Claims,
};
use rustls::{
    client::{danger::ServerCertVerified, WebPkiServerVerifier},
    Error,
};
use tokio_rustls::rustls::RootCertStore;

use crate::{config::ra::VerifyArgs, executor::envoy::confgen::ENVOY_DUMMY_CERT};

#[derive(Debug)]
pub struct CoCoCertVerifier {
    verify: VerifyArgs,
    inner: Arc<WebPkiServerVerifier>,
}

impl CoCoCertVerifier {
    pub fn new(verify: VerifyArgs) -> Result<Self> {
        let mut cert = ENVOY_DUMMY_CERT.as_bytes();
        let certs = rustls_pemfile::certs(&mut cert).collect::<Result<Vec<_>, _>>()?;
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(certs);
        /* The WebPkiServerVerifier requires that the root certs not empty, or it will failed with 'no root trust anchors were provided'. So let's put a dummy cert here as a root cert to make WebPkiServerVerifier happy. */
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots)).build()?;

        Ok(Self {
            verify: verify,
            inner: verifier,
        })
    }
}

impl rustls::client::danger::ServerCertVerifier for CoCoCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let res = CertVerifier::new(VerifyPolicy::Coco {
            verify_mode: CocoVerifyMode::Evidence {
                as_addr: self.verify.as_addr.to_owned(),
                as_is_grpc: self.verify.as_is_grpc,
            },
            policy_ids: self.verify.policy_ids.to_owned(),
            trusted_certs_paths: None,
            claims_check: ClaimsCheck::Contains(Claims::new()), // We do not check the claims here, just leave it to be checked by attestation service.
        })
        .verify_pem(&end_entity);

        match res {
            Ok(VerifyPolicyOutput::Passed) => {
                return Ok(ServerCertVerified::assertion());
            }
            Ok(VerifyPolicyOutput::Failed) => {
                return Err(Error::General(
                    "Verify failed because of claims".to_string(),
                ));
            }
            Err(err) => {
                return Err(Error::General(
                    format!("Verify failed with err: {:?}", err).to_string(),
                ));
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

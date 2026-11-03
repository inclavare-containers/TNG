//! Self-signed certificate chain for the embedded attestation service.

use pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls_pki_types::CertificateDer;

use crate::errors::*;

/// Certificate validity period in days (10 years)
const CERT_VALIDITY_DAYS: i64 = 365 * 10;

pub(crate) struct SelfSignedSigner {
    pub(crate) cert_chain: Vec<CertificateDer<'static>>,
    private_key: p256::SecretKey,
}

impl SelfSignedSigner {
    pub(crate) fn new() -> Result<Self> {
        let (cert_chain, private_key) = generate_certificates()?;
        Ok(Self {
            cert_chain,
            private_key,
        })
    }
}

impl attestation_service::token::signer::SignKeyProvider<p256::SecretKey> for SelfSignedSigner {
    fn private_key(&self) -> &p256::SecretKey {
        &self.private_key
    }
    fn cert_chain(&self) -> Option<anyhow::Result<Vec<CertificateDer<'static>>>> {
        Some(Ok(self.cert_chain.clone()))
    }
    fn cert_url(&self) -> Option<&str> {
        None
    }
    fn cert_pem_live(&self) -> Option<anyhow::Result<Vec<u8>>> {
        // Return None here since this function will not be called actually
        None
    }
}

/// Generate CA and AS certificates using rcgen
fn generate_certificates() -> Result<(Vec<CertificateDer<'static>>, p256::SecretKey)> {
    // Generate CA key pair
    let ca_key_pair =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(Error::CaCertGenerationFailed)?;

    // Create CA certificate parameters
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "Builtin AS CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params.not_before = time::OffsetDateTime::now_utc();
    ca_params.not_after = ca_params.not_before + time::Duration::days(CERT_VALIDITY_DAYS);

    // Generate CA certificate
    let ca_cert = ca_params
        .self_signed(&ca_key_pair)
        .map_err(Error::CaCertGenerationFailed)?;

    // Generate AS key pair
    let as_key_pair =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(Error::AsCertGenerationFailed)?;

    // Create AS certificate parameters
    let mut as_params = CertificateParams::default();
    as_params
        .distinguished_name
        .push(DnType::CommonName, "Builtin AS");
    as_params
        .distinguished_name
        .push(DnType::OrganizationName, "Builtin AS CA");
    as_params.is_ca = IsCa::NoCa;
    as_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    as_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Any];
    as_params.not_before = time::OffsetDateTime::now_utc();
    as_params.not_after = as_params.not_before + time::Duration::days(CERT_VALIDITY_DAYS);

    // Sign AS certificate with CA
    let as_cert = as_params
        .signed_by(&as_key_pair, &ca_cert, &ca_key_pair)
        .map_err(Error::AsCertGenerationFailed)?;

    // Build certificate chain (AS cert + CA cert)
    let cert_chain = vec![CertificateDer::from(as_cert), CertificateDer::from(ca_cert)];

    // BuildAS private key
    let as_private_key = p256::SecretKey::from_pkcs8_der(as_key_pair.serialized_der())
        .map_err(Error::FromPkcs8DerFailed)?;

    Ok((cert_chain, as_private_key))
}

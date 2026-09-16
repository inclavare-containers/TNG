use std::collections::HashMap;

use super::dice::cbor::{
    generate_pubkey_hash_value_buffer, parse_claims_buffer, parse_evidence_buffer_with_tag,
};
use super::dice::extensions::{OID_TCG_DICE_ENDORSEMENT_MANIFEST, OID_TCG_DICE_TAGGED_EVIDENCE};
use super::CLAIM_NAME_PUBLIC_KEY_HASH;
use crate::crypto::DefaultCrypto;
use crate::crypto::HashAlgo;
use crate::errors::*;
use crate::tee::claims::Claims;
use crate::tee::ReportData;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use const_oid::ObjectIdentifier;
use pkcs8::der::referenced::OwnedToRef;
use pkcs8::der::{Decode, DecodePem, Encode};
use pkcs8::spki::AlgorithmIdentifierOwned;
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

// Cert self-signature verification routes through rustls-webpki's algorithm
// constants so the hot path uses aws-lc-rs on native (AVX512/VAES) and ring on
// wasm (aws-lc-sys cannot compile for wasm32-unknown-unknown; see build.rs
// `wasm` cfg). Same backend split as jwk.rs / the rustls provider init.
use rustls_pki_types::SignatureVerificationAlgorithm;
#[cfg(not(wasm))]
use rustls_webpki::aws_lc_rs::{
    ECDSA_P256_SHA256, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
};
#[cfg(wasm)]
use rustls_webpki::ring::{
    ECDSA_P256_SHA256, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
};

// Re-export builtin config types for external use
#[cfg(feature = "__builtin-as")]
pub use crate::tee::coco::converter::builtin::{
    PolicyConfig, ReferenceValueConfig, SampleProvenancePayloadConfig,
    SlsaReferenceValuePayloadConfig, DEFAULT_POLICY_ID,
};

// Re-export reference value list types from RVPS
#[cfg(feature = "__builtin-as")]
pub use reference_value_provider_service::rv_list::{
    ReferenceValueListItem, ReferenceValueListPayload, ReferenceValueProvenanceInfo,
    ReferenceValueProvenanceSource,
};

// Re-export Provenance type from RVPS
#[cfg(feature = "__builtin-as")]
pub use reference_value_provider_service::extractors::extractor_modules::sample::Provenance;

/// Provider-agnostic pending result from certificate verification.
///
/// Contains the raw CBOR tag, raw evidence bytes, and expected report data.
/// The caller (e.g. `TngCommonCertVerifier`) is responsible for parsing the
/// raw evidence into the appropriate provider-specific type.
pub struct CertVerifyPendingResult {
    /// The CBOR tag identifying the evidence type
    pub cbor_tag: u64,
    /// The raw evidence bytes (not yet parsed into a provider-specific type)
    pub raw_evidence: Vec<u8>,
    /// The expected report data (containing pubkey hash) for verification
    pub report_data: ReportData,
}

/// Attestation service address configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationServiceAddrArgs {
    /// Attestation service address
    pub as_addr: String,

    /// Whether attestation service uses gRPC protocol, default is false (using REST API). If true, connect to Attestation Service via Grpc protocol. If false, connect via HTTP protocol.
    #[serde(default = "bool::default")]
    pub as_is_grpc: bool,

    /// Custom headers to be sent with attestation service requests
    #[serde(default = "Default::default")]
    pub as_headers: HashMap<String, String>,
}

/// Lightweight certificate verifier
///
/// This struct only handles certificate parsing and evidence extraction.
/// The actual evidence verification should be done by the caller using
/// the appropriate verifier (CocoVerifier, BuiltinCocoConverter, etc.).
pub struct CertVerifier;

impl Default for CertVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CertVerifier {
    pub fn new() -> Self {
        Self
    }

    /// Verify a PEM-encoded certificate and extract evidence
    ///
    /// Returns a pending result that the caller should verify with an appropriate verifier.
    pub async fn verify_pem(&self, cert: &[u8]) -> Result<CertVerifyPendingResult> {
        let cert = Certificate::from_pem(cert).map_err(Error::ParsePemCertError)?;
        self.verify_cert(&cert).await
    }

    /// Verify a DER-encoded certificate and extract evidence
    ///
    /// Returns a pending result that the caller should verify with an appropriate verifier.
    pub async fn verify_der(&self, cert: &[u8]) -> Result<CertVerifyPendingResult> {
        let cert = Certificate::from_der(cert).map_err(Error::ParseDerCertError)?;
        self.verify_cert(&cert).await
    }

    async fn verify_cert(&self, cert: &Certificate) -> Result<CertVerifyPendingResult> {
        /* check self-signed cert */
        verify_cert_signature(cert, cert)?;

        /* Extract the evidence_buffer and endorsements_buffer(optional) from the X.509 certificate extension. */
        let evidence_buffer = extract_ext_with_oid(cert, &OID_TCG_DICE_TAGGED_EVIDENCE);
        let _endorsements_buffer = extract_ext_with_oid(cert, &OID_TCG_DICE_ENDORSEMENT_MANIFEST);

        /* evidence extension is not optional */
        let evidence_buffer = match evidence_buffer {
            Some(v) => v,
            None => Err(Error::CertExtractExtensionFailed)?,
        };
        /* endorsements extension is optional */
        // TODO: endorsements extension

        let (cbor_tag, raw_evidence, _) = parse_evidence_buffer_with_tag(evidence_buffer)?;
        // Note: the implementation here is not compatible with the Interoperable RA-TLS now

        /* Prepare expected pubkey-hash claim */
        let spki_bytes = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(Error::DerError)?;
        // TODO: Hash algorithm is currently hardcoded to SHA256.
        // Future support should include extracting the hash algorithm from the evidence.
        let pubkey_hash = DefaultCrypto::hash(HashAlgo::Sha256, &spki_bytes);
        let pubkey_hash_value_buffer =
            generate_pubkey_hash_value_buffer(HashAlgo::Sha256, &pubkey_hash)?;

        let mut expected_claims = Claims::new();
        expected_claims.insert(
            CLAIM_NAME_PUBLIC_KEY_HASH.into(),
            serde_json::Value::String(BASE64_STANDARD.encode(pubkey_hash_value_buffer)),
        );
        let report_data = ReportData::Claims(expected_claims);

        Ok(CertVerifyPendingResult {
            cbor_tag,
            raw_evidence,
            report_data,
        })
    }
}

fn verify_cert_signature(issuer: &Certificate, signed: &Certificate) -> Result<()> {
    if issuer.tbs_certificate.subject != signed.tbs_certificate.issuer {
        return Err(Error::CertIssuerMismatch);
    }

    let signed_data = signed
        .tbs_certificate
        .to_der()
        .map_err(Error::CertEncodeFailed)?;
    let signature = signed
        .signature
        .as_bytes()
        .ok_or(Error::CertSignatureNotFound)?;

    verify_signed_data(issuer, &signed_data, signature, &signed.signature_algorithm)
}

fn verify_signed_data(
    issuer: &Certificate,
    signed_data: &[u8],
    signature: &[u8],
    algo: &AlgorithmIdentifierOwned,
) -> Result<()> {
    // `public_key` is the raw subjectPublicKey content (the uncompressed EC
    // point for ECDSA, the DER RSAPublicKey for RSA), which is the form
    // webpki's own EndEntityCert::verify_signature feeds to the same algorithm
    // constants. See `BitStringRef::raw_bytes` (strips the unused-bits octet).
    let public_key = issuer
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref()
        .subject_public_key
        .raw_bytes();

    let alg: &dyn SignatureVerificationAlgorithm = match algo.oid {
        const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => RSA_PKCS1_2048_8192_SHA256,
        const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION => RSA_PKCS1_2048_8192_SHA384,
        const_oid::db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION => RSA_PKCS1_2048_8192_SHA512,
        const_oid::db::rfc5912::ECDSA_WITH_SHA_256 => ECDSA_P256_SHA256,
        _ => {
            return Err(Error::UnknownSignatureAlgo(
                issuer.tbs_certificate.signature.oid,
            ))
        }
    };

    alg.verify_signature(public_key, signed_data, signature)
        .map_err(|_| Error::CertVerifySignatureFailed(signature::Error::new()))?;

    Ok(())
}

fn extract_ext_with_oid<'a>(cert: &'a Certificate, oid: &ObjectIdentifier) -> Option<&'a [u8]> {
    cert.tbs_certificate.extensions.as_ref().and_then(|exts| {
        let mut it = exts.iter().filter(|ext| ext.extn_id == *oid);
        it.next().map(|ext| ext.extn_value.as_bytes())
    })
}

#[cfg(test)]
mod tests {
    //! Characterization tests for `verify_signed_data`: the self-signature
    //! verification backend. They assert the public contract (a valid
    //! self-signed DICE cert verifies; a tampered signature or TBS does not),
    //! in both directions, so a crypto-backend swap (pure-Rust p256/rsa ->
    //! rustls-webpki aws-lc-rs/ring) that breaks either direction is caught.
    use super::*;
    use crate::cert::dice::generate_and_sign_dice_cert;
    use crate::crypto::{AsymmetricAlgo, DefaultCrypto, HashAlgo};
    use pkcs8::der::Encode;

    /// Build a self-signed DICE cert with the given key algorithm. The
    /// evidence buffer is irrelevant to `verify_signed_data` (it only checks
    /// the cert's self-signature), so a fixed dummy payload is fine.
    fn make_self_signed(algo: AsymmetricAlgo) -> Certificate {
        let key = DefaultCrypto::gen_private_key(algo).expect("gen key");
        generate_and_sign_dice_cert(
            "CN=tng-verify-test",
            HashAlgo::Sha256,
            &key,
            &[0x01, 0x02, 0x03, 0x04],
            None,
        )
        .expect("generate_and_sign_dice_cert")
    }

    /// Extract the (tbs_der, signature_bytes, signature_algorithm) triple that
    /// `verify_cert` feeds into `verify_signed_data`.
    fn verify_inputs(cert: &Certificate) -> (Vec<u8>, Vec<u8>, AlgorithmIdentifierOwned) {
        let tbs = cert.tbs_certificate.to_der().expect("tbs to_der");
        let sig = cert.signature.as_bytes().expect("signature bytes").to_vec();
        let alg = cert.signature_algorithm.clone();
        (tbs, sig, alg)
    }

    #[test]
    fn p256_self_signed_cert_verifies() {
        let cert = make_self_signed(AsymmetricAlgo::P256);
        let (tbs, sig, alg) = verify_inputs(&cert);
        verify_signed_data(&cert, &tbs, &sig, &alg).expect("valid P256 self-signature must verify");
    }

    #[test]
    fn p256_tampered_signature_is_rejected() {
        let cert = make_self_signed(AsymmetricAlgo::P256);
        let (tbs, mut sig, alg) = verify_inputs(&cert);
        sig[0] ^= 0xff;
        verify_signed_data(&cert, &tbs, &sig, &alg)
            .expect_err("tampered P256 signature must be rejected");
    }

    #[test]
    fn p256_tampered_tbs_is_rejected() {
        let cert = make_self_signed(AsymmetricAlgo::P256);
        let (mut tbs, sig, alg) = verify_inputs(&cert);
        tbs[0] ^= 0xff;
        verify_signed_data(&cert, &tbs, &sig, &alg)
            .expect_err("tampered P256 TBS must be rejected");
    }

    #[test]
    fn rsa_self_signed_cert_verifies() {
        let cert = make_self_signed(AsymmetricAlgo::Rsa2048);
        let (tbs, sig, alg) = verify_inputs(&cert);
        verify_signed_data(&cert, &tbs, &sig, &alg).expect("valid RSA self-signature must verify");
    }

    #[test]
    fn rsa_tampered_signature_is_rejected() {
        let cert = make_self_signed(AsymmetricAlgo::Rsa2048);
        let (tbs, mut sig, alg) = verify_inputs(&cert);
        sig[0] ^= 0xff;
        verify_signed_data(&cert, &tbs, &sig, &alg)
            .expect_err("tampered RSA signature must be rejected");
    }
}

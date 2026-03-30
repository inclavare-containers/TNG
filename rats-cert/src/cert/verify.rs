use std::collections::HashMap;

use super::dice::cbor::OCBR_TAG_EVIDENCE_COCO_TOKEN;
use super::dice::cbor::{
    generate_pubkey_hash_value_buffer, parse_claims_buffer, parse_evidence_buffer_with_tag,
};
use super::dice::extensions::{OID_TCG_DICE_ENDORSEMENT_MANIFEST, OID_TCG_DICE_TAGGED_EVIDENCE};
use super::CLAIM_NAME_PUBLIC_KEY_HASH;
use crate::crypto::DefaultCrypto;
use crate::crypto::HashAlgo;
use crate::errors::*;
use crate::tee::coco::evidence::{CocoAsToken, CocoEvidence};
use crate::tee::ReportData;
use crate::tee::{claims::Claims, GenericEvidence};

use anyhow::Context;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use const_oid::ObjectIdentifier;
use pkcs8::der::referenced::OwnedToRef;
use pkcs8::der::{Decode, DecodePem, Encode};
use pkcs8::spki::AlgorithmIdentifierOwned;
use serde::{Deserialize, Serialize};
use signature::Verifier;
use x509_cert::Certificate;

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
};

// Re-export Provenance type from RVPS
#[cfg(feature = "__builtin-as")]
pub use reference_value_provider_service::extractors::extractor_modules::sample::Provenance;

/// Evidence extracted from certificate - either raw evidence or already-verified token
pub enum CertEvidence {
    /// Raw CoCo evidence that needs to be verified by an Attestation Service
    Evidence(CocoEvidence),
    /// CoCo AS token that has already been verified (passport mode)
    Token(CocoAsToken),
}

/// Pending result from certificate verification
///
/// Contains the extracted evidence and expected report data.
/// The caller should use an appropriate verifier to complete the verification.
pub struct CertVerifyPendingResult {
    /// The extracted evidence from the certificate
    pub evidence: CertEvidence,
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

        /* Parse evidence based on CBOR tag */
        let evidence = if cbor_tag == OCBR_TAG_EVIDENCE_COCO_TOKEN {
            // This is a CoCo AS token (passport mode)
            let token = Into::<Result<_>>::into(CocoAsToken::create_evidence_from_dice(
                cbor_tag,
                &raw_evidence,
            ))
            .map_err(|e| {
                Error::UnrecognizedEvidenceType {
                    detail: format!(
                        "Failed to parse CoCo AS token: cbor_tag: {:#x?}, raw_evidence: {:02x?}...({}bytes): {e}",
                        cbor_tag, &raw_evidence[..raw_evidence.len().min(10)], raw_evidence.len()
                    ),
                }
            })?;
            CertEvidence::Token(token)
        } else {
            // This is raw evidence (background check or builtin mode)
            let evidence = Into::<Result<_>>::into(CocoEvidence::create_evidence_from_dice(
                cbor_tag,
                &raw_evidence,
            ))
            .map_err(|e| {
                Error::UnrecognizedEvidenceType {
                    detail: format!(
                        "Failed to parse CoCo evidence: cbor_tag: {:#x?}, raw_evidence: {:02x?}...({}bytes): {e}",
                        cbor_tag, &raw_evidence[..raw_evidence.len().min(10)], raw_evidence.len()
                    ),
                }
            })?;
            CertEvidence::Evidence(evidence)
        };

        Ok(CertVerifyPendingResult {
            evidence,
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
    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();

    match algo.oid {
        const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
            rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(
                rsa::RsaPublicKey::try_from(spki).map_err(Error::RsaPublicKeyConversionFailed)?,
            )
            .verify(
                signed_data,
                &signature
                    .try_into()
                    .map_err(Error::CertVerifySignatureFailed)?,
            )
            .map_err(Error::CertVerifySignatureFailed)?;
        }
        const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION => {
            rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(
                rsa::RsaPublicKey::try_from(spki).map_err(Error::RsaPublicKeyConversionFailed)?,
            )
            .verify(
                signed_data,
                &signature
                    .try_into()
                    .map_err(Error::CertVerifySignatureFailed)?,
            )
            .map_err(Error::CertVerifySignatureFailed)?;
        }
        const_oid::db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION => {
            rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(
                rsa::RsaPublicKey::try_from(spki).map_err(Error::RsaPublicKeyConversionFailed)?,
            )
            .verify(
                signed_data,
                &signature
                    .try_into()
                    .map_err(Error::CertVerifySignatureFailed)?,
            )
            .map_err(Error::CertVerifySignatureFailed)?;
        }
        const_oid::db::rfc5912::ECDSA_WITH_SHA_256 => {
            let signature = p256::ecdsa::DerSignature::try_from(signature)
                .map_err(Error::CertVerifySignatureFailed)?;
            p256::ecdsa::VerifyingKey::try_from(spki)
                .map_err(Error::P256PublicKeyConversionFailed)?
                .verify(signed_data, &signature)
                .map_err(Error::CertVerifySignatureFailed)?;
        }

        _ => {
            return Err(Error::UnknownSignatureAlgo(
                issuer.tbs_certificate.signature.oid,
            ))
        }
    }

    Ok(())
}

fn extract_ext_with_oid<'a>(cert: &'a Certificate, oid: &ObjectIdentifier) -> Option<&'a [u8]> {
    cert.tbs_certificate.extensions.as_ref().and_then(|exts| {
        let mut it = exts.iter().filter(|ext| ext.extn_id == *oid);
        it.next().map(|ext| ext.extn_value.as_bytes())
    })
}

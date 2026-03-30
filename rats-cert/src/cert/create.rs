use super::dice::cbor::{generate_evidence_buffer_with_tag, generate_pubkey_hash_value_buffer};
use super::dice::generate_and_sign_dice_cert;
use super::CLAIM_NAME_PUBLIC_KEY_HASH;
use crate::crypto::{AsymmetricAlgo, AsymmetricPrivateKey, DefaultCrypto, HashAlgo};
use crate::errors::*;
use crate::tee::claims::Claims;
use crate::tee::GenericEvidence;
use crate::tee::{GenericAttester, ReportData};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use pkcs8::der::{Encode, EncodePem};
use pkcs8::LineEnding;
use x509_cert::Certificate;

pub struct CertBundle<Evidence: GenericEvidence> {
    private_key: AsymmetricPrivateKey,
    cert: Certificate,
    evidence: Evidence,
}

impl<Evidence: GenericEvidence> CertBundle<Evidence> {
    pub fn cert_to_pem(&self) -> Result<String> {
        self.cert
            .to_pem(LineEnding::LF)
            .kind(ErrorKind::GenCertError)
            .context("failed to encode certificate as pem")
    }

    pub fn cert_to_der(&self) -> Result<Vec<u8>> {
        self.cert
            .to_der()
            .kind(ErrorKind::GenCertError)
            .context("failed to encode certificate as der")
    }

    pub fn private_key(&self) -> &AsymmetricPrivateKey {
        &self.private_key
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub fn cert(&self) -> &Certificate {
        &self.cert
    }
}

pub struct CertBuilder<A: GenericAttester> {
    attester: A,
    claims: Option<Claims>,
    subject: String,
    hash_algo: HashAlgo,
}

impl<A: GenericAttester> CertBuilder<A> {
    pub fn new(attester: A, hash_algo: HashAlgo) -> Self {
        Self {
            attester,
            claims: None,
            subject: "CN=rats-rs,O=Inclavare Containers".into(),
            hash_algo,
        }
    }

    pub fn with_claims(mut self, claims: Claims) -> Self {
        self.claims = Some(claims);
        self
    }

    pub fn with_subject(mut self, subject: impl AsRef<str>) -> Self {
        self.subject = subject.as_ref().into();
        self
    }

    pub async fn build(&self, private_key_algo: AsymmetricAlgo) -> Result<CertBundle<A::Evidence>> {
        let key = DefaultCrypto::gen_private_key(private_key_algo)?;
        let (cert, evidence) = self.build_with_private_key_inner(&key).await?;

        Ok(CertBundle {
            private_key: key,
            cert,
            evidence,
        })
    }

    pub async fn build_with_private_key(
        &self,
        key: &AsymmetricPrivateKey,
    ) -> Result<CertBundle<A::Evidence>> {
        let (cert, evidence) = self.build_with_private_key_inner(key).await?;

        Ok(CertBundle {
            private_key: key.clone(),
            cert,
            evidence,
        })
    }

    async fn build_with_private_key_inner(
        &self,
        key: &AsymmetricPrivateKey,
    ) -> Result<(Certificate, A::Evidence)> {
        /* Prepare custom claim `pubkey-hash` and add to claims map */
        let pubkey_hash = DefaultCrypto::hash_of_private_key(self.hash_algo, key)?;
        let pubkey_hash_value_buffer =
            generate_pubkey_hash_value_buffer(self.hash_algo, &pubkey_hash)?;

        let mut claims = match &self.claims {
            Some(claims) => claims.clone(),
            None => Claims::new(),
        };
        // Note: the implementation here is not compatible with the Interoperable RA-TLS now
        claims.insert(
            CLAIM_NAME_PUBLIC_KEY_HASH.into(),
            serde_json::Value::String(BASE64_STANDARD.encode(pubkey_hash_value_buffer)),
        );

        /* Generate evidence buffer */
        let evidence = self
            .attester
            .get_evidence(&ReportData::Claims(claims))
            .await?;
        let evidence_buffer = generate_evidence_buffer_with_tag(
            evidence.get_dice_cbor_tag(),
            &evidence.get_dice_raw_evidence()?,
            &[], // The claims_buffer field is deprecated, put an empty slice here
        )?;

        let cert = generate_and_sign_dice_cert(
            &self.subject,
            self.hash_algo,
            key,
            &evidence_buffer,
            Some(&[]),
        )?;

        Ok((cert, evidence))
    }
}

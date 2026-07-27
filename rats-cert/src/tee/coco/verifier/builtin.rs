use std::sync::Arc;

use rustls_pki_types::CertificateDer;

use super::super::converter::builtin::DEFAULT_POLICY_ID;
use super::super::evidence::{CocoAsToken, CocoEvidence};
use crate::tee::coco::verifier::common::CommonCocoVerifier;
use crate::tee::coco::verifier::token::{AttestationTokenVerifierConfig, TokenVerifier};
use crate::tee::ReportData;
use crate::{errors::*, tee::GenericVerifier};

pub struct BuiltinCocoVerifier {
    inner: CommonCocoVerifier,
}

impl BuiltinCocoVerifier {
    pub async fn new(trusted_certs: Vec<CertificateDer<'static>>) -> Result<Self> {
        let config = AttestationTokenVerifierConfig {
            #[cfg(not(wasm))]
            trusted_certs_paths: Default::default(),
            trusted_certs,
            trusted_jwk_sets: Default::default(),
            as_addr: None,
            as_headers: None,
            insecure_key: true,
            skip_cert_verify: false,
        };

        let token_verifier = TokenVerifier::from_config(config)
            .await
            .map_err(Error::CocoTokenVerifierError)?;

        Ok(Self {
            inner: CommonCocoVerifier {
                token_verifier,
                policy_ids: vec![DEFAULT_POLICY_ID.to_string()],
                // Builtin AS does not support signer transparency verification
                verify_signer_transparency: false,
            },
        })
    }
}

#[cfg_attr(wasm, async_trait::async_trait(?Send))]
#[cfg_attr(not(wasm), async_trait::async_trait)]
impl GenericVerifier for BuiltinCocoVerifier {
    type Evidence = CocoAsToken;

    async fn verify_evidence(
        &self,
        evidence: &Self::Evidence,
        report_data: &ReportData,
    ) -> Result<()> {
        self.inner
            .verify_evidence_internal(evidence, report_data)
            .await
    }
}

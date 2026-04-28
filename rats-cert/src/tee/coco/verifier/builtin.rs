use std::sync::Arc;

use super::super::converter::builtin::DEFAULT_POLICY_ID;
use super::super::evidence::{CocoAsToken, CocoEvidence};
use crate::tee::coco::converter::builtin::AttestationServiceWorkDir;
use crate::tee::coco::verifier::common::CommonCocoVerifier;
use crate::tee::coco::verifier::token::{AttestationTokenVerifierConfig, TokenVerifier};
use crate::tee::ReportData;
use crate::{errors::*, tee::GenericVerifier};

pub struct BuiltinCocoVerifier {
    inner: CommonCocoVerifier,
    #[allow(dead_code)]
    work_dir: Arc<AttestationServiceWorkDir>,
}

impl BuiltinCocoVerifier {
    pub async fn new(
        work_dir: Arc<AttestationServiceWorkDir>,
        verify_signer_transparency: bool,
    ) -> Result<Self> {
        let config = AttestationTokenVerifierConfig {
            trusted_certs_paths: vec![work_dir.cert_chain_path().to_string_lossy().to_string()],
            trusted_jwk_sets: Default::default(),
            as_addr: None,
            as_headers: None,
            insecure_key: true,
        };

        let token_verifier = TokenVerifier::from_config(config)
            .await
            .map_err(Error::CocoTokenVerifierError)?;

        Ok(Self {
            inner: CommonCocoVerifier {
                token_verifier,
                policy_ids: vec![DEFAULT_POLICY_ID.to_string()],
                verify_signer_transparency,
            },
            work_dir,
        })
    }
}

#[async_trait::async_trait]
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

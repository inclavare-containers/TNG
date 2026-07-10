#[cfg(feature = "__builtin-as")]
use std::sync::Arc;

use super::super::converter::builtin_config::DEFAULT_POLICY_ID;
use super::super::evidence::{CocoAsToken, CocoEvidence};
#[cfg(feature = "__builtin-as")]
use crate::tee::coco::converter::builtin::AttestationServiceWorkDir;
use crate::tee::coco::verifier::common::CommonCocoVerifier;
use crate::tee::coco::verifier::token::{AttestationTokenVerifierConfig, TokenVerifier};
use crate::tee::ReportData;
use crate::{errors::*, tee::GenericVerifier};

pub struct BuiltinCocoVerifier {
    inner: CommonCocoVerifier,
    #[cfg(feature = "__builtin-as")]
    #[allow(dead_code)]
    work_dir: Arc<AttestationServiceWorkDir>,
}

impl BuiltinCocoVerifier {
    #[cfg(feature = "__builtin-as")]
    pub async fn new(work_dir: Arc<AttestationServiceWorkDir>) -> Result<Self> {
        let config = AttestationTokenVerifierConfig {
            trusted_certs_paths: vec![work_dir.cert_chain_path().to_string_lossy().to_string()],
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
            work_dir,
        })
    }

    /// Wasm constructor: no filesystem. The converter embeds the AS public JWK in the
    /// JWT header; with `insecure_key: true` the verifier trusts that JWK (closed
    /// system — same TNG instance signs and verifies), mirroring native builtin.
    #[cfg(all(
        feature = "__builtin-as-wasm",
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))]
    pub async fn new_wasm() -> Result<Self> {
        let config = AttestationTokenVerifierConfig {
            trusted_certs_paths: vec![],
            trusted_jwk_sets: vec![],
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
                verify_signer_transparency: false,
            },
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

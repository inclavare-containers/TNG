use super::super::evidence::{CocoAsToken, CocoEvidence};
use crate::cert::verify::AttestationServiceAddrArgs;
use crate::tee::coco::verifier::common::CommonCocoVerifier;
use crate::tee::coco::verifier::token::{AttestationTokenVerifierConfig, TokenVerifier};
use crate::tee::ReportData;
use crate::{errors::*, tee::GenericVerifier};

pub struct CocoVerifier {
    inner: CommonCocoVerifier,
}

impl CocoVerifier {
    pub async fn new(
        as_addr_config: &Option<AttestationServiceAddrArgs>,
        trusted_certs_paths: &Option<Vec<String>>,
        policy_ids: &Vec<String>,
    ) -> Result<Self> {
        if let Some(as_addr_config) = as_addr_config {
            if as_addr_config.as_is_grpc {
                return Err(Error::kind_with_msg(
                    ErrorKind::CocoVerifyTokenFailed,
                    "Grpc is not supported for CoCo AS token verification",
                ));
            }
        }

        let trusted_certs_paths = trusted_certs_paths.clone().unwrap_or_default();

        // Check if any trust source is provided
        let has_trust_source = !trusted_certs_paths.is_empty() || as_addr_config.is_some();

        if !has_trust_source {
            Err(Error::kind_with_msg(
                ErrorKind::CocoVerifyTokenFailed,
                "No trust source provided (neither trusted_certs_paths nor as_addr)".to_string(),
            ))?
        }

        let config = AttestationTokenVerifierConfig {
            trusted_certs_paths,
            trusted_jwk_sets: Default::default(),
            as_addr: as_addr_config.as_ref().map(|config| config.as_addr.clone()),
            as_headers: as_addr_config
                .as_ref()
                .map(|config| config.as_headers.clone()),
            insecure_key: false,
        };

        let token_verifier = TokenVerifier::from_config(config).await?;

        Ok(Self {
            inner: CommonCocoVerifier {
                token_verifier,
                policy_ids: policy_ids.to_owned(),
            },
        })
    }
}

#[async_trait::async_trait]
impl GenericVerifier for CocoVerifier {
    type Evidence = CocoAsToken;

    async fn verify_evidence(
        &self,
        evidence: &Self::Evidence,
        report_data: &ReportData,
    ) -> Result<()> {
        self.inner
            .verify_evidence_internal(evidence, report_data)
            .await
            .context("Failed to verify CoCo AS token")
            .map_err(|e| {
                if e.get_kind() == ErrorKind::Unknown {
                    e.with_kind(ErrorKind::CocoVerifyTokenFailed)
                } else {
                    e
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::{claims::Claims, coco::verifier::remote::CocoVerifier};

    /// Helper function to run JWT verification tests
    async fn run_jwt_verification_test(
        token_str: &str,
        test_name: &str,
        policy_ids: Vec<String>,
        trusted_certs_paths: Option<Vec<String>>,
    ) {
        let token = CocoAsToken::new(token_str.trim().to_string())
            .expect(&format!("Failed to create CocoAsToken from {}", test_name));

        let report_data = ReportData::Claims(Claims::default());

        let verifier = CocoVerifier::new(&None, &trusted_certs_paths, &policy_ids)
            .await
            .expect("Failed to create CocoVerifier");

        let result = verifier.verify_evidence(&token, &report_data).await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_verify_simple_jwt_token() {
        let (_dir, cert_path) = write_pem_to_temp_file(
            include_str!("test_cases/simple.as-ca.pem"),
            "simple.as-ca.pem",
        );

        run_jwt_verification_test(
            include_str!("test_cases/simple.jwt"),
            "Simple JWT",
            vec!["default".to_string()],
            Some(vec![cert_path]),
        )
        .await;
    }

    #[tokio::test]
    async fn test_verify_ear_jwt_token() {
        let (_dir, cert_path) =
            write_pem_to_temp_file(include_str!("test_cases/ear.as-ca.pem"), "ear.as-ca.pem");

        run_jwt_verification_test(
            include_str!("test_cases/ear.jwt"),
            "EAR JWT",
            vec!["default".to_string()],
            Some(vec![cert_path]),
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_simple_jwt_token_policy_id_mismatch() {
        let (_dir, cert_path) = write_pem_to_temp_file(
            include_str!("test_cases/simple.as-ca.pem"),
            "simple.as-ca.pem",
        );

        run_jwt_verification_test(
            include_str!("test_cases/simple.jwt"),
            "Simple JWT with wrong policy_id",
            vec!["non-existent-policy".to_string()],
            Some(vec![cert_path]),
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_ear_jwt_token_policy_id_mismatch() {
        let (_dir, cert_path) =
            write_pem_to_temp_file(include_str!("test_cases/ear.as-ca.pem"), "ear.as-ca.pem");

        run_jwt_verification_test(
            include_str!("test_cases/ear.jwt"),
            "EAR JWT with wrong policy_id",
            vec!["non-existent-policy".to_string()],
            Some(vec![cert_path]),
        )
        .await;
    }

    fn write_pem_to_temp_file(pem: &str, filename: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("to create tempdir for test cert");
        let path = dir.path().join(filename);
        std::fs::write(&path, pem).expect("to write test cert");
        (dir, path.to_string_lossy().into_owned())
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_simple_jwt_token_with_wrong_trusted_cert() {
        let (_dir, wrong_cert_path) =
            write_pem_to_temp_file(include_str!("test_cases/ear.as-ca.pem"), "ear.as-ca.pem");

        run_jwt_verification_test(
            include_str!("test_cases/simple.jwt"),
            "Simple JWT with wrong trusted cert",
            vec!["default".to_string()],
            Some(vec![wrong_cert_path]),
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_ear_jwt_token_with_wrong_trusted_cert() {
        let (_dir, wrong_cert_path) = write_pem_to_temp_file(
            include_str!("test_cases/simple.as-ca.pem"),
            "simple.as-ca.pem",
        );

        run_jwt_verification_test(
            include_str!("test_cases/ear.jwt"),
            "EAR JWT with wrong trusted cert",
            vec!["default".to_string()],
            Some(vec![wrong_cert_path]),
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_simple_jwt_token_with_empty_trusted_certs() {
        run_jwt_verification_test(
            include_str!("test_cases/simple.jwt"),
            "Simple JWT with empty trusted_certs",
            vec!["default".to_string()],
            None,
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_ear_jwt_token_with_empty_trusted_certs() {
        run_jwt_verification_test(
            include_str!("test_cases/ear.jwt"),
            "EAR JWT with empty trusted_certs",
            vec!["default".to_string()],
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn test_verify_ear_with_additional_device_jwt_token() {
        let (_dir, cert_path) = write_pem_to_temp_file(
            include_str!("test_cases/ear_with_additional_device.as-ca.pem"),
            "ear_with_additional_device.as-ca.pem",
        );

        run_jwt_verification_test(
            include_str!("test_cases/ear_with_additional_device.jwt"),
            "EAR JWT with additional device evidence",
            vec!["default".to_string()],
            Some(vec![cert_path]),
        )
        .await;
    }
}

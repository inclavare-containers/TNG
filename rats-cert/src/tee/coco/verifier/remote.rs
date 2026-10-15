use super::super::evidence::{CocoAsToken, CocoEvidence};
use crate::cert::verify::AttestationServiceAddrArgs;
use crate::tee::coco::verifier::common::CommonCocoVerifier;
use crate::tee::coco::verifier::token::{AttestationTokenVerifierConfig, TokenVerifier};
use crate::tee::ReportData;
use crate::{errors::*, tee::GenericVerifier};

pub struct CocoRemoteVerifier {
    inner: CommonCocoVerifier,
}

impl CocoRemoteVerifier {
    pub async fn new(
        as_addr_config: &Option<AttestationServiceAddrArgs>,
        #[cfg(not(wasm))] trusted_certs_paths: &Option<Vec<String>>,
        policy_ids: &Vec<String>,
        verify_signer_transparency: bool,
        skip_as_token_cert_verify: bool,
    ) -> Result<Self> {
        if let Some(as_addr_config) = as_addr_config {
            if as_addr_config.as_is_grpc {
                return Err(Error::RemoteAsGrpcNotSupported);
            }
        }

        #[cfg(not(wasm))]
        let trusted_certs_paths = trusted_certs_paths.clone().unwrap_or_default();

        // Check if any trust source is provided (skip when skip_as_token_cert_verify is true)
        if !skip_as_token_cert_verify {
            #[cfg(not(wasm))]
            let has_trust_source = !trusted_certs_paths.is_empty() || as_addr_config.is_some();
            #[cfg(wasm)]
            let has_trust_source = as_addr_config.is_some();
            if !has_trust_source {
                Err(Error::NoTrustSource)?
            }
        }

        // An explicitly pinned CA is authoritative. Mainline Trustee does not
        // implement the OpenAnolis-only /certificate discovery endpoint.
        #[cfg(not(wasm))]
        let pinned_certificates = !trusted_certs_paths.is_empty();
        #[cfg(wasm)]
        let pinned_certificates = false;
        let config = AttestationTokenVerifierConfig {
            #[cfg(not(wasm))]
            trusted_certs_paths,
            trusted_certs: Default::default(),
            trusted_jwk_sets: Default::default(),
            as_addr: if skip_as_token_cert_verify || pinned_certificates {
                // Discovery is unnecessary with explicit roots or when skipped.
                None
            } else {
                as_addr_config.as_ref().map(|config| config.as_addr.clone())
            },
            as_headers: if skip_as_token_cert_verify {
                None
            } else {
                as_addr_config
                    .as_ref()
                    .map(|config| config.as_headers.clone())
            },
            insecure_key: false,
            skip_cert_verify: skip_as_token_cert_verify,
        };

        let token_verifier = TokenVerifier::from_config(config)
            .await
            .map_err(Error::CocoTokenVerifierError)?;

        Ok(Self {
            inner: CommonCocoVerifier {
                token_verifier,
                policy_ids: policy_ids.to_owned(),
                verify_signer_transparency,
            },
        })
    }
}

#[cfg_attr(wasm, async_trait::async_trait(?Send))]
#[cfg_attr(not(wasm), async_trait::async_trait)]
impl GenericVerifier for CocoRemoteVerifier {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::{claims::Claims, coco::verifier::remote::CocoRemoteVerifier};

    #[cfg(not(wasm))]
    #[tokio::test]
    async fn pinned_roots_do_not_require_certificate_discovery() {
        use std::time::Duration;

        let (_dir, cert_path) = write_pem_to_temp_file(
            include_str!("test_cases/simple.as-ca.pem"),
            "simple.as-ca.pem",
        )
        .await;
        // A service may appraise evidence without implementing /certificate.
        // Hold the socket open: an unexpected discovery request must time out.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = Some(AttestationServiceAddrArgs {
            as_addr: format!("http://{}", listener.local_addr().unwrap()),
            as_is_grpc: false,
            as_headers: Default::default(),
        });
        let verifier = tokio::time::timeout(
            Duration::from_secs(1),
            CocoRemoteVerifier::new(
                &address,
                &Some(vec![cert_path]),
                &vec!["default".to_string()],
                false,
                false,
            ),
        )
        .await
        .expect("explicit roots must not contact /certificate")
        .expect("load the pinned root");

        let report_data = ReportData::Claims(Claims::default());
        let approved =
            CocoAsToken::new(include_str!("test_cases/simple.jwt").trim().into()).unwrap();
        verifier
            .verify_evidence(&approved, &report_data)
            .await
            .unwrap();
        let unrelated = CocoAsToken::new(include_str!("test_cases/ear.jwt").trim().into()).unwrap();
        assert!(verifier
            .verify_evidence(&unrelated, &report_data)
            .await
            .is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[cfg(not(wasm))]
    #[tokio::test]
    async fn empty_roots_still_require_certificate_discovery() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = Some(AttestationServiceAddrArgs {
            as_addr: format!("http://{}", listener.local_addr().unwrap()),
            as_is_grpc: false,
            as_headers: Default::default(),
        });
        let server = async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut request = String::new();
            stream.read_line(&mut request).await.unwrap();
            assert!(request.starts_with("GET /certificate "));
            stream
                .get_mut()
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        };
        let roots = Some(vec![]);
        let policies = vec![];
        let verify = CocoRemoteVerifier::new(&address, &roots, &policies, false, false);
        let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(verify, server)
        })
        .await
        .expect("certificate discovery should finish");
        assert!(result.is_err());
    }

    /// Helper function to run JWT verification tests
    async fn run_jwt_verification_test(
        token_str: &str,
        test_name: &str,
        policy_ids: Vec<String>,
        trusted_certs_paths: Option<Vec<String>>,
    ) {
        let token = CocoAsToken::new(token_str.trim().to_string())
            .unwrap_or_else(|_| panic!("Failed to create CocoAsToken from {}", test_name));

        let report_data = ReportData::Claims(Claims::default());

        let verifier =
            CocoRemoteVerifier::new(&None, &trusted_certs_paths, &policy_ids, false, false)
                .await
                .expect("Failed to create CocoRemoteVerifier");

        let result = verifier.verify_evidence(&token, &report_data).await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_verify_simple_jwt_token() {
        let (_dir, cert_path) = write_pem_to_temp_file(
            include_str!("test_cases/simple.as-ca.pem"),
            "simple.as-ca.pem",
        )
        .await;

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
            write_pem_to_temp_file(include_str!("test_cases/ear.as-ca.pem"), "ear.as-ca.pem").await;

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
        )
        .await;

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
            write_pem_to_temp_file(include_str!("test_cases/ear.as-ca.pem"), "ear.as-ca.pem").await;

        run_jwt_verification_test(
            include_str!("test_cases/ear.jwt"),
            "EAR JWT with wrong policy_id",
            vec!["non-existent-policy".to_string()],
            Some(vec![cert_path]),
        )
        .await;
    }

    async fn write_pem_to_temp_file(pem: &str, filename: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("to create tempdir for test cert");
        let path = dir.path().join(filename);
        tokio::fs::write(&path, pem)
            .await
            .expect("to write test cert");
        (dir, path.to_string_lossy().into_owned())
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_simple_jwt_token_with_wrong_trusted_cert() {
        let (_dir, wrong_cert_path) =
            write_pem_to_temp_file(include_str!("test_cases/ear.as-ca.pem"), "ear.as-ca.pem").await;

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
        )
        .await;

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
        )
        .await;

        run_jwt_verification_test(
            include_str!("test_cases/ear_with_additional_device.jwt"),
            "EAR JWT with additional device evidence",
            vec!["default".to_string()],
            Some(vec![cert_path]),
        )
        .await;
    }

    #[tokio::test]
    async fn test_verify_jwt_with_skip_cert_verify() {
        // When skip_as_token_cert_verify is true, the verifier should
        // accept tokens without any trusted certs or AS address
        let token = CocoAsToken::new(include_str!("test_cases/simple.jwt").trim().to_string())
            .expect("Failed to create CocoAsToken");

        let report_data = ReportData::Claims(Claims::default());

        // Create verifier with skip=true, no certs, no as_addr
        let verifier = CocoRemoteVerifier::new(
            &None,
            &None,
            &vec!["default".to_string()],
            false,
            true, // skip_as_token_cert_verify
        )
        .await
        .expect("Failed to create CocoRemoteVerifier with skip=true");

        // Should succeed - token signature is still verified using embedded JWK
        let result = verifier.verify_evidence(&token, &report_data).await;
        assert!(
            result.is_ok(),
            "should succeed with skip_cert_verify: {result:?}"
        );
    }
}

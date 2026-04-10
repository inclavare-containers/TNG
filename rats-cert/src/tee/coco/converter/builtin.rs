//! Builtin Attestation Service Converter
//!
//! This module implements local evidence verification using the embedded attestation-service crate.
//! It converts CocoEvidence to CocoAsToken by running attestation-service in-process.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use attestation_service::rvps::{RvpsConfig, RvpsCrateConfig};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use reference_value_provider_service::extractors::extractor_modules::sample::Provenance;
use reference_value_provider_service::rv_list::ReferenceValueListPayload;
use reference_value_provider_service::storage::{local_json, ReferenceValueStorageConfig};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tempfile::TempDir;
use tokio::sync::RwLock;

use attestation_service::{
    config::Config,
    token::{ear_broker, AttestationTokenConfig},
    AttestationService, HashAlgorithm, Tee,
};

use super::super::evidence::{AttestationServiceHashAlgo, CocoAsToken, CocoEvidence};
use super::convert_additional_evidence;
use crate::errors::*;
use crate::tee::coco::converter::CoCoNonce;
use crate::tee::coco::verifier::builtin::BuiltinCocoVerifier;
use crate::tee::GenericConverter;

/// Default policy ID used by builtin AS
pub const DEFAULT_POLICY_ID: &str = "default";

/// Certificate validity period in days (10 years)
const CERT_VALIDITY_DAYS: i64 = 365 * 10;

/// Working directory for builtin Attestation Service
///
/// This struct manages the lifecycle of a temporary directory used by the
/// attestation service, including generated certificates for token signing.
/// The directory and all its contents are automatically cleaned up when dropped.
pub struct AttestationServiceWorkDir {
    /// Temporary directory (cleaned up on drop)
    temp_dir: TempDir,
    /// Path to the certificate chain file (AS cert + CA cert)
    cert_chain_path: PathBuf,
    /// Path to the AS private key file
    key_path: PathBuf,
}

impl AttestationServiceWorkDir {
    /// Create a new working directory with generated certificates
    async fn new() -> Result<Self> {
        let temp_dir =
            tempfile::tempdir().map_err(Error::BuilinAttestationServiceCreateWorkDirFailed)?;

        let (cert_chain_path, key_path) = Self::generate_certificates(temp_dir.path()).await?;

        tracing::debug!(work_dir = ?temp_dir.path(), "Created builtin AS working directory");

        Ok(Self {
            temp_dir,
            cert_chain_path,
            key_path,
        })
    }

    /// Get the path to the working directory
    fn path(&self) -> &Path {
        self.temp_dir.path()
    }

    /// Get the path to the certificate chain file
    pub fn cert_chain_path(&self) -> &Path {
        &self.cert_chain_path
    }

    /// Get the path to the private key file
    fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// Generate CA and AS certificates using rcgen
    async fn generate_certificates(work_dir: &Path) -> Result<(PathBuf, PathBuf)> {
        // Generate CA key pair
        let ca_key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(Error::CaCertGenerationFailed)?;

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
        let as_key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(Error::AsCertGenerationFailed)?;

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

        // Write AS private key
        let key_path = work_dir.join("as.key");
        tokio::fs::write(&key_path, as_key_pair.serialize_pem())
            .await
            .map_err(|e| Error::WriteAsPrivateKeyFailed {
                path: key_path.to_string_lossy().to_string(),
                source: e,
            })?;

        // Write certificate chain (AS cert + CA cert)
        let cert_chain_path = work_dir.join("as-chain.pem");
        let cert_chain = format!("{}{}", as_cert.pem(), ca_cert.pem());
        tokio::fs::write(&cert_chain_path, cert_chain)
            .await
            .map_err(|e| Error::WriteCertChainFailed {
                path: cert_chain_path.to_string_lossy().to_string(),
                source: e,
            })?;

        Ok((cert_chain_path, key_path))
    }
}

/// Configuration for policy loading
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyConfig {
    /// Use the attestation-service default policy.
    /// The default policy performs comprehensive measurements of TEE hardware and software.
    /// See: https://github.com/openanolis/trustee/blob/7a6a7b8a2554295bcd296963d353761eaf4f70eb/attestation-service/src/token/ear_default_policy_cpu.rego
    #[default]
    Default,
    /// Base64 encoded policy content
    Inline { content: String },
    /// Path to policy file
    Path { path: String },
}

/// Configuration for sample provenance payload loading
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SampleProvenancePayloadConfig {
    /// Inline JSON content (Provenance)
    Inline { content: Provenance },
    /// Path to payload file
    Path { path: String },
}

/// Configuration for SLSA reference value payload loading
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SlsaReferenceValuePayloadConfig {
    /// Inline JSON content (ReferenceValueListPayload)
    Inline { content: ReferenceValueListPayload },
    /// Path to payload file
    Path { path: String },
}

/// Configuration for reference values
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReferenceValueConfig {
    /// Sample reference values (inline or from file)
    Sample {
        payload: SampleProvenancePayloadConfig,
    },
    /// SLSA-based reference values from Rekor
    Slsa {
        payload: SlsaReferenceValuePayloadConfig,
    },
}

/// Builtin CoCo Converter
///
/// Converts CocoEvidence to CocoAsToken using an embedded attestation-service instance.
/// This provides local evidence verification without requiring a remote AS.
pub struct BuiltinCocoConverter {
    /// Embedded attestation service instance
    ///
    /// Note the attestation service is boxed to save the stack space and avoid large memory copy.
    attestation_service: Box<AttestationService>,

    /// Working directory for attestation service (cleaned up on drop)
    #[allow(dead_code)]
    work_dir: Arc<AttestationServiceWorkDir>,
}

impl BuiltinCocoConverter {
    /// Create a new BuiltinCocoConverter with the given policy and reference values
    pub async fn new(
        policy: &PolicyConfig,
        reference_values: &[ReferenceValueConfig],
    ) -> Result<Self> {
        // Create a working directory with generated certificates
        let work_dir = Arc::new(AttestationServiceWorkDir::new().await?);

        // Create AS config with token signer configuration
        let config = Config {
            work_dir: work_dir.path().to_owned(),
            rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig {
                storage: ReferenceValueStorageConfig::LocalJson(local_json::Config {
                    file_path: work_dir
                        .path()
                        .join("reference_values.json")
                        .to_string_lossy()
                        .to_string(),
                }),
            }),
            attestation_token_broker: AttestationTokenConfig::Ear(ear_broker::Configuration {
                signer: Some(ear_broker::TokenSignerConfig {
                    key_path: work_dir.key_path().to_string_lossy().to_string(),
                    cert_url: None,
                    cert_path: Some(work_dir.cert_chain_path().to_string_lossy().to_string()),
                }),
                policy_dir: work_dir
                    .path()
                    .join("token/ear/policies")
                    .to_string_lossy()
                    .to_string(),
                ..Default::default()
            }),
        };

        // Create AttestationService instance
        let mut attestation_service = Box::new(
            AttestationService::new(config)
                .await
                .map_err(Error::AttestationServiceCreateFailed)?,
        );

        // Load policy (skip to use AS built-in default policy for Default)
        if let Some(policy_content) = Self::load_policy_as_base64_url_safe_no_pad(policy).await? {
            attestation_service
                .set_policy(DEFAULT_POLICY_ID.to_string(), policy_content)
                .await
                .map_err(Error::AttestationServiceSetPolicyFailed)?;
        }

        // Load reference values
        Self::load_reference_values(&mut attestation_service, reference_values).await?;

        Ok(Self {
            attestation_service,
            work_dir,
        })
    }

    /// Load policy from configuration
    /// Returns None for Default policy (use AS built-in default)
    async fn load_policy_as_base64_url_safe_no_pad(
        policy: &PolicyConfig,
    ) -> Result<Option<String>> {
        match policy {
            PolicyConfig::Default => Ok(None),
            PolicyConfig::Inline { content } => {
                // Decode base64 encoded policy
                let decoded = BASE64_STANDARD
                    .decode(content)
                    .map_err(Error::DecodePolicyContentFailed)?;
                Ok(Some(URL_SAFE_NO_PAD.encode(decoded)))
            }
            PolicyConfig::Path { path } => {
                let content_str = tokio::fs::read_to_string(path).await.map_err(|e| {
                    Error::ReadPolicyFileFailed {
                        path: path.clone(),
                        source: e,
                    }
                })?;
                Ok(Some(URL_SAFE_NO_PAD.encode(content_str)))
            }
        }
    }

    /// Load reference values from configuration
    async fn load_reference_values(
        attestation_service: &mut AttestationService,
        reference_values: &[ReferenceValueConfig],
    ) -> Result<()> {
        for rv in reference_values {
            match rv {
                ReferenceValueConfig::Sample { payload } => {
                    let provenance = match payload {
                        SampleProvenancePayloadConfig::Inline { content } => Ok(content.clone()),
                        SampleProvenancePayloadConfig::Path { path } => {
                            let content_str =
                                tokio::fs::read_to_string(path).await.map_err(|e| {
                                    Error::ReadReferenceValueFileFailed {
                                        path: path.clone(),
                                        source: e,
                                    }
                                })?;
                            serde_json::from_str(&content_str).map_err(|e| {
                                Error::ParseReferenceValuePayloadFailed {
                                    path: path.clone(),
                                    source: e,
                                }
                            })
                        }
                    }?;
                    let provenance_base64 = base64::engine::general_purpose::STANDARD.encode(
                        serde_json::to_vec(&provenance)
                            .map_err(Error::SerializeProvenanceFailed)?,
                    );

                    #[derive(Serialize)]
                    struct RvpsMessage<'a> {
                        #[serde(skip_serializing_if = "Option::is_none")]
                        version: Option<&'a str>,
                        #[serde(rename = "type")]
                        provenance_type: &'a str,
                        payload: String,
                    }

                    let message = RvpsMessage {
                        version: Some("0.1.0"),
                        provenance_type: "sample",
                        payload: provenance_base64,
                    };
                    let rvps_message = serde_json::to_string(&message)
                        .map_err(Error::SerializeReferenceValueMessageFailed)?;
                    attestation_service
                        .register_reference_value(&rvps_message)
                        .await
                        .map_err(Error::RegisterSampleReferenceValueFailed)?;
                }
                ReferenceValueConfig::Slsa { payload } => {
                    let payload_value = match payload {
                        SlsaReferenceValuePayloadConfig::Inline { content } => content.clone(),
                        SlsaReferenceValuePayloadConfig::Path { path } => {
                            let content_str =
                                tokio::fs::read_to_string(path).await.map_err(|e| {
                                    Error::ReadReferenceValueFileFailed {
                                        path: path.clone(),
                                        source: e,
                                    }
                                })?;
                            serde_json::from_str::<ReferenceValueListPayload>(&content_str)
                                .map_err(|e| Error::ParseReferenceValuePayloadFailed {
                                    path: path.clone(),
                                    source: e,
                                })?
                        }
                    };

                    let payload_str = serde_json::to_string(&payload_value)
                        .map_err(Error::SerializeSlsaReferenceValueListFailed)?;
                    attestation_service
                        .set_reference_value_list(&payload_str)
                        .await
                        .map_err(Error::SetSlsaReferenceValueListFailed)?;
                }
            }
        }
        Ok(())
    }

    /// Convert hash algorithm to attestation-service HashAlgorithm
    fn hash_algo_to_as(hash_algo: &AttestationServiceHashAlgo) -> HashAlgorithm {
        match hash_algo {
            AttestationServiceHashAlgo::Sha256 => HashAlgorithm::Sha256,
            AttestationServiceHashAlgo::Sha384 => HashAlgorithm::Sha384,
            AttestationServiceHashAlgo::Sha512 => HashAlgorithm::Sha512,
        }
    }

    pub async fn new_verifier(&self) -> Result<BuiltinCocoVerifier> {
        BuiltinCocoVerifier::new(self.work_dir.clone()).await
    }
}

#[async_trait::async_trait]
impl GenericConverter for BuiltinCocoConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;
    type Nonce = CoCoNonce;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        tracing::debug!("Convert CoCo evidence to CoCo AS token via builtin-as");

        // Get TEE type from evidence (kbs_types::Tee is compatible with attestation_service::Tee)
        let tee = in_evidence.get_tee_type();

        // Get hash algorithm
        let hash_algo =
            AttestationServiceHashAlgo::from(in_evidence.get_aa_runtime_data_hash_algo());
        let hash_algorithm = Self::hash_algo_to_as(&hash_algo);

        // Parse runtime data as JSON
        let runtime_data: serde_json::Value =
            serde_json::from_str(in_evidence.aa_runtime_data_ref())
                .map_err(Error::ParseRuntimeDataJsonFailed)?;

        // Build verification requests
        let mut verification_requests = vec![attestation_service::VerificationRequest {
            evidence: serde_json::from_slice(in_evidence.aa_evidence_ref())
                .map_err(Error::ParseEvidenceFromBytesFailed)?,
            tee: *tee,
            runtime_data: Some(attestation_service::RuntimeData::Structured(runtime_data)),
            runtime_data_hash_algorithm: hash_algorithm,
            init_data: None,
            additional_data: None,
        }];

        // Add additional evidence if present
        for (tee_type, evidence) in convert_additional_evidence(in_evidence)? {
            verification_requests.push(attestation_service::VerificationRequest {
                evidence,
                tee: tee_type,
                runtime_data: None,
                runtime_data_hash_algorithm: HashAlgorithm::Sha256,
                init_data: None,
                additional_data: None,
            });
        }

        // Evaluate evidence
        let token = self
            .attestation_service
            .evaluate(verification_requests, vec![DEFAULT_POLICY_ID.to_owned()])
            .await
            .map_err(Error::AttestationServiceVerifyFailed)?;

        CocoAsToken::new(token)
    }

    async fn get_nonce(&self) -> Result<Self::Nonce> {
        // Generate a challenge nonce for the attestation
        self.attestation_service
            .generate_challenge(None, None)
            .await
            .map_err(Error::AttestationServiceGenerateChallengeFailed)
            .map(CoCoNonce::Jwt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use reference_value_provider_service::rv_list::{
        ReferenceValueListItem, ReferenceValueProvenanceInfo, ReferenceValueProvenanceSource,
    };
    use serial_test::serial;

    #[tokio::test]
    async fn test_load_inline_policy() {
        // Base64 encoded policy with EAR claims
        let policy_content = r#"package policy

default executables := 3
default hardware := 2
default configuration := 2
default file_system := 2"#;
        let policy_b64 = base64::engine::general_purpose::STANDARD.encode(policy_content);
        let policy_config = PolicyConfig::Inline {
            content: policy_b64,
        };

        let result =
            BuiltinCocoConverter::load_policy_as_base64_url_safe_no_pad(&policy_config).await;
        assert!(result.is_ok());
        let encoded_content = result
            .unwrap()
            .expect("Should return Some for Inline policy");
        // Decode the URL_SAFE_NO_PAD encoded content to verify
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded_content)
            .expect("Failed to decode policy");
        let content = String::from_utf8(decoded).expect("Invalid UTF-8");
        assert!(content.contains("package policy"));
        assert!(content.contains("default executables"));
    }

    #[tokio::test]
    async fn test_load_default_policy() {
        let policy_config = PolicyConfig::Default;
        let result =
            BuiltinCocoConverter::load_policy_as_base64_url_safe_no_pad(&policy_config).await;
        assert!(result.is_ok());
        assert!(
            result.unwrap().is_none(),
            "Default policy should return None"
        );
    }

    #[tokio::test]
    async fn test_attestation_service_work_dir_creation() {
        let work_dir = AttestationServiceWorkDir::new()
            .await
            .expect("Failed to create work dir");

        // Verify directory exists
        assert!(work_dir.path().exists());
        assert!(work_dir.path().is_dir());

        // Verify certificate files exist
        assert!(work_dir.cert_chain_path().exists());
        assert!(work_dir.key_path().exists());

        // Verify file names
        assert_eq!(
            work_dir.cert_chain_path().file_name().unwrap(),
            "as-chain.pem"
        );
        assert_eq!(work_dir.key_path().file_name().unwrap(), "as.key");
    }

    #[tokio::test]
    async fn test_attestation_service_work_dir_cert_chain_valid_pem() {
        let work_dir = AttestationServiceWorkDir::new()
            .await
            .expect("Failed to create work dir");

        // Read certificate chain
        let cert_chain_pem = tokio::fs::read_to_string(work_dir.cert_chain_path())
            .await
            .expect("Failed to read cert chain");

        // Verify it contains two PEM blocks (AS cert + CA cert)
        let cert_count = cert_chain_pem
            .matches("-----BEGIN CERTIFICATE-----")
            .count();
        assert_eq!(
            cert_count, 2,
            "Certificate chain should contain 2 certificates"
        );

        let end_count = cert_chain_pem.matches("-----END CERTIFICATE-----").count();
        assert_eq!(end_count, 2, "Certificate chain should have 2 END markers");
    }

    #[tokio::test]
    async fn test_attestation_service_work_dir_key_valid_pem() {
        let work_dir = AttestationServiceWorkDir::new()
            .await
            .expect("Failed to create work dir");

        // Read private key
        let key_pem = tokio::fs::read_to_string(work_dir.key_path())
            .await
            .expect("Failed to read key");

        // Verify it's a valid PEM private key
        assert!(
            key_pem.contains("-----BEGIN PRIVATE KEY-----"),
            "Key should be PKCS#8 PEM format"
        );
        assert!(
            key_pem.contains("-----END PRIVATE KEY-----"),
            "Key should have END marker"
        );
    }

    #[tokio::test]
    async fn test_attestation_service_work_dir_cleanup_on_drop() {
        let path;
        let cert_path;
        let key_path;

        {
            let work_dir = AttestationServiceWorkDir::new()
                .await
                .expect("Failed to create work dir");
            path = work_dir.path().to_path_buf();
            cert_path = work_dir.cert_chain_path().to_path_buf();
            key_path = work_dir.key_path().to_path_buf();

            // Verify files exist before drop
            assert!(path.exists());
            assert!(cert_path.exists());
            assert!(key_path.exists());
        }
        // work_dir is dropped here

        // Verify directory and files are cleaned up
        assert!(
            !path.exists(),
            "Work directory should be cleaned up on drop"
        );
        assert!(
            !cert_path.exists(),
            "Cert chain should be cleaned up on drop"
        );
        assert!(!key_path.exists(), "Key file should be cleaned up on drop");
    }

    #[tokio::test]
    async fn test_attestation_service_work_dir_unique_paths() {
        let work_dir1 = AttestationServiceWorkDir::new()
            .await
            .expect("Failed to create work dir 1");
        let work_dir2 = AttestationServiceWorkDir::new()
            .await
            .expect("Failed to create work dir 2");

        // Each instance should have unique paths
        assert_ne!(work_dir1.path(), work_dir2.path());
        assert_ne!(work_dir1.cert_chain_path(), work_dir2.cert_chain_path());
        assert_ne!(work_dir1.key_path(), work_dir2.key_path());
    }

    // === Reference value loading tests ===

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_sample_inline_reference() {
        let mut rvs = std::collections::HashMap::new();
        rvs.insert("example-measurement".to_string(), vec![]);
        let provenance = Provenance { rvs };
        let reference = ReferenceValueConfig::Sample {
            payload: SampleProvenancePayloadConfig::Inline {
                content: provenance,
            },
        };
        let result = BuiltinCocoConverter::new(&PolicyConfig::Default, &[reference]).await;
        assert!(
            result.is_ok(),
            "Failed to create converter with inline sample reference: {:?}",
            result.err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_sample_path_reference() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let ref_path = dir.path().join("ref.json");
        tokio::fs::write(&ref_path, r#"{"example-component":["value1", "value2"]}"#)
            .await
            .expect("Failed to write ref file");

        let reference = ReferenceValueConfig::Sample {
            payload: SampleProvenancePayloadConfig::Path {
                path: ref_path.to_string_lossy().to_string(),
            },
        };
        BuiltinCocoConverter::new(&PolicyConfig::Default, &[reference])
            .await
            .expect("Failed to create converter with path sample reference");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_slsa_reference_and_provenance() {
        let rv_item = ReferenceValueListItem {
            id: "test-artifact".to_string(),
            version: "1.0.0".to_string(),
            rv_type: "binary".to_string(),
            provenance_info: ReferenceValueProvenanceInfo {
                provenance_type: "slsa-intoto-statements".to_string(),
                rekor_url: "https://log2025-1.rekor.sigstore.dev".to_string(),
                rekor_api_version: Some(2),
            },
            provenance_source: Some(ReferenceValueProvenanceSource {
                protocol: "oci".to_string(),
                uri: "oci://127.0.0.1:5000/trustee/provenance:test-artifact-1.0.0".to_string(),
                artifact: Some("bundle".to_string()),
            }),
            operation_type: "refresh".to_string(),
            rv_name: None,
        };
        let payload = ReferenceValueListPayload {
            rv_list: vec![rv_item],
        };

        let reference = ReferenceValueConfig::Slsa {
            payload: SlsaReferenceValuePayloadConfig::Inline { content: payload },
        };
        BuiltinCocoConverter::new(&PolicyConfig::Default, &[reference])
            .await
            .expect("Failed to create converter with path slsa reference");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_multiple_references() {
        let mut rvs1 = std::collections::HashMap::new();
        rvs1.insert("component-a".to_string(), vec![]);
        let provenance1 = Provenance { rvs: rvs1 };

        let mut rvs2 = std::collections::HashMap::new();
        rvs2.insert("component-b".to_string(), vec![]);
        let provenance2 = Provenance { rvs: rvs2 };

        let references = vec![
            ReferenceValueConfig::Sample {
                payload: SampleProvenancePayloadConfig::Inline {
                    content: provenance1,
                },
            },
            ReferenceValueConfig::Sample {
                payload: SampleProvenancePayloadConfig::Inline {
                    content: provenance2,
                },
            },
        ];
        let result = BuiltinCocoConverter::new(&PolicyConfig::Default, &references).await;
        assert!(
            result.is_ok(),
            "Failed with multiple references: {:?}",
            result.err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_empty_references() {
        BuiltinCocoConverter::new(&PolicyConfig::Default, &[])
            .await
            .expect("Failed with empty references");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_error_sample_path_not_found() {
        let reference = ReferenceValueConfig::Sample {
            payload: SampleProvenancePayloadConfig::Path {
                path: "/nonexistent/reference_values.json".to_string(),
            },
        };
        let result = BuiltinCocoConverter::new(&PolicyConfig::Default, &[reference]).await;
        assert!(
            result.is_err(),
            "Should fail with nonexistent reference path"
        );
    }

    // === ReferenceValueConfig serialization/deserialization tests ===

    #[test]
    fn test_reference_value_config_sample_inline_serde() -> Result<(), serde_json::Error> {
        // Create a Provenance for testing
        let mut rvs = std::collections::HashMap::new();
        rvs.insert(
            "my-component".to_string(),
            vec![
                "expected-value-1".to_string(),
                "expected-value-2".to_string(),
            ],
        );
        let provenance = Provenance { rvs };

        let config = ReferenceValueConfig::Sample {
            payload: SampleProvenancePayloadConfig::Inline {
                content: provenance,
            },
        };

        // Serialize to JSON
        let json_str = serde_json::to_string(&config).expect("Failed to serialize");
        assert!(json_str.contains("\"type\":\"sample\""));
        assert!(json_str.contains("\"type\":\"inline\""));
        assert!(json_str.contains("my-component"));

        // Deserialize back
        let deserialized: ReferenceValueConfig =
            serde_json::from_str(&json_str).expect("Failed to deserialize");
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(deserialized)?
        );

        Ok(())
    }

    #[test]
    fn test_reference_value_config_sample_path_serde() -> Result<(), serde_json::Error> {
        let config = ReferenceValueConfig::Sample {
            payload: SampleProvenancePayloadConfig::Path {
                path: "/path/to/provenance.json".to_string(),
            },
        };

        let json_str = serde_json::to_string(&config).expect("Failed to serialize");
        assert!(json_str.contains("\"type\":\"sample\""));
        assert!(json_str.contains("\"type\":\"path\""));
        assert!(json_str.contains("/path/to/provenance.json"));

        let deserialized: ReferenceValueConfig =
            serde_json::from_str(&json_str).expect("Failed to deserialize");
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(deserialized)?
        );
        Ok(())
    }

    #[test]
    fn test_reference_value_config_slsa_inline_serde() -> Result<(), serde_json::Error> {
        // Create a ReferenceValueListPayload for testing
        let rv_item = ReferenceValueListItem {
            id: "test-artifact".to_string(),
            version: "1.0.0".to_string(),
            rv_type: "binary".to_string(),
            provenance_info: ReferenceValueProvenanceInfo {
                provenance_type: "slsa-intoto-statements".to_string(),
                rekor_url: "https://log2025-1.rekor.sigstore.dev".to_string(),
                rekor_api_version: Some(2),
            },
            provenance_source: Some(ReferenceValueProvenanceSource {
                protocol: "oci".to_string(),
                uri: "oci://127.0.0.1:5000/trustee/provenance:test-artifact-1.0.0".to_string(),
                artifact: Some("bundle".to_string()),
            }),
            operation_type: "refresh".to_string(),
            rv_name: None,
        };
        let payload = ReferenceValueListPayload {
            rv_list: vec![rv_item],
        };

        let config = ReferenceValueConfig::Slsa {
            payload: SlsaReferenceValuePayloadConfig::Inline { content: payload },
        };

        let json_str = serde_json::to_string(&config).expect("Failed to serialize");
        assert!(json_str.contains("\"type\":\"slsa\""));
        assert!(json_str.contains("\"type\":\"inline\""));
        assert!(json_str.contains("\"rv_list\""));
        assert!(json_str.contains("test-artifact"));

        let deserialized: ReferenceValueConfig =
            serde_json::from_str(&json_str).expect("Failed to deserialize");
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(deserialized)?
        );
        Ok(())
    }

    #[test]
    fn test_reference_value_config_slsa_path_serde() -> Result<(), serde_json::Error> {
        let config = ReferenceValueConfig::Slsa {
            payload: SlsaReferenceValuePayloadConfig::Path {
                path: "/path/to/slsa_payload.json".to_string(),
            },
        };

        let json_str = serde_json::to_string(&config).expect("Failed to serialize");
        assert!(json_str.contains("\"type\":\"slsa\""));
        assert!(json_str.contains("\"type\":\"path\""));
        assert!(json_str.contains("/path/to/slsa_payload.json"));

        let deserialized: ReferenceValueConfig =
            serde_json::from_str(&json_str).expect("Failed to deserialize");
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(deserialized)?
        );
        Ok(())
    }

    #[test]
    fn test_reference_value_config_deserialize_from_json() {
        // Test deserializing Sample inline from raw JSON
        let sample_json = r#"{
            "type": "sample",
            "payload": {
                "type": "inline",
                "content": {"example-key": ["expected-value"]}
            }
        }"#;
        let config: ReferenceValueConfig =
            serde_json::from_str(sample_json).expect("Failed to parse");
        match config {
            ReferenceValueConfig::Sample { payload } => match payload {
                SampleProvenancePayloadConfig::Inline { content } => {
                    // Provenance uses flattened HashMap, verify it has the expected key
                    assert!(content.rvs.get("example-key").is_some());
                }
                _ => panic!("Expected Inline payload"),
            },
            _ => panic!("Expected Sample variant"),
        }

        // Test deserializing SLSA inline from raw JSON
        let slsa_json = r#"{
            "type": "slsa",
            "payload": {
                "type": "inline",
                "content": {
                    "rv_list": [{
                        "id": "test-artifact",
                        "version": "1.0.0",
                        "type": "binary",
                        "provenance_info": {
                            "type": "slsa-intoto-statements",
                            "rekor_url": "https://log2025-1.rekor.sigstore.dev",
                            "rekor_api_version": 2
                        },
                        "provenance_source": {
                            "protocol": "oci",
                            "uri": "oci://127.0.0.1:5000/trustee/provenance:test-artifact-1.0.0",
                            "artifact": "bundle"
                        },
                        "operation_type": "refresh"
                    }]
                }
            }
        }"#;
        let config: ReferenceValueConfig =
            serde_json::from_str(slsa_json).expect("Failed to parse");
        match config {
            ReferenceValueConfig::Slsa { payload } => match payload {
                SlsaReferenceValuePayloadConfig::Inline { content } => {
                    assert_eq!(content.rv_list.len(), 1);
                    assert_eq!(content.rv_list[0].id, "test-artifact");
                }
                _ => panic!("Expected Inline payload"),
            },
            _ => panic!("Expected Slsa variant"),
        }
    }

    // === Full convert flow tests ===

    #[cfg(feature = "attester-coco")]
    mod convert_flow_tests {
        use super::*;
        use crate::tee::coco::attester::CocoAttester;
        use crate::tee::{GenericAttester, GenericConverter, GenericVerifier, ReportData};
        use base64::Engine;
        use serial_test::serial;

        const TEST_AA_ADDR: &str =
            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_builtin_convert_with_default_policy() {
            let converter = BuiltinCocoConverter::new(&PolicyConfig::Default, &[])
                .await
                .expect("Failed to create converter");
            let attester = CocoAttester::new(TEST_AA_ADDR).expect("Failed to create attester");
            let report_data = ReportData::Claims(serde_json::Map::new());
            let evidence = attester
                .get_evidence(&report_data)
                .await
                .expect("Failed to get evidence");
            let token = converter.convert(&evidence).await;
            assert!(token.is_ok(), "Convert failed: {:?}", token.err());
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_builtin_convert_with_inline_policy() {
            let policy_content = base64::engine::general_purpose::STANDARD.encode(
                r#"package policy

default executables := 3
default hardware := 2
default configuration := 2
default file_system := 2"#,
            );
            let converter = BuiltinCocoConverter::new(
                &PolicyConfig::Inline {
                    content: policy_content,
                },
                &[],
            )
            .await
            .expect("Failed to create converter with inline policy");

            let attester = CocoAttester::new(TEST_AA_ADDR).expect("Failed to create attester");
            let report_data = ReportData::Claims(serde_json::Map::new());
            let evidence = attester
                .get_evidence(&report_data)
                .await
                .expect("Failed to get evidence");
            let token = converter.convert(&evidence).await;
            assert!(
                token.is_ok(),
                "Convert with inline policy failed: {:?}",
                token.err()
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        #[should_panic(expected = "EarStatusNotAffirming")]
        async fn test_builtin_convert_and_verify_roundtrip() {
            let converter = BuiltinCocoConverter::new(&PolicyConfig::Default, &[])
                .await
                .expect("Failed to create converter");
            let verifier = converter
                .new_verifier()
                .await
                .expect("Failed to create verifier");

            let attester = CocoAttester::new(TEST_AA_ADDR).expect("Failed to create attester");
            let report_data = ReportData::Claims(serde_json::Map::new());
            let evidence = attester
                .get_evidence(&report_data)
                .await
                .expect("Failed to get evidence");

            let token = converter
                .convert(&evidence)
                .await
                .expect("Failed to convert evidence");

            let result = verifier.verify_evidence(&token, &report_data).await;
            assert!(
                result.is_ok(),
                "Roundtrip verify failed: {:?}",
                result.err()
            );
        }
    }
}

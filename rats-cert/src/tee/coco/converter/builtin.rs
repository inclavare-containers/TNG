//! Builtin Attestation Service Converter
//!
//! This module implements local evidence verification using the embedded attestation-service crate.
//! It converts CocoEvidence to CocoAsToken by running attestation-service in-process.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use attestation_service::rvps::{RvpsConfig, RvpsCrateConfig};
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
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

use super::super::evidence::{CocoAsToken, CocoEvidence};
use super::convert_additional_evidence;
use super::AttestationServiceHashAlgo;
use crate::errors::*;
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
    fn new() -> Result<Self> {
        let temp_dir = tempfile::tempdir().context("Failed to create builtin AS temp directory")?;

        let (cert_chain_path, key_path) = Self::generate_certificates(temp_dir.path())?;

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
    fn generate_certificates(work_dir: &Path) -> Result<(PathBuf, PathBuf)> {
        // Generate CA key pair
        let ca_key_pair =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("Failed to generate CA key")?;

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
            .context("Failed to generate CA certificate")?;

        // Generate AS key pair
        let as_key_pair =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("Failed to generate AS key")?;

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
            .context("Failed to sign AS certificate")?;

        // Write AS private key
        let key_path = work_dir.join("as.key");
        std::fs::write(&key_path, as_key_pair.serialize_pem())
            .context("Failed to write AS private key")?;

        // Write certificate chain (AS cert + CA cert)
        let cert_chain_path = work_dir.join("as-chain.pem");
        let cert_chain = format!("{}{}", as_cert.pem(), ca_cert.pem());
        std::fs::write(&cert_chain_path, cert_chain)
            .context("Failed to write certificate chain")?;

        tracing::debug!(
            key_path = %key_path.display(),
            cert_chain_path = %cert_chain_path.display(),
            "Generated builtin AS certificates"
        );

        Ok((cert_chain_path, key_path))
    }
}

/// Configuration for policy loading
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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

/// Configuration for payload loading (used in reference values)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PayloadConfig {
    /// Inline JSON content
    Inline { content: String },
    /// Path to payload file
    Path { path: String },
}

/// Provenance source configuration for SLSA reference values
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProvenanceSource {
    pub protocol: String,
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
}

/// Configuration for reference values
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReferenceValueConfig {
    /// Sample reference values (inline or from file)
    Sample { payload: PayloadConfig },
    /// SLSA-based reference values from Rekor
    Slsa {
        id: String,
        version: String,
        artifact_type: String,
        rekor_url: String,
        #[serde(default = "default_rekor_api_version")]
        rekor_api_version: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provenance_source: Option<ProvenanceSource>,
    },
}

fn default_rekor_api_version() -> u8 {
    2
}

/// Builtin CoCo Converter
///
/// Converts CocoEvidence to CocoAsToken using an embedded attestation-service instance.
/// This provides local evidence verification without requiring a remote AS.
pub struct BuiltinCocoConverter {
    attestation_service: AttestationService,

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
        let work_dir = Arc::new(AttestationServiceWorkDir::new()?);

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
                ..Default::default()
            }),
            ..Default::default()
        };

        // Create AttestationService instance
        let mut attestation_service = AttestationService::new(config)
            .await
            .context("Failed to create AttestationService")?;

        // Load policy (skip to use AS built-in default policy for Default)
        if let Some(policy_content) = Self::load_policy(policy)? {
            attestation_service
                .set_policy(DEFAULT_POLICY_ID.to_string(), policy_content)
                .await
                .context("Failed to set policy")?;
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
    fn load_policy(policy: &PolicyConfig) -> Result<Option<String>> {
        match policy {
            PolicyConfig::Default => Ok(None),
            PolicyConfig::Inline { content } => {
                // Decode base64 encoded policy
                let decoded = BASE64_STANDARD
                    .decode(content)
                    .context("Failed to decode base64 policy content")?;
                Ok(Some(
                    String::from_utf8(decoded).context("Policy content is not valid UTF-8")?,
                ))
            }
            PolicyConfig::Path { path } => {
                Ok(Some(std::fs::read_to_string(path).with_context(|| {
                    format!("Failed to read policy file: {}", path)
                })?))
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
                    let payload_content = Self::load_payload(payload)?;
                    attestation_service
                        .set_reference_value_list(&payload_content)
                        .await
                        .context("Failed to set sample reference values")?;
                }
                ReferenceValueConfig::Slsa {
                    id,
                    version,
                    artifact_type,
                    rekor_url,
                    rekor_api_version,
                    provenance_source,
                } => {
                    // Build SLSA reference value payload
                    // Reference: attestation-challenge-client set_reference_value.rs
                    let payload = Self::build_slsa_payload(
                        id,
                        version,
                        artifact_type,
                        rekor_url,
                        *rekor_api_version,
                        provenance_source.as_ref(),
                    );

                    attestation_service
                        .set_reference_value_list(&payload.to_string())
                        .await
                        .context("Failed to set SLSA reference values")?;
                }
            }
        }
        Ok(())
    }

    /// Build SLSA reference value payload
    fn build_slsa_payload(
        id: &str,
        version: &str,
        artifact_type: &str,
        rekor_url: &str,
        rekor_api_version: u8,
        provenance_source: Option<&ProvenanceSource>,
    ) -> serde_json::Value {
        let mut rv_entry = json!({
            "id": id,
            "version": version,
            "type": artifact_type,
            "provenance_info": {
                "type": "slsa-intoto-statements",
                "rekor_url": rekor_url,
                "rekor_api_version": rekor_api_version
            },
            "operation_type": "refresh"
        });

        if let Some(ps) = provenance_source {
            rv_entry["provenance_source"] = json!({
                "protocol": ps.protocol,
                "uri": ps.uri,
                "artifact": ps.artifact
            });
        }

        json!({ "rv_list": [rv_entry] })
    }

    /// Load payload from configuration
    fn load_payload(payload: &PayloadConfig) -> Result<String> {
        match payload {
            PayloadConfig::Inline { content } => Ok(content.clone()),
            PayloadConfig::Path { path } => std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read payload file: {}", path)),
        }
    }

    /// Generate a challenge nonce for the attestation
    pub async fn generate_challenge(&self) -> Result<String> {
        self.attestation_service
            .generate_challenge(None, None)
            .await
            .context("Failed to generate challenge")
    }

    /// Convert TEE type string to attestation-service Tee enum
    fn tee_str_to_enum(tee_str: &str) -> Result<Tee> {
        match tee_str.to_lowercase().as_str() {
            "sample" => Ok(Tee::Sample),
            "tdx" => Ok(Tee::Tdx),
            "sgx" => Ok(Tee::Sgx),
            "snp" | "sev-snp" => Ok(Tee::Snp),
            "csv" => Ok(Tee::Csv),
            "cca" => Ok(Tee::Cca),
            "aztdx" | "az-tdx-vtpm" => Ok(Tee::AzTdxVtpm),
            "azsnp" | "az-snp-vtpm" => Ok(Tee::AzSnpVtpm),
            _ => Err(Error::msg(format!("Unknown TEE type: {}", tee_str))),
        }
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

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        tracing::debug!("Convert CoCo evidence to CoCo AS token via builtin-as");

        // Get TEE type from evidence
        let tee_str = in_evidence.get_tee_type().as_attestation_service_str_id();
        let tee = Self::tee_str_to_enum(tee_str)?;

        // Get hash algorithm
        let hash_algo =
            AttestationServiceHashAlgo::from(in_evidence.get_aa_runtime_data_hash_algo());
        let hash_algorithm = Self::hash_algo_to_as(&hash_algo);

        // Parse runtime data as JSON
        let runtime_data: serde_json::Value =
            serde_json::from_str(in_evidence.aa_runtime_data_ref())
                .context("Failed to parse runtime data as JSON")?;

        // Build verification requests
        let mut verification_requests = vec![attestation_service::VerificationRequest {
            evidence: serde_json::Value::String(
                URL_SAFE_NO_PAD.encode(in_evidence.aa_evidence_ref()),
            ),
            tee,
            runtime_data: Some(attestation_service::RuntimeData::Structured(runtime_data)),
            runtime_data_hash_algorithm: hash_algorithm,
            init_data: None,
            additional_data: None,
        }];

        // Add additional evidence if present
        for (tee_type, evidence) in convert_additional_evidence(in_evidence)? {
            let additional_tee = Self::tee_str_to_enum(tee_type.as_attestation_service_str_id())?;
            verification_requests.push(attestation_service::VerificationRequest {
                evidence: evidence,
                tee: additional_tee,
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
            .context("Evidence verification failed")?;

        CocoAsToken::new(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[tokio::test]
    async fn test_load_inline_policy() {
        // Base64 encoded "package policy\ndefault allow = true"
        let policy_b64 = "cGFja2FnZSBwb2xpY3kKZGVmYXVsdCBhbGxvdyA9IHRydWU=";
        let policy_config = PolicyConfig::Inline {
            content: policy_b64.to_string(),
        };

        let result = BuiltinCocoConverter::load_policy(&policy_config);
        assert!(result.is_ok());
        let content = result
            .unwrap()
            .expect("Should return Some for Inline policy");
        assert!(content.contains("package policy"));
        assert!(content.contains("default allow = true"));
    }

    #[tokio::test]
    async fn test_load_default_policy() {
        let policy_config = PolicyConfig::Default;
        let result = BuiltinCocoConverter::load_policy(&policy_config);
        assert!(result.is_ok());
        assert!(
            result.unwrap().is_none(),
            "Default policy should return None"
        );
    }

    #[tokio::test]
    async fn test_load_inline_payload() {
        let payload_content = r#"{"name": "test", "values": ["v1", "v2"]}"#;
        let payload_config = PayloadConfig::Inline {
            content: payload_content.to_string(),
        };

        let result = BuiltinCocoConverter::load_payload(&payload_config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), payload_content);
    }

    #[test]
    fn test_tee_str_to_enum() {
        assert!(matches!(
            BuiltinCocoConverter::tee_str_to_enum("sample"),
            Ok(Tee::Sample)
        ));
        assert!(matches!(
            BuiltinCocoConverter::tee_str_to_enum("tdx"),
            Ok(Tee::Tdx)
        ));
        assert!(matches!(
            BuiltinCocoConverter::tee_str_to_enum("sgx"),
            Ok(Tee::Sgx)
        ));
        assert!(matches!(
            BuiltinCocoConverter::tee_str_to_enum("snp"),
            Ok(Tee::Snp)
        ));
    }

    #[test]
    fn test_build_slsa_payload() {
        let payload = BuiltinCocoConverter::build_slsa_payload(
            "my-artifact",
            "1.0.0",
            "container",
            "https://rekor.sigstore.dev",
            1,
            Some(&ProvenanceSource {
                protocol: "oci".to_string(),
                uri: "ghcr.io/example/image".to_string(),
                artifact: Some("sha256:abc123".to_string()),
            }),
        );

        let rv_list = payload.get("rv_list").unwrap().as_array().unwrap();
        assert_eq!(rv_list.len(), 1);

        let rv = &rv_list[0];
        assert_eq!(rv.get("id").unwrap(), "my-artifact");
        assert_eq!(rv.get("version").unwrap(), "1.0.0");
        assert_eq!(rv.get("type").unwrap(), "container");
        assert_eq!(rv.get("operation_type").unwrap(), "refresh");

        let provenance_info = rv.get("provenance_info").unwrap();
        assert_eq!(
            provenance_info.get("type").unwrap(),
            "slsa-intoto-statements"
        );
        assert_eq!(
            provenance_info.get("rekor_url").unwrap(),
            "https://rekor.sigstore.dev"
        );

        let provenance_source = rv.get("provenance_source").unwrap();
        assert_eq!(provenance_source.get("protocol").unwrap(), "oci");
    }

    #[test]
    fn test_attestation_service_work_dir_creation() {
        let work_dir = AttestationServiceWorkDir::new().expect("Failed to create work dir");

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

    #[test]
    fn test_attestation_service_work_dir_cert_chain_valid_pem() {
        let work_dir = AttestationServiceWorkDir::new().expect("Failed to create work dir");

        // Read certificate chain
        let cert_chain_pem =
            std::fs::read_to_string(work_dir.cert_chain_path()).expect("Failed to read cert chain");

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

    #[test]
    fn test_attestation_service_work_dir_key_valid_pem() {
        let work_dir = AttestationServiceWorkDir::new().expect("Failed to create work dir");

        // Read private key
        let key_pem = std::fs::read_to_string(work_dir.key_path()).expect("Failed to read key");

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

    #[test]
    fn test_attestation_service_work_dir_cleanup_on_drop() {
        let path;
        let cert_path;
        let key_path;

        {
            let work_dir = AttestationServiceWorkDir::new().expect("Failed to create work dir");
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

    #[test]
    fn test_attestation_service_work_dir_unique_paths() {
        let work_dir1 = AttestationServiceWorkDir::new().expect("Failed to create work dir 1");
        let work_dir2 = AttestationServiceWorkDir::new().expect("Failed to create work dir 2");

        // Each instance should have unique paths
        assert_ne!(work_dir1.path(), work_dir2.path());
        assert_ne!(work_dir1.cert_chain_path(), work_dir2.cert_chain_path());
        assert_ne!(work_dir1.key_path(), work_dir2.key_path());
    }

    // === Reference value loading tests ===

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_sample_inline_reference() {
        let reference = ReferenceValueConfig::Sample {
            payload: PayloadConfig::Inline {
                content: r#"{"tdx":{}}"#.to_string(),
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
        std::fs::write(&ref_path, r#"{"tdx":{}}"#).expect("Failed to write ref file");

        let reference = ReferenceValueConfig::Sample {
            payload: PayloadConfig::Path {
                path: ref_path.to_string_lossy().to_string(),
            },
        };
        let result = BuiltinCocoConverter::new(&PolicyConfig::Default, &[reference]).await;
        assert!(
            result.is_ok(),
            "Failed to create converter with path sample reference: {:?}",
            result.err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_slsa_reference() {
        let reference = ReferenceValueConfig::Slsa {
            id: "test-artifact".to_string(),
            version: "1.0.0".to_string(),
            artifact_type: "container-image".to_string(),
            rekor_url: "https://rekor.sigstore.dev".to_string(),
            rekor_api_version: 2,
            provenance_source: None,
        };
        // SLSA reference loading may fail if Rekor is unreachable, so we just test the creation path
        let _result = BuiltinCocoConverter::new(&PolicyConfig::Default, &[reference]).await;
        // Not asserting Ok since Rekor may be unreachable; the important thing is no panic
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_slsa_reference_and_provenance() {
        let reference = ReferenceValueConfig::Slsa {
            id: "test-artifact".to_string(),
            version: "1.0.0".to_string(),
            artifact_type: "container-image".to_string(),
            rekor_url: "https://rekor.sigstore.dev".to_string(),
            rekor_api_version: 2,
            provenance_source: Some(ProvenanceSource {
                protocol: "oci".to_string(),
                uri: "oci://registry/repo:tag".to_string(),
                artifact: Some("bundle".to_string()),
            }),
        };
        let _result = BuiltinCocoConverter::new(&PolicyConfig::Default, &[reference]).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_multiple_references() {
        let references = vec![
            ReferenceValueConfig::Sample {
                payload: PayloadConfig::Inline {
                    content: r#"{"tdx":{}}"#.to_string(),
                },
            },
            ReferenceValueConfig::Sample {
                payload: PayloadConfig::Inline {
                    content: r#"{"sample":{}}"#.to_string(),
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
        let result = BuiltinCocoConverter::new(&PolicyConfig::Default, &[]).await;
        assert!(
            result.is_ok(),
            "Failed with empty references: {:?}",
            result.err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_error_sample_path_not_found() {
        let reference = ReferenceValueConfig::Sample {
            payload: PayloadConfig::Path {
                path: "/nonexistent/reference_values.json".to_string(),
            },
        };
        let result = BuiltinCocoConverter::new(&PolicyConfig::Default, &[reference]).await;
        assert!(
            result.is_err(),
            "Should fail with nonexistent reference path"
        );
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
            let policy_content = base64::engine::general_purpose::STANDARD
                .encode("package policy\ndefault allow = true");
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

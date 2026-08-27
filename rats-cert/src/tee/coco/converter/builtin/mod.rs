//! Builtin Attestation Service Converter
//!
//! This module implements local evidence verification using the embedded attestation-service crate.
//! It converts CocoEvidence to CocoAsToken by running attestation-service in-process.

mod rekor_v1;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use attestation_service::rvps::{RvpsConfig, RvpsCrateConfig};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use reference_value_provider_service::extractors::extractor_modules::sample::Provenance;
use reference_value_provider_service::rv_list::ReferenceValueListPayload;
use reference_value_provider_service::storage::ReferenceValueStorageConfig;
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;

use attestation_service::{
    config::Config, token::AttestationTokenConfig, AttestationService, HashAlgorithm, Tee,
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

struct SelfSignedSigner {
    pub cert_chain: Vec<CertificateDer<'static>>,
    private_key: p256::SecretKey,
}

impl SelfSignedSigner {
    fn new() -> Result<Self> {
        let (cert_chain, private_key) = generate_certificates()?;
        Ok(Self {
            cert_chain,
            private_key,
        })
    }
}

impl attestation_service::token::signer::SignKeyProvider<p256::SecretKey> for SelfSignedSigner {
    fn private_key(&self) -> &p256::SecretKey {
        &self.private_key
    }
    fn cert_chain(&self) -> Option<anyhow::Result<Vec<CertificateDer<'static>>>> {
        Some(Ok(self.cert_chain.clone()))
    }
    fn cert_url(&self) -> Option<&str> {
        None
    }
    fn cert_pem_live(&self) -> Option<anyhow::Result<Vec<u8>>> {
        // Return None here since this function will not be called actually
        None
    }
}

/// Generate CA and AS certificates using rcgen
fn generate_certificates() -> Result<(Vec<CertificateDer<'static>>, p256::SecretKey)> {
    // Generate CA key pair
    let ca_key_pair =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(Error::CaCertGenerationFailed)?;

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
    let as_key_pair =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(Error::AsCertGenerationFailed)?;

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

    // Build certificate chain (AS cert + CA cert)
    let cert_chain = vec![CertificateDer::from(as_cert), CertificateDer::from(ca_cert)];

    // BuildAS private key
    let as_private_key = p256::SecretKey::from_pkcs8_der(as_key_pair.serialized_der())
        .map_err(Error::FromPkcs8DerFailed)?;

    Ok((cert_chain, as_private_key))
}

/// Configuration for policy loading
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyConfig {
    /// Use the attestation-service default policy (the trustee
    /// `ear_default_policy_cpu.rego`): a comprehensive appraisal that checks
    /// hardware, boot measurements, configuration and filesystem against
    /// configured reference values. Suited to deployments where those
    /// reference values are available and mandatory.
    /// See: https://github.com/openanolis/trustee/blob/7a6a7b8a2554295bcd296963d353761eaf4f70eb/attestation-service/src/token/ear_default_policy_cpu.rego
    HardwareWithReferenceValues,
    /// Trustee default reference-value appraisal with stricter TDX hardware
    /// requirements: TDX evidence must be non-debug and include an event log.
    HardwareStrictWithReferenceValues,
    /// tng-bundled template: only hardware TEE recognition is enforced; the
    /// other three trustworthiness dimensions are affirming by default and
    /// `data.reference` is ignored. This is the default policy, suited to
    /// general-purpose deployments that only need to assert the hardware TEE.
    #[default]
    #[serde(alias = "default")]
    HardwareOnly,
    /// tng-bundled template: keeps the hardware-only posture for reference
    /// values, but TDX evidence must be non-debug and include an event log.
    HardwareOnlyStrict,
    /// tng-bundled template: every trustworthiness dimension is affirming
    /// regardless of input. **For development and testing only.**
    TrustAll,
    /// At init, fetch a Rekor v1 entry by logIndex, authenticate it
    /// (checkpoint + Merkle inclusion + SET), and bake the trusted
    /// `payloadHash` into Rego. At appraisal the Rego reconstructs the
    /// ReleaseManifest from the actual TDX measurement values, hashes it,
    /// and compares to the baked payloadHash. Mirrors the transparency-verification
    /// flow for signed release manifests. See
    /// docs/superpowers/specs/2026-08-23-rekor-transparency-policy-design.md.
    #[serde(rename = "transparency_log")]
    TransparencyLog {
        /// Ordered measurement types baked into the policy. When `None`
        /// (the `publishedMeasurements` JSON field is absent), the policy
        /// skips the measurement reconstruction + verification entirely and
        /// `executables` stays affirming (2) — only TDX platform checks
        /// gate the appraisal. An explicit `[]` still runs the check (and
        /// fails it, since no manifest can match the baked payloadHash).
        #[serde(rename = "publishedMeasurements", default)]
        published_measurements: Option<Vec<String>>,
        #[serde(rename = "schemaVersion", default = "default_schema_version")]
        schema_version: String,
        services: Vec<TransparencyServiceConfig>,
    },
    /// Base64 encoded policy content
    Inline { content: String },
    /// Path to policy file
    #[cfg(not(wasm))]
    Path { path: String },
}

/// Default schema version for the transparency-log policy config.
fn default_schema_version() -> String {
    "1.0.0".to_string()
}

/// A transparency-log service whose entry authenticates the reference
/// measurements. Currently only Rekor v1 (fetch by logIndex) is supported.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TransparencyServiceConfig {
    #[serde(rename = "rekor-v1")]
    RekorV1 {
        #[serde(rename = "logUrl")]
        log_url: String,
        #[serde(rename = "logIndex")]
        log_index: i64,
        #[serde(rename = "rekorPublicKeyPem", default)]
        rekor_public_key_pem: Option<String>,
        #[serde(rename = "publisherPublicKeyPem", default)]
        publisher_public_key_pem: Option<String>,
    },
}

/// Configuration for sample provenance payload loading
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SampleProvenancePayloadConfig {
    /// Inline JSON content (Provenance)
    Inline { content: Provenance },
    /// Path to payload file
    #[cfg(not(wasm))]
    Path { path: String },
}

/// Configuration for SLSA reference value payload loading
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SlsaReferenceValuePayloadConfig {
    /// Inline JSON content (ReferenceValueListPayload)
    Inline { content: ReferenceValueListPayload },
    /// Path to payload file
    #[cfg(not(wasm))]
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
    /// RV release manifest-based reference values
    ReleaseManifest {
        payload: SlsaReferenceValuePayloadConfig,
    },
}

/// Builtin CoCo Converter
///
/// Converts CocoEvidence to CocoAsToken using an embedded attestation-service instance.
/// This provides local evidence verification without requiring a remote AS.
pub struct BuiltinCocoConverter {
    self_signed_signer: Arc<SelfSignedSigner>,
    /// Embedded attestation service instance
    ///
    /// Note the attestation service is boxed to save the stack space and avoid large memory copy.
    attestation_service: Box<AttestationService>,
    /// Test-only flag: when true, `convert()` passes `runtime_data: None` to
    /// the attestation-service `VerificationRequest`, so the TDX verifier
    /// treats the report data as `ReportData::NotProvided` and skips the
    /// `report_data == hash(runtime_data)` binding check. Lets the
    /// transparency-log appraisal test run without supplying real runtime data.
    #[cfg(test)]
    skip_runtime_data_check: bool,
}

impl BuiltinCocoConverter {
    /// Create a new BuiltinCocoConverter with the given policy and reference values
    pub async fn new(
        policy: &PolicyConfig,
        reference_values: &[ReferenceValueConfig],
    ) -> Result<Self> {
        // Create AttestationService instance
        let (self_signed_signer, mut attestation_service) = {
            let self_signed_signer = Arc::new(SelfSignedSigner::new()?);

            let rvps = Arc::new(attestation_service::rvps::builtin::BuiltinRvps::new(
                reference_value_provider_service::config::Config {
                    storage:
                        reference_value_provider_service::storage::ReferenceValueStorageConfig::InMemory(
                            reference_value_provider_service::storage::in_memory::Config {},
                        ),
                },
            )
            .map_err(attestation_service::ServiceError::Rvps)
            .map_err(Error::AttestationServiceCreateFailed)?) as Arc<dyn attestation_service::rvps::RvpsApi>;

            let token_broker = Box::new(
                attestation_service::token::ear_broker::EarAttestationTokenBroker::from_components(
                    attestation_service::token::ear_broker::TokenBrokerSettings::default(),
                    self_signed_signer.clone(),
                    Arc::new(
                        attestation_service::policy_engine::opa::OPAInMemory::with_raw_default_policy(
                            attestation_service::token::ear_broker::DEFAULT_POLICY,
                            DEFAULT_POLICY_ID,
                            // The artifact-server address is only consumed
                            // under attestation-service's `policy-artifact-server`
                            // feature (not enabled here), so this value has no
                            // effect today. Pass trustee's own default
                            // (`config::DEFAULT_ARTIFACT_SERVER_ADDRESS`) rather
                            // than `""` so the call site mirrors upstream usage
                            // and stays correct if that feature is ever enabled.
                            attestation_service::config::DEFAULT_ARTIFACT_SERVER_ADDRESS,
                        )
                        .map_err(Error::AttestationServicePolicyEngineCreateFailed)?
                        // Inject the `crypto.sha256` host-await function so
                        // rego policies that call `crypto.sha256(...)` (e.g.
                        // the transparency-log policy's
                        // `crypto.sha256(json.marshal(manifest))`) resolve
                        // against a real sha256 implementation. regorus 0.11
                        // ships no crypto builtins by design. Under
                        // `crypto-rustcrypto`, `verify_dsse_signature`
                        // (DSSEPAE + ECDSA P-256) is injected too — see
                        // `builtin_as_host_await_functions`.
                        .with_extra_host_await_functions(builtin_as_host_await_functions()),
                    ),
                ),
            )
            as Box<dyn attestation_service::token::AttestationTokenBroker + Send + Sync>;

            // The builtin AS now stores the challenger by value as a concrete
            // `JwtChallenger` (the old `Challenger` trait / `LocalNonceChallenger`
            // were removed upstream). On non-wasm we let rustcrypto generate the
            // RSA-2048 key; on wasm that prime generation is pure software and
            // slow, so we ask the host Web Crypto API to generate the key
            // (hardware-accelerated) and feed it in via `new_with_private_key`.
            let challenger = Self::build_challenger()
                .await
                .map_err(Error::AttestationServiceChallengerCreateFailed)?;

            (
                self_signed_signer,
                Box::new(AttestationService::from_components(
                    rvps,
                    token_broker,
                    challenger,
                )),
            )
        };

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
            self_signed_signer,
            attestation_service,
            #[cfg(test)]
            skip_runtime_data_check: false,
        })
    }

    /// Test-only builder: make `convert()` pass `runtime_data: None` to the
    /// attestation-service `VerificationRequest` so the verifier skips the
    /// `report_data == hash(runtime_data)` binding check. Used by the
    /// transparency-log appraisal test, which supplies dummy runtime data.
    #[cfg(test)]
    pub(crate) fn for_testing_skip_runtime_data(mut self) -> Self {
        self.skip_runtime_data_check = true;
        self
    }

    /// Construct the [`JwtChallenger`] used by the embedded attestation service.
    ///
    /// The builtin AS stores the challenger by value as a concrete
    /// `JwtChallenger` (the `Challenger` trait and `LocalNonceChallenger` were
    /// removed upstream in favor of a single JWT-based challenger).
    ///
    /// `JwtChallenger::new` generates a fresh RSA-2048 key with rustcrypto.
    /// That is fine on native, but on wasm rustcrypto prime generation is pure
    /// software and prohibitively slow, so on wasm we ask the host Web Crypto
    /// API (`SubtleCrypto::generateKey`, hardware-accelerated) to produce the
    /// RSA key, export it as PKCS#8, and feed it to `new_with_private_key`.
    /// The actual RS384 signing in the challenger still uses rustcrypto; only
    /// key generation is offloaded to WebCrypto.
    async fn build_challenger() -> anyhow::Result<attestation_service::JwtChallenger> {
        #[cfg(wasm)]
        {
            Self::build_challenger_webcrypto().await
        }
        #[cfg(not(wasm))]
        {
            attestation_service::JwtChallenger::new()
        }
    }

    /// wasm path: generate the challenger's RSA key via the Web Crypto API.
    #[cfg(wasm)]
    async fn build_challenger_webcrypto() -> anyhow::Result<attestation_service::JwtChallenger> {
        use rsa::pkcs8::DecodePrivateKey as _;
        use rsa::RsaPrivateKey;
        use wasm_bindgen::JsCast as _;
        use wasm_bindgen_futures::JsFuture;

        // Helper to convert a thrown `JsValue` into an `anyhow::Error`. A
        // `JsValue` carries no Rust error chain, so there is nothing to preserve
        // via `.context()`; rendering its Debug form is the only option.
        fn js_err(msg: &str, value: wasm_bindgen::JsValue) -> anyhow::Error {
            anyhow::Error::msg(format!("{msg}: {value:?}"))
        }

        let window = web_sys::window().ok_or_else(|| {
            anyhow::anyhow!("no global `window` available (not a browser/WASM worker context)")
        })?;
        let crypto = window.crypto().map_err(|e| js_err("window.crypto", e))?;
        let subtle = crypto.subtle();

        // RSASSA-PKCS1-v1_5 with SHA-384 == RS384, the scheme JwtChallenger
        // signs with. modulusLength 2048, publicExponent 65537 ([1,0,1]).
        let algorithm = js_sys::Object::new();
        js_sys::Reflect::set(&algorithm, &"name".into(), &"RSASSA-PKCS1-v1_5".into())
            .map_err(|e| js_err("set algorithm.name", e))?;
        js_sys::Reflect::set(&algorithm, &"modulusLength".into(), &2048u32.into())
            .map_err(|e| js_err("set algorithm.modulusLength", e))?;
        let public_exponent = js_sys::Uint8Array::from(&[1u8, 0, 1][..]);
        js_sys::Reflect::set(&algorithm, &"publicExponent".into(), &public_exponent)
            .map_err(|e| js_err("set algorithm.publicExponent", e))?;
        let hash = js_sys::Object::new();
        js_sys::Reflect::set(&hash, &"name".into(), &"SHA-384".into())
            .map_err(|e| js_err("set algorithm.hash.name", e))?;
        js_sys::Reflect::set(&algorithm, &"hash".into(), &hash)
            .map_err(|e| js_err("set algorithm.hash", e))?;

        // extractable=true so we can export the private key material as PKCS#8.
        let key_usages = js_sys::Array::new();
        key_usages.push(&"sign".into());
        let key_gen_promise = subtle
            .generate_key_with_object(&algorithm, true, &key_usages)
            .map_err(|e| js_err("SubtleCrypto::generateKey", e))?;
        let key_pair_value = JsFuture::from(key_gen_promise)
            .await
            .map_err(|e| js_err("await SubtleCrypto::generateKey", e))?;

        // `generateKey` for an asymmetric algorithm resolves to a JS object
        // `{ privateKey: CryptoKey, publicKey: CryptoKey }`. web-sys models
        // `CryptoKeyPair` as a write-only dictionary (setters, no getters), so
        // read the `privateKey` property off the raw value via Reflect instead.
        let private_key_value = js_sys::Reflect::get(&key_pair_value, &"privateKey".into())
            .map_err(|e| js_err("read CryptoKeyPair.privateKey", e))?;
        let private_key: web_sys::CryptoKey = private_key_value
            .dyn_into()
            .map_err(|_| anyhow::anyhow!("CryptoKeyPair.privateKey is not a CryptoKey"))?;

        let export_promise = subtle
            .export_key("pkcs8", &private_key)
            .map_err(|e| js_err("SubtleCrypto::exportKey", e))?;
        let exported = JsFuture::from(export_promise)
            .await
            .map_err(|e| js_err("await SubtleCrypto::exportKey", e))?;
        let buffer: js_sys::ArrayBuffer = exported.dyn_into().map_err(|_| {
            anyhow::anyhow!("SubtleCrypto::exportKey did not return an ArrayBuffer")
        })?;
        let der = js_sys::Uint8Array::new(&buffer).to_vec();

        let rsa_key = RsaPrivateKey::from_pkcs8_der(&der)
            .map_err(|e| anyhow::Error::from(e).context("parse WebCrypto RSA key as PKCS#8"))?;
        Ok(attestation_service::JwtChallenger::new_with_private_key(
            rsa_key,
        ))
    }

    /// Builtin converters run the attestation service in-process and have no
    /// remote attestation-service address; return a sentinel for error context.
    pub fn as_addr(&self) -> &'static str {
        "<builtin-attestation-service>"
    }

    /// Load policy from configuration
    /// Returns None for the AS built-in default policy
    /// (HardwareWithReferenceValues), and a URL-safe base64 encoding of the
    /// policy source for the tng-bundled templates and the user-supplied
    /// Inline/Path variants.
    async fn load_policy_as_base64_url_safe_no_pad(
        policy: &PolicyConfig,
    ) -> Result<Option<String>> {
        match policy {
            PolicyConfig::HardwareWithReferenceValues => Ok(None),
            PolicyConfig::HardwareStrictWithReferenceValues => Ok(Some(
                URL_SAFE_NO_PAD.encode(Self::build_hardware_strict_with_reference_values_policy()?),
            )),
            PolicyConfig::HardwareOnly => Ok(Some(
                URL_SAFE_NO_PAD.encode(include_str!("../policies/hardware_only.rego")),
            )),
            PolicyConfig::HardwareOnlyStrict => Ok(Some(
                URL_SAFE_NO_PAD.encode(include_str!("../policies/hardware_only_strict.rego")),
            )),
            PolicyConfig::TrustAll => Ok(Some(
                URL_SAFE_NO_PAD.encode(include_str!("../policies/trust_all.rego")),
            )),
            // Fetch + authenticate the Rekor v1 entry by logIndex, then bake
            // the trusted payloadHash into Rego. The cryptography (P-256 ECDSA
            // SET verification + SHA-256 Merkle inclusion proof) lives behind
            // the `crypto-rustcrypto` feature; the arm is gated the same way so
            // a non-crypto build still compiles (and bails there instead).
            #[cfg(feature = "crypto-rustcrypto")]
            PolicyConfig::TransparencyLog {
                published_measurements,
                schema_version,
                services,
            } => {
                // Initial implementation: exactly one rekor-v1 service.
                let svc = match services.as_slice() {
                    [TransparencyServiceConfig::RekorV1 {
                        log_url,
                        log_index,
                        rekor_public_key_pem,
                        publisher_public_key_pem,
                    }] => (
                        log_url.as_str(),
                        *log_index,
                        rekor_public_key_pem.as_deref(),
                        publisher_public_key_pem.as_deref(),
                    ),
                    _ => {
                        return Err(Error::TransparencyLogFetchFailed(anyhow::anyhow!(
                            "transparency_log policy requires exactly one rekor-v1 service"
                        )))
                    }
                };
                let (log_url, log_index, rekor_public_key_pem, publisher_public_key_pem) = svc;
                tracing::info!(
                    log_url,
                    log_index,
                    "Loading transparency_log policy: fetching Rekor v1 entry"
                );
                let auth =
                    rekor_v1::fetch_trusted_payload_hash(log_url, log_index, rekor_public_key_pem)
                        .await
                        .map_err(Error::TransparencyLogFetchFailed)?;
                // Resolve the DSSE signature to bake into the policy. A real
                // rekor v1 `dsse` entry always carries a signature, so an empty
                // field means a malformed/non-dsse entry. If the operator
                // configured a publisher key (opting into DSSE verify), that is
                // a config/entry mismatch — fail closed rather than silently
                // emitting a weaker payloadHash-only policy. With no publisher
                // key configured there is no DSSE expectation, so
                // payloadHash-only is the intended fallback.
                let dsse_signature =
                    resolve_dsse_signature(&auth.dsse_signature, publisher_public_key_pem)
                        .map_err(Error::TransparencyLogFetchFailed)?;
                let policy = build_transparency_log_policy(
                    &auth.payload_hash,
                    schema_version,
                    published_measurements.as_deref(),
                    dsse_signature,
                    publisher_public_key_pem,
                );
                tracing::info!(payload_hash = %auth.payload_hash, policy = %policy, "Transparency_log policy loaded: baking payloadHash into Rego");
                Ok(Some(URL_SAFE_NO_PAD.encode(policy)))
            }
            #[cfg(not(feature = "crypto-rustcrypto"))]
            PolicyConfig::TransparencyLog { .. } => {
                Err(Error::TransparencyLogPolicyRequiresCryptoRustcrypto)
            }
            PolicyConfig::Inline { content } => {
                // Decode base64 encoded policy
                let decoded = BASE64_STANDARD
                    .decode(content)
                    .map_err(Error::DecodePolicyContentFailed)?;
                Ok(Some(URL_SAFE_NO_PAD.encode(decoded)))
            }
            #[cfg(not(wasm))]
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

    fn build_hardware_strict_with_reference_values_policy() -> Result<String> {
        const TDX_HARDWARE_RULE: &str = r#"hardware := 2 if {
	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
	# Check TDX Module version and its hash. Also check OVMF code hash.
	# input.tdx.quote.body.mr_seam in query_reference_value("tdx.mr_seam")
	# input.tdx.quote.body.tcb_svn in query_reference_value("tdx.tcb_svn")
	# input.tdx.quote.body.mr_td in query_reference_value("tdx.mr_td")
}"#;
        const TDX_HARDWARE_RULE_STRICT: &str = r#"hardware := 2 if {
	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
	tdx_debug_disabled
	tdx_eventlog_present
	# Check TDX Module version and its hash. Also check OVMF code hash.
	# input.tdx.quote.body.mr_seam in query_reference_value("tdx.mr_seam")
	# input.tdx.quote.body.tcb_svn in query_reference_value("tdx.tcb_svn")
	# input.tdx.quote.body.mr_td in query_reference_value("tdx.mr_td")
}"#;
        const TDX_STRICT_HELPERS: &str = r#"

# TNG strict TDX hardware predicates. The verifier has already replayed the
# event log against quote RTMRs before these claims reach policy evaluation.
tdx_debug_disabled if {
	regex.match("^[0-9a-f][02468ace]", input.tdx.quote.body.td_attributes)
}

tdx_eventlog_present if {
	count(input.tdx.uefi_event_logs) > 0
}
"#;

        let default_policy = attestation_service::token::ear_broker::DEFAULT_POLICY;
        if !default_policy.contains(TDX_HARDWARE_RULE) {
            return Err(Error::BuiltinPolicyTemplateFailed {
                detail: "TDX hardware rule not found in Trustee default policy".to_string(),
            });
        }

        Ok(
            default_policy.replacen(TDX_HARDWARE_RULE, TDX_HARDWARE_RULE_STRICT, 1)
                + TDX_STRICT_HELPERS,
        )
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
                        #[cfg(not(wasm))]
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
                        #[cfg(not(wasm))]
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
                ReferenceValueConfig::ReleaseManifest { payload } => {
                    let payload_value = match payload {
                        SlsaReferenceValuePayloadConfig::Inline { content } => content.clone(),
                        #[cfg(not(wasm))]
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
        BuiltinCocoVerifier::new(self.self_signed_signer.cert_chain.clone()).await
    }
}

#[cfg_attr(wasm, async_trait::async_trait(?Send))]
#[cfg_attr(not(wasm), async_trait::async_trait)]
impl GenericConverter for BuiltinCocoConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;
    type Nonce = CoCoNonce;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        tracing::debug!("Convert CoCo evidence to CoCo AS token via builtin-as");

        // Get TEE type from evidence (kbs_types::Tee is compatible with attestation_service::Tee)
        let tee = in_evidence.get_tee_type();

        // Get hash algorithm used to bind the runtime data.
        let hash_algo =
            AttestationServiceHashAlgo::from(in_evidence.get_aa_runtime_data_hash_algo());
        let hash_algorithm = Self::hash_algo_to_as(&hash_algo);

        // Parse the runtime data JSON and wrap as `Structured` so the verifier
        // checks `report_data == hash(runtime_data)`. Under `cfg(test)`, when
        // `skip_runtime_data_check` is set, pass `runtime_data: None` instead —
        // the TDX verifier then treats the report data as
        // `ReportData::NotProvided` and skips the binding check. This lets the
        // transparency-log appraisal test run without real runtime data.
        let runtime_data: serde_json::Value =
            serde_json::from_str(in_evidence.aa_runtime_data_ref())
                .map_err(Error::ParseRuntimeDataJsonFailed)?;
        #[cfg(test)]
        let runtime_data_field = if self.skip_runtime_data_check {
            None
        } else {
            Some(attestation_service::RuntimeData::Structured(runtime_data))
        };
        #[cfg(not(test))]
        let runtime_data_field = Some(attestation_service::RuntimeData::Structured(runtime_data));

        // Build verification requests
        let mut verification_requests = vec![attestation_service::VerificationRequest {
            evidence: serde_json::from_slice(in_evidence.aa_evidence_ref())
                .map_err(Error::ParseEvidenceFromBytesFailed)?,
            tee: *tee,
            runtime_data: runtime_data_field,
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
        // The builtin AS issues the challenge as a JSON object
        // `{"nonce": <b64>, "extra-params": {"jwt": <signed jwt>}}` (see
        // `JwtChallenger::generate_challenge_json`). The client echoes only the
        // JWT back as `runtime_data["challenge_token"]`, which the AS verifies via
        // `verify_challenge_token` (signature + `exp` — it splits on `.` and treats
        // the value as a bare JWT, NOT the wrapper JSON). So extract the bare JWT
        // here, mirroring the REST converter (`challenge_response.extra_params.jwt`).
        let challenge_json = self
            .attestation_service
            .generate_challenge(None, None)
            .await
            .map_err(Error::AttestationServiceGenerateChallengeFailed)?;
        let challenge: serde_json::Value = serde_json::from_str(&challenge_json).map_err(|e| {
            Error::AttestationServiceChallengeParseFailed(
                anyhow::Error::from(e).context("parse attestation challenge response"),
            )
        })?;
        let jwt = challenge
            .get("extra-params")
            .and_then(|p| p.get("jwt"))
            .and_then(|j| j.as_str())
            .ok_or_else(|| {
                Error::AttestationServiceChallengeParseFailed(anyhow::anyhow!(
                    "missing `extra-params.jwt` in attestation challenge response"
                ))
            })?;
        Ok(CoCoNonce::Jwt(jwt.to_string()))
    }
}

/// Resolve the DSSE signature to bake into the `transparency_log` policy.
///
/// A real rekor v1 `dsse` entry always carries a signature, so an empty
/// `dsse_signature` means a malformed/non-dsse entry. If the operator
/// configured a `publisher_key` (opting into DSSE verify), an empty signature
/// is a config/entry mismatch — return `Err` so the loader fails closed
/// rather than silently emitting a weaker payloadHash-only policy. With no
/// publisher key configured there is no DSSE expectation, so `Ok(None)`
/// (payloadHash-only binding) is the intended fallback. Otherwise return
/// `Ok(Some(sig))`.
fn resolve_dsse_signature<'a>(
    dsse_signature: &'a str,
    publisher_key: Option<&str>,
) -> anyhow::Result<Option<&'a str>> {
    if dsse_signature.is_empty() {
        if publisher_key.is_some() {
            return Err(anyhow::anyhow!(
                "publisher_public_key_pem configured but rekor entry has no DSSE signature (config/entry mismatch)"
            ));
        }
        Ok(None)
    } else {
        Ok(Some(dsse_signature))
    }
}

/// Build the `transparency_log` Rego policy string. Bakes the trusted
/// `payload_hash`, the manifest `schema_version`, the ordered
/// `published_measurements`, and — when a publisher key is configured — the
/// DSSE publisher signature + trusted publisher public key. At appraisal the
/// Rego reconstructs the manifest from actual TDX measurement values, hashes
/// it via `crypto.sha256(json.marshal(...))`, and compares to `payload_hash`.
/// When a publisher key is baked, it additionally calls
/// `verify_dsse_signature([json.marshal(reconstructed_manifest),
/// dsse_signature, publisher_key])`, binding the entry to a trusted publisher
/// (the DSSE check strictly subsumes the payloadHash content-binding and adds
/// publisher-identity binding). Absent publisher key => payloadHash-only (the
/// base design's weaker, logIndex-anchored model).
// Wired into `load_policy_as_base64_url_safe_no_pad` under the
// `crypto-rustcrypto` feature; with that feature off the loader bails before
// reaching here, so the function stays dead code in non-crypto builds.
#[cfg_attr(not(feature = "crypto-rustcrypto"), allow(dead_code))]
fn build_transparency_log_policy(
    payload_hash: &str,
    schema_version: &str,
    published_measurements: Option<&[String]>,
    dsse_signature: Option<&str>,
    publisher_key: Option<&str>,
) -> String {
    // The DSSE publisher-signature check is added only when a publisher key is
    // configured (some signature + some key). When `None`, fall back to the
    // base-design payloadHash-only check: no `dsse_signature`/`publisher_key`
    // literals, no `verify_dsse_signature` call. The signature + publisher key
    // are public data (a logged rekor entry's signature + the configured
    // publisher key) — baking them as Rego literals leaks no secret.
    let (dsse_literals, dsse_verify_line) = match (dsse_signature, publisher_key) {
        (Some(sig), Some(key)) => (
            format!(
                "\n# baked: DSSE publisher signature + trusted publisher public key\n\
                 dsse_signature := {sig:?}\n\
                 publisher_key := {key:?}\n",
            ),
            "    verify_dsse_signature([json.marshal(reconstructed_manifest), dsse_signature, publisher_key]) == true\n",
        ),
        _ => (String::new(), ""),
    };

    match published_measurements {
        // No `publishedMeasurements` configured (the JSON field is absent):
        // skip the measurement reconstruction + verification entirely.
        // `executables` stays at its affirming default (2) — only the TDX
        // platform hardware checks gate the appraisal. The trusted
        // payloadHash, schemaVersion, and (when configured) the DSSE
        // publisher signature/key are still baked for reference, but no
        // manifest is reconstructed or compared.
        None => format!(
            r#"package policy
import rego.v1

default executables := 2
default configuration := 2
default file_system := 2

# hardware: progressive scoring for TDX platform checks.
# AR4SI: 0-32 valid, 33-96 warning, 97-127 contraindicated.
# Lower score = more checks passed = more trusted.
# 127 = default, TDX not recognized (nothing matched)
# 126 = tee_type matched but vendor_id didn't (contraindicated)
# 125 = tee_type + vendor_id matched but debug enabled (contraindicated)
# 33  = tee_type + vendor_id + non-debug but eventlog missing (warning)
# 2   = all passed (valid)
default hardware := 127

# baked: trusted payloadHash (lowercase hex) from the authenticated Rekor entry
payload_hash := {payload_hash:?}

# baked: the logged manifest's schemaVersion
schema_version := {schema_version:?}{dsse_literals}

# hardware: progressive scoring for TDX platform checks.
# Score 2 = affirming (all checks pass).
hardware := 2 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
    tdx_debug_disabled
    tdx_eventlog_present
}}

# Score 126 = tee_type matched but vendor_id didn't (contraindicated).
hardware := 126 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id != "939a7233f79c4ca9940a0db3957f0607"
}}

# Score 125 = tee_type + vendor_id matched but debug enabled (contraindicated).
hardware := 125 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
    not tdx_debug_disabled
}}

# Score 33 = all TDX checks passed except eventlog missing (warning).
hardware := 33 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
    tdx_debug_disabled
    not tdx_eventlog_present
}}

# Score 2 = all passed (valid, affirming).
hardware := 2 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
    tdx_debug_disabled
    tdx_eventlog_present
}}

# Score 127 = TDX not recognized (default, contraindicated).

tdx_debug_disabled if {{ regex.match("^[0-9a-f][02468ace]", input.tdx.quote.body.td_attributes) }}
tdx_eventlog_present if {{ count(input.tdx.uefi_event_logs) > 0 }}
"#,
            payload_hash = payload_hash,
            schema_version = schema_version,
            dsse_literals = dsse_literals,
        ),
        // `publishedMeasurements` present (possibly empty `[]`): run the
        // full measurement verification. Bake the ordered array, reconstruct
        // the manifest from actual TDX measurement values at appraisal, hash
        // it via `crypto.sha256(json.marshal(...))`, and compare to the baked
        // `payload_hash`. An empty array yields an empty manifest whose hash
        // never matches a real payloadHash → `measurements_verified` is
        // false → `executables` stays at its contraindicated default (97).
        Some(published_measurements) => {
            // Bake the published_measurements array as a Rego array literal.
            let items: Vec<String> = published_measurements
                .iter()
                .map(|t| format!("{t:?}"))
                .collect();
            let pm = format!("[{}]", items.join(", "));

            format!(
                r#"package policy
import rego.v1

default executables := 97
default configuration := 2
default file_system := 2

# hardware: progressive scoring for TDX platform checks.
# AR4SI: 0-32 valid, 33-96 warning, 97-127 contraindicated.
# Lower score = more checks passed = more trusted.
# 127 = default, TDX not recognized (nothing matched)
# 126 = tee_type matched but vendor_id didn't (contraindicated)
# 125 = tee_type + vendor_id matched but debug enabled (contraindicated)
# 33  = tee_type + vendor_id + non-debug but eventlog missing (warning)
# 2   = all passed (valid)
default hardware := 127

# baked: trusted payloadHash (lowercase hex) from the authenticated Rekor entry
payload_hash := {payload_hash:?}

# baked: the logged manifest's schemaVersion
schema_version := {schema_version:?}

# baked: published measurement types, same order as the logged manifest's
# measurements array (must be exact set + order)
published_measurements := {pm}{dsse_literals}

# extract the actual measurement value for a type from rego input
actual_measurement("tdx.td-shim") := input.tdx.quote.body.mr_td

actual_measurement(type) := digest if {{
    startswith(type, "container.image.")
    repo := replace(type, "container.image.", "")
    some e in input.tdx.uefi_event_logs
    e.details.unicode_name == "AAEL"
    e.details.data.domain == "alibabacloud.com"
    e.details.data.operation == "kangaroo/pull-image"
    image_repo_name(e.details.data.content.reference) == repo
    digest := e.details.data.content.digest
}}

# repo name = last '/' segment of image reference, before first ':' or '@'
image_repo_name(ref) := name if {{
    segs := split(ref, "/")
    last := segs[count(segs) - 1]
    name := split(split(last, "@")[0], ":")[0]
}}

# reconstruct the manifest object (rego object keys serialize sorted == ASCII
# JCS; json.marshal is compact; no numbers in this shape)
reconstructed_manifest := {{
    "measurements": [{{"type": t, "value": actual_measurement(t)}} | some t in published_measurements],
    "schemaVersion": schema_version,
}}

# crypto.sha256 returns lowercase hex (== payloadHash format). When a publisher
# key is baked, verify_dsse_signature additionally binds the entry to the
# trusted publisher (fails closed → false → executables 97 → reject).
measurements_verified if {{
    crypto.sha256(json.marshal(reconstructed_manifest)) == payload_hash
{dsse_verify_line}}}

# executables: 2 only if measurements verified
executables := 2 if {{
    measurements_verified
}}

# hardware: progressive scoring for TDX platform checks.
# Score 2 = affirming (all checks pass).
hardware := 2 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
    tdx_debug_disabled
    tdx_eventlog_present
}}

# Score 126 = tee_type matched but vendor_id didn't (contraindicated).
hardware := 126 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id != "939a7233f79c4ca9940a0db3957f0607"
}}

# Score 125 = tee_type + vendor_id matched but debug enabled (contraindicated).
hardware := 125 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
    not tdx_debug_disabled
}}

# Score 33 = all TDX checks passed except eventlog missing (warning).
hardware := 33 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
    tdx_debug_disabled
    not tdx_eventlog_present
}}

# Score 2 = all passed (valid, affirming).
hardware := 2 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
    tdx_debug_disabled
    tdx_eventlog_present
}}

# Score 127 = TDX not recognized (default, contraindicated).

tdx_debug_disabled if {{ regex.match("^[0-9a-f][02468ace]", input.tdx.quote.body.td_attributes) }}
tdx_eventlog_present if {{ count(input.tdx.uefi_event_logs) > 0 }}
"#,
                payload_hash = payload_hash,
                schema_version = schema_version,
                pm = pm,
                dsse_literals = dsse_literals,
                dsse_verify_line = dsse_verify_line,
            )
        }
    }
}

/// Host-await function that injects the `crypto.sha256` builtin regorus 0.11
/// omits by design. It sha256-hashes its single string argument and resumes
/// the VM with the lowercase-hex digest as a `regorus::Value::String`,
/// matching the format Rekor's `payloadHash` is published in (so the rego
/// `crypto.sha256(json.marshal(manifest)) == payload_hash` comparison works).
///
/// Registered under the dotted name `crypto.sha256` (regorus's function-rule
/// syntax accepts dotted keys) via `OPAInMemory::with_extra_host_await_functions`
/// so the existing, already-written rego policy is unchanged and stays
/// forward-compatible with a future regorus that ships the builtin natively.
/// Only the sha256 primitive is injected; manifest reconstruction
/// (`json.marshal`) and the comparison stay in rego.
///
/// The `RegoVmHostAwaitFunction` type alias already cfg-gates the `Send` bound
/// (dropped on `wasm32-unknown-unknown`, where the RVPS resolver is `?Send`),
/// so this closure's `Box::pin(async move { ... })` future matches both the
/// native and wasm variants without an explicit cfg here. Mirrors the trustee
/// fork's `evaluate_with_injected_crypto_sha256_dotted_host_await` test.
fn crypto_sha256_host_await() -> attestation_service::policy_engine::opa::RegoVmHostAwaitFunction {
    use attestation_service::policy_engine::PolicyError;

    std::sync::Arc::new(|argument: regorus::Value| {
        Box::pin(async move {
            let s = argument.as_string().map_err(|e| {
                PolicyError::EvalPolicyFailed(anyhow::anyhow!(
                    "crypto.sha256 arg not a string: {e}"
                ))
            })?;
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(s.as_bytes());
            Ok(regorus::Value::String(
                hex::encode(hasher.finalize()).into(),
            ))
        })
    })
}

/// DSSE payload type for the ReleaseManifest signatures. Hardcoded to the
/// release-manifest payload type
/// `application/vnd.alibabacloud.confidential-computing.release+json`
/// (the `payloadType` the publisher signs over).
const DSSE_PAYLOAD_TYPE: &str = "application/vnd.alibabacloud.confidential-computing.release+json";
/// DSSE v1 pre-authentication encoding:
/// `DSSEv1 {len(ptype)} {ptype} {len(payload)} {payload}`. The PAE (with the
/// payload bytes appended after the space-terminated prefix) is what a DSSE
/// publisher signature is computed over.
fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let prefix = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut out = prefix.into_bytes();
    out.extend_from_slice(payload);
    out
}

/// Host-await function that verifies a DSSE publisher signature over a
/// reconstructed ReleaseManifest. regorus 0.11 ships no ECDSA builtin, so the
/// DSSEPAE + sha256 + ECDSA P-256 `VerifyASN1` primitive is injected here via
/// `OPAInMemory::with_extra_host_await_functions`, alongside `crypto.sha256`.
///
/// Takes a packed 3-element array `[payload_str, signature_b64, publisher_key_pem]`
/// (single-arg, since the host-await wrapper is single-arg). Computes
/// `dsse_pae(DSSE_PAYLOAD_TYPE, payload)` then verifies the base64-decoded DER
/// ECDSA signature with the P-256 publisher key — `p256::VerifyingKey::verify`
/// hashes the PAE with SHA-256 internally, equivalent to an ECDSA P-256
/// `VerifyASN1(sha256(pae), sig)`.
///
/// Fail-closed: any failure (mismatch, bad sig format, bad key) returns
/// `Ok(Bool(false))` so the rego `verify_dsse_signature(...) == true` check
/// cleanly sees `false` rather than aborting evaluation.
///
/// Only the ECDSA+PAE primitive is in Rust; manifest reconstruction
/// (`json.marshal`) and the comparison stay in rego. Gated on
/// `crypto-rustcrypto` (needs p256 + x509-cert, the same crates rekor_v1's key
/// module pulls in); the rego policy that calls this is itself only generated
/// under `crypto-rustcrypto`.
#[cfg(feature = "crypto-rustcrypto")]
fn verify_dsse_signature_host_await(
) -> attestation_service::policy_engine::opa::RegoVmHostAwaitFunction {
    use attestation_service::policy_engine::PolicyError;
    use p256::ecdsa::signature::Verifier;

    std::sync::Arc::new(|argument: regorus::Value| {
        Box::pin(async move {
            // argument = [payload_str, signature_b64, publisher_key_pem]
            let arr = argument.as_array().map_err(|e| {
                PolicyError::EvalPolicyFailed(anyhow::anyhow!(
                    "verify_dsse_signature arg not array: {e}"
                ))
            })?;
            let payload = arr
                .first()
                .and_then(|v| v.as_string().ok())
                .ok_or_else(|| {
                    PolicyError::EvalPolicyFailed(anyhow::anyhow!(
                        "verify_dsse_signature: missing payload"
                    ))
                })?;
            let sig_b64 = arr.get(1).and_then(|v| v.as_string().ok()).ok_or_else(|| {
                PolicyError::EvalPolicyFailed(anyhow::anyhow!(
                    "verify_dsse_signature: missing signature"
                ))
            })?;
            let key_pem = arr.get(2).and_then(|v| v.as_string().ok()).ok_or_else(|| {
                PolicyError::EvalPolicyFailed(anyhow::anyhow!(
                    "verify_dsse_signature: missing publisher key"
                ))
            })?;
            let verified = (|| -> anyhow::Result<bool> {
                let key = rekor_v1::parse_p256_public_key(key_pem.as_ref())?;
                let sig_bytes =
                    base64::engine::general_purpose::STANDARD.decode(sig_b64.as_ref())?;
                let signature = p256::ecdsa::Signature::from_der(&sig_bytes)?;
                let pae = dsse_pae(DSSE_PAYLOAD_TYPE, payload.as_bytes());
                // p256 VerifyingKey::verify hashes the PAE with SHA-256
                // internally == ECDSA P-256 over sha256(pae) (VerifyASN1).
                key.verify(&pae, &signature)?;
                Ok(true)
            })()
            .unwrap_or(false);
            Ok(regorus::Value::Bool(verified))
        })
    })
}

/// Build the host-await function injection vec for the builtin-AS OPA engine:
/// always `crypto.sha256`, plus `verify_dsse_signature` (DSSEPAE + sha256 +
/// ECDSA P-256) under `crypto-rustcrypto` — it needs p256/x509-cert, and the
/// transparency-log rego that calls it is itself only generated under that
/// feature. Both `OPAInMemory` construction sites (the prod converter and the
/// `eval_policy_vector` test helper) share this so the injected set stays in
/// sync.
fn builtin_as_host_await_functions() -> Vec<(
    String,
    attestation_service::policy_engine::opa::RegoVmHostAwaitFunction,
)> {
    let mut fns = vec![("crypto.sha256".to_string(), crypto_sha256_host_await())];
    #[cfg(feature = "crypto-rustcrypto")]
    fns.push((
        "verify_dsse_signature".to_string(),
        verify_dsse_signature_host_await(),
    ));
    fns
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use attestation_service::policy_engine::PolicyEngine as _;
    use reference_value_provider_service::rv_list::{
        ReferenceValueListItem, ReferenceValueProvenanceInfo, ReferenceValueProvenanceSource,
    };
    use serial_test::serial;
    use sha2::Digest;

    // Imports for the transparency_log e2e framework (fixture → CocoEvidence →
    // convert → verify_evidence). `tee_from_str` + `CocoEvidence` live in the
    // evidence module; `HashAlgo` in crate::crypto; `ReportData` in crate::tee.
    // (Not all of these are imported by the builtin mod, so pull them in here.)
    use crate::crypto::HashAlgo;
    use crate::tee::coco::evidence::tee_from_str;
    use crate::tee::{GenericConverter, GenericVerifier, ReportData};

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
    async fn test_load_hardware_with_reference_values_policy() {
        // Equivalent to the former Default: falls through to the AS built-in
        // trustee rego, so no inline content is registered.
        let policy_config = PolicyConfig::HardwareWithReferenceValues;
        let result =
            BuiltinCocoConverter::load_policy_as_base64_url_safe_no_pad(&policy_config).await;
        assert!(result.is_ok());
        assert!(
            result.unwrap().is_none(),
            "HardwareWithReferenceValues policy should return None"
        );
    }

    #[tokio::test]
    async fn test_load_hardware_strict_with_reference_values_policy() {
        let policy_config = PolicyConfig::HardwareStrictWithReferenceValues;
        let result =
            BuiltinCocoConverter::load_policy_as_base64_url_safe_no_pad(&policy_config).await;
        assert!(result.is_ok());
        let encoded = result
            .unwrap()
            .expect("Should return Some for HardwareStrictWithReferenceValues policy");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("Failed to decode policy");
        let content = String::from_utf8(decoded).expect("Invalid UTF-8");
        assert!(content.contains("tdx_debug_disabled"));
        assert!(content.contains("tdx_eventlog_present"));
        assert!(content.contains("validate_boot_measurements_uefi_event_log"));
    }

    #[tokio::test]
    async fn test_load_hardware_only_policy() {
        let policy_config = PolicyConfig::HardwareOnly;
        let result =
            BuiltinCocoConverter::load_policy_as_base64_url_safe_no_pad(&policy_config).await;
        assert!(result.is_ok());
        let encoded = result
            .unwrap()
            .expect("Should return Some for HardwareOnly policy");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("Failed to decode policy");
        let content = String::from_utf8(decoded).expect("Invalid UTF-8");
        assert!(content.contains("package policy"));
        assert!(content.contains("default hardware := 97"));
        assert!(content.contains("input.tdx.quote.header.tee_type"));
        assert!(content.contains(r#"vendor_id == "939a7233f79c4ca9940a0db3957f0607""#));
    }

    #[tokio::test]
    async fn test_load_hardware_only_strict_policy() {
        let policy_config = PolicyConfig::HardwareOnlyStrict;
        let result =
            BuiltinCocoConverter::load_policy_as_base64_url_safe_no_pad(&policy_config).await;
        assert!(result.is_ok());
        let encoded = result
            .unwrap()
            .expect("Should return Some for HardwareOnlyStrict policy");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("Failed to decode policy");
        let content = String::from_utf8(decoded).expect("Invalid UTF-8");
        assert!(content.contains("package policy"));
        assert!(content.contains("tdx_debug_disabled"));
        assert!(content.contains("tdx_eventlog_present"));
    }

    #[tokio::test]
    async fn test_load_trust_all_policy() {
        let policy_config = PolicyConfig::TrustAll;
        let result =
            BuiltinCocoConverter::load_policy_as_base64_url_safe_no_pad(&policy_config).await;
        assert!(result.is_ok());
        let encoded = result
            .unwrap()
            .expect("Should return Some for TrustAll policy");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("Failed to decode policy");
        let content = String::from_utf8(decoded).expect("Invalid UTF-8");
        assert!(content.contains("package policy"));
        assert!(content.contains("default hardware := 2"));
    }

    // === Reference value loading tests ===

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_sample_inline_reference() {
        let mut rvs = std::collections::HashMap::new();
        rvs.insert("example-measurement".to_string(), json!([]));
        let provenance = Provenance { rvs };
        let reference = ReferenceValueConfig::Sample {
            payload: SampleProvenancePayloadConfig::Inline {
                content: provenance,
            },
        };
        let result =
            BuiltinCocoConverter::new(&PolicyConfig::HardwareWithReferenceValues, &[reference])
                .await;
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
        BuiltinCocoConverter::new(&PolicyConfig::HardwareWithReferenceValues, &[reference])
            .await
            .expect("Failed to create converter with path sample reference");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_slsa_reference_and_provenance() {
        // NOTE: Despite the legacy test name, make test-dep-as now uploads
        // test-artifact as a release manifest bundle via rv-release-tool.
        // This test validates the OCI provenance fetching flow with the
        // rv-release-manifest provenance type.
        let rv_item = ReferenceValueListItem {
            id: "test-artifact".to_string(),
            version: "1.0.0".to_string(),
            rv_type: "binary".to_string(),
            provenance_info: ReferenceValueProvenanceInfo {
                provenance_type: "rv-release-manifest".to_string(),
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

        let reference = ReferenceValueConfig::ReleaseManifest {
            payload: SlsaReferenceValuePayloadConfig::Inline { content: payload },
        };
        BuiltinCocoConverter::new(&PolicyConfig::HardwareWithReferenceValues, &[reference])
            .await
            .expect("Failed to create converter with path slsa reference");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_release_manifest_reference() {
        let rv_item = ReferenceValueListItem {
            id: "cvm_container_proxy".to_string(),
            version: "1.0.0".to_string(),
            rv_type: "container".to_string(),
            provenance_info: ReferenceValueProvenanceInfo {
                provenance_type: "rv-release-manifest".to_string(),
                rekor_url: "https://log2025-1.rekor.sigstore.dev".to_string(),
                rekor_api_version: Some(2),
            },
            provenance_source: Some(ReferenceValueProvenanceSource {
                protocol: "oci".to_string(),
                uri: "oci://127.0.0.1:5000/trustee/provenance:cvm_container_proxy-1.0.0"
                    .to_string(),
                artifact: Some("bundle".to_string()),
            }),
            operation_type: "refresh".to_string(),
            rv_name: None,
        };
        let payload = ReferenceValueListPayload {
            rv_list: vec![rv_item],
        };

        let reference = ReferenceValueConfig::ReleaseManifest {
            payload: SlsaReferenceValuePayloadConfig::Inline { content: payload },
        };
        BuiltinCocoConverter::new(&PolicyConfig::HardwareWithReferenceValues, &[reference])
            .await
            .expect("Failed to create converter with release manifest reference");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_release_manifest_file_reference() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let bundle_path = dir.path().join("release-manifest.bundle.json");
        let manifest = r#"{"measurements":{"cvm_uki":{"algorithm":"sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},"schemaVersion":1}"#;
        tokio::fs::write(&bundle_path, format!(r#"{{"releasePayload":{manifest}}}"#))
            .await
            .expect("Failed to write bundle file");

        let ref_path = dir.path().join("release_manifest.json");
        let payload = serde_json::json!({
            "rv_list": [{
                "id": "cvm_uki",
                "version": "1.0.0",
                "type": "uki",
                "provenance_info": {
                    "type": "rv-release-manifest",
                    "rekor_url": "https://log2025-1.rekor.sigstore.dev",
                    "rekor_api_version": 2
                },
                "provenance_source": {
                    "protocol": "file",
                    "uri": bundle_path.to_string_lossy().to_string(),
                    "artifact": "bundle"
                },
                "operation_type": "refresh"
            }]
        });
        tokio::fs::write(&ref_path, payload.to_string())
            .await
            .expect("Failed to write ref file");

        let reference = ReferenceValueConfig::ReleaseManifest {
            payload: SlsaReferenceValuePayloadConfig::Path {
                path: ref_path.to_string_lossy().to_string(),
            },
        };
        BuiltinCocoConverter::new(&PolicyConfig::HardwareWithReferenceValues, &[reference])
            .await
            .expect("Failed to create converter with release manifest path reference");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_multiple_references() {
        let mut rvs1 = std::collections::HashMap::new();
        rvs1.insert("component-a".to_string(), json!([]));
        let provenance1 = Provenance { rvs: rvs1 };

        let mut rvs2 = std::collections::HashMap::new();
        rvs2.insert("component-b".to_string(), json!([]));
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
        let result =
            BuiltinCocoConverter::new(&PolicyConfig::HardwareWithReferenceValues, &references)
                .await;
        assert!(
            result.is_ok(),
            "Failed with multiple references: {:?}",
            result.err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_empty_references() {
        BuiltinCocoConverter::new(&PolicyConfig::HardwareWithReferenceValues, &[])
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
        let result =
            BuiltinCocoConverter::new(&PolicyConfig::HardwareWithReferenceValues, &[reference])
                .await;
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
            json!(["expected-value-1", "expected-value-2"]),
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
    fn test_reference_value_config_release_manifest_inline_serde() -> Result<(), serde_json::Error>
    {
        let rv_item = ReferenceValueListItem {
            id: "cvm_uki".to_string(),
            version: "1.0.0".to_string(),
            rv_type: "uki".to_string(),
            provenance_info: ReferenceValueProvenanceInfo {
                provenance_type: "rv-release-manifest".to_string(),
                rekor_url: "https://log2025-1.rekor.sigstore.dev".to_string(),
                rekor_api_version: Some(2),
            },
            provenance_source: Some(ReferenceValueProvenanceSource {
                protocol: "oci".to_string(),
                uri: "oci://127.0.0.1:5000/trustee/provenance:cvm_uki-1.0.0".to_string(),
                artifact: Some("bundle".to_string()),
            }),
            operation_type: "refresh".to_string(),
            rv_name: None,
        };
        let payload = ReferenceValueListPayload {
            rv_list: vec![rv_item],
        };

        let config = ReferenceValueConfig::ReleaseManifest {
            payload: SlsaReferenceValuePayloadConfig::Inline { content: payload },
        };

        let json_str = serde_json::to_string(&config).expect("Failed to serialize");
        assert!(json_str.contains("\"type\":\"release_manifest\""));

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
                    assert!(content.rvs.contains_key("example-key"));
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
            let converter =
                BuiltinCocoConverter::new(&PolicyConfig::HardwareWithReferenceValues, &[])
                    .await
                    .expect("Failed to create converter");
            let attester = CocoAttester::new(TEST_AA_ADDR).expect("Failed to create attester");
            let report_data = ReportData::Claims(serde_json::Map::new());
            let evidence = attester
                .get_evidence(&report_data)
                .await
                .expect("Failed to get evidence");
            let token = converter.convert(&evidence).await;
            if let Err(error) = &token {
                assert!(
                    format!("{error:?}")
                        .contains("feature `tdx-verifier` is not enabled for `verifier` crate"),
                    "{error:?}"
                );
                return;
            }
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
            if let Err(error) = &token {
                assert!(
                    format!("{error:?}")
                        .contains("feature `tdx-verifier` is not enabled for `verifier` crate"),
                    "{error:?}"
                );
                return;
            }

            assert!(
                token.is_ok(),
                "Convert with inline policy failed: {:?}",
                token.err()
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_builtin_convert_and_verify_roundtrip() {
            let converter =
                BuiltinCocoConverter::new(&PolicyConfig::HardwareWithReferenceValues, &[])
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

            // Convert evidence to token using builtin AS
            let token = converter.convert(&evidence).await;
            if let Err(error) = &token {
                assert!(
                    format!("{error:?}")
                        .contains("feature `tdx-verifier` is not enabled for `verifier` crate"),
                    "{error:?}"
                );
                return;
            }
            let token = token.expect("Failed to convert evidence");

            let result = verifier.verify_evidence(&token, &report_data).await;
            assert!(result.is_err());
            let error = result.unwrap_err();
            assert!(
                format!("{error:?}").contains("EarStatusNotAffirming"),
                "{error:?}"
            );
        }
    }

    // --- Rego behavior tests -------------------------------------------------
    // These evaluate the bundled rego templates through the real attestation-service
    // OPA engine (regorus, pure-Rust) against constructed evidence, asserting the
    // resulting trust vector. This is the only test that actually *executes* the
    // rego, so it guards against the class of bug the substring tests can't catch
    // (e.g. a typo in a TDX vendor_id that silently makes `hardware` never affirm).

    /// Evaluate a bundled rego policy against `input` and return the four AR4SI
    /// trust-vector values as (executables, hardware, configuration, file_system).
    async fn eval_policy_vector(policy: &str, input: &str) -> (i8, i8, i8, i8) {
        let engine = attestation_service::policy_engine::opa::OPAInMemory::with_raw_default_policy(
            policy,
            DEFAULT_POLICY_ID,
            // The artifact-server address is only consumed under
            // attestation-service's `policy-artifact-server` feature (not
            // enabled for these tests), so this value has no effect here.
            // Pass trustee's own default to mirror upstream usage.
            attestation_service::config::DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .expect("create OPA in-memory engine")
        // Inject `crypto.sha256` so the transparency-log rego policy's
        // `crypto.sha256(json.marshal(manifest))` call resolves to a real
        // sha256 during the behavior test below. Under `crypto-rustcrypto`,
        // `verify_dsse_signature` is injected too — see
        // `builtin_as_host_await_functions`.
        .with_extra_host_await_functions(builtin_as_host_await_functions());
        // The four rules our templates define. The real AS also queries four more
        // AR4SI claims (instance-identity, runtime-opaque, ...); those are simply
        // skipped when a policy leaves them undefined, so they need not be queried.
        let rules = vec![
            "executables".to_string(),
            "hardware".to_string(),
            "configuration".to_string(),
            "file_system".to_string(),
        ];
        // The upstream `PolicyEngine::evaluate` now resolves Rego
        // `query_reference_value(...)` calls through a `ReferenceValueResolver`
        // (backed by an `RvpsApi` implementor). None of these policy templates
        // query reference values, so an empty in-memory RVPS resolver suffices.
        let resolver = Arc::new(attestation_service::rvps::ReferenceValueResolver::new(
            Arc::new(
                attestation_service::rvps::builtin::BuiltinRvps::new(
                    reference_value_provider_service::config::Config {
                        storage: reference_value_provider_service::storage::ReferenceValueStorageConfig::InMemory(
                            reference_value_provider_service::storage::in_memory::Config {},
                        ),
                    },
                )
                .expect("create in-memory RVPS for policy test"),
            ) as Arc<dyn attestation_service::rvps::RvpsApi>,
        ));
        let result = engine
            .evaluate(input, DEFAULT_POLICY_ID, rules, resolver)
            .await
            .expect("evaluate policy");
        let get = |name: &str| -> i8 {
            result
                .rules_result
                .get(name)
                .and_then(|v| v.as_i64())
                .and_then(|n| i8::try_from(n).ok())
                .unwrap_or_else(|| panic!("policy did not produce a value for {name}"))
        };
        (
            get("executables"),
            get("hardware"),
            get("configuration"),
            get("file_system"),
        )
    }

    #[tokio::test]
    async fn test_rego_hardware_only_recognizes_known_tees() {
        let policy = include_str!("../policies/hardware_only.rego");

        // TDX with the canonical Intel quoting-enclave vendor_id -> all affirming.
        let tdx = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}}}}"#;
        assert_eq!(eval_policy_vector(policy, tdx).await, (2, 2, 2, 2));

        // Hygon CSV v2.
        let csv = r#"{"csv":{"version":"2"}}"#;
        assert_eq!(eval_policy_vector(policy, csv).await, (2, 2, 2, 2));

        // TPM and generic SYSTEM attesters.
        let tpm = r#"{"tpm":{"firmware_version":"1.0"}}"#;
        assert_eq!(eval_policy_vector(policy, tpm).await, (2, 2, 2, 2));
        let system = r#"{"system":{}}"#;
        assert_eq!(eval_policy_vector(policy, system).await, (2, 2, 2, 2));
    }

    #[tokio::test]
    async fn test_rego_hardware_only_rejects_unrecognized_hardware() {
        let policy = include_str!("../policies/hardware_only.rego");

        // A valid TDX tee_type but a WRONG vendor_id: hardware must stay at its
        // "unrecognized" default (97 -> Contraindicated), while the other three
        // dimensions remain affirming. This pins the exact canonical vendor_id.
        let tdx_bad_vendor = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}}}"#;
        assert_eq!(
            eval_policy_vector(policy, tdx_bad_vendor).await,
            (2, 97, 2, 2)
        );

        // No TEE evidence at all -> hardware stays unrecognized.
        assert_eq!(eval_policy_vector(policy, "{}").await, (2, 97, 2, 2));
    }

    #[tokio::test]
    async fn test_rego_hardware_only_strict_requires_non_debug_tdx_eventlog() {
        let policy = include_str!("../policies/hardware_only_strict.rego");

        let valid_tdx = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"},"body":{"td_attributes":"0000001000000080"}},"uefi_event_logs":[{"event":"ok"}]}}"#;
        assert_eq!(eval_policy_vector(policy, valid_tdx).await, (2, 2, 2, 2));

        let debug_tdx = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"},"body":{"td_attributes":"0100001000000080"}},"uefi_event_logs":[{"event":"ok"}]}}"#;
        assert_eq!(eval_policy_vector(policy, debug_tdx).await, (2, 97, 2, 2));

        let missing_eventlog = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"},"body":{"td_attributes":"0000001000000080"}}}}"#;
        assert_eq!(
            eval_policy_vector(policy, missing_eventlog).await,
            (2, 97, 2, 2)
        );
    }

    #[tokio::test]
    async fn test_rego_hardware_strict_with_reference_values_restricts_tdx_hardware() {
        let policy = BuiltinCocoConverter::build_hardware_strict_with_reference_values_policy()
            .expect("build strict reference-values policy");

        let valid_tdx = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"},"body":{"td_attributes":"0000001000000080"}},"uefi_event_logs":[{"event":"ok"}]}}"#;
        assert_eq!(eval_policy_vector(&policy, valid_tdx).await.1, 2);

        let debug_tdx = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"},"body":{"td_attributes":"0100001000000080"}},"uefi_event_logs":[{"event":"ok"}]}}"#;
        assert_eq!(eval_policy_vector(&policy, debug_tdx).await.1, 97);

        let missing_eventlog = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"},"body":{"td_attributes":"0000001000000080"}}}}"#;
        assert_eq!(eval_policy_vector(&policy, missing_eventlog).await.1, 97);
    }

    #[tokio::test]
    async fn test_rego_trust_all_affirms_everything() {
        let policy = include_str!("../policies/trust_all.rego");

        // trust_all affirms every dimension regardless of input, even with no
        // TEE evidence and an unrecognized vendor_id.
        assert_eq!(eval_policy_vector(policy, "{}").await, (2, 2, 2, 2));
        let bad_tdx =
            r#"{"tdx":{"quote":{"header":{"tee_type":"00000000","vendor_id":"deadbeef"}}}}"#;
        assert_eq!(eval_policy_vector(policy, bad_tdx).await, (2, 2, 2, 2));
    }

    #[test]
    fn transparency_log_config_round_trips() {
        let json = r#"{
            "type": "transparency_log",
            "publishedMeasurements": ["tdx.td-shim", "container.image.cmaas-runtime"],
            "schemaVersion": "1.0.0",
            "services": [{
                "type": "rekor-v1",
                "logUrl": "https://rekor.sigstore.dev",
                "logIndex": 2279770888
            }]
        }"#;
        let cfg: PolicyConfig = serde_json::from_str(json).expect("parse");
        match cfg {
            PolicyConfig::TransparencyLog {
                published_measurements,
                schema_version,
                services,
            } => {
                assert_eq!(
                    published_measurements,
                    Some(vec![
                        "tdx.td-shim".to_string(),
                        "container.image.cmaas-runtime".to_string()
                    ])
                );
                assert_eq!(schema_version, "1.0.0");
                assert_eq!(services.len(), 1);
                match &services[0] {
                    TransparencyServiceConfig::RekorV1 {
                        log_url,
                        log_index,
                        rekor_public_key_pem,
                        ..
                    } => {
                        assert_eq!(log_url, "https://rekor.sigstore.dev");
                        assert_eq!(*log_index, 2279770888);
                        assert!(rekor_public_key_pem.is_none());
                    }
                }
            }
            other => panic!("expected TransparencyLog, got {other:?}"),
        }
    }

    #[test]
    fn transparency_log_config_round_trips_with_publisher_key() {
        let json = r#"{
            "type": "transparency_log",
            "publishedMeasurements": ["container.image.cmaas-runtime"],
            "services": [{
                "type": "rekor-v1",
                "logUrl": "https://rekor.sigstore.dev",
                "logIndex": 2279770888,
                "publisherPublicKeyPem": "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"
            }]
        }"#;
        let cfg: PolicyConfig = serde_json::from_str(json).expect("parse");
        match cfg {
            PolicyConfig::TransparencyLog { services, .. } => match &services[0] {
                TransparencyServiceConfig::RekorV1 {
                    publisher_public_key_pem,
                    ..
                } => {
                    assert!(publisher_public_key_pem.is_some());
                }
            },
            _ => panic!(),
        }
    }

    #[test]
    fn transparency_log_schema_version_defaults_when_absent() {
        let json = r#"{
            "type": "transparency_log",
            "publishedMeasurements": ["tdx.td-shim"],
            "services": []
        }"#;
        let cfg: PolicyConfig = serde_json::from_str(json).expect("parse");
        match cfg {
            PolicyConfig::TransparencyLog { schema_version, .. } => {
                assert_eq!(schema_version, "1.0.0")
            }
            _ => panic!(),
        }
    }

    /// An absent `publishedMeasurements` field must deserialize to `None`
    /// (distinct from an explicit `[]`, which deserializes to `Some(vec![])`).
    /// `None` means "skip the measurement check entirely"; `Some([])` means
    /// "run the check against an empty manifest" (which fails). Keeping the
    /// two apart is the whole point of the `Option<Vec<String>>` field type.
    #[test]
    fn transparency_log_config_without_published_measurements() {
        let json = r#"{
            "type": "transparency_log",
            "schemaVersion": "1.0.0",
            "services": [{
                "type": "rekor-v1",
                "logUrl": "https://rekor.sigstore.dev",
                "logIndex": 2279770888
            }]
        }"#;
        let cfg: PolicyConfig = serde_json::from_str(json).expect("parse");
        match cfg {
            PolicyConfig::TransparencyLog {
                published_measurements,
                ..
            } => {
                assert_eq!(
                    published_measurements, None,
                    "absent publishedMeasurements must be None, not Some([])"
                );
            }
            other => panic!("expected TransparencyLog, got {other:?}"),
        }

        // Contrast: an explicit empty array is Some(vec![]), NOT None.
        let empty_json = r#"{
            "type": "transparency_log",
            "publishedMeasurements": [],
            "services": []
        }"#;
        let cfg: PolicyConfig = serde_json::from_str(empty_json).expect("parse");
        match cfg {
            PolicyConfig::TransparencyLog {
                published_measurements,
                ..
            } => {
                assert_eq!(published_measurements, Some(vec![]));
            }
            _ => panic!(),
        }
    }

    /// When `publishedMeasurements` is absent (`None`), the generated policy
    /// skips measurement reconstruction + verification entirely: `executables`
    /// stays at its affirming default (2), so a valid TDX platform input
    /// affirms across all four trust dimensions without any manifest-hash
    /// comparison. Only the TDX hardware checks gate the appraisal.
    #[tokio::test]
    async fn transparency_log_rego_affirms_when_published_measurements_absent() {
        let payload_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let policy = build_transparency_log_policy(payload_hash, "1.0.0", None, None, None);

        // Valid TDX platform input (non-debug, canonical Intel vendor_id, event
        // log present). No AAEL image event is needed: with publishedMeasurements
        // absent the manifest is never reconstructed, so the payloadHash is
        // irrelevant to the appraisal outcome here.
        let ok = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"},"body":{"td_attributes":"0000001000000000"}},"uefi_event_logs":[{"event":"ok"}]}}"#;
        assert_eq!(
            eval_policy_vector(&policy, ok).await,
            (2, 2, 2, 2),
            "absent publishedMeasurements must affirm on a valid TDX platform"
        );

        // Debug bit set must still reject on hardware (125) — the platform
        // checks run regardless of the measurement check being skipped.
        let debug = ok.replace("\"0000001000000000\"", "\"0100001000000000\"");
        assert_eq!(
            eval_policy_vector(&policy, &debug).await,
            (2, 125, 2, 2),
            "absent publishedMeasurements must still reject a debug TDX"
        );
    }

    /// With `publishedMeasurements` absent, an input that would normally fail
    /// the manifest-hash check (no AAEL event, so `actual_measurement` is
    /// undefined) still affirms on `executables` — proving the measurement
    /// block was genuinely elided, not just made permissive. Compare against
    /// `transparency_log_rego_affirms_on_matching_measurements`, where the same
    /// no-AAEL input under a `Some(["container.image.cmaas-runtime"])` policy
    /// yields `(97, 33, 2, 2)`.
    #[tokio::test]
    async fn transparency_log_rego_skips_measurements_when_absent() {
        let payload_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let policy = build_transparency_log_policy(payload_hash, "1.0.0", None, None, None);

        // No AAEL event at all — under a Some([...]) policy this would drop the
        // measurement and mismatch the (deliberately wrong) payloadHash → 97.
        // Under the None policy the measurement check is skipped → executables 2.
        let no_aael = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"},"body":{"td_attributes":"0000001000000000"}},"uefi_event_logs":[]}}"#;
        assert_eq!(
            eval_policy_vector(&policy, no_aael).await,
            (2, 33, 2, 2),
            "absent publishedMeasurements must skip the measurement check (executables=2)"
        );
    }

    #[tokio::test]
    async fn transparency_log_rego_affirms_on_matching_measurements() {
        // Real fixture manifest: {schemaVersion:1.0.0, measurements:[{type:
        // container.image.cmaas-runtime, value: sha256:d42f6e1b...}]}. Its
        // sha256(json.marshal) == the real rekor payloadHash.
        let payload_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let policy = build_transparency_log_policy(
            payload_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            None,
            None,
        );

        // Matching input: AAEL kangaroo/pull-image event for cmaas-runtime with the exact digest.
        let ok = format!(
            r#"{{"tdx":{{"quote":{{"header":{{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}},"body":{{"td_attributes":"0000001000000000"}}}},"uefi_event_logs":[{{"type_name":"EV_EVENT_TAG","details":{{"unicode_name":"AAEL","data":{{"domain":"alibabacloud.com","operation":"kangaroo/pull-image","content":{{"reference":"registry.example.com/ns/cmaas-runtime:latest","digest":{digest:?}}}}}}}}}]}}}}"#
        );
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "matching measurements must affirm"
        );

        // Tampered digest -> reject (hardware non-affirming).
        let bad = ok.replace(
            digest,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(eval_policy_vector(&policy, &bad).await, (97, 2, 2, 2));

        // Wrong repo -> reject.
        let wrong_repo = ok.replace("cmaas-runtime", "other-runtime");
        assert_eq!(
            eval_policy_vector(&policy, &wrong_repo).await,
            (97, 2, 2, 2)
        );

        // No AAEL event -> reject.
        let no_aael = r#"{"tdx":{"quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"},"body":{"td_attributes":"0000001000000000"}},"uefi_event_logs":[]}}"#;
        assert_eq!(eval_policy_vector(&policy, no_aael).await, (97, 33, 2, 2));

        // Debug bit set -> reject.
        let debug = ok.replace("\"0000001000000000\"", "\"0100001000000000\"");
        assert_eq!(eval_policy_vector(&policy, &debug).await, (2, 125, 2, 2));
    }

    /// Build the synthetic matching input for the `container.image.cmaas-runtime`
    /// measurement: a TDX quote (non-debug, canonical Intel vendor_id) with one
    /// AAEL `kangaroo/pull-image` event carrying the exact image digest. Mirrors
    /// the inline `ok` string in
    /// `transparency_log_rego_affirms_on_matching_measurements` so the tampering
    /// tests below share one canonical happy-path input.
    fn matching_cmaas_input(digest: &str) -> String {
        format!(
            r#"{{"tdx":{{"quote":{{"header":{{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}},"body":{{"td_attributes":"0000001000000000"}}}},"uefi_event_logs":[{{"type_name":"EV_EVENT_TAG","details":{{"unicode_name":"AAEL","data":{{"domain":"alibabacloud.com","operation":"kangaroo/pull-image","content":{{"reference":"registry.example.com/ns/cmaas-runtime:latest","digest":{digest:?}}}}}}}}}]}}}}"#
        )
    }

    /// Tampering `publishedMeasurements` (a wrong measurement type name) must
    /// reject: the rego `actual_measurement("container.image.cmaas-WRONG")` rule
    /// finds no matching AAEL event (the input's repo is `cmaas-runtime`) →
    /// `actual_measurement` is undefined → the measurement is dropped from the
    /// reconstructed manifest → its hash ≠ `payload_hash` → `measurements_verified`
    /// false → hardware stays non-affirming (97). The correct type name affirms,
    /// so this is not a tautology.
    #[tokio::test]
    async fn transparency_log_rego_rejects_wrong_measurement_type() {
        let payload_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let ok = matching_cmaas_input(digest);

        // Correct measurement type name → affirm (not a tautology).
        let correct_policy = build_transparency_log_policy(
            payload_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            None,
            None,
        );
        assert_eq!(
            eval_policy_vector(&correct_policy, &ok).await,
            (2, 2, 2, 2),
            "correct measurement type name must affirm"
        );

        // Wrong measurement type name → no matching AAEL event → reject.
        let wrong_policy = build_transparency_log_policy(
            payload_hash,
            "1.0.0",
            Some(&["container.image.cmaas-WRONG".to_string()]),
            None,
            None,
        );
        assert_eq!(
            eval_policy_vector(&wrong_policy, &ok).await,
            (97, 2, 2, 2),
            "wrong measurement type name must reject"
        );
    }

    /// Tampering `schemaVersion` must reject: the reconstructed manifest carries
    /// the baked `schema_version`, so a wrong value (e.g. "9.9.9") changes the
    /// `json.marshal` output → `crypto.sha256(manifest) != payload_hash` → reject.
    /// The correct "1.0.0" affirms, so this is not a tautology.
    #[tokio::test]
    async fn transparency_log_rego_rejects_wrong_schema_version() {
        let payload_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let ok = matching_cmaas_input(digest);

        // Correct schema version "1.0.0" → affirm.
        let correct_policy = build_transparency_log_policy(
            payload_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            None,
            None,
        );
        assert_eq!(
            eval_policy_vector(&correct_policy, &ok).await,
            (2, 2, 2, 2),
            "correct schema version must affirm"
        );

        // Wrong schema version "9.9.9" → reconstructed manifest hash mismatches →
        // reject.
        let wrong_policy = build_transparency_log_policy(
            payload_hash,
            "9.9.9",
            Some(&["container.image.cmaas-runtime".to_string()]),
            None,
            None,
        );
        assert_eq!(
            eval_policy_vector(&wrong_policy, &ok).await,
            (97, 2, 2, 2),
            "wrong schema version must reject"
        );
    }

    /// Tampering the baked `payload_hash` must reject: the rego recomputes
    /// `crypto.sha256(json.marshal(manifest))` from the actual evidence and
    /// compares to the baked value, so a wrong baked hash never matches → reject.
    /// The real payload hash affirms, so this is not a tautology.
    #[tokio::test]
    async fn transparency_log_rego_rejects_wrong_payload_hash() {
        let real_digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let ok = matching_cmaas_input(real_digest);

        // Correct payload hash → affirm.
        let correct_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let correct_policy = build_transparency_log_policy(
            correct_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            None,
            None,
        );
        assert_eq!(
            eval_policy_vector(&correct_policy, &ok).await,
            (2, 2, 2, 2),
            "correct payload hash must affirm"
        );

        // Wrong payload hash → recomputed manifest hash never matches → reject.
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let wrong_policy = build_transparency_log_policy(
            wrong_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            None,
            None,
        );
        assert_eq!(
            eval_policy_vector(&wrong_policy, &ok).await,
            (97, 2, 2, 2),
            "wrong payload hash must reject"
        );
    }

    /// Tampering the `publishedMeasurements` ORDER must reject. The rego
    /// reconstructs the manifest's `measurements` array iterating
    /// `published_measurements` in order, so a reversed order produces a
    /// different `json.marshal` output → hash ≠ `payload_hash` → reject. The real
    /// fixture has only one measurement, so this is a SYNTHETIC two-measurement
    /// case: `[cmaas-runtime, td-shim]`. The `payload_hash` is computed from the
    /// forward-order manifest (JCS sorted-compact + sha256, exactly what rego's
    /// `json.marshal` yields), so the forward-order policy genuinely affirms (not
    /// a tautology); the reversed-order policy rejects.
    #[tokio::test]
    async fn transparency_log_rego_rejects_wrong_measurement_order() {
        let cmaas_digest =
            "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let mr_td = "321ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";

        // Forward-order manifest — the order the CORRECT policy uses. Compute
        // its payloadHash the same way the rego will at appraisal (JCS
        // sorted-compact, then sha256), so the affirm case is genuinely correct.
        let forward = serde_json::json!({
            "measurements": [
                {"type": "container.image.cmaas-runtime", "value": cmaas_digest},
                {"type": "tdx.td-shim", "value": mr_td},
            ],
            "schemaVersion": "1.0.0",
        });
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, jcs_compact(&forward).as_bytes());
        let payload_hash = hex::encode(sha2::Digest::finalize(hasher));

        // Input carries BOTH the AAEL cmaas event (→ cmaas_digest) AND `mr_td`
        // in the quote body (→ td-shim value), so both measurement types resolve.
        let ok = format!(
            r#"{{"tdx":{{"quote":{{"header":{{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}},"body":{{"mr_td":{mr_td:?},"td_attributes":"0000001000000000"}}}},"uefi_event_logs":[{{"type_name":"EV_EVENT_TAG","details":{{"unicode_name":"AAEL","data":{{"domain":"alibabacloud.com","operation":"kangaroo/pull-image","content":{{"reference":"registry.example.com/ns/cmaas-runtime:latest","digest":{cmaas_digest:?}}}}}}}}}]}}}}"#
        );

        // Correct order [cmaas, td-shim] → rego reconstructs the forward manifest
        // → hash == payload_hash → affirm.
        let correct_policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&[
                "container.image.cmaas-runtime".to_string(),
                "tdx.td-shim".to_string(),
            ]),
            None,
            None,
        );
        assert_eq!(
            eval_policy_vector(&correct_policy, &ok).await,
            (2, 2, 2, 2),
            "correct measurement order must affirm"
        );

        // Reversed order [td-shim, cmaas] → rego builds the measurements array in
        // reversed order → json.marshal differs → hash ≠ payload_hash → reject.
        let reversed_policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&[
                "tdx.td-shim".to_string(),
                "container.image.cmaas-runtime".to_string(),
            ]),
            None,
            None,
        );
        assert_eq!(
            eval_policy_vector(&reversed_policy, &ok).await,
            (97, 2, 2, 2),
            "wrong measurement order must reject"
        );
    }

    /// Mirror of `transparency_log_rego_affirms_on_matching_measurements` for the
    /// `tdx.td-shim` reconstruction path. The rego rule
    /// `actual_measurement("tdx.td-shim") := input.tdx.quote.body.mr_td` is never
    /// exercised by the container test above, so a typo in the `mr_td` path would
    /// ship undetected without this test. The expected `payloadHash` is computed
    /// self-contained (JCS-canonicalize + sha256) so the test stays correct if the
    /// fixture value changes.
    #[tokio::test]
    async fn transparency_log_rego_affirms_on_matching_td_shim_measurement() {
        // 96-hex MRTD value (real value from the evidence fixture).
        let mr_td = "321ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";

        // Build the logged manifest and compute its payloadHash the same way the
        // rego policy will at appraisal (JCS — sorted, compact — then sha256).
        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{
                "type": "tdx.td-shim",
                "value": mr_td,
            }]
        });
        let canonical = jcs_compact(&manifest);
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, canonical.as_bytes());
        let payload_hash = hex::encode(sha2::Digest::finalize(hasher));

        let policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&["tdx.td-shim".to_string()]),
            None,
            None,
        );

        // Matching input: mr_td in the quote body matches the logged manifest.
        // A non-empty uefi_event_logs is required because the rego `hardware`
        // rule gates on `tdx_eventlog_present` (count > 0); the td-shim path reads
        // mr_td from the quote body, so the event-log contents are irrelevant
        // here — a minimal entry satisfies the presence check.
        let ok = format!(
            r#"{{"tdx":{{"quote":{{"header":{{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}},"body":{{"mr_td":{mr_td:?},"td_attributes":"0000001000000000"}}}},"uefi_event_logs":[{{"type_name":"EV_EVENT_TAG","details":{{"unicode_name":"AAEL","data":{{}}}}}}]}}}}"#
        );
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "matching td-shim mr_td must affirm"
        );

        // Tampered mr_td (flip one hex digit) -> reconstructed manifest hash
        // mismatches payload_hash -> measurements_verified fails -> reject.
        let tampered = "421ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";
        let bad = ok.replace(mr_td, tampered);
        assert_eq!(
            eval_policy_vector(&policy, &bad).await,
            (97, 2, 2, 2),
            "tampered td-shim mr_td must reject on hardware"
        );
    }

    /// DSSE publisher-signature behavior test for the `transparency_log` rego:
    /// with the real fixture DSSE signature + the fixture's in-band publisher
    /// key baked, (1) a matching reconstructed manifest affirms (payloadHash
    /// AND DSSE both pass), (2) a tampered digest rejects (payloadHash AND DSSE
    /// both fail), (3) a wrong publisher key baked rejects even when the
    /// payloadHash still matches (DSSE gates — publisher-identity binding). The
    /// signature + key are extracted from the real rekor fixture the same way
    /// the `verify_dsse_signature` primitive's S3 unit test does.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_affirms_with_dsse_publisher_signature() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        // Real fixture entry: extract body.spec.signatures[0].{signature,
        // verifier}. `verifier` is base64 of the publisher PEM — decode it.
        let entry_raw = include_str!("tests/fixtures/rekor_v1_entry.json");
        let entry: serde_json::Value = serde_json::from_str(entry_raw).expect("parse fixture");
        let body_bytes = STANDARD
            .decode(entry["body"].as_str().expect("body"))
            .expect("decode entry body");
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("parse body");
        let sig0 = &body["spec"]["signatures"][0];
        let dsse_signature = sig0["signature"].as_str().expect("signature").to_string();
        let publisher_key = String::from_utf8(
            STANDARD
                .decode(sig0["verifier"].as_str().expect("verifier"))
                .expect("decode verifier b64"),
        )
        .expect("publisher PEM utf8");

        // Real payloadHash 1011b70c... and the real cmaas-runtime image digest.
        let payload_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";

        let policy = build_transparency_log_policy(
            payload_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            Some(&dsse_signature),
            Some(&publisher_key),
        );

        // Matching input: AAEL kangaroo/pull-image event for cmaas-runtime with
        // the exact digest -> payloadHash AND DSSE both pass -> affirm.
        let ok = format!(
            r#"{{"tdx":{{"quote":{{"header":{{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}},"body":{{"td_attributes":"0000001000000000"}}}},"uefi_event_logs":[{{"type_name":"EV_EVENT_TAG","details":{{"unicode_name":"AAEL","data":{{"domain":"alibabacloud.com","operation":"kangaroo/pull-image","content":{{"reference":"registry.example.com/ns/cmaas-runtime:latest","digest":{digest:?}}}}}}}}}]}}}}"#
        );
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "matching manifest with real DSSE signature + publisher key must affirm"
        );

        // Tampered digest -> reconstructed manifest hash mismatches payloadHash
        // AND the reconstructed payload no longer matches the DSSE signature ->
        // measurements_verified fails -> reject.
        let bad = ok.replace(
            digest,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(
            eval_policy_vector(&policy, &bad).await,
            (97, 2, 2, 2),
            "tampered digest must reject (payloadHash AND DSSE both fail)"
        );

        // Wrong publisher key baked: the payloadHash still matches (so the
        // cheap pre-filter would pass), but DSSE verify fails because the
        // signature is not bound to this key -> reject. A different valid P-256
        // public key (the Sigstore Rekor v1 key) serves as the bogus publisher.
        let bogus_pem = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n\
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n\
-----END PUBLIC KEY-----\n";
        let wrong_policy = build_transparency_log_policy(
            payload_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            Some(&dsse_signature),
            Some(bogus_pem),
        );
        assert_eq!(
            eval_policy_vector(&wrong_policy, &ok).await,
            (97, 2, 2, 2),
            "wrong publisher key must reject even when payloadHash matches (DSSE gates)"
        );
    }

    /// Prove the canonical (JCS — sorted, compact) form of the manifest hashes
    /// to the REAL rekor payloadHash. This is the form regorus's `json.marshal`
    /// produces (it serializes object keys in sorted order), so the rego
    /// `crypto.sha256(json.marshal(manifest)) == payload_hash` comparison is
    /// valid. TNG's `serde_json` is built with `preserve_order` (insertion order,
    /// NOT sorted), so raw `serde_json::to_string` does not yield JCS — the keys
    /// must be sorted first.
    #[test]
    fn serde_json_serialization_matches_real_rekor_payload_hash() {
        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{
                "type": "container.image.cmaas-runtime",
                "value": "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46"
            }]
        });
        let s = jcs_compact(&manifest);
        let mut h = sha2::Sha256::new();
        sha2::Digest::update(&mut h, s.as_bytes());
        let got = hex::encode(sha2::Digest::finalize(h));
        assert_eq!(
            got, "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8",
            "JCS (sorted compact) form must equal the real rekor payloadHash"
        );
    }

    /// `resolve_dsse_signature` decides what (if anything) to bake as the DSSE
    /// publisher signature. A real rekor v1 `dsse` entry always carries a
    /// signature, so an empty signature with a configured publisher key is a
    /// config/entry mismatch that must fail closed (not silently fall back to
    /// payloadHash-only). With no publisher key, an empty signature simply
    /// yields `None` (payloadHash-only is the intended fallback there).
    #[test]
    fn resolve_dsse_signature_matches_expectations() {
        // empty signature, no publisher key -> payloadHash-only fallback
        assert_eq!(
            resolve_dsse_signature("", None).expect("no-key empty -> None"),
            None
        );
        // non-empty signature, no publisher key -> bake it (harmless when no
        // verify is wired, but the entry did carry one)
        assert_eq!(
            resolve_dsse_signature("sig", None).expect("no-key sig -> Some"),
            Some("sig")
        );
        // non-empty signature + publisher key -> bake it (DSSE verify wired)
        assert_eq!(
            resolve_dsse_signature("sig", Some("key")).expect("key+sig -> Some"),
            Some("sig")
        );
        // empty signature + publisher key -> config/entry mismatch, fail closed
        let err = resolve_dsse_signature("", Some("key")).expect_err("key+empty must fail closed");
        assert!(
            err.to_string().contains("config/entry mismatch"),
            "error should describe the mismatch, got: {err}"
        );
    }

    /// Serialize a `serde_json::Value` as compact JSON with object keys sorted
    /// (RFC 8785 JCS ordering for this shape — no numbers, so JCS == sorted
    /// compact). Needed because TNG's `serde_json` preserves insertion order.
    fn jcs_compact(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut s = String::from("{");
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str(&serde_json::to_string(k).unwrap());
                    s.push(':');
                    s.push_str(&jcs_compact(&map[*k]));
                }
                s.push('}');
                s
            }
            serde_json::Value::Array(arr) => {
                let items: Vec<String> = arr.iter().map(jcs_compact).collect();
                format!("[{}]", items.join(","))
            }
            _ => serde_json::to_string(value).unwrap(),
        }
    }

    /// Prove the real fixture's DSSE signature verifies with its own
    /// in-band publisher key over the real ReleaseManifest, via the same
    /// DSSEPAE + sha256 + ECDSA P-256 path the `verify_dsse_signature`
    /// host-await primitive uses. Tampering the manifest digest, or
    /// substituting a different publisher key, must fail verification
    /// (fail-closed → false). This is the RED→GREEN test for the primitive:
    /// `dsse_pae`/`parse_p256_public_key`/`DSSE_PAYLOAD_TYPE` are the SUT.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_dsse_signature_validates_real_fixture_signature() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        use p256::ecdsa::signature::Verifier;

        // Real fixture entry: extract body.spec.signatures[0].{signature, verifier}.
        // `verifier` is base64 of the publisher PEM — decode it to get the PEM.
        let entry_raw = include_str!("tests/fixtures/rekor_v1_entry.json");
        let entry: serde_json::Value = serde_json::from_str(entry_raw).expect("parse fixture");
        let body_bytes = STANDARD
            .decode(entry["body"].as_str().expect("body"))
            .expect("decode entry body");
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("parse body");
        let sig0 = &body["spec"]["signatures"][0];
        let sig_b64 = sig0["signature"].as_str().expect("signature").to_string();
        let verifier_pem = String::from_utf8(
            STANDARD
                .decode(sig0["verifier"].as_str().expect("verifier"))
                .expect("decode verifier b64"),
        )
        .expect("publisher PEM utf8");

        // Real manifest (runtime image digest). JCS (sorted compact) is
        // the form regorus's `json.marshal` produces and the form the publisher signs over.
        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{
                "type": "container.image.cmaas-runtime",
                "value": "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46"
            }]
        });
        let payload = jcs_compact(&manifest);

        // Mirror the primitive's verify path: dsse_pae + p256 verify (which
        // hashes the PAE with SHA-256 internally == ECDSA P-256 over sha256(pae) (VerifyASN1)).
        let verify = |payload_str: &str, sig_b64: &str, key_pem: &str| -> bool {
            (|| -> anyhow::Result<bool> {
                let key = rekor_v1::parse_p256_public_key(key_pem)?;
                let sig_bytes = STANDARD.decode(sig_b64)?;
                let signature = p256::ecdsa::Signature::from_der(&sig_bytes)?;
                let pae = dsse_pae(DSSE_PAYLOAD_TYPE, payload_str.as_bytes());
                key.verify(&pae, &signature)?;
                Ok(true)
            })()
            .unwrap_or(false)
        };

        // Real fixture sig + the fixture's own publisher key → true.
        assert!(
            verify(&payload, &sig_b64, &verifier_pem),
            "real fixture DSSE signature must verify with its publisher key"
        );

        // Tamper a digest char → verify fails (false).
        let tampered = payload.replace(
            "d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
            "e42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
        );
        assert_ne!(payload, tampered, "tamper did not change payload");
        assert!(
            !verify(&tampered, &sig_b64, &verifier_pem),
            "tampered manifest must fail DSSE verification"
        );

        // A different valid P-256 public key (the Sigstore Rekor v1 key) over
        // the real payload → verify fails (false). Confirms the signature is
        // bound to the fixture's publisher key, not just any well-formed key.
        let wrong_pem = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n\
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n\
-----END PUBLIC KEY-----\n";
        assert!(
            !verify(&payload, &sig_b64, wrong_pem),
            "wrong publisher key must fail DSSE verification"
        );
    }

    /// Requires live network access to rekor.sigstore.dev (fetch by logIndex).
    /// Uses a hardcoded config (logIndex 2544139140, publishedMeasurements
    /// ["container.image.cmaas-runtime"], schemaVersion "1.0.0"). Un-ignore
    /// once a confirmed-valid config + network is available. Needs
    /// `crypto-rustcrypto` (default feature set has it).
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn new_with_transparency_log_policy_fetches_reference_values() {
        // Simple hardcoded config — the converter fetches the rekor entry by
        // logIndex 2544139140 from rekor.sigstore.dev + authenticates it
        // (checkpoint + inclusion + SET) + bakes the trusted payloadHash.
        let cfg: PolicyConfig = serde_json::from_str(
            r#"
            {
                "type": "transparency_log",
                "publishedMeasurements": [
                    "container.image.cmaas-runtime"
                ],
                "schemaVersion": "1.0.0",
                "services": [
                    {
                        "type": "rekor-v1",
                        "logUrl": "https://rekor.sigstore.dev",
                        "logIndex": 2544139140
                    }
                ]
            }
        "#,
        )
        .expect("parse transparency_log config");
        let result = BuiltinCocoConverter::new(&cfg, &[]).await;
        assert!(
            result.is_ok(),
            "BuiltinCocoConverter::new with TransparencyLog policy failed: {:?}",
            result.err()
        );
    }

    // --- transparency_log e2e tampering test --------------------------------
    // One comprehensive test: shared helper (converter.new → convert →
    // verify_evidence) + systematic tampering of EVERY config field + evidence
    // field. Each tampering must cause the flow to fail (new() Err, convert()
    // Err, or verify_evidence Err). #[ignore]d — needs live rekor network +
    // the real TDX attestation-materials fixture.

    /// The shared main flow: parse config → converter.new (live rekor fetch +
    /// authenticate + bake payloadHash) → build CocoEvidence from quote +
    /// cc_eventlog → convert → verify_evidence. Returns Ok(()) on affirm,
    /// Err on any rejection (new/convert/verify failure).
    async fn run_transparency_log_appraisal(
        cfg_json: &str,
        quote: &str,
        cc_eventlog: &str,
    ) -> Result<()> {
        let cfg: PolicyConfig = serde_json::from_str(cfg_json)?;
        let converter = BuiltinCocoConverter::new(&cfg, &[])
            .await?
            .for_testing_skip_runtime_data();
        let verifier = converter.new_verifier().await?;
        let evidence = build_cmaas_evidence(quote, cc_eventlog);
        let token = converter.convert(&evidence).await;
        let token = match token {
            Ok(t) => t,
            Err(error) => {
                if format!("{error:?}")
                    .contains("feature `tdx-verifier` is not enabled for `verifier` crate")
                {
                    return Ok(()); // environment limitation, not a real failure
                }
                return Err(error.into());
            }
        };
        verifier.verify_evidence(&token, &ReportData::None).await?;
        Ok(())
    }

    /// Load the real cmaas evidence fixture → (quote, cc_eventlog) base64.
    fn cmaas_fixture_quote_and_eventlog() -> (String, String) {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "tests/fixtures/cmaas_evidence_with_rekor_v1_transparency.json"
        ))
        .expect("parse evidence fixture");
        let ev = &fixture["evidence"];
        (
            ev["quote"].as_str().expect("quote").to_string(),
            ev["cc_eventlog"].as_str().expect("cc_eventlog").to_string(),
        )
    }

    /// Build CocoEvidence from a quote + cc_eventlog pair (TDX, test mode).
    fn build_cmaas_evidence(quote: &str, cc_eventlog: &str) -> CocoEvidence {
        let tee = tee_from_str("tdx").expect("tee");
        let aa_evidence = serde_json::to_vec(&serde_json::json!({
            "quote": quote,
            "cc_eventlog": cc_eventlog,
        }))
        .expect("serialize aa_evidence");
        CocoEvidence::new(tee, aa_evidence, None, "{}".to_string(), HashAlgo::Sha256)
            .expect("build CocoEvidence")
    }

    /// Flip one base64 char (A↔B) to corrupt the decoded bytes.
    fn flip_one_char(s: &str) -> String {
        let mut chars: Vec<char> = s.chars().collect();
        let idx = chars
            .iter()
            .position(|c| *c == 'A' || *c == 'B')
            .unwrap_or(0);
        chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
        chars.into_iter().collect()
    }

    /// A valid P-256 PEM that is NOT the rekor signing key (the cmaas publisher
    /// key) — used as a bogus rekorPublicKeyPem / publisherPublicKeyPem.
    const BOGUS_P256_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsGjh0eIF22/JwEkRvU5KROvNsL/F\nK6qP/kbKO0CoelOqRKJQuC9z0ruwyx12S94/m69+iaan0SKR1IJjIbbfHw==\n-----END PUBLIC KEY-----\n";

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn evidence_appraises_with_transparency_log_policy() {
        // --- The two base inputs ---
        let cfg = r#"{"type":"transparency_log","publishedMeasurements":["container.image.cmaas-runtime"],"schemaVersion":"1.0.0","services":[{"type":"rekor-v1","logUrl":"https://rekor.sigstore.dev","logIndex":2310520944}]}"#;
        let (quote, cc_eventlog) = cmaas_fixture_quote_and_eventlog();

        // --- Happy path: correct config + correct evidence → affirm ---
        assert!(
            run_transparency_log_appraisal(cfg, &quote, &cc_eventlog)
                .await
                .is_ok(),
            "correct config + evidence must affirm"
        );

        // --- Tamper each CONFIG field → must fail ---

        // 1. Wrong publishedMeasurements (type name)
        let cfg_t1 = cfg.replace("cmaas-runtime", "cmaas-WRONG");
        assert!(
            run_transparency_log_appraisal(&cfg_t1, &quote, &cc_eventlog)
                .await
                .is_err(),
            "wrong publishedMeasurements type must fail"
        );

        // 2. Wrong schemaVersion
        let cfg_t2 = cfg.replace("1.0.0", "9.9.9");
        assert!(
            run_transparency_log_appraisal(&cfg_t2, &quote, &cc_eventlog)
                .await
                .is_err(),
            "wrong schemaVersion must fail"
        );

        // 3. Wrong logIndex (out-of-range → fetch 404)
        let cfg_t3 = cfg.replace("2310520944", "99999999999");
        assert!(
            run_transparency_log_appraisal(&cfg_t3, &quote, &cc_eventlog)
                .await
                .is_err(),
            "wrong logIndex must fail"
        );

        // 4. Wrong logUrl (non-existent host → fetch fails)
        let cfg_t4 = cfg.replace("rekor.sigstore.dev", "rekor.invalid.example");
        assert!(
            run_transparency_log_appraisal(&cfg_t4, &quote, &cc_eventlog)
                .await
                .is_err(),
            "wrong logUrl must fail"
        );

        // 5. Wrong rekorPublicKeyPem (bogus P-256 key → logID/checkpoint/SET fails)
        let cfg_t5 = cfg.replace(
            "\"logIndex\":2310520944}",
            &format!(
                "\"logIndex\":2310520944,\"rekorPublicKeyPem\":\"{}\"}}",
                BOGUS_P256_PEM
            ),
        );
        assert!(
            run_transparency_log_appraisal(&cfg_t5, &quote, &cc_eventlog)
                .await
                .is_err(),
            "wrong rekorPublicKeyPem must fail"
        );

        // 6. Wrong publisherPublicKeyPem (bogus key → DSSE verify fails)
        let cfg_t6 = cfg.replace(
            "\"logIndex\":2310520944}",
            &format!(
                "\"logIndex\":2310520944,\"publisherPublicKeyPem\":\"{}\"}}",
                BOGUS_P256_PEM
            ),
        );
        assert!(
            run_transparency_log_appraisal(&cfg_t6, &quote, &cc_eventlog)
                .await
                .is_err(),
            "wrong publisherPublicKeyPem must fail"
        );

        // --- Tamper each EVIDENCE field → must fail ---

        // 7. Tampered quote (flip a char → DCAP signature fails)
        let tampered_quote = flip_one_char(&quote);
        assert!(
            run_transparency_log_appraisal(cfg, &tampered_quote, &cc_eventlog)
                .await
                .is_err(),
            "tampered quote must fail"
        );

        // 8. Tampered cc_eventlog (replace with empty → no AAEL events → reject)
        assert!(
            run_transparency_log_appraisal(cfg, &quote, "AAAA")
                .await
                .is_err(),
            "tampered cc_eventlog must fail"
        );
    }
}

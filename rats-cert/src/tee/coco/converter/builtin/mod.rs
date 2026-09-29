//! Builtin Attestation Service Converter
//!
//! This module implements local evidence verification using the embedded attestation-service crate.
//! It converts CocoEvidence to CocoAsToken by running attestation-service in-process.

mod artifact_server;
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
    /// flow for signed release manifests.
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
        /// Fallback measurement types used when the artifact-server primary
        /// cannot resolve a measurement; must be a subset of
        /// `publishedMeasurements`.
        #[serde(rename = "fallbackPublishedMeasurements", default)]
        fallback_published_measurements: Option<Vec<String>>,
        /// Fallback transparency-log services (rekor-v1 only) used when the
        /// artifact-server primary cannot resolve a measurement; only supported
        /// when the primary service is an `artifact-server`.
        #[serde(rename = "fallbackServices", default)]
        fallback_services: Option<Vec<TransparencyServiceConfig>>,
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

impl PolicyConfig {
    /// Validate a `TransparencyLog` config against the artifact-server +
    /// fallback transparency policy constraints. No-op for non-`TransparencyLog`
    /// variants.
    pub fn validate_transparency_config(&self) -> anyhow::Result<()> {
        let PolicyConfig::TransparencyLog {
            published_measurements,
            services,
            fallback_published_measurements,
            fallback_services,
            ..
        } = self
        else {
            return Ok(());
        };

        let pm = published_measurements.as_deref().unwrap_or(&[]);
        if pm.is_empty() {
            anyhow::bail!("publishedMeasurements must be non-empty");
        }
        let mut seen = std::collections::HashSet::new();
        for t in pm {
            if !matches!(
                t.as_str(),
                "tdx.td-shim" | "tdx.kernel" | "container.image.cmaas-runtime"
            ) {
                anyhow::bail!("unsupported publishedMeasurements type {t}");
            }
            if !seen.insert(t) {
                anyhow::bail!("duplicate publishedMeasurements type {t}");
            }
        }

        if services.is_empty() {
            anyhow::bail!("services must be non-empty");
        }
        let mut artifact_server = false;
        for (i, svc) in services.iter().enumerate() {
            match svc {
                TransparencyServiceConfig::ArtifactServer {
                    url,
                    log_services,
                    publisher_public_key_pem: _,
                } => {
                    artifact_server = true;
                    if services.len() != 1 {
                        anyhow::bail!("artifact-server must be the only primary service");
                    }
                    if url.is_empty() {
                        anyhow::bail!("services[{i}] url is required");
                    }
                    if log_services.is_empty() {
                        anyhow::bail!("services[{i}] logServices non-empty");
                    }
                    let mut ls = std::collections::HashSet::new();
                    for (j, s) in log_services.iter().enumerate() {
                        if s.type_ != "rekor-v1" {
                            anyhow::bail!("services[{i}].logServices[{j}] type must be rekor-v1");
                        }
                        if s.url.is_empty() {
                            anyhow::bail!("services[{i}].logServices[{j}] url required");
                        }
                        if !ls.insert((s.type_.clone(), s.url.trim_end_matches('/'))) {
                            anyhow::bail!("services[{i}].logServices[{j}] duplicate");
                        }
                    }
                }
                TransparencyServiceConfig::RekorV1 {
                    log_url, log_index, ..
                } => {
                    if log_url.is_empty() {
                        anyhow::bail!("services[{i}] logUrl required");
                    }
                    if *log_index < 0 {
                        anyhow::bail!("services[{i}] logIndex must be >= 0");
                    }
                }
            }
        }

        match (
            fallback_services.as_ref(),
            fallback_published_measurements.as_ref(),
        ) {
            (None, Some(_)) => {
                anyhow::bail!("fallbackPublishedMeasurements requires fallbackServices");
            }
            (None, None) => return Ok(()),
            (Some(fs), _) => {
                if !artifact_server {
                    anyhow::bail!(
                        "fallbackServices is only supported with an artifact-server primary"
                    );
                }
                if fs.is_empty() {
                    anyhow::bail!("fallbackServices must be non-empty");
                }
                for (i, svc) in fs.iter().enumerate() {
                    match svc {
                        TransparencyServiceConfig::RekorV1 {
                            log_url, log_index, ..
                        } => {
                            if log_url.is_empty() {
                                anyhow::bail!("fallbackServices[{i}] logUrl required");
                            }
                            if *log_index < 0 {
                                anyhow::bail!("fallbackServices[{i}] logIndex >= 0");
                            }
                        }
                        _ => anyhow::bail!("fallbackServices[{i}] must be rekor-v1"),
                    }
                }
                if let Some(fpm) = fallback_published_measurements {
                    if fpm.is_empty() {
                        anyhow::bail!("fallbackPublishedMeasurements non-empty");
                    }
                    let primary: std::collections::HashSet<&String> = pm.iter().collect();
                    for t in fpm {
                        if !primary.contains(t) {
                            anyhow::bail!(
                                "fallbackPublishedMeasurements type {t} not in publishedMeasurements"
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// A transparency-log service whose entry authenticates the reference
/// measurements. `rekor-v1` fetches an entry by logIndex; `artifact-server`
/// delegates to a log-services list.
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
    #[serde(rename = "artifact-server")]
    ArtifactServer {
        #[serde(rename = "url")]
        url: String,
        #[serde(rename = "logServices")]
        log_services: Vec<ArtifactLogService>,
        /// Optional DSSE publisher public key (PEM) overriding the built-in
        /// publisher key baseline: when empty, DSSE verification falls back to
        /// the built-in publisher key. Used for both the primary resolve path
        /// and (when absent) the built-in default.
        #[serde(rename = "publisherPublicKeyPem", default)]
        publisher_public_key_pem: Option<String>,
    },
}

/// A single log-service entry nested under an `artifact-server` transparency
/// service: `{"type":"rekor-v1","url":"..."}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ArtifactLogService {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "url")]
    pub url: String,
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
                        // Inject the `tng.sha256` host-await function so
                        // rego policies that call `tng.sha256(...)` (e.g.
                        // the transparency-log policy's
                        // `tng.sha256(json.marshal(manifest))`) resolve
                        // against a real sha256 implementation. regorus 0.11
                        // ships no crypto builtins by design. Under
                        // `crypto-rustcrypto`, `tng.verify_dsse_signature`
                        // (DSSEPAE + ECDSA P-256) is injected too — see
                        // `builtin_as_host_await_functions`.
                        .with_extra_extension_functions(builtin_as_host_await_functions()),
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
                fallback_published_measurements,
                fallback_services,
            } => {
                // Validate the full config shape BEFORE dispatching on the
                // primary service type. This turns every operator-supplied config
                // violation (empty/missing fields, artifact-server-not-sole-primary,
                // fallback-requires-artifact-server-primary, non-rekor-v1 in
                // fallbackServices, fallbackPublishedMeasurements-not-subset,
                // duplicate logServices, etc.) into a clean `Err` at load time
                // rather than a process panic (e.g. `unreachable!` / `fs[0]` in
                // `build_artifact_server_policy`) downstream.
                policy
                    .validate_transparency_config()
                    .map_err(Error::TransparencyLogFetchFailed)?;
                // Dispatch on the primary service type. `RekorV1` keeps the
                // existing init-bake path verbatim (fetch + bake payloadHash);
                // `ArtifactServer` generates Rego that resolves the
                // manifest at appraisal time via `tng.resolve_artifact_server`
                // (with an optional `tng.fetch_rekor_on_demand` fallback) and
                // bakes NO payloadHash.
                let primary = services.first().ok_or_else(|| {
                    Error::TransparencyLogFetchFailed(anyhow::anyhow!(
                        "transparency_log services must be non-empty"
                    ))
                })?;
                match primary {
                    TransparencyServiceConfig::RekorV1 { .. } => {
                        // EXISTING init-bake path, unchanged (fetch the rekor-v1
                        // entry by logIndex, authenticate it, bake the trusted
                        // payloadHash into Rego). The artifact-server primary path is a
                        // separate arm below; this stays verbatim for rekor-v1.
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
                        let (log_url, log_index, rekor_public_key_pem, publisher_public_key_pem) =
                            svc;
                        tracing::info!(
                            log_url,
                            log_index,
                            "Loading transparency_log policy: fetching Rekor v1 entry"
                        );
                        let auth = rekor_v1::fetch_trusted_payload_hash(
                            log_url,
                            log_index,
                            rekor_public_key_pem,
                        )
                        .await
                        .map_err(Error::TransparencyLogFetchFailed)?;
                        // DSSE publisher-signature verification is mandatory:
                        // resolve the publisher key unconditionally — the
                        // configured `publisherPublicKeyPem`, or the built-in
                        // publisher key baseline when none is set — and always
                        // bake both the DSSE signature and the publisher key so
                        // the generated Rego emits the
                        // `tng.verify_dsse_signature` line. An empty
                        // `dsse_signature` means a malformed/non-dsse entry →
                        // fail closed. This mirrors
                        // `build_artifact_server_policy`'s approach (the
                        // publisher key literal is the configured value or
                        // empty→built-in).
                        let publisher_key = publisher_public_key_pem
                            .filter(|s| !s.is_empty())
                            .unwrap_or(artifact_server::BUILTIN_LOG_ENTRY_PUB_KEY_PEM);
                        let dsse_signature = resolve_dsse_signature(&auth.dsse_signature)
                            .map_err(Error::TransparencyLogFetchFailed)?;
                        let policy = build_transparency_log_policy(
                            &auth.payload_hash,
                            schema_version,
                            published_measurements.as_deref(),
                            dsse_signature,
                            publisher_key,
                        );
                        tracing::info!(payload_hash = %auth.payload_hash, policy = %policy, "Transparency_log policy loaded: baking payloadHash + DSSE into Rego");
                        Ok(Some(URL_SAFE_NO_PAD.encode(policy)))
                    }
                    TransparencyServiceConfig::ArtifactServer {
                        url,
                        log_services,
                        publisher_public_key_pem,
                    } => {
                        tracing::info!(
                            artifact_server_url = %url,
                            "Loading transparency_log policy: generating artifact-server-primary Rego"
                        );
                        let policy = build_artifact_server_policy(
                            schema_version,
                            published_measurements.as_deref(),
                            url,
                            log_services,
                            publisher_public_key_pem.as_deref(),
                            fallback_published_measurements.as_deref(),
                            fallback_services.as_deref(),
                        )?;
                        tracing::info!(policy = %policy, "Transparency_log policy loaded: artifact-server primary, no baked payloadHash");
                        Ok(Some(URL_SAFE_NO_PAD.encode(policy)))
                    }
                }
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
/// A real rekor v1 `dsse` entry always carries a signature in
/// `body.spec.signatures[0].signature`. An empty `dsse_signature` therefore
/// means a malformed/non-dsse entry — fail closed rather than silently emitting
/// a weaker payloadHash-only policy. The publisher key is resolved
/// unconditionally by the caller (configured `publisherPublicKeyPem` or the
/// built-in publisher key), so DSSE verification is always wired.
fn resolve_dsse_signature(dsse_signature: &str) -> anyhow::Result<&str> {
    if dsse_signature.is_empty() {
        anyhow::bail!(
            "rekor entry has no DSSE signature (malformed/non-dsse entry; \
             body.spec.signatures[0].signature is required)"
        );
    }
    Ok(dsse_signature)
}

/// Build the `transparency_log` Rego policy string. Bakes the trusted
/// `payload_hash`, the manifest `schema_version`, the ordered
/// `published_measurements`, and the DSSE publisher signature + trusted
/// publisher public key. At appraisal the Rego reconstructs the manifest from
/// actual TDX measurement values, hashes it via
/// `tng.sha256(json.marshal(...))`, and compares to `payload_hash`. It
/// additionally always calls
/// `tng.verify_dsse_signature([json.marshal(reconstructed_manifest),
/// dsse_signature, publisher_key])`, binding the entry to a trusted publisher
/// (the DSSE check strictly subsumes the payloadHash content-binding and adds
/// publisher-identity binding). DSSE verification is mandatory — there is no
/// payloadHash-only fallback, so the DSSE-verification Rego is always emitted.
// Wired into `load_policy_as_base64_url_safe_no_pad` under the
// `crypto-rustcrypto` feature; with that feature off the loader bails before
// reaching here, so the function stays dead code in non-crypto builds.
#[cfg_attr(not(feature = "crypto-rustcrypto"), allow(dead_code))]
fn build_transparency_log_policy(
    payload_hash: &str,
    schema_version: &str,
    published_measurements: Option<&[String]>,
    dsse_signature: &str,
    publisher_key: &str,
) -> String {
    // The DSSE publisher-signature check is always emitted (DSSE verification is
    // mandatory; no payloadHash-only fallback). The signature + publisher
    // key are public data (a logged rekor entry's signature + the configured
    // publisher key) — baking them as Rego literals leaks no secret. An empty
    // `dsse_signature` means a malformed/non-dsse entry → fail closed (the
    // loader's `resolve_dsse_signature` bails on empty before reaching here).
    let dsse_literals = format!(
        "\n# baked: DSSE publisher signature + trusted publisher public key\n\
         dsse_signature := {dsse_signature:?}\n\
         publisher_key := {publisher_key:?}\n",
    );
    let dsse_verify_line =
        "    tng.verify_dsse_signature([json.marshal(reconstructed_manifest), dsse_signature, publisher_key]) == true\n";

    match published_measurements {
        // No `publishedMeasurements` configured (the JSON field is absent):
        // skip the measurement reconstruction + verification entirely.
        // `executables` stays at its affirming default (2) — only the TDX
        // platform hardware checks gate the appraisal. The trusted
        // payloadHash, schemaVersion, and DSSE publisher signature/key are
        // still baked for reference, but no manifest is reconstructed or
        // compared (so `tng.verify_dsse_signature` is not invoked here —
        // there is no reconstructed manifest to bind the signature to).
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
        // it via `tng.sha256(json.marshal(...))`, and compare to the baked
        // `payload_hash`. An empty array yields an empty manifest whose hash
        // never matches a real payloadHash → `measurements_verified` is
        // false → `executables` stays at its contraindicated default (97).
        Some(published_measurements) => {
            // Sort the measurement types before baking. The publisher's
            // `payloadHash` is computed over the type-sorted manifest (sorted by
            // measurement `Type` before JCS canonicalization + sha256), so the
            // reconstructed Rego manifest must iterate `published_measurements`
            // in the same sorted order for the hash to agree — independent of
            // the operator-supplied config order. `sort()` on `String` is by
            // Unicode code point.
            let mut sorted: Vec<String> = published_measurements.to_vec();
            sorted.sort();
            let published_measurements = sorted.as_slice();
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

# extract the actual measurement value for a type from rego input.
# Each rule gates its digest on a canonical-format regex: td-shim/td-kernel
# require 96 lowercase hex chars; container.image.* require sha256:+64 lowercase
# hex. A value that fails the format check makes the rule undefined → the
# measurement is dropped from the reconstructed manifest → its hash mismatches
# payload_hash → measurements_verified fails → reject (fail-closed).
actual_measurement("tdx.td-shim") := digest if {{
    digest := input.tdx.quote.body.mr_td
    regex.match("^[0-9a-f]{{96}}$", digest)
}}

actual_measurement("tdx.kernel") := digest if {{
    some e in input.tdx.uefi_event_logs
    e.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"
    # Exact descriptor match against "td_payload". The UEFI event-log parser
    # exposes the description WITHOUT the trailing NUL (`data[1..length]`,
    # length includes the NUL byte), so the parsed `e.details.string` is
    # `"td_payload"` (10 chars). A `startswith` prefix would wrongly match
    # unrelated `td_payload_*` descriptors.
    e.details.string == "td_payload"
    e.index == 2
    some d in e.digests
    d.alg == "SHA-384"
    digest := d.digest
    regex.match("^[0-9a-f]{{96}}$", digest)
    # Guard (#2): fail-closed if ANY descriptor-matching td_payload event has
    # register index != 2. A td_payload descriptor-matching event must extend
    # RTMR1 (register index 2); any such event with a non-2 index is a
    # violation. Without this guard the `e2.index == 2` filter inside the
    # comprehensions below would silently exclude such an event from the
    # conflict set rather than rejecting. The set is empty iff no
    # descriptor-matching event has a non-2 index → count == 0 lets the rule
    # proceed; any bad event → count 1 → rule undefined → drop → reject
    # (fail-closed).
    bad_index_events := {{1 | some eb in input.tdx.uefi_event_logs; eb.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; eb.details.string == "td_payload"; eb.index != 2}}
    count(bad_index_events) == 0
    # Guard (#3): fail-closed if ANY descriptor-matching td_payload event
    # (extending RTMR1) lacks a SHA-384 digest. A td_payload event must carry a
    # 48-byte SHA-384 digest; an event with no digests (or no SHA-384 digest)
    # is a violation. Without this guard the
    # `some d2 ... d2.alg == "SHA-384"` filter inside the comprehensions below
    # would silently exclude such an event from the conflict set rather than
    # rejecting. The 96-hex regex on the extracted value (#7) already enforces
    # the 48-byte length on matching events; this guard rejects events that
    # have NO SHA-384 digest at all. Compare the distinct set of
    # descriptor-matching index-2 events (by `event` body) against the subset
    # that carries a SHA-384 digest — equal counts iff every such event has a
    # SHA-384 digest.
    td_index2_events := {{ev | some e2 in input.tdx.uefi_event_logs; e2.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; e2.details.string == "td_payload"; e2.index == 2; ev := e2.event}}
    td_index2_with_sha384 := {{ev | some e2 in input.tdx.uefi_event_logs; e2.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; e2.details.string == "td_payload"; e2.index == 2; some d2 in e2.digests; d2.alg == "SHA-384"; ev := e2.event}}
    count(td_index2_events) == count(td_index2_with_sha384)
    # Conflicting-events check across ALL td_payload descriptor+RTMR1 events.
    # A digest OR blobLength disagreement is a conflict ("conflicting
    # td_payload events") — both the digest and the blobLength must agree
    # across every matching event. Build distinct digest and blobLength sets
    # WITHOUT the 32 MiB pre-filter so a non-32 MiB td_payload event is counted
    # as a conflict rather than silently excluded. The distinct-digest set must
    # have exactly one element (all digests agree); the distinct-length set must
    # equal exactly {{33554432}} (all lengths agree AND the agreed length is
    # 32 MiB = 32<<20). A 32 MiB + non-32 MiB td_payload pair → length set
    # {{33554432, other}} → set != {{33554432}} → rule undefined → drop →
    # reject (fail-closed).
    matching_digests := {{dg | some e2 in input.tdx.uefi_event_logs; e2.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; e2.details.string == "td_payload"; e2.index == 2; some d2 in e2.digests; d2.alg == "SHA-384"; dg := d2.digest}}
    count(matching_digests) == 1
    matching_lengths := {{tng.td_payload_blob_length([e2.event]) | some e2 in input.tdx.uefi_event_logs; e2.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; e2.details.string == "td_payload"; e2.index == 2; some d2 in e2.digests; d2.alg == "SHA-384"}}
    matching_lengths == {{33554432}}
}}

actual_measurement(type) := digest if {{
    startswith(type, "container.image.")
    repo := replace(type, "container.image.", "")
    some e in input.tdx.uefi_event_logs
    e.details.unicode_name == "AAEL"
    e.details.data.domain == "alibabacloud.com"
    e.details.data.operation == "kangaroo/pull-image"
    image_repo_name(e.details.data.content.reference) == repo
    digest := e.details.data.content.digest
    regex.match("^sha256:[0-9a-f]{{64}}$", digest)
    # Explicit conflicting-events check: all AAEL kangaroo/pull-image events
    # for this repo must agree on the digest. A conflict makes the
    # distinct-digest set size > 1 → rule undefined → measurement dropped →
    # manifest mismatch → reject (fail-closed).
    matching_digests := {{dg | some e2 in input.tdx.uefi_event_logs; e2.details.unicode_name == "AAEL"; e2.details.data.domain == "alibabacloud.com"; e2.details.data.operation == "kangaroo/pull-image"; image_repo_name(e2.details.data.content.reference) == repo; dg := e2.details.data.content.digest}}
    count(matching_digests) == 1
    # NOTE: AAEL event-digest integrity (sha384(event) == digests[0]) is NOT
    # re-verified here. It is verified by the attestation-service event-log
    # replay (trustee CcEventLog
    # replay_and_match, which replays events against RTMRs) before claims reach
    # the policy — TNG's Rego layer trusts that replay. This is by-design
    # delegated to the AS event-log replay, not silently skipped.
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

# tng.sha256 returns lowercase hex (== payloadHash format). When a publisher
# key is baked, tng.verify_dsse_signature additionally binds the entry to the
# trusted publisher (fails closed → false → executables 97 → reject).
measurements_verified if {{
    tng.sha256(json.marshal(reconstructed_manifest)) == payload_hash
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

/// Build the Rego policy for a transparency_log config whose primary
/// service is an `artifact-server`. Unlike the init-bake `build_transparency_log_policy`
/// (which fetches a rekor-v1 entry at init and bakes the trusted `payloadHash`),
/// It bakes NO payloadHash: at appraisal the Rego reconstructs the manifest
/// from the actual TDX measurement values (`actual_measurement`), then calls
/// `tng.resolve_artifact_server(url, json.marshal(full_manifest), json.marshal(log_services))`
/// as the primary verification path. When a fallback is configured, it also
/// defines `fallback_manifest` + `fallback_ok`; the `fallback_ok` rule body is
/// `not primary_ok; tng.fetch_rekor_on_demand(...)`, so regorus's left-to-right
/// body short-circuit must skip the fallback network call when `primary_ok` is
/// true (verified by `branch_b_does_not_call_fallback_when_primary_ok`).
///
/// The header + `actual_measurement`/`image_repo_name` reconstruction + the
/// hardware scoring block are copied verbatim from the existing rekor-v1
/// template (same appraisal semantics).
///
/// Carry #1: `measurements_verified if { fallback_ok }` is emitted ONLY when
/// fallback is configured (otherwise the undefined `fallback_ok` rule would be
/// a Rego parse/eval error); with no fallback `measurements_verified` depends
/// solely on `primary_ok`.
#[cfg(feature = "crypto-rustcrypto")]
fn build_artifact_server_policy(
    schema_version: &str,
    published_measurements: Option<&[String]>,
    artifact_url: &str,
    log_services: &[ArtifactLogService],
    publisher_public_key_pem: Option<&str>,
    fallback_published_measurements: Option<&[String]>,
    fallback_services: Option<&[TransparencyServiceConfig]>,
) -> Result<String> {
    // Sort the measurement types before baking. The publisher's `payloadHash`
    // is computed over the type-sorted manifest (sorted by measurement `Type`
    // before JCS canonicalization + sha256), so the Rego reconstruction must
    // iterate in the same sorted order — independent of the operator-supplied
    // config order.
    let mut pm: Vec<String> = published_measurements.unwrap_or_default().to_vec();
    pm.sort();
    let pm_lit = format!(
        "[{}]",
        pm.iter()
            .map(|t| format!("{t:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let ls_lit = serde_json::to_string(log_services).map_err(Error::SerializeJsonFailed)?;
    let url_lit = serde_json::to_string(artifact_url).map_err(Error::SerializeJsonFailed)?;
    // Bake the publisher key literal: the configured `publisherPublicKeyPem`,
    // or empty string when none is set. The host-await treats an empty 4th arg
    // as "use built-in publisher key", so baking "" preserves the default path.
    // Passing it explicitly as a 4th arg makes DSSE verification mandatory.
    let publisher_key_lit = serde_json::to_string(
        publisher_public_key_pem
            .filter(|s| !s.is_empty())
            .unwrap_or(""),
    )
    .map_err(Error::SerializeJsonFailed)?;

    // Fallback block: only when fallback is configured.
    let (fallback_lit, fallback_rules) = match (fallback_published_measurements, fallback_services)
    {
        (Some(fpm), Some(fs)) => {
            let first = match fs.first() {
                Some(TransparencyServiceConfig::RekorV1 {
                    log_url, log_index, ..
                }) => (log_url.clone(), *log_index),
                Some(_) => {
                    return Err(Error::TransparencyLogFetchFailed(anyhow::anyhow!(
                        "fallbackServices must contain only rekor-v1 services"
                    )))
                }
                None => {
                    return Err(Error::TransparencyLogFetchFailed(anyhow::anyhow!(
                        "fallbackServices is empty"
                    )))
                }
            };
            let mut fpm_sorted: Vec<String> = fpm.to_vec();
            // Same type-sort as the primary `published_measurements` so the
            // fallback manifest reconstruction matches the publisher's
            // type-sorted canonical form.
            fpm_sorted.sort();
            let fpm_lit = format!(
                "[{}]",
                fpm_sorted
                    .iter()
                    .map(|t| format!("{t:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            (
                format!(
                    "\nfallback_published_measurements := {fpm_lit}\nfallback_log_url := {:?}\nfallback_log_index := {}\n",
                    first.0, first.1
                ),
                // `not primary_ok` short-circuits the body before the
                // `tng.fetch_rekor_on_demand` call when primary_ok is true.
                // The 4th arg threads the publisher key (empty → built-in) so
                // the on-demand fallback also runs mandatory DSSE verification.
                r#"
fallback_manifest := {"measurements": [{"type": t, "value": actual_measurement(t)} | some t in fallback_published_measurements], "schemaVersion": schema_version}
fallback_ok if {
    not primary_ok
    tng.fetch_rekor_on_demand([fallback_log_url, fallback_log_index, json.marshal(fallback_manifest), publisher_key]) == true
}
"#,
            )
        }
        _ => (String::new(), ""),
    };

    // Carry #1: emit the `measurements_verified if { fallback_ok }` line ONLY
    // when fallback is configured. With no fallback, `fallback_ok` is undefined
    // and referencing it would be a Rego error; `measurements_verified` then
    // depends solely on `primary_ok`.
    let measurements_verified_lines = if fallback_rules.is_empty() {
        "measurements_verified if { primary_ok }\n".to_string()
    } else {
        "measurements_verified if { primary_ok }\nmeasurements_verified if { fallback_ok }\n"
            .to_string()
    };

    let rego = format!(
        r#"package policy
import rego.v1

default executables := 97
default configuration := 2
default file_system := 2
default hardware := 127

schema_version := {schema_version:?}
published_measurements := {pm_lit}
artifact_server_url := {url_lit}
log_services := {ls_lit}
# baked: configured publisher key PEM (empty string → host-await uses the
# built-in publisher key baseline). Threaded into both the primary
# (tng.resolve_artifact_server) and fallback (tng.fetch_rekor_on_demand)
# host-awaits as the 4th arg so DSSE publisher-signature verification always
# runs.
publisher_key := {publisher_key_lit}{fallback_lit}

# Each rule gates its digest on a canonical-format regex: td-shim/td-kernel
# require 96 lowercase hex chars; container.image.* require sha256:+64 lowercase
# hex. A value that fails the format check makes the rule undefined → the
# measurement is dropped from the reconstructed manifest → its hash mismatches
# payload_hash → measurements_verified fails → reject (fail-closed).
actual_measurement("tdx.td-shim") := digest if {{
    digest := input.tdx.quote.body.mr_td
    regex.match("^[0-9a-f]{{96}}$", digest)
}}

actual_measurement("tdx.kernel") := digest if {{
    some e in input.tdx.uefi_event_logs
    e.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"
    # Exact descriptor match against "td_payload". The UEFI event-log parser
    # exposes the description WITHOUT the trailing NUL (`data[1..length]`,
    # length includes the NUL byte), so the parsed `e.details.string` is
    # `"td_payload"` (10 chars). A `startswith` prefix would wrongly match
    # unrelated `td_payload_*` descriptors.
    e.details.string == "td_payload"
    e.index == 2
    some d in e.digests
    d.alg == "SHA-384"
    digest := d.digest
    regex.match("^[0-9a-f]{{96}}$", digest)
    # Guard (#2): fail-closed if ANY descriptor-matching td_payload event has
    # register index != 2. A td_payload descriptor-matching event must extend
    # RTMR1 (register index 2); any such event with a non-2 index is a
    # violation. Without this guard the `e2.index == 2` filter inside the
    # comprehensions below would silently exclude such an event from the
    # conflict set rather than rejecting. The set is empty iff no
    # descriptor-matching event has a non-2 index → count == 0 lets the rule
    # proceed; any bad event → count 1 → rule undefined → drop → reject
    # (fail-closed).
    bad_index_events := {{1 | some eb in input.tdx.uefi_event_logs; eb.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; eb.details.string == "td_payload"; eb.index != 2}}
    count(bad_index_events) == 0
    # Guard (#3): fail-closed if ANY descriptor-matching td_payload event
    # (extending RTMR1) lacks a SHA-384 digest. A td_payload event must carry a
    # 48-byte SHA-384 digest; an event with no digests (or no SHA-384 digest)
    # is a violation. Without this guard the
    # `some d2 ... d2.alg == "SHA-384"` filter inside the comprehensions below
    # would silently exclude such an event from the conflict set rather than
    # rejecting. The 96-hex regex on the extracted value (#7) already enforces
    # the 48-byte length on matching events; this guard rejects events that
    # have NO SHA-384 digest at all. Compare the distinct set of
    # descriptor-matching index-2 events (by `event` body) against the subset
    # that carries a SHA-384 digest — equal counts iff every such event has a
    # SHA-384 digest.
    td_index2_events := {{ev | some e2 in input.tdx.uefi_event_logs; e2.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; e2.details.string == "td_payload"; e2.index == 2; ev := e2.event}}
    td_index2_with_sha384 := {{ev | some e2 in input.tdx.uefi_event_logs; e2.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; e2.details.string == "td_payload"; e2.index == 2; some d2 in e2.digests; d2.alg == "SHA-384"; ev := e2.event}}
    count(td_index2_events) == count(td_index2_with_sha384)
    # Conflicting-events check across ALL td_payload descriptor+RTMR1 events.
    # A digest OR blobLength disagreement is a conflict ("conflicting
    # td_payload events") — both the digest and the blobLength must agree
    # across every matching event. Build distinct digest and blobLength sets
    # WITHOUT the 32 MiB pre-filter so a non-32 MiB td_payload event is counted
    # as a conflict rather than silently excluded. The distinct-digest set must
    # have exactly one element (all digests agree); the distinct-length set must
    # equal exactly {{33554432}} (all lengths agree AND the agreed length is
    # 32 MiB = 32<<20). A 32 MiB + non-32 MiB td_payload pair → length set
    # {{33554432, other}} → set != {{33554432}} → rule undefined → drop →
    # reject (fail-closed).
    matching_digests := {{dg | some e2 in input.tdx.uefi_event_logs; e2.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; e2.details.string == "td_payload"; e2.index == 2; some d2 in e2.digests; d2.alg == "SHA-384"; dg := d2.digest}}
    count(matching_digests) == 1
    matching_lengths := {{tng.td_payload_blob_length([e2.event]) | some e2 in input.tdx.uefi_event_logs; e2.type_name == "EV_EFI_PLATFORM_FIRMWARE_BLOB2"; e2.details.string == "td_payload"; e2.index == 2; some d2 in e2.digests; d2.alg == "SHA-384"}}
    matching_lengths == {{33554432}}
}}

actual_measurement(type) := digest if {{
    startswith(type, "container.image.")
    repo := replace(type, "container.image.", "")
    some e in input.tdx.uefi_event_logs
    e.details.unicode_name == "AAEL"
    e.details.data.domain == "alibabacloud.com"
    e.details.data.operation == "kangaroo/pull-image"
    image_repo_name(e.details.data.content.reference) == repo
    digest := e.details.data.content.digest
    regex.match("^sha256:[0-9a-f]{{64}}$", digest)
    # Explicit conflicting-events check: all AAEL kangaroo/pull-image events
    # for this repo must agree on the digest. A conflict makes the
    # distinct-digest set size > 1 → rule undefined → measurement dropped →
    # manifest mismatch → reject (fail-closed).
    matching_digests := {{dg | some e2 in input.tdx.uefi_event_logs; e2.details.unicode_name == "AAEL"; e2.details.data.domain == "alibabacloud.com"; e2.details.data.operation == "kangaroo/pull-image"; image_repo_name(e2.details.data.content.reference) == repo; dg := e2.details.data.content.digest}}
    count(matching_digests) == 1
    # NOTE: AAEL event-digest integrity (sha384(event) == digests[0]) is NOT
    # re-verified here. It is verified by the attestation-service event-log
    # replay (trustee CcEventLog
    # replay_and_match, which replays events against RTMRs) before claims reach
    # the policy — TNG's Rego layer trusts that replay. This is by-design
    # delegated to the AS event-log replay, not silently skipped.
}}

image_repo_name(ref) := name if {{
    segs := split(ref, "/")
    last := segs[count(segs) - 1]
    name := split(split(last, "@")[0], ":")[0]
}}

full_manifest := {{
    "measurements": [{{"type": t, "value": actual_measurement(t)}} | some t in published_measurements],
    "schemaVersion": schema_version,
}}

primary_ok if {{
    tng.resolve_artifact_server([artifact_server_url, json.marshal(full_manifest), json.marshal(log_services), publisher_key]) == true
}}{fallback_rules}

{measurements_verified_lines}
executables := 2 if {{ measurements_verified }}

hardware := 2 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
    tdx_debug_disabled
    tdx_eventlog_present
}}
hardware := 126 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id != "939a7233f79c4ca9940a0db3957f0607"
}}
hardware := 125 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
    not tdx_debug_disabled
}}
hardware := 33 if {{
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
    tdx_debug_disabled
    not tdx_eventlog_present
}}
tdx_debug_disabled if {{ regex.match("^[0-9a-f][02468ace]", input.tdx.quote.body.td_attributes) }}
tdx_eventlog_present if {{ count(input.tdx.uefi_event_logs) > 0 }}
"#,
        schema_version = schema_version,
        pm_lit = pm_lit,
        url_lit = url_lit,
        ls_lit = ls_lit,
        publisher_key_lit = publisher_key_lit,
        fallback_lit = fallback_lit,
        fallback_rules = fallback_rules,
        // `measurements_verified_lines` is interpolated on its own template line
        // where the literal already supplies the trailing newline (the line break
        // before `executables := 2 if {{ ... }}`), so its own trailing `\n` is
        // trimmed to avoid a double blank line. `fallback_rules`/`fallback_lit`
        // are interpolated mid-line (`}}{fallback_rules}`, `{ls_lit}{fallback_lit}`)
        // where the template provides no separating newline, so they KEEP their
        // trailing `\n` to terminate their last rule on its own line.
        measurements_verified_lines = measurements_verified_lines.trim_end(),
    );
    Ok(rego)
}

/// Host-await function that injects the `tng.sha256` builtin regorus 0.11
/// omits by design. It sha256-hashes its single string argument and resumes
/// the VM with the lowercase-hex digest as a `regorus::Value::String`,
/// matching the format Rekor's `payloadHash` is published in (so the rego
/// `tng.sha256(json.marshal(manifest)) == payload_hash` comparison works).
///
/// Registered under the dotted name `tng.sha256` (regorus's function-rule
/// syntax accepts dotted keys) via `OPAInMemory::with_extra_extension_functions`
/// so the existing, already-written rego policy is unchanged and stays
/// forward-compatible with a future regorus that ships the builtin natively.
/// Only the sha256 primitive is injected; manifest reconstruction
/// (`json.marshal`) and the comparison stay in rego.
///
/// The `ExtensionFunction` type alias already cfg-gates the `Send` bound
/// (dropped on `wasm32-unknown-unknown`, where the RVPS resolver is `?Send`),
/// so this closure's `Box::pin(async move { ... })` future matches both the
/// native and wasm variants without an explicit cfg here. Mirrors the trustee
/// fork's `evaluate_with_injected_crypto_sha256_dotted_host_await` test.
fn crypto_sha256_host_await() -> attestation_service::policy_engine::opa::ExtensionFunction {
    use attestation_service::policy_engine::PolicyError;

    std::sync::Arc::new(|argument: regorus::Value| {
        Box::pin(async move {
            let s = argument.as_string().map_err(|e| {
                PolicyError::EvalPolicyFailed(anyhow::anyhow!("tng.sha256 arg not a string: {e}"))
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

/// `tng.td_payload_blob_length([event_b64]) -> number`. Parses the
/// UEFI_PLATFORM_FIRMWARE_BLOB2 layout from a base64-encoded TD-payload event
/// and returns the declared `BlobLength` (LE u64): byte 0 = descriptionSize,
/// bytes [1..1+desc_size] = description, then 8-byte BlobBase, then 8-byte LE
/// BlobLength at offset `1 + desc_size + 8`. The TD-payload kernel measurement
/// rule collects the blobLength of every td_payload descriptor+RTMR1 event
/// into a set and requires that set to equal exactly `{33554432}` (32 MiB =
/// 32<<20) — so a 32 MiB + non-32 MiB td_payload pair is a conflict (set
/// mismatch) → reject.
///
/// Fail-closed: any decode/parse/length error returns `Ok(Number(-1))` so the
/// length set never equals `{33554432}` → the tdx.kernel measurement rule is
/// undefined → the measurement is dropped → manifest mismatch → reject. An
/// `Err` would abort the whole policy evaluation (verified via the in-tree
/// `evaluate_with_regovm_propagates_async_builtin_error` test), breaking the
/// fail-closed contract, so errors map to a sentinel that never equals the
/// required 32 MiB.
fn td_payload_blob_length_host_await() -> attestation_service::policy_engine::opa::ExtensionFunction
{
    use base64::Engine;
    use regorus::Value;

    std::sync::Arc::new(|argument: regorus::Value| {
        Box::pin(async move {
            // Fail-closed sentinel: -1 never equals 33554432 (32 MiB).
            let bail = || Value::Number((-1.0f64).into());
            let arr = match argument.as_array() {
                Ok(a) if a.len() == 1 => a,
                _ => return Ok(bail()),
            };
            let event_b64: &str = match arr[0].as_string() {
                Ok(s) => s,
                Err(_) => return Ok(bail()),
            };
            let event = match base64::engine::general_purpose::STANDARD.decode(event_b64) {
                Ok(b) => b,
                Err(_) => return Ok(bail()),
            };
            if event.is_empty() {
                return Ok(bail());
            }
            let desc_size = event[0] as usize;
            // Layout requires len == 1 + desc_size + 16 (BlobBase + BlobLength).
            let expected_len = 1usize
                .checked_add(desc_size)
                .and_then(|n| n.checked_add(16));
            let blob_length_offset = 1usize.checked_add(desc_size).and_then(|n| n.checked_add(8));
            let (blob_length_offset, expected_len) = match (blob_length_offset, expected_len) {
                (Some(o), Some(l)) => (o, l),
                _ => return Ok(bail()),
            };
            if event.len() != expected_len {
                return Ok(bail());
            }
            let blob_length_bytes = &event[blob_length_offset..blob_length_offset + 8];
            let mut buf = [0u8; 8];
            buf.copy_from_slice(blob_length_bytes);
            let blob_length = u64::from_le_bytes(buf);
            Ok(Value::Number((blob_length as f64).into()))
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
/// `OPAInMemory::with_extra_extension_functions`, alongside `tng.sha256`.
///
/// Takes a packed 3-element array `[payload_str, signature_b64, publisher_key_pem]`
/// (single-arg, since the host-await wrapper is single-arg). Computes
/// `dsse_pae(DSSE_PAYLOAD_TYPE, payload)` then verifies the base64-decoded DER
/// ECDSA signature with the P-256 publisher key — `p256::VerifyingKey::verify`
/// hashes the PAE with SHA-256 internally, equivalent to an ECDSA P-256
/// `VerifyASN1(sha256(pae), sig)`.
///
/// Fail-closed: any failure (mismatch, bad sig format, bad key) returns
/// `Ok(Bool(false))` so the rego `tng.verify_dsse_signature(...) == true` check
/// cleanly sees `false` rather than aborting evaluation.
///
/// Only the ECDSA+PAE primitive is in Rust; manifest reconstruction
/// (`json.marshal`) and the comparison stay in rego. Gated on
/// `crypto-rustcrypto` (needs p256 + x509-cert, the same crates rekor_v1's key
/// module pulls in); the rego policy that calls this is itself only generated
/// under `crypto-rustcrypto`.
#[cfg(feature = "crypto-rustcrypto")]
fn verify_dsse_signature_host_await() -> attestation_service::policy_engine::opa::ExtensionFunction
{
    use attestation_service::policy_engine::PolicyError;
    use p256::ecdsa::signature::Verifier;

    std::sync::Arc::new(|argument: regorus::Value| {
        Box::pin(async move {
            // argument = [payload_str, signature_b64, publisher_key_pem]
            let arr = argument.as_array().map_err(|e| {
                PolicyError::EvalPolicyFailed(anyhow::anyhow!(
                    "tng.verify_dsse_signature arg not array: {e}"
                ))
            })?;
            let payload = arr
                .first()
                .and_then(|v| v.as_string().ok())
                .ok_or_else(|| {
                    PolicyError::EvalPolicyFailed(anyhow::anyhow!(
                        "tng.verify_dsse_signature: missing payload"
                    ))
                })?;
            let sig_b64 = arr.get(1).and_then(|v| v.as_string().ok()).ok_or_else(|| {
                PolicyError::EvalPolicyFailed(anyhow::anyhow!(
                    "tng.verify_dsse_signature: missing signature"
                ))
            })?;
            let key_pem = arr.get(2).and_then(|v| v.as_string().ok()).ok_or_else(|| {
                PolicyError::EvalPolicyFailed(anyhow::anyhow!(
                    "tng.verify_dsse_signature: missing publisher key"
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
/// always `tng.sha256`, plus `tng.verify_dsse_signature` (DSSEPAE + sha256 +
/// ECDSA P-256) under `crypto-rustcrypto` — it needs p256/x509-cert, and the
/// transparency-log rego that calls it is itself only generated under that
/// feature. Both `OPAInMemory` construction sites (the prod converter and the
/// `eval_policy_vector` test helper) share this so the injected set stays in
/// sync.
fn builtin_as_host_await_functions() -> Vec<(
    String,
    attestation_service::policy_engine::opa::ExtensionFunction,
)> {
    let mut fns = vec![
        ("tng.sha256".to_string(), crypto_sha256_host_await()),
        // TD-payload firmware-blob2 BlobLength parser (no crypto deps; the rego
        // that calls it is only generated under crypto-rustcrypto, but the
        // primitive itself is pure parsing). Always registered so the
        // eval_policy_vector test helper resolves it.
        (
            "tng.td_payload_blob_length".to_string(),
            td_payload_blob_length_host_await(),
        ),
    ];
    #[cfg(feature = "crypto-rustcrypto")]
    fns.push((
        "tng.verify_dsse_signature".to_string(),
        verify_dsse_signature_host_await(),
    ));
    // On-demand rekor fallback (transparency_log artifact-server path).
    // Fetch+authenticate a Rekor v1 entry by logIndex at appraisal time and
    // compare its trusted payloadHash to sha256(canonical manifest). Caches
    // successes only; failures re-try. Same feature gate as
    // `verify_dsse_signature`; it needs the `rekor_v1` crypto path.
    #[cfg(feature = "crypto-rustcrypto")]
    fns.push((
        "tng.fetch_rekor_on_demand".to_string(),
        artifact_server::fetch_rekor_on_demand_host_await(),
    ));
    // Primary artifact-server path: resolve the manifest via the Artifact
    // Server `POST /api/v1/transparency/resolve`, authenticate each returned
    // rekor-v1 entry locally, and verify payloadHash == sha256(canonical
    // manifest). On any failure returns `false` (not cached) so Rego falls
    // back to `tng.fetch_rekor_on_demand`. Same feature gate; it needs the
    // `rekor_v1` crypto path.
    #[cfg(feature = "crypto-rustcrypto")]
    fns.push((
        "tng.resolve_artifact_server".to_string(),
        artifact_server::resolve_artifact_server_host_await(),
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
        // Inject `tng.sha256` so the transparency-log rego policy's
        // `tng.sha256(json.marshal(manifest))` call resolves to a real
        // sha256 during the behavior test below. Under `crypto-rustcrypto`,
        // `tng.verify_dsse_signature` is injected too; see
        // `builtin_as_host_await_functions`.
        .with_extra_extension_functions(builtin_as_host_await_functions());
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
                ..
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
                    TransparencyServiceConfig::ArtifactServer { .. } => {
                        panic!("expected RekorV1 service, got ArtifactServer")
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
                TransparencyServiceConfig::ArtifactServer { .. } => {
                    panic!("expected RekorV1 service, got ArtifactServer")
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
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_affirms_when_published_measurements_absent() {
        let payload_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let (dsse_sig, publisher_key) = fixture_dsse();
        let policy =
            build_transparency_log_policy(payload_hash, "1.0.0", None, &dsse_sig, &publisher_key);

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
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_skips_measurements_when_absent() {
        let payload_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let (dsse_sig, publisher_key) = fixture_dsse();
        let policy =
            build_transparency_log_policy(payload_hash, "1.0.0", None, &dsse_sig, &publisher_key);

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

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_affirms_on_matching_measurements() {
        // Real fixture manifest: {schemaVersion:1.0.0, measurements:[{type:
        // container.image.cmaas-runtime, value: sha256:d42f6e1b...}]}. Its
        // sha256(json.marshal) == the real rekor payloadHash.
        let payload_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let (dsse_sig, publisher_key) = fixture_dsse();
        let policy = build_transparency_log_policy(
            payload_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            &dsse_sig,
            &publisher_key,
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

    /// Build a single AAEL `kangaroo/pull-image` event for `cmaas-runtime`
    /// carrying the given digest, as a `serde_json::Value`. Used by the
    /// conflicting-events test to assemble multi-event inputs without fighting
    /// `format!` brace-escaping.
    fn aael_event(digest: &str) -> serde_json::Value {
        serde_json::json!({
            "type_name": "EV_EVENT_TAG",
            "details": {
                "unicode_name": "AAEL",
                "data": {
                    "domain": "alibabacloud.com",
                    "operation": "kangaroo/pull-image",
                    "content": {
                        "reference": "registry.example.com/ns/cmaas-runtime:latest",
                        "digest": digest,
                    }
                }
            }
        })
    }

    /// Tampering `publishedMeasurements` (a wrong measurement type name) must
    /// reject: the rego `actual_measurement("container.image.cmaas-WRONG")` rule
    /// finds no matching AAEL event (the input's repo is `cmaas-runtime`) →
    /// `actual_measurement` is undefined → the measurement is dropped from the
    /// reconstructed manifest → its hash ≠ `payload_hash` → `measurements_verified`
    /// false → hardware stays non-affirming (97). The correct type name affirms,
    /// so this is not a tautology.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_rejects_wrong_measurement_type() {
        let payload_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let ok = matching_cmaas_input(digest);
        let (dsse_sig, publisher_key) = fixture_dsse();

        // Correct measurement type name → affirm (not a tautology).
        let correct_policy = build_transparency_log_policy(
            payload_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            &dsse_sig,
            &publisher_key,
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
            &dsse_sig,
            &publisher_key,
        );
        assert_eq!(
            eval_policy_vector(&wrong_policy, &ok).await,
            (97, 2, 2, 2),
            "wrong measurement type name must reject"
        );
    }

    /// Tampering `schemaVersion` must reject: the reconstructed manifest carries
    /// the baked `schema_version`, so a wrong value (e.g. "9.9.9") changes the
    /// `json.marshal` output → `tng.sha256(manifest) != payload_hash` → reject.
    /// The correct "1.0.0" affirms, so this is not a tautology.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_rejects_wrong_schema_version() {
        let payload_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let ok = matching_cmaas_input(digest);
        let (dsse_sig, publisher_key) = fixture_dsse();

        // Correct schema version "1.0.0" → affirm.
        let correct_policy = build_transparency_log_policy(
            payload_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            &dsse_sig,
            &publisher_key,
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
            &dsse_sig,
            &publisher_key,
        );
        assert_eq!(
            eval_policy_vector(&wrong_policy, &ok).await,
            (97, 2, 2, 2),
            "wrong schema version must reject"
        );
    }

    /// Tampering the baked `payload_hash` must reject: the rego recomputes
    /// `tng.sha256(json.marshal(manifest))` from the actual evidence and
    /// compares to the baked value, so a wrong baked hash never matches → reject.
    /// The real payload hash affirms, so this is not a tautology.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_rejects_wrong_payload_hash() {
        let real_digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let ok = matching_cmaas_input(real_digest);
        let (dsse_sig, publisher_key) = fixture_dsse();

        // Correct payload hash → affirm.
        let correct_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let correct_policy = build_transparency_log_policy(
            correct_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            &dsse_sig,
            &publisher_key,
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
            &dsse_sig,
            &publisher_key,
        );
        assert_eq!(
            eval_policy_vector(&wrong_policy, &ok).await,
            (97, 2, 2, 2),
            "wrong payload hash must reject"
        );
    }

    /// `publishedMeasurements` config ORDER must not matter: the policy
    /// generator sorts measurement types before baking the Rego literal (sorted
    /// by measurement `Type` before canonicalization + sha256). The publisher's
    /// `payloadHash` is computed over the type-sorted manifest, so the Rego
    /// reconstruction must iterate in the same sorted order regardless of the
    /// operator-supplied config order. Both a sorted and a reversed config order
    /// produce the same sorted Rego literal and affirm against a payload_hash
    /// computed from the sorted manifest. A deliberately wrong payload_hash
    /// still rejects, so the affirm is not tautological.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_sorts_published_measurements_by_type() {
        let cmaas_digest =
            "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let mr_td = "321ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";

        // The type-sorted manifest (the publisher's canonical form): the
        // runtime measurement type sorts before td-shim (c < t). Compute its
        // payloadHash the same way the rego will at appraisal (JCS
        // sorted-compact, then sha256).
        let sorted = serde_json::json!({
            "measurements": [
                {"type": "container.image.cmaas-runtime", "value": cmaas_digest},
                {"type": "tdx.td-shim", "value": mr_td},
            ],
            "schemaVersion": "1.0.0",
        });
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, jcs_compact(&sorted).as_bytes());
        let payload_hash = hex::encode(sha2::Digest::finalize(hasher));
        let (dsse_sig, publisher_key) = sign_dsse_for_manifest(&sorted);

        // Input carries BOTH the AAEL runtime event (→ cmaas_digest) AND `mr_td`
        // in the quote body (→ td-shim value), so both measurement types resolve.
        let ok = format!(
            r#"{{"tdx":{{"quote":{{"header":{{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}},"body":{{"mr_td":{mr_td:?},"td_attributes":"0000001000000000"}}}},"uefi_event_logs":[{{"type_name":"EV_EVENT_TAG","details":{{"unicode_name":"AAEL","data":{{"domain":"alibabacloud.com","operation":"kangaroo/pull-image","content":{{"reference":"registry.example.com/ns/cmaas-runtime:latest","digest":{cmaas_digest:?}}}}}}}}}]}}}}"#
        );

        // Already-sorted config order [runtime, td-shim] → affirm.
        let sorted_policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&[
                "container.image.cmaas-runtime".to_string(),
                "tdx.td-shim".to_string(),
            ]),
            &dsse_sig,
            &publisher_key,
        );
        assert_eq!(
            eval_policy_vector(&sorted_policy, &ok).await,
            (2, 2, 2, 2),
            "sorted measurement order must affirm"
        );

        // Reversed config order [td-shim, runtime] → policy generator sorts before
        // baking → same sorted Rego literal → affirm.
        let reversed_policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&[
                "tdx.td-shim".to_string(),
                "container.image.cmaas-runtime".to_string(),
            ]),
            &dsse_sig,
            &publisher_key,
        );
        assert_eq!(
            eval_policy_vector(&reversed_policy, &ok).await,
            (2, 2, 2, 2),
            "reversed measurement order must still affirm (sorted before hashing)"
        );

        // Deliberately wrong payload_hash → recomputed manifest hash never
        // matches → reject (proves the affirm above is not tautological).
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let wrong_policy = build_transparency_log_policy(
            wrong_hash,
            "1.0.0",
            Some(&[
                "container.image.cmaas-runtime".to_string(),
                "tdx.td-shim".to_string(),
            ]),
            &dsse_sig,
            &publisher_key,
        );
        assert_eq!(
            eval_policy_vector(&wrong_policy, &ok).await,
            (97, 2, 2, 2),
            "wrong payload hash must reject even when order is sorted"
        );
    }

    /// Mirror of `transparency_log_rego_affirms_on_matching_measurements` for the
    /// `tdx.td-shim` reconstruction path. The rego rule
    /// `actual_measurement("tdx.td-shim") := input.tdx.quote.body.mr_td` is never
    /// exercised by the container test above, so a typo in the `mr_td` path would
    /// ship undetected without this test. The expected `payloadHash` is computed
    /// self-contained (JCS-canonicalize + sha256) so the test stays correct if the
    /// fixture value changes.
    #[cfg(feature = "crypto-rustcrypto")]
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
        let (dsse_sig, publisher_key) = sign_dsse_for_manifest(&manifest);

        let policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&["tdx.td-shim".to_string()]),
            &dsse_sig,
            &publisher_key,
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

    /// `actual_measurement("tdx.kernel")` extracts the SHA-384 of the
    /// `td_payload` firmware-blob2 event (EV_EFI_PLATFORM_FIRMWARE_BLOB2 whose
    /// description starts with "td_payload", extending RTMR1 / index 2) from
    /// the parsed event log. This exercises that rule: a matching kernel digest affirms, a tampered
    /// digest rejects.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_affirms_on_matching_td_kernel_measurement() {
        // 96-hex SHA-384 value (the td_payload event's recorded digest).
        let kernel = "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let mr_td = "321ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";
        // Raw td_payload event (base64) carrying BlobLength = 32 MiB
        // (33554432): desc_size=11, desc="td_payload\0", BlobBase=0,
        // BlobLength=33554432 (LE). The rego rule gates on
        // `tng.td_payload_blob_length([e.event]) == 33554432`.
        let event_32mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAACAAAAAA==";

        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{
                "type": "tdx.kernel",
                "value": kernel,
            }]
        });
        let canonical = jcs_compact(&manifest);
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, canonical.as_bytes());
        let payload_hash = hex::encode(sha2::Digest::finalize(hasher));
        let (dsse_sig, publisher_key) = sign_dsse_for_manifest(&manifest);

        let policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&["tdx.kernel".to_string()]),
            &dsse_sig,
            &publisher_key,
        );

        // Matching input: the td_payload firmware-blob2 event carries the
        // kernel digest AND the 32 MiB BlobLength; the reconstructed manifest
        // matches the logged one.
        let ok = format!(
            r#"{{"tdx":{{"quote":{{"header":{{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}},"body":{{"mr_td":{mr_td:?},"td_attributes":"0000001000000000"}}}},"uefi_event_logs":[{{"type_name":"EV_EFI_PLATFORM_FIRMWARE_BLOB2","details":{{"string":"td_payload"}},"event":{event_32mib:?},"digests":[{{"alg":"SHA-384","digest":{kernel:?}}}],"index":2}}]}}}}"#
        );
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "matching td-payload kernel digest + 32 MiB blob length must affirm"
        );

        // Tampered kernel digest -> reconstructed manifest hash mismatches
        // payload_hash -> reject.
        let tampered = "b1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let bad = ok.replace(kernel, tampered);
        assert_eq!(
            eval_policy_vector(&policy, &bad).await,
            (97, 2, 2, 2),
            "tampered td-payload kernel digest must reject on hardware"
        );
    }

    /// `actual_measurement("tdx.kernel")` requires an EXACT descriptor match
    /// (`e.details.string == "td_payload"`). A `startswith` prefix would wrongly
    /// match `td_payload_extra`; the exact rule must drop it →
    /// `actual_measurement("tdx.kernel")` is undefined → the reconstructed
    /// manifest is missing the measurement → its hash
    // mismatches `payload_hash` → reject.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_tdx_kernel_descriptor_must_be_exact_match() {
        let kernel = "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let mr_td = "321ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";
        let event_32mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAACAAAAAA==";

        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{"type": "tdx.kernel", "value": kernel}]
        });
        let payload_hash = {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, jcs_compact(&manifest).as_bytes());
            hex::encode(sha2::Digest::finalize(h))
        };
        let (dsse_sig, publisher_key) = sign_dsse_for_manifest(&manifest);
        let policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&["tdx.kernel".to_string()]),
            &dsse_sig,
            &publisher_key,
        );

        // Exact descriptor "td_payload" + 32 MiB blob → match → affirm.
        let ok = format!(
            r#"{{"tdx":{{"quote":{{"header":{{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}},"body":{{"mr_td":{mr_td:?},"td_attributes":"0000001000000000"}}}},"uefi_event_logs":[{{"type_name":"EV_EFI_PLATFORM_FIRMWARE_BLOB2","details":{{"string":"td_payload"}},"event":{event_32mib:?},"digests":[{{"alg":"SHA-384","digest":{kernel:?}}}],"index":2}}]}}}}"#
        );
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "exact td_payload descriptor + 32 MiB blob must affirm"
        );

        // Prefix-only descriptor "td_payload_extra" must NOT match → reject.
        let prefixed = format!(
            r#"{{"tdx":{{"quote":{{"header":{{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}},"body":{{"mr_td":{mr_td:?},"td_attributes":"0000001000000000"}}}},"uefi_event_logs":[{{"type_name":"EV_EFI_PLATFORM_FIRMWARE_BLOB2","details":{{"string":"td_payload_extra"}},"event":{event_32mib:?},"digests":[{{"alg":"SHA-384","digest":{kernel:?}}}],"index":2}}]}}}}"#
        );
        assert_eq!(
            eval_policy_vector(&policy, &prefixed).await,
            (97, 2, 2, 2),
            "prefix-only td_payload_* descriptor must reject (exact match required)"
        );
    }

    /// `actual_measurement("tdx.kernel")` enforces the TD-payload blob length
    /// be exactly 32 MiB (33554432 = `32<<20`). The rego rule calls the
    /// host-await `tng.td_payload_blob_length([e.event])`, which parses
    /// UEFI_PLATFORM_FIRMWARE_BLOB2 from the base64 `e.event` and returns the
    /// declared BlobLength. A blob of the wrong size (e.g. 16 MiB) must drop
    /// the measurement → manifest mismatch → reject (fail-closed). A
    /// malformed/short event likewise drops → reject.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_tdx_kernel_blob_length_must_be_32mib() {
        let kernel = "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let mr_td = "321ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";
        // 32 MiB (33554432) — affirms.
        let event_32mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAACAAAAAA==";
        // 16 MiB (16777216) — wrong size, must reject.
        let event_16mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAABAAAAAA==";

        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{"type": "tdx.kernel", "value": kernel}]
        });
        let payload_hash = {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, jcs_compact(&manifest).as_bytes());
            hex::encode(sha2::Digest::finalize(h))
        };
        let (dsse_sig, publisher_key) = sign_dsse_for_manifest(&manifest);
        let policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&["tdx.kernel".to_string()]),
            &dsse_sig,
            &publisher_key,
        );

        // 32 MiB → affirm.
        let ok = format!(
            r#"{{"tdx":{{"quote":{{"header":{{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}},"body":{{"mr_td":{mr_td:?},"td_attributes":"0000001000000000"}}}},"uefi_event_logs":[{{"type_name":"EV_EFI_PLATFORM_FIRMWARE_BLOB2","details":{{"string":"td_payload"}},"event":{event_32mib:?},"digests":[{{"alg":"SHA-384","digest":{kernel:?}}}],"index":2}}]}}}}"#
        );
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "td_payload blob length == 32 MiB must affirm"
        );

        // 16 MiB → reject (blob length mismatch drops the measurement).
        let wrong_blob = ok.replace(event_32mib, event_16mib);
        assert_eq!(
            eval_policy_vector(&policy, &wrong_blob).await,
            (97, 2, 2, 2),
            "td_payload blob length != 32 MiB must reject"
        );

        // Malformed (truncated) event → host-await returns -1 → never equals
        // 33554432 → reject.
        let malformed = ok.replace(event_32mib, "AAAA");
        assert_eq!(
            eval_policy_vector(&policy, &malformed).await,
            (97, 2, 2, 2),
            "malformed td_payload event must reject (fail-closed)"
        );
    }

    /// A 32 MiB + non-32 MiB td_payload event pair with the SAME digest is a
    /// conflict: a blobLength disagreement is "conflicting td_payload events"
    /// even when the digest is identical. Before R1, the rego `matching_digests`
    /// set filtered by `tng.td_payload_blob_length([e2.event]) == 33554432`, so a
    /// non-32 MiB td_payload event was silently excluded from the set → a 32 MiB
    /// + 16 MiB pair (same digest) yielded `count == 1` → affirm (bug: the 16
    /// MiB event was silently ignored instead of conflicting). After R1 the
    /// distinct-length set is `{33554432, 16777216}` != `{33554432}` → rule
    /// undefined → drop → reject (fail-closed). A duplicate pair (both 32 MiB,
    /// same digest) still affirms (same-digest+same-length duplicates are
    /// consistent).
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_tdx_kernel_conflicting_blob_length_rejects() {
        let kernel = "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let mr_td = "321ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";
        // 32 MiB (33554432) and 16 MiB (16777216) td_payload events.
        let event_32mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAACAAAAAA==";
        let event_16mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAABAAAAAA==";

        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{"type": "tdx.kernel", "value": kernel}]
        });
        let payload_hash = {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, jcs_compact(&manifest).as_bytes());
            hex::encode(sha2::Digest::finalize(h))
        };
        let (dsse_sig, publisher_key) = sign_dsse_for_manifest(&manifest);
        let policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&["tdx.kernel".to_string()]),
            &dsse_sig,
            &publisher_key,
        );

        // Helper: a td_payload firmware-blob2 event with the given base64 event
        // body and kernel digest, at RTMR1 (index 2).
        let td_payload_event = |event_b64: &str| {
            serde_json::json!({
                "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
                "details": {"string": "td_payload"},
                "event": event_b64,
                "digests": [{"alg": "SHA-384", "digest": kernel}],
                "index": 2
            })
        };
        let quote_header = serde_json::json!({
            "tee_type": "81000000",
            "vendor_id": "939a7233f79c4ca9940a0db3957f0607"
        });
        let quote_body = serde_json::json!({
            "mr_td": mr_td,
            "td_attributes": "0000001000000000"
        });

        // Single 32 MiB td_payload event → affirm.
        let single = serde_json::json!({
            "tdx": {"quote": {"header": quote_header, "body": quote_body},
                    "uefi_event_logs": [td_payload_event(event_32mib)]}
        })
        .to_string();
        assert_eq!(
            eval_policy_vector(&policy, &single).await,
            (2, 2, 2, 2),
            "single 32 MiB td_payload event must affirm"
        );

        // Duplicate pair (both 32 MiB, same digest) → benign duplicate → affirm
        // (same-digest + same-length duplicates are consistent).
        let dup_same = serde_json::json!({
            "tdx": {"quote": {"header": quote_header, "body": quote_body},
                    "uefi_event_logs": [td_payload_event(event_32mib), td_payload_event(event_32mib)]}
        })
        .to_string();
        assert_eq!(
            eval_policy_vector(&policy, &dup_same).await,
            (2, 2, 2, 2),
            "duplicate 32 MiB td_payload events (same digest) must still affirm"
        );

        // 32 MiB + 16 MiB pair (same digest) → blobLength conflict → reject
        // (fail-closed). Before R1 this affirmed because the 16 MiB event was
        // silently excluded by the `== 33554432` filter inside the digest set.
        let conflict = serde_json::json!({
            "tdx": {"quote": {"header": quote_header, "body": quote_body},
                    "uefi_event_logs": [td_payload_event(event_32mib), td_payload_event(event_16mib)]}
        })
        .to_string();
        assert_eq!(
            eval_policy_vector(&policy, &conflict).await,
            (97, 2, 2, 2),
            "32 MiB + 16 MiB td_payload pair (same digest) must reject (blobLength conflict)"
        );
    }

    /// Fix #2: a descriptor-matching td_payload event at register index != 2
    /// must REJECT (not be silently excluded from the conflict set). A
    /// td_payload descriptor-matching event must extend RTMR1 (register index
    /// 2); any such event with a non-2 index is a violation. Before fix #2 the
    /// `e2.index == 2` filter inside the `matching_digests`/`matching_lengths`
    /// comprehensions silently excluded a non-2-index td_payload event, so a
    /// pair of (32 MiB index-2 event) + (same-digest index-1 event) affirmed
    /// instead of rejecting. After fix #2 the `bad_index_events` guard makes
    /// the rule undefined → drop → reject (fail-closed).
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_tdx_kernel_rejects_non_rtmr1_index() {
        let kernel = "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let mr_td = "321ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";
        let event_32mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAACAAAAAA==";

        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{"type": "tdx.kernel", "value": kernel}]
        });
        let payload_hash = {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, jcs_compact(&manifest).as_bytes());
            hex::encode(sha2::Digest::finalize(h))
        };
        let (dsse_sig, publisher_key) = sign_dsse_for_manifest(&manifest);
        let policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&["tdx.kernel".to_string()]),
            &dsse_sig,
            &publisher_key,
        );

        // td_payload firmware-blob2 event with a given RTMR register index.
        let td_payload_event = |index: u32| {
            serde_json::json!({
                "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
                "details": {"string": "td_payload"},
                "event": event_32mib,
                "digests": [{"alg": "SHA-384", "digest": kernel}],
                "index": index
            })
        };
        let quote_header = serde_json::json!({
            "tee_type": "81000000",
            "vendor_id": "939a7233f79c4ca9940a0db3957f0607"
        });
        let quote_body = serde_json::json!({
            "mr_td": mr_td,
            "td_attributes": "0000001000000000"
        });

        // Single 32 MiB td_payload event at index 2 → affirm (baseline).
        let single = serde_json::json!({
            "tdx": {"quote": {"header": quote_header, "body": quote_body},
                    "uefi_event_logs": [td_payload_event(2)]}
        })
        .to_string();
        assert_eq!(
            eval_policy_vector(&policy, &single).await,
            (2, 2, 2, 2),
            "single index-2 td_payload event must affirm"
        );

        // Pair: index-2 (32 MiB) + index-1 (same digest, 32 MiB). The index-1
        // event is descriptor-matching but extends RTMR0, not RTMR1 → a
        // violation → must reject (fail-closed). Before fix #2 the index-1
        // event was silently excluded by the `e2.index == 2` filter → affirm
        // (bug).
        let bad = serde_json::json!({
            "tdx": {"quote": {"header": quote_header, "body": quote_body},
                    "uefi_event_logs": [td_payload_event(2), td_payload_event(1)]}
        })
        .to_string();
        assert_eq!(
            eval_policy_vector(&policy, &bad).await,
            (97, 2, 2, 2),
            "descriptor-matching td_payload event at index != 2 must reject (fail-closed)"
        );
    }

    /// Fix #3: a descriptor-matching td_payload event (extending RTMR1) that
    /// has NO SHA-384 digest must REJECT (not be silently excluded). A
    /// td_payload event must carry a 48-byte SHA-384 digest; an event with no
    /// digests or a non-SHA-384 digest is a violation. Before fix #3 the
    /// `some d2 ... d2.alg == "SHA-384"` filter inside the
    /// `matching_digests`/`matching_lengths` comprehensions silently excluded
    /// such an event, so a pair of (32 MiB index-2 event with SHA-384) + (32
    /// MiB index-2 event with only a SHA-256 digest) affirmed instead of
    /// rejecting. After fix #3 the `td_index2_events` vs
    /// `td_index2_with_sha384` count guard makes the rule undefined → drop →
    /// reject (fail-closed).
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_tdx_kernel_rejects_missing_sha384_digest() {
        let kernel = "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let mr_td = "321ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";
        let event_32mib = "C3RkX3BheWxvYWQAAAAAAAAAAAAAAAACAAAAAA==";

        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{"type": "tdx.kernel", "value": kernel}]
        });
        let payload_hash = {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, jcs_compact(&manifest).as_bytes());
            hex::encode(sha2::Digest::finalize(h))
        };
        let (dsse_sig, publisher_key) = sign_dsse_for_manifest(&manifest);
        let policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&["tdx.kernel".to_string()]),
            &dsse_sig,
            &publisher_key,
        );

        let quote_header = serde_json::json!({
            "tee_type": "81000000",
            "vendor_id": "939a7233f79c4ca9940a0db3957f0607"
        });
        let quote_body = serde_json::json!({
            "mr_td": mr_td,
            "td_attributes": "0000001000000000"
        });

        // td_payload event carrying a SHA-384 digest → affirm (baseline).
        let with_sha384 = serde_json::json!({
            "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
            "details": {"string": "td_payload"},
            "event": event_32mib,
            "digests": [{"alg": "SHA-384", "digest": kernel}],
            "index": 2
        });
        let ok = serde_json::json!({
            "tdx": {"quote": {"header": quote_header, "body": quote_body},
                    "uefi_event_logs": [with_sha384]}
        })
        .to_string();
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "single index-2 td_payload event with SHA-384 digest must affirm"
        );

        // Same event but with only a SHA-256 digest (no SHA-384) → must reject:
        // a td_payload event must carry a SHA-384 digest. Before fix #3
        // the event was silently excluded by the `d2.alg == "SHA-384"` filter.
        let no_sha384 = serde_json::json!({
            "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
            "details": {"string": "td_payload"},
            "event": event_32mib,
            "digests": [{"alg": "SHA-256", "digest": "0000000000000000000000000000000000000000000000000000000000000000"}],
            "index": 2
        });
        let bad = serde_json::json!({
            "tdx": {"quote": {"header": {"tee_type": "81000000", "vendor_id": "939a7233f79c4ca9940a0db3957f0607"}, "body": quote_body},
                    "uefi_event_logs": [no_sha384]}
        })
        .to_string();
        assert_eq!(
            eval_policy_vector(&policy, &bad).await,
            (97, 2, 2, 2),
            "td_payload event with no SHA-384 digest must reject (fail-closed)"
        );

        // Empty digests array → also reject (no digest path).
        let empty_digests = serde_json::json!({
            "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
            "details": {"string": "td_payload"},
            "event": event_32mib,
            "digests": [],
            "index": 2
        });
        let bad2 = serde_json::json!({
            "tdx": {"quote": {"header": {"tee_type": "81000000", "vendor_id": "939a7233f79c4ca9940a0db3957f0607"}, "body": quote_body},
                    "uefi_event_logs": [empty_digests]}
        })
        .to_string();
        assert_eq!(
            eval_policy_vector(&policy, &bad2).await,
            (97, 2, 2, 2),
            "td_payload event with empty digests array must reject (fail-closed)"
        );
    }

    /// Real-evidence port of cmaas's `TestExtractKernelMeasurementFromPAIEventLog`
    /// / `TestVerifyTEEMeasurementsAcceptsKernel` /
    /// `RejectsKernelMismatch`. Parses the real 5892-byte PAI TD CC event log
    /// (`tdx_CCEL_data_pai`) through the SAME `eventlog` crate the
    /// attestation-service TDX verifier uses to build `input.tdx.uefi_event_logs`,
    /// then runs the Rego `actual_measurement("tdx.kernel")` rule over the
    /// structured events and asserts the real SHA-384 TD-payload digest
    /// `85619a91…` (a real kernel measurement, not a synthetic `a1b2c3d4…`).
    ///
    /// The affirm arm publishes a manifest carrying the real kernel value;
    /// the reject arm tampers it. This is a non-`#[ignore]` test (init-bake
    /// path, no live rekor). The DSSE signature is produced by the test's own
    /// `sign_dsse_for_manifest` over the canonical manifest, mirroring the
    /// synthetic tdx.kernel tests (the real fixture's DSSE sig is for a
    /// different runtime-image manifest, not this kernel manifest).
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_tdx_kernel_extracts_real_pai_event_log_measurement() {
        // The real PAI TD kernel measurement (SHA-384) carried by the
        // `td_payload` firmware-blob2 event at RTMR1 (index 2) in
        // `tdx_CCEL_data_pai`. Pinned from cmaas's
        // `TestExtractKernelMeasurementFromPAIEventLog`.
        let kernel = "85619a9146b5c1409bf034bdabd6d93df26a5a23b41b43f92a7a4025760a1c4f110194ae75a2b9625b0de97f2b00fc8f";

        // Parse the real CC event log through the production `eventlog` crate
        // (the same crate attestation-service's TDX verifier uses to build
        // `input.tdx.uefi_event_logs`). `CcEventLog` serializes with the
        // `uefi_event_logs` field name, so its JSON IS the Rego input's
        // `tdx.uefi_event_logs` array — no hand-rolled event shaping.
        let ccel_bytes =
            std::fs::read("src/tee/coco/converter/builtin/tests/fixtures/tdx_CCEL_data_pai")
                .expect("read real PAI event-log fixture");
        let ccel: eventlog::CcEventLog =
            ccel_bytes.try_into().expect("parse real PAI CC event log");
        let parsed = serde_json::to_value(&ccel)
            .expect("serialize parsed CC event log")
            .as_object()
            .expect("parsed event log is an object")
            .clone();

        // Mirror the synthetic tdx.kernel tests' quote shape: a non-debug
        // `td_attributes` + canonical TDX vendor_id so the `hardware` rule
        // affirms; `mr_td` is a dummy (the policy publishes only tdx.kernel,
        // not tdx.td-shim, so `mr_td` is never read).
        let quote_header = serde_json::json!({
            "tee_type": "81000000",
            "vendor_id": "939a7233f79c4ca9940a0db3957f0607"
        });
        let quote_body = serde_json::json!({
            "mr_td": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "td_attributes": "0000001000000000"
        });

        let mut tdx = serde_json::Map::new();
        tdx.insert(
            "quote".to_string(),
            serde_json::json!({"header": quote_header, "body": quote_body}),
        );
        // Splice the parsed `uefi_event_logs` array straight in under `tdx`
        // (the Rego rules read `input.tdx.uefi_event_logs`).
        tdx.insert(
            "uefi_event_logs".to_string(),
            parsed["uefi_event_logs"].clone(),
        );
        let ok_input = serde_json::json!({"tdx": tdx}).to_string();

        // Publish a manifest carrying the REAL kernel. The init-bake path
        // binds the reconstructed manifest (rebuilt from the actual
        // measurement) to this signed payload hash.
        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{"type": "tdx.kernel", "value": kernel}]
        });
        let payload_hash = {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, jcs_compact(&manifest).as_bytes());
            hex::encode(sha2::Digest::finalize(h))
        };
        let (dsse_sig, publisher_key) = sign_dsse_for_manifest(&manifest);
        let policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&["tdx.kernel".to_string()]),
            &dsse_sig,
            &publisher_key,
        );

        // Real PAI log → Rego extracts the real kernel → manifest matches → affirm.
        assert_eq!(
            eval_policy_vector(&policy, &ok_input).await,
            (2, 2, 2, 2),
            "real PAI event log must extract the real kernel measurement and affirm"
        );

        // Tamper the published kernel → reconstructed manifest (still the real
        // kernel from the event log) mismatches payload_hash → reject on
        // hardware (cmaas `RejectsKernelMismatch`).
        let tampered = "85619a9146b5c1409bf034bdabd6d93df26a5a23b41b43f92a7a4025760a1c4f110194ae75a2b9625b0de97f2b00fc80";
        let bad_manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{"type": "tdx.kernel", "value": tampered}]
        });
        let bad_payload_hash = {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, jcs_compact(&bad_manifest).as_bytes());
            hex::encode(sha2::Digest::finalize(h))
        };
        let (bad_dsse_sig, bad_publisher_key) = sign_dsse_for_manifest(&bad_manifest);
        let bad_policy = build_transparency_log_policy(
            &bad_payload_hash,
            "1.0.0",
            Some(&["tdx.kernel".to_string()]),
            &bad_dsse_sig,
            &bad_publisher_key,
        );
        assert_eq!(
            eval_policy_vector(&bad_policy, &ok_input).await,
            (97, 2, 2, 2),
            "a published kernel that differs from the real PAI event-log kernel must reject"
        );
    }

    /// Real-evidence port of cmaas's `TestExtractAAELContainerEvents`. Parses
    /// the real 5892-byte PAI TD CC event log (`tdx_CCEL_data_pai`) through the
    /// SAME `eventlog` crate the attestation-service TDX verifier uses to build
    /// `input.tdx.uefi_event_logs`, then runs the Rego
    /// `actual_measurement("container.image.<repo>")` rule over the structured
    /// events and asserts the real AAEL `kangaroo/pull-image` event resolves to
    /// repo `busybox` (last `/` segment of the real reference
    /// `pai-registry.cn-wulanchabu-acdr-1.cr.aliyuncs.com/default/busybox:2025052701`)
    /// with digest `sha256:16ece118…` — a real container image measurement, not
    /// the synthetic `cmaas-runtime`/`d42f6e1b…` fixture.
    ///
    /// The affirm arm publishes a manifest carrying the real `busybox` digest;
    /// the reject arm tampers it. Non-`#[ignore]` (init-bake path, no live
    /// rekor). DSSE signature produced by `sign_dsse_for_manifest` over the
    /// canonical manifest, mirroring the synthetic container.image tests.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_container_image_extracts_real_pai_event_log_measurement() {
        // The real PAI AAEL kangaroo/pull-image event resolves to repo `busybox`
        // (image_repo_name of the real reference) carrying this digest. Pinned
        // from cmaas's `TestExtractAAELContainerEvents`.
        let image_digest =
            "sha256:16ece118a36d152ed7562347741470b1bb0b0f7561ff1fe0049857a03d4fec5d";
        let measurement_type = "container.image.busybox";

        // Parse the real CC event log through the production `eventlog` crate.
        // `CcEventLog` serializes with the `uefi_event_logs` field name, so its
        // JSON IS the Rego input's `tdx.uefi_event_logs` array.
        let ccel_bytes =
            std::fs::read("src/tee/coco/converter/builtin/tests/fixtures/tdx_CCEL_data_pai")
                .expect("read real PAI event-log fixture");
        let ccel: eventlog::CcEventLog =
            ccel_bytes.try_into().expect("parse real PAI CC event log");
        let parsed = serde_json::to_value(&ccel)
            .expect("serialize parsed CC event log")
            .as_object()
            .expect("parsed event log is an object")
            .clone();

        // Mirror the synthetic container.image tests' quote shape: non-debug
        // `td_attributes` + canonical TDX vendor_id so `hardware` affirms. No
        // `mr_td` is needed (the policy publishes only container.image.busybox).
        let quote_header = serde_json::json!({
            "tee_type": "81000000",
            "vendor_id": "939a7233f79c4ca9940a0db3957f0607"
        });
        let quote_body = serde_json::json!({
            "td_attributes": "0000001000000000"
        });

        let mut tdx = serde_json::Map::new();
        tdx.insert(
            "quote".to_string(),
            serde_json::json!({"header": quote_header, "body": quote_body}),
        );
        // Splice the parsed `uefi_event_logs` array straight in under `tdx`.
        tdx.insert(
            "uefi_event_logs".to_string(),
            parsed["uefi_event_logs"].clone(),
        );
        let ok_input = serde_json::json!({"tdx": tdx}).to_string();

        // Publish a manifest carrying the REAL busybox digest.
        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{"type": measurement_type, "value": image_digest}]
        });
        let payload_hash = {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, jcs_compact(&manifest).as_bytes());
            hex::encode(sha2::Digest::finalize(h))
        };
        let (dsse_sig, publisher_key) = sign_dsse_for_manifest(&manifest);
        let policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&[measurement_type.to_string()]),
            &dsse_sig,
            &publisher_key,
        );

        // Real PAI log → Rego resolves repo `busybox` + real digest → manifest
        // matches → affirm.
        assert_eq!(
            eval_policy_vector(&policy, &ok_input).await,
            (2, 2, 2, 2),
            "real PAI event log must extract the real busybox container image measurement and affirm"
        );

        // Tamper the published digest → reconstructed manifest (still the real
        // digest from the AAEL event) mismatches payload_hash → reject on
        // hardware (cmaas tampering-equivalent).
        let tampered_digest =
            "sha256:26ece118a36d152ed7562347741470b1bb0b0f7561ff1fe0049857a03d4fec5d";
        let bad_manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{"type": measurement_type, "value": tampered_digest}]
        });
        let bad_payload_hash = {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, jcs_compact(&bad_manifest).as_bytes());
            hex::encode(sha2::Digest::finalize(h))
        };
        let (bad_dsse_sig, bad_publisher_key) = sign_dsse_for_manifest(&bad_manifest);
        let bad_policy = build_transparency_log_policy(
            &bad_payload_hash,
            "1.0.0",
            Some(&[measurement_type.to_string()]),
            &bad_dsse_sig,
            &bad_publisher_key,
        );
        assert_eq!(
            eval_policy_vector(&bad_policy, &ok_input).await,
            (97, 2, 2, 2),
            "a published container image digest that differs from the real PAI AAEL event must reject"
        );
    }

    /// `actual_measurement` rules explicitly detect conflicting events (two
    /// matching events with different digests) and drop the measurement →
    /// manifest mismatch → reject (fail-closed), the `conflicting <type>
    /// measurements` check. Without this guard a conflict would surface as a
    /// Rego function-value runtime error aborting the whole eval; the explicit
    /// distinct-digest set size check turns it into a clean reject. Covers the
    /// container.image rule (the runtime repo gets two AAEL events with
    /// different digests → reject).
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_rejects_conflicting_container_image_events() {
        let digest_a = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let digest_b = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // The affirm case uses digest_a; the policy's payloadHash is computed
        // from the manifest carrying digest_a.
        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{
                "type": "container.image.cmaas-runtime",
                "value": digest_a,
            }]
        });
        let payload_hash = {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, jcs_compact(&manifest).as_bytes());
            hex::encode(sha2::Digest::finalize(h))
        };
        let (dsse_sig, publisher_key) = sign_dsse_for_manifest(&manifest);
        let policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            &dsse_sig,
            &publisher_key,
        );

        // Single matching AAEL event → affirm.
        let single = matching_cmaas_input(digest_a);
        assert_eq!(
            eval_policy_vector(&policy, &single).await,
            (2, 2, 2, 2),
            "single matching AAEL event must affirm"
        );

        // Two matching AAEL events with the SAME digest → still affirms
        // (distinct-digest set size == 1). This is a benign duplicate, not a
        // conflict — same-digest duplicates are consistent.
        let dup_same = serde_json::json!({
            "tdx": {
                "quote": {"header": {"tee_type": "81000000", "vendor_id": "939a7233f79c4ca9940a0db3957f0607"}, "body": {"td_attributes": "0000001000000000"}},
                "uefi_event_logs": [aael_event(digest_a), aael_event(digest_a)]
            }
        })
        .to_string();
        assert_eq!(
            eval_policy_vector(&policy, &dup_same).await,
            (2, 2, 2, 2),
            "duplicate AAEL events with the SAME digest must still affirm"
        );

        // Two matching AAEL events with DIFFERENT digests → conflict → drop →
        // manifest mismatch → reject (fail-closed, not a silent pick).
        let conflict = serde_json::json!({
            "tdx": {
                "quote": {"header": {"tee_type": "81000000", "vendor_id": "939a7233f79c4ca9940a0db3957f0607"}, "body": {"td_attributes": "0000001000000000"}},
                "uefi_event_logs": [aael_event(digest_a), aael_event(digest_b)]
            }
        })
        .to_string();
        assert_eq!(
            eval_policy_vector(&policy, &conflict).await,
            (97, 2, 2, 2),
            "conflicting AAEL digests must reject (explicit conflict detection)"
        );
    }

    /// `actual_measurement` rules gate digests on canonical-format regexes:
    /// td-shim/td-kernel require 96 lowercase hex; container.image.* require
    /// `sha256:` + 64 lowercase hex. A malformed digest makes the rule
    /// undefined → the measurement is dropped from the reconstructed manifest
    /// → its hash mismatches `payload_hash` → reject (fail-closed). A
    /// well-formed matching digest still affirms (not a tautology).
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_rejects_malformed_measurement_value_format() {
        // Well-formed cmaas-runtime digest affirms.
        let good_digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{
                "type": "container.image.cmaas-runtime",
                "value": good_digest,
            }]
        });
        let payload_hash = {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, jcs_compact(&manifest).as_bytes());
            hex::encode(sha2::Digest::finalize(h))
        };
        let (dsse_sig, publisher_key) = sign_dsse_for_manifest(&manifest);
        let policy = build_transparency_log_policy(
            &payload_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            &dsse_sig,
            &publisher_key,
        );
        let ok = matching_cmaas_input(good_digest);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "well-formed sha256:+64hex digest must affirm"
        );

        // Malformed: uppercase hex → fails lowercase regex → measurement
        // dropped → manifest mismatch → reject.
        let uppercase = "sha256:D42F6E1B2AAFB59383D0892824AEBF5E0A2E27DAD989A3FB26552A6E77E4BE46";
        let bad_upper = matching_cmaas_input(uppercase);
        assert_eq!(
            eval_policy_vector(&policy, &bad_upper).await,
            (97, 2, 2, 2),
            "uppercase-hex digest must reject (lowercase required)"
        );

        // Malformed: wrong length (only 32 hex after prefix) → reject.
        let too_short = "sha256:abc123";
        let bad_short = matching_cmaas_input(too_short);
        assert_eq!(
            eval_policy_vector(&policy, &bad_short).await,
            (97, 2, 2, 2),
            "too-short digest must reject (length-format check)"
        );

        // Malformed: missing `sha256:` prefix → reject.
        let no_prefix = "d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let bad_noprefix = matching_cmaas_input(no_prefix);
        assert_eq!(
            eval_policy_vector(&policy, &bad_noprefix).await,
            (97, 2, 2, 2),
            "missing sha256: prefix must reject"
        );
    }

    /// DSSE publisher-signature behavior test for the `transparency_log` rego:
    /// with the real fixture DSSE signature + the fixture's in-band publisher
    /// key baked, (1) a matching reconstructed manifest affirms (payloadHash
    /// AND DSSE both pass), (2) a tampered digest rejects (payloadHash AND DSSE
    /// both fail), (3) a wrong publisher key baked rejects even when the
    /// payloadHash still matches (DSSE gates — publisher-identity binding). The
    /// signature + key are extracted from the real rekor fixture the same way
    /// the `tng.verify_dsse_signature` primitive's S3 unit test does.
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
            &dsse_signature,
            &publisher_key,
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
            &dsse_signature,
            bogus_pem,
        );
        assert_eq!(
            eval_policy_vector(&wrong_policy, &ok).await,
            (97, 2, 2, 2),
            "wrong publisher key must reject even when payloadHash matches (DSSE gates)"
        );
    }

    /// R5: the legacy rekor-v1 init-bake path must make DSSE verification
    /// mandatory even when no `publisherPublicKeyPem` is configured — there is
    /// always a trusted publisher key (configured, or the built-in publisher
    /// key when the config leaves it empty), and DSSE verification always runs.
    /// The loader now resolves the publisher key to the built-in baseline when
    /// none is configured (mirroring `build_artifact_server_policy`), so a
    /// policy baked with the built-in key + the fixture's real DSSE signature
    /// affirms on a matching manifest and rejects on a wrong signature
    /// (publisher-identity binding). The fixture's
    /// `body.spec.signatures[0].verifier` IS the built-in publisher key, so
    /// the built-in key verifies the real signature.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rego_dsse_verifies_against_builtin_publisher_key() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        // Extract the real DSSE signature from the fixture entry.
        let entry_raw = include_str!("tests/fixtures/rekor_v1_entry.json");
        let entry: serde_json::Value = serde_json::from_str(entry_raw).expect("parse fixture");
        let body_bytes = STANDARD
            .decode(entry["body"].as_str().expect("body"))
            .expect("decode entry body");
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("parse body");
        let dsse_signature = body["spec"]["signatures"][0]["signature"]
            .as_str()
            .expect("signature")
            .to_string();
        // The built-in publisher key (the loader's fallback when no config key
        // is set). The fixture's `signatures[0].verifier` is the base64 of this
        // same PEM, so the real signature verifies against it.
        let builtin_key = artifact_server::BUILTIN_LOG_ENTRY_PUB_KEY_PEM;

        let payload_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let ok = format!(
            r#"{{"tdx":{{"quote":{{"header":{{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}},"body":{{"td_attributes":"0000001000000000"}}}},"uefi_event_logs":[{{"type_name":"EV_EVENT_TAG","details":{{"unicode_name":"AAEL","data":{{"domain":"alibabacloud.com","operation":"kangaroo/pull-image","content":{{"reference":"registry.example.com/ns/cmaas-runtime:latest","digest":{digest:?}}}}}}}}}]}}}}"#
        );

        // Built-in key + real signature → DSSE verifies → affirm.
        let policy = build_transparency_log_policy(
            payload_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            &dsse_signature,
            builtin_key,
        );
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "built-in publisher key + real DSSE signature must affirm (no config key needed)"
        );

        // Wrong (bogus) signature baked with the built-in key → DSSE verify
        // fails → reject even though payloadHash matches. A 32-byte base64
        // blob that is not a valid DER signature for this key.
        let bogus_sig = STANDARD.encode([0u8; 64]);
        let wrong_policy = build_transparency_log_policy(
            payload_hash,
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            &bogus_sig,
            builtin_key,
        );
        assert_eq!(
            eval_policy_vector(&wrong_policy, &ok).await,
            (97, 2, 2, 2),
            "wrong DSSE signature must reject against the built-in publisher key"
        );
    }

    /// Prove the canonical (JCS — sorted, compact) form of the manifest hashes
    /// to the REAL rekor payloadHash. This is the form regorus's `json.marshal`
    /// produces (it serializes object keys in sorted order), so the rego
    /// `tng.sha256(json.marshal(manifest)) == payload_hash` comparison is
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

    /// `resolve_dsse_signature` always returns the signature to bake: a real
    /// rekor v1 `dsse` entry always carries a signature in
    /// `body.spec.signatures[0].signature`, so an empty signature means a
    /// malformed/non-dsse entry → fail closed. The publisher key is resolved
    /// unconditionally by the caller (configured or built-in publisher key), so
    /// DSSE verification is always mandatory — there is no payloadHash-only
    /// fallback in the production init-bake path.
    #[test]
    fn resolve_dsse_signature_matches_expectations() {
        // non-empty signature -> bake it (DSSE always mandatory)
        assert_eq!(resolve_dsse_signature("sig").expect("sig -> Ok"), "sig");
        // empty signature -> malformed/non-dsse entry -> fail closed
        let err = resolve_dsse_signature("").expect_err("empty must fail closed");
        assert!(
            err.to_string().contains("no DSSE signature"),
            "error should describe the missing signature, got: {err}"
        );
    }

    /// Fix #4: the legacy rekor-v1 init-bake path (`build_transparency_log_policy`)
    /// must ALWAYS emit the `tng.verify_dsse_signature` call for the
    /// measurement-verification branch — DSSE verification is mandatory; there
    /// is no payloadHash-only fallback. The dead `_ => (String::new(), "")` arm
    /// that previously let callers opt out of DSSE is removed:
    /// `dsse_signature`/`publisher_key` are now non-`Option`. The
    /// `publishedMeasurements: None` branch bakes the DSSE literals for
    /// reference but does not invoke verification (no manifest to bind the
    /// signature to).
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn transparency_log_rego_legacy_path_always_emits_dsse_verify() {
        let (dsse_sig, publisher_key) = fixture_dsse();
        // Some(publishedMeasurements) → the verify call is always present.
        let policy = build_transparency_log_policy(
            "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8",
            "1.0.0",
            Some(&["container.image.cmaas-runtime".to_string()]),
            &dsse_sig,
            &publisher_key,
        );
        assert!(
            policy.contains("tng.verify_dsse_signature("),
            "legacy rekor-v1 policy must always emit tng.verify_dsse_signature (no payloadHash-only fallback)"
        );
        assert!(
            policy.contains("dsse_signature := "),
            "dsse_signature literal must be baked"
        );
        assert!(
            policy.contains("publisher_key := "),
            "publisher_key literal must be baked"
        );

        // publishedMeasurements: None → DSSE literals baked for reference, but
        // no `measurements_verified` rule → no verify call (no manifest to bind).
        let none_policy = build_transparency_log_policy(
            "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8",
            "1.0.0",
            None,
            &dsse_sig,
            &publisher_key,
        );
        assert!(
            none_policy.contains("dsse_signature := "),
            "None branch still bakes the dsse_signature literal"
        );
        assert!(
            !none_policy.contains("tng.verify_dsse_signature("),
            "None branch must not invoke DSSE verify (no reconstructed manifest)"
        );
    }

    /// Canonicalize a `serde_json::Value` via the shared `rekor_v1::canonical_json`
    /// (RFC 8785 JCS) so the init-bake tests and the on-demand host-await path
    /// compute identical bytes.
    fn jcs_compact(value: &serde_json::Value) -> String {
        rekor_v1::canonical_json(value).expect("canonical JSON serialize")
    }

    /// Sign a ReleaseManifest with a fixed test P-256 key and return
    /// `(dsse_signature_b64, publisher_key_pem)` so a policy baked with these
    /// DSSE-verifies against the reconstructed manifest at appraisal. Used by
    /// the legacy rekor-v1 init-bake tests whose synthetic manifests (td-shim,
    /// td-kernel, multi-measurement) have no real rekor fixture signature.
    /// Mirrors the `tng.verify_dsse_signature` host-await verify path exactly:
    /// `dsse_pae(DSSE_PAYLOAD_TYPE, jcs_compact(manifest))` signed with ECDSA
    /// P-256 (the p256 `Signer` hashes the PAE with SHA-256 internally, matching
    /// `VerifyingKey::verify`). The publisher key is hand-wrapped as a P-256
    /// SPKI PEM so `rekor_v1::parse_p256_public_key` accepts it.
    #[cfg(feature = "crypto-rustcrypto")]
    fn sign_dsse_for_manifest(manifest: &serde_json::Value) -> (String, String) {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        use p256::ecdsa::signature::Signer;

        // Fixed deterministic test signing key (RFC 6979 nonce). NOT the
        // built-in publisher key, so tests prove the signature is bound to the
        // baked key.
        let secret_bytes: [u8; 32] = [0x42; 32];
        let signing_key = p256::ecdsa::SigningKey::from_bytes((&secret_bytes).into())
            .expect("fixed test key valid");
        let payload = jcs_compact(manifest);
        let pae = dsse_pae(DSSE_PAYLOAD_TYPE, payload.as_bytes());
        let sig: p256::ecdsa::Signature = signing_key.sign(&pae);
        let sig_b64 = STANDARD.encode(sig.to_der());
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
        let sec1 = verifying_key.to_sec1_bytes();
        // P-256 SPKI DER: SEQUENCE { AlgId(ecPublicKey, prime256v1),
        // BIT STRING(0x00 || SEC1 point) }.
        let prefix: [u8; 26] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let mut spki = Vec::with_capacity(prefix.len() + sec1.len());
        spki.extend_from_slice(&prefix);
        spki.extend_from_slice(&sec1);
        let b64 = STANDARD.encode(&spki);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n");
        (sig_b64, pem)
    }

    /// Convenience: a `(dsse_signature, publisher_key)` pair that DSSE-verifies
    /// against the real fixture ReleaseManifest (`container.image.cmaas-runtime`
    /// with the `d42f6e1b...` digest, payloadHash `1011b70c...`). Used by the
    /// legacy init-bake tests that bake a hardcoded fixture `payload_hash` and
    /// need the reconstructed manifest to DSSE-verify on the affirm arm. For the
    /// `publishedMeasurements: None` tests the DSSE line is not emitted, so the
    /// values are merely baked-but-unused; the fixture pair still serves fine.
    #[cfg(feature = "crypto-rustcrypto")]
    fn fixture_dsse() -> (String, String) {
        let manifest = serde_json::json!({
            "schemaVersion": "1.0.0",
            "measurements": [{
                "type": "container.image.cmaas-runtime",
                "value": "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46"
            }]
        });
        sign_dsse_for_manifest(&manifest)
    }

    /// Prove the real fixture's DSSE signature verifies with its own
    /// in-band publisher key over the real ReleaseManifest, via the same
    /// DSSEPAE + sha256 + ECDSA P-256 path the `tng.verify_dsse_signature`
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

        // Replicate the primitive's verify path: dsse_pae + p256 verify (which
        // hashes the PAE with SHA-256 internally == ECDSA P-256 over sha256(pae)).
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
    // Err, or verify_evidence Err). This test exercises the full convert→verify
    // flow against the real evidence fixture; in CI it early-returns Ok when
    // the tdx-verifier backend is not enabled (the default tdx-dcap-rust
    // backend), so it no-ops unless the tdx-verifier feature + live rekor are
    // available.

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

    /// Load the real evidence fixture → (quote, cc_eventlog) base64.
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

    /// A valid P-256 PEM that is NOT the rekor signing key (it is the DSSE
    /// publisher key) — used as a bogus rekorPublicKeyPem / publisherPublicKeyPem.
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

    #[test]
    fn parse_artifact_server_with_fallback_matches_secure_proxy_readme() {
        let cfg = serde_json::json!({
            "type": "transparency_log",
            "publishedMeasurements": ["tdx.td-shim", "tdx.kernel", "container.image.cmaas-runtime"],
            "schemaVersion": "1.0.0",
            "services": [{
                "type": "artifact-server",
                "url": "https://attest.cn-beijing.aliyuncs.com",
                "logServices": [
                    {"type": "rekor-v1", "url": "https://rekor.sigstore.dev"},
                    {"type": "rekor-v1", "url": "https://rekor.openanolis.cn"}
                ]
            }],
            "fallbackPublishedMeasurements": ["container.image.cmaas-runtime"],
            "fallbackServices": [
                {"type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 2310520944i64}
            ]
        });
        let p: PolicyConfig = serde_json::from_value(cfg).unwrap();
        match &p {
            PolicyConfig::TransparencyLog {
                published_measurements,
                fallback_published_measurements,
                fallback_services,
                services,
                ..
            } => {
                assert_eq!(
                    published_measurements.as_deref().unwrap(),
                    &["tdx.td-shim", "tdx.kernel", "container.image.cmaas-runtime"]
                );
                assert_eq!(services.len(), 1);
                assert!(matches!(
                    services[0],
                    TransparencyServiceConfig::ArtifactServer { .. }
                ));
                assert_eq!(
                    fallback_published_measurements.as_ref().unwrap(),
                    &["container.image.cmaas-runtime"]
                );
                assert_eq!(fallback_services.as_ref().unwrap().len(), 1);
                assert!(matches!(
                    fallback_services.as_ref().unwrap()[0],
                    TransparencyServiceConfig::RekorV1 { .. }
                ));
            }
            _ => panic!("wrong variant"),
        }
        p.validate_transparency_config().unwrap();
    }

    #[test]
    fn validate_rejects_artifact_server_not_sole_primary() {
        let cfg = serde_json::json!({
            "type": "transparency_log", "publishedMeasurements": ["tdx.td-shim"],
            "services": [
                {"type":"artifact-server","url":"https://x","logServices":[{"type":"rekor-v1","url":"https://r"}]},
                {"type":"rekor-v1","logUrl":"https://r","logIndex":1}
            ]
        });
        let p: PolicyConfig = serde_json::from_value(cfg).unwrap();
        assert!(p.validate_transparency_config().is_err());
    }

    #[test]
    fn validate_rejects_fallback_without_artifact_server_primary() {
        let cfg = serde_json::json!({
            "type":"transparency_log","publishedMeasurements":["tdx.td-shim"],
            "services":[{"type":"rekor-v1","logUrl":"https://r","logIndex":1}],
            "fallbackServices":[{"type":"rekor-v1","logUrl":"https://r","logIndex":2}]
        });
        let p: PolicyConfig = serde_json::from_value(cfg).unwrap();
        assert!(p.validate_transparency_config().is_err());
    }

    #[test]
    fn validate_rejects_fallback_measurements_not_subset() {
        let cfg = serde_json::json!({
            "type":"transparency_log",
            "publishedMeasurements":["tdx.td-shim","container.image.cmaas-runtime"],
            "services":[{"type":"artifact-server","url":"https://x","logServices":[{"type":"rekor-v1","url":"https://r"}]}],
            "fallbackPublishedMeasurements":["tdx.kernel"],
            "fallbackServices":[{"type":"rekor-v1","logUrl":"https://r","logIndex":1}]
        });
        let p: PolicyConfig = serde_json::from_value(cfg).unwrap();
        assert!(p.validate_transparency_config().is_err());
    }

    #[test]
    fn validate_rejects_duplicate_logservice() {
        let cfg = serde_json::json!({
            "type":"transparency_log","publishedMeasurements":["tdx.td-shim"],
            "services":[{"type":"artifact-server","url":"https://x","logServices":[
                {"type":"rekor-v1","url":"https://r"},
                {"type":"rekor-v1","url":"https://r"}
            ]}]
        });
        let p: PolicyConfig = serde_json::from_value(cfg).unwrap();
        assert!(p.validate_transparency_config().is_err());
    }

    // Gate mirrors the `#[cfg(feature = "crypto-rustcrypto")]` on the
    // `tng.verify_dsse_signature` registration this test asserts; `tng.sha256`
    // (always registered) is still checked under the same gate when crypto is on.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn host_await_functions_use_tng_prefix() {
        let fns = builtin_as_host_await_functions();
        let names: Vec<&str> = fns.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"tng.sha256"));
        assert!(names.contains(&"tng.verify_dsse_signature"));
        assert!(!names
            .iter()
            .any(|n| n == &"crypto.sha256" || n == &"verify_dsse_signature"));
    }

    /// The generated Rego must reference the two host-awaits, the
    /// `primary_ok`/`fallback_ok` rules, the baked artifact-server URL, and must
    /// NOT bake a `payload_hash :=` (the whole point: the manifest
    /// is resolved at appraisal time, not baked at init).
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn artifact_server_primary_generates_branch_b_rego() {
        let cfg = serde_json::json!({
            "type":"transparency_log",
            "publishedMeasurements":["tdx.td-shim","container.image.cmaas-runtime"],
            "schemaVersion":"1.0.0",
            "services":[{"type":"artifact-server","url":"https://attest.example.com",
                "logServices":[{"type":"rekor-v1","url":"https://rekor.sigstore.dev"}]}],
            "fallbackPublishedMeasurements":["container.image.cmaas-runtime"],
            "fallbackServices":[{"type":"rekor-v1","logUrl":"https://rekor.sigstore.dev","logIndex":42}]
        });
        let p: PolicyConfig = serde_json::from_value(cfg).unwrap();
        let encoded = BuiltinCocoConverter::load_policy_as_base64_url_safe_no_pad(&p)
            .await
            .unwrap()
            .expect("artifact-server primary must produce a policy");
        let rego = String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(&encoded)
                .expect("decode base64 policy"),
        )
        .expect("utf8");
        assert!(
            rego.contains("tng.resolve_artifact_server"),
            "rego must call the primary host-await\n{rego}"
        );
        assert!(
            rego.contains("tng.fetch_rekor_on_demand"),
            "rego must call the fallback host-await (fallback configured)\n{rego}"
        );
        assert!(
            rego.contains("\"https://attest.example.com\""),
            "rego must bake the artifact-server URL\n{rego}"
        );
        assert!(
            rego.contains("primary_ok"),
            "rego must define primary_ok\n{rego}"
        );
        assert!(
            rego.contains("fallback_ok"),
            "rego must define fallback_ok (fallback configured)\n{rego}"
        );
        assert!(
            !rego.contains("payload_hash :="),
            "rego must NOT bake a payload_hash (artifact-server primary resolves at appraisal)\n{rego}"
        );
    }

    /// With NO fallback configured, the Rego omits the `fallback_ok` rule
    /// AND the `measurements_verified if { fallback_ok }` line (carry #1):
    /// referencing an undefined `fallback_ok` would be a Rego eval error.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn artifact_server_primary_without_fallback_omits_fallback_rules() {
        let cfg = serde_json::json!({
            "type":"transparency_log",
            "publishedMeasurements":["container.image.cmaas-runtime"],
            "schemaVersion":"1.0.0",
            "services":[{"type":"artifact-server","url":"https://attest.example.com",
                "logServices":[{"type":"rekor-v1","url":"https://rekor.sigstore.dev"}]}]
        });
        let p: PolicyConfig = serde_json::from_value(cfg).unwrap();
        let encoded = BuiltinCocoConverter::load_policy_as_base64_url_safe_no_pad(&p)
            .await
            .unwrap()
            .expect("policy");
        let rego = String::from_utf8(URL_SAFE_NO_PAD.decode(&encoded).unwrap()).unwrap();
        assert!(
            !rego.contains("fallback_ok"),
            "no-fallback rego must not reference fallback_ok\n{rego}"
        );
        assert!(
            !rego.contains("fallback_manifest"),
            "no-fallback rego must not reference fallback_manifest\n{rego}"
        );
        assert!(
            rego.contains("measurements_verified if { primary_ok }"),
            "no-fallback rego must still define measurements_verified via primary_ok\n{rego}"
        );
    }

    /// Short-circuit verification: when the artifact-server primary
    /// resolves successfully (`primary_ok` true), regorus must NOT evaluate the
    /// `tng.fetch_rekor_on_demand` call in the `fallback_ok` body. Detect any
    /// eager fallback network call with a raw TCP listener: if
    /// `tng.fetch_rekor_on_demand` fires, it opens a TCP connection here and
    /// `fallback_called` becomes true (the host-await's clean-deny then swallows
    /// the connection-reset into `Ok(false)`, so `executables` stays 2 either
    /// way, the listener is what makes the short-circuit observable).
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn branch_b_does_not_call_fallback_when_primary_ok() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use tokio::net::TcpListener;

        // Clear the process-global resolve cache so the artifact-server mock is
        // actually exercised (proves the primary path works end-to-end through
        // the real rego, not just a stale cache hit).
        artifact_server::invalidate_host_await_caches_for_test();

        // Detector listener: any TCP connection here means the fallback
        // host-await was called despite primary_ok being true.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = listener.local_addr().unwrap();
        let fallback_called = Arc::new(AtomicBool::new(false));
        let called_clone = fallback_called.clone();
        tokio::spawn(async move {
            // Accept at most a few connections so a stray retry doesn't block
            // forever; the first accept flips the flag.
            for _ in 0..4 {
                if listener.accept().await.is_ok() {
                    called_clone.store(true, Ordering::SeqCst);
                }
            }
        });

        // Artifact-server mock: resolve success using the evidence fixture (the
        // entry's authenticated payloadHash == sha256(JCS(release_manifest))).
        let server = wiremock::MockServer::start().await;
        let evidence: serde_json::Value = serde_json::from_str(include_str!(
            "tests/fixtures/cmaas_evidence_with_rekor_v1_transparency.json"
        ))
        .unwrap();
        let manifest = evidence["transparency"]["release_manifest"].clone();
        let log_entry = evidence["transparency"]["log_entries"][0]["log_entry"].clone();
        let entry_url = evidence["transparency"]["log_entries"][0]["url"]
            .as_str()
            .unwrap()
            .to_string();
        let resolve_body = serde_json::json!({
            "status": "resolved",
            "release_manifest": manifest,
            "log_entries": [{
                "type": "rekor-v1",
                "url": entry_url,
                "log_entry": log_entry,
                "entry_verifier": {"type": "public_key", "content": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsGjh0eIF22/JwEkRvU5KROvNsL/F\nK6qP/kbKO0CoelOqRKJQuC9z0ruwyx12S94/m69+iaan0SKR1IJjIbbfHw==\n-----END PUBLIC KEY-----"},
                "log_verifier": {"public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\nkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n-----END PUBLIC KEY-----"}
            }]
        })
        .to_string();
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/transparency/resolve"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(resolve_body))
            .mount(&server)
            .await;

        // Build the policy via the real entry point. The fallback
        // log_url points at the detector listener; log_index is arbitrary.
        let cfg_json = serde_json::json!({
            "type":"transparency_log",
            "publishedMeasurements":["container.image.cmaas-runtime"],
            "schemaVersion":"1.0.0",
            "services":[{"type":"artifact-server","url":server.uri(),
                "logServices":[{"type":"rekor-v1","url":entry_url}]}],
            "fallbackPublishedMeasurements":["container.image.cmaas-runtime"],
            "fallbackServices":[{"type":"rekor-v1",
                "logUrl":format!("http://{}",fallback_addr),"logIndex":42}]
        });
        let p: PolicyConfig = serde_json::from_value(cfg_json).unwrap();
        let encoded = BuiltinCocoConverter::load_policy_as_base64_url_safe_no_pad(&p)
            .await
            .unwrap()
            .expect("policy");
        let policy = String::from_utf8(URL_SAFE_NO_PAD.decode(&encoded).unwrap()).unwrap();

        // Rego input: valid non-debug TDX platform + AAEL kangaroo/pull-image
        // event carrying the fixture's measurement digest (the same
        // release_manifest the mock resolves, so the reconstructed
        // `full_manifest` hashes to the entry's authenticated payloadHash).
        let digest = manifest["measurements"][0]["value"]
            .as_str()
            .expect("fixture manifest measurement value");
        let input = format!(
            r#"{{"tdx":{{"quote":{{"header":{{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}},"body":{{"td_attributes":"0000001000000000"}}}},"uefi_event_logs":[{{"type_name":"EV_EVENT_TAG","details":{{"unicode_name":"AAEL","data":{{"domain":"alibabacloud.com","operation":"kangaroo/pull-image","content":{{"reference":"registry.example.com/ns/cmaas-runtime:latest","digest":{digest:?}}}}}}}}}]}}}}"#
        );

        let vec = eval_policy_vector(&policy, &input).await;
        assert_eq!(vec.0, 2, "primary_ok must affirm executables (got {vec:?})");

        // Give the detector task a moment to observe a connection if regorus
        // made one (the host-await's reqwest GET would open the TCP connection
        // before the connection is reset).
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !fallback_called.load(Ordering::SeqCst),
            "tng.fetch_rekor_on_demand must NOT be called when primary_ok is true \
             (regorus left-to-right body short-circuit), but a TCP connection to the \
             fallback listener was observed; regorus eagerly evaluated the fallback \
             host-await (carry #2): switch to a combined host-await"
        );
    }

    /// Load the evidence fixture and extract the matched
    /// `(release_manifest, log_entry, entry_url, log_index)` tuple. The entry's
    /// authenticated `payloadHash` == `sha256(JCS(release_manifest))` ==
    /// `b40611d4...` (verified in `rekor_v1` fixture tests + the e2e), so a
    /// resolve/fetch response built from it exercises real inclusion/checkpoint/SET
    /// crypto and the payloadHash comparison → `true`.
    fn cmaas_transparency_tuple() -> (serde_json::Value, serde_json::Value, String, i64) {
        let evidence: serde_json::Value = serde_json::from_str(include_str!(
            "tests/fixtures/cmaas_evidence_with_rekor_v1_transparency.json"
        ))
        .expect("parse evidence fixture");
        let manifest = evidence["transparency"]["release_manifest"].clone();
        let log_entry = evidence["transparency"]["log_entries"][0]["log_entry"].clone();
        let entry_url = evidence["transparency"]["log_entries"][0]["url"]
            .as_str()
            .expect("entry url")
            .to_string();
        let log_index = log_entry["logIndex"].as_i64().expect("logIndex");
        (manifest, log_entry, entry_url, log_index)
    }

    /// Build a resolve-response JSON body from the fixture pair. The SDK's
    /// `LogEntry` requires non-optional `entry_verifier`/`log_verifier` fields, so
    /// dummy values are supplied; `authenticate_entry` ignores both (the rekor
    /// key is resolved via the entry URL's hostname → built-in sigstore key).
    fn resolve_response_body(
        manifest: &serde_json::Value,
        log_entry: &serde_json::Value,
        entry_url: &str,
    ) -> String {
        // Real response verifiers (response-key path): the impl now USES
        // `entry_verifier.content` (DSSE publisher PEM) and
        // `log_verifier.public_key_pem` (Sigstore rekor PEM) instead of
        // ignoring them. These are the built-in DSSE publisher key and the
        // Sigstore rekor key the fixture carries.
        const LOG_ENTRY_PUB_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsGjh0eIF22/JwEkRvU5KROvNsL/F\nK6qP/kbKO0CoelOqRKJQuC9z0ruwyx12S94/m69+iaan0SKR1IJjIbbfHw==\n-----END PUBLIC KEY-----";
        const SIGSTORE_REKOR_V1_PUB_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\nkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n-----END PUBLIC KEY-----";
        serde_json::json!({
            "status": "resolved",
            "release_manifest": manifest,
            "log_entries": [{
                "type": "rekor-v1",
                "url": entry_url,
                "log_entry": log_entry,
                "entry_verifier": {"type": "public_key", "content": LOG_ENTRY_PUB_KEY_PEM},
                "log_verifier": {"public_key_pem": SIGSTORE_REKOR_V1_PUB_KEY_PEM}
            }]
        })
        .to_string()
    }

    /// Build a rekor-v1 `GET /api/v1/log/entries?logIndex=` response body
    /// (`{uuid: entry}` wire format) from the fixture log_entry.
    fn rekor_entries_body(log_entry: &serde_json::Value) -> String {
        let uuid = "00000000-0000-0000-0000-000000000000";
        serde_json::json!({ uuid: log_entry }).to_string()
    }

    /// Build the TDX rego `input` carrying the fixture's measurement digest
    /// in an AAEL kangaroo/pull-image event, plus valid non-debug TDX platform
    /// evidence. The `full_manifest` Rego reconstructs from this digest hashes to
    /// the entry's authenticated `payloadHash`, so `primary_ok`/`fallback_ok`
    /// can reach `true` when the mock serves the fixture entry.
    fn cmaas_tdx_input(manifest: &serde_json::Value) -> String {
        let digest = manifest["measurements"][0]["value"]
            .as_str()
            .expect("fixture manifest measurement value");
        format!(
            r#"{{"tdx":{{"quote":{{"header":{{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"}},"body":{{"td_attributes":"0000001000000000"}}}},"uefi_event_logs":[{{"type_name":"EV_EVENT_TAG","details":{{"unicode_name":"AAEL","data":{{"domain":"alibabacloud.com","operation":"kangaroo/pull-image","content":{{"reference":"registry.example.com/ns/cmaas-runtime:latest","digest":{digest:?}}}}}}}}}]}}}}"#
        )
    }

    /// Build a policy from the evidence fixture + per-scenario mock URLs.
    /// `published_measurements` = the fixture's cmaas-runtime type; the fallback
    /// rekor service points at the given `fallback_log_url`/`fallback_log_index`.
    async fn build_branch_b_policy(
        artifact_url: &str,
        entry_url: &str,
        fallback_log_url: &str,
        fallback_log_index: i64,
    ) -> String {
        let cfg_json = serde_json::json!({
            "type":"transparency_log",
            "publishedMeasurements":["container.image.cmaas-runtime"],
            "schemaVersion":"1.0.0",
            "services":[{"type":"artifact-server","url":artifact_url,
                "logServices":[{"type":"rekor-v1","url":entry_url}]}],
            "fallbackPublishedMeasurements":["container.image.cmaas-runtime"],
            "fallbackServices":[{"type":"rekor-v1",
                "logUrl":fallback_log_url,"logIndex":fallback_log_index}]
        });
        let p: PolicyConfig = serde_json::from_value(cfg_json).expect("parse cfg");
        p.validate_transparency_config().expect("validate cfg");
        let encoded = BuiltinCocoConverter::load_policy_as_base64_url_safe_no_pad(&p)
            .await
            .expect("encode")
            .expect("policy");
        String::from_utf8(URL_SAFE_NO_PAD.decode(&encoded).unwrap()).unwrap()
    }

    /// End-to-end integration: drive the full policy through the
    /// real regorus evaluator (`eval_policy_vector`, which injects
    /// `builtin_as_host_await_functions()`, `tng.resolve_artifact_server` +
    /// `tng.fetch_rekor_on_demand`) across the three appraisal outcomes:
    ///
    ///  (a) **Primary success**, the artifact-server mock returns a valid
    ///      resolved entry for the evidence's reconstructed manifest →
    ///      `primary_ok` true → `executables == 2` (fallback never fires).
    ///  (b) **Fallback success**, the artifact-server mock returns 500 →
    ///      `primary_ok` false; the fallback rekor mock returns the evidence fixture
    ///      entry by `logIndex` for the fallback manifest → `fallback_ok` true →
    ///      `executables == 2`.
    ///  (c) **Both fail**, artifact-server 500 and fallback rekor 500 →
    ///      `primary_ok` false, `fallback_ok` false → `executables == 97` (deny).
    ///
    /// Each scenario clears the process-global host-await caches
    /// (`invalidate_host_await_caches_for_test`) so a prior scenario's cached
    /// success/failure cannot short-circuit the next (the resolve cache key is
    /// `(manifest_hash, canonical_log_services)`, shared across (a) and (b)
    /// despite different artifact-server URLs).
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    #[serial]
    async fn branch_b_e2e_primary_success_then_fallback_then_deny() {
        let (manifest, log_entry, entry_url, log_index) = cmaas_transparency_tuple();
        let input = cmaas_tdx_input(&manifest);
        let resolve_body = resolve_response_body(&manifest, &log_entry, &entry_url);
        let rekor_body = rekor_entries_body(&log_entry);

        // Fallback points at a dead port; if the primary failed and the
        // short-circuit did not hold, the fallback would fail too → 97. So
        // asserting 2 proves the primary path resolved + authenticated.
        artifact_server::invalidate_host_await_caches_for_test();
        {
            let server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::path("/api/v1/transparency/resolve"))
                .respond_with(
                    wiremock::ResponseTemplate::new(200).set_body_string(resolve_body.clone()),
                )
                .expect(1)
                .mount(&server)
                .await;
            let policy =
                build_branch_b_policy(&server.uri(), &entry_url, "http://127.0.0.1:1", log_index)
                    .await;
            let vec = eval_policy_vector(&policy, &input).await;
            assert_eq!(
                vec.0, 2,
                "primary success must affirm executables (got {vec:?})"
            );
        }

        // Artifact-server returns 500; the fallback rekor mock serves the
        // fixture entry at the fallback logIndex, authenticates, and its
        // payloadHash matches the reconstructed fallback manifest.
        artifact_server::invalidate_host_await_caches_for_test();
        {
            let as_server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::path("/api/v1/transparency/resolve"))
                .respond_with(
                    wiremock::ResponseTemplate::new(500).set_body_string("upstream error"),
                )
                .mount(&as_server)
                .await;
            let rekor_server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/api/v1/log/entries"))
                .and(wiremock::matchers::query_param(
                    "logIndex",
                    log_index.to_string(),
                ))
                .respond_with(
                    wiremock::ResponseTemplate::new(200).set_body_string(rekor_body.clone()),
                )
                .expect(1)
                .mount(&rekor_server)
                .await;
            let policy =
                build_branch_b_policy(&as_server.uri(), &entry_url, &rekor_server.uri(), log_index)
                    .await;
            let vec = eval_policy_vector(&policy, &input).await;
            assert_eq!(
                vec.0, 2,
                "fallback success must affirm executables (got {vec:?})"
            );
        }

        // Artifact-server 500 and fallback rekor 500: primary_ok false,
        // fallback_ok false → `measurements_verified` undefined → executables
        // stays at its contraindicated default (97).
        artifact_server::invalidate_host_await_caches_for_test();
        {
            let as_server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::path("/api/v1/transparency/resolve"))
                .respond_with(
                    wiremock::ResponseTemplate::new(500).set_body_string("upstream error"),
                )
                .mount(&as_server)
                .await;
            let rekor_server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/api/v1/log/entries"))
                .and(wiremock::matchers::query_param(
                    "logIndex",
                    log_index.to_string(),
                ))
                .respond_with(wiremock::ResponseTemplate::new(500).set_body_string("rekor down"))
                .mount(&rekor_server)
                .await;
            let policy =
                build_branch_b_policy(&as_server.uri(), &entry_url, &rekor_server.uri(), log_index)
                    .await;
            let vec = eval_policy_vector(&policy, &input).await;
            assert_eq!(vec.0, 97, "both-fail must deny executables (got {vec:?})");
        }
    }

    /// Config parity: the exact artifact-server + fallback example from the
    /// secure-proxy README (wrapped in `PolicyConfig::TransparencyLog`
    /// top-level shape) must parse into `PolicyConfig`, pass
    /// `validate_transparency_config`, and round-trip (serialize → parse →
    /// Debug-equal). Pins wire compatibility between the secure-proxy config
    /// writer and the tng `PolicyConfig` schema (Tasks 1–6).
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn secure_proxy_readme_json_round_trips() {
        let json = std::fs::read_to_string(
            "src/tee/coco/converter/builtin/tests/fixtures/secure_proxy_artifact_server_config.json",
        )
        .expect("read fixture");
        let p: PolicyConfig = serde_json::from_str(&json).expect("parse into PolicyConfig");
        p.validate_transparency_config()
            .expect("validate_transparency_config succeeds");
        let round = serde_json::to_string(&p).expect("serialize");
        let p2: PolicyConfig = serde_json::from_str(&round).expect("re-parse");
        assert_eq!(
            format!("{p:?}"),
            format!("{p2:?}"),
            "PolicyConfig must round-trip (serialize → parse → Debug-equal)"
        );
    }

    /// Lines 714-716: when the primary service is `RekorV1` but `services`
    /// contains MORE than one element (e.g. two RekorV1 services),
    /// `load_policy_as_base64_url_safe_no_pad` rejects with "requires exactly
    /// one rekor-v1 service". The error fires BEFORE any network fetch, so no
    /// mock is needed. `validate_transparency_config` passes (each service is
    /// individually valid), but the dispatch arm's structural check catches
    /// the multi-service case.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn load_policy_rejects_multiple_rekor_v1_services() {
        let cfg = serde_json::json!({
            "type":"transparency_log",
            "publishedMeasurements":["tdx.td-shim"],
            "schemaVersion":"1.0.0",
            "services":[
                {"type":"rekor-v1","logUrl":"https://rekor.sigstore.dev","logIndex":1},
                {"type":"rekor-v1","logUrl":"https://rekor.sigstore.dev","logIndex":2}
            ]
        });
        let p: PolicyConfig = serde_json::from_value(cfg).unwrap();
        // Validation passes; each service is individually valid.
        p.validate_transparency_config().unwrap();
        // But the dispatch arm rejects the multi-service case (no network).
        let err = BuiltinCocoConverter::load_policy_as_base64_url_safe_no_pad(&p)
            .await
            .unwrap_err();
        match err {
            Error::TransparencyLogFetchFailed(inner) => assert!(
                inner
                    .to_string()
                    .contains("requires exactly one rekor-v1 service"),
                "got: {inner}"
            ),
            _ => panic!("wrong error variant: {err:?}"),
        }
    }

    /// Lines 1400-1402: `build_artifact_server_policy` rejects a
    /// non-rekor-v1 entry in `fallback_services`. These are
    /// `bail!` arms behind upstream `validate_transparency_config`, but the
    /// function is callable directly (e.g. from future callers that bypass
    /// validation), so the bounds check is intentional defense-in-depth.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn build_artifact_server_policy_rejects_non_rekor_v1_fallback() {
        let bad_fallback = vec![TransparencyServiceConfig::ArtifactServer {
            url: "https://x".to_string(),
            log_services: vec![],
            publisher_public_key_pem: None,
        }];
        let err = build_artifact_server_policy(
            "1.0.0",
            Some(&["tdx.td-shim".to_string()]),
            "https://as.example.com",
            &[ArtifactLogService {
                type_: "rekor-v1".to_string(),
                url: "https://rekor.sigstore.dev".to_string(),
            }],
            None,
            Some(&["tdx.td-shim".to_string()]),
            Some(&bad_fallback),
        )
        .unwrap_err();
        match err {
            Error::TransparencyLogFetchFailed(inner) => assert!(
                inner
                    .to_string()
                    .contains("fallbackServices must contain only rekor-v1"),
                "got: {inner}"
            ),
            _ => panic!("wrong error variant: {err:?}"),
        }
    }

    /// Lines 1405-1407: `build_artifact_server_policy` rejects an empty
    /// `fallback_services` slice (the `None` arm of `fs.first()`).
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn build_artifact_server_policy_rejects_empty_fallback() {
        let empty_fallback: Vec<TransparencyServiceConfig> = vec![];
        let err = build_artifact_server_policy(
            "1.0.0",
            Some(&["tdx.td-shim".to_string()]),
            "https://as.example.com",
            &[ArtifactLogService {
                type_: "rekor-v1".to_string(),
                url: "https://rekor.sigstore.dev".to_string(),
            }],
            None,
            Some(&["tdx.td-shim".to_string()]),
            Some(&empty_fallback),
        )
        .unwrap_err();
        match err {
            Error::TransparencyLogFetchFailed(inner) => assert!(
                inner.to_string().contains("fallbackServices is empty"),
                "got: {inner}"
            ),
            _ => panic!("wrong error variant: {err:?}"),
        }
    }
}

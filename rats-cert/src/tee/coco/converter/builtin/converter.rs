//! The builtin CoCo converter: an in-process attestation-service instance.

use std::sync::Arc;

use attestation_service::{AttestationService, HashAlgorithm, Tee};

use super::super::super::evidence::{AttestationServiceHashAlgo, CocoAsToken, CocoEvidence};
use super::super::convert_additional_evidence;
use super::host_fns::builtin_as_host_await_functions;
use super::policy_config::{PolicyConfig, ReferenceValueConfig};
use super::signer::SelfSignedSigner;
use super::DEFAULT_POLICY_ID;
use crate::errors::*;
use crate::tee::coco::converter::CoCoNonce;
use crate::tee::coco::verifier::builtin::BuiltinCocoVerifier;
use crate::tee::GenericConverter;

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
        // These policies' verification rules never consume reference values,
        // so a non-empty external `reference_values` list would be silently
        // inert. Supplying one is a configuration error, rejected before any
        // state is built.
        if !reference_values.is_empty() {
            if let Some(policy_name) = Self::policy_without_reference_values(policy) {
                return Err(Error::BuiltinPolicyTemplateFailed(anyhow::anyhow!(
                    "attestation_policy \"{policy_name}\" does not accept external reference_values: its verification rules do not consume them"
                )));
            }
        }

        // Create AttestationService instance
        let (self_signed_signer, mut attestation_service) = {
            let self_signed_signer = Arc::new(SelfSignedSigner::new()?);

            let rvps = Arc::new(attestation_service::rvps::builtin::BuiltinRvps::new(
                reference_value_provider_service::config::Config {
                    // Only the standalone RVPS binary uses the shared storage
                    // backend; the builtin instance is in-memory.
                    storage_backend: None,
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

        // Install the configured policy. Every variant now yields one: the
        // bundled templates are embedded, `modules` generates Rego, and
        // `inline`/`path` pass user content through.
        if let Some(policy_content) = super::policies::load_policy(policy).await? {
            attestation_service
                .set_policy(DEFAULT_POLICY_ID.to_string(), policy_content)
                .await
                .map_err(Error::AttestationServiceSetPolicyFailed)?;
        }

        // Load reference values
        super::reference_values::load_reference_values(&mut attestation_service, reference_values)
            .await?;

        Ok(Self {
            self_signed_signer,
            attestation_service,
            #[cfg(test)]
            skip_runtime_data_check: false,
        })
    }

    /// Short policy name used in configuration errors, for the variants whose
    /// verification rules do not consume reference values. `inline` and `path`
    /// may read them, so they return `None`.
    fn policy_without_reference_values(policy: &PolicyConfig) -> Option<&'static str> {
        match policy {
            PolicyConfig::HardwareOnly => Some("hardware_only"),
            PolicyConfig::HardwareOnlyStrict => Some("hardware_only_strict"),
            PolicyConfig::TrustAll => Some("trust_all"),
            PolicyConfig::Modules { .. } => Some("modules"),
            PolicyConfig::Inline { .. } => None,
            #[cfg(not(wasm))]
            PolicyConfig::Path { .. } => None,
        }
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

        // Evaluate evidence. If a TdxCollateral extension is present, use
        // evaluate_with_collateral so the verifier skips PCCS fetch.
        let dcap_collateral = in_evidence.extensions_ref().as_ref().and_then(|exts| {
            exts.iter()
                .map(|e| match e {
                    crate::tee::coco::evidence::EvidenceExtension::TdxCollateral(v) => v,
                })
                .next()
        });
        let token = if let Some(collateral) = dcap_collateral {
            self.attestation_service
                .evaluate_with_collateral(
                    verification_requests,
                    vec![DEFAULT_POLICY_ID.to_owned()],
                    collateral,
                )
                .await
                .map_err(Error::AttestationServiceVerifyFailed)?
        } else {
            self.attestation_service
                .evaluate(verification_requests, vec![DEFAULT_POLICY_ID.to_owned()])
                .await
                .map_err(Error::AttestationServiceVerifyFailed)?
        };

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

#[cfg(test)]
mod tests {
    use super::super::policy_config::{
        ModuleGroupsConfig, SampleProvenancePayloadConfig, SlsaReferenceValuePayloadConfig,
    };
    use super::*;
    use base64::Engine;
    use reference_value_provider_service::extractors::extractor_modules::sample::Provenance;
    use reference_value_provider_service::rv_list::{
        ReferenceValueListItem, ReferenceValueListPayload, ReferenceValueProvenanceInfo,
        ReferenceValueProvenanceSource,
    };
    use serde_json::json;
    use serial_test::serial;

    /// A non-empty external reference value, used to exercise the
    /// construction-time rejection.
    fn sample_reference() -> ReferenceValueConfig {
        let mut rvs = std::collections::HashMap::new();
        rvs.insert("example-measurement".to_string(), json!([]));
        ReferenceValueConfig::Sample {
            payload: SampleProvenancePayloadConfig::Inline {
                content: Provenance { rvs },
            },
        }
    }

    /// A user-supplied `inline` policy: its rego may consume reference values,
    /// so construction keeps accepting a non-empty `reference_values` list.
    fn accepting_policy() -> PolicyConfig {
        PolicyConfig::Inline {
            content: base64::engine::general_purpose::STANDARD.encode(
                "package policy\n\ndefault executables := 3\ndefault hardware := 2\ndefault configuration := 2\ndefault file_system := 2",
            ),
        }
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
        let result = BuiltinCocoConverter::new(&accepting_policy(), &[reference]).await;
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
        BuiltinCocoConverter::new(&accepting_policy(), &[reference])
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
        BuiltinCocoConverter::new(&accepting_policy(), &[reference])
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
        BuiltinCocoConverter::new(&accepting_policy(), &[reference])
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
        BuiltinCocoConverter::new(&accepting_policy(), &[reference])
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
        let result = BuiltinCocoConverter::new(&accepting_policy(), &references).await;
        assert!(
            result.is_ok(),
            "Failed with multiple references: {:?}",
            result.err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_with_empty_references() {
        BuiltinCocoConverter::new(&PolicyConfig::HardwareOnly, &[])
            .await
            .expect("Failed with empty references");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_rejects_reference_values_for_policies_that_ignore_them() {
        let cases = [
            (PolicyConfig::TrustAll, "trust_all"),
            (PolicyConfig::HardwareOnly, "hardware_only"),
            (PolicyConfig::HardwareOnlyStrict, "hardware_only_strict"),
            (
                PolicyConfig::Modules {
                    modules: ModuleGroupsConfig::Single(Vec::new()),
                },
                "modules",
            ),
        ];
        for (policy, policy_name) in cases {
            let err = match BuiltinCocoConverter::new(&policy, &[sample_reference()]).await {
                Ok(_) => panic!("{policy_name}: non-empty reference_values must be rejected"),
                Err(e) => e,
            };
            let debug = format!("{err:?}");
            assert!(
                debug.contains("does not accept external reference_values"),
                "{policy_name}: {debug}"
            );
            assert!(
                err.to_string()
                    .contains(&format!("attestation_policy \"{policy_name}\"")),
                "{policy_name}: {debug}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_accepts_empty_reference_values_for_policies_that_ignore_them() {
        let policies = [
            PolicyConfig::HardwareOnly,
            PolicyConfig::HardwareOnlyStrict,
            PolicyConfig::TrustAll,
            PolicyConfig::Modules {
                modules: ModuleGroupsConfig::Single(Vec::new()),
            },
        ];
        for policy in policies {
            BuiltinCocoConverter::new(&policy, &[])
                .await
                .expect("empty reference_values must be accepted");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_accepting_policy_keeps_loading_reference_values() {
        BuiltinCocoConverter::new(&accepting_policy(), &[sample_reference()])
            .await
            .expect("inline policy must keep accepting reference values");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_converter_new_error_sample_path_not_found() {
        let reference = ReferenceValueConfig::Sample {
            payload: SampleProvenancePayloadConfig::Path {
                path: "/nonexistent/reference_values.json".to_string(),
            },
        };
        let result = BuiltinCocoConverter::new(&accepting_policy(), &[reference]).await;
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
            let converter = BuiltinCocoConverter::new(&PolicyConfig::HardwareOnly, &[])
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
            // A modules policy pinning a boot measurement to a dummy value that
            // real hardware never matches: the appraisal stays non-affirming, so
            // the verifier rejects the token (the assertion below). The removed
            // `hardware_with_reference_values` policy achieved the same by
            // appraising against (empty) registered reference values.
            let policy: PolicyConfig = serde_json::from_str(
            r#"{"type":"modules","modules":[{"type":"tdx.ovmf","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#,
        )
        .expect("modules policy parses");
            let converter = BuiltinCocoConverter::new(&policy, &[])
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
}

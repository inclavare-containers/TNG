//! Host-await extension functions and DSSE helpers injected into the
//! builtin attestation service's OPA engine.

use super::transparency::{artifact_server, dsse};

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

/// DSSE payload type for the ReleaseManifest signatures. Hardcoded to the
/// release-manifest payload type
/// `application/vnd.alibabacloud.confidential-computing.release+json`
/// (the `payloadType` the publisher signs over).
pub(crate) use dsse::{dsse_pae, DSSE_PAYLOAD_TYPE};

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
            let verified = dsse::verify_publisher_signature(
                key_pem.as_ref(),
                payload.as_bytes(),
                sig_b64.as_ref(),
            )
            .is_ok();
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
pub(crate) fn builtin_as_host_await_functions() -> Vec<(
    String,
    attestation_service::policy_engine::opa::ExtensionFunction,
)> {
    let mut fns = vec![("tng.sha256".to_string(), crypto_sha256_host_await())];
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

    // The `tng.verify_dsse_signature` registration this test asserts is gated
    // on `crypto-rustcrypto`; `tng.sha256` (always registered) is still
    // checked under the same gate when crypto is on.
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
}

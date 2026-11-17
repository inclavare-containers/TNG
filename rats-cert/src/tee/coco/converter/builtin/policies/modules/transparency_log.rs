//! The `transparency_log` module entry: config validation and Rego fragments.
//! The rekor-v1 and artifact-server services live in `builtin/transparency`.

use super::super::super::policy_config::{TransparencyLogEntryConfig, TransparencyServiceConfig};
use super::super::super::transparency::AuthenticatedRekor;

/// Render the Rego that reconstructs one ReleaseManifest and binds it to
/// `name`.
///
/// Each configured type contributes one ordered entry array. A non-image type
/// is a single `{"type", "value"}` entry; a container image type expands to one
/// entry per observed digest, sorted ascending. Types are rendered in the order
/// given (the caller sorts them), so concatenating the per-type arrays keeps
/// the whole `measurements` array in `(type, value)` order, which is the
/// canonical form the publisher signs.
///
/// The literal/rule form is what makes a missing extraction structurally
/// fail-closed: an undefined extraction makes its per-type array undefined, and
/// `array.concat` propagates that, so the assembled manifest is undefined too.
/// A comprehension over the per-type arrays could instead silently drop the
/// missing type.
fn manifest_rules(types: &[String], schema_expr: &str, name: &str) -> String {
    let mut entry_arrays: Vec<String> = Vec::new();
    let mut rules = String::new();
    for (index, measurement_type) in types.iter().enumerate() {
        let entry_name = format!("{name}_entries_{index}");
        if measurement_type.starts_with("container.image.") {
            rules.push_str(&format!(
                "{entry_name} := entries if {{\n\
                 \tdigests := sort(actual_measurement_set({measurement_type:?}))\n\
                 \tentries := [{{\"type\": {measurement_type:?}, \"value\": d}} | some d in digests]\n\
                 }}\n\n"
            ));
        } else {
            rules.push_str(&format!(
                "{entry_name} := [{{\"type\": {measurement_type:?}, \"value\": actual_measurement({measurement_type:?})}}]\n\n"
            ));
        }
        entry_arrays.push(entry_name);
    }
    let measurements = entry_arrays
        .iter()
        .cloned()
        .reduce(|acc, entries| format!("array.concat({acc}, {entries})"))
        .unwrap_or_else(|| "[]".to_string());
    rules.push_str(&format!(
        "{name} := {{\n\t\"measurements\": {measurements},\n\t\"schemaVersion\": {schema_expr},\n}}\n"
    ));
    rules
}

/// Render the Rego rules for one `transparency_log` module entry.
///
/// `pred` is the entry predicate the modules builder ANDs into its group, and
/// `prefix` namespaces every global identifier the entry defines so several
/// entries coexist in one policy. A rekor-v1 primary expects `resolved` to
/// carry the data fetched and authenticated at load; an artifact-server primary
/// resolves its manifest at appraisal time and ignores `resolved`.
pub(super) fn build_entry_rules(
    cfg: &TransparencyLogEntryConfig,
    resolved: Option<&AuthenticatedRekor>,
    pred: &str,
    prefix: &str,
) -> anyhow::Result<String> {
    let primary = cfg
        .services
        .first()
        .ok_or_else(|| anyhow::anyhow!("services must be non-empty"))?;
    let mut sorted_pm = cfg.published_measurements.clone();
    sorted_pm.sort();
    let schema_expr = format!("{prefix}_schema_version");

    match primary {
        TransparencyServiceConfig::RekorV1 { .. } => {
            let resolved = resolved.ok_or_else(|| {
                anyhow::anyhow!("rekor-v1 transparency_log entry was not resolved")
            })?;
            let manifest = manifest_rules(
                &sorted_pm,
                &schema_expr,
                &format!("{prefix}_reconstructed_manifest"),
            );
            Ok(format!(
                r#"# transparency_log entry: rekor-v1 primary, payloadHash + DSSE baked at load
{prefix}_payload_hash := {payload_hash:?}
{prefix}_schema_version := {schema_version:?}
# baked: DSSE publisher signature + trusted publisher public key
{prefix}_dsse_signature := {dsse_signature:?}
{prefix}_publisher_key := {publisher_key:?}

# reconstruct the manifest object (rego object keys serialize sorted == ASCII
# JCS; json.marshal is compact; no numbers in this shape). Each type's entry
# array is undefined when its extraction is, so a missing measurement leaves
# the whole manifest undefined instead of silently dropping an entry.
{manifest}
# The transparency-log manifest check and the mandatory DSSE publisher
# binding. Any mismatch leaves the entry predicate undefined (fail-closed).
{pred} if {{
    tng.sha256(json.marshal({prefix}_reconstructed_manifest)) == {prefix}_payload_hash
    tng.verify_dsse_signature([json.marshal({prefix}_reconstructed_manifest), {prefix}_dsse_signature, {prefix}_publisher_key]) == true
}}

"#,
                prefix = prefix,
                payload_hash = resolved.payload_hash,
                schema_version = cfg.schema_version,
                manifest = manifest,
                dsse_signature = resolved.dsse_signature,
                publisher_key = resolved.publisher_key,
                pred = pred,
            ))
        }
        TransparencyServiceConfig::ArtifactServer {
            url,
            log_services,
            publisher_public_key_pem,
        } => {
            let manifest =
                manifest_rules(&sorted_pm, &schema_expr, &format!("{prefix}_full_manifest"));
            let url_lit = serde_json::to_string(url)?;
            let ls_lit = serde_json::to_string(log_services)?;
            // Bake the configured publisher key, or empty string when none is
            // set; the host-await treats empty as "use the built-in publisher
            // key", so baking "" preserves the default path.
            let publisher_key_lit = serde_json::to_string(
                publisher_public_key_pem
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(""),
            )?;

            let (fallback_lit, fallback_rules) = match (
                &cfg.fallback_published_measurements,
                &cfg.fallback_services,
            ) {
                (Some(fpm), Some(fs)) => {
                    let (log_url, log_index) = match fs.first() {
                        Some(TransparencyServiceConfig::RekorV1 {
                            log_url, log_index, ..
                        }) => (log_url, *log_index),
                        Some(_) => {
                            anyhow::bail!("fallbackServices must contain only rekor-v1 services")
                        }
                        None => anyhow::bail!("fallbackServices is empty"),
                    };
                    let mut fpm_sorted = fpm.clone();
                    fpm_sorted.sort();
                    let fallback_manifest = manifest_rules(
                        &fpm_sorted,
                        &schema_expr,
                        &format!("{prefix}_fallback_manifest"),
                    );
                    (
                        format!(
                            "\n{prefix}_fallback_log_url := {log_url:?}\n\
                                 {prefix}_fallback_log_index := {log_index}\n"
                        ),
                        format!(
                            r#"
{fallback_manifest}
{pred} if {{
    {prefix}_primary_status == "fail"
    tng.fetch_rekor_on_demand([{prefix}_fallback_log_url, {prefix}_fallback_log_index, json.marshal({prefix}_fallback_manifest), {prefix}_publisher_key]) == true
}}
"#
                        ),
                    )
                }
                _ => (String::new(), String::new()),
            };

            Ok(format!(
                r#"# transparency_log entry: artifact-server primary, resolved at appraisal
{prefix}_schema_version := {schema_version:?}
{prefix}_artifact_server_url := {url_lit}
{prefix}_log_services := {ls_lit}
# baked: configured publisher key PEM (empty string → host-await uses the
# built-in publisher key baseline)
{prefix}_publisher_key := {publisher_key_lit}{fallback_lit}

{manifest}
# A missing measurement makes the full manifest undefined. Map that to "fail"
# (not "deny") so the configured fallback baseline is still consulted; a real
# revocation resolves to "deny" and never falls back.
{prefix}_primary_status := "fail" if {{
    not {prefix}_full_manifest
}}

{prefix}_primary_status := tng.resolve_artifact_server([{prefix}_artifact_server_url, json.marshal({prefix}_full_manifest), json.marshal({prefix}_log_services), {prefix}_publisher_key]) if {{
    {prefix}_full_manifest
}}

{pred} if {{ {prefix}_primary_status == "ok" }}
{fallback_rules}"#,
                prefix = prefix,
                schema_version = cfg.schema_version,
                url_lit = url_lit,
                ls_lit = ls_lit,
                publisher_key_lit = publisher_key_lit,
                fallback_lit = fallback_lit,
                fallback_rules = fallback_rules,
                manifest = manifest,
                pred = pred,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::super::test_fixtures::{
        self, aael_event, hex64, hex96, jcs_compact, manifest, rekor_entry_value, tdx_input,
        tdx_quote_input, transparency_entry,
    };
    #[cfg(feature = "crypto-rustcrypto")]
    use super::super::super::test_harness::resolved_from_manifest;
    use super::super::super::test_harness::{
        eval_policy_vector, render_modules_json as render, render_rekor,
    };
    use super::*;
    use crate::tee::coco::converter::builtin::policy_config::ArtifactLogService;
    use crate::tee::coco::converter::builtin::transparency::dsse;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    use serde_json::{json, Value};

    /// The generated Rego is the artifact the AS loads, so the structural
    /// guarantees behavior cannot observe directly stay pinned here. Semantics
    /// are covered by the equivalence corpus.
    #[test]
    fn transparency_log_rego_shape_contract() {
        let resolved = [
            Some(AuthenticatedRekor {
                payload_hash: "00".repeat(32),
                dsse_signature: "sig-a".to_string(),
                publisher_key: "key-a".to_string(),
            }),
            Some(AuthenticatedRekor {
                payload_hash: "11".repeat(32),
                dsse_signature: "sig-b".to_string(),
                publisher_key: "key-b".to_string(),
            }),
        ];
        let policy = render(
            json!([
                transparency_entry(rekor_entry_value(
                    &["tdx.td-shim", "rootfs.cc", "container.image.cmaas-runtime"],
                    1
                )),
                transparency_entry(rekor_entry_value(&["tdx.kernel", "rootfs.cc"], 2)),
            ]),
            &resolved,
        );

        // Per-entry prefixes keep the two entries' baked data apart.
        assert!(policy.contains("t_0_0_payload_hash := "), "{policy}");
        assert!(policy.contains("t_0_1_payload_hash := "), "{policy}");

        // The shared extraction is emitted once per family for the whole
        // policy, and each needed helper once.
        for rule in [
            "actual_measurement(\"tdx.td-shim\") :=",
            "actual_measurement(\"tdx.kernel\") :=",
            "actual_measurement(\"rootfs.cc\") :=",
            "actual_measurement_set(type) :=",
            "image_repo_name(ref) :=",
            "has_sha384_digest(e) if {",
        ] {
            assert_eq!(
                policy.matches(rule).count(),
                1,
                "rule {rule:?} must be emitted once"
            );
        }

        // The single-value image extraction and the removed reference-value
        // and blob-length helpers never appear.
        assert!(!policy.contains("actual_measurement(type) :="), "{policy}");
        assert!(!policy.contains("query_reference_value"));
        assert!(!policy.contains("td_payload_blob_length"), "{policy}");
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_rejects_wrong_schema_version() {
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let ok = tdx_input(&[aael_event(digest)]);

        // Correct schema version -> affirm.
        let correct = manifest("1.0.0", &[("container.image.cmaas-runtime", digest)]);
        let policy = render_rekor(
            &["container.image.cmaas-runtime"],
            &resolved_from_manifest(&correct),
        );
        assert_eq!(eval_policy_vector(&policy, &ok).await, (2, 2, 2, 2));

        // The logged manifest carries "9.9.9" while the entry config bakes
        // "1.0.0": the reconstruction differs -> reject.
        let wrong = manifest("9.9.9", &[("container.image.cmaas-runtime", digest)]);
        let policy = render_rekor(
            &["container.image.cmaas-runtime"],
            &resolved_from_manifest(&wrong),
        );
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (97, 2, 2, 2),
            "mismatched schemaVersion must reject executables"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_rejects_wrong_payload_hash() {
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let logged = manifest("1.0.0", &[("container.image.cmaas-runtime", digest)]);
        let ok = tdx_input(&[aael_event(digest)]);

        let policy = render_rekor(
            &["container.image.cmaas-runtime"],
            &resolved_from_manifest(&logged),
        );
        assert_eq!(eval_policy_vector(&policy, &ok).await, (2, 2, 2, 2));

        let mut wrong = resolved_from_manifest(&logged);
        wrong.payload_hash = "00".repeat(32);
        let policy = render_rekor(&["container.image.cmaas-runtime"], &wrong);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (97, 2, 2, 2),
            "wrong payloadHash must reject executables"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_sorts_published_measurements_by_type() {
        let cmaas_digest =
            "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let mr_td = "321ab9904f6ca6de72a3163b02143624600dbc368fdfd1d9adffd5f97b8b95a74a1e5975a9df5a3471849bd6f9b83fec";
        // The type-sorted manifest (the publisher's canonical form): the
        // runtime type sorts before td-shim (c < t).
        let logged = manifest(
            "1.0.0",
            &[
                ("container.image.cmaas-runtime", cmaas_digest),
                ("tdx.td-shim", mr_td),
            ],
        );
        let resolved = resolved_from_manifest(&logged);
        let ok = tdx_quote_input(Some(mr_td), "0000001000000000", &[aael_event(cmaas_digest)]);

        for order in [
            ["container.image.cmaas-runtime", "tdx.td-shim"],
            ["tdx.td-shim", "container.image.cmaas-runtime"],
        ] {
            let policy = render_rekor(&order, &resolved);
            assert_eq!(
                eval_policy_vector(&policy, &ok).await,
                (2, 2, 2, 2),
                "measurement order {order:?} must affirm (types are sorted before hashing)"
            );
        }

        let mut wrong = resolved.clone();
        wrong.payload_hash = "00".repeat(32);
        let policy = render_rekor(&["container.image.cmaas-runtime", "tdx.td-shim"], &wrong);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (97, 2, 2, 2),
            "wrong payloadHash must reject even when the order is sorted"
        );
    }

    #[tokio::test]
    async fn manifest_rules_order_entries_by_type_then_value() {
        let digest_a = format!("sha256:{}", hex64('a'));
        let digest_b = format!("sha256:{}", hex64('b'));
        let mr_td = hex96('c');
        // The caller passes types in ascending order; the image digests are
        // deliberately handed over as an unordered set.
        let types = vec![
            "container.image.runtime".to_string(),
            "tdx.td-shim".to_string(),
        ];
        let rules = manifest_rules(&types, "\"1.0.0\"", "test_manifest");
        let expected = jcs_compact(&json!({
            "measurements": [
                {"type": "container.image.runtime", "value": digest_a},
                {"type": "container.image.runtime", "value": digest_b},
                {"type": "tdx.td-shim", "value": mr_td},
            ],
            "schemaVersion": "1.0.0",
        }));
        let policy = format!(
            "package policy\n\nimport rego.v1\n\ndefault executables := 97\ndefault hardware := 2\ndefault configuration := 2\ndefault file_system := 2\n\n\
             actual_measurement_set(type) := {{\"{digest_b}\", \"{digest_a}\"}} if {{\n\tstartswith(type, \"container.image.\")\n}}\n\
             actual_measurement(\"tdx.td-shim\") := \"{mr_td}\"\n\n\
             {rules}\nexecutables := 2 if {{\n\tjson.marshal(test_manifest) == {expected:?}\n}}\n"
        );
        assert_eq!(
            eval_policy_vector(&policy, "{}").await,
            (2, 2, 2, 2),
            "the assembled manifest must equal the (type, value)-ordered JCS form"
        );

        // A type whose extraction is undefined must leave the manifest
        // undefined instead of contributing an empty array.
        let undefined_rules = manifest_rules(&["tdx.kernel".to_string()], "\"1.0.0\"", "m");
        let undefined_policy = format!(
            "package policy\n\nimport rego.v1\n\ndefault executables := 97\ndefault hardware := 2\ndefault configuration := 2\ndefault file_system := 2\n\n\
             actual_measurement(\"tdx.kernel\") := v if {{\n\tv := input.missing\n}}\n\n\
             {undefined_rules}\nexecutables := 2 if {{\n\tjson.marshal(m)\n}}\n"
        );
        assert_eq!(
            eval_policy_vector(&undefined_policy, "{}").await,
            (97, 2, 2, 2),
            "an undefined extraction must make the whole manifest undefined"
        );
    }

    /// Red-green regression: a declared type that neither the signed manifest
    /// nor the evidence carries must reject. With an array comprehension the
    /// undefined extraction was silently dropped and the shrunken manifest
    /// still matched `payloadHash`; the literal manifest makes it undefined.
    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_rejects_declared_type_missing_from_manifest() {
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        // The publisher signed a manifest that omits the declared tdx.kernel.
        let logged = manifest("1.0.0", &[("container.image.cmaas-runtime", digest)]);
        let policy = render_rekor(
            &["tdx.kernel", "container.image.cmaas-runtime"],
            &resolved_from_manifest(&logged),
        );

        // The evidence carries only the image event: tdx.kernel extracts to
        // undefined, so the whole reconstructed manifest is undefined.
        let input = tdx_input(&[aael_event(digest)]);
        assert_eq!(
            eval_policy_vector(&policy, &input).await,
            (97, 2, 2, 2),
            "a declared type missing from both the signed manifest and the evidence must reject"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_requires_valid_dsse_signature() {
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let logged = manifest("1.0.0", &[("container.image.cmaas-runtime", digest)]);
        let ok = tdx_input(&[aael_event(digest)]);

        let resolved = resolved_from_manifest(&logged);
        let policy = render_rekor(&["container.image.cmaas-runtime"], &resolved);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "matching manifest with a valid DSSE signature must affirm"
        );

        // A signature that does not verify rejects even though the payloadHash
        // still matches: DSSE verification is mandatory.
        let mut bad_signature = resolved.clone();
        bad_signature.dsse_signature = BASE64_STANDARD.encode([0u8; 64]);
        let policy = render_rekor(&["container.image.cmaas-runtime"], &bad_signature);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (97, 2, 2, 2),
            "invalid DSSE signature must reject executables"
        );

        // A different valid P-256 publisher key rejects even though the
        // payloadHash matches (publisher-identity binding).
        let mut wrong_key = resolved;
        wrong_key.publisher_key = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n\
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n\
-----END PUBLIC KEY-----\n"
            .to_string();
        let policy = render_rekor(&["container.image.cmaas-runtime"], &wrong_key);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (97, 2, 2, 2),
            "wrong publisher key must reject even when the payloadHash matches"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_rekor_dsse_verifies_against_builtin_publisher_key() {
        // Extract the real DSSE signature from the fixture entry.
        let entry_raw = test_fixtures::REKOR_V1_ENTRY_JSON;
        let entry: Value = serde_json::from_str(entry_raw).expect("parse fixture");
        let body_bytes = BASE64_STANDARD
            .decode(entry["body"].as_str().expect("body"))
            .expect("decode entry body");
        let body: Value = serde_json::from_slice(&body_bytes).expect("parse body");
        let dsse_signature = body["spec"]["signatures"][0]["signature"]
            .as_str()
            .expect("signature")
            .to_string();

        let payload_hash = "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8";
        let digest = "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46";
        let ok = tdx_input(&[aael_event(digest)]);

        // Built-in key + real signature -> DSSE verifies -> affirm.
        let mut resolved = AuthenticatedRekor {
            payload_hash: payload_hash.to_string(),
            dsse_signature: dsse_signature.clone(),
            publisher_key: dsse::BUILTIN_LOG_ENTRY_PUB_KEY_PEM.to_string(),
        };
        let policy = render_rekor(&["container.image.cmaas-runtime"], &resolved);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (2, 2, 2, 2),
            "built-in publisher key + real DSSE signature must affirm"
        );

        // A bogus signature with the built-in key rejects.
        resolved.dsse_signature = BASE64_STANDARD.encode([0u8; 64]);
        let policy = render_rekor(&["container.image.cmaas-runtime"], &resolved);
        assert_eq!(
            eval_policy_vector(&policy, &ok).await,
            (97, 2, 2, 2),
            "wrong DSSE signature must reject against the built-in publisher key"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn transparency_log_artifact_server_rejects_defensive_fallback_shapes() {
        let log_services = vec![ArtifactLogService {
            type_: "rekor-v1".to_string(),
            url: "https://rekor.sigstore.dev".to_string(),
        }];
        let primary = TransparencyServiceConfig::ArtifactServer {
            url: "https://x".to_string(),
            log_services,
            publisher_public_key_pem: None,
        };
        let base = TransparencyLogEntryConfig {
            published_measurements: vec!["tdx.td-shim".to_string()],
            schema_version: "1.0.0".to_string(),
            services: vec![primary],
            fallback_published_measurements: Some(vec!["tdx.td-shim".to_string()]),
            fallback_services: None,
        };

        // A non-rekor-v1 fallback service is rejected even when validation is
        // bypassed (defense in depth for direct callers).
        let mut cfg = base.clone();
        cfg.fallback_services = Some(vec![TransparencyServiceConfig::ArtifactServer {
            url: "https://x2".to_string(),
            log_services: vec![],
            publisher_public_key_pem: None,
        }]);
        let err = build_entry_rules(&cfg, None, "m_0_0", "t_0_0").unwrap_err();
        assert!(
            err.to_string()
                .contains("fallbackServices must contain only rekor-v1"),
            "{err}"
        );

        // An empty fallback service list is rejected.
        let mut cfg = base;
        cfg.fallback_services = Some(vec![]);
        let err = build_entry_rules(&cfg, None, "m_0_0", "t_0_0").unwrap_err();
        assert!(
            err.to_string().contains("fallbackServices is empty"),
            "{err}"
        );
    }
}

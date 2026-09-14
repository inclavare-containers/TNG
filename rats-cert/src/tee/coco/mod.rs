#[cfg(feature = "attester-coco")]
pub mod asr_attester;
#[cfg(feature = "attester-coco")]
pub mod attester;
#[cfg(feature = "verifier-coco")]
pub mod converter;
#[cfg(any(feature = "attester-coco", feature = "verifier-coco"))]
pub mod evidence;
#[cfg(feature = "verifier-coco")]
pub mod verifier;

#[cfg(feature = "attester-coco")]
pub const TTRPC_DEFAULT_TIMEOUT_NANO: i64 = 50 * 1000 * 1000 * 1000;

#[cfg(all(test, feature = "attester-coco", feature = "verifier-coco"))]
mod tests {
    use crate::cert::verify::AttestationServiceAddrArgs;
    use crate::tee::coco::attester::CocoAttester;
    use crate::tee::coco::converter::restful::CocoRestfulConverter;
    use crate::tee::coco::converter::CocoConverter;
    use crate::tee::coco::verifier::remote::CocoRemoteVerifier;
    use crate::tee::coco::verifier::CocoVerifier;
    use crate::tee::GenericAttester;
    use crate::tee::GenericConverter;
    use crate::tee::GenericVerifier;
    use crate::tee::ReportData;
    use std::collections::HashMap;

    const TEST_AA_ADDR: &str =
        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";
    const TEST_AS_ADDR: &str = "http://127.0.0.1:8080";
    const TEST_ASR_ADDR: &str = "http://127.0.0.1:8006";
    const TEST_AS_CERT_PATH: &str = "/tmp/as-full.pem";

    fn make_as_addr_config() -> AttestationServiceAddrArgs {
        AttestationServiceAddrArgs {
            as_addr: TEST_AS_ADDR.to_string(),
            as_is_grpc: false,
            as_headers: HashMap::new(),
        }
    }

    /// E2E test: BackgroundCheck model
    /// Flow: CocoAttester::get_evidence -> CocoConverter::convert -> CocoVerifier::verify_evidence
    /// The converter sends evidence to remote AS for evaluation, then the verifier validates the resulting token.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_e2e_background_check_flow() {
        // Create attester (connects to running AA)
        let attester = CocoAttester::new(TEST_AA_ADDR).expect("Failed to create attester");

        // Create converter (sends evidence to remote AS for verification)
        let converter =
            CocoRestfulConverter::new(TEST_AS_ADDR, &vec!["default".to_string()], &HashMap::new())
                .expect("Failed to create converter");

        // Create verifier (validates AS-issued token)
        let verifier = CocoRemoteVerifier::new(
            &Some(make_as_addr_config()),
            &Some(vec![TEST_AS_CERT_PATH.to_string()]),
            &vec!["default".to_string()],
            false,
            false,
        )
        .await
        .expect("Failed to create verifier");

        // Get evidence from TEE via AA
        let report_data = ReportData::Claims(serde_json::Map::new());
        let evidence = attester
            .get_evidence(&report_data)
            .await
            .expect("Failed to get evidence");

        // Convert evidence to AS token
        let token = converter
            .convert(&evidence)
            .await
            .expect("Failed to convert evidence");

        // Verify the token
        let result = verifier.verify_evidence(&token, &report_data).await;
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }

    /// E2E test: Passport model
    /// Flow: CocoAttester::get_evidence -> CocoConverter::convert (attester side) -> CocoVerifier::verify_evidence (verifier side)
    /// In passport model, the attester obtains a token from AS, then presents it to the verifier.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_e2e_passport_flow() {
        // Create attester
        let attester = CocoAttester::new(TEST_AA_ADDR).expect("Failed to create attester");

        // Create converter (attester-side, converts evidence to token via AS)
        let converter =
            CocoRestfulConverter::new(TEST_AS_ADDR, &vec!["default".to_string()], &HashMap::new())
                .expect("Failed to create converter");

        // Get evidence
        let report_data = ReportData::Claims(serde_json::Map::new());
        let evidence = attester
            .get_evidence(&report_data)
            .await
            .expect("Failed to get evidence");

        // Convert to token (attester side)
        let token = converter
            .convert(&evidence)
            .await
            .expect("Failed to convert evidence to token");

        // Create verifier (verifier side - only verifies token, no converter needed)
        let verifier = CocoRemoteVerifier::new(
            &Some(make_as_addr_config()),
            &Some(vec![TEST_AS_CERT_PATH.to_string()]),
            &vec!["default".to_string()],
            false,
            false,
        )
        .await
        .expect("Failed to create verifier");

        // Verify the token (verifier side)
        let result = verifier.verify_evidence(&token, &report_data).await;
        assert!(
            result.is_ok(),
            "Passport verification failed: {:?}",
            result.err()
        );
    }

    /// E2E test: ASR variant
    /// Flow: CocoAsrAttester::get_evidence -> CocoConverter::convert -> CocoVerifier::verify_evidence
    /// Same as the AA-based e2e but collects evidence via the ASR HTTP proxy.
    ///
    /// Requires ASR version with [PR #91](https://github.com/inclavare-containers/guest-components/pull/91)
    /// merged (`/info`, `encoding` parameter, `/additional-evidence` endpoint).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_e2e_asr_flow() {
        use crate::tee::coco::asr_attester::CocoAsrAttester;

        // Create attester (connects to running ASR, fetches TEE type from /info)
        let attester = CocoAsrAttester::new(TEST_ASR_ADDR)
            .await
            .expect("Failed to create ASR attester");

        // Create converter (sends evidence to remote AS for verification)
        let converter =
            CocoRestfulConverter::new(TEST_AS_ADDR, &vec!["default".to_string()], &HashMap::new())
                .expect("Failed to create converter");

        // Create verifier (validates AS-issued token)
        let verifier = CocoRemoteVerifier::new(
            &Some(make_as_addr_config()),
            &Some(vec![TEST_AS_CERT_PATH.to_string()]),
            &vec!["default".to_string()],
            false,
            false,
        )
        .await
        .expect("Failed to create verifier");

        // Get evidence from TEE via ASR
        let report_data = ReportData::Claims(serde_json::Map::new());
        let evidence = attester
            .get_evidence(&report_data)
            .await
            .expect("Failed to get evidence via ASR");

        // Convert evidence to AS token
        let token = converter
            .convert(&evidence)
            .await
            .expect("Failed to convert evidence");

        // Verify the token
        let result = verifier.verify_evidence(&token, &report_data).await;
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }

    #[cfg(feature = "__builtin-as")]
    mod builtin_e2e_tests {
        use super::*;
        use crate::tee::coco::converter::builtin::{BuiltinCocoConverter, PolicyConfig};
        use serial_test::serial;

        /// E2E test: Builtin model (local AS)
        /// Flow: CocoAttester::get_evidence -> BuiltinCocoConverter::convert -> BuiltinCocoVerifier::verify_evidence
        /// Uses embedded attestation-service for local verification.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_e2e_builtin_flow() {
            // Create attester
            let attester = CocoAttester::new(TEST_AA_ADDR).expect("Failed to create attester");

            // Create builtin converter (embedded AS)
            let converter =
                BuiltinCocoConverter::new(&PolicyConfig::HardwareWithReferenceValues, &[])
                    .await
                    .expect("Failed to create builtin converter");

            // Create builtin verifier from converter's work dir
            let verifier = converter
                .new_verifier()
                .await
                .expect("Failed to create builtin verifier");

            // Get evidence
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

            let token = token.expect("Failed to convert evidence via builtin AS");

            // Verify the token
            let result = verifier.verify_evidence(&token, &report_data).await;
            assert!(result.is_err());
            let error = result.unwrap_err();
            assert!(
                format!("{error:?}").contains("EarStatusNotAffirming"),
                "{error:?}"
            );
        }

        /// Temp bench: measure attestation cert generation (attester, via AA)
        /// and cert verification (verifier, builtin AS) latency on this host.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        // This is host-only bench code (cfg(test) + non-wasm __builtin-as), so
        // std::time::Instant::now is fine here despite the repo-wide disallow
        // (which exists only because Instant::now panics on wasm32).
        #[allow(clippy::disallowed_methods)]
        async fn test_bench_cert_gen_and_verify_builtin() {
            use crate::cert::create::CertBuilder;
            use crate::cert::verify::CertVerifier;
            use crate::crypto::{AsymmetricAlgo, HashAlgo};
            use crate::tee::coco::evidence::CocoEvidence;
            use crate::tee::{GenericAttester, GenericConverter, GenericEvidence, GenericVerifier};
            use std::time::{Duration, Instant};

            const AA_ADDR: &str =
                "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";
            // First verify call is the cold path: the dcap-qvl collateral cache
            // (in-process) is empty, so it fetches TDX collateral from the PCCS
            // over a fresh HTTPS/TLS connection. Later calls are warm cache hits.
            const ITERS: usize = 10;

            fn fmt_ms(d: Duration) -> String {
                format!("{:.3} ms", d.as_secs_f64() * 1000.0)
            }
            fn stats(samples: &[Duration]) -> (Duration, Duration) {
                let min = samples.iter().min().copied().unwrap_or_default();
                let avg = samples.iter().sum::<Duration>() / samples.len() as u32;
                (min, avg)
            }

            // One-time setup: builtin converter (embeds AS + RVPS + rego + signer)
            // and the verifier it produces. Building these is not part of the
            // measured path; only per-cert gen/verify calls are timed.
            // Policy selectable via BENCH_POLICY env (default TrustAll) so the
            // rego-appraisal cost can be isolated by comparing policies.
            let policy = match std::env::var("BENCH_POLICY").as_deref() {
                Ok("hw_rv") => PolicyConfig::HardwareWithReferenceValues,
                Ok("hw_only") => PolicyConfig::HardwareOnly,
                _ => PolicyConfig::TrustAll,
            };
            let converter = BuiltinCocoConverter::new(&policy, &[])
                .await
                .expect("Failed to create builtin converter");
            let verifier = converter
                .new_verifier()
                .await
                .expect("Failed to create builtin verifier");

            // ---- cert generation (attester side): AA get_evidence + DICE sign ----
            let mut gen_times: Vec<Duration> = Vec::with_capacity(ITERS);
            let mut certs: Vec<Vec<u8>> = Vec::with_capacity(ITERS);
            for i in 0..ITERS {
                // CocoAttester is not Clone; a fresh ttrpc client per iter is cheap.
                let attester = CocoAttester::new(AA_ADDR)
                    .unwrap_or_else(|_| panic!("Failed to create attester (iter {i})"));
                let t0 = Instant::now();
                let bundle = CertBuilder::new(attester, HashAlgo::Sha256)
                    .build(AsymmetricAlgo::P256)
                    .await
                    .expect("Failed to build cert");
                let dt = t0.elapsed();
                let der = bundle.cert_to_der().expect("Failed to encode cert to DER");
                println!("[gen  {i}] {dt:?}");
                gen_times.push(dt);
                certs.push(der);
            }
            let (g_min, g_avg) = stats(&gen_times);

            // ---- cert verification (verifier side, builtin AS) ----
            // verify_der (parse + self-sig check + evidence extract) +
            // converter.convert (builtin AS: dcap-qvl TDX quote verify + rego) +
            // verifier.verify_evidence (JWT sig/exp). First call is cold
            // (collateral fetch); later calls are warm (cached).
            let mut ver_times: Vec<Duration> = Vec::with_capacity(ITERS);
            // Sub-step accumulators for the breakdown: per-verify timing of
            // each phase of the verifier path (cert layer + builtin AS).
            let mut sub_verify_der = Vec::<Duration>::with_capacity(ITERS);
            let mut sub_parse_ev = Vec::<Duration>::with_capacity(ITERS);
            let mut sub_convert = Vec::<Duration>::with_capacity(ITERS);
            let mut sub_verify_tok = Vec::<Duration>::with_capacity(ITERS);
            for (i, der) in certs.iter().enumerate() {
                let t0 = Instant::now();
                let pending = CertVerifier::new()
                    .verify_der(der)
                    .await
                    .expect("Failed to verify_der");
                let t_verify_der = t0.elapsed();

                let t1 = Instant::now();
                let evidence: CocoEvidence = Result::from(CocoEvidence::create_evidence_from_dice(
                    pending.cbor_tag,
                    &pending.raw_evidence,
                ))
                .expect("Failed to reconstruct evidence from DICE cert");
                let t_parse_ev = t1.elapsed();

                let t2 = Instant::now();
                let token = converter
                    .convert(&evidence)
                    .await
                    .expect("Failed to convert evidence via builtin AS");
                let t_convert = t2.elapsed();

                let t3 = Instant::now();
                let _ = verifier.verify_evidence(&token, &pending.report_data).await;
                let t_verify_tok = t3.elapsed();

                let dt = t_verify_der + t_parse_ev + t_convert + t_verify_tok;
                if i == 0 {
                    println!(
                        "[cold] verify_der={} parse_ev={} convert={} verify_tok={} total={}",
                        fmt_ms(t_verify_der),
                        fmt_ms(t_parse_ev),
                        fmt_ms(t_convert),
                        fmt_ms(t_verify_tok),
                        fmt_ms(dt)
                    );
                }
                sub_verify_der.push(t_verify_der);
                sub_parse_ev.push(t_parse_ev);
                sub_convert.push(t_convert);
                sub_verify_tok.push(t_verify_tok);
                println!("[verify{i}] {dt:?}");
                ver_times.push(dt);
            }
            let (v_min, v_avg) = stats(&ver_times);
            let cold = ver_times.first().copied().unwrap_or_default();
            let warm = if ver_times.len() > 1 {
                stats(&ver_times[1..])
            } else {
                (cold, cold)
            };

            println!("================ rats-tls cert bench (builtin AS) ================");
            println!(
                "cert generation  : min={}, avg={} ({} iters)",
                fmt_ms(g_min),
                fmt_ms(g_avg),
                ITERS
            );
            println!(
                "cert verification: cold(first)={}, warm min={}, warm avg={}",
                fmt_ms(cold),
                fmt_ms(warm.0),
                fmt_ms(warm.1)
            );
            println!(
                "cert verification: overall min={}, avg={} ({} iters)",
                fmt_ms(v_min),
                fmt_ms(v_avg),
                ITERS
            );
            // Per-phase breakdown (warm avg over iters 1..; cold = iter 0).
            let warm_sub = |v: &[Duration]| -> Duration {
                if v.len() > 1 {
                    v[1..].iter().sum::<Duration>() / (v.len() - 1) as u32
                } else {
                    v[0]
                }
            };
            println!("--- verify breakdown (cold | warm avg) ---");
            println!(
                "  verify_der    : {} | {}",
                fmt_ms(sub_verify_der[0]),
                fmt_ms(warm_sub(&sub_verify_der))
            );
            println!(
                "  parse_evidence : {} | {}",
                fmt_ms(sub_parse_ev[0]),
                fmt_ms(warm_sub(&sub_parse_ev))
            );
            println!(
                "  convert(AS)   : {} | {}",
                fmt_ms(sub_convert[0]),
                fmt_ms(warm_sub(&sub_convert))
            );
            println!(
                "  verify_evidence: {} | {}",
                fmt_ms(sub_verify_tok[0]),
                fmt_ms(warm_sub(&sub_verify_tok))
            );
            println!("====================================================================");
        }
    }
}

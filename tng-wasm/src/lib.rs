#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::Layer;
use tracing_wasm::{WASMLayer, WASMLayerConfigBuilder};
use wasm_bindgen::prelude::*;

pub mod fetch;

#[wasm_bindgen(start)]
pub fn init_tng() {
    // print pretty errors in wasm https://github.com/rustwasm/console_error_panic_hook
    // This is not needed for tracing_wasm to work, but it is a common tool for getting proper error line numbers for panics.
    console_error_panic_hook::set_once();

    let wasm_layer_config = WASMLayerConfigBuilder::new()
        .set_console_config(tracing_wasm::ConsoleConfig::ReportWithoutConsoleColor)
        .build();
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(
        WASMLayer::new(wasm_layer_config).with_filter(Into::<tracing_subscriber::EnvFilter>::into(
            "warn,tokio_graceful=off",
        )),
    ))
    .expect("failed to set tng default global tracing subscriber");

    tng::show_banner("wasm");
}

#[cfg(all(
    test,
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
mod tests {
    use wasm_bindgen_test::*;

    use rats_cert::cert::verify::PolicyConfig;
    use rats_cert::tee::coco::converter::builtin::BuiltinCocoConverter;
    use rats_cert::tee::coco::converter::CoCoNonce;
    use rats_cert::tee::GenericConverter;

    // Run these in a real browser so `window.crypto.subtle` (the Web Crypto API
    // used by `build_challenger_webcrypto`) is available. Run with:
    //   make wasm-unit-test-chrome
    wasm_bindgen_test_configure!(run_in_browser);

    // Public upstream Trustee vectors exercise the exact crypto/evidence
    // backend in the browser, including altered signatures and bindings.
    #[wasm_bindgen_test]
    #[allow(clippy::unwrap_used)]
    async fn snp_report_signatures_and_workload_bindings() {
        use sev::firmware::{
            guest::AttestationReport,
            host::{CertTableEntry, CertType},
        };
        use verifier::{InitDataHash, ReportData, Verifier};
        for (report_bytes, certificate) in [
            (
                include_bytes!("../test_data/test-report.bin").as_slice(),
                include_bytes!("../test_data/test-vcek.der").as_slice(),
            ),
            (
                include_bytes!("../test_data/turin-report.bin").as_slice(),
                include_bytes!("../test_data/turin-vcek.der").as_slice(),
            ),
        ] {
            let report: AttestationReport = bincode::deserialize(report_bytes).unwrap();
            let evidence = serde_json::json!({ "attestation_report": report,
                "cert_chain": [CertTableEntry::new(CertType::VCEK, certificate.to_vec())] });
            let verifier = verifier::snp::Snp::new().unwrap();
            let (claims, _) = verifier
                .evaluate(
                    evidence.clone(),
                    &ReportData::Value(&report.report_data),
                    &InitDataHash::Value(&report.host_data),
                )
                .await
                .unwrap();
            assert_eq!(claims["init_data"], hex::encode(report.host_data));
            assert_eq!(claims["report_data"], hex::encode(report.report_data));
            // Current native CoCo emits the sev 7 JSON schema. It must verify
            // through the same WASM backend, not only the older wire schema.
            use sev_modern::parser::ByteParser;
            let modern =
                sev_modern::firmware::guest::AttestationReport::from_bytes(report_bytes).unwrap();
            let modern_evidence = serde_json::json!({ "attestation_report": modern,
                "cert_chain": evidence["cert_chain"].clone() });
            verifier
                .evaluate(
                    modern_evidence.clone(),
                    &ReportData::Value(&report.report_data),
                    &InitDataHash::Value(&report.host_data),
                )
                .await
                .unwrap();
            let mut altered = modern_evidence;
            altered["attestation_report"]["host_data"][0] =
                serde_json::json!(report.host_data[0] ^ 1);
            assert!(verifier
                .evaluate(
                    altered,
                    &ReportData::Value(&report.report_data),
                    &InitDataHash::NotProvided
                )
                .await
                .is_err());
            let mut wrong = report.host_data;
            wrong[0] ^= 1;
            assert!(verifier
                .evaluate(
                    evidence.clone(),
                    &ReportData::Value(&report.report_data),
                    &InitDataHash::Value(&wrong)
                )
                .await
                .is_err());
            let mut tampered = evidence;
            tampered["attestation_report"]["measurement"][0] =
                serde_json::json!(255 - report.measurement[0]);
            assert!(verifier
                .evaluate(
                    tampered,
                    &ReportData::Value(&report.report_data),
                    &InitDataHash::NotProvided
                )
                .await
                .is_err());
        }
    }

    // Constructing the builtin attestation-service converter on wasm must drive
    // the WebCrypto RSA keygen path (`build_challenger_webcrypto`) rather than
    // the slow pure-software `rsa` prime generation, and then produce a
    // challenge nonce that is a bare 3-segment JWT. This exercises that whole
    // flow end-to-end in a headless browser.
    #[wasm_bindgen_test]
    async fn builtin_challenger_webcrypto_keygen_and_nonce() {
        let converter = match BuiltinCocoConverter::new(
            &PolicyConfig::HardwareWithReferenceValues,
            &[],
        )
        .await
        {
            Ok(c) => c,
            Err(error) => panic!("failed to build builtin converter: {error:?}"),
        };

        let nonce = match converter.get_nonce().await {
            Ok(n) => n,
            Err(error) => panic!("failed to get nonce: {error:?}"),
        };

        let CoCoNonce::Jwt(jwt) = nonce;
        assert_eq!(
            jwt.split('.').count(),
            3,
            "builtin challenge nonce should be a bare 3-segment JWT, got: {jwt}"
        );
    }
}

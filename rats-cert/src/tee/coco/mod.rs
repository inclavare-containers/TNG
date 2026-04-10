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
    use crate::tee::coco::converter::CocoConverter;
    use crate::tee::coco::verifier::CocoVerifier;
    use crate::tee::GenericAttester;
    use crate::tee::GenericConverter;
    use crate::tee::GenericVerifier;
    use crate::tee::ReportData;
    use std::collections::HashMap;

    const TEST_AA_ADDR: &str =
        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";
    const TEST_AS_ADDR: &str = "http://127.0.0.1:8080";
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
        let converter = CocoConverter::new(
            TEST_AS_ADDR,
            &vec!["default".to_string()],
            false,
            &HashMap::new(),
        )
        .expect("Failed to create converter");

        // Create verifier (validates AS-issued token)
        let verifier = CocoVerifier::new(
            &Some(make_as_addr_config()),
            &Some(vec![TEST_AS_CERT_PATH.to_string()]),
            &vec!["default".to_string()],
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
        let converter = CocoConverter::new(
            TEST_AS_ADDR,
            &vec!["default".to_string()],
            false,
            &HashMap::new(),
        )
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
        let verifier = CocoVerifier::new(
            &Some(make_as_addr_config()),
            &Some(vec![TEST_AS_CERT_PATH.to_string()]),
            &vec!["default".to_string()],
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
        #[should_panic(expected = "EarStatusNotAffirming")]
        async fn test_e2e_builtin_flow() {
            // Create attester
            let attester = CocoAttester::new(TEST_AA_ADDR).expect("Failed to create attester");

            // Create builtin converter (embedded AS)
            let converter = BuiltinCocoConverter::new(&PolicyConfig::Default, &[])
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
            let token = converter
                .convert(&evidence)
                .await
                .expect("Failed to convert evidence via builtin AS");

            // Verify the token
            let result = verifier.verify_evidence(&token, &report_data).await;
            assert!(
                result.is_ok(),
                "Builtin verification failed: {:?}",
                result.err()
            );
        }
    }
}

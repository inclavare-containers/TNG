#[cfg(any(feature = "attester-ita", feature = "verifier-ita"))]
pub mod evidence;
#[cfg(any(feature = "attester-ita", feature = "verifier-ita"))]
pub mod token;

#[cfg(feature = "attester-ita")]
mod asr_attester;
#[cfg(feature = "attester-ita")]
mod attester;
#[cfg(feature = "attester-ita")]
mod attester_common;
#[cfg(any(feature = "attester-ita", feature = "verifier-ita"))]
pub mod converter;
#[cfg(any(feature = "attester-ita", feature = "verifier-ita"))]
mod retry;
#[cfg(feature = "verifier-ita")]
pub mod verifier;

#[cfg(any(feature = "attester-ita", feature = "verifier-ita"))]
pub use evidence::{ItaEvidence, ItaNonce};
#[cfg(any(feature = "attester-ita", feature = "verifier-ita"))]
pub use token::ItaToken;

#[cfg(feature = "attester-ita")]
pub use asr_attester::ItaAsrAttester;
#[cfg(feature = "attester-ita")]
pub use attester::ItaAttester;
#[cfg(any(feature = "attester-ita", feature = "verifier-ita"))]
pub use converter::ItaConverter;
#[cfg(feature = "verifier-ita")]
pub use verifier::ItaVerifier;

#[cfg(all(test, feature = "attester-ita", feature = "verifier-ita"))]
mod tests {
    use crate::tee::ita::attester::ItaAttester;
    use crate::tee::ita::converter::ItaConverter;
    use crate::tee::ita::verifier::ItaVerifier;
    use crate::tee::{GenericAttester, GenericConverter, GenericVerifier, ReportData};

    const TEST_AA_ADDR: &str =
        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";
    const TEST_ASR_ADDR: &str = "http://127.0.0.1:8006";
    const TEST_ITA_API_URL: &str = "https://api.trustauthority.intel.com";
    const TEST_ITA_JWKS_URL: &str = "https://portal.trustauthority.intel.com";

    /// E2E test: ItaAttester -> ItaConverter -> ItaVerifier
    ///
    /// Requires a running Attestation Agent at `TEST_AA_ADDR`.
    /// Ignored if the `ITA_API_KEY` env var is not set.
    #[test_with::env(ITA_API_KEY)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_e2e_ita_flow() {
        let api_key = std::env::var("ITA_API_KEY").unwrap();

        // Create attester (connects to running AA)
        let attester = ItaAttester::new(TEST_AA_ADDR).expect("Failed to create attester");

        // Create converter (sends evidence to ITA for appraisal)
        let converter =
            ItaConverter::new(&api_key, TEST_ITA_API_URL, &[]).expect("Failed to create converter");

        // Create verifier (validates ITA-issued JWT via JWKS)
        let verifier = ItaVerifier::new(TEST_ITA_JWKS_URL, &[]).expect("Failed to create verifier");

        // Get evidence from TEE via AA
        let report_data = ReportData::Claims(serde_json::Map::new());
        let evidence = attester
            .get_evidence(&report_data)
            .await
            .expect("Failed to get evidence");

        // Convert evidence to ITA token
        let token = converter
            .convert(&evidence)
            .await
            .expect("Failed to convert evidence to token");

        // Verify the token
        let result = verifier.verify_evidence(&token, &report_data).await;
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }

    /// E2E test with nonce: ItaConverter::get_nonce -> ItaAttester -> ItaConverter -> ItaVerifier
    ///
    /// Same as `test_e2e_ita_flow` but fetches a nonce from ITA first and
    /// binds it into the evidence via the `challenge_token` claim.
    /// Ignored if the `ITA_API_KEY` env var is not set.
    #[test_with::env(ITA_API_KEY)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_e2e_ita_flow_with_nonce() {
        let api_key = std::env::var("ITA_API_KEY").unwrap();

        // Create attester (connects to running AA)
        let attester = ItaAttester::new(TEST_AA_ADDR).expect("Failed to create attester");

        // Create converter (sends evidence to ITA for appraisal)
        let converter =
            ItaConverter::new(&api_key, TEST_ITA_API_URL, &[]).expect("Failed to create converter");

        // Create verifier (validates ITA-issued JWT via JWKS)
        let verifier = ItaVerifier::new(TEST_ITA_JWKS_URL, &[]).expect("Failed to create verifier");

        // Fetch nonce from ITA
        let nonce = converter
            .get_nonce()
            .await
            .expect("Failed to get nonce from ITA");

        // Include nonce as challenge_token in the report data claims
        let mut claims = serde_json::Map::new();
        claims.insert(
            "challenge_token".to_string(),
            serde_json::Value::String(nonce),
        );
        let report_data = ReportData::Claims(claims);

        // Get evidence from TEE via AA (nonce bound into evidence)
        let evidence = attester
            .get_evidence(&report_data)
            .await
            .expect("Failed to get evidence");

        // Convert evidence to ITA token
        let token = converter
            .convert(&evidence)
            .await
            .expect("Failed to convert evidence to token");

        // Verify the token
        let result = verifier.verify_evidence(&token, &report_data).await;
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }

    /// E2E test with nonce: ItaConverter::get_nonce -> ItaAsrAttester -> ItaConverter -> ItaVerifier
    /// Same as the AA-based nonce e2e but collects evidence via the ASR HTTP proxy.
    ///
    /// Requires a running ASR proxy at `TEST_ASR_ADDR`.
    /// Ignored if the `ITA_API_KEY` env var is not set.
    #[test_with::env(ITA_API_KEY)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_e2e_ita_asr_flow() {
        use crate::tee::ita::ItaAsrAttester;

        let api_key = std::env::var("ITA_API_KEY").unwrap();

        // Create attester (connects to running ASR)
        let attester = ItaAsrAttester::new(TEST_ASR_ADDR).expect("Failed to create ASR attester");

        // Create converter (sends evidence to ITA for appraisal)
        let converter =
            ItaConverter::new(&api_key, TEST_ITA_API_URL, &[]).expect("Failed to create converter");

        // Create verifier (validates ITA-issued JWT via JWKS)
        let verifier = ItaVerifier::new(TEST_ITA_JWKS_URL, &[]).expect("Failed to create verifier");

        // Fetch nonce from ITA
        let nonce = converter
            .get_nonce()
            .await
            .expect("Failed to get nonce from ITA");

        // Include nonce as challenge_token in the report data claims
        let mut claims = serde_json::Map::new();
        claims.insert(
            "challenge_token".to_string(),
            serde_json::Value::String(nonce),
        );
        let report_data = ReportData::Claims(claims);

        // Get evidence from TEE via ASR (nonce bound into evidence)
        let evidence = attester
            .get_evidence(&report_data)
            .await
            .expect("Failed to get evidence via ASR");

        // Convert evidence to ITA token
        let token = converter
            .convert(&evidence)
            .await
            .expect("Failed to convert evidence to token");

        // Verify the token
        let result = verifier.verify_evidence(&token, &report_data).await;
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }
}

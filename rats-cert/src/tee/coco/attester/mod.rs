use crate::crypto::{DefaultCrypto, HashAlgo};
use crate::errors::*;
use crate::tee::coco::evidence::{tee_from_str, CocoEvidence, EvidenceExtension};
use crate::tee::{
    serialize_canon_json, wrap_runtime_data_as_structed, GenericAttester, ReportData,
};

pub(crate) mod aa_client;
mod ttrpc_protocol;

pub(crate) use aa_client::AaClient;

pub struct CocoAttester {
    aa: AaClient,
    /// When true, get_evidence best-effort fetches DCAP verification collateral
    /// from PCCS and carries it in the evidence so the verifier can skip PCCS.
    tdx_carry_collateral: bool,
}

impl CocoAttester {
    pub fn new(aa_addr: &str) -> Result<Self> {
        Ok(Self {
            aa: AaClient::new(aa_addr)?,
            tdx_carry_collateral: false,
        })
    }

    pub fn new_with_timeout_nano(aa_addr: &str, timeout_nano: i64) -> Result<Self> {
        Ok(Self {
            aa: AaClient::new_with_timeout(aa_addr, timeout_nano)?,
            tdx_carry_collateral: false,
        })
    }

    /// Enable best-effort DCAP collateral carry so the verifier can skip PCCS.
    pub fn with_tdx_carry_collateral(mut self, carry: bool) -> Self {
        self.tdx_carry_collateral = carry;
        self
    }

    /// Best-effort TDX DCAP collateral fetch. Returns None when carrying is
    /// disabled, the TEE is not TDX, or the fetch fails (verifier falls back
    /// to PCCS).
    async fn fetch_collateral(
        &self,
        quote: &[u8],
        tee_type_str: &str,
    ) -> Option<Vec<EvidenceExtension>> {
        #[cfg(feature = "tdx-carry-collateral")]
        {
            if !self.tdx_carry_collateral || tee_type_str != "tdx" {
                return None;
            }
            match fetch_collateral_from_pccs(quote).await {
                Ok(e) => Some(e),
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "failed to fetch DCAP collateral; verifier will fall back to PCCS"
                    );
                    None
                }
            }
        }
        #[cfg(not(feature = "tdx-carry-collateral"))]
        {
            let _ = quote;
            None
        }
    }
}

#[cfg_attr(wasm, async_trait::async_trait(?Send))]
#[cfg_attr(not(wasm), async_trait::async_trait)]
impl GenericAttester for CocoAttester {
    type Evidence = CocoEvidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<CocoEvidence> {
        // Here we wrap rats-rs's report_data to a StructuredRuntimeData instead of RawRuntimeData, so that we can check the value in our verifier. See: https://github.com/confidential-containers/trustee/blob/86a407ecb1bc1897ef8fba5ee59e33e56e11ef4d/attestation-service/attestation-service/src/lib.rs#L245
        let aa_runtime_data = wrap_runtime_data_as_structed(report_data)?;
        let aa_runtime_data_bytes = serialize_canon_json(&aa_runtime_data)?;
        let aa_runtime_data_hash_algo = HashAlgo::Sha384; // TODO: make this configable from user

        let aa_runtime_data_hash_value =
            DefaultCrypto::hash(aa_runtime_data_hash_algo, &aa_runtime_data_bytes);

        let evidence = self.aa.get_evidence(aa_runtime_data_hash_value)?;

        let tee_type_str = self.aa.get_tee_type()?;
        let tee_type = tee_from_str(&tee_type_str)?;

        // Attempt to get additional evidence from AA, but don't fail if not supported
        let additional_evidence = self.aa.get_additional_evidence(Vec::new());

        // Best-effort: fetch DCAP verification collateral so the verifier can
        // skip PCCS. Failure is non-fatal; the verifier falls back to fetching.
        let extensions = self.fetch_collateral(&evidence, &tee_type_str).await;

        Ok(CocoEvidence::new(
            tee_type,
            evidence,
            additional_evidence,
            String::from_utf8(aa_runtime_data_bytes).map_err(Error::InvalidUtf8)?,
            aa_runtime_data_hash_algo,
            extensions,
        )?)
    }
}

/// Fetch DCAP collateral via dcap-qvl CollateralClient and wrap as an extension.
#[cfg(feature = "tdx-carry-collateral")]
async fn fetch_collateral_from_pccs(quote: &[u8]) -> anyhow::Result<Vec<EvidenceExtension>> {
    use anyhow::Context;
    let pccs_url = std::env::var("PCCS_URL")
        .or_else(|_| std::env::var("PCCS_URLS"))
        .context("PCCS_URL/PCCS_URLS not configured; cannot carry DCAP collateral")?;
    let pccs_url = pccs_url
        .split(',')
        .next()
        .unwrap_or(&pccs_url)
        .trim()
        .to_string();
    let client = dcap_qvl::collateral::CollateralClient::with_default_http(pccs_url)
        .context("failed to build dcap-qvl HTTP client")?;
    let collateral = client
        .fetch(quote)
        .await
        .context("dcap-qvl collateral fetch failed")?;
    let value = serde_json::to_value(&collateral).context("serialize DCAP collateral")?;
    Ok(vec![EvidenceExtension::TdxCollateral(value)])
}

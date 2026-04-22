use crate::crypto::{DefaultCrypto, HashAlgo};
use crate::errors::*;
use crate::tee::coco::evidence::{tee_from_str, CocoEvidence};
use crate::tee::{
    serialize_canon_json, wrap_runtime_data_as_structed, GenericAttester, ReportData,
};

pub(crate) mod asr_client;

pub(crate) use asr_client::AsrClient;

/// CoCo attester that fetches evidence via the API Server Rest (ASR) HTTP
/// interface instead of talking to the Attestation Agent over ttrpc.
///
/// Produces the same [`CocoEvidence`] as [`CocoAttester`], so downstream
/// converters and verifiers are unaffected.
pub struct CocoAsrAttester {
    asr: AsrClient,
}

impl CocoAsrAttester {
    pub fn new(asr_addr: &str) -> Result<Self> {
        Ok(Self {
            asr: AsrClient::new(asr_addr)?,
        })
    }
}

#[async_trait::async_trait]
impl GenericAttester for CocoAsrAttester {
    type Evidence = CocoEvidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<CocoEvidence> {
        let aa_runtime_data = wrap_runtime_data_as_structed(report_data)?;
        let aa_runtime_data_bytes = serialize_canon_json(&aa_runtime_data)?;
        let aa_runtime_data_hash_algo = HashAlgo::Sha384;

        let aa_runtime_data_hash_value =
            DefaultCrypto::hash(aa_runtime_data_hash_algo, &aa_runtime_data_bytes);

        let evidence = self.asr.get_evidence(aa_runtime_data_hash_value).await?;

        let tee_type_str = self.asr.get_tee_type().await?;
        let tee_type = tee_from_str(&tee_type_str)?;

        let additional_evidence = self.asr.get_additional_evidence(Vec::new()).await;

        Ok(CocoEvidence::new(
            tee_type,
            evidence,
            additional_evidence,
            String::from_utf8(aa_runtime_data_bytes).map_err(Error::InvalidUtf8)?,
            aa_runtime_data_hash_algo,
        )?)
    }
}

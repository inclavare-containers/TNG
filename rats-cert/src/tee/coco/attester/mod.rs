use super::evidence::CocoEvidence;
use crate::crypto::{DefaultCrypto, HashAlgo};
use crate::errors::*;
use crate::tee::coco::evidence::tee_from_str;
use crate::tee::{
    serialize_canon_json, wrap_runtime_data_as_structed, GenericAttester, ReportData,
};

pub(crate) mod aa_client;
mod ttrpc_protocol;

pub(crate) use aa_client::AaClient;

pub struct CocoAttester {
    aa: AaClient,
}

impl CocoAttester {
    pub fn new(aa_addr: &str) -> Result<Self> {
        Ok(Self {
            aa: AaClient::new(aa_addr)?,
        })
    }

    pub fn new_with_timeout_nano(aa_addr: &str, timeout_nano: i64) -> Result<Self> {
        Ok(Self {
            aa: AaClient::new_with_timeout(aa_addr, timeout_nano)?,
        })
    }
}

#[async_trait::async_trait]
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

        Ok(CocoEvidence::new(
            tee_type,
            evidence,
            additional_evidence,
            String::from_utf8(aa_runtime_data_bytes).map_err(Error::InvalidUtf8)?,
            aa_runtime_data_hash_algo,
        )?)
    }
}

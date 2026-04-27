use canon_json::CanonicalFormatter;
use serde::Serialize;

use super::super::evidence::CocoEvidence;
use super::super::TTRPC_DEFAULT_TIMEOUT_NANO;
use super::ttrpc_protocol::attestation_agent::{
    GetAdditionalEvidenceRequest, GetEvidenceRequest, GetTeeTypeRequest,
};
use super::ttrpc_protocol::attestation_agent_ttrpc::AttestationAgentServiceClient;
use crate::crypto::{DefaultCrypto, HashAlgo};
use crate::errors::*;
use crate::tee::coco::evidence::tee_from_str;
use crate::tee::{GenericAttester, GenericEvidence, ReportData};

pub(super) fn serialize_canon_json<T: Serialize>(value: T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value
        .serialize(&mut ser)
        .map_err(Error::SerializeCanonicalJsonFailed)?;
    Ok(buf)
}

pub struct CocoUdsAttester {
    client: AttestationAgentServiceClient,
    timeout_nano: i64,
}

impl CocoUdsAttester {
    pub fn new(aa_addr: &str) -> Result<Self> {
        Self::new_with_timeout_nano(aa_addr, TTRPC_DEFAULT_TIMEOUT_NANO)
    }

    pub fn new_with_timeout_nano(aa_addr: &str, timeout_nano: i64) -> Result<Self> {
        // TODO: turn ttrpc client to async client
        let inner =
            ttrpc::Client::connect(aa_addr).map_err(Error::ConnectAttestationAgentTtrpcFailed)?;
        let client = AttestationAgentServiceClient::new(inner);
        Ok(Self {
            client,
            timeout_nano,
        })
    }
}

#[async_trait::async_trait]
impl GenericAttester for CocoUdsAttester {
    type Evidence = CocoEvidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<CocoEvidence> {
        // Here we wrap rats-rs's report_data to a StructuredRuntimeData instead of RawRuntimeData, so that we can check the value in our verifier. See: https://github.com/confidential-containers/trustee/blob/86a407ecb1bc1897ef8fba5ee59e33e56e11ef4d/attestation-service/attestation-service/src/lib.rs#L245
        let aa_runtime_data = CocoEvidence::wrap_runtime_data_as_structed(report_data)?;
        let aa_runtime_data_bytes = serialize_canon_json(&aa_runtime_data)?;
        let aa_runtime_data_hash_algo = HashAlgo::Sha384; // TODO: make this configable from user

        let aa_runtime_data_hash_value =
            DefaultCrypto::hash(aa_runtime_data_hash_algo, &aa_runtime_data_bytes);

        // Get evidence from AA
        let get_evidence_req = GetEvidenceRequest {
            RuntimeData: aa_runtime_data_hash_value,
            ..Default::default()
        };
        let get_evidence_res = self
            .client
            .get_evidence(
                ttrpc::context::with_timeout(self.timeout_nano),
                &get_evidence_req,
            )
            .map_err(Error::GetEvidenceFromAAFailed)?;

        // Query tee type from AA
        let get_tee_type_req = GetTeeTypeRequest {
            ..Default::default()
        };
        let get_tee_type_res = self
            .client
            .get_tee_type(
                ttrpc::context::with_timeout(self.timeout_nano),
                &get_tee_type_req,
            )
            .map_err(Error::GetTeeTypeFromAAFailed)?;
        let tee_type = tee_from_str(&get_tee_type_res.tee)?;

        // Attempt to get additional evidence from AA, but don't fail if not supported.
        // According to the proto file, GetAdditionalEvidence returns GetEvidenceResponse which has an 'Evidence' field.
        let additional_evidence_res = self.client.get_additional_evidence(
            ttrpc::context::with_timeout(self.timeout_nano),
            &GetAdditionalEvidenceRequest {
                RuntimeData: Default::default(), // use empty user data here
                ..Default::default()
            },
        );

        let additional_evidence = match additional_evidence_res {
            Ok(res) => {
                // If GetAdditionalEvidence is supported, we get additional evidence as a single evidence blob
                if res.Evidence.is_empty() {
                    None
                } else {
                    Some(res.Evidence)
                }
            }
            Err(error) => {
                // If GetAdditionalEvidence is not supported by AA, return empty map
                tracing::warn!(
                    ?error,
                    "GetAdditionalEvidence is not supported by AA, use empty additional evidence"
                );
                None
            }
        };

        Ok(CocoEvidence::new(
            tee_type,
            get_evidence_res.Evidence,
            additional_evidence,
            String::from_utf8(aa_runtime_data_bytes).map_err(Error::InvalidUtf8)?,
            aa_runtime_data_hash_algo,
        )?)
    }
}

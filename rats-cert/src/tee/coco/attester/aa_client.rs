use super::ttrpc_protocol::attestation_agent::{
    GetAdditionalEvidenceRequest, GetEvidenceRequest, GetTeeTypeRequest,
};
use super::ttrpc_protocol::attestation_agent_ttrpc::AttestationAgentServiceClient;
use crate::errors::*;
use crate::tee::coco::TTRPC_DEFAULT_TIMEOUT_NANO;

/// Shared low-level client for the CoCo Attestation Agent ttrpc service.
///
/// Both `CocoAttester` and `ItaAttester` talk to the same AA daemon; this
/// struct encapsulates the connection and raw RPC calls so the attesters
/// only need to implement their provider-specific REPORTDATA derivation
/// and evidence construction.
pub(crate) struct AaClient {
    client: AttestationAgentServiceClient,
    timeout_nano: i64,
}

impl AaClient {
    pub fn new(aa_addr: &str) -> Result<Self> {
        Self::new_with_timeout(aa_addr, TTRPC_DEFAULT_TIMEOUT_NANO)
    }

    pub fn new_with_timeout(aa_addr: &str, timeout_nano: i64) -> Result<Self> {
        let inner =
            ttrpc::Client::connect(aa_addr).map_err(Error::ConnectAttestationAgentTtrpcFailed)?;
        let client = AttestationAgentServiceClient::new(inner);
        Ok(Self {
            client,
            timeout_nano,
        })
    }

    /// Request a TEE evidence quote from the AA with the given runtime_data_hash_value bytes.
    pub fn get_evidence(&self, runtime_data_hash_value: Vec<u8>) -> Result<Vec<u8>> {
        let req = GetEvidenceRequest {
            RuntimeData: runtime_data_hash_value,
            ..Default::default()
        };
        let res = self
            .client
            .get_evidence(ttrpc::context::with_timeout(self.timeout_nano), &req)
            .map_err(Error::GetEvidenceFromAAFailed)?;
        Ok(res.Evidence)
    }

    /// Query the TEE type string from the AA (e.g. "tdx", "snp").
    pub fn get_tee_type(&self) -> Result<String> {
        let req = GetTeeTypeRequest::default();
        let res = self
            .client
            .get_tee_type(ttrpc::context::with_timeout(self.timeout_nano), &req)
            .map_err(Error::GetTeeTypeFromAAFailed)?;
        Ok(res.tee)
    }

    /// Request additional device evidence (e.g. GPU attestation) from the AA.
    ///
    /// Returns `Ok(None)` when the AA does not support additional evidence or
    /// when the response is empty. Never fails the caller — unsupported RPCs
    /// are logged and swallowed.
    pub fn get_additional_evidence(&self, runtime_data_hash_value: Vec<u8>) -> Option<Vec<u8>> {
        let req = GetAdditionalEvidenceRequest {
            RuntimeData: runtime_data_hash_value,
            ..Default::default()
        };
        match self
            .client
            .get_additional_evidence(ttrpc::context::with_timeout(self.timeout_nano), &req)
        {
            Ok(res) if !res.Evidence.is_empty() => Some(res.Evidence),
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "GetAdditionalEvidence not supported by AA, proceeding without additional evidence"
                );
                None
            }
        }
    }
}

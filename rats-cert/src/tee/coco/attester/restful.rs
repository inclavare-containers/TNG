use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use kbs_types::Tee;
use reqwest::Client;

use super::super::evidence::CocoEvidence;
use super::uds::serialize_canon_json;
use crate::crypto::{DefaultCrypto, HashAlgo};
use crate::errors::*;
use crate::tee::{GenericAttester, ReportData};

#[cfg(unix)]
const RESTFUL_AA_CONNECT_TIMEOUT_DEFAULT: u64 = 5;

pub struct CocoRestfulAttester {
    aa_addr: String,
    tee: Tee,
    client: Client,
}

impl CocoRestfulAttester {
    pub fn new(aa_addr: &str, tee: Tee) -> Result<Self> {
        let client = {
            let builder = reqwest::Client::builder()
                .user_agent(format!("rats-rs/{}", env!("CARGO_PKG_VERSION")));
            #[cfg(unix)]
            let builder =
                builder.connect_timeout(Duration::from_secs(RESTFUL_AA_CONNECT_TIMEOUT_DEFAULT));
            builder
                .build()
                .map_err(Error::ConnectAttestationAgentRestfulFailed)?
        };

        Ok(Self {
            aa_addr: aa_addr.trim_end_matches('/').to_owned(),
            tee,
            client,
        })
    }
}

#[async_trait::async_trait]
impl GenericAttester for CocoRestfulAttester {
    type Evidence = CocoEvidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<CocoEvidence> {
        let aa_runtime_data = CocoEvidence::wrap_runtime_data_as_structed(report_data)?;
        let aa_runtime_data_bytes = serialize_canon_json(&aa_runtime_data)?;
        let aa_runtime_data_hash_algo = HashAlgo::Sha384;

        let aa_runtime_data_hash_value =
            DefaultCrypto::hash(aa_runtime_data_hash_algo, &aa_runtime_data_bytes);

        // Encode the binary hash as base64 URL-safe no-pad for the query parameter.
        // The REST server passes the string's UTF-8 bytes as RuntimeData to AA via ttrpc.
        let runtime_data_param = URL_SAFE_NO_PAD.encode(&aa_runtime_data_hash_value);

        let url = format!("{}/aa/evidence", self.aa_addr);
        let response = self
            .client
            .get(&url)
            .query(&[("runtime_data", &runtime_data_param)])
            .send()
            .await
            .map_err(Error::GetEvidenceFromAARestfulFailed)?;

        let status = response.status();
        let evidence_bytes = response
            .bytes()
            .await
            .map_err(Error::GetEvidenceFromAARestfulResponseReadFailed)?;

        if !status.is_success() {
            return Err(Error::GetEvidenceFromAARestfulHttpError {
                status_code: status.as_u16(),
                response_body: String::from_utf8_lossy(&evidence_bytes).into_owned(),
            });
        }

        // get_additional_evidence is not implemented in the REST API
        Ok(CocoEvidence::new(
            self.tee,
            evidence_bytes.to_vec(),
            None,
            String::from_utf8(aa_runtime_data_bytes).map_err(Error::InvalidUtf8)?,
            aa_runtime_data_hash_algo,
        )?)
    }
}

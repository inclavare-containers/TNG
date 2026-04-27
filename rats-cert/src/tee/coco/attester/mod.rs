mod restful;
mod ttrpc_protocol;
mod uds;

pub use restful::CocoRestfulAttester;
pub use uds::CocoUdsAttester;

use super::evidence::CocoEvidence;
use crate::errors::*;
use crate::tee::{GenericAttester, ReportData};

pub enum CocoAttester {
    Uds(CocoUdsAttester),
    Restful(CocoRestfulAttester),
}

impl CocoAttester {
    /// Convenience constructor that creates a UDS (ttrpc) attester.
    pub fn new(aa_addr: &str) -> Result<Self> {
        Ok(Self::Uds(CocoUdsAttester::new(aa_addr)?))
    }
}

#[async_trait::async_trait]
impl GenericAttester for CocoAttester {
    type Evidence = CocoEvidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<CocoEvidence> {
        match self {
            Self::Uds(a) => a.get_evidence(report_data).await,
            Self::Restful(a) => a.get_evidence(report_data).await,
        }
    }
}

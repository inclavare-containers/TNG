use rats_cert::errors::*;
use rats_cert::tee::coco::attester::CocoAttester;
use rats_cert::tee::{GenericAttester, ReportData};

use super::evidence::TngEvidence;

pub enum TngAttester {
    Coco(CocoAttester),
}

#[async_trait::async_trait]
impl GenericAttester for TngAttester {
    type Evidence = TngEvidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<TngEvidence> {
        match self {
            Self::Coco(a) => Ok(a.get_evidence(report_data).await?.into()),
        }
    }
}

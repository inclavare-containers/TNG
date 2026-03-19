use std::any::Any;

use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use self::claims::Claims;
use crate::errors::*;

pub mod auto;
pub mod claims;

#[cfg(any(feature = "attester-coco", feature = "verifier-coco"))]
pub mod coco;

pub enum DiceParseEvidenceOutput<T> {
    NotMatch,
    MatchButInvalid(Error),
    Ok(T),
}

impl<T> From<DiceParseEvidenceOutput<T>> for Result<T> {
    fn from(value: DiceParseEvidenceOutput<T>) -> Self {
        match value {
            crate::tee::DiceParseEvidenceOutput::NotMatch => Err(Error::kind_with_msg(
                ErrorKind::UnrecognizedEvidenceType,
                "Unrecognized evidence type",
            )),
            crate::tee::DiceParseEvidenceOutput::MatchButInvalid(e) => Err(e),
            crate::tee::DiceParseEvidenceOutput::Ok(v) => Ok(v),
        }
    }
}

/// Trait representing generic evidence.
pub trait GenericEvidence: Any + Send {
    /// Return the CBOR tag used for generating DICE cert.
    fn get_dice_cbor_tag(&self) -> u64;

    /// Return the raw evidence data used for generating DICE cert.
    fn get_dice_raw_evidence(&self) -> Result<Vec<u8>>;

    /// Create evidence from cbor tag and raw evidence of a DICE cert.
    fn create_evidence_from_dice(
        cbor_tag: u64,
        raw_evidence: &[u8],
    ) -> DiceParseEvidenceOutput<Self>
    where
        Self: Sized;

    /// Parse the evidence and return a set of claims.
    fn get_claims(&self) -> Result<Claims>;
}

/// Trait representing a generic attester.
#[async_trait::async_trait]
pub trait GenericAttester {
    type Evidence: GenericEvidence;

    /// Generate evidence based on the provided report data.
    async fn get_evidence(&self, report_data: &ReportData) -> Result<Self::Evidence>;
}

/// Trait representing a generic verifier.
#[async_trait::async_trait]
pub trait GenericVerifier {
    type Evidence: GenericEvidence;

    /// Verify the provided evidence with the Trust Anchor and checking the report data matches the one in the evidence.
    async fn verify_evidence(
        &self,
        evidence: &Self::Evidence,
        report_data: &ReportData,
    ) -> Result<()>;
}

#[async_trait::async_trait]
pub trait GenericConverter {
    type InEvidence: GenericEvidence;
    type OutEvidence: GenericEvidence;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence>;
}

pub struct AttesterPipeline<A: GenericAttester, C: GenericConverter<InEvidence = A::Evidence>> {
    attester: A,
    converter: C,
}

impl<A: GenericAttester, C: GenericConverter<InEvidence = A::Evidence>> AttesterPipeline<A, C> {
    pub fn new(attester: A, converter: C) -> Self {
        Self {
            attester,
            converter,
        }
    }
}

#[async_trait::async_trait]
impl<A, C> GenericAttester for AttesterPipeline<A, C>
where
    A: GenericAttester + Sync,
    C: GenericConverter<InEvidence = A::Evidence> + Sync,
{
    type Evidence = C::OutEvidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<Self::Evidence> {
        let evidence = self.attester.get_evidence(report_data).await?;
        self.converter.convert(&evidence).await
    }
}

/// Enum representing different types of TEEs.
#[derive(Debug, PartialEq, EnumIter, Clone, Copy)]
pub enum TeeType {
    // This only used for testing with CoCo
    Sample,
    // China Secure Virtualization
    Csv,
}

impl TeeType {
    /// Detects the current TEE environment and returns the detected TeeType.
    pub fn detect_env() -> Option<Self> {
        // Only CoCo TEE types are supported
        None
    }
}

/// Enum representing report data type.
#[derive(Debug, PartialEq, EnumIter, Clone)]
pub enum ReportData {
    Raw(Vec<u8>),
    Claims(Claims),
}

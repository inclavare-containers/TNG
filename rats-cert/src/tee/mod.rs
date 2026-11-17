use std::any::Any;

use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use self::claims::Claims;
use crate::errors::*;

pub mod claims;

#[cfg(any(feature = "attester-coco", feature = "verifier-coco"))]
pub mod coco;

#[cfg(any(feature = "attester-ita", feature = "verifier-ita"))]
pub mod ita;

pub enum DiceParseEvidenceOutput<T> {
    NotMatch,
    MatchButInvalid(Error),
    Ok(T),
}

impl<T> DiceParseEvidenceOutput<T> {
    pub fn map_ok<U: From<T>>(self) -> DiceParseEvidenceOutput<U> {
        match self {
            Self::Ok(v) => DiceParseEvidenceOutput::Ok(v.into()),
            Self::MatchButInvalid(e) => DiceParseEvidenceOutput::MatchButInvalid(e),
            Self::NotMatch => DiceParseEvidenceOutput::NotMatch,
        }
    }

    pub fn or_else(self, f: impl FnOnce() -> DiceParseEvidenceOutput<T>) -> Self {
        match self {
            Self::NotMatch => f(),
            other => other,
        }
    }
}

impl<T> From<DiceParseEvidenceOutput<T>> for Result<T> {
    fn from(value: DiceParseEvidenceOutput<T>) -> Self {
        match value {
            crate::tee::DiceParseEvidenceOutput::NotMatch => Err(Error::DiceParseEvidenceFailed {
                detail: "CBOR tag does not match".to_string(),
            }),
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
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
#[cfg_attr(not(wasm), async_trait::async_trait)]
pub trait GenericAttester {
    type Evidence: GenericEvidence;

    /// Generate evidence based on the provided report data.
    async fn get_evidence(&self, report_data: &ReportData) -> Result<Self::Evidence>;
}

/// Blanket implementation for references to attesters.
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
#[cfg_attr(not(wasm), async_trait::async_trait)]
impl<A: GenericAttester + Sync> GenericAttester for &A {
    type Evidence = A::Evidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<Self::Evidence> {
        (*self).get_evidence(report_data).await
    }
}

/// Trait representing a generic verifier.
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
#[cfg_attr(not(wasm), async_trait::async_trait)]
pub trait GenericVerifier {
    type Evidence: GenericEvidence;

    /// Verify the provided evidence with the Trust Anchor and checking the report data matches the one in the evidence.
    async fn verify_evidence(
        &self,
        evidence: &Self::Evidence,
        report_data: &ReportData,
    ) -> Result<()>;
}

#[cfg_attr(wasm, async_trait::async_trait(?Send))]
#[cfg_attr(not(wasm), async_trait::async_trait)]
pub trait GenericConverter {
    type InEvidence: GenericEvidence;
    type OutEvidence: GenericEvidence;
    type Nonce;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence>;

    async fn get_nonce(&self) -> Result<Self::Nonce>;
}

/// How a converter obtains the AS challenge nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceCapability {
    /// The AS issues a real signed challenge, so evidence freshness can be
    /// bound to it.
    Signed,
    /// A real challenge on current servers, a fixed dummy value on servers
    /// that predate the challenge API.
    SignedOrDummy,
    /// Always a fixed dummy value; freshness cannot be bound.
    Dummy,
}

/// Whether a converter retries with an older AS request shape after a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackCapability {
    /// No automatic protocol downgrade.
    None,
    /// Downgrades only for the error that identifies an old server.
    OnSpecificError,
    /// Downgrades on any conversion error.
    OnAnyError,
}

/// Observable behavior differences between converter implementations.
///
/// These describe what a converter does today; they are not knobs. Callers use
/// them to explain outcomes (for example why a nonce is not a real challenge)
/// without re-deriving the behavior of each adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConverterCapabilities {
    pub nonce: NonceCapability,
    pub fallback: FallbackCapability,
    /// Whether caller-supplied policy IDs reach the AS.
    pub policy_ids: bool,
    /// Whether additional evidence is forwarded to the AS.
    pub additional_evidence: bool,
}

/// Blanket implementation for references to attesters.
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
#[cfg_attr(not(wasm), async_trait::async_trait)]
impl<A: GenericConverter + Sync> GenericConverter for &A
where
    <A as GenericConverter>::InEvidence: Sync,
{
    type InEvidence = A::InEvidence;
    type OutEvidence = A::OutEvidence;
    type Nonce = A::Nonce;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        (*self).convert(in_evidence).await
    }

    async fn get_nonce(&self) -> Result<Self::Nonce> {
        (*self).get_nonce().await
    }
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

#[cfg_attr(wasm, async_trait::async_trait(?Send))]
#[cfg_attr(not(wasm), async_trait::async_trait)]
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

/// Enum representing report data type.
#[derive(Debug, PartialEq, EnumIter, Clone)]
pub enum ReportData {
    Claims(Claims),
    /// No report_data to verify — `verify_evidence` skips the runtime_data
    /// subset check when this variant is passed.
    None,
}

/// Wrap [`ReportData`] into a structured JSON value suitable for embedding
/// into TEE REPORTDATA.  Used by both CoCo and ITA attesters/verifiers.
pub(crate) fn wrap_runtime_data_as_structed(report_data: &ReportData) -> Result<serde_json::Value> {
    match report_data {
        ReportData::Claims(claims) => {
            serde_json::to_value(claims).map_err(Error::SerializeClaimsToJsonFailed)
        }
        ReportData::None => Ok(serde_json::Value::Null),
    }
}

/// Deterministic canonical-JSON serialization via [`canon_json`].
#[cfg(feature = "attester-coco")]
pub(crate) fn serialize_canon_json<T: serde::Serialize>(value: T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut ser =
        serde_json::Serializer::with_formatter(&mut buf, canon_json::CanonicalFormatter::new());
    serde::Serialize::serialize(&value, &mut ser).map_err(Error::SerializeCanonicalJsonFailed)?;
    Ok(buf)
}

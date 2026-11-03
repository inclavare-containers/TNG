//! Builtin Attestation Service Converter
//!
//! This module implements local evidence verification using the embedded attestation-service crate.
//! It converts CocoEvidence to CocoAsToken by running attestation-service in-process.

mod converter;
mod host_fns;
mod policies;
mod policy_config;
mod reference_values;
mod signer;

pub use converter::BuiltinCocoConverter;
// The config types were all public before the split into `policy_config`; keep
// that reachability for downstream users of the builtin converter.
pub use policy_config::{
    ArtifactLogService, PolicyConfig, ReferenceValueConfig, SampleProvenancePayloadConfig,
    SlsaReferenceValuePayloadConfig, TransparencyServiceConfig,
};

/// Default policy ID used by builtin AS
pub const DEFAULT_POLICY_ID: &str = "default";

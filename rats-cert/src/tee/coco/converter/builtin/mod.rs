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
    ArtifactLogService, GpuPostureConfig, ModuleEntryConfig, ModuleGroupsConfig,
    NvidiaPostureConfig, PolicyConfig, ReferenceValueConfig, SampleProvenancePayloadConfig,
    SlsaReferenceValuePayloadConfig, TcbMinStatus, TdxBit, TdxCollateralConfig, TdxEventlog,
    TdxPostureConfig, TdxSeptVe, TdxTcbConfig, TransparencyLogEntryConfig,
    TransparencyServiceConfig,
};

/// Render the Rego source a builtin AS loads for `policy`. This is the same
/// function the tunnel uses; the tunnel additionally base64-encodes the result.
pub use policies::render_policy_source;

/// Default policy ID used by builtin AS
pub const DEFAULT_POLICY_ID: &str = "default";

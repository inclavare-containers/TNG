//! Polymorphic provider layer for attestation components.
//!
//! This module abstracts over concrete attestation providers (currently CoCo,
//! designed for future ITA/others) by defining `Tng*` wrapper enums that
//! implement the `Generic*` traits from `rats-cert`. Factory functions
//! (`create_attester`, `create_converter`, `create_verifier`) instantiate
//! the correct underlying provider based on config enums.

pub mod attester;
pub mod converter;
pub mod evidence;
pub mod factory;
pub mod provider_type;
pub mod token;
pub mod verifier;

pub use attester::TngAttester;
pub use converter::TngConverter;
pub use evidence::TngEvidence;
pub use factory::*;
#[allow(unused_imports)]
pub use provider_type::ProviderType;
pub use token::TngToken;
pub use verifier::TngVerifier;

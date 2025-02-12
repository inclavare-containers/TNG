use std::fmt::Debug;

use super::attestation_result::AttestationResult;

#[derive(Debug)]
pub struct AccessLog<T1: Debug, T2: Debug> {
    pub downstream: T1,
    pub upstream: T2,
    pub to_trusted_tunnel: bool,
    pub peer_attested: Option<AttestationResult>,
}

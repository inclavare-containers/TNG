use std::fmt::Debug;

use super::attestation_result::AttestationResult;

#[derive(Debug)]
pub enum AccessLog<T1: Debug, T2: Debug> {
    Ingress {
        downstream: T1,
        upstream: T2,
        to_trusted_tunnel: bool,
        peer_attested: Option<AttestationResult>,
    },
    Egress {
        downstream: T1,
        upstream: T2,
        from_trusted_tunnel: bool,
        peer_attested: Option<AttestationResult>,
    },
}

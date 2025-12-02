use std::{borrow::Cow, fmt::Debug};

use super::attestation_result::AttestationResult;

#[derive(Debug)]
#[allow(dead_code)]
pub enum AccessLog<'a, T1: Debug, T2: Debug> {
    Ingress {
        downstream: T1,
        upstream: T2,
        to_trusted_tunnel: bool,
        attestation_result: Option<Cow<'a, AttestationResult>>,
    },
    Egress {
        downstream: T1,
        upstream: T2,
        from_trusted_tunnel: bool,
        attestation_info: Option<Cow<'a, AttestationResult>>,
    },
}

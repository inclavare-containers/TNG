//! Egress-side OHTTP protocol handling. The trusted stream manager claims
//! accepted connections for this protocol outright and hands them to the
//! security layer's `handle_stream`; the security layer serves the outer
//! HTTP, and its request handlers dial the backend themselves.

pub mod security;

pub mod egress;
pub mod ingress;

pub const ENVOY_DUMMY_CERT: &'static str = include_str!("servercert.pem");
pub const ENVOY_DUMMY_KEY: &'static str = include_str!("serverkey.pem");

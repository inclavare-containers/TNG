use http_body_util::combinators::BoxBody;
use hyper_util::client::legacy::Client;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Debug;
use std::hash::Hash;

use crate::tunnel::endpoint::TngEndpoint;

use super::{RatsTlsClient, SecurityConnector};

pub type HyperClientType = Client<SecurityConnector, BoxBody<bytes::Bytes, Infallible>>;

pub type ClientPool = HashMap<PoolKey, RatsTlsClient>;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PoolKey {
    /// The distination endpoint where the underlying transport layer will connect to.
    endpoint: TngEndpoint,
}

impl PoolKey {
    pub fn new(endpoint: TngEndpoint) -> Self {
        Self { endpoint }
    }

    pub fn get_endpoint(&self) -> &TngEndpoint {
        &self.endpoint
    }
}

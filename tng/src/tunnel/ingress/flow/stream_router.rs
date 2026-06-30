use crate::tunnel::{endpoint::TngEndpoint, utils::endpoint_matcher::EndpointMatcher};

pub struct StreamRouter {
    endpoint_matcher: EndpointMatcher,
}

impl StreamRouter {
    pub fn with_endpoint_matcher(endpoint_matcher: EndpointMatcher) -> Self {
        Self { endpoint_matcher }
    }

    pub fn should_forward_via_tunnel(&self, endpoint: &TngEndpoint) -> bool {
        let encrypted = self.endpoint_matcher.matches(endpoint);
        tracing::debug!(
            endpoint=?endpoint,
            encrypted,
            "Determine whether to forward the stream via secure tunnel"
        );
        encrypted
    }
}

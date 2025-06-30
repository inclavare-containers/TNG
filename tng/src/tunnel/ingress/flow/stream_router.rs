use crate::tunnel::{endpoint::TngEndpoint, utils::endpoint_matcher::EndpointMatcher};

pub struct StreamRouter {
    endpoint_matcher: EndpointMatcher,
}

impl StreamRouter {
    pub fn with_endpoint_matcher(endpoint_matcher: EndpointMatcher) -> Self {
        Self { endpoint_matcher }
    }

    pub fn should_forward_via_tunnel(&self, endpoint: &TngEndpoint) -> bool {
        let via_tunnel = self.endpoint_matcher.matches(&endpoint);
        tracing::debug!(
            endpoint=?endpoint,
            via_tunnel,
            "Determine whether to forward the stream via secure tunnel"
        );
        via_tunnel
    }
}

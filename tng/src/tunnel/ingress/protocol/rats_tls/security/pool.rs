use http_body_util::combinators::BoxBody;
use hyper_util::client::legacy::Client;
use std::collections::HashMap;
use std::convert::Infallible;
use std::hash::Hash;

use crate::tunnel::endpoint::TngEndpoint;

use super::{RatsTlsClient, SecurityConnector};

pub type HyperClientType = Client<SecurityConnector, BoxBody<bytes::Bytes, Infallible>>;

/// Shards (h2 tunnels) per destination endpoint. A tunnel is added lazily when
/// every existing tunnel for the endpoint is at its stream cap.
pub type ClientPool = HashMap<PoolKey, Vec<RatsTlsClient>>;

#[derive(PartialEq, Eq, Hash, Clone)]
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

/// Tunnel-count cap applied when `multiplex_max_connections` is unset. The
/// sharding gain comes from spreading TLS crypto across cores; past the core
/// count extra tunnels only add handshake cost, not parallelism.
pub(super) fn default_max_connections() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Least-active shard selection: index of the shard with fewest active streams,
/// or `None` when every shard is at `max` (caller creates a new shard) or the
/// endpoint has no shards yet. `max = None` never rejects a shard, preserving
/// the single-tunnel behavior. `at_limit` (the endpoint already holds
/// `max_connections` shards) reuses the least-loaded shard beyond the cap to
/// keep the pool bounded.
pub(super) fn select_shard_index(
    counts: &[u32],
    max: Option<u32>,
    at_limit: bool,
) -> Option<usize> {
    let (idx, min) = counts.iter().enumerate().min_by_key(|(_, count)| *count)?;
    match max {
        Some(max) if *min >= max => at_limit.then_some(idx),
        _ => Some(idx),
    }
}

/// Select the shard for a new stream from a pool entry.
pub(super) fn pick_shard(
    shards: &[RatsTlsClient],
    max: Option<u32>,
    max_connections: usize,
) -> Option<usize> {
    let counts: Vec<u32> = shards.iter().map(RatsTlsClient::active_streams).collect();
    select_shard_index(&counts, max, shards.len() >= max_connections)
}

#[cfg(test)]
mod tests {
    use super::select_shard_index;

    #[test]
    fn select_shard_prefers_least_active() {
        assert_eq!(select_shard_index(&[3, 1, 2], Some(4), false), Some(1));
    }

    #[test]
    fn select_shard_requires_new_when_all_at_cap() {
        assert_eq!(select_shard_index(&[4, 4], Some(4), false), None);
    }

    #[test]
    fn select_shard_unlimited_never_rejects() {
        assert_eq!(select_shard_index(&[7, 3], None, false), Some(1));
    }

    #[test]
    fn select_shard_empty_needs_new() {
        assert_eq!(select_shard_index(&[], Some(4), false), None);
        assert_eq!(select_shard_index(&[], None, false), None);
    }

    #[test]
    fn select_shard_ties_pick_first() {
        assert_eq!(select_shard_index(&[0, 0], Some(4), false), Some(0));
    }

    #[test]
    fn select_shard_cap_one_spreads_across_shards() {
        assert_eq!(select_shard_index(&[0, 1], Some(1), false), Some(0));
        assert_eq!(select_shard_index(&[1, 1], Some(1), false), None);
    }

    #[test]
    fn select_shard_at_limit_overflows_cap() {
        assert_eq!(select_shard_index(&[4, 4], Some(4), true), Some(0));
        // The overflow bound still respects least-active.
        assert_eq!(select_shard_index(&[9, 4], Some(4), true), Some(1));
    }

    #[test]
    fn select_shard_at_limit_empty_still_needs_new() {
        assert_eq!(select_shard_index(&[], Some(4), true), None);
    }
}

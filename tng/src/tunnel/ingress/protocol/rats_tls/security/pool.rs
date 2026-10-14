use http_body_util::combinators::BoxBody;
use hyper_util::client::legacy::Client;
use std::collections::HashMap;
use std::convert::Infallible;
use std::hash::Hash;

use crate::tunnel::endpoint::TngEndpoint;

use web_time_compat::{Instant, InstantExt};

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

/// How long a shard whose CONNECT attempt failed is skipped by least-active
/// selection. Short enough that a healthy shard recovering from a transient
/// failure is retried promptly; long enough that a persistently failing
/// endpoint does not concentrate every new stream on the broken shard.
pub(super) const SHARD_CONNECT_FAILURE_COOLDOWN: std::time::Duration =
    std::time::Duration::from_secs(5);

/// Shard picked for a new stream.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ShardPick {
    /// Least-loaded shard with free stream capacity.
    Reuse(usize),
    /// Least-loaded shard past the per-tunnel stream cap: the endpoint is at
    /// its tunnel bound, so the stream cap is exceeded (soft) instead of
    /// opening another tunnel.
    Overflow(usize),
}

impl ShardPick {
    pub(super) fn index(&self) -> usize {
        match self {
            ShardPick::Reuse(idx) | ShardPick::Overflow(idx) => *idx,
        }
    }

    pub(super) fn is_overflow(&self) -> bool {
        matches!(self, ShardPick::Overflow(_))
    }
}

/// Least-active shard selection over the shard stream counts. Shards in their
/// failure cooldown (see [`SHARD_CONNECT_FAILURE_COOLDOWN`]) are preferred
/// against; when every shard is cooling the endpoint itself is likely down, so
/// the cooldown is ignored rather than blocking allocation. Returns `None`
/// when every candidate is at `max` (caller creates a new shard) or the
/// endpoint has no shards yet. `max = None` never rejects a shard, preserving
/// the single-tunnel behavior. `at_limit` (the endpoint already holds
/// `max_connections` shards) reuses the least-loaded shard beyond the cap to
/// keep the pool bounded.
pub(super) fn select_shard_index(
    counts: &[u32],
    cooling: &[bool],
    max: Option<u32>,
    at_limit: bool,
) -> Option<ShardPick> {
    let all: Vec<usize> = (0..counts.len()).collect();
    let fresh: Vec<usize> = all.iter().copied().filter(|&idx| !cooling[idx]).collect();
    let candidates: &[usize] = if fresh.is_empty() { &all } else { &fresh };
    let (idx, min) = candidates
        .iter()
        .copied()
        .map(|idx| (idx, counts[idx]))
        .min_by_key(|(_, count)| *count)?;
    match max {
        Some(max) if min >= max => at_limit.then_some(ShardPick::Overflow(idx)),
        _ => Some(ShardPick::Reuse(idx)),
    }
}

/// Select the shard for a new stream from a pool entry.
pub(super) fn pick_shard(
    shards: &[RatsTlsClient],
    max: Option<u32>,
    max_connections: usize,
) -> Option<ShardPick> {
    let counts: Vec<u32> = shards.iter().map(RatsTlsClient::active_streams).collect();
    let now = Instant::get();
    let cooling: Vec<bool> = shards.iter().map(|shard| shard.is_cooling(now)).collect();
    select_shard_index(&counts, &cooling, max, shards.len() >= max_connections)
}

#[cfg(test)]
mod tests {
    use super::{select_shard_index, ShardPick};

    const NO_COOLING: &[bool] = &[false, false];

    #[test]
    fn select_shard_prefers_least_active() {
        assert_eq!(
            select_shard_index(&[3, 1, 2], &[false, false, false], Some(4), false),
            Some(ShardPick::Reuse(1))
        );
    }

    #[test]
    fn select_shard_requires_new_when_all_at_cap() {
        assert_eq!(
            select_shard_index(&[4, 4], NO_COOLING, Some(4), false),
            None
        );
    }

    #[test]
    fn select_shard_unlimited_never_rejects() {
        assert_eq!(
            select_shard_index(&[7, 3], NO_COOLING, None, false),
            Some(ShardPick::Reuse(1))
        );
    }

    #[test]
    fn select_shard_empty_needs_new() {
        assert_eq!(select_shard_index(&[], NO_COOLING, Some(4), false), None);
        assert_eq!(select_shard_index(&[], NO_COOLING, None, false), None);
    }

    #[test]
    fn select_shard_ties_pick_first() {
        assert_eq!(
            select_shard_index(&[0, 0], NO_COOLING, Some(4), false),
            Some(ShardPick::Reuse(0))
        );
    }

    #[test]
    fn select_shard_cap_one_spreads_across_shards() {
        assert_eq!(
            select_shard_index(&[0, 1], NO_COOLING, Some(1), false),
            Some(ShardPick::Reuse(0))
        );
        assert_eq!(
            select_shard_index(&[1, 1], NO_COOLING, Some(1), false),
            None
        );
    }

    #[test]
    fn select_shard_at_limit_overflows_cap() {
        assert_eq!(
            select_shard_index(&[4, 4], NO_COOLING, Some(4), true),
            Some(ShardPick::Overflow(0))
        );
        // The overflow bound still respects least-active.
        assert_eq!(
            select_shard_index(&[9, 4], NO_COOLING, Some(4), true),
            Some(ShardPick::Overflow(1))
        );
    }

    #[test]
    fn select_shard_at_limit_empty_still_needs_new() {
        assert_eq!(select_shard_index(&[], NO_COOLING, Some(4), true), None);
    }

    #[test]
    fn select_shard_skips_cooling_shard() {
        // The cooling shard is the least loaded, but a more loaded healthy
        // shard is preferred.
        assert_eq!(
            select_shard_index(&[3, 0], &[false, true], Some(4), false),
            Some(ShardPick::Reuse(0))
        );
    }

    #[test]
    fn select_shard_cooling_shard_not_used_when_new_tunnel_possible() {
        // Only the fresh shard is at cap while the cooling one has capacity:
        // a new tunnel is still preferable to the failing shard.
        assert_eq!(
            select_shard_index(&[4, 0], &[false, true], Some(4), false),
            None
        );
    }

    #[test]
    fn select_shard_all_cooling_ignores_cooldown() {
        // Every shard cooling means the endpoint is likely down as a whole;
        // allocation must not block.
        assert_eq!(
            select_shard_index(&[1, 0], &[true, true], Some(4), false),
            Some(ShardPick::Reuse(1))
        );
    }

    #[test]
    fn select_shard_overflow_prefers_healthy_shard() {
        // At the tunnel bound the overflow lands on the least-loaded healthy
        // shard even though the cooling one is emptier.
        assert_eq!(
            select_shard_index(&[4, 0], &[false, true], Some(4), true),
            Some(ShardPick::Overflow(0))
        );
    }
}

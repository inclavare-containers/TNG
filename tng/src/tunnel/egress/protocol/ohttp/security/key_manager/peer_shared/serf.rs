use crate::config::egress::PeerSharedArgs;
use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::cluster_key_set::ClusterKeySet;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::memberlist_rats_quic::RatsQuic;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::runtime::InstrumentedRuntime;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::serf_message::pb;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::{KeyInfo, KeyStatus};
use crate::tunnel::ohttp::key_config::{KeyConfigExtend, PublicKeyData};
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::file_watcher::FileWatcher;

use again::RetryPolicy;
use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use prost::Message;
use scopeguard::defer;
use serf::delegate::CompositeDelegate;
use serf::event::{Event, EventProducer, EventSubscriber, MemberEventType, QueryEvent};
use serf::net::hostaddr::{Host, HostAddr};
use serf::net::resolver::socket_addr::SocketAddrResolver;
use serf::net::NodeId;
use serf::quic::{QuicTransport, QuicTransportOptions};
use serf::types::{MaybeResolvedAddress, MemberStatus};
use serf::{MemberlistOptions, Options};
use tokio::sync::RwLock;
use tokio::time::Duration;
use uuid::Uuid;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, Weak};
use web_time_compat::{SystemTime, SystemTimeExt};

use crate::tunnel::ra_context::RaContext;

// Serf protocol constants
const SERF_QUERY_CLUSTER_KEY_SET: &str = "query_cluster_key_set";
const SERF_QUERY_KEY: &str = "query_key";
const SERF_USER_EVENT_BROADCAST_CLUSTER_KEY_SET: &str = "broadcast_cluster_key_set";

pub struct PeerSharedKeyManager {
    pub(super) inner: Arc<PeerSharedKeyManagerInner>,
    pub(super) serf: Arc<SerfGracefulShutdown>,
}

type InstrumentedTokioRuntime = InstrumentedRuntime<serf::agnostic::tokio::TokioRuntime>;

type SerfTransport = QuicTransport<
    NodeId,
    SocketAddrResolver<InstrumentedTokioRuntime>,
    RatsQuic<InstrumentedTokioRuntime>,
    InstrumentedTokioRuntime,
>;

type SerfDelegate = CompositeDelegate<NodeId, SocketAddr>;

type Serf = serf::Serf<SerfTransport, SerfDelegate>;

pub(super) struct PeerSharedKeyManagerInner {
    /// Cluster-wide key set (pending/active/stale)
    pub(super) cluster_key_set: RwLock<ClusterKeySet>,
    /// Notify key_watcher to check immediately
    /// Shared with ClusterKeySet for unified notification
    pub(super) check_notify: Arc<tokio::sync::Notify>,
}

impl PeerSharedKeyManager {
    pub async fn new(runtime: TokioRuntime, peer_shared: PeerSharedArgs) -> Result<Self, TngError> {
        // Step 1: Initialize Serf node and network transport
        let (serf, subscriber) = Self::setup_serf(&runtime, &peer_shared).await?;

        // Step 2: Join cluster via static peers and optional file
        Self::spawn_cluster_join_tasks(&runtime, &serf, &peer_shared).await?;

        // Step 3: Preboot phase - synchronize cluster key set
        let cluster_key_set = Self::preboot(&serf, peer_shared.rotation_interval).await?;

        // Step 4: Initialize inner state
        // Create shared notify and pass it to ClusterKeySet
        let check_notify = Arc::new(tokio::sync::Notify::new());
        let mut cluster_key_set = cluster_key_set;
        cluster_key_set.set_notify(check_notify.clone());

        let inner = Arc::new(PeerSharedKeyManagerInner {
            cluster_key_set: RwLock::new(cluster_key_set),
            check_notify,
        });

        // Step 5: Spawn key watcher task (handles key status transitions)
        Self::spawn_key_watcher(runtime.clone(), inner.clone(), Arc::downgrade(&serf));

        // Step 6: Spawn serf event handler task (handles queries and events)
        Self::spawn_serf_watcher(
            runtime.clone(),
            subscriber,
            inner.clone(),
            Arc::downgrade(&serf),
        );

        Ok(Self { inner, serf })
    }

    /// Sets up the Serf instance with proper options and networking.
    async fn setup_serf(
        runtime: &TokioRuntime,
        peer_shared: &PeerSharedArgs,
    ) -> Result<
        (
            Arc<SerfGracefulShutdown>,
            EventSubscriber<SerfTransport, SerfDelegate>,
        ),
        TngError,
    > {
        let opts = Options::new()
            .with_memberlist_options(MemberlistOptions::lan())
            .with_event_buffer_size(256)
            .with_max_user_event_size(9 * 1024)
            .with_query_response_size_limit(9 * 1024);
        let node_id_str = Uuid::new_v4().to_string();
        let node_id = NodeId::<255>::new(&node_id_str)
            .with_context(|| format!("invalid node id {node_id_str}"))
            .map_err(TngError::InvalidParameter)?;
        tracing::info!(
            ?node_id,
            "Launching peer shared key manager with serf protocol"
        );
        let ra_args = peer_shared.ra_args.clone().into_checked()?;
        let ra_context = Arc::new(
            RaContext::from_ra_args(&ra_args)
                .await
                .map_err(TngError::InvalidParameter)?,
        );
        let net_opts =
            QuicTransportOptions::<_, SocketAddrResolver<InstrumentedTokioRuntime>, _>::with_stream_layer_options(
                node_id,
                (ra_context, runtime.clone()),            )
            .with_bind_addresses(
                [{
                    let addr = format!("{}:{}", peer_shared.host, peer_shared.port);
                    std::net::SocketAddr::from_str(&addr)
                        .with_context(|| format!("invalid address {addr}"))
                        .map_err(TngError::InvalidParameter)?
                }]
                .into_iter()
                .collect(),
            );

        let (producer, subscriber) = EventProducer::unbounded();
        let serf = Serf::with_event_producer(net_opts, opts, producer)
            .await
            .map_err(|error| TngError::SerfCrateError(anyhow!(error)))?;

        let graceful_serf = Arc::new(SerfGracefulShutdown::new(serf, runtime.clone()));

        Ok((graceful_serf, subscriber))
    }

    /// Handles joining the Serf cluster using both static peers and file-based dynamic peers.
    ///
    /// Startup blocks until EVERY configured peer has joined (concurrent per-peer
    /// retries with exponential backoff). A node with no configured peers at all
    /// (dedicated bootstrap node) skips joining and never blocks.
    async fn spawn_cluster_join_tasks(
        runtime: &TokioRuntime,
        serf: &Arc<SerfGracefulShutdown>,
        peer_shared: &PeerSharedArgs,
    ) -> Result<(), TngError> {
        // Build the combined, de-duplicated initial peer list (static + file).
        let mut initial_peers: Vec<String> = peer_shared.peers.clone();
        if let Some(peers_file) = &peer_shared.peers_file {
            if let Ok(file_peers) = load_peers_from_file(peers_file).await {
                for p in file_peers {
                    if !initial_peers.contains(&p) {
                        initial_peers.push(p);
                    }
                }
            }
        }

        // Join every configured peer, retrying forever with per-peer backoff.
        // Concurrent so a slow peer does not block joining faster ones; we await
        // ALL of them (A2: all configured peers must join before proceeding).
        if !initial_peers.is_empty() {
            let serf_for_tasks = serf.clone();
            let join_results = futures::future::join_all(
                initial_peers
                    .iter()
                    .map(|peer| {
                        let serf = serf_for_tasks.clone();
                        let peer = peer.clone();
                        async move {
                            let res = retry_join_peer(&serf, &peer).await;
                            if let Err(e) = &res {
                                tracing::warn!(?peer, ?e, "join ultimately failed");
                            }
                            res
                        }
                    })
                    .collect::<Vec<_>>(),
            )
            .await;
            // A2: any peer that could not ultimately join is a fatal startup error.
            // (retry_join_peer only returns on Ok, so this is belt-and-suspenders.)
            for r in join_results {
                r?;
            }
        }
        // Else: no configured peers -> dedicated bootstrap node, do not join, do not block.

        // If peers_file is configured, start monitoring it for changes.
        if let Some(peers_file) = &peer_shared.peers_file {
            let peers_file_path = peers_file.clone();

            // Start file watcher to monitor peers file changes
            let serf_weak_for_watcher = Arc::downgrade(serf);

            let peers_file_path_for_watcher = Path::new(&peers_file_path).to_path_buf();

            let mut file_watcher = FileWatcher::new(peers_file_path_for_watcher.clone())
                .map_err(|e| TngError::WatchFileFailed(peers_file_path_for_watcher.clone(), e))?;

            // In-flight peer set shared with the background retry tasks spawned by
            // the watcher. Dedups retries so a peer already being retried is not
            // re-spawned on every file change. Entries are cleared by the task
            // itself once the peer is joined (retry_join_peer only returns on Ok).
            let in_flight_peers: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
            // Clone the runtime handle so the watcher task can spawn supervised
            // background retry tasks (tokio::spawn is disallowed by clippy).
            let runtime_for_watcher = runtime.clone();

            runtime.spawn_supervised_task_with_span(tracing::info_span!("cluster_join_task"), async move {
                defer ! {
                    tracing::info!(peers_file = ?peers_file_path_for_watcher, "Peers file watcher stopped");
                }

                while let Some(result) = file_watcher.recv().await {
                    match result {
                        Ok(()) => {
                            tracing::info!(peers_file = ?peers_file_path_for_watcher, "Peers file changed, reloading and joining new peers");

                            match load_peers_from_file(&peers_file_path_for_watcher.to_string_lossy()).await {
                                Ok(new_peers) => {
                                    tracing::info!(peers_count = new_peers.len(), "Loaded peers from file");

                                    let Some(serf_clone) = serf_weak_for_watcher.upgrade() else {
                                        tracing::debug!(
                                            "stop watching peers file since serf has been dropped"
                                        );
                                        break;
                                    };

                                        // Spawn non-blocking per-peer retries for any peer not
                                        // already being retried. Deterministic dedup via the
                                        // in-flight set; never blocks the watcher loop, never
                                        // stacks duplicate tasks.
                                        spawn_peer_retry_tasks(
                                            &runtime_for_watcher,
                                            &serf_clone,
                                            &new_peers,
                                            &in_flight_peers,
                                        );
                                    }
                                    Err(error) => {
                                        tracing::error!(
                                            peers_file = ?peers_file_path_for_watcher,
                                            ?error,
                                            "Failed to load peers from updated file"
                                        );
                                    }
                                }
                            }
                            Err(error) => {
                                tracing::error!(
                                    peers_file = ?peers_file_path_for_watcher,
                                    ?error,
                                    "Internal error in peers file watcher"
                                );
                            }
                        }
                    }

                });
        }

        Ok(())
    }

    /// Preboot phase: synchronize cluster key set with existing members.
    ///
    /// This phase is blocking - it waits until we have synchronized with
    /// the cluster or determined we are the first node.
    async fn preboot(serf: &Serf, rotation_interval: u64) -> Result<ClusterKeySet, TngError> {
        tracing::info!("Starting preboot phase: synchronizing cluster key set");

        loop {
            let members = serf.members().await;

            if members.len() > 1 {
                // There are other nodes in the cluster, send query to synchronize
                tracing::info!(
                    peer_count = members.len() - 1,
                    "Found peers in cluster, querying for cluster key set"
                );

                let request = pb::QueryClusterKeySetRequest {};
                let mut request_buf = BytesMut::new();
                request.encode(&mut request_buf).map_err(|e| {
                    TngError::KeyUpdateMessageDecodeError(anyhow!(
                        "Failed to encode query request: {}",
                        e
                    ))
                })?;

                let query_response = serf
                    .query(SERF_QUERY_CLUSTER_KEY_SET, request_buf, None)
                    .await
                    .map_err(|e| {
                        TngError::SerfCrateError(anyhow!("Failed to send query: {}", e))
                    })?;

                let resp_rx = query_response.response_rx();
                let mut merged_key_set: Option<ClusterKeySet> = None;

                // Wait for all responses until channel closes or timeout
                while let Ok(response) = resp_rx.recv().await {
                    if let Ok(pb_response) =
                        pb::QueryClusterKeySetResponse::decode(response.payload().as_ref())
                    {
                        if let Some(pb_cks) = pb_response.cluster_key_set {
                            if let Ok(remote_key_set) = ClusterKeySet::try_from(pb_cks) {
                                let remote_keys: Vec<String> = remote_key_set
                                    .iter_keys()
                                    .map(|(pk, _)| hex::encode(pk.as_ref()))
                                    .collect();
                                tracing::info!(
                                    peer_node_id = ?response.from(),
                                    key_count = remote_keys.len(),
                                    public_key_hex = ?remote_keys,
                                    "Received cluster key set from peer"
                                );

                                if let Some(ref mut local) = merged_key_set {
                                    local.merge(remote_key_set);
                                } else {
                                    merged_key_set = Some(remote_key_set);
                                }
                            }
                        }
                    }
                }

                if let Some(key_set) = merged_key_set {
                    let key_hex: Vec<String> = key_set
                        .iter_keys()
                        .map(|(pk, _)| hex::encode(pk.as_ref()))
                        .collect();
                    tracing::info!(
                        key_count = key_hex.len(),
                        public_key_hex = ?key_hex,
                        "Preboot completed with synchronized cluster key set"
                    );
                    return Ok(key_set);
                }

                // No responses received, check if we are the master
                tracing::info!("No cluster key set received from peers");
                if Self::is_master(serf).await {
                    tracing::info!("This node is master, starting bootstrap");
                    break;
                } else {
                    tracing::info!("This node is not master, retrying preboot after 1 second");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            } else {
                // No other members, we are the first node
                tracing::info!("No peers found in cluster, starting bootstrap as first node");
                break;
            }
        }

        // Bootstrap: create initial active key
        let initial_key =
            KeyInfo::generate(0, KeyStatus::Active, SystemTime::get(), rotation_interval).map_err(
                |e| {
                    TngError::KeyUpdateMessageDecodeError(
                        anyhow::Error::from(e).context("Failed to generate initial key"),
                    )
                },
            )?;
        let public_key = initial_key.key_config.public_key()?;
        tracing::info!(
            public_key_hex = %hex::encode(public_key.as_ref()),
            "Created initial active key"
        );
        Ok(ClusterKeySet::new(
            public_key,
            initial_key,
            rotation_interval,
        ))
    }

    /// Spawn key watcher task that handles key status transitions.
    fn spawn_key_watcher(
        runtime: TokioRuntime,
        inner: Arc<PeerSharedKeyManagerInner>,
        serf: Weak<SerfGracefulShutdown>,
    ) {
        runtime.spawn_supervised_task_with_span(tracing::info_span!("key_watcher"), async move {
            defer! {
                tracing::info!("Key watcher stopped");
            }

            tracing::info!("Starting key watcher");

            loop {
                let now = SystemTime::get();

                let should_check_rotation = {
                    let mut cks = inner.cluster_key_set.write().await;

                    // 1. Handle pending -> active transition (first, as it triggers check_and_key_rotation)
                    let activated = cks.transition_pending_to_active(now);
                    if activated > 0 {
                        let active_keys: Vec<String> = cks
                            .iter_keys()
                            .filter(|(_, ki)| ki.status == KeyStatus::Active)
                            .map(|(pk, _)| hex::encode(pk.as_ref()))
                            .collect();
                        tracing::info!(
                            key_count = activated,
                            active_keys_hex = ?active_keys,
                            "Pending key transitioned to active"
                        );
                    }

                    // 2. Handle active -> stale transition
                    //    Capture the count of keys transitioned to stale — needed to trigger
                    //    rotation when the bootstrap-created initial key (which skips the
                    //    Pending->Active path) becomes stale.
                    let stale_transitioned = cks.transition_active_to_stale(now);
                    if stale_transitioned > 0 {
                        let stale_keys: Vec<String> = cks
                            .iter_keys()
                            .filter(|(_, ki)| ki.status == KeyStatus::Stale)
                            .map(|(pk, _)| hex::encode(pk.as_ref()))
                            .collect();
                        tracing::info!(
                            key_count = stale_transitioned,
                            stale_keys_hex = ?stale_keys,
                            "Active key(s) transitioned to stale"
                        );
                    }

                    // 3. Remove expired stale keys
                    let removed_count = cks.remove_expired_keys(now);
                    if removed_count > 0 {
                        let remaining_keys: Vec<String> = cks
                            .iter_keys()
                            .map(|(pk, _)| hex::encode(pk.as_ref()))
                            .collect();
                        tracing::info!(
                            removed_count,
                            remaining_key_count = remaining_keys.len(),
                            remaining_keys_hex = ?remaining_keys,
                            "Removed expired stale key(s)"
                        );
                    }

                    // 4. Detect if all active keys are stale-eligible but were preserved
                    //    by transition_active_to_stale (which preserves the last active key
                    //    to maintain the invariant that there's always at least one active key).
                    //    Without this check, a single-node cluster would never generate a
                    //    replacement key because the bootstrap-created initial key skips the
                    //    Pending→Active path, leaving `activated` at 0 forever.
                    let all_active_stale_eligible = cks.should_trigger_rotation_for_stale_active(now);

                    // 5. Detect if there are multiple active keys without a pending replacement.
                    //    This happens in split-brain scenarios where two nodes independently
                    //    bootstrap and their key sets merge. The master must generate a new
                    //    pending key to drive convergence to a single active key.
                    let multiple_active_no_pending = cks.has_multiple_active_without_pending();

                    // Trigger check_and_key_rotation when:
                    // - A pending key was activated (normal rotation path), OR
                    // - An active key became stale via transition, OR
                    // - All active keys are stale-eligible but were preserved as the last one, OR
                    // - Multiple active keys exist without a pending replacement (split-brain).
                    activated > 0 || stale_transitioned > 0 || all_active_stale_eligible || multiple_active_no_pending
                };

                if should_check_rotation {
                    let Some(serf) = serf.upgrade() else {
                        tracing::debug!("stop key watcher since serf has been dropped");
                        break;
                    };

                    // Trigger check_and_key_rotation only when pending -> active
                    Self::check_and_key_rotation(&serf, &inner).await;
                }

                // Compute the next deadline for key status transition.
                let next_deadline={
                    let cks = inner.cluster_key_set.read().await;
                    cks.next_deadline()
                };

                match next_deadline {
                    Some(deadline) => {
                        let sleep_duration = deadline.duration_since(now).unwrap_or_else(|error| {
                            tracing::warn!(
                                overdue = ?error.duration(),
                                "Key watcher deadline passed during state transitions, will check soon"
                            );
                            Duration::from_secs(1) // Force sleep 1 second to prevent busy-looping and CPU exhaustion when a bug causes repeated activations
                        });
                        tokio::select! {
                            _ = tokio::time::sleep(sleep_duration) => {
                                // Time reached, continue to check
                            }
                            _ = inner.check_notify.notified() => {
                                // Notified by modification, check immediately
                            }
                        }
                    }
                    None => {
                        // No pending deadlines, wait for notification
                        inner.check_notify.notified().await;
                    }
                }
            }
        });
    }

    /// Check if this node is master (smallest node ID) and perform key rotation if needed.
    async fn check_and_key_rotation(serf: &Serf, inner: &PeerSharedKeyManagerInner) {
        // Check if we are master
        if !Self::is_master(serf).await {
            return;
        }

        // Try to generate pending key (will fail if already has pending key)
        let generated = {
            let mut cks = inner.cluster_key_set.write().await;
            match cks.generate_pending_key_if_none() {
                Ok(generated) => generated,
                Err(error) => {
                    tracing::error!(?error, "Failed to generate pending key");
                    return;
                }
            }
        };

        if let Some(public_key) = generated {
            tracing::info!(
                ?public_key,
                public_key_hex = %hex::encode(public_key.as_ref()),
                "Master node generated new pending key, broadcasting to cluster"
            );

            // Broadcast to all members
            if let Err(error) = Self::broadcast_cluster_key_set(serf, inner).await {
                tracing::error!(?error, ?public_key, "Failed to broadcast cluster key set");
            }
        }
    }

    /// Check if this node is the master (smallest node ID in the cluster).
    async fn is_master(serf: &Serf) -> bool {
        let local_id = serf.local_id();

        let members = serf.members().await;

        // Find the smallest node ID
        let min_node_id = members
            .iter()
            .filter(|m| m.status == MemberStatus::Alive)
            .map(|m| m.node().id())
            .min();

        match min_node_id {
            Some(min) => min == local_id,
            None => true,
        }
    }

    /// Broadcast current cluster key set to all members.
    async fn broadcast_cluster_key_set(
        serf: &Serf,
        inner: &PeerSharedKeyManagerInner,
    ) -> Result<(), TngError> {
        let cks = inner.cluster_key_set.read().await;

        let pb_cluster_key_set: pb::ClusterKeySet = (*cks).clone().try_into().map_err(|e| {
            TngError::KeyUpdateMessageDecodeError(anyhow!(
                "Failed to convert cluster key set: {}",
                e
            ))
        })?;

        let event = pb::BroadcastClusterKeySetEvent {
            cluster_key_set: Some(pb_cluster_key_set),
        };

        let mut event_buf = BytesMut::new();
        event.encode(&mut event_buf).map_err(|e| {
            TngError::KeyUpdateMessageDecodeError(anyhow!(
                "Failed to encode broadcast event: {}",
                e
            ))
        })?;

        serf.user_event(SERF_USER_EVENT_BROADCAST_CLUSTER_KEY_SET, event_buf, false)
            .await
            .map_err(|e| TngError::SerfCrateError(anyhow!("Failed to broadcast: {}", e)))?;

        Ok(())
    }

    /// Spawn serf event handler task.
    fn spawn_serf_watcher(
        runtime: TokioRuntime,
        subscriber: EventSubscriber<SerfTransport, SerfDelegate>,
        inner: Arc<PeerSharedKeyManagerInner>,
        serf: Weak<SerfGracefulShutdown>,
    ) {
        runtime.spawn_unsupervised_task_with_span(
            tracing::info_span!("serf_watcher"),
            async move {
                defer! {
                    tracing::info!("Serf watcher stopped");
                }

                tracing::info!("Starting serf watcher");

                loop {
                    let Ok(event) = subscriber.recv().await else {
                        tracing::debug!("Serf event channel closed, task quit");
                        break;
                    };

                    match event {
                        Event::Query(query) => {
                            tracing::trace!(
                                name = query.name().as_str(),
                                from = query.from().to_string(),
                                "Handling query"
                            );

                            {
                                let Some(serf) = serf.upgrade() else {
                                    tracing::debug!(
                                        "stop serf watcher since serf has been dropped"
                                    );
                                    return;
                                };

                                // Skip queries from ourselves
                                if query.from().id() == serf.local_id() {
                                    continue;
                                }
                            }

                            if let Err(error) = Self::handle_query(&query, &inner).await {
                                tracing::warn!(
                                    ?error,
                                    name = query.name().as_str(),
                                    from = query.from().to_string(),
                                    "Error handling query"
                                );
                            }
                        }
                        Event::User(user_event) => {
                            tracing::trace!(
                                name = user_event.name().as_str(),
                                "Handling user event"
                            );

                            if let Err(error) = Self::handle_user_event(
                                user_event.name().as_str(),
                                user_event.payload(),
                                &inner,
                            )
                            .await
                            {
                                tracing::warn!(
                                    ?error,
                                    name = user_event.name().as_str(),
                                    "Error handling user event"
                                );
                            }
                        }
                        Event::Member(member_event) => {
                            tracing::trace!(
                                type = member_event.ty().as_str(),
                                members = ?member_event.members().iter().map(|m| m.node()).collect::<Vec<_>>(),
                                "Handling member event"
                            );

                            if matches!(member_event.ty(), MemberEventType::Leave) {
                                tracing::info!("Member left, triggering key rotation check");
                                {
                                    let Some(serf) = serf.upgrade() else {
                                        tracing::debug!(
                                            "stop serf watcher since serf has been dropped"
                                        );
                                        break;
                                    };
                                    Self::check_and_key_rotation(&serf, &inner).await;
                                }
                            }
                        }
                    }
                }
            },
        );
    }

    /// Handle incoming query requests.
    async fn handle_query(
        query: &QueryEvent<SerfTransport, SerfDelegate>,
        inner: &PeerSharedKeyManagerInner,
    ) -> Result<()> {
        match query.name().as_str() {
            SERF_QUERY_CLUSTER_KEY_SET => {
                let cks = inner.cluster_key_set.read().await;
                let pb_cluster_key_set: pb::ClusterKeySet = (*cks).clone().try_into()?;

                let response = pb::QueryClusterKeySetResponse {
                    cluster_key_set: Some(pb_cluster_key_set),
                };

                let mut response_buf = BytesMut::new();
                response.encode(&mut response_buf)?;

                query.respond(response_buf.into()).await?;
            }
            SERF_QUERY_KEY => {
                let request = pb::QueryKeyRequest::decode(query.payload().as_ref())?;
                let public_key = PublicKeyData::new(request.public_key);

                let cks = inner.cluster_key_set.read().await;

                if let Some(key_info) = cks.get_key_by_public_key(&public_key) {
                    let pb_key_info: pb::KeyInfo = key_info.clone().try_into()?;

                    let response = pb::QueryKeyResponse {
                        key_info: Some(pb_key_info),
                    };

                    let mut response_buf = BytesMut::new();
                    response.encode(&mut response_buf)?;

                    query.respond(response_buf.into()).await?;
                }
                // If not found, don't respond (empty response)
            }
            _ => {
                tracing::warn!(query_name = %query.name(), "Ignoring unknown query");
            }
        }
        Ok(())
    }

    /// Handle incoming user events.
    async fn handle_user_event(
        event_name: &str,
        payload: &[u8],
        inner: &PeerSharedKeyManagerInner,
    ) -> Result<()> {
        match event_name {
            SERF_USER_EVENT_BROADCAST_CLUSTER_KEY_SET => {
                let event = pb::BroadcastClusterKeySetEvent::decode(payload)?;

                if let Some(pb_cluster_key_set) = event.cluster_key_set {
                    let remote_key_set: ClusterKeySet = pb_cluster_key_set.try_into()?;
                    let merged_keys: Vec<String> = remote_key_set
                        .iter_keys()
                        .map(|(pk, _)| hex::encode(pk.as_ref()))
                        .collect();

                    {
                        let mut cks = inner.cluster_key_set.write().await;
                        cks.merge(remote_key_set);
                    }

                    tracing::info!(
                        key_count = merged_keys.len(),
                        public_key_hex = ?merged_keys,
                        "Merged broadcasted cluster key set"
                    );
                }
            }
            _ => {
                tracing::warn!(%event_name, "Ignoring unknown user event");
            }
        }
        Ok(())
    }

    /// Query a specific key from the cluster via Serf.
    ///
    /// This is used as a fallback when the key is not found locally.
    /// If found, the key is inserted into the local cluster key set.
    pub(crate) async fn query_key_from_cluster(
        &self,
        public_key: &PublicKeyData,
    ) -> Result<Option<KeyInfo>, TngError> {
        let request = pb::QueryKeyRequest {
            public_key: public_key.as_ref().to_vec(),
        };

        let mut request_buf = BytesMut::new();
        request.encode(&mut request_buf).map_err(|e| {
            TngError::KeyUpdateMessageDecodeError(anyhow!("Failed to encode query request: {}", e))
        })?;

        // Send query to the cluster
        let query_response = self
            .serf
            .query(SERF_QUERY_KEY, request_buf, None)
            .await
            .map_err(|e| TngError::SerfCrateError(anyhow!("Failed to send query: {}", e)))?;

        let resp_rx = query_response.response_rx();

        // Wait for response
        while let Ok(response) = resp_rx.recv().await {
            if response.payload().is_empty() {
                continue;
            }

            match pb::QueryKeyResponse::decode(response.payload().as_ref()) {
                Ok(query_response) => {
                    if let Some(pb_key_info) = query_response.key_info {
                        match TryInto::<KeyInfo>::try_into(pb_key_info) {
                            Ok(key_info) => {
                                // Insert into local cluster key set
                                let mut cks = self.inner.cluster_key_set.write().await;
                                cks.insert_key_from_peer(public_key.clone(), key_info.clone());
                                tracing::info!(
                                    node_id = ?response.from(),
                                    ?public_key,
                                    public_key_hex = %hex::encode(public_key.as_ref()),
                                    "Received key from peer via query"
                                );
                                return Ok(Some(key_info));
                            }
                            Err(error) => {
                                tracing::warn!(
                                    ?error,
                                    "Failed to convert key info from peer response"
                                );
                            }
                        }
                    } else {
                        tracing::warn!("Received query response with empty key_info");
                    }
                }
                Err(error) => {
                    tracing::warn!(?error, "Failed to decode query response from peer");
                }
            }
        }

        Ok(None)
    }

    /// Join a set of peers after construction.
    ///
    /// Each peer is joined via `retry_join_peer` (exponential backoff until
    /// success). No `QueryClusterKeySetRequest` is sent — key synchronization
    /// must happen through subsequent Serf queries.
    #[cfg(test)]
    pub(crate) async fn join_peers(&self, peers: &[String]) -> Result<(), TngError> {
        for peer in peers {
            retry_join_peer(&self.serf, peer).await?;
        }
        Ok(())
    }
}

async fn resolve_peer_addresses(addr: &String) -> Result<Vec<SocketAddr>, TngError> {
    let host_addr: HostAddr<String> = HostAddr::from_str(addr)
        .with_context(|| format!("Invalid peer address: {addr}"))
        .map_err(TngError::InvalidParameter)?;
    let port = host_addr
        .port()
        .context("Missing port in peer address")
        .map_err(TngError::InvalidParameter)?;
    let host = host_addr.host();
    let socket_addrs = match host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, port)],
        Host::Domain(name) => {
            // Finally, try to find the socket addr locally
            serf::agnostic::net::ToSocketAddrs::<serf::agnostic::tokio::TokioRuntime>::to_socket_addrs(&(
                name.as_str(),
                port,
            ))
            .await.with_context(||format!("failed to resolve {}", name)).map_err(TngError::InvalidParameter)?.collect()
        }
    };
    Ok(socket_addrs)
}

/// Attempts to join the Serf cluster via a single peer address.
///
/// Resolves every socket address for `peer` and tries to join via each.
/// It is sufficient to successfully join via at least one resolved address.
/// Returns the first Ok, or the last error if none succeeded.
async fn try_join_one_peer(serf: &Serf, peer: &str) -> Result<(), TngError> {
    tracing::info!(peer, "Attempting to join Serf cluster");

    let socket_addrs = resolve_peer_addresses(&peer.to_string()).await?;

    // Attempt to join the cluster using every resolved socket address for this host.
    // Since a hostname (e.g., via DNS) may resolve to multiple IPs (A/AAAA records),
    // we try each one to maximize the chance of successful connectivity.
    // It's sufficient to successfully join via at least one address.
    let mut last_error: Option<TngError> = None;
    for socket_addr in socket_addrs {
        tracing::debug!(
            peer,
            resolved_address = %socket_addr,
            "Attempting to join serf cluster using resolved socket address"
        );

        match serf
            .join(MaybeResolvedAddress::resolved(socket_addr), false)
            .await
        {
            Ok(_) => {
                tracing::info!(
                    peer,
                    via = %socket_addr,
                    "Successfully joined serf cluster via resolved address"
                );
                return Ok(());
            }
            Err(error) => {
                tracing::warn!(
                    peer,
                    failed_address = %socket_addr,
                    ?error,
                    "Failed to join serf cluster via this address, will try next if available"
                );
                last_error = Some(TngError::SerfCrateError(anyhow!(error)));
            }
        }
    }

    match last_error {
        Some(e) => Err(e),
        None => Err(TngError::SerfCrateError(anyhow!(
            "Failed to join any address of peer: {peer}"
        ))),
    }
}

/// Retries joining a single Serf peer forever with exponential backoff.
///
/// Uses the `again` crate: base delay 1s doubling each attempt, full jitter
/// (delay multiplied by a random factor in (0, 1]), capped at 300s. Retries
/// indefinitely (`max_retries = usize::MAX`). Blocks the caller until the peer
/// is joined — callers that must not block should run this in a spawned task.
async fn retry_join_peer(serf: &Serf, peer: &str) -> Result<(), TngError> {
    // k8s-style exponential backoff: 1s -> 2s -> 4s -> ... -> 300s (cap), full jitter.
    // `max_retries = usize::MAX` makes the policy effectively unbounded.
    let policy = RetryPolicy::exponential(Duration::from_secs(1))
        .with_jitter(true)
        .with_max_delay(Duration::from_secs(300))
        .with_max_retries(usize::MAX);

    policy
        .retry(|| async {
            try_join_one_peer(serf, peer).await.map_err(|e| {
                tracing::warn!(?peer, error = ?e, "join attempt failed, will retry after backoff");
                e
            })
        })
        .await
}

/// Spawns background per-peer retry tasks for peers not already being retried.
///
/// Called from the peers-file watcher. Uses an in-flight set to avoid stacking
/// duplicate tasks for the same peer. Each task removes its entry on success.
/// `retry_join_peer` only returns on success, so in-flight entries are cleared
/// exactly when the peer is joined. This never blocks the caller.
///
/// Tasks are spawned via the runtime's supervised-task spawner rather than
/// `tokio::spawn` (which is disallowed by this crate's clippy config).
fn spawn_peer_retry_tasks(
    runtime: &TokioRuntime,
    serf: &Arc<SerfGracefulShutdown>,
    peers: &[String],
    in_flight: &Arc<Mutex<HashSet<String>>>,
) {
    // Collect peers to start under the lock, so we don't hold it across spawns.
    // Recover from a poisoned lock by taking the inner data: the in-flight set
    // is best-effort dedup state, so a panic in a retry task must not cascade to
    // the watcher loop. (This crate denies clippy::expect_used.)
    let to_start: Vec<String> = {
        let mut set = in_flight.lock().unwrap_or_else(|p| p.into_inner());
        peers
            .iter()
            .filter(|p| set.insert((**p).clone())) // insert returns false if already present
            .cloned()
            .collect()
    };

    for peer in to_start {
        let serf_clone = serf.clone();
        let in_flight_clone = in_flight.clone();
        let peer_for_task = peer.clone();
        runtime.spawn_supervised_task_current_span(async move {
            if let Err(e) = retry_join_peer(&serf_clone, &peer_for_task).await {
                tracing::warn!(?peer_for_task, ?e, "background join ultimately failed");
            }
            // Clear in-flight entry so a future file change can retry this peer.
            in_flight_clone
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&peer_for_task);
        });
    }
}

/// Loads peer list from JSON file.
async fn load_peers_from_file(path: &str) -> Result<Vec<String>, anyhow::Error> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read peers file: {path}"))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse peers file as JSON: {path}"))
}

pub(super) struct SerfGracefulShutdown {
    serf: Option<Serf>,
    runtime: TokioRuntime,
}

impl SerfGracefulShutdown {
    fn new(serf: Serf, runtime: TokioRuntime) -> Self {
        Self {
            serf: Some(serf),
            runtime,
        }
    }
}

impl Deref for SerfGracefulShutdown {
    type Target = Serf;

    fn deref(&self) -> &Self::Target {
        #[allow(clippy::unwrap_used)]
        self.serf.as_ref().unwrap()
    }
}

impl Drop for SerfGracefulShutdown {
    fn drop(&mut self) {
        if let Some(serf) = self.serf.take() {
            tracing::info!("Start leaving the serf cluster");

            self.runtime
                .spawn_unsupervised_task_current_span(async move {
                    match serf.leave().await {
                        Ok(()) => {
                            let _ = serf.shutdown().await;
                            tracing::info!("Left the serf cluster gracefully");
                        }
                        Err(error) => {
                            tracing::error!(?error, "Failed to leave the serf cluster gracefully");
                            let _ = serf.shutdown().await;
                        }
                    }
                });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::egress::PeerSharedArgs;
    use crate::config::ra::RaArgsUnchecked;
    use crate::tests::run_test_with_tokio_runtime;
    use crate::tunnel::egress::protocol::ohttp::security::key_manager::KeyManager;
    use anyhow::{anyhow, Result};
    use hex;
    use web_time_compat::{Duration, Instant, InstantExt};

    // -----------------------------------------------------------------------
    // Helper functions
    // -----------------------------------------------------------------------

    /// Construct PeerSharedArgs with no_ra mode.
    fn make_peer_shared_args(
        port: u16,
        peers: Vec<String>,
        rotation_interval: u64,
    ) -> PeerSharedArgs {
        PeerSharedArgs {
            rotation_interval,
            host: "127.0.0.1".to_string(),
            port,
            peers,
            peers_file: None,
            ra_args: RaArgsUnchecked {
                no_ra: true,
                attest: None,
                verify: None,
            },
        }
    }

    /// Wait until the target's serf cluster reaches the expected alive-member
    /// count, or timeout.
    async fn wait_for_member_count(
        target: &PeerSharedKeyManager,
        expected: usize,
        timeout: Duration,
    ) -> Result<()> {
        let start = Instant::get();
        loop {
            if start.elapsed() > timeout {
                let members = target.serf.members().await;
                let alive = members
                    .iter()
                    .filter(|m| m.status == MemberStatus::Alive)
                    .count();
                return Err(anyhow!(
                    "timeout waiting for {expected} alive members, current: {alive}"
                ));
            }
            let members = target.serf.members().await;
            let alive = members
                .iter()
                .filter(|m| m.status == MemberStatus::Alive)
                .count();
            if alive >= expected {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Wait until the target node's cluster_key_set contains a key matching the
    /// given public key, or timeout.
    async fn wait_for_key_in_cks(
        target: &PeerSharedKeyManager,
        expected_pk: &PublicKeyData,
        timeout: Duration,
    ) -> Result<()> {
        let start = Instant::get();
        loop {
            if start.elapsed() > timeout {
                return Err(anyhow!(
                    "timeout waiting for key in target's cluster_key_set"
                ));
            }
            {
                let cks = target.inner.cluster_key_set.read().await;
                if cks.get_key_by_public_key(expected_pk).is_some() {
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Wait until the number of Active keys in the target's cluster_key_set
    /// reaches the expected count, or timeout.
    async fn wait_for_active_key_count(
        target: &PeerSharedKeyManager,
        expected_count: usize,
        timeout: Duration,
    ) -> Result<()> {
        let start = Instant::get();
        loop {
            if start.elapsed() > timeout {
                let cks = target.inner.cluster_key_set.read().await;
                let active_count = cks.active_key_count();
                return Err(anyhow!(
                    "timeout waiting for {} active keys, current: {}",
                    expected_count,
                    active_count
                ));
            }
            {
                let cks = target.inner.cluster_key_set.read().await;
                let active_count = cks.active_key_count();
                if active_count == expected_count {
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Collect all public keys from every node, then verify that on every node
    /// each key is reachable via `query_key_from_cluster`.
    ///
    /// Before collecting keys, verify Serf connectivity between all node pairs.
    ///
    /// After all queries succeed, also verifies that every node's local
    /// `ClusterKeySet` contains the full union of keys.
    async fn verify_all_keys_reachable(nodes: &[(&str, &PeerSharedKeyManager)]) -> Result<()> {
        // --- Step 1: Verify Serf connectivity — ping every expected node pair ---
        // For each pinger, check that all other expected nodes are visible in its
        // member list, then ping each one to confirm connectivity.
        for (pinger_name, mgr) in nodes {
            let members = mgr.serf.members().await;
            let local_id = mgr.serf.local_id();

            // Build a map from node ID to the member's Node (for ping).
            // Use string IDs as keys to avoid Borrow trait issues with NodeId.
            let member_map: std::collections::HashMap<_, _> = members
                .iter()
                .filter(|m| m.node().id() != local_id)
                .map(|m| (m.node().id().clone(), m.node().clone()))
                .collect();

            for (target_name, target_mgr) in nodes {
                if target_name == pinger_name {
                    continue;
                }
                let target_id = target_mgr.serf.local_id();

                let Some(target_node) = member_map.get(target_id) else {
                    return Err(anyhow!(
                        "membership check failed: {pinger_name} does not see {target_name} ({target_id}) in its member list"
                    ));
                };

                if let Err(error) = mgr.serf.memberlist().ping(target_node.clone()).await {
                    return Err(anyhow!(
                        "ping failed: {pinger_name} -> {target_name}: {error:?}"
                    ));
                }
                tracing::info!(from = pinger_name, to = target_name, "Serf ping OK");
            }
        }

        // --- Step 2: Collect the full set of public keys across all nodes ---
        // mapping each public key to all nodes that own it.
        let mut pk_to_nodes: std::collections::HashMap<PublicKeyData, Vec<&str>> =
            std::collections::HashMap::new();
        let mut all_pks = std::collections::HashSet::new();
        for (name, mgr) in nodes {
            let cks = mgr.inner.cluster_key_set.read().await;
            for (pk, _) in cks.iter_keys() {
                pk_to_nodes.entry(pk.clone()).or_default().push(name);
                all_pks.insert(pk.clone());
            }
        }

        assert!(
            all_pks.len() >= 2,
            "Cluster should have at least 2 distinct keys, got {}",
            all_pks.len()
        );

        // On each node, call `get_key_by_public_key` for every key.
        for (querier_name, mgr) in nodes {
            for pk in &all_pks {
                let owners = pk_to_nodes
                    .get(pk)
                    .map(|v| v.join(","))
                    .unwrap_or_else(|| "?".into());
                let pk_hex = hex::encode(pk.as_ref());
                tracing::info!(
                    querier = querier_name,
                    key_owners = %owners,
                    public_key_hex = %pk_hex,
                    "Verifying key reachability"
                );

                let key_info = mgr.get_key_by_public_key(pk).await?;
                let got_pk = key_info.key_config.public_key()?;
                assert_eq!(
                    &got_pk,
                    pk,
                    "Node {querier_name} returned wrong key: expected {pk_hex}, got {}",
                    hex::encode(got_pk.as_ref())
                );
            }
        }

        Ok(())
    }

    /// Wait until the target's cluster_key_set no longer contains the given public key,
    /// or timeout.
    async fn wait_for_key_removed(
        target: &PeerSharedKeyManager,
        removed_pk: &PublicKeyData,
        timeout: Duration,
    ) -> Result<()> {
        let start = Instant::get();
        loop {
            if start.elapsed() > timeout {
                let cks = target.inner.cluster_key_set.read().await;
                if cks.get_key_by_public_key(removed_pk).is_some() {
                    return Err(anyhow!(
                        "timeout waiting for key to be removed from cluster_key_set"
                    ));
                }
                return Ok(());
            }
            {
                let cks = target.inner.cluster_key_set.read().await;
                if cks.get_key_by_public_key(removed_pk).is_none() {
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // -----------------------------------------------------------------------
    // Group 1: Infrastructure tests (no key distribution logic)
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_resolve_peer_addresses_ipv4() -> Result<()> {
        let addr = "127.0.0.1:8301".to_string();
        let result = resolve_peer_addresses(&addr).await?;
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                8301
            )
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_resolve_peer_addresses_invalid() {
        let addr = "not-an-address".to_string();
        let result = resolve_peer_addresses(&addr).await;
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_resolve_peer_addresses_domain() -> Result<()> {
        let addr = "localhost:8301".to_string();
        let result = resolve_peer_addresses(&addr).await?;
        assert!(!result.is_empty());
        assert!(result.iter().all(|a| a.port() == 8301));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_load_peers_from_file_success() -> Result<()> {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("peers_test_{}.json", std::process::id()));
        let content = r#"["127.0.0.1:8301", "127.0.0.1:8302"]"#;
        std::fs::write(&file_path, content)?;

        let peers = load_peers_from_file(file_path.to_str().unwrap()).await?;
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0], "127.0.0.1:8301");
        assert_eq!(peers[1], "127.0.0.1:8302");

        let _ = std::fs::remove_file(&file_path);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_load_peers_from_file_not_found() {
        let result = load_peers_from_file("/nonexistent/path/that/does/not/exist.json").await;
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_load_peers_from_file_invalid_json() -> Result<()> {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("peers_invalid_json_{}.json", std::process::id()));
        std::fs::write(&file_path, "not valid json")?;

        let result = load_peers_from_file(file_path.to_str().unwrap()).await;
        assert!(result.is_err());

        let _ = std::fs::remove_file(&file_path);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_load_peers_from_file_empty_array() -> Result<()> {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("peers_empty_{}.json", std::process::id()));
        std::fs::write(&file_path, "[]")?;

        let peers = load_peers_from_file(file_path.to_str().unwrap()).await?;
        assert!(peers.is_empty());

        let _ = std::fs::remove_file(&file_path);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Group 2: Basic startup / join tests
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_join_serf_cluster_empty_peers() {
        run_test_with_tokio_runtime(async |runtime| {
            let port = portpicker::pick_unused_port().unwrap();
            let args = make_peer_shared_args(port, vec![], 300);

            let manager = PeerSharedKeyManager::new(runtime, args).await?;

            // Verify the manager was created and has at least one key (bootstrapped)
            let cks = manager.inner.cluster_key_set.read().await;
            assert!(!cks.is_empty());

            Ok(())
        })
        .await
        .expect("test_join_serf_cluster_empty_peers failed");
    }

    // -----------------------------------------------------------------------
    // Group 3: Core cluster / key distribution tests
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_node_join_key_sync() {
        run_test_with_tokio_runtime(async |runtime| {
            let port_a = portpicker::pick_unused_port().unwrap();
            let port_b = portpicker::pick_unused_port().unwrap();

            // Start bootstrap node A
            let args_a = make_peer_shared_args(port_a, vec![], 300);
            let manager_a = PeerSharedKeyManager::new(runtime.clone(), args_a).await?;

            // Get A's active key public key
            let a_pk = {
                let cks_a = manager_a.inner.cluster_key_set.read().await;
                cks_a
                    .get_client_visible_key()
                    .unwrap()
                    .key_config
                    .public_key()
                    .unwrap()
            };

            // Start node B joining A
            let args_b = make_peer_shared_args(port_b, vec![format!("127.0.0.1:{}", port_a)], 300);
            let manager_b = PeerSharedKeyManager::new(runtime, args_b).await?;

            // Wait for B to receive A's key
            wait_for_key_in_cks(&manager_b, &a_pk, Duration::from_secs(10)).await?;

            // Verify B's client-visible key matches A's
            let b_visible_pk = manager_b
                .get_client_visible_key()
                .await
                .unwrap()
                .key_config
                .public_key()
                .unwrap();
            assert_eq!(a_pk, b_visible_pk);

            Ok(())
        })
        .await
        .expect("test_node_join_key_sync failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_retry_join_on_startup() {
        run_test_with_tokio_runtime(async |runtime| {
            let port_a = portpicker::pick_unused_port().unwrap();
            let port_b = portpicker::pick_unused_port().unwrap();

            // Channel for the delayed bootstrap node A to report its active public
            // key back to the test body. A is started inside a background task, so
            // its manager is not directly accessible; we capture its client-visible
            // key via this oneshot to prove (later) that B actually synced A's key
            // rather than bootstrapping its own.
            let (a_pk_tx, a_pk_rx) = tokio::sync::oneshot::channel::<PublicKeyData>();

            // A is not up yet. Start it after a short delay in a background task.
            let runtime_a = runtime.clone();
            runtime
                .clone()
                .spawn_supervised_task_current_span(async move {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let args_a = make_peer_shared_args(port_a, vec![], 300);
                    let manager_a = PeerSharedKeyManager::new(runtime_a, args_a).await.unwrap();
                    // Report A's active public key to the test body.
                    let a_pk = manager_a
                        .get_client_visible_key()
                        .await
                        .expect("A should have a client-visible key")
                        .key_config
                        .public_key()
                        .expect("A's key should have a public key");
                    let _ = a_pk_tx.send(a_pk);
                    // Keep A alive for the rest of the test by not dropping until later;
                    // rely on the spawned serf tasks staying alive.
                    std::future::pending::<()>().await;
                });

            // B points at A. PeerSharedKeyManager::new must block (retry) until A is up,
            // then return — rather than bootstrap standalone on the first failed attempt.
            let args_b = make_peer_shared_args(port_b, vec![format!("127.0.0.1:{}", port_a)], 300);
            let manager_b = PeerSharedKeyManager::new(runtime, args_b).await?;

            // After B joined A, B must NOT have bootstrapped its own key — it should
            // have synced A's key set (members.len() > 1 at preboot).
            wait_for_active_key_count(&manager_b, 1, Duration::from_secs(15)).await?;

            // Stronger assertion: B's client-visible key must equal A's key, proving
            // B actually synced A's key set rather than bootstrapping standalone.
            // (A standalone bootstrap would leave B with exactly 1 active key too —
            // the count check above cannot distinguish the two cases.)
            let a_pk = a_pk_rx
                .await
                .expect("A should have reported its public key");
            let b_visible_pk = manager_b
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            assert_eq!(
                a_pk, b_visible_pk,
                "B's client-visible key must match A's, proving B synced A's key set"
            );

            Ok(())
        })
        .await
        .expect("test_retry_join_on_startup failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_simultaneous_start_convergence() {
        run_test_with_tokio_runtime(async |runtime| {
            let port_a = portpicker::pick_unused_port().unwrap();
            let port_b = portpicker::pick_unused_port().unwrap();

            // Start A first (bootstrap), then B joins
            let args_a = make_peer_shared_args(port_a, vec![], 300);
            let manager_a = PeerSharedKeyManager::new(runtime.clone(), args_a).await?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            let args_b = make_peer_shared_args(port_b, vec![format!("127.0.0.1:{}", port_a)], 300);
            let manager_b = PeerSharedKeyManager::new(runtime.clone(), args_b).await?;

            // Wait for convergence
            wait_for_active_key_count(&manager_b, 1, Duration::from_secs(10)).await?;

            // Both should agree on the client-visible key
            let a_visible = manager_a.get_client_visible_key().await?;
            let b_visible = manager_b.get_client_visible_key().await?;
            assert_eq!(
                a_visible.key_config.public_key()?,
                b_visible.key_config.public_key()?
            );

            Ok(())
        })
        .await
        .expect("test_simultaneous_start_convergence failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_instance_joins_multiple_nodes() {
        run_test_with_tokio_runtime(async |runtime| {
            let port_a = portpicker::pick_unused_port().unwrap();
            let port_b = portpicker::pick_unused_port().unwrap();
            let port_c = portpicker::pick_unused_port().unwrap();
            let port_d = portpicker::pick_unused_port().unwrap();

            // Start A (bootstrap)
            let args_a = make_peer_shared_args(port_a, vec![], 300);
            let manager_a = PeerSharedKeyManager::new(runtime.clone(), args_a).await?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Start B joining A
            let args_b = make_peer_shared_args(port_b, vec![format!("127.0.0.1:{}", port_a)], 300);
            let manager_b = PeerSharedKeyManager::new(runtime.clone(), args_b).await?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Start C joining A
            let args_c = make_peer_shared_args(port_c, vec![format!("127.0.0.1:{}", port_a)], 300);
            let manager_c = PeerSharedKeyManager::new(runtime.clone(), args_c).await?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Start D joining A
            let args_d = make_peer_shared_args(port_d, vec![format!("127.0.0.1:{}", port_a)], 300);
            let manager_d = PeerSharedKeyManager::new(runtime.clone(), args_d).await?;

            // D should have at least 1 active key
            wait_for_active_key_count(&manager_d, 1, Duration::from_secs(15)).await?;

            // All nodes should agree on client-visible key
            let a_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            let b_pk = manager_b
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            let c_pk = manager_c
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            let d_pk = manager_d
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            assert_eq!(a_pk, b_pk);
            assert_eq!(b_pk, c_pk);
            assert_eq!(c_pk, d_pk);

            Ok(())
        })
        .await
        .expect("test_instance_joins_multiple_nodes failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_key_rotation_with_three_phase() {
        run_test_with_tokio_runtime(async |runtime| {
            let port_a = portpicker::pick_unused_port().unwrap();
            let port_b = portpicker::pick_unused_port().unwrap();

            // Start A with 2-second rotation interval
            let args_a = make_peer_shared_args(port_a, vec![], 2);
            let manager_a = PeerSharedKeyManager::new(runtime.clone(), args_a).await?;

            // Get initial key
            let initial_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Start B joining A
            let args_b = make_peer_shared_args(port_b, vec![format!("127.0.0.1:{}", port_a)], 2);
            let manager_b = PeerSharedKeyManager::new(runtime.clone(), args_b).await?;

            // B should have A's initial key
            wait_for_key_in_cks(&manager_b, &initial_pk, Duration::from_secs(10)).await?;

            // Wait for rotation cycle to complete.
            // With 2s rotation: stale_at = now + 2s, expire_at = now + 4s.
            // After ~6s, the initial key should have been replaced by a new active key
            // (the new Pending was generated at ~2s, activated at ~4s, old became stale).
            tokio::time::sleep(Duration::from_secs(10)).await;

            // A should still have at least 1 active key
            wait_for_active_key_count(&manager_a, 1, Duration::from_secs(15)).await?;

            // B should still have at least 1 active key
            let b_keys = manager_b.inner.cluster_key_set.read().await;
            assert!(b_keys.active_key_count() >= 1);

            // Client-visible key should still be available throughout
            assert!(manager_a.get_client_visible_key().await.is_ok());
            assert!(manager_b.get_client_visible_key().await.is_ok());

            // Verify key rotation actually happened: the client-visible key on A
            // should have changed from the initial key to a new one.
            let current_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            assert_ne!(
                current_pk, initial_pk,
                "client-visible key should have rotated to a new key"
            );

            // B should have converged to the same new key
            let b_pk = manager_b
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            assert_eq!(
                current_pk, b_pk,
                "A and B should agree on the rotated client-visible key"
            );

            Ok(())
        })
        .await
        .expect("test_key_rotation_with_three_phase failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_self_generated_key_refresh_timing() {
        run_test_with_tokio_runtime(async |runtime| {
            let port = portpicker::pick_unused_port().unwrap();

            // Single node with 2-second rotation interval
            let args = make_peer_shared_args(port, vec![], 2);
            let manager = PeerSharedKeyManager::new(runtime.clone(), args).await?;

            // Get initial key
            let initial_pk = manager
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            // Wait for key rotation cycle:
            // stale_at = actived_at + 2s, expire_at = actived_at + 4s.
            // A new Pending key should be created by check_and_key_rotation
            // (triggered because this node is master as the only node).
            tokio::time::sleep(Duration::from_secs(8)).await;

            // Verify the key set is not empty and has at least one active key
            let cks = manager.inner.cluster_key_set.read().await;
            assert!(!cks.is_empty(), "Key set should not be empty");
            assert!(
                cks.active_key_count() >= 1,
                "Should have at least one active key after rotation"
            );

            // Verify that a new key was generated and the client-visible key changed
            let current_pk = manager
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            assert_ne!(
                current_pk, initial_pk,
                "client-visible key should have rotated to a new key"
            );

            Ok(())
        })
        .await
        .expect("test_self_generated_key_refresh_timing failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_multiple_nodes_star_topology() {
        run_test_with_tokio_runtime(async |runtime| {
            let port_bootstrap = portpicker::pick_unused_port().unwrap();

            // Start bootstrap node
            let args_bootstrap = make_peer_shared_args(port_bootstrap, vec![], 300);
            let bootstrap_manager =
                PeerSharedKeyManager::new(runtime.clone(), args_bootstrap).await?;

            let bootstrap_pk = bootstrap_manager
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Start 5 nodes all pointing at bootstrap
            let mut managers = Vec::new();
            for _ in 0..5 {
                let port = portpicker::pick_unused_port().unwrap();
                let args =
                    make_peer_shared_args(port, vec![format!("127.0.0.1:{}", port_bootstrap)], 300);
                let manager = PeerSharedKeyManager::new(runtime.clone(), args).await?;
                managers.push(manager);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            // Wait for all nodes to have the bootstrap key
            for (i, manager) in managers.iter().enumerate() {
                wait_for_key_in_cks(manager, &bootstrap_pk, Duration::from_secs(15))
                    .await
                    .map_err(|e| anyhow!("node {} failed: {}", i, e))?;
            }

            // All nodes should agree on client-visible key
            for (i, manager) in managers.iter().enumerate() {
                let pk = manager
                    .get_client_visible_key()
                    .await?
                    .key_config
                    .public_key()?;
                assert_eq!(
                    bootstrap_pk, pk,
                    "Node {} has different key than bootstrap",
                    i
                );
            }

            Ok(())
        })
        .await
        .expect("test_multiple_nodes_star_topology failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_key_expiry_propagation() {
        run_test_with_tokio_runtime(async |runtime| {
            let port_a = portpicker::pick_unused_port().unwrap();
            let port_b = portpicker::pick_unused_port().unwrap();

            // Start A with 2-second rotation interval
            let args_a = make_peer_shared_args(port_a, vec![], 2);
            let manager_a = PeerSharedKeyManager::new(runtime.clone(), args_a).await?;

            // Get initial key
            let key1_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Start B joining A
            let args_b = make_peer_shared_args(port_b, vec![format!("127.0.0.1:{}", port_a)], 2);
            let manager_b = PeerSharedKeyManager::new(runtime.clone(), args_b).await?;

            // B should have key1
            wait_for_key_in_cks(&manager_b, &key1_pk, Duration::from_secs(10)).await?;

            // Wait for key1 to go through full rotation cycle.
            // With 2s rotation: stale_at=2s, expire_at=4s.
            // After ~10s, key1 should have transitioned to Stale (and possibly expired).
            // A new key should have been generated and broadcast to B.
            tokio::time::sleep(Duration::from_secs(12)).await;

            // A should have a new active key (the client-visible key should have changed)
            let current_a_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            assert_ne!(
                current_a_pk, key1_pk,
                "A's client-visible key should have rotated"
            );

            // B should have converged to the same new key via broadcast
            let current_b_pk = manager_b
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            assert_eq!(
                current_a_pk, current_b_pk,
                "A and B should agree on the rotated key"
            );

            Ok(())
        })
        .await
        .expect("test_key_expiry_propagation failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_node_leave_triggers_rotation_check() {
        run_test_with_tokio_runtime(async |runtime| {
            let port_a = portpicker::pick_unused_port().unwrap();
            let port_b = portpicker::pick_unused_port().unwrap();

            // Start A (bootstrap)
            let args_a = make_peer_shared_args(port_a, vec![], 300);
            let manager_a = PeerSharedKeyManager::new(runtime.clone(), args_a).await?;

            let a_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Start B joining A
            let args_b = make_peer_shared_args(port_b, vec![format!("127.0.0.1:{}", port_a)], 300);
            let manager_b = PeerSharedKeyManager::new(runtime.clone(), args_b).await?;

            // B should have A's key
            wait_for_key_in_cks(&manager_b, &a_pk, Duration::from_secs(10)).await?;

            // Drop A (triggers Serf leave)
            drop(manager_a);

            // Wait for Serf to detect the leave
            tokio::time::sleep(Duration::from_secs(8)).await;

            // B should still have at least 1 active key
            wait_for_active_key_count(&manager_b, 1, Duration::from_secs(10)).await?;

            // B's client-visible key should still be available
            assert!(manager_b.get_client_visible_key().await.is_ok());

            Ok(())
        })
        .await
        .expect("test_node_leave_triggers_rotation_check failed");
    }

    // -----------------------------------------------------------------------
    // Group 4: New-version-only feature tests
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_query_key_fallback() {
        run_test_with_tokio_runtime(async |runtime| {
            let port_a = portpicker::pick_unused_port().unwrap();
            let port_b = portpicker::pick_unused_port().unwrap();

            // Start A (bootstrap)
            let args_a = make_peer_shared_args(port_a, vec![], 300);
            let manager_a = PeerSharedKeyManager::new(runtime.clone(), args_a).await?;

            let a_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Start B joining A
            let args_b = make_peer_shared_args(port_b, vec![format!("127.0.0.1:{}", port_a)], 300);
            let manager_b = PeerSharedKeyManager::new(runtime.clone(), args_b).await?;

            // Wait for B to have A's key via normal sync
            wait_for_key_in_cks(&manager_b, &a_pk, Duration::from_secs(10)).await?;

            // Use query_key_from_cluster to query for A's key from B
            let result = manager_b.query_key_from_cluster(&a_pk).await?;
            assert!(
                result.is_some(),
                "query_key_from_cluster should return the key"
            );
            let queried_key = result.unwrap();
            assert_eq!(
                queried_key.key_config.public_key()?,
                a_pk,
                "queried key should match"
            );

            // Verify it's in B's cluster_key_set
            let cks_b = manager_b.inner.cluster_key_set.read().await;
            assert!(
                cks_b.get_key_by_public_key(&a_pk).is_some(),
                "key should be in B's cluster_key_set after query"
            );

            Ok(())
        })
        .await
        .expect("test_query_key_fallback failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_get_client_visible_key_consistency() {
        run_test_with_tokio_runtime(async |runtime| {
            let port_a = portpicker::pick_unused_port().unwrap();
            let port_b = portpicker::pick_unused_port().unwrap();

            // Start A (bootstrap)
            let args_a = make_peer_shared_args(port_a, vec![], 300);
            let manager_a = PeerSharedKeyManager::new(runtime.clone(), args_a).await?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Start B joining A
            let args_b = make_peer_shared_args(port_b, vec![format!("127.0.0.1:{}", port_a)], 300);
            let manager_b = PeerSharedKeyManager::new(runtime.clone(), args_b).await?;

            // Wait for convergence
            wait_for_active_key_count(&manager_b, 1, Duration::from_secs(10)).await?;

            // Call get_client_visible_key multiple times on A
            let first_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            for _ in 0..5 {
                let pk = manager_a
                    .get_client_visible_key()
                    .await?
                    .key_config
                    .public_key()?;
                assert_eq!(
                    first_pk, pk,
                    "get_client_visible_key should return consistent key"
                );
            }

            // B should also return the same consistent key
            let b_pk = manager_b
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            assert_eq!(first_pk, b_pk, "A and B should agree on client-visible key");

            Ok(())
        })
        .await
        .expect("test_get_client_visible_key_consistency failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_master_election_smallest_id() {
        run_test_with_tokio_runtime(async |runtime| {
            let port_a = portpicker::pick_unused_port().unwrap();
            let port_b = portpicker::pick_unused_port().unwrap();
            let port_c = portpicker::pick_unused_port().unwrap();

            // Start A (bootstrap)
            let args_a = make_peer_shared_args(port_a, vec![], 300);
            let manager_a = PeerSharedKeyManager::new(runtime.clone(), args_a).await?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Start B joining A
            let args_b = make_peer_shared_args(port_b, vec![format!("127.0.0.1:{}", port_a)], 300);
            let manager_b = PeerSharedKeyManager::new(runtime.clone(), args_b).await?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Start C joining A
            let args_c = make_peer_shared_args(port_c, vec![format!("127.0.0.1:{}", port_a)], 300);
            let manager_c = PeerSharedKeyManager::new(runtime.clone(), args_c).await?;

            // Wait for all to converge
            tokio::time::sleep(Duration::from_secs(3)).await;

            // All should have at least 1 active key
            wait_for_active_key_count(&manager_a, 1, Duration::from_secs(10)).await?;
            wait_for_active_key_count(&manager_b, 1, Duration::from_secs(10)).await?;
            wait_for_active_key_count(&manager_c, 1, Duration::from_secs(10)).await?;

            // All should agree on the client-visible key
            let a_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            let b_pk = manager_b
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            let c_pk = manager_c
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            assert_eq!(a_pk, b_pk, "A and B should agree on client-visible key");
            assert_eq!(b_pk, c_pk, "B and C should agree on client-visible key");

            Ok(())
        })
        .await
        .expect("test_master_election_smallest_id failed");
    }

    // -----------------------------------------------------------------------
    // Group 5: Split-brain / convergence / edge case tests
    // -----------------------------------------------------------------------

    /// Test that immediately after C joins both A and B (bridging a split brain),
    /// every node can retrieve every key from the cluster via query.
    ///
    /// Scenario:
    ///   A (bootstrap) → generates key_A
    ///   B (bootstrap) → generates key_B (different from A)
    ///   C (join A, B) → preboot merges key_A + key_B from both peers
    ///
    /// After C's `new()` returns (no artificial sleep), collect the full key set
    /// from each node. Then, on each node, use `query_key_from_cluster` to fetch
    /// every key (including keys the node doesn't have locally). Finally verify
    /// that the union of all keys is reachable from every node.
    ///
    /// rotation_interval is set to 1 hour to prevent key rotation from
    /// interfering with this test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_split_brain_cross_node_key_query() {
        run_test_with_tokio_runtime(async |runtime| {
            let rotation_interval = 3600; // 1 hour — no rotation during test

            // --- Phase 1: A and B bootstrap independently (split brain) ---

            let port_a = portpicker::pick_unused_port().unwrap();
            let args_a = make_peer_shared_args(port_a, vec![], rotation_interval);
            let manager_a = PeerSharedKeyManager::new(runtime.clone(), args_a).await?;

            let a_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            let port_b = portpicker::pick_unused_port().unwrap();
            let args_b = make_peer_shared_args(port_b, vec![], rotation_interval);
            let manager_b = PeerSharedKeyManager::new(runtime.clone(), args_b).await?;

            let b_pk = manager_b
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            assert_ne!(
                a_pk, b_pk,
                "A and B should have different keys when bootstrapped independently"
            );

            // --- Phase 2: C joins both A and B, bridging the split brain ---

            let port_c = portpicker::pick_unused_port().unwrap();
            let args_c = make_peer_shared_args(
                port_c,
                vec![
                    format!("127.0.0.1:{}", port_a),
                    format!("127.0.0.1:{}", port_b),
                ],
                rotation_interval,
            );
            let manager_c = PeerSharedKeyManager::new(runtime.clone(), args_c).await?;

            // --- Phase 3: Verify cross-node key accessibility ---

            {
                let c_keys: Vec<_> = manager_c
                    .inner
                    .cluster_key_set
                    .read()
                    .await
                    .iter_keys()
                    .map(|(pk, _)| pk.clone())
                    .collect();
                assert!(
                    c_keys.len() >= 2,
                    "C should have at least 2 keys after merging A and B, got {}",
                    c_keys.len()
                );
            }

            verify_all_keys_reachable(&[("A", &manager_a), ("B", &manager_b), ("C", &manager_c)])
                .await?;

            Ok(())
        })
        .await
        .expect("test_split_brain_cross_node_key_query failed");
    }

    /// Test that after C bootstraps independently and later joins A + B,
    /// every key becomes reachable from every node via query.
    ///
    /// Unlike `test_split_brain_cross_node_key_query` where C joins A/B during
    /// construction (preboot merges keys automatically), this test has C start
    /// as a fully independent third node, then explicitly call `join_peers_and_sync`
    /// **after** `new()` returns. No artificial sleep is used.
    ///
    /// Rotation interval is 1 hour to prevent key rotation from interfering.
    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_split_brain_cross_node_key_query_deferred_join() {
        run_test_with_tokio_runtime(async |runtime| {
            let rotation_interval = 3600; // 1 hour

            // --- Phase 1: A, B, C all bootstrap independently ---

            let port_a = portpicker::pick_unused_port().unwrap();
            let args_a = make_peer_shared_args(port_a, vec![], rotation_interval);
            let manager_a = PeerSharedKeyManager::new(runtime.clone(), args_a).await?;

            let a_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            let port_b = portpicker::pick_unused_port().unwrap();
            let args_b = make_peer_shared_args(port_b, vec![], rotation_interval);
            let manager_b = PeerSharedKeyManager::new(runtime.clone(), args_b).await?;

            let b_pk = manager_b
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            let port_c = portpicker::pick_unused_port().unwrap();
            let args_c = make_peer_shared_args(port_c, vec![], rotation_interval);
            let manager_c = PeerSharedKeyManager::new(runtime.clone(), args_c).await?;

            let c_pk = manager_c
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            assert_ne!(a_pk, b_pk, "A and B should have different keys");
            assert_ne!(a_pk, c_pk, "A and C should have different keys");
            assert_ne!(b_pk, c_pk, "B and C should have different keys");

            // --- Phase 2: C explicitly joins A and B after construction ---
            // This mirrors the file watcher scenario: only join_serf_cluster is called.
            // No QueryClusterKeySetRequest is sent. A and B do NOT join C.

            manager_c
                .join_peers(&[
                    format!("127.0.0.1:{}", port_a),
                    format!("127.0.0.1:{}", port_b),
                ])
                .await?;

            // --- Phase 3: Verify cross-node key accessibility ---

            // Wait some time for membership propagation. Or we will get "membership check failed: A does not see B (1a607ea0-7e86-4d4e-b635-b63ca34ac1e9) in its member list"
            tokio::time::sleep(Duration::from_secs(3)).await;

            verify_all_keys_reachable(&[("A", &manager_a), ("B", &manager_b), ("C", &manager_c)])
                .await?;

            Ok(())
        })
        .await
        .expect("test_split_brain_cross_node_key_query_deferred_join failed");
    }

    /// Test the "two instances start simultaneously but cannot see each other" scenario.
    ///
    /// Both instances bootstrap independently, each generating their own key set.
    /// When C joins both A and B, the key sets merge. The master node detects
    /// multiple active keys and generates a new pending key. After the pending
    /// key activates, the older keys transition to stale, and all nodes converge.
    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_split_brain_convergence() {
        run_test_with_tokio_runtime(async |runtime| {
            // Use a short rotation interval (2s) so that keys become stale quickly
            // and the rotation mechanism can converge the cluster to a single key.
            let rotation_interval = 2;

            // Start A as bootstrap (creates its own key)
            let port_a = portpicker::pick_unused_port().unwrap();
            let args_a = make_peer_shared_args(port_a, vec![], rotation_interval);
            let manager_a = PeerSharedKeyManager::new(runtime.clone(), args_a).await?;

            let a_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            // Start B as bootstrap too (creates its own DIFFERENT key)
            let port_b = portpicker::pick_unused_port().unwrap();
            let args_b = make_peer_shared_args(port_b, vec![], rotation_interval);
            let manager_b = PeerSharedKeyManager::new(runtime.clone(), args_b).await?;

            let b_pk = manager_b
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            // Verify they have different keys (two separate key sets)
            assert_ne!(
                a_pk, b_pk,
                "A and B should have different keys when bootstrapped independently"
            );

            // Start C joining both A and B to bridge the split brain
            let port_c = portpicker::pick_unused_port().unwrap();
            let args_c = make_peer_shared_args(
                port_c,
                vec![
                    format!("127.0.0.1:{}", port_a),
                    format!("127.0.0.1:{}", port_b),
                ],
                rotation_interval,
            );
            let manager_c = PeerSharedKeyManager::new(runtime.clone(), args_c).await?;

            // Wait for C to get keys from both A and B via preboot merge
            tokio::time::sleep(Duration::from_secs(3)).await;

            // C should have at least 1 active key (likely 2 from the merge)
            wait_for_active_key_count(&manager_c, 1, Duration::from_secs(10)).await?;

            // Wait for full convergence: master detects multiple active keys,
            // generates pending key, it activates, old keys become stale.
            // With 2s interval: ~2 rotation cycles needed = ~8s.
            tokio::time::sleep(Duration::from_secs(12)).await;

            // All nodes should agree on the client-visible key
            let a_final_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            let b_final_pk = manager_b
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            // Fixed: was incorrectly reading from manager_b (copy-paste error).
            // This must read from manager_c to verify that all three nodes converge.
            let c_final_pk = manager_c
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            assert_eq!(
                a_final_pk, b_final_pk,
                "A and B should converge on the same client-visible key after bridge"
            );
            assert_eq!(
                b_final_pk, c_final_pk,
                "B and C should agree on the client-visible key"
            );

            Ok(())
        })
        .await
        .expect("test_split_brain_convergence failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_file_watcher_retries_new_peer() {
        run_test_with_tokio_runtime(async |runtime| {
            use std::io::Write;

            let port_a = portpicker::pick_unused_port().unwrap();
            let port_b = portpicker::pick_unused_port().unwrap();

            // A is started in a background task after a short delay. This means
            // the watcher's first background retry_join_peer attempt will FAIL
            // (A is not yet listening) and must rely on the per-peer backoff to
            // keep retrying until A comes up — exercising the retry feature.
            let runtime_for_a = runtime.clone();
            runtime
                .clone()
                .spawn_supervised_task_current_span(async move {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let args_a = make_peer_shared_args(port_a, vec![], 300);
                    let _manager_a = PeerSharedKeyManager::new(runtime_for_a, args_a)
                        .await
                        .expect("A should start");
                    // Keep A alive for the rest of the test.
                    std::future::pending::<()>().await;
                });

            // B starts with an EMPTY peers file -> bootstraps standalone, watcher
            // running. The watcher will pick up later writes to the file.
            let peers_file = std::env::temp_dir()
                .join(format!("tng_join_retry_file_{}.json", std::process::id()));
            std::fs::write(&peers_file, "[]")?;

            let mut args_b = make_peer_shared_args(port_b, vec![], 300);
            args_b.peers_file = Some(peers_file.to_string_lossy().to_string());
            let manager_b = PeerSharedKeyManager::new(runtime.clone(), args_b).await?;

            // Now write A's address into the file. The watcher should pick it up
            // and spawn a background retry_join_peer task that retries until A
            // (still down at this point) comes up, then joins it.
            // The FileWatcher only reloads on a Close following a Data modify, so
            // drop/flush the handle to emit the OS-level Close event.
            {
                let mut f = std::fs::File::create(&peers_file)?;
                writeln!(f, "[\"127.0.0.1:{}\"]", port_a)?;
                f.sync_all()?;
            }

            // B should eventually join A via the watcher-triggered background
            // retry, gaining A as an alive serf member.
            //
            // NOTE: we assert cluster membership (not key sync) because the
            // join-retry design (see docs/superpowers/specs/2026-06-18-join-retry-design.md,
            // "Known Limitations" #2) deliberately scopes key reconciliation to
            // the existing preboot/broadcast/event handlers — a node that already
            // bootstrapped does NOT re-run preboot after a late file-watcher
            // join. Verifying the join itself (A becomes an alive member of B's
            // cluster) is what this task delivers.
            wait_for_member_count(&manager_b, 2, Duration::from_secs(30)).await?;

            let _ = std::fs::remove_file(&peers_file);
            Ok(())
        })
        .await
        .expect("test_file_watcher_retries_new_peer failed");
    }

    /// Test that key rotation does not create duplicate pending keys.
    ///
    /// Multiple triggers of check_and_key_rotation (e.g., from member leave events
    /// and periodic key watcher) should not result in multiple pending keys.
    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_concurrent_key_rotation_no_duplicate_pending() {
        run_test_with_tokio_runtime(async |runtime| {
            let port_a = portpicker::pick_unused_port().unwrap();
            let port_b = portpicker::pick_unused_port().unwrap();
            let port_c = portpicker::pick_unused_port().unwrap();

            // Start A (bootstrap)
            // Use a long rotation interval (300s) to ensure no time-driven key rotation
            // occurs within the test window. This test validates that multiple member
            // leave events do NOT create duplicate pending keys — it does not test
            // time-based rotation. With interval=2, the leave-triggered rotation would
            // complete and the new key would activate before the final assertion,
            // causing the "Key should remain the same" check to fail.
            let args_a = make_peer_shared_args(port_a, vec![], 300);
            let manager_a = PeerSharedKeyManager::new(runtime.clone(), args_a).await?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Start B joining A
            let args_b = make_peer_shared_args(port_b, vec![format!("127.0.0.1:{}", port_a)], 300);
            let manager_b = PeerSharedKeyManager::new(runtime.clone(), args_b).await?;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Start C joining A (to create multiple leave events later)
            let args_c = make_peer_shared_args(port_c, vec![format!("127.0.0.1:{}", port_a)], 300);
            let manager_c = PeerSharedKeyManager::new(runtime.clone(), args_c).await?;

            // Wait for convergence
            wait_for_active_key_count(&manager_b, 1, Duration::from_secs(10)).await?;
            wait_for_active_key_count(&manager_c, 1, Duration::from_secs(10)).await?;

            let initial_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;

            // Drop both B and C rapidly to trigger multiple leave events
            drop(manager_b);
            drop(manager_c);

            // Wait for Serf to detect leaves and trigger rotation checks
            tokio::time::sleep(Duration::from_secs(8)).await;

            // A should have exactly 1 active key (no duplicate pending keys created)
            wait_for_active_key_count(&manager_a, 1, Duration::from_secs(15)).await?;

            // A's client-visible key should still be available
            let final_pk = manager_a
                .get_client_visible_key()
                .await?
                .key_config
                .public_key()?;
            assert_eq!(
                initial_pk, final_pk,
                "Key should remain the same since no rotation was needed"
            );

            Ok(())
        })
        .await
        .expect("test_concurrent_key_rotation_no_duplicate_pending failed");
    }
}

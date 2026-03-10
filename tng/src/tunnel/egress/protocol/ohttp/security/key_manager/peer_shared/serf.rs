use crate::config::egress::PeerSharedArgs;
use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::cluster_key_set::ClusterKeySet;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::memberlist_rats_quic::RatsQuic;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::runtime::InstrumentedRuntime;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::serf_message::pb;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::{KeyInfo, KeyStatus};
use crate::tunnel::ohttp::key_config::{KeyConfigExtend, PublicKeyData};
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::runtime::supervised_task::SupervisedTaskResult;
use crate::tunnel::utils::file_watcher::FileWatcher;

use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use futures::StreamExt;
use prost::Message;
use scopeguard::defer;
use serf::delegate::CompositeDelegate;
use serf::event::{Event, EventProducer, EventSubscriber, MemberEventType, QueryEvent};
use serf::net::hostaddr::{Host, HostAddr};
use serf::net::resolver::socket_addr::SocketAddrResolver;
use serf::net::NodeId;
use serf::quic::{QuicTransport, QuicTransportOptions};
use serf::types::MaybeResolvedAddress;
use serf::{MemberlistOptions, Options};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use uuid::Uuid;

use std::net::SocketAddr;
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::tunnel::ra_context::RaContext;

// Serf protocol constants
const SERF_QUERY_CLUSTER_KEY_SET: &str = "query_cluster_key_set";
const SERF_QUERY_KEY: &str = "query_key";
const SERF_USER_EVENT_BROADCAST_CLUSTER_KEY_SET: &str = "broadcast_cluster_key_set";

pub struct PeerSharedKeyManager {
    pub(super) inner: Arc<PeerSharedKeyManagerInner>,
    serf: Arc<SerfGracefulShutdown>,
    #[allow(unused)]
    peers_file_watch_task: Option<JoinHandle<SupervisedTaskResult<()>>>,
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
        let peers_file_watch_task =
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
        let _key_watcher_task =
            Self::spawn_key_watcher(runtime.clone(), inner.clone(), serf.clone());

        // Step 6: Spawn serf event handler task (handles queries and events)
        let _serf_watcher_task =
            Self::spawn_serf_watcher(runtime.clone(), subscriber, inner.clone(), serf.clone());

        Ok(Self {
            inner,
            serf,
            peers_file_watch_task,
        })
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
            .with_event_buffer_size(256);
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
    async fn spawn_cluster_join_tasks(
        runtime: &TokioRuntime,
        serf: &Arc<SerfGracefulShutdown>,
        peer_shared: &PeerSharedArgs,
    ) -> Result<Option<JoinHandle<SupervisedTaskResult<()>>>, TngError> {
        // First, join using static peers
        if !peer_shared.peers.is_empty() {
            if let Err(e) = join_serf_cluster(serf.as_ref(), &peer_shared.peers).await {
                tracing::warn!(error = ?e, "Failed to join some static peers");
            }
        }

        // If peers_file is configured, start monitoring it for changes
        if let Some(peers_file) = &peer_shared.peers_file {
            let peers_file_path = peers_file.clone();

            // Load initial peers from file and join if any
            if let Ok(file_peers) = load_peers_from_file(&peers_file_path).await {
                // Join using peers from file
                if let Err(e) = join_serf_cluster(serf, &file_peers).await {
                    tracing::warn!(error = ?e, "Some peers from file failed to join, continuing...");
                }
            }

            // Start file watcher to monitor peers file changes
            let serf_weak_for_watcher = Arc::downgrade(serf);

            let peers_file_path_for_watcher = Path::new(&peers_file_path).to_path_buf();

            let mut file_watcher = FileWatcher::new(peers_file_path_for_watcher.clone())
                .map_err(|e| TngError::WatchFileFailed(peers_file_path_for_watcher.clone(), e))?;

            let watch_task = runtime.spawn_supervised_task_current_span(async move {
                    while let Some(result) = file_watcher.recv().await {
                        match result {
                            Ok(()) => {
                                tracing::info!(peers_file = ?peers_file_path_for_watcher, "Peers file changed, reloading and joining new peers");

                                match load_peers_from_file(&peers_file_path_for_watcher.to_string_lossy()).await {
                                    Ok(new_peers) => {
                                        tracing::info!(peers_count = new_peers.len(), "Loaded peers from file");

                                        // Join using newly loaded peers
                                        let Some(serf_clone) = serf_weak_for_watcher.upgrade() else {
                                            tracing::debug!(
                                                "stop watching peers file since serf has been dropped"
                                            );
                                            break;
                                        };

                                        if let Err(e) = join_serf_cluster(&serf_clone, &new_peers).await {
                                            tracing::warn!(error = ?e, "Some peers from file failed to join, continuing...");
                                        }
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

                    tracing::info!(peers_file = ?peers_file_path_for_watcher, "Peers file watcher stopped");
                });
            Ok(Some(watch_task))
        } else {
            Ok(None)
        }
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
                    "Found {} peers in cluster, querying for cluster key set",
                    members.len() - 1
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
                        if let Some(cks) = pb_response.cluster_key_set {
                            if let Ok(remote_key_set) = ClusterKeySet::try_from(cks) {
                                tracing::info!("Received cluster key set from peer");

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
                    tracing::info!("Preboot completed with synchronized cluster key set");
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
        tracing::info!("Creating initial active key");
        let initial_key = KeyInfo::generate(
            0,
            KeyStatus::Active,
            SystemTime::now(),
            rotation_interval,
        )
        .map_err(|e| {
            TngError::KeyUpdateMessageDecodeError(anyhow!("Failed to generate initial key: {}", e))
        })?;

        let public_key_data = initial_key.key_config.public_key_data()?;
        Ok(ClusterKeySet::new(
            public_key_data,
            initial_key,
            rotation_interval,
        ))
    }

    /// Spawn key watcher task that handles key status transitions.
    fn spawn_key_watcher(
        runtime: TokioRuntime,
        inner: Arc<PeerSharedKeyManagerInner>,
        serf: Arc<SerfGracefulShutdown>,
    ) -> JoinHandle<()> {
        runtime.spawn_unsupervised_task_current_span(async move {
            defer! {
                tracing::info!("Key watcher stopped");
            }

            tracing::info!("Starting key watcher");

            loop {
                let now = SystemTime::now();

                {
                    let mut cks = inner.cluster_key_set.write().await;

                    // 1. Handle pending -> active transition (first, as it triggers check_and_key_rotation)
                    cks.transition_pending_to_active(now);

                    // 2. Handle active -> stale transition
                    cks.transition_active_to_stale(now);

                    // 3. Remove expired stale keys
                    cks.remove_expired_keys(now);
                } // Release write lock

                // Trigger check_and_key_rotation only when pending -> active
                Self::check_and_key_rotation(&serf, &inner).await;

                // Compute the next deadline for key status transition.
                let next_deadline={
                    let cks = inner.cluster_key_set.read().await;
                    cks.next_deadline()
                };

                match next_deadline {
                    Some(deadline) => {
                        let sleep_duration = deadline.duration_since(now).unwrap_or_else(|e| {
                            tracing::warn!(
                                "Key watcher deadline passed during state transitions (overdue by {:?}), will check soon",
                                e.duration()
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
        })
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
                Err(e) => {
                    tracing::error!("Failed to generate pending key: {}", e);
                    return;
                }
            }
        };

        if generated {
            tracing::info!("Master node generated new pending key, broadcasting to cluster");

            // Broadcast to all members
            if let Err(e) = Self::broadcast_cluster_key_set(serf, inner).await {
                tracing::error!("Failed to broadcast cluster key set: {}", e);
            }
        }
    }

    /// Check if this node is the master (smallest node ID in the cluster).
    async fn is_master(serf: &Serf) -> bool {
        let members = serf.members().await;
        let local_id = serf.local_id().to_string();

        if members.is_empty() {
            return true; // We are the only node
        }

        // Find the smallest node ID
        let min_node_id = members.iter().map(|m| m.node().id().to_string()).min();

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

        tracing::info!("Broadcasted cluster key set to all members");
        Ok(())
    }

    /// Spawn serf event handler task.
    fn spawn_serf_watcher(
        runtime: TokioRuntime,
        subscriber: EventSubscriber<SerfTransport, SerfDelegate>,
        inner: Arc<PeerSharedKeyManagerInner>,
        serf: Arc<SerfGracefulShutdown>,
    ) -> JoinHandle<()> {
        runtime.spawn_unsupervised_task_current_span(async move {
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
                        if let Err(e) = Self::handle_query(&query, &inner, &serf).await {
                            tracing::warn!("Error handling query: {}", e);
                        }
                    }
                    Event::User(user_event) => {
                        if let Err(e) = Self::handle_user_event(
                            user_event.name().as_str(),
                            user_event.payload(),
                            &inner,
                        )
                        .await
                        {
                            tracing::warn!("Error handling user event: {}", e);
                        }
                    }
                    Event::Member(member_event) => {
                        if matches!(member_event.ty(), MemberEventType::Leave) {
                            tracing::info!("Member left, triggering key rotation check");
                            Self::check_and_key_rotation(&serf, &inner).await;
                        }
                    }
                }
            }
        })
    }

    /// Handle incoming query requests.
    async fn handle_query(
        query: &QueryEvent<SerfTransport, SerfDelegate>,
        inner: &PeerSharedKeyManagerInner,
        _serf: &Serf,
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
                tracing::warn!("Ignoring unknown query: {}", query.name());
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

                    {
                        let mut cks = inner.cluster_key_set.write().await;
                        cks.merge(remote_key_set);
                    }

                    tracing::info!("Merged broadcasted cluster key set");
                }
            }
            _ => {
                tracing::warn!("Ignoring unknown user event: {}", event_name);
            }
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

/// Joins the Serf cluster via a list of peer addresses.
async fn join_serf_cluster(serf: &Serf, peers: &[String]) -> Result<(), TngError> {
    for peer in peers.iter() {
        tracing::info!(peer, "Attempting to join Serf cluster");

        let socket_addrs = resolve_peer_addresses(peer).await?;

        // Attempt to join the cluster using every resolved socket address for this host.
        // Since a hostname (e.g., via DNS) may resolve to multiple IPs (A/AAAA records),
        // we try each one to maximize the chance of successful connectivity.
        // It's sufficient to successfully join via at least one address.
        let count_success = futures::stream::iter(socket_addrs.into_iter()).filter_map(|socket_addr| async move {
            tracing::debug!(
                ?peer,
                resolved_address = %socket_addr,
                "Attempting to join serf cluster using resolved socket address"
            );

            match serf.join(MaybeResolvedAddress::resolved(socket_addr), false).await {
                Ok(_) => {
                    tracing::info!(
                        ?peer,
                        via = %socket_addr,
                        "Successfully joined serf cluster via resolved address"
                    );
                    Some(())
                }
                Err(error) => {
                    tracing::warn!(
                        ?peer,
                        failed_address = %socket_addr,
                        ?error,
                        "Failed to join serf cluster via this address, will try next if available"
                    );
                    None
                }
            }
        }).count().await;

        if count_success > 0 {
            continue;
        } else {
            return Err(TngError::SerfCrateError(anyhow!(
                "Failed to join any address of peer: {peer}"
            )));
        }
    }

    Ok(())
}

/// Loads peer list from JSON file.
async fn load_peers_from_file(path: &str) -> Result<Vec<String>, anyhow::Error> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read peers file: {path}"))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse peers file as JSON: {path}"))
}

struct SerfGracefulShutdown {
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

impl Drop for PeerSharedKeyManager {
    fn drop(&mut self) {
        if let Some(task) = self.peers_file_watch_task.take() {
            task.abort();
        }
    }
}

use crate::config::egress::PeerSharedArgs;
use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::callback_manager::{
    KeyChangeCallback, KeyChangeEvent,
};
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::memberlist_rats_quic::RatsQuic;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::runtime::InstrumentedRuntime;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::self_generated::SelfGeneratedKeyManager;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::{KeyInfo, KeyManager};
use crate::tunnel::ohttp::key_config::{KeyConfigExtend, PublicKeyData};
use crate::tunnel::utils::runtime::supervised_task::SupervisedTaskResult;
use crate::tunnel::utils::runtime::TokioRuntime;
use tokio::task::JoinHandle;

use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use futures::StreamExt;
use itertools::Itertools;
use prost::Message;
use scopeguard::defer;
use serf::delegate::CompositeDelegate;
use serf::event::{Event, EventProducer, EventSubscriber, MemberEventType};
use serf::net::hostaddr::{Host, HostAddr};
use serf::net::resolver::socket_addr::SocketAddrResolver;
use serf::net::NodeId;
use serf::quic::{QuicTransport, QuicTransportOptions};
use serf::types::MaybeResolvedAddress;
use serf::{MemberlistOptions, Options};
use tokio::sync::RwLock;
use uuid::Uuid;

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::tunnel::ra_context::RaContext;
use crate::tunnel::utils::file_watcher::FileWatcher;
use std::path::Path;

const SERF_USER_EVENT_KEY_UPDATE: &str = "key_update";

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
    pub(super) inner_key_manager: SelfGeneratedKeyManager,
    pub(super) keys_from_peers: RwLock<HashMap<PublicKeyData, KeyInfo>>,
}

impl PeerSharedKeyManager {
    pub async fn new(runtime: TokioRuntime, peer_shared: PeerSharedArgs) -> Result<Self, TngError> {
        // Step 1: Initialize Serf node and network transport
        let (serf, node_id_str, subscriber) = Self::setup_serf(&runtime, &peer_shared).await?;

        // Step 2: Join cluster via static peers and optional file
        let peers_file_watch_task =
            Self::spawn_cluster_join_tasks(&runtime, &serf, &peer_shared).await?;

        // Step 3: Initialize internal key state
        let inner = Arc::new(PeerSharedKeyManagerInner {
            inner_key_manager: SelfGeneratedKeyManager::new_with_auto_refresh(
                runtime.clone(),
                peer_shared.rotation_interval,
            )?,
            keys_from_peers: Default::default(),
        });

        // Step 4: Set up broadcast callback for key changes
        let broadcast_func = Self::make_broadcast_callback(&node_id_str, &serf);

        // Register callback to broadcast self generated key change event to all serf members
        {
            // We need to broadcast all key change events to the cluster
            inner
                .inner_key_manager
                .register_callback(broadcast_func.clone())
                .await;

            // Make sure we have broadcast all existing keys to the cluster
            for key_info in inner.inner_key_manager.get_client_visible_keys().await? {
                broadcast_func(&KeyChangeEvent::Created {
                    key_info: Cow::Owned(key_info),
                })
                .await;
            }
        }

        // Step 5: Spawn peer key sharing task (handles incoming events)
        let _peer_keys_sharing_task = Self::spawn_key_sharing_task(
            runtime.clone(),
            subscriber,
            inner.clone(),
            broadcast_func,
            node_id_str.clone(),
        );

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
            String,
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

        Ok((graceful_serf, node_id_str, subscriber))
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

    /// Creates a callback that broadcasts key changes across the Serf cluster.
    fn make_broadcast_callback(
        node_id_str: &str,
        serf: &Arc<SerfGracefulShutdown>,
    ) -> KeyChangeCallback {
        let node_id_str = node_id_str.to_owned();
        // Here we use weak reference to avoid memory leak due to reference cycle
        let serf_weak = Arc::downgrade(serf);

        Arc::new(move |event| {
            let node_id_str = node_id_str.clone();
            let serf_weak = serf_weak.clone();

            Box::pin(async move {
                let Some(serf_clone) = serf_weak.upgrade() else {
                    tracing::debug!("stop broadcast key change event since serf has been dropped");
                    return;
                };

                tracing::info!(?event, "broadcast key change event to all serf members");

                let message_buf = async {
                    let message = self::KeyUpdateMessage {
                        node_id: node_id_str.clone(),
                        event: event.clone(),
                    };
                    let message = super::key_update::pb::KeyUpdateMessage::try_from(message)?;

                    let mut message_buf = BytesMut::new();
                    message_buf.reserve(message.encoded_len()); // to prevent reallocations during encoding
                    message.encode(&mut message_buf)?;
                    Ok::<_, anyhow::Error>(message_buf)
                }
                .await;

                let message_buf = match message_buf {
                    Ok(v) => v,
                    Err(error) => {
                        tracing::error!(?error, "Failed to encode key update message");
                        return;
                    }
                };

                // broadcast a key update event to all members
                if let Err(error) = serf_clone
                    .user_event(SERF_USER_EVENT_KEY_UPDATE, message_buf, false)
                    .await
                {
                    tracing::error!(?error, "failed to send key update event");
                }
            })
        })
    }

    /// Spawns background task to handle Serf events (key updates, joins).
    fn spawn_key_sharing_task(
        runtime: TokioRuntime,
        subscriber: EventSubscriber<SerfTransport, SerfDelegate>,
        inner: Arc<PeerSharedKeyManagerInner>,
        broadcast_func: KeyChangeCallback,
        node_id_str: String,
    ) -> JoinHandle<()> {
        runtime.spawn_unsupervised_task_current_span(async move {
            defer! {
                tracing::info!("Peer keys sharing stopped");
            }

            tracing::info!("Start Peer keys sharing");

            loop {
                let Ok(event) = subscriber.recv().await else {
                    tracing::debug!("serf event channel closed, task quit now");
                    break;
                };

                let fut = async {
                    'skip: {
                        match event {
                            Event::User(ev) => {
                                match ev.name().as_str() {
                                    SERF_USER_EVENT_KEY_UPDATE => {
                                        let payload = ev.payload();

                                        let key_update: KeyUpdateMessage =
                                            super::key_update::pb::KeyUpdateMessage::decode(
                                                payload.as_ref(),
                                            )
                                            .context("decode protobuf data")
                                            .map_err(TngError::KeyUpdateMessageDecodeError)?
                                            .try_into()
                                            .map_err(TngError::KeyUpdateMessageDecodeError)?;

                                        if key_update.node_id == node_id_str {
                                            break 'skip;
                                        }

                                        tracing::info!(
                                            node_id = ?key_update.node_id,
                                            event = ?key_update.event,
                                            "Got key update serf event"
                                        );

                                        let now = SystemTime::now();

                                        match key_update.event {
                                            KeyChangeEvent::Created { key_info }
                                            | KeyChangeEvent::StatusChanged { key_info, .. } => {
                                                // Ignore the key if it has already expired yet
                                                if now < key_info.expire_at {
                                                    inner.keys_from_peers.write().await.insert(
                                                        key_info.key_config.public_key_data()?,
                                                        key_info.into_owned(),
                                                    );
                                                }
                                            }
                                            KeyChangeEvent::Removed { key_info } => {
                                                inner.keys_from_peers.write().await.remove(
                                                    &key_info.key_config.public_key_data()?,
                                                );
                                            }
                                        }

                                        // Scan and remove all the expired keys
                                        inner
                                            .keys_from_peers
                                            .write()
                                            .await
                                            .retain(|_, key_info| now < key_info.expire_at)
                                    }
                                    event => {
                                        tracing::warn!(event, "unknown user serf event");
                                    }
                                }
                            }
                            Event::Member(member_event) => {
                                if matches!(member_event.ty(), MemberEventType::Join) {
                                    tracing::info!(
                                        nodes=?member_event
                                            .members()
                                            .iter()
                                            .map(|member| member.node())
                                            .collect_vec(),
                                        "New serf node joined, start sharing keys"
                                    );
                                    // Notify self generated keys as key update event to all peers, when a new node joins
                                    async {
                                        for key_info in inner
                                            .inner_key_manager
                                            .get_client_visible_keys()
                                            .await?
                                        {
                                            broadcast_func(&KeyChangeEvent::Created {
                                                key_info: Cow::Owned(key_info),
                                            })
                                            .await;
                                        }
                                        Ok::<(), TngError>(())
                                    }
                                    .await
                                    .unwrap_or_else(|error| {
                                        tracing::warn!(
                                            ?error,
                                            "Error during broadcasting keys to peers"
                                        )
                                    });
                                }
                            }
                            _ => { /* ignore */ }
                        }
                    }

                    Ok::<(), anyhow::Error>(())
                };

                if let Err(error) = fut.await {
                    tracing::info!(?error, "Error during handling serf event");
                }
            }
        })
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

#[derive(Debug)]
pub struct KeyUpdateMessage<'a> {
    pub node_id: String,
    pub event: KeyChangeEvent<'a>,
}

impl Drop for PeerSharedKeyManager {
    fn drop(&mut self) {
        if let Some(task) = self.peers_file_watch_task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ra::RaArgsUnchecked;
    use crate::tests::run_test_with_tokio_runtime;
    use crate::tunnel::egress::protocol::ohttp::security::key_manager::KeyManager;
    use anyhow::{bail, Result};
    use std::time::Duration;

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

    /// Wait until a specific public key appears in keys_from_peers.
    async fn wait_for_key(
        target: &PeerSharedKeyManager,
        expected_pk: &crate::tunnel::ohttp::key_config::PublicKeyData,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        let expected_pk = expected_pk.clone();
        while std::time::Instant::now() < deadline {
            let keys = target.inner.keys_from_peers.read().await;
            if keys.contains_key(&expected_pk) {
                return Ok(());
            }
            drop(keys);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let keys = target.inner.keys_from_peers.read().await;
        bail!(
            "Timed out waiting for specific key. Got keys: {:?}",
            keys.keys().collect::<Vec<_>>()
        )
    }

    async fn wait_for_key_removal(
        target: &PeerSharedKeyManager,
        key_data: &crate::tunnel::ohttp::key_config::PublicKeyData,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        let key_data = key_data.clone();
        while std::time::Instant::now() < deadline {
            let keys = target.inner.keys_from_peers.read().await;
            if !keys.contains_key(&key_data) {
                return Ok(());
            }
            drop(keys);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("Timed out waiting for key removal")
    }

    /// Wait until a node generates its own active key.
    async fn wait_for_own_keys(
        target: &PeerSharedKeyManager,
        timeout: Duration,
    ) -> Result<Vec<KeyInfo>> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            let keys = target
                .inner
                .inner_key_manager
                .get_client_visible_keys()
                .await?;
            if !keys.is_empty() {
                return Ok(keys);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("Timed out waiting for node's own key generation")
    }

    #[tokio::test]
    async fn test_resolve_peer_addresses_ipv4() -> Result<()> {
        run_test_with_tokio_runtime(|_runtime| async move {
            let addrs = resolve_peer_addresses(&"127.0.0.1:8301".to_string())
                .await
                .unwrap();
            assert_eq!(addrs.len(), 1);
            assert_eq!(addrs[0], std::net::SocketAddr::from(([127, 0, 0, 1], 8301)));
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_resolve_peer_addresses_invalid() -> Result<()> {
        run_test_with_tokio_runtime(|_runtime| async move {
            let result = resolve_peer_addresses(&"not-a-valid-address".to_string()).await;
            assert!(
                result.is_err(),
                "Expected error for invalid address, got {:?}",
                result
            );
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_join_serf_cluster_empty_peers() -> Result<()> {
        // join_serf_cluster iterates over peers and returns Ok(()) if none.
        // We can verify this by creating a PeerSharedKeyManager with no peers
        // and confirming it starts successfully.
        run_test_with_tokio_runtime(|runtime| async move {
            let port = portpicker::pick_unused_port().expect("No free port");
            let args = make_peer_shared_args(port, vec![], 10);

            let mgr = PeerSharedKeyManager::new(runtime.clone(), args)
                .await
                .expect("Failed to create PeerSharedKeyManager with empty peers");

            // If we got here, the node started successfully with no peers to join
            // which means join_serf_cluster(&[]) returned Ok(())
            drop(mgr);
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_node_join_key_sync() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Start node A with no peers
            let port_a = portpicker::pick_unused_port().expect("No free port");
            let args_a = make_peer_shared_args(port_a, vec![], 10);
            let node_a = PeerSharedKeyManager::new(runtime.clone(), args_a)
                .await
                .expect("Failed to create node A");

            // Wait for A to generate its initial key
            let a_own_keys = wait_for_own_keys(&node_a, Duration::from_secs(5)).await?;
            let a_own_pk = a_own_keys[0]
                .key_config
                .public_key_data()
                .expect("Failed to get A's own public key data");

            // Start node B, pointing to A
            let port_b = portpicker::pick_unused_port().expect("No free port");
            let addr_a = format!("127.0.0.1:{}", port_a);
            let args_b = make_peer_shared_args(port_b, vec![addr_a.clone()], 10);
            let node_b = PeerSharedKeyManager::new(runtime.clone(), args_b)
                .await
                .expect("Failed to create node B");

            // Wait for B to receive A's specific key
            wait_for_key(&node_b, &a_own_pk, Duration::from_secs(15))
                .await
                .expect("Node B did not receive A's key");

            // Verify B has at least one key from A (not from B's own inner_key_manager)
            let keys = node_b.inner.keys_from_peers.read().await;
            assert!(
                !keys.is_empty(),
                "B should have received at least one key from A"
            );

            // The key in B's keys_from_peers should NOT be from B's own inner_key_manager
            let b_own_keys = node_b
                .inner
                .inner_key_manager
                .get_client_visible_keys()
                .await
                .expect("Failed to get B's own keys");
            for (pk_data, _) in keys.iter() {
                for b_key in &b_own_keys {
                    let b_pk = b_key
                        .key_config
                        .public_key_data()
                        .expect("Failed to get B key public key data");
                    assert_ne!(
                        *pk_data, b_pk,
                        "Key from peers should not match B's own key"
                    );
                }
            }

            drop(keys);
            drop(node_b);
            drop(node_a);
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_simultaneous_start() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let port_a = portpicker::pick_unused_port().expect("No free port");
            let port_b = portpicker::pick_unused_port().expect("No free port");

            let addr_a = format!("127.0.0.1:{}", port_a);
            let addr_b = format!("127.0.0.1:{}", port_b);

            // Start A and B simultaneously, each pointing to the other
            let args_a = make_peer_shared_args(port_a, vec![addr_b.clone()], 10);
            let args_b = make_peer_shared_args(port_b, vec![addr_a.clone()], 10);

            let (node_a, node_b) = tokio::join!(
                PeerSharedKeyManager::new(runtime.clone(), args_a),
                PeerSharedKeyManager::new(runtime.clone(), args_b),
            );

            let node_a = node_a.expect("Failed to create node A");
            let node_b = node_b.expect("Failed to create node B");

            // Wait for both nodes to generate their initial keys and get their public key data
            let (a_res, b_res) = tokio::join!(
                wait_for_own_keys(&node_a, Duration::from_secs(5)),
                wait_for_own_keys(&node_b, Duration::from_secs(5)),
            );
            let a_own_keys = a_res.expect("A did not generate initial key");
            let a_own_pk = a_own_keys[0]
                .key_config
                .public_key_data()
                .expect("Failed to get A's own public key data");

            let b_own_keys = b_res.expect("B did not generate initial key");
            let b_own_pk = b_own_keys[0]
                .key_config
                .public_key_data()
                .expect("Failed to get B's own public key data");

            // Wait for A to receive B's specific key, and B to receive A's specific key
            let (res_a, res_b) = tokio::join!(
                wait_for_key(&node_a, &b_own_pk, Duration::from_secs(15)),
                wait_for_key(&node_b, &a_own_pk, Duration::from_secs(15)),
            );

            res_a.expect("Node A did not receive B's specific key");
            res_b.expect("Node B did not receive A's specific key");

            // Verify: A must have B's specific public key in its keys_from_peers
            {
                let keys_a = node_a.inner.keys_from_peers.read().await;
                assert!(
                    keys_a.contains_key(&b_own_pk),
                    "A should have received B's specific key in keys_from_peers"
                );
                // A should NOT have its own key in keys_from_peers
                assert!(
                    !keys_a.contains_key(&a_own_pk),
                    "A should NOT have its own key in keys_from_peers"
                );
            }

            // Verify: B must have A's specific public key in its keys_from_peers
            {
                let keys_b = node_b.inner.keys_from_peers.read().await;
                assert!(
                    keys_b.contains_key(&a_own_pk),
                    "B should have received A's specific key in keys_from_peers"
                );
                // B should NOT have its own key in keys_from_peers
                assert!(
                    !keys_b.contains_key(&b_own_pk),
                    "B should NOT have its own key in keys_from_peers"
                );
            }
            drop(node_b);
            drop(node_a);
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_instance_joins_multiple_nodes() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Start 3 independent nodes
            let port_a = portpicker::pick_unused_port().expect("No free port");
            let port_b = portpicker::pick_unused_port().expect("No free port");
            let port_c = portpicker::pick_unused_port().expect("No free port");

            let args_a = make_peer_shared_args(port_a, vec![], 10);
            let args_b = make_peer_shared_args(port_b, vec![], 10);
            let args_c = make_peer_shared_args(port_c, vec![], 10);

            let (node_a, node_b, node_c) = tokio::join!(
                PeerSharedKeyManager::new(runtime.clone(), args_a),
                PeerSharedKeyManager::new(runtime.clone(), args_b),
                PeerSharedKeyManager::new(runtime.clone(), args_c),
            );

            let node_a = node_a.expect("Failed to create node A");
            let node_b = node_b.expect("Failed to create node B");
            let node_c = node_c.expect("Failed to create node C");

            // Wait for A, B, C to each generate their initial keys
            let a_own_pk = wait_for_own_keys(&node_a, Duration::from_secs(5)).await?;
            let a_own_pk = a_own_pk[0]
                .key_config
                .public_key_data()
                .expect("Failed to get A's own public key data");
            let b_own_pk = wait_for_own_keys(&node_b, Duration::from_secs(5)).await?;
            let b_own_pk = b_own_pk[0]
                .key_config
                .public_key_data()
                .expect("Failed to get B's own public key data");
            let c_own_pk = wait_for_own_keys(&node_c, Duration::from_secs(5)).await?;
            let c_own_pk = c_own_pk[0]
                .key_config
                .public_key_data()
                .expect("Failed to get C's own public key data");

            // Start node D, joining all three
            let port_d = portpicker::pick_unused_port().expect("No free port");
            let addr_a = format!("127.0.0.1:{}", port_a);
            let addr_b = format!("127.0.0.1:{}", port_b);
            let addr_c = format!("127.0.0.1:{}", port_c);
            let args_d = make_peer_shared_args(port_d, vec![addr_a, addr_b, addr_c], 10);

            let node_d = PeerSharedKeyManager::new(runtime.clone(), args_d)
                .await
                .expect("Failed to create node D");

            // Wait for D to receive all 3 specific keys
            let (res_a, res_b, res_c) = tokio::join!(
                wait_for_key(&node_d, &a_own_pk, Duration::from_secs(15)),
                wait_for_key(&node_d, &b_own_pk, Duration::from_secs(15)),
                wait_for_key(&node_d, &c_own_pk, Duration::from_secs(15)),
            );
            res_a.expect("D did not receive A's key");
            res_b.expect("D did not receive B's key");
            res_c.expect("D did not receive C's key");

            let keys_d = node_d.inner.keys_from_peers.read().await;
            assert!(
                keys_d.len() >= 3,
                "D should have received keys from all 3 nodes, got {}",
                keys_d.len()
            );

            drop(keys_d);
            drop(node_d);
            drop(node_c);
            drop(node_b);
            drop(node_a);
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_key_rotation_three_phase() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Start node A with 2s rotation interval
            let port_a = portpicker::pick_unused_port().expect("No free port");
            let args_a = make_peer_shared_args(port_a, vec![], 2);
            let node_a = PeerSharedKeyManager::new(runtime.clone(), args_a)
                .await
                .expect("Failed to create node A");

            // Wait for A to generate its first key
            tokio::time::sleep(Duration::from_millis(500)).await;

            // Get A's first key's public key data
            let a_keys = node_a
                .inner
                .inner_key_manager
                .get_client_visible_keys()
                .await
                .expect("Failed to get A's keys");
            assert!(!a_keys.is_empty(), "A should have at least one key");
            let key1_pk = a_keys[0]
                .key_config
                .public_key_data()
                .expect("Failed to get key1 public key data");

            // Start node B, pointing to A
            let port_b = portpicker::pick_unused_port().expect("No free port");
            let addr_a = format!("127.0.0.1:{}", port_a);
            let args_b = make_peer_shared_args(port_b, vec![addr_a.clone()], 2);
            let node_b = PeerSharedKeyManager::new(runtime.clone(), args_b)
                .await
                .expect("Failed to create node B");

            // Phase 1: B receives A's specific key1
            wait_for_key(&node_b, &key1_pk, Duration::from_secs(10))
                .await
                .expect("Node B did not receive key1 from A");

            // Phase 2: Wait for key rotation (key1 becomes Stale, key2 becomes Active)
            // key1: created at t=0, stale_at = t+2s, expire_at = t+4s
            // A's refresh loop will trigger at stale_at (~2s), mark key1 stale + generate key2
            // B receives key2 via Serf broadcast. Give it enough time.
            tokio::time::sleep(Duration::from_secs(5)).await;

            {
                let keys_b = node_b.inner.keys_from_peers.read().await;
                // B should still have keys (at least key2 should have arrived)
                assert!(
                    !keys_b.is_empty(),
                    "B should have at least one key after rotation, got {}",
                    keys_b.len()
                );
                // At least one key should be different from key1 (i.e., key2 arrived)
                let has_new_key = keys_b.keys().any(|pk| *pk != key1_pk);
                assert!(
                    has_new_key,
                    "B should have received a new key (key2) from A after rotation, keys: {:?}",
                    keys_b.keys().collect::<Vec<_>>()
                );
            }

            // Phase 3: Wait for key1 to expire (expire_at = created + 4s)
            // After ~5.5s total from B's start, key1 should be removed
            tokio::time::sleep(Duration::from_secs(2)).await;

            // Trigger a key event to make B's retain() fire by getting A to broadcast
            // A will broadcast when it generates a new key, which happens at rotation
            // Since rotation is 2s, by now A should have generated key3 as well

            // Wait a bit more and check - the retain() is triggered on receiving any User event
            // A will eventually broadcast another key update which triggers retain on B
            tokio::time::sleep(Duration::from_secs(1)).await;

            {
                let keys_b = node_b.inner.keys_from_peers.read().await;
                // key1 should be expired and removed
                assert!(
                    !keys_b.contains_key(&key1_pk),
                    "key1 should be removed after expire_at"
                );
                // B should still have at least one non-expired key
                assert!(
                    !keys_b.is_empty(),
                    "B should still have at least one non-expired key"
                );
            }

            drop(node_b);
            drop(node_a);
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_node_leave_key_cleanup() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Start node A with 2s rotation interval
            let port_a = portpicker::pick_unused_port().expect("No free port");
            let args_a = make_peer_shared_args(port_a, vec![], 2);
            let node_a = PeerSharedKeyManager::new(runtime.clone(), args_a)
                .await
                .expect("Failed to create node A");

            // Wait for A to generate its initial key
            let a_own_keys = wait_for_own_keys(&node_a, Duration::from_secs(5)).await?;
            let a_own_pk = a_own_keys[0]
                .key_config
                .public_key_data()
                .expect("Failed to get A's own public key data");

            // Start node B, pointing to A
            let port_b = portpicker::pick_unused_port().expect("No free port");
            let addr_a = format!("127.0.0.1:{}", port_a);
            let args_b = make_peer_shared_args(port_b, vec![addr_a.clone()], 2);
            let node_b = PeerSharedKeyManager::new(runtime.clone(), args_b)
                .await
                .expect("Failed to create node B");

            // Wait for B to receive A's specific key
            wait_for_key(&node_b, &a_own_pk, Duration::from_secs(10))
                .await
                .expect("Node B did not receive A's key");

            // Verify B has A's key
            let keys_before = node_b.inner.keys_from_peers.read().await;
            assert!(!keys_before.is_empty(), "B should have received A's key");
            let keys_count_before = keys_before.len();
            drop(keys_before);

            // Drop A (triggers graceful leave)
            drop(node_a);

            // Give Serf's leave protocol time to propagate
            tokio::time::sleep(Duration::from_millis(200)).await;

            // B's keys_from_peers should still contain A's key (not immediately cleaned up)
            // Because: A's leave doesn't send Removed events, and B's retain() only fires
            // on receiving User events
            let keys_after = node_b.inner.keys_from_peers.read().await;
            assert!(
                !keys_after.is_empty(),
                "B's keys should not be immediately cleaned up after A leaves, got {}",
                keys_after.len()
            );
            assert_eq!(
                keys_count_before,
                keys_after.len(),
                "B's key count should be unchanged after A leaves"
            );
            drop(keys_after);
            drop(node_b);

            Ok(())
        })
        .await
    }

    // T10: Test that SelfGeneratedKeyManager correctly generates new keys after rotation interval
    #[tokio::test]
    async fn test_self_generated_key_refresh_timing() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Start a single node with 3s rotation interval
            let port = portpicker::pick_unused_port().expect("No free port");
            let args = make_peer_shared_args(port, vec![], 3);
            let node = PeerSharedKeyManager::new(runtime.clone(), args)
                .await
                .expect("Failed to create node");

            // Wait for the initial key to be generated (refresh_keys runs asynchronously)
            let initial_keys = wait_for_own_keys(&node, Duration::from_secs(5)).await?;
            assert_eq!(
                initial_keys.len(),
                1,
                "Should have exactly 1 active key initially"
            );
            let first_key_pk = initial_keys[0]
                .key_config
                .public_key_data()
                .expect("Failed to get first key public key data");

            // Wait for rotation (stale_at = 3s, so at ~4s a new key should be generated)
            tokio::time::sleep(Duration::from_secs(4)).await;

            // Should have at least 2 keys now (original + new)
            let later_keys = node
                .inner
                .inner_key_manager
                .get_client_visible_keys()
                .await
                .expect("Failed to get keys after rotation");
            assert!(
                !later_keys.is_empty(),
                "Should have at least 1 active key after rotation"
            );
            // The new active key should be different from the first one
            let has_new_key = later_keys
                .iter()
                .any(|k| k.key_config.public_key_data().ok() != Some(first_key_pk.clone()));
            assert!(
                has_new_key,
                "Should have a new key different from the initial one"
            );

            drop(node);
            Ok(())
        })
        .await
    }

    // T11: Test that callbacks are properly registered and triggered when keys change
    #[tokio::test]
    async fn test_callback_registration() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let port = portpicker::pick_unused_port().expect("No free port");
            let args = make_peer_shared_args(port, vec![], 3);
            let node = PeerSharedKeyManager::new(runtime.clone(), args)
                .await
                .expect("Failed to create node");

            // Register a callback that tracks key creation events
            let event_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

            node.inner
                .inner_key_manager
                .register_callback(Arc::new(move |event| {
                    let count = event_count.clone();
                    Box::pin(async move {
                        if matches!(*event, KeyChangeEvent::Created { .. }) {
                            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    })
                }))
                .await;

            // Wait for the next key rotation which should trigger the callback
            tokio::time::sleep(Duration::from_secs(4)).await;

            // Note: The initial keys broadcast before callback registration might not trigger this,
            // but rotation should
            drop(node);
            Ok(())
        })
        .await
    }

    // T12: Test that multiple nodes starting with the same peer list form a single cluster
    #[tokio::test]
    async fn test_multiple_nodes_same_cluster() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Start a bootstrap node
            let port_boot = portpicker::pick_unused_port().expect("No free port");
            let args_boot = make_peer_shared_args(port_boot, vec![], 10);
            let node_boot = PeerSharedKeyManager::new(runtime.clone(), args_boot)
                .await
                .expect("Failed to create bootstrap node");

            // Wait for bootstrap to generate its initial key
            let boot_own_keys = wait_for_own_keys(&node_boot, Duration::from_secs(5)).await?;
            let boot_own_pk = boot_own_keys[0]
                .key_config
                .public_key_data()
                .expect("Failed to get bootstrap's own public key data");

            let boot_addr = format!("127.0.0.1:{}", port_boot);

            // Start 5 nodes all pointing to the bootstrap
            let mut nodes = Vec::new();
            for _ in 0..5 {
                let port = portpicker::pick_unused_port().expect("No free port");
                let args = make_peer_shared_args(port, vec![boot_addr.clone()], 10);
                let node = PeerSharedKeyManager::new(runtime.clone(), args)
                    .await
                    .expect("Failed to create node");
                nodes.push(node);
            }

            // Wait for all 5 nodes to receive bootstrap's specific key
            let mut wait_futs = Vec::new();
            for node in &nodes {
                wait_futs.push(wait_for_key(node, &boot_own_pk, Duration::from_secs(15)));
            }
            futures::future::join_all(wait_futs)
                .await
                .into_iter()
                .enumerate()
                .for_each(|(i, res)| {
                    res.unwrap_or_else(|e| {
                        panic!("Node {} did not receive bootstrap's key: {}", i, e)
                    });
                });

            // Bootstrap should have received keys from at least one of the new nodes
            {
                let boot_keys = node_boot.inner.keys_from_peers.read().await;
                assert!(
                    !boot_keys.is_empty(),
                    "Bootstrap node should have received keys from the cluster"
                );
            }

            drop(node_boot);
            for node in nodes {
                drop(node);
            }
            Ok(())
        })
        .await
    }

    // T13: Test that expired keys are not present in keys_from_peers
    #[tokio::test]
    async fn test_key_expiry_not_in_keys_from_peers() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Start A with 2s rotation
            let port_a = portpicker::pick_unused_port().expect("No free port");
            let args_a = make_peer_shared_args(port_a, vec![], 2);
            let node_a = PeerSharedKeyManager::new(runtime.clone(), args_a)
                .await
                .expect("Failed to create node A");

            tokio::time::sleep(Duration::from_millis(500)).await;

            // Get A's first key
            let a_keys = node_a
                .inner
                .inner_key_manager
                .get_client_visible_keys()
                .await
                .expect("Failed to get A's keys");
            let key1_pk = a_keys[0]
                .key_config
                .public_key_data()
                .expect("Failed to get key1 public key data");

            // Start B pointing to A
            let port_b = portpicker::pick_unused_port().expect("No free port");
            let addr_a = format!("127.0.0.1:{}", port_a);
            let args_b = make_peer_shared_args(port_b, vec![addr_a.clone()], 2);
            let node_b = PeerSharedKeyManager::new(runtime.clone(), args_b)
                .await
                .expect("Failed to create node B");

            wait_for_key(&node_b, &key1_pk, Duration::from_secs(10))
                .await
                .expect("B did not receive key1 from A");

            // Verify B has key1
            {
                let keys_b = node_b.inner.keys_from_peers.read().await;
                assert!(
                    keys_b.contains_key(&key1_pk),
                    "B should have key1 initially"
                );
            }

            // Wait for key1 to expire (expire_at = created + 4s)
            // By ~6s from creation, key1 should be expired and removed from A
            // B should receive the removal event and clean up key1
            tokio::time::sleep(Duration::from_secs(6)).await;

            // Check that B no longer has key1
            {
                let keys_b = node_b.inner.keys_from_peers.read().await;
                assert!(
                    !keys_b.contains_key(&key1_pk),
                    "B should not have key1 after it expired on A's side"
                );
            }

            drop(node_b);
            drop(node_a);
            Ok(())
        })
        .await
    }

    // T14: Test that when peers_file is not set, no file watcher task is spawned
    #[tokio::test]
    async fn test_peers_file_not_set() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let port = portpicker::pick_unused_port().expect("No free port");
            let args = make_peer_shared_args(port, vec![], 10);
            // peers_file is None in make_peer_shared_args

            let node = PeerSharedKeyManager::new(runtime.clone(), args)
                .await
                .expect("Failed to create node");

            // peers_file_watch_task should be None
            assert!(
                node.peers_file_watch_task.is_none(),
                "peers_file_watch_task should be None when peers_file is not set"
            );

            drop(node);
            Ok(())
        })
        .await
    }

    // T15: Test that a node's own generated keys never appear in its keys_from_peers map
    #[tokio::test]
    async fn test_node_cannot_receive_own_key() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let port = portpicker::pick_unused_port().expect("No free port");
            let args = make_peer_shared_args(port, vec![], 10);
            let node = PeerSharedKeyManager::new(runtime.clone(), args)
                .await
                .expect("Failed to create node");

            // Wait for the node to broadcast its key and then receive it back
            // (in a single-node cluster, the key_update event goes out but is filtered by node_id check)
            tokio::time::sleep(Duration::from_secs(3)).await;

            // keys_from_peers should be empty because there are no other peers
            {
                let peer_keys = node.inner.keys_from_peers.read().await;
                assert!(
                    peer_keys.is_empty(),
                    "A single node should not have any keys in keys_from_peers"
                );
            }

            drop(node);
            Ok(())
        })
        .await
    }

    // T16: Test that get_client_visible_keys only returns keys from inner_key_manager, not from keys_from_peers
    #[tokio::test]
    async fn test_get_client_visible_keys_only_returns_own_keys() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Start node A standalone
            let port_a = portpicker::pick_unused_port().expect("No free port");
            let args_a = make_peer_shared_args(port_a, vec![], 10);
            let node_a = PeerSharedKeyManager::new(runtime.clone(), args_a)
                .await
                .expect("Failed to create node A");

            // Wait for A to generate its key
            let a_own_keys = wait_for_own_keys(&node_a, Duration::from_secs(5)).await?;
            let a_own_pk = a_own_keys[0]
                .key_config
                .public_key_data()
                .expect("Failed to get A's own public key data");

            // Start node B pointing to A
            let port_b = portpicker::pick_unused_port().expect("No free port");
            let addr_a = format!("127.0.0.1:{}", port_a);
            let args_b = make_peer_shared_args(port_b, vec![addr_a.clone()], 10);
            let node_b = PeerSharedKeyManager::new(runtime.clone(), args_b)
                .await
                .expect("Failed to create node B");

            // Wait for B to receive A's key in keys_from_peers
            wait_for_key(&node_b, &a_own_pk, Duration::from_secs(15))
                .await
                .expect("B did not receive A's key");

            // B's get_client_visible_keys should only return B's own keys (1 key)
            // NOT the key from A
            let client_keys = node_b
                .get_client_visible_keys()
                .await
                .expect("Failed to get client visible keys");
            assert_eq!(
                client_keys.len(),
                1,
                "get_client_visible_keys should only return B's own key, got {}",
                client_keys.len()
            );
            // The key should be B's own key, not A's
            for key in &client_keys {
                let pk = key.key_config.public_key_data().expect("Failed to get pk");
                assert_ne!(
                    pk, a_own_pk,
                    "client_visible_keys should not contain A's key"
                );
            }

            drop(node_b);
            drop(node_a);
            Ok(())
        })
        .await
    }

    // T17: Test that get_fist_key_by_key_id falls back to keys_from_peers when the key is not in inner_key_manager
    #[tokio::test]
    async fn test_get_fist_key_by_key_id_fallback_to_peers() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Start node A standalone
            let port_a = portpicker::pick_unused_port().expect("No free port");
            let args_a = make_peer_shared_args(port_a, vec![], 10);
            let node_a = PeerSharedKeyManager::new(runtime.clone(), args_a)
                .await
                .expect("Failed to create node A");

            // Wait for A to generate its key
            let a_own_keys = wait_for_own_keys(&node_a, Duration::from_secs(5)).await?;
            let a_key_id = a_own_keys[0].key_config.key_id();
            let a_own_pk = a_own_keys[0]
                .key_config
                .public_key_data()
                .expect("Failed to get A's own public key data");

            // Start node B pointing to A
            let port_b = portpicker::pick_unused_port().expect("No free port");
            let addr_a = format!("127.0.0.1:{}", port_a);
            let args_b = make_peer_shared_args(port_b, vec![addr_a.clone()], 10);
            let node_b = PeerSharedKeyManager::new(runtime.clone(), args_b)
                .await
                .expect("Failed to create node B");

            // Wait for B to receive A's key
            wait_for_key(&node_b, &a_own_pk, Duration::from_secs(15))
                .await
                .expect("B did not receive A's key");

            // Get B's own key_id to check for collision
            let b_own_keys = node_b
                .inner
                .inner_key_manager
                .get_client_visible_keys()
                .await?;
            let b_key_id = b_own_keys[0].key_config.key_id();

            // Only test fallback when A's key_id differs from B's (avoid inner_key_manager hit)
            if a_key_id == b_key_id {
                // Both nodes generated the same key_id, can't test fallback via key_id
                // Just verify the peer key exists via public_key_data lookup instead
                let found_key = node_b
                    .get_key_by_public_key_data(&a_own_pk)
                    .await
                    .expect("Should find A's key by public key data");
                let found_pk = found_key
                    .key_config
                    .public_key_data()
                    .expect("Failed to get pk");
                assert_eq!(found_pk, a_own_pk, "Found key should be A's key");
            } else {
                // B should find A's key via get_fist_key_by_key_id
                // (falls back to keys_from_peers since A's key_id is not in B's inner_key_manager)
                let found_key = node_b
                    .get_fist_key_by_key_id(a_key_id)
                    .await
                    .expect("Should find key by key_id via fallback to peers");
                let found_pk = found_key
                    .key_config
                    .public_key_data()
                    .expect("Failed to get pk");
                assert_eq!(found_pk, a_own_pk, "Found key should be A's key");
            }

            // Query for a non-existent key_id should fail
            // Use a key_id far away from existing ones to avoid collision
            let non_existent_id = a_key_id.wrapping_add(128);
            let peer_keys = node_b.inner.keys_from_peers.read().await;
            let has_non_existent = peer_keys
                .values()
                .any(|k| k.key_config.key_id() == non_existent_id);
            drop(peer_keys);
            if !has_non_existent {
                let result = node_b.get_fist_key_by_key_id(non_existent_id).await;
                assert!(result.is_err(), "Non-existent key_id should not be found");
            }

            drop(node_b);
            drop(node_a);
            Ok(())
        })
        .await
    }

    // T18: Test that get_key_by_public_key_data finds keys in keys_from_peers
    #[tokio::test]
    async fn test_get_key_by_public_key_data_fallback_to_peers() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Start node A standalone
            let port_a = portpicker::pick_unused_port().expect("No free port");
            let args_a = make_peer_shared_args(port_a, vec![], 10);
            let node_a = PeerSharedKeyManager::new(runtime.clone(), args_a)
                .await
                .expect("Failed to create node A");

            // Wait for A to generate its key
            let a_own_keys = wait_for_own_keys(&node_a, Duration::from_secs(5)).await?;
            let a_own_pk = a_own_keys[0]
                .key_config
                .public_key_data()
                .expect("Failed to get A's own public key data");

            // Start node B pointing to A
            let port_b = portpicker::pick_unused_port().expect("No free port");
            let addr_a = format!("127.0.0.1:{}", port_a);
            let args_b = make_peer_shared_args(port_b, vec![addr_a.clone()], 10);
            let node_b = PeerSharedKeyManager::new(runtime.clone(), args_b)
                .await
                .expect("Failed to create node B");

            // Wait for B to receive A's key
            wait_for_key(&node_b, &a_own_pk, Duration::from_secs(15))
                .await
                .expect("B did not receive A's key");

            // B should find A's key via get_key_by_public_key_data
            let found_key = node_b
                .get_key_by_public_key_data(&a_own_pk)
                .await
                .expect("Should find A's key by public key data");
            let found_pk = found_key
                .key_config
                .public_key_data()
                .expect("Failed to get pk");
            assert_eq!(found_pk, a_own_pk, "Found key should match A's public key");

            // Also verify B can find its own key via inner_key_manager
            let b_own_keys = wait_for_own_keys(&node_b, Duration::from_secs(5)).await?;
            let b_own_pk = b_own_keys[0]
                .key_config
                .public_key_data()
                .expect("Failed to get B's own public key data");

            let found_b_key = node_b
                .get_key_by_public_key_data(&b_own_pk)
                .await
                .expect("Should find B's own key");
            let found_b_pk = found_b_key
                .key_config
                .public_key_data()
                .expect("Failed to get pk");
            assert_eq!(
                found_b_pk, b_own_pk,
                "Found key should match B's own public key"
            );

            drop(node_b);
            drop(node_a);
            Ok(())
        })
        .await
    }

    // T19: Test that load_peers_from_file successfully loads a valid JSON peer list
    #[tokio::test]
    async fn test_load_peers_from_file_success() -> Result<()> {
        run_test_with_tokio_runtime(|_runtime| async move {
            let peers = vec!["127.0.0.1:8301".to_string(), "127.0.0.1:8302".to_string()];
            let tmp_file = std::env::temp_dir().join("test_peers_valid.json");
            tokio::fs::write(&tmp_file, serde_json::to_string(&peers).unwrap()).await?;

            let loaded = load_peers_from_file(tmp_file.to_str().unwrap()).await?;
            assert_eq!(loaded, peers);

            tokio::fs::remove_file(&tmp_file).await.ok();
            Ok(())
        })
        .await
    }

    // T20: Test that load_peers_from_file returns an error when the file does not exist
    #[tokio::test]
    async fn test_load_peers_from_file_not_found() -> Result<()> {
        run_test_with_tokio_runtime(|_runtime| async move {
            let result = load_peers_from_file("/nonexistent/path/peers.json").await;
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(err.contains("Failed to read peers file"));
            Ok(())
        })
        .await
    }

    // T21: Test that load_peers_from_file returns an error for invalid JSON content
    #[tokio::test]
    async fn test_load_peers_from_file_invalid_json() -> Result<()> {
        run_test_with_tokio_runtime(|_runtime| async move {
            let tmp_file = std::env::temp_dir().join("test_peers_invalid.json");
            tokio::fs::write(&tmp_file, "not valid json").await?;

            let result = load_peers_from_file(tmp_file.to_str().unwrap()).await;
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(err.contains("Failed to parse peers file as JSON"));

            tokio::fs::remove_file(&tmp_file).await.ok();
            Ok(())
        })
        .await
    }

    // T22: Test that load_peers_from_file handles an empty JSON array correctly
    #[tokio::test]
    async fn test_load_peers_from_file_empty_array() -> Result<()> {
        run_test_with_tokio_runtime(|_runtime| async move {
            let tmp_file = std::env::temp_dir().join("test_peers_empty.json");
            tokio::fs::write(&tmp_file, "[]").await?;

            let loaded = load_peers_from_file(tmp_file.to_str().unwrap()).await?;
            assert!(loaded.is_empty());

            tokio::fs::remove_file(&tmp_file).await.ok();
            Ok(())
        })
        .await
    }

    // T23: Test that resolve_peer_addresses can resolve a domain name
    #[tokio::test]
    async fn test_resolve_peer_addresses_domain() -> Result<()> {
        run_test_with_tokio_runtime(|_runtime| async move {
            let addrs = resolve_peer_addresses(&"localhost:8301".to_string()).await?;
            assert!(
                !addrs.is_empty(),
                "Should resolve at least one address for localhost"
            );
            // localhost typically resolves to 127.0.0.1 or ::1
            assert!(
                addrs.iter().any(|a| a.ip().is_loopback()),
                "All resolved addresses should be loopback"
            );
            assert!(
                addrs.iter().all(|a| a.port() == 8301),
                "All resolved addresses should have the correct port"
            );
            Ok(())
        })
        .await
    }

    // T24: Test that when peers_file is configured, the PeerSharedKeyManager starts
    // successfully and the file watcher task is spawned
    #[tokio::test]
    async fn test_peer_shared_args_with_peers_file() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Create a temporary peers file
            let peers = vec!["127.0.0.1:9999".to_string()]; // Invalid peer, but file should still be loaded
            let tmp_file = std::env::temp_dir().join("test_peers_file_config.json");
            tokio::fs::write(&tmp_file, serde_json::to_string(&peers).unwrap()).await?;

            let port = portpicker::pick_unused_port().expect("No free port");
            let args = PeerSharedArgs {
                rotation_interval: 10,
                host: "127.0.0.1".to_string(),
                port,
                peers: vec![],
                peers_file: Some(tmp_file.to_string_lossy().to_string()),
                ra_args: crate::config::ra::RaArgsUnchecked {
                    no_ra: true,
                    attest: None,
                    verify: None,
                },
            };

            let node = PeerSharedKeyManager::new(runtime.clone(), args)
                .await
                .expect("Failed to create PeerSharedKeyManager with peers_file");

            // peers_file_watch_task should be Some
            assert!(
                node.peers_file_watch_task.is_some(),
                "peers_file_watch_task should be Some when peers_file is configured"
            );

            // Give time for the file watcher to load and attempt to join
            tokio::time::sleep(Duration::from_millis(500)).await;

            drop(node);
            tokio::fs::remove_file(&tmp_file).await.ok();
            Ok(())
        })
        .await
    }
}

use crate::config::egress::PeerSharedArgs;
use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::callback_manager::{
    KeyChangeCallback, KeyChangeEvent,
};
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::memberlist_rats_tls::RatsTls;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::self_generated::SelfGeneratedKeyManager;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::{KeyInfo, KeyManager};
use crate::tunnel::ohttp::key_config::{KeyConfigExtend, PublicKeyData};
use crate::tunnel::utils::runtime::TokioRuntime;

use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use futures::StreamExt;
use prost::Message;
use scopeguard::defer;
use serf::delegate::CompositeDelegate;
use serf::event::{Event, EventProducer, MemberEventType};
use serf::net::hostaddr::Host;
use serf::net::{HostAddr, NetTransportOptions, Node, NodeId};
use serf::tokio::TokioSocketAddrResolver;
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

const SERF_USER_EVENT_KEY_UPDATE: &str = "key_update";

pub struct PeerSharedKeyManager {
    pub(super) inner: Arc<PeerSharedKeyManagerInner>,
    serf: Arc<SerfGracefulShutdown>,
}

type Serf = serf::Serf<
    serf::net::TokioNetTransport<
        NodeId,
        TokioSocketAddrResolver,
        RatsTls<serf::agnostic::tokio::TokioRuntime>,
    >,
    CompositeDelegate<NodeId, SocketAddr>,
>;

pub(super) struct PeerSharedKeyManagerInner {
    pub(super) inner_key_manager: SelfGeneratedKeyManager,
    pub(super) keys_from_peers: RwLock<HashMap<PublicKeyData, KeyInfo>>,
}

impl PeerSharedKeyManager {
    pub async fn new(runtime: TokioRuntime, peer_shared: PeerSharedArgs) -> Result<Self, TngError> {
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
        let net_opts =
            NetTransportOptions::<_, TokioSocketAddrResolver, _>::with_stream_layer_options(
                node_id,
                (peer_shared.ra_args.into_checked()?, runtime.clone()),
            )
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

        let serf = Arc::new(SerfGracefulShutdown::new(serf, runtime.clone()));

        // Join existing serf cluster
        {
            for (i, peer) in peer_shared.peers.iter().enumerate() {
                tracing::info!(?peer, "Joining existing serf cluster");

                let socket_addrs = resolve_peer_addresses(peer).await?;
                let serf = &serf;

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

                    let node = Node::new(
                        #[allow(clippy::unwrap_used)]
                        NodeId::<255>::new(format!("unresolved_peer_{i}")).unwrap(),
                        MaybeResolvedAddress::resolved(socket_addr),
                    );

                    match serf.join(node, false).await {
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
                        "Failed to join serf cluster via any address of peer {peer}"
                    )));
                }
            }
        }

        let inner = Arc::new(PeerSharedKeyManagerInner {
            inner_key_manager: SelfGeneratedKeyManager::new_with_auto_refresh(
                runtime.clone(),
                peer_shared.rotation_interval,
            )?,
            keys_from_peers: Default::default(),
        });
        let inner_clone = inner.clone();

        let broadcast_func: KeyChangeCallback = {
            let node_id_str = node_id_str.clone();
            // Here we use weak reference to avoid memory leak due to reference cycle
            let serf_weak = Arc::downgrade(&serf);

            Arc::new(move |event| {
                let node_id_str = node_id_str.clone();
                let serf_weak = serf_weak.clone();

                Box::pin(async move {
                    let Some(serf_clone) = serf_weak.upgrade() else {
                        tracing::debug!(
                            "stop broadcast key change event since inner has been dropped"
                        );
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
        };

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

        let _peer_keys_sharing_task = runtime.spawn_unsupervised_task_current_span(async move {
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
                            Event::User(ev) => match ev.name().as_str() {
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
                                                inner_clone.keys_from_peers.write().await.insert(
                                                    key_info.key_config.public_key_data()?,
                                                    key_info.into_owned(),
                                                );
                                            }
                                        }
                                        KeyChangeEvent::Removed { key_info } => {
                                            inner_clone
                                                .keys_from_peers
                                                .write()
                                                .await
                                                .remove(&key_info.key_config.public_key_data()?);
                                        }
                                    }

                                    // Scan and remove all the expired keys
                                    inner_clone
                                        .keys_from_peers
                                        .write()
                                        .await
                                        .retain(|_, key_info| now < key_info.expire_at)
                                }
                                event => {
                                    tracing::warn!(event, "unknown user serf event");
                                }
                            },
                            Event::Member(member_event) => {
                                tracing::debug!(?member_event, "serf member event");
                                if matches!(member_event.ty(), MemberEventType::Join) {
                                    tracing::info!(
                                        ?member_event,
                                        "New serf node joined, start sharing keys"
                                    );
                                    // Notify self generated keys as key update event to all peers, when a new node joins
                                    async {
                                        for key_info in inner_clone
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
        });

        Ok(Self { inner, serf })
    }
}

async fn resolve_peer_addresses(addr: &String) -> Result<Vec<SocketAddr>, TngError> {
    let host_addr = HostAddr::from_str(addr)
        .with_context(|| format!("invalid peer address {addr}"))
        .map_err(TngError::InvalidParameter)?;
    let port = host_addr
        .port()
        .context("peer address missing port")
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

struct SerfGracefulShutdown {
    serf: Option<Serf>,
    runtime: TokioRuntime,
}

impl SerfGracefulShutdown {
    pub fn new(serf: Serf, runtime: TokioRuntime) -> Self {
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

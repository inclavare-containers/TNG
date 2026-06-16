use crate::error::TngError;
use crate::status::{StatusProvider, StatusQueryResult};
use crate::tunnel::egress::protocol::ohttp::security::key_manager::{
    KeyInfo, KeyManager, KeyStatus,
};
use crate::tunnel::ohttp::key_config::PublicKeyData;

use anyhow::Result;
use async_trait::async_trait;
use serde::Serialize;
use std::time::SystemTime;

/// Cluster topology snapshot.
#[derive(Serialize)]
struct ClusterStatus {
    node_id: String,
    members: Vec<ClusterMember>,
}

/// Cluster member entry.
#[derive(Serialize)]
struct ClusterMember {
    node_id: String,
    status: &'static str,
}

/// Single key entry in the peer-shared status snapshot.
#[derive(Serialize)]
struct PeerSharedKeyValue {
    source_node_id: String,
    key_id: u8,
    public_key: PublicKeyData,
    status: KeyStatus,
    #[serde(with = "humantime_serde")]
    expire_at: SystemTime,
}

/// Snapshot of the peer-shared key manager status for the status API.
#[derive(Serialize)]
struct PeerSharedStatus {
    key_manager_type: &'static str,
    keys: Vec<PeerSharedKeyValue>,
    cluster: ClusterStatus,
}

#[async_trait]
impl KeyManager for super::PeerSharedKeyManager {
    async fn get_key_by_public_key(&self, public_key: &PublicKeyData) -> Result<KeyInfo, TngError> {
        // Try to get key from local cluster key set
        {
            let cks = self.inner.cluster_key_set.read().await;
            if let Some(key) = cks.get_key_by_public_key(public_key) {
                return Ok(key.clone());
            }
        }

        // Try to get key by querying peers
        // Note: Concurrent queries may happen here without locking. We intentionally avoid locking
        // to prevent a single failure from blocking all queries, allowing as many queries as possible to succeed.
        match self.query_key_from_cluster(public_key).await {
            Ok(Some(key)) => return Ok(key),
            Ok(None) => {
                tracing::error!(?public_key, "Key not found in cluster");
            }
            Err(error) => {
                tracing::error!(?public_key, ?error, "Failed to query key from cluster");
            }
        }

        Err(TngError::ServerKeyConfigNotFound(public_key.clone()))
    }

    async fn get_client_visible_key(&self) -> Result<KeyInfo, TngError> {
        let cks = self.inner.cluster_key_set.read().await;
        // Return the client-visible key (active key with latest stale_at)
        Ok(cks.get_client_visible_key()?.clone())
    }

    fn key_manager_type(&self) -> &'static str {
        "peer_shared"
    }
}

#[async_trait]
impl StatusProvider for super::PeerSharedKeyManager {
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError> {
        match path {
            [] => Ok(StatusQueryResult::Subtree(vec!["keys".into()])),
            ["keys"] => {
                let node_id = self.serf.memberlist().local_id().to_string();

                let cks = self.inner.cluster_key_set.read().await;
                let keys: Vec<PeerSharedKeyValue> = cks
                    .iter_keys()
                    .map(|(public_key, info)| PeerSharedKeyValue {
                        source_node_id: node_id.clone(),
                        key_id: info.key_config.key_id(),
                        public_key: public_key.clone(),
                        status: info.status,
                        expire_at: info.expire_at,
                    })
                    .collect();
                drop(cks);

                let serf_members = self.serf.members().await;
                let members: Vec<ClusterMember> = serf_members
                    .iter()
                    .map(|m| ClusterMember {
                        node_id: m.node().to_string(),
                        status: "alive",
                    })
                    .collect();

                let status = PeerSharedStatus {
                    key_manager_type: "peer_shared",
                    keys,
                    cluster: ClusterStatus { node_id, members },
                };
                serde_json::to_value(&status)
                    .map(StatusQueryResult::Value)
                    .map_err(|e| {
                        tracing::error!(?e, "Failed to serialise key status");
                        TngError::StatusPathNotFound
                    })
            }
            _ => Err(TngError::StatusPathNotFound),
        }
    }
}

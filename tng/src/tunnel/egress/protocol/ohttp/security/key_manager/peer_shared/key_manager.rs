use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::{KeyInfo, KeyManager};
use crate::tunnel::ohttp::key_config::PublicKeyData;

use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
impl KeyManager for super::PeerSharedKeyManager {
    async fn get_key_by_public_key_data(
        &self,
        public_key_data: &PublicKeyData,
    ) -> Result<KeyInfo, TngError> {
        // Try to get key from local cluster key set
        {
            let cks = self.inner.cluster_key_set.read().await;
            if let Some(key) = cks.get_key_by_public_key(public_key_data) {
                return Ok(key.clone());
            }
        }

        // Try to get key by querying peers
        match self.query_key_from_cluster(public_key_data).await {
            Ok(Some(key)) => return Ok(key),
            Ok(None) => {
                tracing::debug!("Key not found in cluster: {:?}", public_key_data);
            }
            Err(e) => {
                tracing::error!("Failed to query key from cluster: {}", e);
            }
        }

        Err(TngError::ServerKeyConfigNotFound(public_key_data.clone()))
    }

    async fn get_client_visible_key(&self) -> Result<KeyInfo, TngError> {
        let cks = self.inner.cluster_key_set.read().await;
        // Return the client-visible key (active key with latest stale_at)
        Ok(cks.get_client_visible_key()?.clone())
    }
}

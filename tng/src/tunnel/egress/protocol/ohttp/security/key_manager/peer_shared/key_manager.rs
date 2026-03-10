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
        match self
            .inner
            .inner_key_manager
            .get_key_by_public_key_data(public_key_data)
            .await
        {
            Ok(key) => Ok(key),
            Err(_) => {
                let keys_from_peers = self.inner.keys_from_peers.read().await;
                keys_from_peers
                    .get(public_key_data)
                    .cloned()
                    .ok_or(TngError::ServerKeyConfigNotFound(public_key_data.clone()))
            }
        }
    }
    async fn get_client_visible_keys(&self) -> Result<Vec<KeyInfo>, TngError> {
        self.inner.inner_key_manager.get_client_visible_keys().await
    }
}

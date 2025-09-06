use crate::tunnel::utils::http_inspector::RequestInfo;

use anyhow::{bail, Result};
use http::uri::Authority;

use super::HttpTransportLayerCreator;
use crate::tunnel::ingress::protocol::rats_tls::security::pool::{ExtraValueMarkTrait, PoolKey};

pub trait PoolKeyExtraDataInserter {
    /// Return true if the transport layer creator needs to insert extra data to the pool key.
    ///
    /// If the result is false, then insert_extra_data_to_pool_key() will not be called.
    fn need_to_insert_extra_data(&self) -> bool;

    fn insert_extra_data_to_pool_key(
        &self,
        request_info: &RequestInfo,
        target_pool_key: &mut PoolKey,
    ) -> Result<()>;
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct HttpPoolKeyExtraData {
    /// The authority which will be used to send http request in the http transport layer.
    pub authority: Authority,
    /// The path which will be used to send http request in the http transport layer.
    pub path: String,
}

impl ExtraValueMarkTrait for HttpPoolKeyExtraData {}

impl PoolKeyExtraDataInserter for HttpTransportLayerCreator {
    fn need_to_insert_extra_data(&self) -> bool {
        true
    }

    fn insert_extra_data_to_pool_key(
        &self,
        request_info: &RequestInfo,
        target_pool_key: &mut PoolKey,
    ) -> Result<()> {
        match request_info {
            RequestInfo::Http1 { authority, path } | RequestInfo::Http2 { authority, path } => {
                let rewrited_path = self.path_rewrite_group.rewrite(path);
                tracing::debug!(original_path = path, rewrited_path, "path is rewrited");

                target_pool_key.insert_extra_data(HttpPoolKeyExtraData {
                    authority: authority.clone(),
                    path: rewrited_path,
                });
            }
            RequestInfo::UnknownProtocol => {
                bail!("failed to determine authority and path used by h2 transport layer due to unknown protocol")
            }
        };

        Ok(())
    }
}

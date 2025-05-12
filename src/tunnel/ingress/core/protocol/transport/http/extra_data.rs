use anyhow::Result;
use http::uri::Authority;

use super::HttpTransportLayerCreator;
use crate::tunnel::{
    ingress::core::protocol::{
        security::pool::{ExtraValueMarkTrait, PoolKey},
        transport::extra_data::PoolKeyExtraDataInserter,
    },
    utils::http_inspector::RequestInfo,
};

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
        };

        Ok(())
    }
}

use anyhow::Result;

use crate::tunnel::{
    ingress::core::protocol::security::pool::PoolKey, utils::http_inspector::RequestInfo,
};

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

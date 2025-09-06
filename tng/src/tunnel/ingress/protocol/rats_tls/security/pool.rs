use http_body_util::combinators::BoxBody;
use hyper_util::client::legacy::Client;
use std::collections::hash_map::DefaultHasher;
use std::convert::Infallible;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::{
    any::{Any, TypeId},
    collections::{BTreeMap, HashMap},
};

use crate::tunnel::endpoint::TngEndpoint;

use super::{RatsTlsClient, SecurityConnector};

pub type HyperClientType = Client<SecurityConnector, BoxBody<bytes::Bytes, Infallible>>;

pub type ClientPool = HashMap<PoolKey, RatsTlsClient>;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PoolKey {
    /// The distination endpoint where the underlying transport layer will connect to.
    endpoint: TngEndpoint,
    /// This is a bundle of extra data that will be used to combined with TngEndpoint to identify a RatsTlsClient. In this case, a request with different pollkey will not be forwarded via the same underlying connection.
    /// The implementation of this map is similar to https://crates.io/crates/typedmap and https://crates.io/crates/type-map. But it use BTreeMap under the hood because BTreeMap is hash-able.
    extra_data: BTreeMap<TypeId, Box<dyn ExtraValueTrait>>,
}

impl PoolKey {
    pub fn new(endpoint: TngEndpoint) -> Self {
        Self {
            endpoint,
            extra_data: BTreeMap::new(),
        }
    }

    pub fn get_endpoint(&self) -> &TngEndpoint {
        &self.endpoint
    }

    pub fn insert_extra_data<T: ExtraValueTrait>(&mut self, data: T) {
        self.extra_data.insert(TypeId::of::<T>(), Box::new(data));
    }

    pub fn get_extra_data<T: ExtraValueTrait>(&self) -> Option<&T> {
        self.extra_data
            .get(&TypeId::of::<T>())
            .and_then(|boxed| boxed.any().downcast_ref::<T>())
    }
}

/// This trait is just a marker trait for limit the rust types that can be used as extra data in PoolKey, so that we can reduce the probility to write bugs.
///
/// Other components can use this trait to mark customized extra data type with something like:
/// ```ignore
/// use std::any::Any;
/// use crate::tunnel::ingress::protocol::transport::extractor::ExtraValueMarkTrait;
///
/// struct MyExtraData;
///
/// impl ExtraValueMarkTrait for MyExtraData {}
///
/// fn foo() {
///     let mut pool_key = PoolKey::new(TngEndpoint::new("127.0.0.1", 80))
///         .insert_extra_data(MyExtraData);
///     pool_key.insert_extra_data(MyExtraData{});
///     let extra_data = pool_key.get_extra_data::<MyExtraData>().unwrap();
/// }
///
/// ```
pub trait ExtraValueMarkTrait {}

/// This trait should be implemented for the extra data value in PoolKey.
///
/// The original implementation is in https://users.rust-lang.org/t/workaround-for-hash-trait-not-being-object-safe/53332/6
pub trait ExtraValueTrait: Send + Sync + 'static {
    fn any(&self) -> &dyn Any;
    fn equals(&self, rhs: &dyn ExtraValueTrait) -> bool;
    fn hash_value(&self) -> u64;
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
    fn clone_to_boxed(&self) -> Box<dyn ExtraValueTrait>;
}

impl<T: 'static + PartialEq + Hash + Debug + Clone + Send + Sync + ExtraValueMarkTrait>
    ExtraValueTrait for T
{
    // Co-opting the compiler's inference was easier than figuring out the
    // direct incantation.
    fn any(&self) -> &dyn Any {
        self
    }

    // Note here that we're downcasting to T and not dyn ExtraValueTrait or Box<dyn ExtraValueTrait>
    fn equals(&self, rhs: &dyn ExtraValueTrait) -> bool {
        rhs.any()
            .downcast_ref::<T>()
            .map(|rhs| rhs == self)
            .unwrap_or(false)
    }

    // If two values are equal, their hashes must be equal.
    // Here's one way to assure that in the generic case: hash the u64 which is
    // the hashed value of the original, for some concrete Hasher type.
    fn hash_value(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt(f)
    }

    fn clone_to_boxed(&self) -> Box<dyn ExtraValueTrait> {
        Box::new(Clone::clone(self))
    }
}

// By implmenting these for dyn ExtraValueTrait, Box<dyn ExtraValueTrait> also implements them
impl Eq for dyn ExtraValueTrait {}

impl PartialEq for dyn ExtraValueTrait + '_ {
    fn eq(&self, rhs: &Self) -> bool {
        self.equals(rhs)
    }
}

impl Hash for dyn ExtraValueTrait + '_ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_value().hash(state);
    }
}

impl Debug for dyn ExtraValueTrait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.debug_fmt(f)
    }
}

impl Clone for Box<dyn ExtraValueTrait> {
    fn clone(&self) -> Self {
        self.clone_to_boxed()
    }
}

#[cfg(test)]
mod tests {

    use anyhow::Result;

    use super::*;

    impl ExtraValueMarkTrait for i32 {}
    impl ExtraValueMarkTrait for &'static str {}

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_pool_key() -> Result<()> {
        let mut pool_key1 = PoolKey::new(TngEndpoint::new("127.0.0.1", 80));
        pool_key1.insert_extra_data(1i32);
        pool_key1.insert_extra_data("value");

        let mut pool_key2 = PoolKey::new(TngEndpoint::new("127.0.0.1", 80));
        pool_key2.insert_extra_data(1i32);
        pool_key2.insert_extra_data("value");

        assert_eq!(pool_key1, pool_key2);

        assert_eq!(pool_key1.get_extra_data::<i32>(), Some(&1i32));
        assert_eq!(pool_key1.get_extra_data::<&'static str>(), Some(&"value"));

        Ok(())
    }
}

use std::sync::Arc;

use indexmap::IndexMap;
use itertools::Itertools;
use opentelemetry::KeyValue;

#[derive(Debug, Clone)]
pub struct AttributedCounter<C, T> {
    pub inner: C,

    pub attributes: Arc<IndexMap<String, String>>,

    cached_kvs: Arc<Vec<KeyValue>>,

    _marker: std::marker::PhantomData<T>,
}

impl<C, T> AttributedCounter<C, T> {
    #[allow(dead_code)]
    fn gen_attributes_array(&self) -> Vec<KeyValue> {
        self.attributes
            .iter()
            .map(|att| KeyValue::new(att.0.clone(), att.1.clone()))
            .collect_vec()
    }
}

impl<T> AttributedCounter<opentelemetry::metrics::Counter<T>, T> {
    pub fn add(&self, value: T) {
        self.inner.add(value, &self.cached_kvs);
    }
}

impl<T> AttributedCounter<opentelemetry::metrics::UpDownCounter<T>, T> {
    pub fn add(&self, value: T) {
        self.inner.add(value, &self.cached_kvs);
    }
}

pub trait WithAttributes<T> {
    fn with_attributes(
        self,
        attributes: Arc<IndexMap<String, String>>,
    ) -> AttributedCounter<Self, T>
    where
        Self: Sized;
}

impl<T> WithAttributes<T> for opentelemetry::metrics::Counter<T> {
    fn with_attributes(
        self,
        attributes: Arc<IndexMap<String, String>>,
    ) -> AttributedCounter<Self, T> {
        let cached_kvs: Vec<KeyValue> = attributes
            .iter()
            .map(|att| KeyValue::new(att.0.clone(), att.1.clone()))
            .collect_vec();
        AttributedCounter::<Self, T> {
            inner: self,
            attributes,
            cached_kvs: Arc::new(cached_kvs),
            _marker: Default::default(),
        }
    }
}

impl<T> WithAttributes<T> for opentelemetry::metrics::UpDownCounter<T> {
    fn with_attributes(
        self,
        attributes: Arc<IndexMap<String, String>>,
    ) -> AttributedCounter<Self, T> {
        let cached_kvs: Vec<KeyValue> = attributes
            .iter()
            .map(|att| KeyValue::new(att.0.clone(), att.1.clone()))
            .collect_vec();
        AttributedCounter::<Self, T> {
            inner: self,
            attributes,
            cached_kvs: Arc::new(cached_kvs),
            _marker: Default::default(),
        }
    }
}

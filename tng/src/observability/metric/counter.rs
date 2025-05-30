use std::sync::Arc;

use indexmap::IndexMap;
use itertools::Itertools;

#[derive(Debug, Clone)]
pub struct AttributedCounter<C, T> {
    pub inner: C,

    pub attributes: Arc<IndexMap<String, String>>,

    _marker: std::marker::PhantomData<T>,
}

impl<C, T> AttributedCounter<C, T> {
    fn gen_attributes_array(&self) -> Vec<opentelemetry::KeyValue> {
        self.attributes
            .iter()
            .map(|att| opentelemetry::KeyValue::new(att.0.clone(), att.1.clone()))
            .collect_vec()
    }
}

impl<T> AttributedCounter<opentelemetry::metrics::Counter<T>, T> {
    pub fn add(&self, value: T) {
        self.inner.add(value, &self.gen_attributes_array());
    }
}

impl<T> AttributedCounter<opentelemetry::metrics::UpDownCounter<T>, T> {
    pub fn add(&self, value: T) {
        self.inner.add(value, &self.gen_attributes_array());
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
        AttributedCounter::<Self, T> {
            inner: self,
            attributes,
            _marker: Default::default(),
        }
    }
}

impl<T> WithAttributes<T> for opentelemetry::metrics::UpDownCounter<T> {
    fn with_attributes(
        self,
        attributes: Arc<IndexMap<String, String>>,
    ) -> AttributedCounter<Self, T> {
        AttributedCounter::<Self, T> {
            inner: self,
            attributes,
            _marker: Default::default(),
        }
    }
}

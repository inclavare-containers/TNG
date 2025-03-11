use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

pub type MetricValue = serde_json::Number;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, EnumIter)]
pub enum ServerMetric {
    #[serde(rename = "live")]
    Live, // Gauge
}

// Metrics name for ingress or egress
#[derive(Debug, Clone, Copy, Serialize, Deserialize, EnumIter)]
pub enum XgressMetric {
    #[serde(rename = "tx_bytes_total")]
    TxBytesTotal, // Counter
    #[serde(rename = "rx_bytes_total")]
    RxBytesTotal, // Counter
    #[serde(rename = "cx_active")]
    CxActive, // Gauge
    #[serde(rename = "cx_total")]
    CxTotal, // Counter
    #[serde(rename = "cx_failed")]
    CxFailed, // Counter
}

#[derive(Eq, Hash, PartialEq, Debug, Clone, Copy, Serialize, Deserialize, EnumIter)]
pub enum XgressId {
    #[serde(rename = "ingress")]
    Ingress { id: usize },
    #[serde(rename = "egress")]
    Egress { id: usize },
}

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum ValueType {
    Counter,
    Gauge,
}

pub trait Metric {
    fn value_type(&self) -> ValueType;

    fn labels(&self) -> IndexMap<String, String>;

    fn name(&self) -> String;
}

impl Metric for (XgressId, XgressMetric) {
    fn value_type(&self) -> ValueType {
        let (_xgress_id, xgress_metric) = self;
        match xgress_metric {
            XgressMetric::TxBytesTotal
            | XgressMetric::RxBytesTotal
            | XgressMetric::CxTotal
            | XgressMetric::CxFailed => ValueType::Counter,
            XgressMetric::CxActive => ValueType::Gauge,
        }
    }

    fn labels(&self) -> IndexMap<String, String> {
        let (xgress_id, _xgress_metric) = self;
        [
            (
                "type".to_owned(),
                serde_variant::to_variant_name(&xgress_id)
                    .unwrap_or("unknown")
                    .to_owned(),
            ),
            (
                "id".to_owned(),
                match xgress_id {
                    XgressId::Ingress { id } => id,
                    XgressId::Egress { id } => id,
                }
                .to_string(),
            ),
        ]
        .into()
    }

    fn name(&self) -> String {
        let (_xgress_id, xgress_metric) = self;

        serde_variant::to_variant_name(&xgress_metric)
            .unwrap_or("unknown")
            .to_owned()
    }
}

impl Metric for ServerMetric {
    fn value_type(&self) -> ValueType {
        match self {
            ServerMetric::Live => ValueType::Gauge,
        }
    }

    fn labels(&self) -> IndexMap<String, String> {
        Default::default()
    }

    fn name(&self) -> String {
        serde_variant::to_variant_name(&self)
            .unwrap_or("unknown")
            .to_owned()
    }
}

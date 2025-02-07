use anyhow::Result;
use egress::mapping::MappingEgress;
use ingress::{http_proxy::serve::HttpProxyIngress, mapping::MappingIngress};
use log::{info, warn};
use tracing::Instrument;

use crate::config::{egress::EgressMode, ingress::IngressMode, TngConfig};

mod egress;
mod ingress;
mod utils;

pub async fn run_native_part(
    mut stop_rx: tokio::sync::watch::Receiver<()>,
    tng_config: TngConfig,
) -> Result<()> {
    info!("TNG native part running now");

    for (id, add_ingress) in tng_config.add_ingress.iter().enumerate() {
        let add_ingress = add_ingress.clone();
        tokio::task::spawn(async move {
            match &add_ingress.ingress_mode {
                IngressMode::Mapping(mapping_args) => {
                    MappingIngress::new(mapping_args, &add_ingress.common)?
                        .serve()
                        .instrument(tracing::info_span!("ingress", id))
                        .await
                }
                IngressMode::HttpProxy(http_proxy_args) => {
                    HttpProxyIngress::new(http_proxy_args, &add_ingress.common)?
                        .serve()
                        .instrument(tracing::info_span!("ingress", id))
                        .await
                }
                IngressMode::Netfilter(_) => todo!(),
            }
        });
    }

    for (id, add_egress) in tng_config.add_egress.iter().enumerate() {
        let add_egress = add_egress.clone();
        tokio::task::spawn(async move {
            match &add_egress.egress_mode {
                EgressMode::Mapping(mapping_args) => {
                    MappingEgress::new(mapping_args, &add_egress.common)?
                        .serve()
                        .instrument(tracing::info_span!("egress", id))
                        .await
                }
                EgressMode::Netfilter(_) => todo!(),
            }
        });
    }

    if let Err(e) = stop_rx.changed().await {
        warn!("The stop signal sender is dropped unexpectedly: {e:#}");
    };

    info!("TNG native part exiting now");
    Ok(())
}

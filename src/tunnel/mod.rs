use std::{future::Future, pin::Pin};

use anyhow::Result;
use egress::{mapping::MappingEgress, netfilter::NetfilterEgress};
use ingress::{http_proxy::serve::HttpProxyIngress, mapping::MappingIngress};
use tracing::Instrument;

use crate::{
    config::{egress::EgressMode, ingress::IngressMode, TngConfig},
    executor::iptables::IpTablesActions,
};

mod egress;
mod ingress;
mod utils;

pub struct TngRuntime {
    tasks: Vec<Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>>,
    stop_rx: tokio::sync::watch::Receiver<()>,
}

impl TngRuntime {
    pub fn launch_from_config(
        stop_rx: tokio::sync::watch::Receiver<()>,
        tng_config: TngConfig,
    ) -> Result<(Self, IpTablesActions)> {
        tracing::info!("TNG native part running now");

        let mut iptables_actions = vec![];
        let mut tasks: Vec<Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>> = vec![];

        for (id, add_ingress) in tng_config.add_ingress.iter().enumerate() {
            let add_ingress = add_ingress.clone();
            match &add_ingress.ingress_mode {
                IngressMode::Mapping(mapping_args) => {
                    let ingress = MappingIngress::new(mapping_args, &add_ingress.common)?;
                    tasks.push(Box::pin(async move {
                        ingress
                            .serve()
                            .instrument(tracing::info_span!("ingress", id))
                            .await
                    }));
                }
                IngressMode::HttpProxy(http_proxy_args) => {
                    let ingress = HttpProxyIngress::new(http_proxy_args, &add_ingress.common)?;
                    tasks.push(Box::pin(async move {
                        ingress
                            .serve()
                            .instrument(tracing::info_span!("ingress", id))
                            .await
                    }));
                }
                IngressMode::Netfilter(_) => todo!(),
            }
        }

        for (id, add_egress) in tng_config.add_egress.iter().enumerate() {
            let add_egress = add_egress.clone();
            match &add_egress.egress_mode {
                EgressMode::Mapping(mapping_args) => {
                    let egress = MappingEgress::new(mapping_args, &add_egress.common)?;
                    tasks.push(Box::pin(async move {
                        egress
                            .serve()
                            .instrument(tracing::info_span!("egress", id))
                            .await
                    }));
                }
                EgressMode::Netfilter(netfilter_args) => {
                    let egress = NetfilterEgress::new(
                        netfilter_args,
                        &add_egress.common,
                        id,
                        &mut iptables_actions,
                    )?;
                    tasks.push(Box::pin(async move {
                        egress
                            .serve()
                            .instrument(tracing::info_span!("egress", id))
                            .await
                    }));
                }
            }
        }

        Ok((Self { tasks, stop_rx }, iptables_actions))
    }

    pub async fn serve(mut self) -> Result<()> {
        // TODO: deperecate admin_bind and warn user

        for task in self.tasks.drain(..) {
            tokio::task::spawn(task);
        }

        if let Err(e) = self.stop_rx.changed().await {
            tracing::warn!("The stop signal sender is dropped unexpectedly: {e:#}");
        };

        tracing::info!("TNG native part exiting now");

        Ok(())
    }
}

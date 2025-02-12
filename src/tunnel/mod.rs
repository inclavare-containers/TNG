use anyhow::Result;
use async_trait::async_trait;
use egress::{mapping::MappingEgress, netfilter::NetfilterEgress};
use ingress::{http_proxy::HttpProxyIngress, mapping::MappingIngress};
use tokio_graceful::ShutdownGuard;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Span};

use crate::{
    config::{egress::EgressMode, ingress::IngressMode, TngConfig},
    executor::iptables::IpTablesActions,
};

pub(self) mod access_log;
pub(self) mod attestation_result;
pub(self) mod cert_verifier;
mod egress;
mod ingress;
mod utils;

#[async_trait]
pub(self) trait RegistedService {
    async fn serve(&self, shutdown_guard: ShutdownGuard) -> Result<()>;
}

pub struct TngRuntime {
    services: Vec<(Box<dyn RegistedService + Send + Sync>, Span)>,
}

impl TngRuntime {
    pub fn launch_from_config(tng_config: TngConfig) -> Result<(Self, IpTablesActions)> {
        let mut iptables_actions = vec![];
        let mut services: Vec<(Box<dyn RegistedService + Send + Sync>, Span)> = vec![];

        for (id, add_ingress) in tng_config.add_ingress.iter().enumerate() {
            let add_ingress = add_ingress.clone();
            match &add_ingress.ingress_mode {
                IngressMode::Mapping(mapping_args) => {
                    services.push((
                        Box::new(MappingIngress::new(mapping_args, &add_ingress.common)?),
                        tracing::info_span!("ingress", id),
                    ));
                }
                IngressMode::HttpProxy(http_proxy_args) => {
                    let ingress = HttpProxyIngress::new(http_proxy_args, &add_ingress.common)?;
                    services.push((Box::new(ingress), tracing::info_span!("ingress", id)));
                }
                IngressMode::Netfilter(_) => todo!(),
            }
        }

        for (id, add_egress) in tng_config.add_egress.iter().enumerate() {
            let add_egress = add_egress.clone();
            match &add_egress.egress_mode {
                EgressMode::Mapping(mapping_args) => {
                    let egress = MappingEgress::new(mapping_args, &add_egress.common)?;
                    services.push((Box::new(egress), tracing::info_span!("egress", id)));
                }
                EgressMode::Netfilter(netfilter_args) => {
                    let egress = NetfilterEgress::new(
                        netfilter_args,
                        &add_egress.common,
                        id,
                        &mut iptables_actions,
                    )?;
                    services.push((Box::new(egress), tracing::info_span!("egress", id)));
                }
            }
        }

        Ok((Self { services }, iptables_actions))
    }

    pub async fn serve(
        mut self,
        shutdown_guard: ShutdownGuard,
        task_exit: CancellationToken,
    ) -> Result<()> {
        // TODO: deperecate admin_bind and warn user
        tracing::info!("TNG native part running now");

        for (service, span) in self.services.drain(..) {
            let task_exit = task_exit.clone();
            shutdown_guard.spawn_task_fn(|shutdown_guard| {
                async move {
                    if let Err(e) = service.serve(shutdown_guard).await {
                        let error = format!("{e:#}");
                        tracing::error!(%error, "failed to serve, canceling and exitng new");
                        task_exit.cancel();
                    }
                }
                .instrument(span)
            });
        }

        shutdown_guard.cancelled().await;

        Ok(())
    }
}

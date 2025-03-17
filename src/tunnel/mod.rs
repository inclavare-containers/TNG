use anyhow::{bail, Result};
use async_trait::async_trait;
use egress::mapping::MappingEgress;
use ingress::{http_proxy::HttpProxyIngress, mapping::MappingIngress};
use tokio::sync::mpsc::Sender;
use tokio_graceful::ShutdownGuard;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Span};

use crate::{
    config::{egress::EgressMode, ingress::IngressMode, TngConfig},
    executor::iptables::IpTablesAction,
    observability::exporter::OpenTelemetryMetricExporterAdapter,
};

pub(self) mod access_log;
pub(self) mod attestation_result;
pub(self) mod cert_verifier;
mod egress;
mod ingress;
pub(self) mod service_metrics;
mod utils;

#[async_trait]
pub(self) trait RegistedService {
    async fn serve(&self, shutdown_guard: ShutdownGuard, ready: Sender<()>) -> Result<()>;
}

pub struct TngRuntime {
    services: Vec<(Box<dyn RegistedService + Send + Sync>, Span)>,
    iptables_actions: Vec<IpTablesAction>,
}

impl TngRuntime {
    fn setup_metric_exporter(tng_config: &TngConfig) -> Result<()> {
        // Initialize OpenTelemetry

        let exporter = if let Some(c) = &tng_config.metric {
            if c.exporters.len() > 1 {
                bail!("Only one exporter is supported for now")
            }
            match c.exporters.iter().next() {
                Some(exporter_type) => {
                    let (_step, exporter) = exporter_type.instantiate()?;
                    // TODO: Use the step to config opentelemetry
                    Some(exporter)
                }
                None => None,
            }
        } else {
            None
        };

        if let Some(exporter) = exporter {
            let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
                .with_periodic_exporter(OpenTelemetryMetricExporterAdapter::new(exporter))
                .build();
            opentelemetry::global::set_meter_provider(meter_provider.clone());
        }

        Ok(())
    }

    pub fn launch_from_config(tng_config: TngConfig) -> Result<Self> {
        let mut iptables_actions = vec![];
        let mut services: Vec<(Box<dyn RegistedService + Send + Sync>, Span)> = vec![];

        for (id, add_ingress) in tng_config.add_ingress.iter().enumerate() {
            let add_ingress = add_ingress.clone();
            match &add_ingress.ingress_mode {
                IngressMode::Mapping(mapping_args) => {
                    services.push((
                        Box::new(MappingIngress::new(id, mapping_args, &add_ingress.common)?),
                        tracing::info_span!("ingress", id),
                    ));
                }
                IngressMode::HttpProxy(http_proxy_args) => {
                    let ingress = HttpProxyIngress::new(id, http_proxy_args, &add_ingress.common)?;
                    services.push((Box::new(ingress), tracing::info_span!("ingress", id)));
                }
                IngressMode::Netfilter(_) => {
                    if !cfg!(target_os = "linux") {
                        anyhow::bail!("Using egress with 'netfilter' type is not supported on OS other than Linux");
                    }

                    todo!()
                }
            }
        }

        for (id, add_egress) in tng_config.add_egress.iter().enumerate() {
            let add_egress = add_egress.clone();
            match &add_egress.egress_mode {
                EgressMode::Mapping(mapping_args) => {
                    let egress = MappingEgress::new(id, mapping_args, &add_egress.common)?;
                    services.push((Box::new(egress), tracing::info_span!("egress", id)));
                }
                EgressMode::Netfilter(netfilter_args) => {
                    if !cfg!(target_os = "linux") {
                        anyhow::bail!("Using egress with 'netfilter' type is not supported on OS other than Linux");
                    }

                    #[cfg(target_os = "linux")]
                    {
                        use egress::netfilter::NetfilterEgress;
                        let egress = NetfilterEgress::new(
                            id,
                            netfilter_args,
                            &add_egress.common,
                            &mut iptables_actions,
                        )?;
                        services.push((Box::new(egress), tracing::info_span!("egress", id)));
                    }
                }
            }
        }

        Self::setup_metric_exporter(&tng_config)?;

        Ok(Self {
            services,
            iptables_actions,
        })
    }

    pub async fn serve(
        mut self,
        shutdown_guard: ShutdownGuard,
        task_exit: CancellationToken,
        ready: tokio::sync::oneshot::Sender<()>,
    ) -> Result<()> {
        // Setup iptables
        #[cfg(not(target_os = "linux"))]
        drop(iptables_actions);
        #[cfg(target_os = "linux")]
        let _iptables_guard =
            crate::executor::iptables::IPTablesGuard::setup_from_actions(self.iptables_actions)?;

        // Setup all services
        let service_count = self.services.len();
        tracing::info!("Starting all {service_count} services");

        let (sender, mut receiver) = tokio::sync::mpsc::channel(service_count);

        for (service, span) in self.services.drain(..) {
            let task_exit = task_exit.clone();
            let sender = sender.clone();
            shutdown_guard.spawn_task_fn(|shutdown_guard| {
                async move {
                    if let Err(e) = service.serve(shutdown_guard, sender).await {
                        let error = format!("{e:#}");
                        tracing::error!(%error, "failed to serve, canceling and exitng new");
                        task_exit.cancel();
                    }
                }
                .instrument(span)
            });
        }

        let check_services_ready = async {
            for _ in 0..service_count {
                receiver.recv().await;
            }
        };

        let meter = opentelemetry::global::meter("tng");
        let live = meter
            .u64_gauge("live")
            .with_description("Indicates the server is alive or not")
            .build();
        live.record(0, &[]);

        tokio::select! {
            _ = check_services_ready => {
                tracing::info!("All of the services are ready");
                live.record(1, &[]);

                let _ = ready.send(());// Ignore any error occuring during send
                shutdown_guard.cancelled().await;
            }
            _ = shutdown_guard.cancelled() => {}
        };

        Ok(())
    }
}

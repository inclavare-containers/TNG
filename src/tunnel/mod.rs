use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context as _, Result};
use async_trait::async_trait;
use egress::mapping::MappingEgress;
use ingress::{http_proxy::HttpProxyIngress, mapping::MappingIngress};
use state::TngState;
use tokio::sync::mpsc::Sender;
use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

use crate::{
    config::{egress::EgressMode, ingress::IngressMode, metric::ExporterInstance, TngConfig},
    control_interface::ControlInterface,
    executor::iptables::IpTablesAction,
    observability::exporter::OpenTelemetryMetricExporterAdapter,
};

pub(self) mod access_log;
pub(self) mod attestation_result;
pub(self) mod cert_verifier;
mod egress;
mod ingress;
pub(self) mod service_metrics;
pub mod state;
mod utils;

#[async_trait]
pub trait RegistedService {
    async fn serve(&self, shutdown_guard: ShutdownGuard, ready: Sender<()>) -> Result<()>;
}

pub struct TngRuntime {
    services: Vec<(Box<dyn RegistedService + Send + Sync>, Span)>,
    iptables_actions: Vec<IpTablesAction>,
    state: Arc<TngState>,
}

impl TngRuntime {
    fn setup_metric_exporter(tng_config: &TngConfig) -> Result<()> {
        // Initialize OpenTelemetry

        let exporter = if let Some(c) = &tng_config.metric {
            if c.exporters.len() > 1 {
                bail!("Only one exporter is supported for now")
            }
            match c.exporters.iter().next() {
                Some(exporter_type) => Some(exporter_type.instantiate()?),
                None => None,
            }
        } else {
            None
        };

        if let Some(exporter) = exporter {
            let resource = opentelemetry_sdk::Resource::builder()
                .with_service_name("tng")
                .with_attribute(
                    // https://opentelemetry.io/docs/specs/semconv/attributes-registry/service/
                    opentelemetry::KeyValue::new("service.version", crate::build::PKG_VERSION),
                )
                .build();
            let meter_provider = match exporter {
                ExporterInstance::Simple(step, simple_metric_exporter) => {
                    let exporter = OpenTelemetryMetricExporterAdapter::new(simple_metric_exporter);
                    let reader = opentelemetry_sdk::metrics::periodic_reader_with_async_runtime::PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio)
                        .with_interval(Duration::from_secs(step))
                        .build();
                    opentelemetry_sdk::metrics::SdkMeterProvider::builder()
                        .with_reader(reader)
                        .with_resource(resource)
                        .build()
                }
                ExporterInstance::OpenTelemetry(step, exporter) => {
                    let reader = opentelemetry_sdk::metrics::periodic_reader_with_async_runtime::PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio)
                        .with_interval(Duration::from_secs(step))
                        .build();
                    opentelemetry_sdk::metrics::SdkMeterProvider::builder()
                        .with_reader(reader)
                        .with_resource(resource)
                        .build()
                }
            };

            opentelemetry::global::set_meter_provider(meter_provider.clone());
        }

        Ok(())
    }

    pub async fn new_from_config(tng_config: TngConfig) -> Result<Self> {
        let mut iptables_actions = vec![];
        let mut services: Vec<(Box<dyn RegistedService + Send + Sync>, Span)> = vec![];

        for (id, add_ingress) in tng_config.add_ingress.iter().enumerate() {
            let add_ingress = add_ingress.clone();
            match &add_ingress.ingress_mode {
                IngressMode::Mapping(mapping_args) => {
                    services.push((
                        Box::new(MappingIngress::new(id, mapping_args, &add_ingress.common).await?),
                        tracing::info_span!("ingress", id),
                    ));
                }
                IngressMode::HttpProxy(http_proxy_args) => {
                    let ingress =
                        HttpProxyIngress::new(id, http_proxy_args, &add_ingress.common).await?;
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
                    let egress = MappingEgress::new(id, mapping_args, &add_egress.common).await?;
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
                        )
                        .await?;
                        services.push((Box::new(egress), tracing::info_span!("egress", id)));
                    }
                }
            }
        }

        Self::setup_metric_exporter(&tng_config)?;

        let state = Arc::new(TngState::new());

        // Launch Control Interface
        if let Some(args) = tng_config.control_interface {
            let control_interface = ControlInterface::new(args, state.clone())
                .await
                .context("Failed to init control interface")?;
            services.push((
                Box::new(control_interface),
                tracing::info_span!("control_interface"),
            ));
        }

        Ok(Self {
            services,
            iptables_actions,
            state,
        })
    }

    pub fn state(&self) -> Arc<TngState> {
        Arc::clone(&self.state)
    }

    pub async fn serve(mut self, shutdown_guard: ShutdownGuard) -> Result<()> {
        // Setup iptables
        #[cfg(not(target_os = "linux"))]
        drop(iptables_actions);
        #[cfg(target_os = "linux")]
        let _iptables_guard =
            crate::executor::iptables::IPTablesGuard::setup_from_actions(self.iptables_actions)?;

        // Setup all services
        let service_count = self.services.len();
        tracing::info!("Starting all {service_count} services");

        let (mut ready_receiver, mut error_receiver) = {
            let (ready_sender, ready_receiver) = tokio::sync::mpsc::channel(service_count);
            let (error_sender, error_receiver) = tokio::sync::mpsc::channel(service_count);

            for (service, span) in self.services.drain(..) {
                let ready_sender = ready_sender.clone();
                let error_sender = error_sender.clone();
                shutdown_guard.spawn_task_fn(|shutdown_guard| {
                    async move {
                        if let Err(e) = service.serve(shutdown_guard, ready_sender).await {
                            tracing::error!(error=?e, "service failed");
                            let _ = error_sender.send(e).await;
                        }
                    }
                    .instrument(span)
                });
            }
            (ready_receiver, error_receiver)
        };

        let check_services_ready = async {
            for _ in 0..service_count {
                ready_receiver.recv().await;
            }
        };

        let meter = opentelemetry::global::meter("tng");
        let live = meter
            .u64_gauge("live")
            .with_description("Indicates the server is alive or not")
            .build();
        live.record(0, &[]);

        let maybe_err = tokio::select! {
            _ = check_services_ready => {
                tracing::info!("All of the services are ready");
                live.record(1, &[]);

                let _ = self.state.ready.0.send(true); // Ignore any error occuring during send

                tokio::select! {
                    maybe_err = error_receiver.recv() => {maybe_err}
                    _ = shutdown_guard.cancelled() => None
                }
            }
            maybe_err = error_receiver.recv() => {maybe_err}
            _ = shutdown_guard.cancelled() => None
        };

        if let Some(_e) = maybe_err {
            tracing::error!("failed to serve all services, canceling and exiting now");
        } else {
            // Shutdown gracefully
        }

        Ok(())
    }
}

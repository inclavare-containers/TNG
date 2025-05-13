use std::sync::Arc;

use crate::observability::metric::exporter::noop::NoopMeterProvider;
use crate::observability::trace::shutdown_guard_ext::ShutdownGuardExt;
use crate::service::RegistedService;
use crate::state::TngState;
use crate::tunnel::egress::mapping::MappingEgress;
use crate::tunnel::ingress::{http_proxy::HttpProxyIngress, mapping::MappingIngress};
use crate::{
    config::{egress::EgressMode, ingress::IngressMode, TngConfig},
    control_interface::ControlInterface,
};

use anyhow::{bail, Context as _, Result};
use opentelemetry::metrics::MeterProvider;
use opentelemetry::trace::TracerProvider;
use scopeguard::defer;
use tokio_graceful::ShutdownGuard;
use tokio_util::sync::CancellationToken;
use tracing::Span;

pub struct TngRuntime {
    services: Vec<(Box<dyn RegistedService + Send + Sync>, Span)>,
    state: Arc<TngState>,
    meter_provider: Arc<dyn MeterProvider + Send + Sync>,
}

pub type TracingReloadHandle = tracing_subscriber::reload::Handle<
    Vec<Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>>,
    tracing_subscriber::Registry,
>;

impl TngRuntime {
    #[cfg(test)]
    pub async fn from_config(tng_config: TngConfig) -> Result<Self> {
        Self::from_config_with_reload_handle(
            tng_config,
            crate::tests::RELOAD_HANDLE
                .get()
                .expect("logger is not initialized"),
        )
        .await
    }

    pub async fn from_config_with_reload_handle(
        mut tng_config: TngConfig,
        reload_handle: &TracingReloadHandle,
    ) -> Result<Self> {
        if tng_config.admin_bind.is_some() {
            tracing::warn!("The field `admin_bind` in configuration is ignored, since envoy admin interface is deprecated");
            tng_config.admin_bind = None;
        }

        let meter_provider =
            Self::setup_metric_exporter(&tng_config).context("Failed to setup metric exporter")?;

        Self::setup_trace_exporter(&tng_config, reload_handle)
            .context("Failed to setup trace exporter")?;

        // Create all ingress and egress.
        let mut services: Vec<(Box<dyn RegistedService + Send + Sync>, Span)> = vec![];

        for (id, add_ingress) in tng_config.add_ingress.iter().enumerate() {
            let add_ingress = add_ingress.clone();
            match &add_ingress.ingress_mode {
                IngressMode::Mapping(mapping_args) => {
                    services.push((
                        Box::new(
                            MappingIngress::new(
                                id,
                                mapping_args,
                                &add_ingress.common,
                                meter_provider.clone(),
                            )
                            .await?,
                        ),
                        tracing::info_span!("ingress", id),
                    ));
                }
                IngressMode::HttpProxy(http_proxy_args) => {
                    services.push((
                        Box::new(
                            HttpProxyIngress::new(
                                id,
                                http_proxy_args,
                                &add_ingress.common,
                                meter_provider.clone(),
                            )
                            .await?,
                        ),
                        tracing::info_span!("ingress", id),
                    ));
                }
                IngressMode::Netfilter(netfilter_args) => {
                    if !cfg!(target_os = "linux") {
                        let _ = netfilter_args;
                        anyhow::bail!("Using egress with 'netfilter' type is not supported on OS other than Linux");
                    }

                    #[cfg(target_os = "linux")]
                    {
                        use crate::tunnel::ingress::netfilter::NetfilterIngress;
                        services.push((
                            Box::new(
                                NetfilterIngress::new(
                                    id,
                                    netfilter_args,
                                    &add_ingress.common,
                                    meter_provider.clone(),
                                )
                                .await?,
                            ),
                            tracing::info_span!("ingress", id),
                        ));
                    }
                }
            }
        }

        for (id, add_egress) in tng_config.add_egress.iter().enumerate() {
            let add_egress = add_egress.clone();
            match &add_egress.egress_mode {
                EgressMode::Mapping(mapping_args) => {
                    let egress = MappingEgress::new(
                        id,
                        mapping_args,
                        &add_egress.common,
                        meter_provider.clone(),
                    )
                    .await?;
                    services.push((Box::new(egress), tracing::info_span!("egress", id)));
                }
                EgressMode::Netfilter(netfilter_args) => {
                    if !cfg!(target_os = "linux") {
                        let _ = netfilter_args;
                        anyhow::bail!("Using egress with 'netfilter' type is not supported on OS other than Linux");
                    }

                    #[cfg(target_os = "linux")]
                    {
                        use crate::tunnel::egress::netfilter::NetfilterEgress;
                        let egress = NetfilterEgress::new(
                            id,
                            netfilter_args,
                            &add_egress.common,
                            meter_provider.clone(),
                        )
                        .await?;
                        services.push((Box::new(egress), tracing::info_span!("egress", id)));
                    }
                }
            }
        }

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
            state,
            meter_provider,
        })
    }

    pub fn state(&self) -> Arc<TngState> {
        Arc::clone(&self.state)
    }

    pub async fn serve_forever(self) -> Result<()> {
        self.serve_with_cancel(CancellationToken::new(), tokio::sync::oneshot::channel().0)
            .await
    }

    pub async fn serve_with_cancel(
        self,
        cancel_by_caller: CancellationToken, // This is a canell token which can be called from the caller to cancel the task. Note that this funnction will not call the cancel() function on this.
        ready: tokio::sync::oneshot::Sender<()>,
    ) -> Result<()> {
        // Start native part
        tracing::info!("Starting tng instance now");

        let cancel_before_func_return = CancellationToken::new();
        let for_cancel_safity = cancel_before_func_return.clone();
        defer! {
            // Cancel-Safity: exit tng in case of the future of this function is dropped
            for_cancel_safity.cancel();
        }

        // Prepare for graceful shutdown
        let shutdown = {
            let cancel_before_func_return = cancel_before_func_return.clone();
            tokio_graceful::Shutdown::builder()
                .with_signal(async move {
                    tokio::select! {
                        _ = cancel_by_caller.cancelled() => {}
                        _ = cancel_before_func_return.cancelled() => {}
                        _ = tokio_graceful::default_signal() => {}
                    }
                })
                .with_overwrite_fn(tokio::signal::ctrl_c)
                .build()
        };

        // Watch the ready signal from the tng runtime state object.
        {
            let mut receiver = self.state().ready.0.subscribe();
            shutdown.guard().spawn_supervised_task(async move {
                loop {
                    let _ = receiver.changed().await; // Ignore any error
                    if *receiver.borrow_and_update() {
                        let _ = ready.send(()); // Ignore any error occuring during send
                        break;
                    }
                }
            });
        }

        // Wait for the runtime to finish serving.
        self.serve(shutdown.guard()).await?;
        // Trigger the shutdown guard to gracefully shutdown all the tokio tasks.
        cancel_before_func_return.cancel();
        // Wait for the shutdown guard to complete.
        shutdown.shutdown().await;

        tracing::debug!("The instance is shutdown complete");
        Ok(())
    }

    async fn serve(mut self, shutdown_guard: ShutdownGuard) -> Result<()> {
        // Setup all services
        let service_count = self.services.len();
        tracing::info!("Starting all {service_count} services");

        let (mut ready_receiver, mut error_receiver) = {
            let (ready_sender, ready_receiver) = tokio::sync::mpsc::channel(service_count);
            let (error_sender, error_receiver) = tokio::sync::mpsc::channel(service_count);

            for (service, span) in self.services.drain(..) {
                let ready_sender = ready_sender.clone();
                let error_sender = error_sender.clone();
                shutdown_guard.spawn_supervised_task_fn_with_span(
                    span,
                    |shutdown_guard| async move {
                        if let Err(e) = service.serve(shutdown_guard, ready_sender).await {
                            tracing::error!(error=?e, "service failed");
                            let _ = error_sender.send(e).await;
                        }
                    },
                );
            }
            (ready_receiver, error_receiver)
        };

        let check_services_ready = async {
            for _ in 0..service_count {
                ready_receiver.recv().await;
            }
        };

        let meter = self.meter_provider.meter("tng");
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

                // Now waiting for exiting signal
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
            tracing::info!("Now shutdown the instance gracefully");
        }

        Ok(())
    }

    fn setup_metric_exporter(
        tng_config: &TngConfig,
    ) -> Result<Arc<dyn MeterProvider + Send + Sync>> {
        let exporter = if let Some(c) = &tng_config.metric {
            if c.exporters.len() > 1 {
                bail!("Only one exporter is supported for now")
            }
            match c.exporters.first() {
                Some(exporter_type) => Some(exporter_type.instantiate()?),
                None => None,
            }
        } else {
            None
        };

        Ok(if let Some(exporter) = exporter {
            let meter_provider = exporter.into_sdk_meter_provider();
            Arc::new(meter_provider)
        } else {
            Arc::new(NoopMeterProvider::new())
        })
    }

    fn setup_trace_exporter(
        tng_config: &TngConfig,
        reload_handle: &TracingReloadHandle,
    ) -> Result<()> {
        if let Some(log_args) = &tng_config.trace {
            for exporter in &log_args.exporters {
                let exporter = exporter.instantiate()?;
                let tracer_provider = exporter.into_sdk_tracer_provider();

                // Note here we register the tracer provider into tracing crate, so there is no need to call `opentelemetry::global::set_tracer_provider()`
                let tracer = tracer_provider.tracer("tng");
                let telemetry_layer = tracing_opentelemetry::layer()
                    .with_level(true)
                    .with_tracer(tracer);

                let reload_result = reload_handle.modify(|layers| {
                    (*layers).push(Box::new(telemetry_layer));
                });
                match reload_result {
                    Ok(_) => {} // Great!
                    Err(err) => tracing::warn!("Unable to add new layer: {}", err),
                }
            }
        }

        Ok(())
    }
}

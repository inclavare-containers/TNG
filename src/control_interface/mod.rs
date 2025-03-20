use std::sync::Arc;

use crate::{
    config::control_interface::ControlInterfaceArgs,
    executor::envoy::admin_interface::EnvoyAdminInterface,
};
use anyhow::Result;
use log::error;
use restful::RestfulControlInterface;
use tokio_graceful::ShutdownGuard;

mod restful;
mod ttrpc;

pub struct ControlInterface {}

impl ControlInterface {
    pub async fn launch(
        args: ControlInterfaceArgs,
        envoy_admin_interface: EnvoyAdminInterface,
        shutdown_guard: ShutdownGuard,
    ) -> Result<()> {
        let core = Arc::new(ControlInterfaceCore::new(envoy_admin_interface));

        if let Some(restful_args) = args.restful {
            shutdown_guard.spawn_task_fn(|shutdown_guard| async move {
                tokio::select! {
                    _ = shutdown_guard.cancelled() => {  /* exit here */ },
                    res = RestfulControlInterface::serve(restful_args, core) => {
                        if let Err(err) = res {
                            error!("restful control interface failed: {}", err);
                        }
                    },
                };
            });
        }

        if let Some(_) = args.ttrpc {
            todo!("ttrpc not implemented yet")
        }

        Ok(())
    }
}

pub struct ControlInterfaceCore {
    envoy_admin_interface: EnvoyAdminInterface,
}

impl ControlInterfaceCore {
    pub fn new(envoy_admin_interface: EnvoyAdminInterface) -> Self {
        Self {
            envoy_admin_interface,
        }
    }

    pub async fn livez(&self) -> bool {
        self.envoy_admin_interface
            .pull_admin_interface_status()
            .await
    }

    pub async fn readyz(&self) -> bool {
        self.envoy_admin_interface.pull_ready_status().await
    }
}

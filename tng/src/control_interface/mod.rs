use std::sync::Arc;

use crate::{
    config::control_interface::ControlInterfaceArgs, service::RegistedService, state::TngState,
    tunnel::utils::runtime::TokioRuntime,
};
use anyhow::{bail, Result};
use async_trait::async_trait;
use restful::RestfulControlInterface;
use tokio::sync::mpsc::Sender;

mod restful;
mod ttrpc;

pub struct ControlInterface {
    inner: ControlInterfaceInner,
    runtime: TokioRuntime,
}

enum ControlInterfaceInner {
    Restful(RestfulControlInterface),
    #[allow(dead_code)]
    Ttrpc(()),
    #[allow(dead_code)]
    Both(RestfulControlInterface, ()),
}

impl ControlInterface {
    pub async fn new(
        args: ControlInterfaceArgs,
        state: Arc<TngState>,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let core = Arc::new(ControlInterfaceCore::new(state));

        Ok(match (args.restful, args.ttrpc) {
            (None, None) => {
                bail!("At least one control interface `restful` or `ttrpc` must be specified")
            }
            (Some(args), None) => ControlInterface {
                inner: ControlInterfaceInner::Restful(
                    RestfulControlInterface::new(args, core).await?,
                ),
                runtime,
            },
            (_, Some(_)) => {
                todo!("control interface with ttrpc type not supported yet")
            }
        })
    }
}

#[async_trait]
impl RegistedService for ControlInterface {
    async fn serve(&self, ready: Sender<()>) -> Result<()> {
        tracing::info!("control interface launching");
        let _ = ready.send(()).await;

        match &self.inner {
            ControlInterfaceInner::Restful(restful) | ControlInterfaceInner::Both(restful, _) => {
                tokio::select! {
                    _ = self.runtime.shutdown_guard().cancelled() => {  /* exit here */ },
                    res = restful.serve() => {
                        if let Err(err) = &res {
                            tracing::error!("restful control interface failed: {}", err);
                        }
                        res?
                    },
                };
            }
            ControlInterfaceInner::Ttrpc(_) => todo!(),
        }

        tracing::info!("control interface exited");
        Ok(())
    }
}
pub struct ControlInterfaceCore {
    state: Arc<TngState>,
}

impl ControlInterfaceCore {
    pub fn new(state: Arc<TngState>) -> Self {
        Self { state }
    }

    pub async fn livez(&self) -> bool {
        true
    }

    pub async fn readyz(&self) -> bool {
        *self.state.ready.1.borrow()
    }
}

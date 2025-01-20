use anyhow::{bail, Result};
use log::{info, warn};
use tracing::Instrument;

use crate::config::{ingress::IngressMode, TngConfig};

mod ingress;

pub async fn run_native_part(
    mut stop_rx: tokio::sync::watch::Receiver<()>,
    tng_config: TngConfig,
) -> Result<()> {
    info!("TNG native part running now");

    for (id, add_ingress) in tng_config.add_ingress.iter().enumerate() {
        let add_ingress = add_ingress.clone();
        tokio::task::spawn(async move {
            match &add_ingress.ingress_mode {
                IngressMode::Mapping(_) => Ok(()),
                IngressMode::HttpProxy(http_proxy_args) => {
                    match &add_ingress.common.encap_in_http {
                        Some(_encap_in_http) => Ok(()),
                        None => {
                            self::ingress::http_proxy::l4::run(http_proxy_args, &add_ingress.common)
                                .instrument(tracing::info_span!("ingress", id))
                                .await
                        }
                    }
                }
                IngressMode::Netfilter(_) => todo!(),
            }
        });
    }

    if let Err(e) = stop_rx.changed().await {
        warn!("The stop signal sender is dropped unexpectedly: {e:#}");
    };

    info!("TNG native part exiting now");
    Ok(())
}

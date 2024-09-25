use anyhow::{bail, Result};
use log::{info, warn};

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
            if add_ingress.attest == None
                && add_ingress.verify == None
                && add_ingress.no_ra == false
            {
                bail!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_ingress'");
            }

            if add_ingress.no_ra {
                warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment")
            }

            match &add_ingress.ingress_mode {
                IngressMode::Mapping { r#in, out } => Ok(()),
                IngressMode::HttpProxy {
                    proxy_listen,
                    dst_filters,
                } => {
                    let proxy_listen_addr = proxy_listen.host.as_deref().unwrap_or("0.0.0.0");
                    let proxy_listen_port = proxy_listen.port;

                    match &add_ingress.encap_in_http {
                        Some(_encap_in_http) => Ok(()),
                        None => {
                            self::ingress::http_proxy::l4::run(
                                id,
                                proxy_listen_addr,
                                proxy_listen_port,
                                dst_filters,
                                add_ingress.no_ra,
                                &add_ingress.attest,
                                &add_ingress.verify,
                            )
                            .await
                        }
                    }
                }
                IngressMode::Netfilter { dst: _ } => todo!(),
            }
        });
    }

    if let Err(e) = stop_rx.changed().await {
        warn!("The stop signal sender is dropped unexpectedly: {e:#}");
    };

    info!("TNG native part exiting now");
    Ok(())
}

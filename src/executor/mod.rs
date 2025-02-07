use anyhow::{bail, Result};
use envoy::EnvoyConfig;
use iptables::{IpTablesAction, IpTablesActions};
use log::{debug, warn};

use crate::config::{
    egress::{EgressMode, EgressNetfilterArgs},
    ingress::{IngressMode, IngressNetfilterArgs},
    TngConfig,
};

pub mod envoy;
pub mod iptables;

const NETFILTER_LISTEN_PORT_BEGIN_DEFAULT: u16 = 40000;
const NETFILTER_SO_MARK_DEFAULT: u32 = 565;

pub fn handle_config(config: TngConfig) -> Result<(EnvoyConfig, IpTablesActions)> {
    let mut listeners = vec![];
    let mut clusters = vec![];

    let mut iptables_actions = vec![];
    for (id, add_ingress) in config.add_ingress.iter().enumerate() {
        if add_ingress.common.ra_args.attest == None
            && add_ingress.common.ra_args.verify == None
            && add_ingress.common.ra_args.no_ra == false
        {
            bail!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_ingress'");
        }

        if add_ingress.common.ra_args.no_ra {
            warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment")
        }

        match &add_ingress.ingress_mode {
            IngressMode::Mapping(_) => { /* do nothing */ }
            IngressMode::HttpProxy(_) => { /* do nothing */ }
            IngressMode::Netfilter(IngressNetfilterArgs { dst: _ }) => todo!(),
        }
    }

    for (id, add_egress) in config.add_egress.iter().enumerate() {
        if add_egress.common.ra_args.attest == None
            && add_egress.common.ra_args.verify == None
            && add_egress.common.ra_args.no_ra == false
        {
            bail!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_egress'");
        }

        if add_egress.common.ra_args.no_ra {
            warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment")
        }

        match &add_egress.egress_mode {
            EgressMode::Mapping(_) => {
                // Do nothing
            }
            EgressMode::Netfilter(EgressNetfilterArgs {
                capture_dst,
                capture_local_traffic,
                listen_port,
                so_mark,
            }) => {
                let listen_port =
                    listen_port.unwrap_or(NETFILTER_LISTEN_PORT_BEGIN_DEFAULT + (id as u16));
                let so_mark = so_mark.unwrap_or(NETFILTER_SO_MARK_DEFAULT);

                iptables_actions.push(IpTablesAction::Redirect {
                    capture_dst: capture_dst.clone(),
                    capture_local_traffic: *capture_local_traffic,
                    listen_port,
                    so_mark,
                });

                let mut yamls = match &add_egress.common.decap_from_http {
                    Some(decap_from_http) => self::envoy::confgen::egress::netfilter::l7::gen(
                        id,
                        listen_port,
                        so_mark,
                        decap_from_http,
                        add_egress.common.ra_args.no_ra,
                        &add_egress.common.ra_args.attest,
                        &add_egress.common.ra_args.verify,
                    )?,
                    None => self::envoy::confgen::egress::netfilter::l4::gen(
                        id,
                        listen_port,
                        so_mark,
                        add_egress.common.ra_args.no_ra,
                        &add_egress.common.ra_args.attest,
                        &add_egress.common.ra_args.verify,
                    )?,
                };
                listeners.append(&mut yamls.0);
                clusters.append(&mut yamls.1);
            }
        }
    }
    let config = format!(
        r#"
bootstrap_extensions:
- name: envoy.bootstrap.internal_listener
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.bootstrap.internal_listener.v3.InternalListener
{}

static_resources:

  listeners:{}

  clusters:{}
"#,
        if let Some(admin_bind) = &config.admin_bind {
            let host = admin_bind.host.as_deref().unwrap_or("0.0.0.0");
            let port = admin_bind.port;

            debug!("Admin interface is enabled for envoy: http://{host}:{port}");

            format!(
                r#"
admin:
  address:
    socket_address:
      address: {}
      port_value: {}
            "#,
                host, port
            )
        } else {
            "".to_owned()
        },
        listeners.join("\n"),
        clusters.join("\n")
    );
    Ok((EnvoyConfig(config), iptables_actions))
}

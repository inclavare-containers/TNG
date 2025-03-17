use anyhow::{bail, Context as _, Result};
use envoy::EnvoyConfig;
use iptables::{IpTablesAction, IpTablesActions};
use log::{debug, warn};

use crate::{
    config::{egress::EgressMode, ingress::IngressMode, TngConfig},
    observability::collector::envoy::{MetricCollector, METRIC_COLLECTOR_STEP_DEFAULT},
};

pub mod envoy;
pub mod iptables;

const NETFILTER_LISTEN_PORT_BEGIN_DEFAULT: u16 = 40000;
const NETFILTER_SO_MARK_DEFAULT: u32 = 565;

pub struct Blueprint {
    pub envoy_config: EnvoyConfig,
    pub metric_collector: MetricCollector,
    pub envoy_admin_endpoint: (String /* host */, u16 /* port */),
    pub iptables_actions: IpTablesActions,
}

pub fn handle_config(config: TngConfig) -> Result<Blueprint> {
    // Prepare envoy admin interface config
    let envoy_admin_endpoint = match config.admin_bind {
        Some(admin_bind) => (
            admin_bind.host.as_deref().unwrap_or("0.0.0.0").to_owned(),
            admin_bind.port,
        ),
        None => (
            "127.0.0.1".to_owned(),
            portpicker::pick_unused_port().context("No available port")?,
        ),
    };

    debug!(
        "Envoy admin interface will be enabled at {}:{}",
        envoy_admin_endpoint.0, envoy_admin_endpoint.1
    );

    let admin_config = format!(
        r#"
admin:
  address:
    socket_address:
      address: {}
      port_value: {}
"#,
        envoy_admin_endpoint.0, envoy_admin_endpoint.1
    );

    let (step, exporter) = if let Some(c) = config.metric {
        if c.exporters.len() > 1 {
            bail!("Only one exporter is supported for now")
        }
        match c.exporters.iter().next() {
            Some(exporter_type) => {
                let (step, exporter) = exporter_type.instantiate()?;
                (step, Some(exporter))
            }
            None => (METRIC_COLLECTOR_STEP_DEFAULT, None),
        }
    } else {
        (METRIC_COLLECTOR_STEP_DEFAULT, None)
    };

    let envoy_admin_endpoint = (
        if envoy_admin_endpoint.0 == "0.0.0.0" {
            "127.0.0.1".to_owned()
        } else {
            envoy_admin_endpoint.0
        },
        envoy_admin_endpoint.1,
    );

    let mut metric_collector = MetricCollector::new(envoy_admin_endpoint.clone(), step);

    if let Some(exporter) = exporter {
        metric_collector.register_metric_exporter(exporter);
    };

    // Prepare envoy listeners and clusters config
    let mut listeners = vec![];
    let mut clusters = vec![];

    let mut iptables_actions = vec![];
    for (id, add_ingress) in config.add_ingress.iter().enumerate() {
        if add_ingress.attest == None && add_ingress.verify == None && add_ingress.no_ra == false {
            bail!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_ingress'");
        }

        if add_ingress.no_ra {
            warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment")
        }

        match &add_ingress.ingress_mode {
            IngressMode::Mapping { r#in, out } => {
                let in_addr = r#in.host.as_deref().unwrap_or("0.0.0.0");
                let in_port = r#in.port;

                let out_addr = out
                    .host
                    .as_deref()
                    .context("'host' of 'out' field must be set")?;
                let out_port = out.port;

                let mut yamls = match &add_ingress.encap_in_http {
                    Some(encap_in_http) => self::envoy::confgen::ingress::mapping::l7::gen(
                        id,
                        in_addr,
                        in_port,
                        out_addr,
                        out_port,
                        add_ingress.web_page_inject,
                        encap_in_http,
                        add_ingress.no_ra,
                        &add_ingress.attest,
                        &add_ingress.verify,
                        &mut metric_collector,
                    )?,
                    None => self::envoy::confgen::ingress::mapping::l4::gen(
                        id,
                        in_addr,
                        in_port,
                        out_addr,
                        out_port,
                        add_ingress.no_ra,
                        &add_ingress.attest,
                        &add_ingress.verify,
                        &mut metric_collector,
                    )?,
                };
                listeners.append(&mut yamls.0);
                clusters.append(&mut yamls.1);
            }
            IngressMode::HttpProxy {
                proxy_listen,
                dst_filters,
            } => {
                let proxy_listen_addr = proxy_listen.host.as_deref().unwrap_or("0.0.0.0");
                let proxy_listen_port = proxy_listen.port;

                let mut yamls = match &add_ingress.encap_in_http {
                    Some(encap_in_http) => self::envoy::confgen::ingress::http_proxy::l7::gen(
                        id,
                        proxy_listen_addr,
                        proxy_listen_port,
                        dst_filters,
                        add_ingress.web_page_inject,
                        encap_in_http,
                        add_ingress.no_ra,
                        &add_ingress.attest,
                        &add_ingress.verify,
                        &mut metric_collector,
                    )?,
                    None => self::envoy::confgen::ingress::http_proxy::l4::gen(
                        id,
                        proxy_listen_addr,
                        proxy_listen_port,
                        dst_filters,
                        add_ingress.no_ra,
                        &add_ingress.attest,
                        &add_ingress.verify,
                        &mut metric_collector,
                    )?,
                };
                listeners.append(&mut yamls.0);
                clusters.append(&mut yamls.1);
            }
            IngressMode::Netfilter { dst: _ } => todo!(),
        }
    }

    for (id, add_egress) in config.add_egress.iter().enumerate() {
        if add_egress.attest == None && add_egress.verify == None && add_egress.no_ra == false {
            bail!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_egress'");
        }

        if add_egress.no_ra {
            warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment")
        }

        match &add_egress.egress_mode {
            EgressMode::Mapping { r#in, out } => {
                let in_addr = r#in.host.as_deref().unwrap_or("0.0.0.0");
                let in_port = r#in.port;

                let out_addr = out
                    .host
                    .as_deref()
                    .context("'host' of 'out' field must be set")?;
                let out_port = out.port;

                let mut yamls = match &add_egress.decap_from_http {
                    Some(decap_from_http) => self::envoy::confgen::egress::mapping::l7::gen(
                        id,
                        in_addr,
                        in_port,
                        out_addr,
                        out_port,
                        decap_from_http,
                        add_egress.no_ra,
                        &add_egress.attest,
                        &add_egress.verify,
                        &mut metric_collector,
                    )?,
                    None => self::envoy::confgen::egress::mapping::l4::gen(
                        id,
                        in_addr,
                        in_port,
                        out_addr,
                        out_port,
                        add_egress.no_ra,
                        &add_egress.attest,
                        &add_egress.verify,
                        &mut metric_collector,
                    )?,
                };
                listeners.append(&mut yamls.0);
                clusters.append(&mut yamls.1);
            }
            EgressMode::Netfilter {
                capture_dst,
                capture_local_traffic,
                listen_port,
                so_mark,
            } => {
                let listen_port =
                    listen_port.unwrap_or(NETFILTER_LISTEN_PORT_BEGIN_DEFAULT + (id as u16));
                let so_mark = so_mark.unwrap_or(NETFILTER_SO_MARK_DEFAULT);

                iptables_actions.push(IpTablesAction::Redirect {
                    capture_dst: capture_dst.clone(),
                    capture_local_traffic: *capture_local_traffic,
                    listen_port,
                    so_mark,
                });

                let mut yamls = match &add_egress.decap_from_http {
                    Some(decap_from_http) => self::envoy::confgen::egress::netfilter::l7::gen(
                        id,
                        listen_port,
                        so_mark,
                        decap_from_http,
                        add_egress.no_ra,
                        &add_egress.attest,
                        &add_egress.verify,
                        &mut metric_collector,
                    )?,
                    None => self::envoy::confgen::egress::netfilter::l4::gen(
                        id,
                        listen_port,
                        so_mark,
                        add_egress.no_ra,
                        &add_egress.attest,
                        &add_egress.verify,
                        &mut metric_collector,
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
        admin_config,
        listeners.join("\n"),
        clusters.join("\n")
    );
    Ok(Blueprint {
        envoy_config: EnvoyConfig(config),
        metric_collector,
        envoy_admin_endpoint,
        iptables_actions,
    })
}

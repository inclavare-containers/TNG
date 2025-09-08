use anyhow::bail;
use cidr::Ipv4Cidr;
use serde::{Deserialize, Serialize};
use serde_with::{formats::PreferMany, serde_as, OneOrMany};

use super::{ra::RaArgsUnchecked, Endpoint};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AddIngressArgs {
    #[serde(flatten)]
    pub ingress_mode: IngressMode,

    #[serde(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommonArgs {
    #[serde(default = "Option::default")]
    #[serde(alias = "encap_in_http")]
    pub ohttp: Option<OHttpArgs>,

    #[serde(default = "bool::default")]
    pub web_page_inject: bool,

    #[serde(flatten)]
    pub ra_args: RaArgsUnchecked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum IngressMode {
    #[serde(rename = "mapping")]
    Mapping(IngressMappingArgs),

    #[serde(rename = "http_proxy")]
    HttpProxy(IngressHttpProxyArgs),

    #[serde(rename = "netfilter")]
    Netfilter(IngressNetfilterArgs),

    #[serde(rename = "socks5")]
    Socks5(IngressSocks5Args),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IngressMappingArgs {
    #[serde(rename = "in")]
    pub r#in: Endpoint,
    pub out: Endpoint,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IngressHttpProxyArgs {
    pub proxy_listen: Endpoint,

    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    #[serde(default = "Vec::new")]
    // In TNG version <= 1.0.1, this field is named as `dst_filter`
    #[serde(alias = "dst_filter")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dst_filters: Vec<EndpointFilter>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IngressNetfilterArgs {
    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    #[serde(default = "Vec::new")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capture_dst: Vec<IngressNetfilterCaptureDstArgs>,

    #[serde(default = "Vec::new")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capture_cgroup: Vec<String>,

    #[serde(default = "Vec::new")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nocapture_cgroup: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub so_mark: Option<u32>,
}

/// Instead of using the IngressNetfilterCaptureDst directly, here we define a common struct for json parsing to get better deserialization error message.
/// See https://github.com/serde-rs/serde/issues/2157
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IngressNetfilterCaptureDstArgs {
    host: Option<Ipv4Cidr>,
    ipset: Option<String>,
    port: Option<u16>,
}

impl TryFrom<IngressNetfilterCaptureDstArgs> for IngressNetfilterCaptureDst {
    type Error = anyhow::Error;

    fn try_from(value: IngressNetfilterCaptureDstArgs) -> Result<Self, Self::Error> {
        Ok(match (value.host, value.ipset, value.port) {
            (None, None, None) => bail!("one of host, ipset, port must be specified"),
            (None, None, Some(port)) => IngressNetfilterCaptureDst::PortOnly { port },
            (None, Some(ipset), None) => IngressNetfilterCaptureDst::IpSetOnly { ipset },
            (None, Some(ipset), Some(port)) => {
                IngressNetfilterCaptureDst::IpSetAndPort { ipset, port }
            }
            (Some(host), None, None) => IngressNetfilterCaptureDst::HostOnly { host },
            (Some(host), None, Some(port)) => {
                IngressNetfilterCaptureDst::HostAndPort { host, port }
            }
            (Some(_), Some(_), _) => bail!("Only one of host or ipset can be specified"),
        })
    }
}

pub enum IngressNetfilterCaptureDst {
    HostOnly { host: Ipv4Cidr },
    IpSetOnly { ipset: String },
    PortOnly { port: u16 },
    HostAndPort { host: Ipv4Cidr, port: u16 },
    IpSetAndPort { ipset: String, port: u16 },
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IngressSocks5Args {
    pub proxy_listen: Endpoint,

    #[serde(default = "Vec::new")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dst_filters: Vec<EndpointFilter>,

    pub auth: Option<Socks5AuthArgs>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Socks5AuthArgs {
    pub username: String,

    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OHttpArgs {
    #[serde(default)]
    pub path_rewrites: Vec<PathRewrite>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PathRewrite {
    pub match_regex: String,
    pub substitution: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EndpointFilter {
    /// Host name to match.
    ///
    /// Only some of the wildcards types are supported. See "domains" field in https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#config-route-v3-virtualhost
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_regex: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::json;

    use crate::config::TngConfig;

    use super::{IngressNetfilterCaptureDst, IngressNetfilterCaptureDstArgs};

    fn test_deserialize_netfilter_common(value: serde_json::Value) -> Result<()> {
        let config: TngConfig = serde_json::from_value(value)?;

        let config_json = serde_json::to_string_pretty(&config)?;

        let config2 = serde_json::from_str(&config_json)?;

        assert_eq!(config, config2);
        Ok(())
    }

    #[test]
    fn test_deserialize_netfilter() -> Result<()> {
        test_deserialize_netfilter_common(json!(
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_dst": [
                                {
                                    "port": 30001
                                },
                                {
                                    "host": "127.0.0.1"
                                },
                                {
                                    "host": "127.0.0.1",
                                    "port": 30002
                                },
                                {
                                    "host": "10.1.1.0/24",
                                    "port": 30002
                                },
                                {
                                    "host": "127.0.0.1/32",
                                    "port": 30002
                                },
                            ],
                            "listen_port": 50000
                        },
                        "verify": {
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": [
                                "default"
                            ]
                        }
                    }
                ]
            }
        ))?;

        assert!(test_deserialize_netfilter_common(json!(
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_dst": [
                                {
                                    "host": "10.1.1.1/24", // Invalid CIDR
                                    "port": 30002
                                },
                            ],
                            "listen_port": 50000
                        },
                        "verify": {
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": [
                                "default"
                            ]
                        }
                    }
                ]
            }
        ))
        .is_err());

        Ok(())
    }

    fn test_deserialize_netfilter_capture_dst_common(value: serde_json::Value) -> Result<()> {
        IngressNetfilterCaptureDst::try_from(serde_json::from_value::<
            IngressNetfilterCaptureDstArgs,
        >(value)?)?;
        Ok(())
    }

    #[test]
    fn test_deserialize_netfilter_capture_dst() -> Result<()> {
        test_deserialize_netfilter_capture_dst_common(serde_json::json!(
        {
            "host": "10.1.1.0/24",
            "port": 30002
        }))?;

        test_deserialize_netfilter_capture_dst_common(serde_json::json!(
        {
            "ipset": "ipset_name",
            "port": 30002
        }))?;

        test_deserialize_netfilter_capture_dst_common(serde_json::json!(
        {
            "port": 30002
        }))?;

        assert!(
            test_deserialize_netfilter_capture_dst_common(serde_json::json!(
            {
                "host": "10.1.1.0/24",
                "ipset": "ipset_name",
                "port": 30002
            }))
            .is_err()
        );

        assert!(
            test_deserialize_netfilter_capture_dst_common(serde_json::json!(
            {
                "host": "10.1.1.0/24",
                "ipset": "ipset_name",
            }))
            .is_err()
        );

        assert!(test_deserialize_netfilter_capture_dst_common(serde_json::json!({})).is_err());

        Ok(())
    }
}

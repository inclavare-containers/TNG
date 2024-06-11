use std::str::FromStr;

use anyhow::{bail, Result};

use super::Endpoint;

#[derive(Debug, PartialEq, Clone)]
pub enum AddIngressArgs {
    /// --add-ingress='mapping,in=10001,out=127.0.0.1:20001'
    Mapping { r#in: Endpoint, out: Endpoint },
    /// --add-ingress='http-proxy,dst=127.0.0.1:9991'
    HttpProxy { dst: Endpoint },
    /// --add-ingress='netfilter,dst=127.0.0.1:9991'
    Netfilter { dst: Endpoint },
}

impl FromStr for AddIngressArgs {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(',').collect();
        match parts[0] {
            "mapping" => {
                if let (Some(in_part), Some(out_part)) = (parts.get(1), parts.get(2)) {
                    if !in_part.starts_with("in=") {
                        bail!("Missing 'in=' prefix")
                    }
                    let r#in = Endpoint::from_str(&in_part[3..])?;

                    if !out_part.starts_with("out=") {
                        bail!("Missing 'out=' prefix")
                    }
                    let out = Endpoint::from_str(&out_part[4..])?;
                    Ok(AddIngressArgs::Mapping { r#in, out })
                } else {
                    bail!("Missing 'in=' or 'out=' parameter for 'mapping' ingress type")
                }
            }
            "http-proxy" | "netfilter" => {
                if let Some(dst_part) = parts.get(1) {
                    if !dst_part.starts_with("dst=") {
                        bail!("Missing 'dst=' prefix")
                    }
                    let dst = Endpoint::from_str(&dst_part[4..])?;
                    Ok(match parts[0] {
                        "http-proxy" => AddIngressArgs::HttpProxy { dst },
                        "netfilter" => AddIngressArgs::Netfilter { dst },
                        _ => unreachable!(), // We already matched the variants above
                    })
                } else {
                    bail!("Missing 'dst=' parameter")
                }
            }
            v => bail!("Unsupported ingress type '{v}'"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_ingress_args() {
        let args_str = "direct,in=7001,dst=127.0.0.1:19991";
        let expected = AddIngressArgs::Mapping {
            r#in: Endpoint {
                host: None,
                port: 7001,
            },
            out: Endpoint {
                host: Some("127.0.0.1".to_owned()),
                port: 19991,
            },
        };
        assert_eq!(args_str.parse::<AddIngressArgs>().unwrap(), expected);
    }

    #[test]
    fn test_http_proxy_ingress_args() {
        let args_str = "http-proxy,dst=127.0.0.1:9991";
        let expected = AddIngressArgs::HttpProxy {
            dst: Endpoint {
                host: Some("127.0.0.1".to_owned()),
                port: 9991,
            },
        };
        assert_eq!(args_str.parse::<AddIngressArgs>().unwrap(), expected);
    }

    #[test]
    fn test_netfilter_ingress_args() {
        let args_str = "netfilter,dst=127.0.0.1:9991";
        let expected = AddIngressArgs::Netfilter {
            dst: Endpoint {
                host: Some("127.0.0.1".to_owned()),
                port: 9991,
            },
        };
        assert_eq!(args_str.parse::<AddIngressArgs>().unwrap(), expected);
    }

    #[test]
    fn test_invalid_ingress_type() {
        let args_str = "unknown,dst=127.0.0.1:9991";
        assert!(args_str.parse::<AddIngressArgs>().is_err());
    }

    #[test]
    fn test_missing_parameters() {
        let args_str = "direct,dst=127.0.0.1:19991";
        assert!(args_str.parse::<AddIngressArgs>().is_err());

        let args_str = "direct,in=7001";
        assert!(args_str.parse::<AddIngressArgs>().is_err());

        let args_str = "http-proxy";
        assert!(args_str.parse::<AddIngressArgs>().is_err());
    }

    #[test]
    fn test_invalid_format() {
        let args_str = "direct,in=port,dst=127.0.0.1:port";
        assert!(args_str.parse::<AddIngressArgs>().is_err());

        let args_str = "http-proxy,dst=notanip:9991";
        assert!(args_str.parse::<AddIngressArgs>().is_err());
    }
}

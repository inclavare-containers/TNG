use clap::error::Result;
use std::net::IpAddr;
use std::str::FromStr;

// --add-ingress='direct,in=7001,dst=127.0.0.1:19991'
// --add-ingress='http-proxy,dst=127.0.0.1:9991'
// --add-ingress='netfilter,dst=127.0.0.1:9991'
#[derive(Debug, PartialEq, Clone)]
pub enum AddIngressArgs {
    Direct { in_port: u16, dst: (IpAddr, u16) },
    HttpProxy { dst: (IpAddr, u16) },
    Netfilter { dst: (IpAddr, u16) },
}

impl AddIngressArgs {
    fn parse_parts(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(',').collect();
        match parts[0] {
            "direct" => {
                if let (Some(in_port_part), Some(dst_part)) = (parts.get(1), parts.get(2)) {
                    let in_port = in_port_part
                        .split('=')
                        .nth(1)
                        .ok_or_else(|| "Invalid 'in' parameter format".to_string())?
                        .parse::<u16>()
                        .map_err(|_| "Invalid port number".to_string())?;
                    let dst = Self::parse_dst(dst_part)?;
                    Ok(AddIngressArgs::Direct { in_port, dst })
                } else {
                    Err("Missing 'in' or 'dst' parameter for direct".to_string())
                }
            }
            "http-proxy" | "netfilter" => {
                if let Some(dst_part) = parts.get(1) {
                    let dst = Self::parse_dst(dst_part)?;
                    Ok(match parts[0] {
                        "http-proxy" => AddIngressArgs::HttpProxy { dst },
                        "netfilter" => AddIngressArgs::Netfilter { dst },
                        _ => unreachable!(), // We already matched the variants above
                    })
                } else {
                    Err("Missing 'dst' parameter".to_string())
                }
            }
            v => Err(format!("Unsupported ingress type '{v}'")),
        }
    }

    fn parse_dst(dst_part: &str) -> Result<(IpAddr, u16), String> {
        if !dst_part.starts_with("dst=") {
            return Err("Missing 'dst=' prefix".to_string());
        }
        let remaining = &dst_part[4..];

        let parts: Vec<&str> = remaining.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid format after 'dst='. Expected IP:Port".to_string());
        }

        let ip_str = parts[0];
        let port_str = parts[1];

        let ip = ip_str
            .parse::<IpAddr>()
            .map_err(|_| format!("Invalid IP address: {}", ip_str))?;

        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid port number: {}", port_str))?;

        Ok((ip, port))
    }
}

impl FromStr for AddIngressArgs {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AddIngressArgs::parse_parts(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_direct_ingress_args() {
        let args_str = "direct,in=7001,dst=127.0.0.1:19991";
        let expected = AddIngressArgs::Direct {
            in_port: 7001,
            dst: (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19991),
        };
        assert_eq!(args_str.parse::<AddIngressArgs>().unwrap(), expected);
    }

    #[test]
    fn test_http_proxy_ingress_args() {
        let args_str = "http-proxy,dst=127.0.0.1:9991";
        let expected = AddIngressArgs::HttpProxy {
            dst: (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9991),
        };
        assert_eq!(args_str.parse::<AddIngressArgs>().unwrap(), expected);
    }

    #[test]
    fn test_netfilter_ingress_args() {
        let args_str = "netfilter,dst=127.0.0.1:9991";
        let expected = AddIngressArgs::Netfilter {
            dst: (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9991),
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

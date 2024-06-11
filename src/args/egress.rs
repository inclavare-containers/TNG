use anyhow::{bail, Result};
use std::str::FromStr;

use super::Endpoint;

#[derive(Debug, PartialEq, Clone)]
pub enum AddEgressArgs {
    /// --add-ingress='mapping,in=20001,out=127.0.0.1:30001'
    Mapping { r#in: Endpoint, out: Endpoint },
}

impl FromStr for AddEgressArgs {
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
                    Ok(AddEgressArgs::Mapping { r#in, out })
                } else {
                    bail!("Missing 'in=' or 'out=' parameter for 'mapping' egress type")
                }
            }
            v => bail!("Unsupported egress type '{v}'"),
        }
    }
}

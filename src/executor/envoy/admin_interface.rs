use std::net::Ipv4Addr;
use std::str::FromStr;

use log::error;
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct EnvoyAdminInterface {
    envoy_admin_endpoint: (String, u16),
}

impl EnvoyAdminInterface {
    pub fn new(envoy_admin_endpoint: (String, u16)) -> Self {
        Self {
            envoy_admin_endpoint,
        }
    }

    pub async fn pull_admin_interface_status(&self) -> bool {
        let res = async {
            // Check if admin interface port is open
            Ok::<_, anyhow::Error>(
                TcpStream::connect((
                    Ipv4Addr::from_str(&self.envoy_admin_endpoint.0)?,
                    self.envoy_admin_endpoint.1,
                ))
                .await
                .is_ok(),
            )
        }
        .await;

        match res {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to pull Envoy admin interface status: {e}");
                false
            }
        }
    }

    pub async fn pull_ready_status(&self) -> bool {
        let res = async {
            let url = format!(
                "http://{}:{}/ready",
                self.envoy_admin_endpoint.0, self.envoy_admin_endpoint.1
            );

            let client = reqwest::Client::new();
            let response = client.get(&url).send().await?;
            Ok::<_, anyhow::Error>(response.status() == reqwest::StatusCode::OK)
        }
        .await;

        match res {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to pull Envoy ready status: {e}");
                false
            }
        }
    }
}

use anyhow::Result;
use async_trait::async_trait;
use http_client::HttpClientMode;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{NodeType, Task};

mod http_client;
mod http_server;
mod load_balancer;
mod tcp_client;
mod tcp_server;

const TCP_PAYLOAD: &str = "Hello World TCP!";
const HTTP_RESPONSE_BODY: &str = "Hello World HTTP!";

pub enum AppType {
    #[allow(dead_code)]
    HttpServer {
        port: u16,
        expected_host_header: &'static str,
        expected_path_and_query: &'static str,
    },
    #[allow(dead_code)]
    HttpClient {
        host: &'static str,
        port: u16,
        host_header: &'static str,
        path_and_query: &'static str,
    },
    #[allow(dead_code)]
    HttpClientWithReverseProxy {
        host_header: &'static str,
        path_and_query: &'static str,
        http_proxy: HttpProxy,
    },
    #[allow(dead_code)]
    LoadBalancer {
        listen_port: u16,
        upstream_servers: Vec<(&'static str, u16)>,
        path_matcher: &'static str,
        rewrite_to: &'static str,
    },
    #[allow(dead_code)]
    TcpServer { port: u16 },
    #[allow(dead_code)]
    TcpClient {
        host: &'static str,
        port: u16,
        http_proxy: Option<HttpProxy>,
    },
}

#[async_trait]
impl Task for AppType {
    fn name(&self) -> String {
        match self {
            AppType::HttpServer { .. } | AppType::TcpServer { .. } => "app_server",
            AppType::HttpClient { .. }
            | AppType::HttpClientWithReverseProxy { .. }
            | AppType::TcpClient { .. } => "app_client",
            AppType::LoadBalancer { .. } => "load_balancer",
        }
        .to_owned()
    }

    fn node_type(&self) -> NodeType {
        match self {
            AppType::HttpServer { .. } | AppType::TcpServer { .. } => NodeType::Server,
            AppType::HttpClient { .. }
            | AppType::HttpClientWithReverseProxy { .. }
            | AppType::TcpClient { .. } => NodeType::Client,
            AppType::LoadBalancer { .. } => NodeType::Middleware,
        }
    }

    async fn launch(&self, token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
        Ok(match self {
            AppType::HttpServer {
                port,
                expected_host_header,
                expected_path_and_query,
            } => {
                http_server::launch_http_server(
                    token,
                    *port,
                    expected_host_header,
                    expected_path_and_query,
                )
                .await
            }
            AppType::HttpClient {
                host,
                port,
                host_header,
                path_and_query,
            } => {
                http_client::launch_http_client_common(
                    token,
                    host_header,
                    path_and_query,
                    HttpClientMode::NoProxy {
                        host: host.to_string(),
                        port: *port,
                    },
                )
                .await
            }
            AppType::HttpClientWithReverseProxy {
                host_header,
                path_and_query,
                http_proxy,
            } => {
                http_client::launch_http_client_common(
                    token,
                    host_header,
                    path_and_query,
                    HttpClientMode::ProxyWithReverseMode {
                        http_proxy: *http_proxy,
                    },
                )
                .await
            }
            AppType::TcpServer { port } => tcp_server::launch_tcp_server(token, *port).await,
            AppType::TcpClient {
                host,
                port,
                http_proxy,
            } => tcp_client::launch_tcp_client(token, host, *port, *http_proxy).await,
            AppType::LoadBalancer {
                listen_port,
                upstream_servers,
                path_matcher,
                rewrite_to,
            } => {
                load_balancer::launch_load_balancer(
                    token,
                    *listen_port,
                    upstream_servers.clone(),
                    path_matcher,
                    rewrite_to,
                )
                .await
            }
        }?)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HttpProxy {
    pub host: &'static str,
    pub port: u16,
}

use std::future::Future;
use std::sync::Arc;

use futures::TryFutureExt;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use smol_str::SmolStr;

use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::rustls::config::alpn::Alpn;
use crate::tunnel::utils::rustls::config::client::BlockingOnetimeTlsClientConfig;
use crate::tunnel::utils::rustls::config::server::BlockingOnetimeTlsServerConfig;
use crate::tunnel::utils::rustls::config::TlsConfigGenerator;
use crate::RaContext;

pub struct RatsQuic<R> {
    quinn: serf::quic::stream_layer::quinn::Quinn<R>,
}

type RatsQuicOptions = (Arc<RaContext>, TokioRuntime);

impl<R: serf::agnostic::Runtime> serf::quic::stream_layer::StreamLayer for RatsQuic<R> {
    type Runtime = <serf::quic::stream_layer::quinn::Quinn<R> as serf::quic::stream_layer::StreamLayer>::Runtime;
    type Acceptor = <serf::quic::stream_layer::quinn::Quinn<R> as serf::quic::stream_layer::StreamLayer>::Acceptor;
    type Connector = <serf::quic::stream_layer::quinn::Quinn<R> as serf::quic::stream_layer::StreamLayer>::Connector;
    type Connection = <serf::quic::stream_layer::quinn::Quinn<R> as serf::quic::stream_layer::StreamLayer>::Connection;
    type Stream = <serf::quic::stream_layer::quinn::Quinn<R> as serf::quic::stream_layer::StreamLayer>::Stream;
    type Options = RatsQuicOptions;

    fn max_stream_data(&self) -> usize {
        self.quinn.max_stream_data()
    }

    fn new(
        (ra_context, runtime): Self::Options,
    ) -> impl Future<Output = std::io::Result<Self>> + Send {
        async {
            let tls_gen = TlsConfigGenerator::new(ra_context, runtime)
                .await
                .map_err(std::io::Error::other)?;

            let BlockingOnetimeTlsClientConfig(client_config) = tls_gen
                .get_blocking_one_time_rustls_client_config(Alpn::Serf)
                .await?;
            let client_config =
                quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_config)?));

            let BlockingOnetimeTlsServerConfig(server_config) = tls_gen
                .get_blocking_one_time_rustls_server_config(Alpn::Serf)
                .await?;
            let server_config = quinn::ServerConfig::with_crypto(Arc::new(
                QuicServerConfig::try_from(server_config)?,
            ));

            Ok::<_, anyhow::Error>(Self {
                quinn: serf::quic::stream_layer::quinn::Quinn::new(
                    serf::quic::stream_layer::quinn::Options::new(
                        SmolStr::new("TNG"), // Should be same as the server name in the certificate
                        server_config,
                        client_config,
                        quinn::EndpointConfig::default(),
                    ),
                )
                .await?,
            })
        }
        .map_err(std::io::Error::other)
    }

    fn bind(
        &self,
        addr: std::net::SocketAddr,
    ) -> impl Future<Output = std::io::Result<(std::net::SocketAddr, Self::Acceptor, Self::Connector)>>
           + Send {
        self.quinn.bind(addr)
    }
}

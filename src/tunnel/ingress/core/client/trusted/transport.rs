use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::Result;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::Instrument;

use crate::{config::ingress::EncapInHttp, tunnel::ingress::core::TngEndpoint};

pub struct TransportLayerCreator {
    encap_in_http: Option<EncapInHttp>,
}

impl TransportLayerCreator {
    pub fn new(encap_in_http: Option<EncapInHttp>) -> Self {
        Self { encap_in_http }
    }

    pub fn create(&self, dst: &TngEndpoint) -> TransportLayerConnector {
        match &self.encap_in_http {
            Some(encap_in_http) => TransportLayerConnector::Http(HttpTransportLayer {
                _encap_in_http: encap_in_http.clone(),
            }),
            None => TransportLayerConnector::Tcp(TcpTransportLayer { dst: dst.clone() }),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TransportLayerConnector {
    Tcp(TcpTransportLayer),
    Http(HttpTransportLayer),
}

// TODO: The connector will be cloned each time when we clone the hyper http client. Maybe we can replace it with std::borrow::Cow to save memory.

#[derive(Debug, Clone)]
pub struct TcpTransportLayer {
    dst: TngEndpoint,
}

#[derive(Debug, Clone)]
pub struct HttpTransportLayer {
    _encap_in_http: EncapInHttp,
}

impl<Req> tower::Service<Req> for TcpTransportLayer {
    type Response = TokioIo<TcpStream>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, _: Req) -> Self::Future {
        let endpoint_owned = self.dst.to_owned();
        let fut = async move {
            tracing::debug!("Establish the underlying tcp connection for rats-tls");

            TcpStream::connect((endpoint_owned.host(), endpoint_owned.port()))
                .await
                .map(|s| TokioIo::new(s))
                .map_err(|e| e.into())
        }
        .instrument(tracing::info_span!("transport", r#type = "tcp"));

        Box::pin(fut)
    }
}

impl<Req> tower::Service<Req> for HttpTransportLayer {
    type Response = TokioIo<Upgraded>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, _: Req) -> Self::Future {
        tracing::debug!("Establish the underlying HTTP connection for rats-tls");
        //         .instrument(tracing::info_span!("transport", r#type = "tcp"));
        todo!()
    }
}

impl<Req> tower::Service<Req> for TransportLayerConnector {
    type Response = TokioIo<TcpStream>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            TransportLayerConnector::Tcp(tcp_transport_layer) => {
                <TcpTransportLayer as tower::Service<Req>>::poll_ready(tcp_transport_layer, context)
            }
            TransportLayerConnector::Http(http_transport_layer) => {
                <HttpTransportLayer as tower::Service<Req>>::poll_ready(
                    http_transport_layer,
                    context,
                )
            }
        }
    }

    fn call(&mut self, req: Req) -> Self::Future {
        match self {
            TransportLayerConnector::Tcp(tcp_transport_layer) => tcp_transport_layer.call(req),
            TransportLayerConnector::Http(http_transport_layer) => todo!(),
        }
    }
}

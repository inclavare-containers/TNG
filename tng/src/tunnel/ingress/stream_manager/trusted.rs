use std::future::Future;
use std::pin::Pin;

use anyhow::{bail, Result};

use crate::tunnel::ingress::protocol::ohttp::OHttpStreamForwarder;
use crate::tunnel::ingress::protocol::rats_tls::RatsTlsStreamForwarder;
use crate::tunnel::ingress::protocol::ProtocolStreamForwarder;
use crate::tunnel::ingress::stream_manager::TngEndpoint;
use crate::CommonStreamTrait;
use crate::{
    config::ingress::CommonArgs,
    tunnel::{attestation_result::AttestationResult, utils::runtime::TokioRuntime},
};

use super::StreamManager;

pub struct TrustedStreamManager {
    stream_forwarder: Box<dyn ProtocolStreamForwarder + Send + Sync + 'static>,

    #[allow(unused)]
    runtime: TokioRuntime,
}

impl TrustedStreamManager {
    pub async fn new(
        common_args: &CommonArgs,
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        if common_args.web_page_inject {
            bail!("The `web_page_inject` field is not supported")
        }

        let ra_args = common_args.ra_args.clone().into_checked()?;

        Ok(Self {
            stream_forwarder: {
                match &common_args.ohttp {
                    Some(ohttp_args) => Box::new(
                        OHttpStreamForwarder::new(
                            #[cfg(any(
                                target_os = "android",
                                target_os = "fuchsia",
                                target_os = "linux"
                            ))]
                            transport_so_mark,
                            ohttp_args,
                            ra_args,
                            runtime.clone(),
                        )
                        .await?,
                    ),

                    None => Box::new(
                        RatsTlsStreamForwarder::new(
                            #[cfg(any(
                                target_os = "android",
                                target_os = "fuchsia",
                                target_os = "linux"
                            ))]
                            transport_so_mark,
                            ra_args,
                            runtime.clone(),
                        )
                        .await?,
                    ),
                }
            },
            runtime,
        })
    }
}

impl StreamManager for TrustedStreamManager {
    async fn forward_stream<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        downstream: Box<dyn CommonStreamTrait + 'static>,
    ) -> Result<(
        Pin<Box<dyn Future<Output = Result<()>> + std::marker::Send + 'static>>,
        Option<AttestationResult>,
    )> {
        self.stream_forwarder
            .forward_stream(endpoint, downstream)
            .await
    }
}

use std::{
    collections::HashMap,
    io::{Cursor, Read as _},
    sync::Arc,
};

use anyhow::{bail, Context as _, Result};
use bytes::Buf;
use http_body_util::BodyExt as _;
use tng::{
    build,
    config::{
        ingress::{self, EncapInHttp},
        ra::{RaArgs, VerifyArgs},
    },
    tunnel::{
        endpoint::TngEndpoint,
        ingress::core::stream_manager::{trusted::TrustedStreamManager, StreamManager},
    },
    AttestationResult, CommonStreamTrait, TokioIo,
};

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub async fn fetch(
    url: String,
    method: String,
    headers: JsValue,
    body: String,
    as_addr: String,
    policy_ids: Vec<String>,
) -> Result<TngResponse, JsError> {
    fetch_impl(url, method, headers, body, as_addr, policy_ids)
        .await
        .map_err(|e: anyhow::Error| JsError::new(&format!("{e:?}")))
}

async fn fetch_impl(
    url: String,
    method: String,
    headers: JsValue,
    body: String,
    as_addr: String,
    policy_ids: Vec<String>,
) -> Result<TngResponse> {
    tracing::debug!(
        url,
        method,
        ?headers,
        body,
        as_addr,
        ?policy_ids,
        "fetch() called"
    );

    let url: hyper::Uri = url.parse().context("Failed to parse url")?;
    let authority = url.authority().context("The authority is empty")?.clone();

    let (s1, s2) = tokio::io::duplex(1024);

    let tunnel_request = {
        let authority = authority.clone();
        async move {
            send_request_async_impl(
                as_addr,
                policy_ids,
                s1,
                authority.host().to_string(),
                authority.port_u16().unwrap_or(80),
            )
            .await
        }
    };

    let send_request_task = async move {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s2)).await?;

        tokio_with_wasm::task::spawn(async move {
            if let Err(err) = conn.await {
                tracing::error!("Connection failed: {:?}", err);
            }
        });

        // Fetch the url...
        let req: http::Request<http_body_util::Full<bytes::Bytes>> = {
            let mut builder = http::Request::builder().uri(url).method(method.as_str());
            let headers: HashMap<String, String> = serde_wasm_bindgen::from_value(headers)
                .map_err(|_| anyhow::anyhow!("Failed to parse request headers"))?;
            for header in headers {
                builder = builder.header(header.0, header.1);
            }
            let builder = builder.header(hyper::header::HOST, authority.as_str());
            builder.body(http_body_util::Full::from(body))?
        };

        let res = sender
            .send_request(req)
            .await
            .context("Failed to send request")?;

        Ok(res)
    };

    let (attestation_result, response) = futures::try_join!(tunnel_request, send_request_task)?;

    // Convert res.headers() to HashMap<String, String>
    let mut headers: HashMap<String, String> = HashMap::new();
    for (key, value) in response.headers() {
        let key_str = key.to_string();
        let value_str = value
            .to_str()
            .context("Response header value is not valid UTF-8")?
            .to_string();
        headers.insert(key_str, value_str);
    }

    let status_code = response.status();

    // asynchronously aggregate the chunks of the body
    let body = response.collect().await?.aggregate();

    // try to convert as string
    let mut text = String::new();
    body.reader()
        .read_to_string(&mut text)
        .context("Failed to convert response body to string")?;

    let tng_response = TngResponse {
        status: status_code.as_u16(),
        body: text,
        headers: serde_wasm_bindgen::to_value(&headers)
            .map_err(|err| anyhow::anyhow!("Failed to convert response headers: {err:?}"))?,
        attestation_result: serde_wasm_bindgen::to_value(attestation_result.claims())
            .map_err(|err| anyhow::anyhow!("Failed to convert response headers: {err:?}"))?,
    };
    tracing::debug!("Converted response: {tng_response:?}");

    Ok(tng_response)
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct TngResponse {
    status: u16,
    headers: JsValue,
    body: String,
    attestation_result: JsValue,
}

#[wasm_bindgen]
impl TngResponse {
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> u16 {
        self.status
    }

    #[wasm_bindgen(getter)]
    pub fn headers(&self) -> JsValue {
        self.headers.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn text(&self) -> String {
        self.body.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    #[wasm_bindgen(getter)]
    pub fn attestation_result(&self) -> JsValue {
        self.attestation_result.clone()
    }
}

#[wasm_bindgen(start)]
pub fn init_tng() {
    // print pretty errors in wasm https://github.com/rustwasm/console_error_panic_hook
    // This is not needed for tracing_wasm to work, but it is a common tool for getting proper error line numbers for panics.
    console_error_panic_hook::set_once();
    tracing_wasm::set_as_global_default();

    tracing::info!(
        r#"
      _______   ________
     /_  __/ | / / ____/
      / / /  |/ / / __  
     / / / /|  / /_/ /  Welcome to the Trusted Network Gateway!
    /_/ /_/ |_/\____/   version: v{}  commit: {}  buildtime: {}"#,
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );
}

#[wasm_bindgen]
pub async fn send_demo_request() -> Result<JsValue, JsError> {
    send_request_async_impl(
        "http://127.0.0.1:8080/".to_string(),
        vec!["default".to_string()],
        Cursor::new(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:30001\r\n\r\n".to_vec()),
        "127.0.0.1".to_string(),
        30001,
    )
    .await
    .and_then(|attestation_result| {
        serde_wasm_bindgen::to_value(attestation_result.claims())
            .map_err(|err| anyhow::anyhow!("Failed to convert response headers: {err:?}"))
    })
    .map_err(|e: anyhow::Error| JsError::new(&format!("{e:?}")))
}

async fn send_request_async_impl(
    as_addr: String,
    policy_ids: Vec<String>,
    downstream: impl CommonStreamTrait,
    host: String,
    port: u16,
) -> Result<AttestationResult> {
    tracing::debug!("TNG called");
    let common_args = ingress::CommonArgs {
        web_page_inject: false,
        encap_in_http: Some(EncapInHttp {
            path_rewrites: vec![],
        }),
        ra_args: RaArgs {
            no_ra: false,
            attest: None,
            verify: Some(VerifyArgs {
                as_addr,
                as_is_grpc: false,
                policy_ids,
                trusted_certs_paths: None,
            }),
        },
    };

    let transport_so_mark = None;
    let trusted_stream_manager =
        Arc::new(TrustedStreamManager::new(&common_args, transport_so_mark).await?);

    let shutdown = tokio_graceful::Shutdown::no_signal();

    let (forward_task, attestation_result) = trusted_stream_manager
        .forward_stream(
            // TODO: note that in wasm mode, this field should be same as the http request in the body
            &TngEndpoint::new(host, port),
            downstream,
            shutdown.guard(),
        )
        .await
        .context("failed to forward stream")?;

    tracing::info!(?attestation_result, "start forward task");

    let Some(attestation_result) = attestation_result else {
        bail!("The attestation result is missing")
    };

    tokio_with_wasm::task::spawn(async move {
        if let Err(err) = forward_task.await {
            tracing::error!("Forward task failed: {:?}", err);
        }
    });

    Ok(attestation_result)
}

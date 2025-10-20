use anyhow::{anyhow, Context as _};
use futures::SinkExt;
use futures::StreamExt;
use futures::TryStreamExt;
use gloo::utils::format::JsValueSerdeExt;
use http_body_util::BodyDataStream;
use tng::{
    config::{
        ingress::{self, OHttpArgs},
        ra::{RaArgs, VerifyArgs},
    },
    tunnel::endpoint::TngEndpoint,
    AttestationResult,
};

use wasm_bindgen::prelude::*;

use crate::send_request_async_impl;

#[wasm_bindgen]
pub async fn fetch(
    url: String,
    init: web_sys::RequestInit,
    config: JsValue,
) -> Result<web_sys::Response, JsValue> {
    let common_args: ingress::CommonArgs = serde_wasm_bindgen::from_value(config)
        .map_err(|e| JsError::new(&format!("Failed to parse config: {e:?}")))?;

    if common_args.web_page_inject {
        Err(anyhow!("The `web_page_inject` field is not supported"))
            .map_err(|e| JsError::new(&format!("{e:?}")))?
    }

    let ohttp = common_args.ohttp.unwrap_or_default();
    let ra_args = common_args
        .ra_args
        .clone()
        .into_checked()
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    let (http_response, attestation_result) = fetch_core_impl(url, init, &ohttp, &ra_args).await?;

    let web_response = convert_to_web_response(http_response).await?;
    Ok(bind_attestation_result(
        web_response,
        attestation_result,
        &ra_args,
    )?)
}

async fn fetch_core_impl(
    url: String,
    init: web_sys::RequestInit,
    ohttp: &OHttpArgs,
    ra_args: &RaArgs,
) -> Result<(axum::response::Response, AttestationResult), JsValue> {
    // Create web_sys::Request
    let web_request: web_sys::Request = web_sys::Request::new_with_str_and_init(&url, &init)?;

    let http_request = convert_to_rust_request(web_request)?;

    let authority = http_request
        .uri()
        .authority()
        .context("The authority is empty")
        .map_err(|e| JsError::new(&format!("{e:?}")))?
        .clone();

    // TODO: note that in wasm mode, this field should be same as the http request in the body
    let endpoint = TngEndpoint::new(
        authority.host().to_string(),
        authority.port_u16().unwrap_or(80),
    );

    send_request_async_impl(&endpoint, ohttp, ra_args, http_request)
        .await
        .map_err(|e| JsError::new(&format!("{e:?}")).into())
}

fn convert_to_rust_request(
    web_request: web_sys::Request,
) -> Result<axum::extract::Request, JsValue> {
    let gloo_request = gloo::net::http::Request::from(web_request);

    // Get ReadableStream from web_sys::Request
    let body_stream = if let Some(body_stream) = gloo_request.body() {
        body_stream
    } else {
        web_sys::ReadableStream::new()?
    };

    // convert ReadableStream to hyper compatible stream
    let stream_body = wasm_streams::ReadableStream::from_raw(body_stream)
        .into_stream()
        .map_ok(|chunk| {
            let uint8_array = chunk
                .dyn_into::<js_sys::Uint8Array>()
                .expect("Expected Uint8Array");
            http_body::Frame::data(bytes::Bytes::from_owner(uint8_array.to_vec()))
        })
        .or_else(|e| async {
            Err::<_, anyhow::Error>(
                gloo::utils::errors::JsError::try_from(e)
                    .map(|e| anyhow!(e))
                    .unwrap_or(anyhow!("Not a JsError")),
            )
        });

    // Create a new stream wrapper here since wasm_streams::ReadableStream is not Send.
    let stream_body = {
        let (mut sender, receiver) = futures::channel::mpsc::unbounded();
        tokio_with_wasm::task::spawn(async move {
            let mut stream_body = std::pin::pin!(stream_body.map(|item| Ok(item)));
            sender.send_all(&mut stream_body).await
        });
        receiver
    };

    let mut builder = http::Request::builder()
        .uri(gloo_request.url())
        .method(gloo_request.method().as_ref())
        .version(http::Version::HTTP_11);
    for (key, value) in gloo_request.headers().entries() {
        builder = builder.header(key, value);
    }

    let http_request = builder
        .body(http_body_util::StreamBody::new(stream_body))
        .context("Failed to build http::Request")
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    let http_request = http_request.map(axum::body::Body::new);

    Ok(http_request)
}

async fn convert_to_web_response(
    http_response: axum::response::Response,
) -> Result<web_sys::Response, JsValue> {
    // Convert res.headers() to web_sys::Headers
    let headers = web_sys::Headers::new()?;
    for (key, value) in http_response.headers() {
        let key_str = key.to_string();
        let value_str = value
            .to_str()
            .context("Response header value is not valid UTF-8")
            .map_err(|e| JsError::new(&format!("{e:?}")))?
            .to_string();
        headers.append(&key_str, &value_str)?;
    }

    // Prepare the ResponseInit
    let init = web_sys::ResponseInit::new();
    init.set_headers(&headers);
    init.set_status(http_response.status().as_u16());

    // Convert body to ReadableStream
    let body_stream = http_response.into_body();
    let readable_stream = wasm_streams::ReadableStream::from_stream(
        BodyDataStream::new(body_stream)
            .map_ok(|v| {
                let array = js_sys::Uint8Array::new_with_length(v.len() as u32);
                array.copy_from(&v);
                array.into()
            })
            .map_err(|e| JsError::new(&format!("{e:?}")).into()),
    );

    // Create and return the web_sys::Response
    web_sys::Response::new_with_opt_readable_stream_and_init(
        Some(&readable_stream.into_raw()),
        &init,
    )
}

fn bind_attestation_result(
    web_response: web_sys::Response,
    attestation_result: AttestationResult,
    ra_args: &RaArgs,
) -> Result<web_sys::Response, JsValue> {
    // Create a JavaScript object from the claims map
    let claims_obj = JsValue::from_serde(attestation_result.claims())
        .context("Failed to serialize attestation_result")
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    // Create the attest_info object with claims as an object
    let attest_info_obj = js_sys::Object::new();
    match ra_args {
        RaArgs::VerifyOnly(verify_args) => {
            let token_verify = match verify_args {
                VerifyArgs::Passport { token_verify } => token_verify,
                VerifyArgs::BackgroundCheck {
                    as_args:
                        tng::config::ra::AttestationServiceArgs {
                            as_addr,
                            token_verify,
                            ..
                        },
                } => {
                    js_sys::Reflect::set(
                        &attest_info_obj,
                        &JsValue::from_str("as_addr"),
                        &JsValue::from_str(&as_addr),
                    )?;
                    token_verify
                }
            };
            js_sys::Reflect::set(
                &attest_info_obj,
                &JsValue::from_str("policy_ids"),
                &JsValue::from_serde(&token_verify.policy_ids)
                    .context("Failed to serialize policy_ids")
                    .map_err(|e| JsError::new(&format!("{e:?}")))?,
            )?;
        }
        RaArgs::NoRa => { /* nothing */ }
    }

    js_sys::Reflect::set(
        &attest_info_obj,
        &JsValue::from_str("attestation_result"),
        &claims_obj,
    )?;

    // Set attest_info as a property on the web_response
    js_sys::Reflect::set(
        &web_response,
        &JsValue::from_str("attest_info"),
        &attest_info_obj,
    )?;

    Ok(web_response)
}

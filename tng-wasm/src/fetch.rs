use anyhow::{anyhow, Context as _};
use futures::TryStreamExt;
use gloo::utils::format::JsValueSerdeExt;
use http_body_util::BodyDataStream;
use hyper::body::Incoming;
use tng::{AttestationResult, TokioIo};

use wasm_bindgen::prelude::*;

use crate::send_request_async_impl;

#[wasm_bindgen]
pub async fn fetch(
    url: String,
    init: web_sys::RequestInit,
    as_addr: String,
    policy_ids: Vec<String>,
) -> Result<web_sys::Response, JsValue> {
    let (attestation_result, http_response) =
        fetch_core_impl(url, init, as_addr.clone(), policy_ids.clone()).await?;

    let web_response = convert_to_web_response(http_response).await?;
    Ok(bind_attestation_result(
        web_response,
        attestation_result,
        as_addr,
        policy_ids,
    )?)
}

async fn fetch_core_impl(
    url: String,
    init: web_sys::RequestInit,
    as_addr: String,
    policy_ids: Vec<String>,
) -> Result<(AttestationResult, http::Response<Incoming>), JsValue> {
    let http_request = {
        // Create web_sys::Request
        let web_request = web_sys::Request::new_with_str_and_init(&url, &init)?;
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

        let mut builder = http::Request::builder()
            .uri(gloo_request.url())
            .method(gloo_request.method().as_ref())
            .version(http::Version::HTTP_11);
        for (key, value) in gloo_request.headers().entries() {
            builder = builder.header(key, value);
        }
        builder
            .body(http_body_util::StreamBody::new(stream_body))
            .context("Failed to build http::Request")
            .map_err(|e| JsError::new(&format!("{e:?}")))?
    };

    let http_request = {
        let (parts, body) = http_request.into_parts();
        tracing::debug!(
            http_request=?parts,
            as_addr,
            ?policy_ids,
            "http::Request to be send"
        );
        http::Request::from_parts(parts, body)
    };

    let authority = http_request
        .uri()
        .authority()
        .context("The authority is empty")
        .map_err(|e| JsError::new(&format!("{e:?}")))?
        .clone();

    let (s1, s2) = tokio::io::duplex(1024);

    let tunnel_request = {
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

        let res = sender
            .send_request(http_request)
            .await
            .context("Failed to send request")?;

        Ok(res)
    };

    futures::try_join!(tunnel_request, send_request_task)
        .map_err(|e| JsError::new(&format!("{e:?}")).into())
}

async fn convert_to_web_response(
    http_response: http::Response<Incoming>,
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
    as_addr: String,
    policy_ids: Vec<String>,
) -> Result<web_sys::Response, JsValue> {
    // Create a JavaScript object from the claims map
    let claims_obj = js_sys::Object::new();
    for (key, value) in attestation_result.claims() {
        // Try to convert value to UTF-8 string first, otherwise use hex encoding
        let value_str = match std::str::from_utf8(value.as_ref()) {
            Ok(s) if !s.contains('\0') => JsValue::from_str(s),
            _ => JsValue::from_str(&hex::encode(value)),
        };
        js_sys::Reflect::set(&claims_obj, &JsValue::from_str(key), &value_str)?;
    }

    // Create the attest_info object with claims as an object
    let attest_info_obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &attest_info_obj,
        &JsValue::from_str("as_addr"),
        &JsValue::from_str(&as_addr),
    )?;
    js_sys::Reflect::set(
        &attest_info_obj,
        &JsValue::from_str("policy_ids"),
        &JsValue::from_serde(&policy_ids)
            .context("Failed to serialize policy_ids")
            .map_err(|e| JsError::new(&format!("{e:?}")))?,
    )?;
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

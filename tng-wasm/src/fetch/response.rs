use anyhow::{Context as _, Result};
use futures::TryStreamExt;
use http_body_util::BodyDataStream;
use wasm_bindgen::prelude::*;

use super::to_js_error;

pub(super) async fn convert_to_web_response(
    http_response: axum::response::Response,
) -> Result<web_sys::Response, JsValue> {
    // Convert res.headers() to web_sys::Headers
    let headers = web_sys::Headers::new()?;
    for (key, value) in http_response.headers() {
        let key_str = key.to_string();
        let value_str = value
            .to_str()
            .context("Response header value is not valid UTF-8")
            .map_err(to_js_error)?
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

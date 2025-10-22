//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsError;
use wasm_bindgen_test::*;

use anyhow::{anyhow, Context as _};
use futures::AsyncReadExt;
use futures::SinkExt;
use futures::StreamExt;
use futures::TryStreamExt;
use gloo::utils::format::JsValueSerdeExt;
use http_body_util::BodyDataStream;
use http_body_util::Full;
use tng::{
    config::{
        ingress::{self, OHttpArgs},
        ra::{RaArgs, VerifyArgs},
    },
    tunnel::endpoint::TngEndpoint,
    AttestationResult,
};

use js_sys::Array;
use js_sys::Function;
use js_sys::Object;
use js_sys::Reflect;
use js_sys::Uint8Array;

// Configure tests to run in the browser environment.
wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_fetch_with_config() -> Result<(), JsError> {
    tng_wasm::init_tng();

    let url = "http://127.0.0.1:1031/v1/models".to_string(); // Endpoint for testing POST requests

    // === Construct RequestInit ===
    let mut init = web_sys::RequestInit::new();
    init.method("POST");
    init.body(Some(&"test data".into()));

    // === Construct config: JsValue ===
    let config_obj = js_sys::Object::new();

    // ohttp: {}
    let ohttp_obj = js_sys::Object::new();
    Reflect::set(&config_obj, &"ohttp".into(), &ohttp_obj.into())
        .map_err(|_| JsError::new("Failed to set ohttp"))?;

    // verify: { ... }
    let verify_obj = js_sys::Object::new();
    Reflect::set(&verify_obj, &"model".into(), &"background_check".into())
        .map_err(|_| JsError::new("Failed to set model"))?;

    Reflect::set(
        &verify_obj,
        &"as_addr".into(),
        &"http://123.56.106.222:8091/api/as".into(),
    )
    .map_err(|_| JsError::new("Failed to set as_addr"))?;

    // policy_ids: ['default']
    let policy_ids_arr = Array::of1(&"default".into());
    Reflect::set(&verify_obj, &"policy_ids".into(), &policy_ids_arr)
        .map_err(|_| JsError::new("Failed to set policy_ids"))?;

    Reflect::set(&config_obj, &"verify".into(), &verify_obj.into())
        .map_err(|_| JsError::new("Failed to set verify"))?;

    let config_js: JsValue = config_obj.into();

    // === Invoke the tested function ===
    let result = tng_wasm::fetch::fetch(url, init, config_js).await;

    // === Assert result (example: check if Response is returned) ===
    match result {
        Ok(resp) => {
            tracing::info!("Fetch succeeded with status: {}", resp.status());
        }
        Err(e) => {
            return Err(JsError::new(&format!("Fetch failed: {:?}", e)));
        }
    }

    Ok(())
}

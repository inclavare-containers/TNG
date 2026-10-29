//! Test suite for the Web and headless browsers.

#![cfg(wasm)]
#![feature(impl_trait_in_fn_trait_return)]

extern crate wasm_bindgen_test;

use gloo::utils::format::JsValueSerdeExt;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

// Configure tests to run in the browser environment.
wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_init() -> Result<(), JsError> {
    tng_wasm::init_tng();

    Ok(())
}

// The standalone verify() export must fail cleanly on an unsupported config,
// before any network activity. This exercises the config-parse path through
// the real wasm export.
#[wasm_bindgen_test]
async fn verify_rejects_web_page_inject() {
    let config = JsValue::from_serde(&serde_json::json!({"web_page_inject": true}))
        .expect("serialize test config");
    let result = tng_wasm::fetch::verify::verify("https://example.com/".to_string(), config).await;
    let err = result.expect_err("web_page_inject must be rejected");
    let msg = js_sys::Error::from(err)
        .message()
        .as_string()
        .unwrap_or_default();
    assert!(
        msg.contains("web_page_inject"),
        "unexpected error message: {msg}"
    );
}

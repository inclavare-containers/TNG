//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen::JsError;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test() -> Result<(), JsError> {
    tng_wasm::init_tng();

    tng_wasm::send_demo_request().await.map(|_| ())
}

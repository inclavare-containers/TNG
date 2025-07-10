//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use tokio_with_wasm::alias as tokio;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test() {
    tng_wasm::init();
    tng_wasm::send_request_async().await;
    // tokio::spawn(async move { tracing::info!("just a test") }).await;
}

//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test() {
    tng_wasm::init();

    tokio_with_wasm::task::spawn(async move { tracing::info!("just a test from spawn") }).await;
    tokio_with_wasm::task::spawn_blocking(|| tracing::info!("just a test from spawn_blocking"))
        .await;

    tng_wasm::send_request_async().await;
}

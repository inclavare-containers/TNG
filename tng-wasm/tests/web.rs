//! Test suite for the Web and headless browsers.

#![cfg(wasm)]

extern crate wasm_bindgen_test;

use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

// Configure tests to run in the browser environment.
wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_init() -> Result<(), JsError> {
    tng_wasm::init_tng();

    Ok(())
}

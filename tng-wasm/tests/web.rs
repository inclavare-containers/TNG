//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]
#![feature(impl_trait_in_fn_trait_return)]

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

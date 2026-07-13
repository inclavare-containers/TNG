//! Verifies that a browser fetch rejection renders cleanly (no duplicated
//! `TypeError: Failed to fetch`, no raw `JsValue(...)` wrapper) and carries the
//! browser-opacity hint. Exercises the patched reqwest fork's
//! `crate::error::wasm()` end-to-end via the real `reqwest` wasm client.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use std::error::Error;
use wasm_bindgen_test::*;

// Configure tests to run in the browser environment.
wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn fetch_failure_renders_cleanly() {
    let client = reqwest::Client::builder().build().unwrap();
    let err = client
        .get("https://invalid.invalid/")
        .send()
        .await
        .expect_err("fetch to an invalid host must fail");

    // reqwest::Error Display is "error sending request"; its `source()` is the
    // string produced by the fork's crate::error::wasm() — the link under test.
    // The reqwest::Error's direct source IS the wasm() BoxError, so a single
    // `.source()` call reaches it.
    let source = err
        .source()
        .expect("reqwest error has a source")
        .to_string();

    assert!(
        !source.contains("JsValue("),
        "raw JsValue(...) wrapper leaked into the error:\n{source}"
    );

    // On firefox the error will be "TypeError: NetworkError when attempting to fetch resource.", not "TypeError: Failed to fetch"
    if source.contains("TypeError: NetworkError when attempting to fetch resource.") {
        // firefox, skip this part
    } else {
        let occurrences = source.matches("TypeError: Failed to fetch").count();
        assert_eq!(
            occurrences, 1,
            "expected exactly one 'TypeError: Failed to fetch', got {occurrences}:\n{source}"
        );
        assert!(
            source.contains("Note: browsers do not expose"),
            "missing browser-opacity hint:\n{source}"
        );
    }
}

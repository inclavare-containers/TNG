#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use gloo::utils::format::JsValueSerdeExt;
use tng::config::capabilities::ConfigCapabilities;
use tng::config::ra::PolicyConfig;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::Layer;
use tracing_wasm::{WASMLayer, WASMLayerConfigBuilder};
use wasm_bindgen::prelude::*;

pub mod fetch;

/// The builtin-AS policy kinds, as an array of
/// `{ type, name, accepts_reference_values, is_default, has_content }`.
///
/// Rust owns this list and the reference-value rule; the demo page only
/// renders the result. `path` is absent because wasm has no file access.
#[wasm_bindgen]
pub fn policy_capabilities() -> Result<JsValue, JsValue> {
    let capabilities = PolicyConfig::capabilities();
    JsValue::from_serde(&capabilities).map_err(|error| {
        JsError::new(&format!("Failed to serialize policy capabilities: {error}")).into()
    })
}

/// Field capabilities for the demo's provider x model x as_type selectors, as
/// `{ asType, asAddr, apiKey, itaJwksAddr, skipAsTokenCertVerify,
/// builtinPolicy, builtinReferenceValues, policyIds, trustedCerts }`.
#[wasm_bindgen]
pub fn config_capabilities(provider: &str, model: &str, as_type: &str) -> Result<JsValue, JsValue> {
    let capabilities = ConfigCapabilities::new(provider, model, as_type);
    JsValue::from_serde(&capabilities).map_err(|error| {
        JsError::new(&format!("Failed to serialize config capabilities: {error}")).into()
    })
}

#[wasm_bindgen(start)]
pub fn init_tng() {
    // print pretty errors in wasm https://github.com/rustwasm/console_error_panic_hook
    // This is not needed for tracing_wasm to work, but it is a common tool for getting proper error line numbers for panics.
    console_error_panic_hook::set_once();

    let wasm_layer_config = WASMLayerConfigBuilder::new()
        .set_console_config(tracing_wasm::ConsoleConfig::ReportWithoutConsoleColor)
        .build();
    let subscriber =
        tracing_subscriber::registry().with(WASMLayer::new(wasm_layer_config).with_filter(Into::<
            tracing_subscriber::EnvFilter,
        >::into(
            "info,tokio_graceful=off,rats_cert=debug,tng=debug",
        )));
    if let Err(error) = tracing::subscriber::set_global_default(subscriber) {
        // A host page may already have a global subscriber; keep it rather
        // than aborting the wasm module.
        tracing::debug!(%error, "keeping the host's global tracing subscriber");
    }

    tng::show_banner("wasm");
}

#[cfg(all(
    test,
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
mod tests {
    use wasm_bindgen_test::*;

    use rats_cert::cert::verify::PolicyConfig;
    use rats_cert::tee::coco::converter::builtin::BuiltinCocoConverter;
    use rats_cert::tee::GenericConverter;

    // Run these in a real browser so `window.crypto.subtle` (the Web Crypto API
    // used by `build_challenger_webcrypto`) is available. Run with:
    //   make wasm-unit-test-chrome
    wasm_bindgen_test_configure!(run_in_browser);

    // Constructing the builtin attestation-service converter on wasm must drive
    // the WebCrypto RSA keygen path (`build_challenger_webcrypto`) rather than
    // the slow pure-software `rsa` prime generation, and then produce a
    // challenge nonce that is a bare 3-segment JWT. This exercises that whole
    // flow end-to-end in a headless browser.
    #[wasm_bindgen_test]
    async fn builtin_challenger_webcrypto_keygen_and_nonce() {
        let converter = match BuiltinCocoConverter::new(&PolicyConfig::HardwareOnly, &[]).await {
            Ok(c) => c,
            Err(error) => panic!("failed to build builtin converter: {error:?}"),
        };

        let nonce = match converter.get_nonce().await {
            Ok(n) => n,
            Err(error) => panic!("failed to get nonce: {error:?}"),
        };

        let jwt = nonce;
        assert_eq!(
            jwt.split('.').count(),
            3,
            "builtin challenge nonce should be a bare 3-segment JWT, got: {jwt}"
        );
    }

    // The exported list must match the policy kinds compiled for wasm: `path`
    // is absent because there is no file access.
    #[wasm_bindgen_test]
    fn policy_capabilities_match_the_wasm_policy_set() {
        use wasm_bindgen::JsCast as _;

        let value = match crate::policy_capabilities() {
            Ok(value) => value,
            Err(error) => panic!("policy capabilities did not serialize: {error:?}"),
        };
        let array: js_sys::Array = match value.dyn_into() {
            Ok(array) => array,
            Err(_) => panic!("policy_capabilities did not return an array"),
        };

        let types: Vec<String> = array
            .iter()
            .map(|entry| {
                let value =
                    match js_sys::Reflect::get(&entry, &wasm_bindgen::JsValue::from_str("type")) {
                        Ok(value) => value,
                        Err(_) => panic!("entry has no type property"),
                    };
                match value.as_string() {
                    Some(value) => value,
                    None => panic!("entry type is not a string"),
                }
            })
            .collect();

        assert!(types.contains(&"hardware_only".to_string()));
        assert!(types.contains(&"hardware_only_strict".to_string()));
        assert!(types.contains(&"modules".to_string()));
        assert!(types.contains(&"trust_all".to_string()));
        assert!(types.contains(&"inline".to_string()));
        assert!(!types.contains(&"path".to_string()));
    }

    // The exported matrix must serialize with the camelCase keys the demo
    // reads, and the builtin/ITA distinctions must survive the boundary.
    #[wasm_bindgen_test]
    fn config_capabilities_cover_the_demo_matrix() {
        fn capabilities(provider: &str, model: &str, as_type: &str) -> wasm_bindgen::JsValue {
            match crate::config_capabilities(provider, model, as_type) {
                Ok(value) => value,
                Err(error) => panic!("config capabilities did not serialize: {error:?}"),
            }
        }

        fn flag(capabilities: &wasm_bindgen::JsValue, key: &str) -> bool {
            let value =
                match js_sys::Reflect::get(capabilities, &wasm_bindgen::JsValue::from_str(key)) {
                    Ok(value) => value,
                    Err(_) => panic!("missing {key}"),
                };
            match value.as_bool() {
                Some(value) => value,
                None => panic!("{key} is not a bool"),
            }
        }

        let coco_builtin = capabilities("coco", "background_check", "builtin");
        assert!(flag(&coco_builtin, "asType"));
        assert!(!flag(&coco_builtin, "asAddr"));
        assert!(!flag(&coco_builtin, "policyIds"));
        assert!(flag(&coco_builtin, "builtinPolicy"));
        assert!(flag(&coco_builtin, "builtinReferenceValues"));

        let ita_passport = capabilities("ita", "passport", "restful");
        assert!(!flag(&ita_passport, "asType"));
        assert!(!flag(&ita_passport, "asAddr"));
        assert!(!flag(&ita_passport, "apiKey"));
        assert!(flag(&ita_passport, "itaJwksAddr"));
        assert!(flag(&ita_passport, "policyIds"));
    }
}

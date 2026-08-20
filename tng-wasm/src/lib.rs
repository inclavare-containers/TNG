#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::Layer;
use tracing_wasm::{WASMLayer, WASMLayerConfigBuilder};
use wasm_bindgen::prelude::*;

pub mod fetch;

#[wasm_bindgen(start)]
pub fn init_tng() {
    // print pretty errors in wasm https://github.com/rustwasm/console_error_panic_hook
    // This is not needed for tracing_wasm to work, but it is a common tool for getting proper error line numbers for panics.
    console_error_panic_hook::set_once();

    let wasm_layer_config = WASMLayerConfigBuilder::new()
        .set_console_config(tracing_wasm::ConsoleConfig::ReportWithoutConsoleColor)
        .build();
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(
        WASMLayer::new(wasm_layer_config).with_filter(Into::<tracing_subscriber::EnvFilter>::into(
            "info,tokio_graceful=off,rats_cert=debug,tng=debug",
        )),
    ))
    .expect("failed to set tng default global tracing subscriber");

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
    use rats_cert::tee::coco::converter::CoCoNonce;
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
        let converter = match BuiltinCocoConverter::new(
            &PolicyConfig::HardwareWithReferenceValues,
            &[],
        )
        .await
        {
            Ok(c) => c,
            Err(error) => panic!("failed to build builtin converter: {error:?}"),
        };

        let nonce = match converter.get_nonce().await {
            Ok(n) => n,
            Err(error) => panic!("failed to get nonce: {error:?}"),
        };

        let CoCoNonce::Jwt(jwt) = nonce;
        assert_eq!(
            jwt.split('.').count(),
            3,
            "builtin challenge nonce should be a bare 3-segment JWT, got: {jwt}"
        );
    }
}

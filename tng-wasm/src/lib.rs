#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use tng::build;

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

    tracing::info!(
        r#"
      _______   ________
     /_  __/ | / / ____/
      / / /  |/ / / __  
     / / / /|  / /_/ /  Welcome to the Trusted Network Gateway!
    /_/ /_/ |_/\____/   version: v{}  commit: {}  buildtime: {}"#,
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );
}

use cfg_aliases::cfg_aliases;
use shadow_rs::ShadowBuilder;
fn main() {
    cfg_aliases! {
        // Platforms
        wasm: { all(target_arch = "wasm32", target_vendor = "unknown", target_os = "unknown") },
        unix: { any(target_os = "linux", target_os = "macos" ) },
    }

    ShadowBuilder::builder().build().unwrap();
}

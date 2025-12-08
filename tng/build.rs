use cfg_aliases::cfg_aliases;
use shadow_rs::ShadowBuilder;
fn main() {
    cfg_aliases! {
        // Platforms
        wasm: { all(target_arch = "wasm32", target_vendor = "unknown", target_os = "unknown") },
        // "unix" is already defined by rustc so we skip it here: https://doc.rust-lang.org/reference/conditional-compilation.html#unix-and-windows
    }

    // For shadow-rs
    ShadowBuilder::builder().build().unwrap();

    // For protoc
    prost_build::compile_protos(
        &["src/tunnel/ohttp/protocol/metadata.proto"],
        &["src/tunnel/ohttp/protocol/"],
    )
    .unwrap();

    prost_build::compile_protos(
        &["src/tunnel/egress/protocol/ohttp/security/key_manager/peer_shared/key_update.proto"],
        &["src/tunnel/egress/protocol/ohttp/security/key_manager/peer_shared/"],
    )
    .unwrap();
}

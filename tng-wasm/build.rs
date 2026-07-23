use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        // Platforms
        wasm: { all(target_arch = "wasm32", target_vendor = "unknown", target_os = "unknown") },
        // "unix" is already defined by rustc so we skip it here: https://doc.rust-lang.org/reference/conditional-compilation.html#unix-and-windows
    }
}

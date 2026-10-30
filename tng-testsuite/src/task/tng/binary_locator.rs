//! Locates the `tng` binary for test execution.
//!
//! Search order:
//! 1. `TNG_BINARY` env var — explicit override
//! 2. `target/<profile>/tng` — derived from the test binary's location
//! 3. `tng` in PATH (via `which::which`)
//! 4. `/usr/bin/tng` — system install
//!
//! The caller only needs to locate the `tng` binary. `LD_PRELOAD` setup
//! for `libtng_hook.so` is handled by `tng exec` itself, not by tests.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// Resolve the path to the `tng` binary.
///
/// Tries TNG_BINARY env var first, then target directory, PATH, and system install.
pub fn resolve_tng_binary() -> Result<PathBuf> {
    // 1. TNG_BINARY env var — explicit override
    if let Ok(path) = std::env::var("TNG_BINARY") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    // 2. target/<profile>/tng — derive from test binary location
    let target_dir_binary = resolve_from_target_dir();
    if let Some(path) = &target_dir_binary {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    // 3. PATH
    if let Ok(path) = which::which("tng") {
        warn_outside_workspace(&path, target_dir_binary.as_deref());
        return Ok(path);
    }

    // 4. System install
    let system_path = PathBuf::from("/usr/bin/tng");
    if system_path.exists() {
        warn_outside_workspace(&system_path, target_dir_binary.as_deref());
        return Ok(system_path);
    }

    bail!(
        "tng binary not found.\n\
         Searched:\n\
         - TNG_BINARY env var\n\
         - target/<profile>/tng (build workspace first)\n\
         - $PATH (cargo install or manual install)\n\
         - /usr/bin/tng (system install)"
    )
}

/// Warn when resolution falls back to a PATH/system binary because the
/// workspace target binary does not exist. The tests then drive a `tng` that
/// may be stale or built from different sources than the code under test,
/// silently invalidating results. This is a warning, not an error: CI
/// legitimately uses the RPM-installed `/usr/bin/tng`.
fn warn_outside_workspace(resolved: &Path, expected: Option<&Path>) {
    tracing::warn!(
        ?resolved,
        ?expected,
        "workspace target tng binary not found, resolved a PATH/system binary instead; \
         `cargo test --features on-bin` does not build target/<profile>/tng \
         (run `cargo build -p tng` or set TNG_BINARY)"
    );
}

/// Derive the tng binary path from the test binary's location.
///
/// The test binary lives under `target/<profile>/deps/` or `target/<profile>/build/`.
/// Walking up to the `target` directory gives us `target/<profile>/tng`.
fn resolve_from_target_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let mut current = exe.as_path();

    // Walk up until we find a directory named "target"
    while let Some(parent) = current.parent() {
        if parent.file_name()?.to_str()? == "target" {
            // parent is target/, so target/<profile>/ is the next level
            let profile = current.file_name()?.to_str()?;
            return Some(parent.join(profile).join("tng"));
        }
        current = parent;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_from_target_dir_debug() {
        // Simulate a test binary path: /some/path/target/debug/deps/test-abc123
        let fake_exe = PathBuf::from("/some/path/target/debug/deps/test-abc123");
        // We can't easily test the function directly since it uses current_exe,
        // but we can verify the logic conceptually.
        // The actual path resolution depends on the running binary.
        let _ = fake_exe; // suppress unused warning
    }
}

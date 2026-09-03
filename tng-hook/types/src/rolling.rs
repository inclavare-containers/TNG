//! Rolling-log config shared by the tng binary and the tng-hook cdylib.

use std::path::{Path, PathBuf};

/// Size+count rolling config. `tracing-rolling-file` v0.1.3 has no MaxAge/
/// Compress support, so those are intentionally absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RollingConfig {
    pub enabled: bool,
    pub max_size: u64,
    pub max_backups: usize,
}

impl Default for RollingConfig {
    fn default() -> Self {
        // Mirrors secure-proxy's lumberjack defaults (64 MiB / 5 backups).
        Self {
            enabled: false,
            max_size: 64 * 1024 * 1024,
            max_backups: 5,
        }
    }
}

impl RollingConfig {
    /// Read from the `TNG_HOOK_LOG_*` env vars injected by the parent `tng exec`.
    /// `max_size` is a plain byte count (the parent serialises the human-readable
    /// CLI/env value to bytes before injecting). Invalid values fall back to the
    /// per-field default silently (a cdylib ctor stays quiet).
    pub fn from_hook_env() -> RollingConfig {
        let mut cfg = RollingConfig::default();
        if let Ok(v) = std::env::var("TNG_HOOK_LOG_ROLLING") {
            cfg.enabled = v.eq_ignore_ascii_case("true") || v == "1";
        }
        if let Ok(v) = std::env::var("TNG_HOOK_LOG_MAX_SIZE") {
            if let Ok(n) = v.parse::<u64>() {
                cfg.max_size = n;
            }
        }
        if let Ok(v) = std::env::var("TNG_HOOK_LOG_MAX_BACKUPS") {
            if let Ok(n) = v.parse::<usize>() {
                cfg.max_backups = n;
            }
        }
        cfg
    }
}

/// Parse a human-readable byte size: `64MB`, `1GB`, `1024`, `0B`. Case-insensitive,
/// binary units (KB = 1024).
pub fn parse_size(input: &str) -> Result<u64, String> {
    let s = input.trim();
    let lower = s.to_ascii_lowercase();
    let (num_str, factor): (&str, u64) = if let Some(n) = lower.strip_suffix("gb") {
        (n, 1 << 30)
    } else if let Some(n) = lower.strip_suffix("mb") {
        (n, 1 << 20)
    } else if let Some(n) = lower.strip_suffix("kb") {
        (n, 1 << 10)
    } else if let Some(n) = lower.strip_suffix("b") {
        (n, 1)
    } else {
        (lower.as_str(), 1)
    };
    let n: u64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid size `{input}` (expected e.g. 64MB or 67108864)"))?;
    n.checked_mul(factor)
        .ok_or_else(|| format!("size `{input}` overflows u64"))
}

/// Derive the hook's own log path: insert `.<pid>` before the last `.`-separated
/// extension of `base`; if `base` has no extension, append `.<pid>`. Mirrors the
/// Go lumberjack "timestamp before extension" convention and is provably
/// collision-free with the main process's `base.N` rotation backups.
pub fn hook_log_path(base: &Path, pid: u32) -> PathBuf {
    let new_name = match (base.file_stem(), base.extension()) {
        (Some(stem), Some(ext)) => {
            format!(
                "{}.{}.{}",
                stem.to_string_lossy(),
                pid,
                ext.to_string_lossy()
            )
        }
        (Some(stem), None) => format!("{}.{}", stem.to_string_lossy(), pid),
        _ => return base.to_path_buf(),
    };
    match base.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(new_name),
        _ => PathBuf::from(new_name),
    }
}

/// True when `path` is a regular file, a symlink to a file, or doesn't exist yet
/// (so it can be created). False for char/block devices (e.g. /dev/tty), fifos,
/// sockets, directories, or unreadable paths — rolling those is nonsensical.
pub fn path_supports_rolling(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(md) => md.is_file(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("64MB").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_size("1GB").unwrap(), 1 << 30);
        assert_eq!(parse_size("2kb").unwrap(), 2 * 1024);
        assert_eq!(parse_size("0B").unwrap(), 0);
    }

    #[test]
    fn parse_size_rejects_garbage() {
        assert!(parse_size("abc").is_err());
        assert!(parse_size("").is_err());
        assert!(parse_size("64QB").is_err());
    }

    #[test]
    fn hook_path_inserts_pid_before_last_ext() {
        assert_eq!(
            hook_log_path(std::path::Path::new("/home/admin/logs/info.log.tng"), 12345),
            std::path::PathBuf::from("/home/admin/logs/info.log.12345.tng")
        );
        assert_eq!(
            hook_log_path(std::path::Path::new("/var/log/tng.log"), 7),
            std::path::PathBuf::from("/var/log/tng.7.log")
        );
        assert_eq!(
            hook_log_path(std::path::Path::new("tng"), 9),
            std::path::PathBuf::from("tng.9")
        );
    }

    #[test]
    fn path_supports_rolling_for_real_and_missing() {
        let f = std::env::temp_dir().join("tng_rolling_probe_real");
        std::fs::write(&f, b"x").unwrap();
        assert!(path_supports_rolling(&f)); // regular file
        let missing = std::env::temp_dir().join("tng_rolling_probe_missing");
        let _ = std::fs::remove_file(&missing);
        assert!(path_supports_rolling(&missing)); // creatable
        assert!(!path_supports_rolling(std::path::Path::new("/dev/null"))); // char device
    }

    #[test]
    fn default_mirrors_secure_proxy() {
        let d = RollingConfig::default();
        assert!(!d.enabled);
        assert_eq!(d.max_size, 64 * 1024 * 1024);
        assert_eq!(d.max_backups, 5);
    }
}

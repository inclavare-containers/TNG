//! Rolling-log config used by the `tng` binary/lib.

use std::path::Path;

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

/// True when `path` is a regular file, a symlink to a file, or doesn't exist yet
/// (so it can be created). False for char/block devices (e.g. /dev/tty), fifos,
/// sockets, directories, or unreadable paths: rolling those is nonsensical.
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

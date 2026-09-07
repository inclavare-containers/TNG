//! Log format resolution: `TNG_LOG_FORMAT` env var takes priority over the
//! `--log-format` CLI flag, which falls back to plain text.

use std::path::PathBuf;
use std::str::FromStr as _;

use tng::rolling::{parse_size, RollingConfig};
use tng_hook_types::LogFormat;

/// Outcome of resolving the log format. The resolved format is always
/// present (falling back to [`LogFormat::Text`]); `invalid_env_warning`
/// carries a message to emit *after* tracing is initialized when the env
/// value could not be parsed (so it lands in the JSON/text log stream rather
/// than being dropped by an uninitialised subscriber).
#[derive(Debug)]
pub struct ResolvedLogFormat {
    pub format: LogFormat,
    pub invalid_env_warning: Option<String>,
}

/// Resolve the active log format, honoring env > CLI > default.
///
/// Order:
/// 1. `TNG_LOG_FORMAT` env var (parsed case-insensitively via `FromStr`).
///    An invalid value defers a warning (returned in
///    [`ResolvedLogFormat::invalid_env_warning`]) and falls back to `Text`
///    rather than aborting startup.
/// 2. `--log-format` CLI flag.
/// 3. `Text`.
///
/// An empty env value is treated as unset so an explicit `TNG_LOG_FORMAT=`
/// falls through to the CLI flag / default (the common "unset" idiom).
pub fn resolve_log_format(cli_value: Option<LogFormat>) -> ResolvedLogFormat {
    match std::env::var("TNG_LOG_FORMAT") {
        Ok(raw) if !raw.is_empty() => match LogFormat::from_str(&raw) {
            Ok(format) => ResolvedLogFormat {
                format,
                invalid_env_warning: None,
            },
            Err(err) => ResolvedLogFormat {
                format: LogFormat::Text,
                invalid_env_warning: Some(format!(
                    "TNG_LOG_FORMAT={raw:?} is not a valid format ({err}); falling back to text"
                )),
            },
        },
        _ => ResolvedLogFormat {
            format: cli_value.unwrap_or(LogFormat::Text),
            invalid_env_warning: None,
        },
    }
}

/// Resolve the error log file path: env `TNG_LOG_ERROR_FILE` > CLI > None.
/// When None, ERROR events go to the main --log-file (current behavior).
pub fn resolve_error_file(cli_value: Option<PathBuf>) -> Option<PathBuf> {
    match std::env::var("TNG_LOG_ERROR_FILE") {
        Ok(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => cli_value,
    }
}

/// Resolved rolling config plus deferred warnings for invalid env/CLI values
/// (emitted after tracing init so they land in the log stream).
#[derive(Debug, Default)]
pub struct ResolvedRolling {
    pub config: RollingConfig,
    pub warnings: Vec<String>,
}

/// Resolve rolling config: `TNG_LOG_*` env > CLI > default. An invalid value
/// defers a warning and keeps the default rather than aborting.
pub fn resolve_rolling(
    cli_rolling: bool,
    cli_max_size: Option<&str>,
    cli_max_backups: Option<usize>,
) -> ResolvedRolling {
    let mut cfg = RollingConfig::default();
    let mut warnings = Vec::new();

    cfg.enabled = match std::env::var("TNG_LOG_ROLLING") {
        Ok(v) if !v.is_empty() => v.eq_ignore_ascii_case("true") || v == "1",
        _ => cli_rolling,
    };

    // max-size: env > CLI > default. Track whether it was explicitly given so
    // we can warn when rolling is disabled (max-size only takes effect when
    // rolling is on).
    let (size_input, size_given) = match std::env::var("TNG_LOG_MAX_SIZE") {
        Ok(v) if !v.is_empty() => (Some(v), true),
        _ => (cli_max_size.map(str::to_string), cli_max_size.is_some()),
    };
    if let Some(s) = size_input {
        match parse_size(&s) {
            Ok(n) => cfg.max_size = n,
            Err(e) => warnings.push(format!(
                "log max-size `{s}` invalid ({e}); using default {} bytes",
                cfg.max_size
            )),
        }
    }

    // max-backups: env > CLI > default.
    let backups_given = match std::env::var("TNG_LOG_MAX_BACKUPS") {
        Ok(v) if !v.is_empty() => match v.parse::<usize>() {
            Ok(n) => {
                cfg.max_backups = n;
                true
            }
            Err(_) => {
                warnings.push(format!(
                    "log max-backups `{v}` invalid; using default {}",
                    cfg.max_backups
                ));
                true
            }
        },
        _ => {
            if let Some(n) = cli_max_backups {
                cfg.max_backups = n;
            }
            cli_max_backups.is_some()
        }
    };

    // max-size / max-backups only take effect when rolling is enabled. If the
    // user set either but left rolling off, say so rather than silently
    // ignoring them.
    if !cfg.enabled && (size_given || backups_given) {
        warnings.push(
            "--log-max-size / --log-max-backups were set but --log-rolling is not enabled; they have no effect".into(),
        );
    }

    ResolvedRolling {
        config: cfg,
        warnings,
    }
}

#[cfg(test)]
mod error_file_tests {
    use super::*;

    #[serial_test::serial]
    #[test]
    fn resolve_error_file_env_over_cli() {
        std::env::remove_var("TNG_LOG_ERROR_FILE");
        let cli = Some(PathBuf::from("/cli.err"));
        assert_eq!(
            resolve_error_file(cli.clone()),
            Some(PathBuf::from("/cli.err"))
        );
        std::env::set_var("TNG_LOG_ERROR_FILE", "/env.err");
        assert_eq!(resolve_error_file(cli), Some(PathBuf::from("/env.err")));
        std::env::remove_var("TNG_LOG_ERROR_FILE");
    }
}

#[cfg(test)]
mod rolling_tests {
    use super::*;

    fn clear_env() {
        std::env::remove_var("TNG_LOG_ROLLING");
        std::env::remove_var("TNG_LOG_MAX_SIZE");
        std::env::remove_var("TNG_LOG_MAX_BACKUPS");
    }

    #[serial_test::serial]
    #[test]
    fn defaults_when_unset() {
        clear_env();
        let r = resolve_rolling(false, None, None);
        assert!(!r.config.enabled);
        assert_eq!(r.config.max_size, 64 * 1024 * 1024);
        assert_eq!(r.config.max_backups, 5);
        assert!(r.warnings.is_empty());
    }

    #[serial_test::serial]
    #[test]
    fn cli_enables_and_overrides() {
        clear_env();
        let r = resolve_rolling(true, Some("1MB"), Some(2));
        assert!(r.config.enabled);
        assert_eq!(r.config.max_size, 1024 * 1024);
        assert_eq!(r.config.max_backups, 2);
    }

    #[serial_test::serial]
    #[test]
    fn env_overrides_cli() {
        clear_env();
        std::env::set_var("TNG_LOG_MAX_SIZE", "2MB");
        std::env::set_var("TNG_LOG_ROLLING", "false");
        let r = resolve_rolling(true, Some("1MB"), None);
        assert!(!r.config.enabled); // env false wins
        assert_eq!(r.config.max_size, 2 * 1024 * 1024); // env wins
        clear_env();
    }

    #[serial_test::serial]
    #[test]
    fn invalid_env_defers_warning() {
        clear_env();
        std::env::set_var("TNG_LOG_MAX_SIZE", "wat");
        let r = resolve_rolling(true, None, None);
        assert!(r.config.enabled);
        assert_eq!(r.config.max_size, 64 * 1024 * 1024); // kept default
        assert!(r.warnings.iter().any(|w| w.contains("wat")));
        clear_env();
    }

    #[serial_test::serial]
    #[test]
    fn warns_when_max_size_set_without_rolling() {
        clear_env();
        // rolling off, max-size explicitly set -> inert + warning
        let r = resolve_rolling(false, Some("1MB"), None);
        assert!(!r.config.enabled);
        assert!(r.warnings.iter().any(|w| w.contains("not enabled")));
        clear_env();
    }

    #[serial_test::serial]
    #[test]
    fn no_warning_when_unset_without_rolling() {
        clear_env();
        // rolling off, nothing set -> no "no effect" warning
        let r = resolve_rolling(false, None, None);
        assert!(!r.config.enabled);
        assert!(r.warnings.is_empty());
        clear_env();
    }
}

//! Log format resolution: `TNG_LOG_FORMAT` env var takes priority over the
//! `--log-format` CLI flag, which falls back to plain text.

use std::str::FromStr as _;

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

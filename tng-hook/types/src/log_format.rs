//! Log output format shared by the `tng` binary and the `tng-hook` cdylib.
//!
//! Lives here (in `tng-hook-types`) so both crates use the *same* domain type
//! instead of round-tripping through a `bool`/`&str`. Parsed case-insensitively
//! from environment variables and CLI args via `FromStr`.

/// Log output format for the tracing fmt layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable plain text (default).
    Text,
    /// One JSON object per line (JSON Lines).
    Json,
}

impl LogFormat {
    /// Lowercase wire string used for the `TNG_HOOK_LOG_FORMAT` env var and
    /// `Display`. Stable for env round-tripping.
    pub fn as_str(&self) -> &'static str {
        match self {
            LogFormat::Text => "text",
            LogFormat::Json => "json",
        }
    }
}

impl std::fmt::Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "text" => Ok(LogFormat::Text),
            "json" => Ok(LogFormat::Json),
            other => Err(format!("unknown log format `{other}` (expected text|json)")),
        }
    }
}

//! Shared readiness helpers for external tng processes.
//!
//! Provides config patching for the control_interface and /readyz polling,
//! used by `TngInstance` (external).

#![cfg(any(feature = "on-bin", feature = "on-podman"))]

use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use serde_json::json;

/// Pick a free port for the injected control_interface, avoiding any port
/// already referenced in the tng config (egress/ingress/hook ports).
///
/// `portpicker::pick_unused_port` alone can return a config port on systems
/// whose ephemeral port range overlaps the configured port, which makes the
/// control interface self-collide with the config's own listener at tng
/// startup ("Address already in use" → process exits before ready).
pub fn pick_control_port(config_json: &str) -> Result<u16> {
    let used: std::collections::HashSet<u16> =
        serde_json::from_str::<serde_json::Value>(config_json)
            .map(|v| collect_ports(&v))
            // If the config isn't valid JSON here, patch_config_with_control_interface
            // will surface the real parse error; just fall back to a plain free port.
            .unwrap_or_default();

    for _ in 0..64 {
        let p = portpicker::pick_unused_port().context("Failed to pick a free port")?;
        if !used.contains(&p) {
            return Ok(p);
        }
    }
    bail!("failed to pick a control port avoiding config ports after 64 tries");
}

/// Recursively collect every numeric `port` field value from the config, so
/// the control port can be chosen to not collide with any of them.
fn collect_ports(v: &serde_json::Value) -> std::collections::HashSet<u16> {
    let mut set = std::collections::HashSet::new();
    match v {
        serde_json::Value::Object(o) => {
            for (k, val) in o {
                if k == "port" {
                    if let Some(n) = val.as_u64().and_then(|n| u16::try_from(n).ok()) {
                        set.insert(n);
                    }
                }
                for p in collect_ports(val) {
                    set.insert(p);
                }
            }
        }
        serde_json::Value::Array(a) => {
            for val in a {
                for p in collect_ports(val) {
                    set.insert(p);
                }
            }
        }
        _ => {}
    }
    set
}

/// Patch a TNG config JSON to inject a REST control_interface on the given port.
///
/// Returns the patched config JSON string. Fails if `control_interface` already exists.
pub fn patch_config_with_control_interface(config_json: &str, port: u16) -> Result<String> {
    let mut tng_config: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(config_json)
            .with_context(|| format!("Failed to parse config json: {config_json}"))?;

    if tng_config.contains_key("control_interface") {
        bail!("control_interface config already exists in the config json");
    }

    tng_config.insert(
        "control_interface".to_string(),
        json!({
            "restful": {
                "host": "127.0.0.1",
                "port": port
            }
        }),
    );

    Ok(serde_json::to_string(&tng_config)?)
}

/// Result of checking the child process status during readyz polling.
pub enum ProcessStatus {
    /// Process is still running, keep polling.
    Running,
    /// Process has exited with the given exit code.
    Exited(Option<i32>),
}

/// Wait for a tng process to become ready by polling `/readyz`.
///
/// - `port`: the control_interface port to poll
/// - `check_process`: closure called each iteration to check if the process is still alive
///
/// Returns once `/readyz` returns 200 OK.
/// Returns an error if the process exits before becoming ready.
pub async fn wait_for_readyz(
    port: u16,
    mut check_process: impl FnMut() -> ProcessStatus,
) -> Result<()> {
    let url = format!("http://127.0.0.1:{port}/readyz");

    loop {
        if let Ok(resp) = reqwest::get(&url).await {
            if resp.status() == reqwest::StatusCode::OK {
                return Ok(());
            }
        }

        match check_process() {
            ProcessStatus::Running => {}
            ProcessStatus::Exited(code) => {
                bail!(
                    "tng process exited before becoming ready, exit code: {:?}",
                    code
                );
            }
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

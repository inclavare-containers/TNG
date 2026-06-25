use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{bail, Context as _, Result};

use crate::config::egress::EgressMode;
use crate::config::egress_hook::EgressHookArgs;
use crate::config::{HookMappingEntry, HookMappingTable, TngConfig};

/// Execute a command with LD_PRELOAD-based port interception.
pub struct TngExec;

impl TngExec {
    /// Validate config, build mappings, and run the child process with TNG tunnel.
    pub async fn run(
        mut config: TngConfig,
        command: Vec<String>,
        reload_handle: &crate::runtime::TracingReloadHandle,
    ) -> Result<()> {
        // 1. Validate all egress entries are Hook mode
        Self::validate_config(&config)?;

        // 2. Build resolved entries for each hook add_egress entry
        let mut all_entries: Vec<HookMappingEntry> = Vec::new();
        let mut next_auto_port: u16 = 49152;

        for egress in &mut config.add_egress {
            if let EgressMode::Hook(args) = &mut egress.egress_mode {
                let (entries, next_port) = Self::build_resolved_entries(args, next_auto_port)?;
                args.resolved_entries = entries;
                next_auto_port = next_port;
                all_entries.extend(args.resolved_entries.clone());
            }
        }

        if all_entries.is_empty() {
            bail!("No capture_listen entries found in config. At least one is required.");
        }

        // 3. Global conflict check
        Self::check_conflicts(&all_entries)?;

        // 4. Combined mapping table for .so
        let mapping_table = Self::build_mapping_table_for_so(&all_entries);
        let mappings_json =
            serde_json::to_string(&mapping_table).context("Failed to serialize mapping table")?;

        tracing::info!(
            entries = mapping_table.entries.len(),
            "Built port mapping table"
        );

        // 5. Resolve lib path
        let lib_path = Self::resolve_lib_path().context("Failed to resolve libtng_hook.so path")?;

        tracing::info!(?lib_path, "Resolved hook library path");

        // 6. Start TNG runtime (config now has resolved_entries populated)
        let runtime =
            crate::runtime::TngRuntime::from_config_with_reload_handle(config, reload_handle)
                .await
                .context("Failed to initialize TNG runtime")?;

        let canceller = runtime.canceller();

        // Create a oneshot channel to signal when the runtime is fully serving.
        // This prevents a TOCTOU race where the child process tries to connect
        // to the hook ports before the runtime's listeners are bound.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

        // Spawn the TNG runtime task. This manages the tunnel lifecycle, which
        // must run concurrently with the child process. We use tokio::spawn here
        // because the runtime's own graceful shutdown is managed internally by
        // TngRuntime (via the CancellationToken above), and this task's lifetime
        // is explicitly tied to the child process (step 8 cancels it).
        #[allow(clippy::disallowed_methods)]
        let runtime_handle = tokio::spawn(async move {
            if let Err(e) = runtime.serve_with_ready(ready_tx).await {
                tracing::error!(?e, "TNG runtime error");
            }
        });

        // Wait for the runtime to signal that all listeners are bound before
        // spawning the child. This ensures the hook library's intercepted
        // connect() calls will succeed immediately.
        ready_rx
            .await
            .context("TNG runtime readiness signal was dropped")?;

        // 7. Spawn child process with LD_PRELOAD
        let (cmd, args) = command.split_first().context("Command is empty")?;

        let mut child = tokio::process::Command::new(cmd)
            .args(args)
            .env("LD_PRELOAD", &lib_path)
            .env("TNG_HOOK_MAPPINGS", &mappings_json)
            .spawn()
            .context("Failed to spawn child command")?;

        let child_id = child.id();
        tracing::info!(pid = child_id, ?command, "Spawned child process");

        // 8. Wait for child exit
        let exit_status = child.wait().await.context("Failed to wait for child")?;

        tracing::info!(?exit_status, "Child process exited");

        // 9. Cancel TNG runtime
        canceller.cancel();
        let _ = runtime_handle.await;

        // 10. Exit with child's exit code
        if !exit_status.success() {
            std::process::exit(exit_status.code().unwrap_or(1));
        }

        Ok(())
    }

    /// Validate that all add_egress entries use Hook mode.
    fn validate_config(config: &TngConfig) -> Result<()> {
        if config.add_egress.is_empty() {
            bail!("tng exec requires at least one add_egress entry");
        }

        for (i, egress) in config.add_egress.iter().enumerate() {
            match &egress.egress_mode {
                EgressMode::Hook(args) => {
                    if args.capture_listen.is_empty() {
                        bail!(
                            "Egress entry {} has hook mode but no capture_listen entries",
                            i
                        );
                    }
                }
                _ => {
                    bail!(
                        "tng exec only supports 'hook' mode, but egress entry {} uses a different mode. \
                         Hook mode is mutually exclusive with other egress modes.",
                        i
                    );
                }
            }
        }

        Ok(())
    }

    /// Build resolved entries for a single EgressHookArgs.
    /// Expands port ranges, auto-allocates real ports for entries without redirect_to_port,
    /// and fills host defaults (unspecified → 0.0.0.0).
    /// Returns (resolved_entries, next_auto_port).
    fn build_resolved_entries(
        args: &EgressHookArgs,
        start_auto_port: u16,
    ) -> Result<(Vec<HookMappingEntry>, u16)> {
        let mut entries = Vec::new();
        let mut next_auto_port = start_auto_port;

        for entry in &args.capture_listen {
            let (new_entries, next_port) = entry
                .expand_mappings(next_auto_port)
                .context("Failed to expand intercept entry")?;

            // For entries with explicit redirect_to_port, keep the ports as-is.
            // For entries without redirect (auto-allocated), re-pick via portpicker.
            if entry.redirect_to_port.is_some() {
                entries.extend(new_entries);
            } else {
                for mut e in new_entries {
                    if let Some(picked) = portpicker::pick_unused_port() {
                        e.real_port = picked;
                    } else {
                        bail!("Failed to pick unused port for hook mapping");
                    }
                    entries.push(e);
                }
            }

            next_auto_port = next_port;
        }

        Ok((entries, next_auto_port))
    }

    /// Check for conflicts across all resolved entries from all egress entries.
    /// Two entries conflict if they map the same (host, origin_port) to different real_ports,
    /// or if two entries claim the same real_port.
    fn check_conflicts(all_entries: &[HookMappingEntry]) -> Result<()> {
        let mut origin_map: HashMap<(std::net::Ipv4Addr, u16), u16> = HashMap::new();
        let mut real_port_map: HashMap<u16, (std::net::Ipv4Addr, u16)> = HashMap::new();

        for entry in all_entries {
            let key = (entry.host, entry.origin_port);

            // Check duplicate (host, origin_port)
            if let Some(existing_real) = origin_map.get(&key) {
                if *existing_real != entry.real_port {
                    bail!(
                        "Conflict: ({}, {}) is mapped to both real_port {} and {}",
                        key.0,
                        key.1,
                        existing_real,
                        entry.real_port
                    );
                }
                // Same mapping is fine (deduplicated at .so level)
            } else {
                origin_map.insert(key, entry.real_port);
            }

            // Check duplicate real_port
            if let Some(existing_key) = real_port_map.get(&entry.real_port) {
                if *existing_key != key {
                    bail!(
                        "Conflict: real_port {} is claimed by both ({}, {}) and ({}, {})",
                        entry.real_port,
                        existing_key.0,
                        existing_key.1,
                        key.0,
                        key.1
                    );
                }
            } else {
                real_port_map.insert(entry.real_port, key);
            }
        }

        Ok(())
    }

    /// Build combined HookMappingTable for .so env var.
    fn build_mapping_table_for_so(all_entries: &[HookMappingEntry]) -> HookMappingTable {
        // Deduplicate: if multiple entries map the same (host, origin_port), first wins
        let mut seen = std::collections::HashSet::new();
        let mut deduped = Vec::new();
        for e in all_entries {
            let key = (e.host, e.origin_port);
            if seen.insert(key) {
                deduped.push(e.clone());
            }
        }

        HookMappingTable { entries: deduped }
    }

    /// Resolve the path to `libtng_hook.so`.
    ///
    /// Search order:
    /// 1. `TNG_HOOK_LIB` environment variable (explicit override)
    /// 2. Same directory as the `tng` binary
    /// 3. System install at `/usr/lib/tng/libtng_hook.so`
    fn resolve_lib_path() -> Result<PathBuf> {
        // 1. Explicit override via environment variable
        if let Ok(path) = std::env::var("TNG_HOOK_LIB") {
            let lib_path = PathBuf::from(&path);
            if lib_path.exists() {
                return Ok(lib_path);
            }
            bail!(
                "TNG_HOOK_LIB points to {:?} but the file does not exist",
                lib_path
            );
        }

        // 2. Same directory as the tng binary
        let exe_path = std::env::current_exe().context("Failed to get current executable path")?;
        if let Some(parent) = exe_path.parent() {
            let lib_path = parent.join("libtng_hook.so");
            if lib_path.exists() {
                return Ok(lib_path);
            }
        }

        // 3. System install
        let system_path = PathBuf::from("/usr/lib/tng/libtng_hook.so");
        if system_path.exists() {
            return Ok(system_path);
        }

        bail!(
            "libtng_hook.so not found.\n\
             Searched:\n\
             - $TNG_HOOK_LIB (not set)\n\
             - {:?}\n\
             - /usr/lib/tng/libtng_hook.so",
            exe_path.parent().map(|p| p.join("libtng_hook.so"))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_hook_config(entries: serde_json::Value) -> TngConfig {
        serde_json::from_value(json!({
            "add_egress": [{
                "hook": {
                    "capture_listen": entries
                },
                "attest": {
                    "no_ra": true,
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }]
        }))
        .unwrap()
    }

    #[test]
    fn test_validate_hook_only() {
        let config = make_hook_config(json!([{ "port": 8080 }]));
        let result = TngExec::validate_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_reject_mapping() {
        let config: TngConfig = serde_json::from_value(json!({
            "add_egress": [{
                "mapping": {
                    "in": { "port": 8080 },
                    "out": { "host": "127.0.0.1", "port": 9090 }
                },
                "attest": {
                    "no_ra": true,
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }]
        }))
        .unwrap();
        let result = TngExec::validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hook"));
    }

    #[test]
    fn test_build_resolved_entries_auto_alloc() {
        let config = make_hook_config(json!([{ "port": 8080 }, { "port": 8081 }]));
        let args = if let EgressMode::Hook(args) = &config.add_egress[0].egress_mode {
            args.clone()
        } else {
            panic!("expected hook mode")
        };
        let (entries, next_port) = TngExec::build_resolved_entries(&args, 49152).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].origin_port, 8080);
        assert_eq!(entries[1].origin_port, 8081);
        // Real ports should be picked by portpicker (non-zero, distinct)
        assert!(entries[0].real_port > 0);
        assert!(entries[1].real_port > 0);
        assert_ne!(entries[0].real_port, entries[1].real_port);
        assert_eq!(next_port, 49154); // next_auto_port incremented by expand_mappings
    }

    #[test]
    fn test_build_resolved_entries_explicit_redirect() {
        let config = make_hook_config(json!([
            { "port": 8080, "redirect_to_port": 48080 },
            { "port": 8081, "redirect_to_port": 48081 }
        ]));
        let args = if let EgressMode::Hook(args) = &config.add_egress[0].egress_mode {
            args.clone()
        } else {
            panic!("expected hook mode")
        };
        let (entries, next_port) = TngExec::build_resolved_entries(&args, 49152).unwrap();
        assert_eq!(entries[0].real_port, 48080);
        assert_eq!(entries[1].real_port, 48081);
        assert_eq!(next_port, 49152); // auto port unchanged
    }

    #[test]
    fn test_build_mapping_table_dedup() {
        let config = make_hook_config(json!([
            { "port": 8080 },
            { "port": 8080, "redirect_to_port": 49000 } // duplicate
        ]));
        TngExec::validate_config(&config).unwrap();
        let args = if let EgressMode::Hook(args) = &config.add_egress[0].egress_mode {
            args.clone()
        } else {
            panic!("expected hook mode")
        };
        let (entries, _) = TngExec::build_resolved_entries(&args, 49152).unwrap();
        let table = TngExec::build_mapping_table_for_so(&entries);
        // First entry wins
        assert_eq!(table.entries.len(), 1);
        assert!(table.entries[0].real_port > 0);
    }

    #[test]
    fn test_check_conflicts_no_conflict() {
        let entries = vec![
            HookMappingEntry {
                host: std::net::Ipv4Addr::UNSPECIFIED,
                origin_port: 8080,
                real_port: 48080,
            },
            HookMappingEntry {
                host: std::net::Ipv4Addr::UNSPECIFIED,
                origin_port: 8081,
                real_port: 48081,
            },
        ];
        assert!(TngExec::check_conflicts(&entries).is_ok());
    }

    #[test]
    fn test_check_conflicts_duplicate_origin() {
        let entries = vec![
            HookMappingEntry {
                host: std::net::Ipv4Addr::UNSPECIFIED,
                origin_port: 8080,
                real_port: 48080,
            },
            HookMappingEntry {
                host: std::net::Ipv4Addr::UNSPECIFIED,
                origin_port: 8080,
                real_port: 48080, // same origin, same real → no conflict
            },
        ];
        assert!(TngExec::check_conflicts(&entries).is_ok());
    }

    #[test]
    fn test_check_conflicts_real_port_collision() {
        let entries = vec![
            HookMappingEntry {
                host: std::net::Ipv4Addr::UNSPECIFIED,
                origin_port: 8080,
                real_port: 48080,
            },
            HookMappingEntry {
                host: std::net::Ipv4Addr::UNSPECIFIED,
                origin_port: 8081,
                real_port: 48080, // different origin, same real → conflict
            },
        ];
        let result = TngExec::check_conflicts(&entries);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Conflict"));
    }
}

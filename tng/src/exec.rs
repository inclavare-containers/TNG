use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{bail, Context as _, Result};

use crate::config::egress::EgressMode;
use crate::config::egress_hook::EgressHookArgs;
use crate::config::ingress::IngressHookArgs;
use crate::config::ingress::IngressMode as IngressHookMode;
use crate::config::{
    EgressHookMappingEntry, EgressHookMappingTable, IngressHookCaptureRule,
    IngressHookMappingTable, IngressHookProxy, TngConfig, TngEgressHookMappingEntry,
};
use crate::tunnel::access_log::EgressAccessMode;
use crate::tunnel::access_log::IngressAccessMode;

/// A centralized port allocator that ensures no two auto-allocated ports collide
/// across all egress and ingress hook entries in exec mode.
///
/// portpicker::pick_unused_port() binds then drops the socket, so another call
/// immediately after can get the same port (TOCTOU). By tracking all allocated
/// ports in a single HashSet and checking before accept, we prevent collisions.
struct PortAllocator {
    used: HashSet<u16>,
}

impl PortAllocator {
    fn new() -> Self {
        Self {
            used: HashSet::new(),
        }
    }

    /// Pick a unique port that hasn't been allocated yet.
    /// Tries portpicker first (up to 50 attempts), then asks the OS,
    /// then falls back to sequential scan from 49152.
    fn pick(&mut self) -> Option<u16> {
        let mut attempts = 0;
        while attempts < 50 {
            if let Some(port) = portpicker::pick_unused_port() {
                if self.used.insert(port) {
                    return Some(port);
                }
                // Port already claimed, try again.
            } else {
                // portpicker exhausted, fall back to asking OS.
                if let Some(port) = Self::ask_os_port() {
                    if self.used.insert(port) {
                        return Some(port);
                    }
                }
            }
            attempts += 1;
        }
        // Final fallback: sequential search from 49152.
        (49152..=65535).find(|p| !self.used.contains(p))
    }

    /// Record a port as used (for explicit redirect_to_port / proxy_port).
    /// Returns Err if the port was already claimed.
    fn reserve(&mut self, port: u16) -> Result<()> {
        if self.used.insert(port) {
            Ok(())
        } else {
            bail!(
                "Conflict: port {} is already claimed by another entry",
                port
            )
        }
    }

    /// Ask the OS for an available TCP port (binds then drops).
    fn ask_os_port() -> Option<u16> {
        for _ in 0..10 {
            let listener =
                std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).ok()?;
            if let Ok(addr) = listener.local_addr() {
                return Some(addr.port());
            }
        }
        None
    }
}
pub struct TngExec;

impl TngExec {
    /// Validate all hook-mode entries, build mappings, and run the child
    /// process with TNG tunnel. Supports both egress and ingress hooks
    /// simultaneously.
    pub async fn run(
        mut config: TngConfig,
        command: Vec<String>,
        reload_handle: &crate::runtime::TracingReloadHandle,
    ) -> Result<()> {
        // 1. Validate all hook-mode entries
        Self::validate_config(&config)?;

        // 2. Build egress resolved entries
        let mut all_egress_entries: Vec<TngEgressHookMappingEntry> = Vec::new();
        let mut next_auto_port: u16 = 49152;
        let mut port_alloc = PortAllocator::new();

        for egress in &mut config.add_egress {
            if let EgressMode::Hook(args) = &mut egress.egress_mode {
                let (entries, next_port) =
                    Self::build_resolved_entries(args, next_auto_port, &mut port_alloc)?;
                args.resolved_entries = entries;
                next_auto_port = next_port;
                all_egress_entries.extend(args.resolved_entries.clone());
            }
        }

        let egress_json = if !all_egress_entries.is_empty() {
            Self::check_conflicts(&all_egress_entries)?;
            let table = Self::build_mapping_table_for_so(&all_egress_entries);
            Some(
                serde_json::to_string(&table)
                    .context("Failed to serialize egress mapping table")?,
            )
        } else {
            None
        };

        // 3. Build ingress mapping table and serialize
        let ingress_table = Self::build_ingress_mapping_table(&mut config, &mut port_alloc)?;
        let has_ingress_hooks = !ingress_table.proxies.is_empty();
        let ingress_json = serde_json::to_string(&ingress_table)
            .context("Failed to serialize ingress mapping table")?;

        // 4. If no hook entries at all, bail
        if egress_json.is_none() && !has_ingress_hooks {
            bail!("tng exec requires at least one hook-mode entry (egress or ingress)");
        }

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

        // 7. Spawn child process with LD_PRELOAD and mapping env vars
        let (cmd, args) = command.split_first().context("Command is empty")?;

        let mut child_cmd = tokio::process::Command::new(cmd);
        child_cmd.args(args).env("LD_PRELOAD", &lib_path);

        if let Some(ref json) = egress_json {
            child_cmd.env("TNG_HOOK_EGRESS_MAPPINGS", json);
        }
        // Always set ingress mapping (even if empty proxies, for consistency)
        child_cmd.env("TNG_HOOK_INGRESS_MAPPINGS", &ingress_json);

        let mut child = child_cmd.spawn().context("Failed to spawn child command")?;

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

    /// Validate hook-mode configuration.
    ///
    /// `tng exec` only supports hook modes (IngressMode::Hook, EgressMode::Hook).
    /// Non-hook modes (mapping, netfilter, http_proxy, socks5) are only allowed
    /// via `tng launch`.
    fn validate_config(config: &TngConfig) -> Result<()> {
        if config.add_ingress.is_empty() && config.add_egress.is_empty() {
            bail!("tng exec requires at least one add_ingress or add_egress entry");
        }

        // Validate all add_ingress entries: only hook mode allowed
        for (i, ingress) in config.add_ingress.iter().enumerate() {
            match &ingress.ingress_mode {
                IngressHookMode::Hook(args) => {
                    if args.capture_dst.is_empty() {
                        bail!(
                            "Ingress entry {} has '{}' mode but no capture_dst entries",
                            i,
                            ingress.ingress_mode.access_mode()
                        );
                    }
                }
                _ => {
                    bail!(
                        "tng exec only supports '{}' mode ingress, but ingress entry {} uses a '{}' mode. \
                         Use `tng launch` for non-hook modes.",
                        IngressAccessMode::Hook,
                        i,
                        ingress.ingress_mode.access_mode()
                    );
                }
            }
        }

        // Validate all add_egress entries: only hook mode allowed
        for (i, egress) in config.add_egress.iter().enumerate() {
            match &egress.egress_mode {
                EgressMode::Hook(args) => {
                    if args.capture_listen.is_empty() {
                        bail!(
                            "Egress entry {} has '{}' mode but no capture_listen entries",
                            i,
                            egress.egress_mode.access_mode()
                        );
                    }
                }
                _ => {
                    bail!(
                        "tng exec only supports '{}' mode egress, but egress entry {} uses a '{}' mode. \
                         Use `tng launch` for non-hook modes.",
                        EgressAccessMode::Hook,
                        i,
                        egress.egress_mode.access_mode()
                    );
                }
            }
        }

        Ok(())
    }

    /// Build resolved entries for a single EgressHookArgs.
    /// Expands port ranges, auto-allocates real ports for entries without redirect_to_port,
    /// and fills host defaults (unspecified → 0.0.0.0).
    ///
    /// `port_alloc` tracks all real ports already claimed across all egress and ingress
    /// entries. Each newly allocated port is registered immediately to prevent portpicker
    /// TOCTOU races. Returns (resolved_entries, next_auto_port).
    fn build_resolved_entries(
        args: &EgressHookArgs,
        start_auto_port: u16,
        port_alloc: &mut PortAllocator,
    ) -> Result<(Vec<TngEgressHookMappingEntry>, u16)> {
        let mut entries = Vec::new();
        let mut next_auto_port = start_auto_port;

        for entry in &args.capture_listen {
            let (mut new_entries, next_port) = entry
                .expand_mappings(next_auto_port)
                .context("Failed to expand intercept entry")?;

            // For entries with explicit redirect_to_port, verify no collision and reserve.
            // For entries without redirect (auto-allocated), pick via the shared allocator
            // until we find an unclaimed port.
            if entry.redirect_to_port.is_some() {
                for e in &new_entries {
                    port_alloc.reserve(e.real_port)?;
                }
                entries.append(&mut new_entries);
            } else {
                for e in new_entries {
                    let real_port = port_alloc
                        .pick()
                        .context("Failed to pick unused port for hook mapping")?;
                    entries.push(TngEgressHookMappingEntry {
                        host_cidr: e.host_cidr,
                        origin_port: e.origin_port,
                        real_port,
                    });
                }
            }

            next_auto_port = next_port;
        }

        Ok((entries, next_auto_port))
    }

    /// Check for conflicts across all resolved entries from all egress entries.
    /// Two entries conflict if they map the same origin_port to different real_ports,
    /// or if two entries claim the same real_port.
    fn check_conflicts(all_entries: &[TngEgressHookMappingEntry]) -> Result<()> {
        let mut origin_map: HashMap<u16, u16> = HashMap::new(); // origin_port -> real_port
        let mut real_port_map: HashMap<u16, u16> = HashMap::new(); // real_port -> origin_port

        for entry in all_entries {
            // Check duplicate origin_port
            if let Some(existing_real) = origin_map.get(&entry.origin_port) {
                if *existing_real != entry.real_port {
                    bail!(
                        "Conflict: origin_port {} is mapped to both real_port {} and {}",
                        entry.origin_port,
                        existing_real,
                        entry.real_port
                    );
                }
                // Same mapping is fine (deduplicated at .so level)
            } else {
                origin_map.insert(entry.origin_port, entry.real_port);
            }

            // Check duplicate real_port
            if let Some(existing_origin) = real_port_map.get(&entry.real_port) {
                if *existing_origin != entry.origin_port {
                    bail!(
                        "Conflict: real_port {} is claimed by both origin_port {} and {}",
                        entry.real_port,
                        existing_origin,
                        entry.origin_port
                    );
                }
            } else {
                real_port_map.insert(entry.real_port, entry.origin_port);
            }
        }

        Ok(())
    }

    /// Build combined EgressHookMappingTable for .so env var.
    fn build_mapping_table_for_so(
        all_entries: &[TngEgressHookMappingEntry],
    ) -> EgressHookMappingTable {
        // Deduplicate: if multiple entries map the same origin_port, first wins
        let mut seen = std::collections::HashSet::new();
        let mut deduped = Vec::new();
        for e in all_entries {
            if seen.insert(e.origin_port) {
                deduped.push(EgressHookMappingEntry {
                    origin_port: e.origin_port,
                    real_port: e.real_port,
                });
            }
        }

        EgressHookMappingTable { entries: deduped }
    }

    /// Build the ingress hook mapping table from all hook-mode ingress entries.
    ///
    /// Uses the shared `port_alloc` to allocate proxy ports, preventing collisions
    /// with egress real ports and other ingress proxy ports.
    fn build_ingress_mapping_table(
        config: &mut TngConfig,
        port_alloc: &mut PortAllocator,
    ) -> Result<IngressHookMappingTable> {
        let mut mapping_table = IngressHookMappingTable::default();

        for (i, ingress) in config.add_ingress.iter_mut().enumerate() {
            if let IngressHookMode::Hook(args) = &mut ingress.ingress_mode {
                let proxy = Self::build_ingress_proxy(i, args, port_alloc)?;
                mapping_table.proxies.push(proxy);
            }
        }

        if !mapping_table.proxies.is_empty() {
            tracing::info!(
                proxies = mapping_table.proxies.len(),
                "Built ingress hook mapping table"
            );
        }

        Ok(mapping_table)
    }

    /// Build a single IngressHookProxy from an IngressHookArgs.
    ///
    /// If `args.proxy_port` is not set, a port is auto-allocated via the shared
    /// allocator and written back to `args.proxy_port` so the runtime uses the
    /// same port.
    fn build_ingress_proxy(
        _entry_index: usize,
        args: &mut IngressHookArgs,
        port_alloc: &mut PortAllocator,
    ) -> Result<IngressHookProxy> {
        let proxy_port = match args.proxy_port {
            Some(port) => {
                port_alloc
                    .reserve(port)
                    .with_context(|| format!("Failed to use ingress proxy port {port}"))?;
                port
            }
            None => {
                let port = port_alloc
                    .pick()
                    .context("Failed to pick unused port for ingress hook proxy")?;
                args.proxy_port = Some(port);
                port
            }
        };

        let capture_rules: Vec<IngressHookCaptureRule> = args
            .capture_dst
            .iter()
            .map(|dst| IngressHookCaptureRule {
                host_cidr: dst
                    .host
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "*".to_string()),
                port: dst.port,
                port_end: dst.port_end,
            })
            .collect();

        if capture_rules.is_empty() {
            bail!("Ingress hook entry has no capture_dst rules. At least one is required.");
        }

        Ok(IngressHookProxy {
            proxy_port,
            capture_rules,
        })
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
        let mut alloc = PortAllocator::new();
        let (entries, next_port) =
            TngExec::build_resolved_entries(&args, 49152, &mut alloc).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].origin_port, 8080);
        assert_eq!(entries[1].origin_port, 8081);
        // Real ports should be picked by portpicker (non-zero, distinct)
        assert!(entries[0].real_port > 0);
        assert!(entries[1].real_port > 0);
        assert_ne!(entries[0].real_port, entries[1].real_port);
        assert_eq!(next_port, 49154); // next_auto_port incremented by expand_mappings
                                      // Both ports tracked in allocator
        assert_eq!(alloc.used.len(), 2);
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
        let mut alloc = PortAllocator::new();
        let (entries, next_port) =
            TngExec::build_resolved_entries(&args, 49152, &mut alloc).unwrap();
        assert_eq!(entries[0].real_port, 48080);
        assert_eq!(entries[1].real_port, 48081);
        assert_eq!(next_port, 49152); // auto port unchanged
        assert_eq!(alloc.used.len(), 2);
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
        let mut alloc = PortAllocator::new();
        let (entries, _) = TngExec::build_resolved_entries(&args, 49152, &mut alloc).unwrap();
        let table = TngExec::build_mapping_table_for_so(&entries);
        // First entry wins
        assert_eq!(table.entries.len(), 1);
        assert!(table.entries[0].real_port > 0);
    }

    #[test]
    fn test_check_conflicts_no_conflict() {
        let entries = vec![
            TngEgressHookMappingEntry {
                host_cidr: cidr::Ipv4Cidr::new(std::net::Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                origin_port: 8080,
                real_port: 48080,
            },
            TngEgressHookMappingEntry {
                host_cidr: cidr::Ipv4Cidr::new(std::net::Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                origin_port: 8081,
                real_port: 48081,
            },
        ];
        assert!(TngExec::check_conflicts(&entries).is_ok());
    }

    #[test]
    fn test_check_conflicts_duplicate_origin() {
        let entries = vec![
            TngEgressHookMappingEntry {
                host_cidr: cidr::Ipv4Cidr::new(std::net::Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                origin_port: 8080,
                real_port: 48080,
            },
            TngEgressHookMappingEntry {
                host_cidr: cidr::Ipv4Cidr::new(std::net::Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                origin_port: 8080,
                real_port: 48080, // same origin, same real → no conflict
            },
        ];
        assert!(TngExec::check_conflicts(&entries).is_ok());
    }

    #[test]
    fn test_check_conflicts_real_port_collision() {
        let entries = vec![
            TngEgressHookMappingEntry {
                host_cidr: cidr::Ipv4Cidr::new(std::net::Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                origin_port: 8080,
                real_port: 48080,
            },
            TngEgressHookMappingEntry {
                host_cidr: cidr::Ipv4Cidr::new(std::net::Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                origin_port: 8081,
                real_port: 48080, // different origin, same real → conflict
            },
        ];
        let result = TngExec::check_conflicts(&entries);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Conflict"));
    }

    #[test]
    fn test_build_resolved_entries_explicit_redirect_collision() {
        // Two entries with the same explicit redirect_to_port should error
        // during build_resolved_entries (no longer waits for check_conflicts)
        let config = make_hook_config(json!([
            { "port": 8080, "redirect_to_port": 48080 },
            { "port": 8081, "redirect_to_port": 48080 }
        ]));
        let args = if let EgressMode::Hook(args) = &config.add_egress[0].egress_mode {
            args.clone()
        } else {
            panic!("expected hook mode")
        };
        let mut alloc = PortAllocator::new();
        let result = TngExec::build_resolved_entries(&args, 49152, &mut alloc);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already claimed"));
    }

    #[test]
    fn test_build_resolved_entries_reuses_used_set() {
        // Simulate multiple egress entries sharing a PortAllocator.
        // Second entry's auto-allocated ports should not collide with first's.
        let config1 = make_hook_config(json!([{ "port": 8080 }]));
        let args1 = if let EgressMode::Hook(args) = &config1.add_egress[0].egress_mode {
            args.clone()
        } else {
            panic!("expected hook mode")
        };
        let mut alloc = PortAllocator::new();
        let (entries1, _) = TngExec::build_resolved_entries(&args1, 49152, &mut alloc).unwrap();
        assert_eq!(entries1.len(), 1);

        let config2 = make_hook_config(json!([{ "port": 9090 }]));
        let args2 = if let EgressMode::Hook(args) = &config2.add_egress[0].egress_mode {
            args.clone()
        } else {
            panic!("expected hook mode")
        };
        let (entries2, _) = TngExec::build_resolved_entries(&args2, 49152, &mut alloc).unwrap();
        assert_eq!(entries2.len(), 1);

        // The second entry's real port must differ from the first's
        assert_ne!(entries1[0].real_port, entries2[0].real_port);
        assert_eq!(alloc.used.len(), 2);
    }

    #[test]
    fn test_validate_ingress_hook_only() {
        // Config with only ingress hook mode (no egress) should pass validation
        let config: TngConfig = serde_json::from_value(json!({
            "add_ingress": [{
                "hook": {
                    "capture_dst": [{ "port": 80 }]
                },
                "attest": {
                    "no_ra": true,
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }]
        }))
        .unwrap();
        let result = TngExec::validate_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_ingress_hook_empty_capture_dst() {
        // Ingress hook with empty capture_dst should fail validation
        let config: TngConfig = serde_json::from_value(json!({
            "add_ingress": [{
                "hook": {
                    "capture_dst": []
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
        assert!(result.unwrap_err().to_string().contains("capture_dst"));
    }

    #[test]
    fn test_build_ingress_proxy_auto_alloc() {
        let mut args: IngressHookArgs = serde_json::from_value(json!({
            "capture_dst": [
                { "host": "10.0.0.0/24", "port": 80 },
                { "host": "10.0.0.0/24", "port": 443 }
            ]
        }))
        .unwrap();
        let mut alloc = PortAllocator::new();
        let proxy = TngExec::build_ingress_proxy(0, &mut args, &mut alloc).unwrap();
        assert!(proxy.proxy_port > 0);
        assert_eq!(proxy.capture_rules.len(), 2);
        assert_eq!(proxy.capture_rules[0].host_cidr, "10.0.0.0/24");
        assert_eq!(proxy.capture_rules[0].port, 80);
        assert_eq!(proxy.capture_rules[1].port, 443);
        // Verify the port was written back to args
        assert_eq!(args.proxy_port, Some(proxy.proxy_port));
        assert_eq!(alloc.used.len(), 1);
    }

    #[test]
    fn test_build_ingress_proxy_explicit_port() {
        let mut args: IngressHookArgs = serde_json::from_value(json!({
            "capture_dst": [{ "port": 80 }],
            "proxy_port": 49001
        }))
        .unwrap();
        let mut alloc = PortAllocator::new();
        let proxy = TngExec::build_ingress_proxy(0, &mut args, &mut alloc).unwrap();
        assert_eq!(proxy.proxy_port, 49001);
        assert_eq!(proxy.capture_rules.len(), 1);
    }

    #[test]
    fn test_egress_ingress_no_collision_shared_allocator() {
        // Egress auto-allocates a port, then ingress auto-allocates.
        // They must not collide because they share the same PortAllocator.
        let config = make_hook_config(json!([{ "port": 8080 }]));
        let args = if let EgressMode::Hook(args) = &config.add_egress[0].egress_mode {
            args.clone()
        } else {
            panic!("expected hook mode")
        };
        let mut alloc = PortAllocator::new();
        let (entries, _) = TngExec::build_resolved_entries(&args, 49152, &mut alloc).unwrap();
        let egress_port = entries[0].real_port;

        let mut ingress_args: IngressHookArgs = serde_json::from_value(json!({
            "capture_dst": [{ "port": 5600 }]
        }))
        .unwrap();
        let proxy = TngExec::build_ingress_proxy(0, &mut ingress_args, &mut alloc).unwrap();

        assert_ne!(proxy.proxy_port, egress_port);
        assert_eq!(alloc.used.len(), 2);
    }

    #[test]
    fn test_explicit_ingress_proxy_port_collision() {
        // If the user explicitly sets proxy_port to a value already claimed
        // by egress, the collision should be detected at build time.
        let config = make_hook_config(json!([{ "port": 8080 }]));
        let args = if let EgressMode::Hook(args) = &config.add_egress[0].egress_mode {
            args.clone()
        } else {
            panic!("expected hook mode")
        };
        let mut alloc = PortAllocator::new();
        let (entries, _) = TngExec::build_resolved_entries(&args, 49152, &mut alloc).unwrap();
        let claimed_port = entries[0].real_port;

        let mut ingress_args: IngressHookArgs = serde_json::from_value(json!({
            "capture_dst": [{ "port": 5600 }],
            "proxy_port": claimed_port
        }))
        .unwrap();
        let result = TngExec::build_ingress_proxy(0, &mut ingress_args, &mut alloc);
        assert!(result.is_err(), "expected error, got: {:?}", result.ok());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("already claimed"));
    }
}

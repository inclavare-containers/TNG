use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Port mapping table distributed from TNG parent to the hook library via env var.
///
/// Serialized as JSON and passed via `TNG_HOOK_EGRESS_MAPPINGS` environment variable.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EgressHookMappingTable {
    pub entries: Vec<EgressHookMappingEntry>,
}

/// A single port mapping entry: when the server binds to origin_port,
/// redirect it to real_port instead. Host IP is NOT checked at bind time —
/// all binds to the origin port are intercepted. Host filtering happens
/// at accept time in the TNG runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressHookMappingEntry {
    /// The port the server thinks it's binding to
    pub origin_port: u16,
    /// The actual port the server binds to (redirected by the hook)
    pub real_port: u16,
}

/// Internal lookup tables built from EgressHookMappingTable.
///
/// Built once at library init time, read-only thereafter.
/// No Mutex needed — HashMap reads are thread-safe after construction.
pub struct EgressHookMappingLookup {
    /// origin_port -> real_port (for bind intercept)
    forward: HashMap<u16, u16>,
    /// real_port -> origin_port (for getsockname rewrite)
    reverse: HashMap<u16, u16>,
}

impl EgressHookMappingLookup {
    /// Build the forward and reverse lookup tables from a deserialized
    /// `EgressHookMappingTable`. Each entry produces one forward mapping
    /// (origin_port -> real_port) and one reverse mapping
    /// (real_port -> origin_port).
    pub fn from_table(table: &EgressHookMappingTable) -> Self {
        let mut forward = HashMap::new();
        let mut reverse = HashMap::new();

        for entry in &table.entries {
            forward.insert(entry.origin_port, entry.real_port);
            reverse.insert(entry.real_port, entry.origin_port);
        }

        Self { forward, reverse }
    }

    /// Look up the real port for a given origin port.
    pub fn lookup_forward(&self, port: u16) -> Option<u16> {
        self.forward.get(&port).copied()
    }

    /// Look up the origin port for a given real port.
    pub fn lookup_reverse(&self, port: u16) -> Option<u16> {
        self.reverse.get(&port).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_forward_exact() {
        let table = EgressHookMappingTable {
            entries: vec![EgressHookMappingEntry {
                origin_port: 8080,
                real_port: 48080,
            }],
        };
        let lookup = EgressHookMappingLookup::from_table(&table);
        assert_eq!(lookup.lookup_forward(8080), Some(48080));
    }

    #[test]
    fn test_lookup_forward_no_match() {
        let table = EgressHookMappingTable {
            entries: vec![EgressHookMappingEntry {
                origin_port: 8080,
                real_port: 48080,
            }],
        };
        let lookup = EgressHookMappingLookup::from_table(&table);
        assert!(lookup.lookup_forward(9090).is_none());
    }

    #[test]
    fn test_lookup_reverse() {
        let table = EgressHookMappingTable {
            entries: vec![EgressHookMappingEntry {
                origin_port: 8080,
                real_port: 48080,
            }],
        };
        let lookup = EgressHookMappingLookup::from_table(&table);
        assert_eq!(lookup.lookup_reverse(48080), Some(8080));
    }

    #[test]
    fn test_json_roundtrip() {
        let table = EgressHookMappingTable {
            entries: vec![
                EgressHookMappingEntry {
                    origin_port: 30001,
                    real_port: 40001,
                },
                EgressHookMappingEntry {
                    origin_port: 30002,
                    real_port: 40002,
                },
            ],
        };
        let json = serde_json::to_string(&table).unwrap();
        let parsed: EgressHookMappingTable = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].origin_port, 30001);
    }
}

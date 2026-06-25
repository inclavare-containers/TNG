use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};

use serde::{Deserialize, Serialize};

/// Port mapping table distributed from TNG parent to the hook library via env var.
///
/// Serialized as JSON and passed via `TNG_HOOK_EGRESS_MAPPINGS` environment variable.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EgressHookMappingTable {
    pub entries: Vec<EgressHookMappingEntry>,
}

/// A single port mapping entry: when the server binds to (host, origin_port),
/// redirect it to real_port instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressHookMappingEntry {
    /// Bind address (e.g. "0.0.0.0", "192.168.1.1")
    pub host: Ipv4Addr,
    /// The port the server thinks it's binding to
    pub origin_port: u16,
    /// The actual ports the server binds to
    pub real_port: u16,
}

/// Internal lookup tables built from EgressHookMappingTable.
///
/// Built once at library init time, read-only thereafter.
/// No Mutex needed — HashMap reads are thread-safe after construction.
pub struct EgressHookMappingLookup {
    /// origin SocketAddrV4 -> real_port (for bind intercept)
    forward: HashMap<SocketAddrV4, u16>,
    /// real SocketAddrV4 -> origin_port (for getsockname rewrite)
    reverse: HashMap<SocketAddrV4, u16>,
}

impl EgressHookMappingLookup {
    /// Build the forward and reverse lookup tables from a deserialized
    /// `EgressHookMappingTable`. Each entry produces one forward mapping
    /// (origin address -> real port) and one reverse mapping
    /// (real address -> origin port).
    pub fn from_table(table: &EgressHookMappingTable) -> Self {
        let mut forward = HashMap::new();
        let mut reverse = HashMap::new();

        for entry in &table.entries {
            let origin_addr = SocketAddrV4::new(entry.host, entry.origin_port);
            let real_addr = SocketAddrV4::new(entry.host, entry.real_port);
            forward.insert(origin_addr, entry.real_port);
            reverse.insert(real_addr, entry.origin_port);
        }

        Self { forward, reverse }
    }

    /// Look up the real port for a given origin address.
    /// First tries exact match, then falls back to wildcard (0.0.0.0).
    pub fn lookup_forward(&self, addr: SocketAddrV4) -> Option<u16> {
        self.forward.get(&addr).copied().or_else(|| {
            let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, addr.port());
            self.forward.get(&wildcard).copied()
        })
    }

    /// Look up the origin port for a given real address.
    /// First tries exact match, then falls back to wildcard (0.0.0.0).
    pub fn lookup_reverse(&self, addr: SocketAddrV4) -> Option<u16> {
        self.reverse.get(&addr).copied().or_else(|| {
            let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, addr.port());
            self.reverse.get(&wildcard).copied()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_forward_exact() {
        let table = EgressHookMappingTable {
            entries: vec![EgressHookMappingEntry {
                host: Ipv4Addr::new(192, 168, 1, 1),
                origin_port: 8080,
                real_port: 48080,
            }],
        };
        let lookup = EgressHookMappingLookup::from_table(&table);
        assert_eq!(
            lookup.lookup_forward(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 8080)),
            Some(48080)
        );
    }

    #[test]
    fn test_lookup_forward_wildcard_fallback() {
        let table = EgressHookMappingTable {
            entries: vec![EgressHookMappingEntry {
                host: Ipv4Addr::UNSPECIFIED,
                origin_port: 8080,
                real_port: 48080,
            }],
        };
        let lookup = EgressHookMappingLookup::from_table(&table);
        // Any IP should match the wildcard
        assert_eq!(
            lookup.lookup_forward(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080)),
            Some(48080)
        );
    }

    #[test]
    fn test_lookup_forward_no_match() {
        let table = EgressHookMappingTable {
            entries: vec![EgressHookMappingEntry {
                host: Ipv4Addr::new(192, 168, 1, 1),
                origin_port: 8080,
                real_port: 48080,
            }],
        };
        let lookup = EgressHookMappingLookup::from_table(&table);
        assert!(lookup
            .lookup_forward(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080))
            .is_none());
    }

    #[test]
    fn test_lookup_reverse() {
        let table = EgressHookMappingTable {
            entries: vec![EgressHookMappingEntry {
                host: Ipv4Addr::UNSPECIFIED,
                origin_port: 8080,
                real_port: 48080,
            }],
        };
        let lookup = EgressHookMappingLookup::from_table(&table);
        assert_eq!(
            lookup.lookup_reverse(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 48080)),
            Some(8080)
        );
    }

    #[test]
    fn test_lookup_reverse_specific_ip() {
        let table = EgressHookMappingTable {
            entries: vec![EgressHookMappingEntry {
                host: Ipv4Addr::new(192, 168, 1, 1),
                origin_port: 8080,
                real_port: 48080,
            }],
        };
        let lookup = EgressHookMappingLookup::from_table(&table);
        assert_eq!(
            lookup.lookup_reverse(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 48080)),
            Some(8080)
        );
        // Should not match a different IP (no wildcard fallback for this entry)
        assert!(lookup
            .lookup_reverse(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 48080))
            .is_none());
    }

    #[test]
    fn test_json_roundtrip() {
        let table = EgressHookMappingTable {
            entries: vec![
                EgressHookMappingEntry {
                    host: Ipv4Addr::UNSPECIFIED,
                    origin_port: 30001,
                    real_port: 40001,
                },
                EgressHookMappingEntry {
                    host: Ipv4Addr::new(192, 168, 1, 1),
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

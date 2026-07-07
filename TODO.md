# TODO: Clarify IP / CIDR / Domain

## Pending: Config `host` field naming consistency

**Context:** Across the TNG JSON config, the field name `host` is used with different
semantic meanings:

| Config location | Type | Actual meaning |
|-----------------|------|----------------|
| `netfilter.capture_dst[].host` | `Option<Ipv4Cidr>` | Target IP/CIDR to capture (filter condition) |
| `hook.capture_dst[].host` | `Option<Ipv4Cidr>` | Target IP/CIDR to capture (filter condition) |
| `egress hook.capture_listen[].host` | `Option<Ipv4Addr>` | Bind address to match |
| `mapping.rules[].in.host` | `Option<String>` → being changed to `Option<Ipv4Addr>` | Listen address |
| `mapping.rules[].out.host` | `Option<String>` → being changed to `Option<Ipv4Addr>` | Target forward address |
| `Endpoint.host` (admin_bind etc.) | `Option<String>` | Listen/bind address |
| `PeerSharedArgs.host` | `String` | Listen address |

**Why not fix now:** Renaming these fields (e.g. `host` → `ip`/`bind_addr`/`target_addr`)
would be a **breaking JSON config change** for every existing deployment. The serialization
format is part of the public API and subject to the version compatibility policy
(`docs/version_compatibility.md`).

**Proposed approach (future):** Introduce distinct field names per semantic domain
(e.g. `bind_addr` for listen endpoints, `target_addr` for forward destinations,
`capture_ip` / `capture_cidr` for netfilter/hook filters), add them alongside the old
`host` field with deprecation warnings, and remove `host` after a grace period.

**Related:** See the IP/CIDR/Domain type clarification work on branch
`clarify_ip_or_cidr_or_domain` — that branch fixes the *type-level* inconsistencies
(`String` vs `Ipv4Cidr` vs `Ipv4Addr`) but deliberately does NOT rename the `host` field
itself to preserve backward compatibility.

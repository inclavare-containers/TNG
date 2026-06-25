# tng-hook

LD_PRELOAD-based egress hook library for TNG. Intercepts server application `bind()` and `getsockname()` syscalls to transparently redirect listening ports through encrypted tunnels — zero application modification required.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  tng exec --config-file=/etc/tng.json -- vllm serve ...       │
│                                                              │
│  Child process                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  LD_PRELOAD=libtng_hook.so                             │  │
│  │  TNG_HOOK_MAPPINGS=<json>                              │  │
│  │                                                        │  │
│  │  Application calls bind(0.0.0.0:8080)                  │  │
│  │       ↓                                                 │  │
│  │  libtng_hook.so intercepts bind()                      │  │
│  │  Looks up 0.0.0.0:8080 → real_port 48080               │  │
│  │  Calls real bind(0.0.0.0:48080)                        │  │
│  │       ↓                                                 │  │
│  │  Application calls getsockname()                        │  │
│  │  libtng_hook.so rewrites 48080 → 8080                  │  │
│  │  Application sees port 8080 (disguised)                │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  TNG parent binds 0.0.0.0:8080 for tunnel traffic            │
│  Forwards decrypted traffic to 127.0.0.1:48080               │
└──────────────────────────────────────────────────────────────┘
```

## How It Works

### Mapping Distribution

TNG serializes a port mapping table to JSON and passes it via the `TNG_HOOK_MAPPINGS` environment variable:

```json
{"entries":[{"host":"0.0.0.0","origin_port":8080,"real_port":48080}]}
```

Each entry means: when the application calls `bind(host:origin_port)`, redirect it to `host:real_port`. TNG listens on `origin_port` to receive tunnel traffic, then forwards decrypted connections to `real_port`.

The `.so` deserializes this at `#[ctor]` init time (before `main()`) and builds two HashMaps:
- **forward**: `SocketAddrV4(origin) → real_port` (used in `bind()` interception)
- **reverse**: `SocketAddrV4(real) → origin_port` (used in `getsockname()` rewrite)

### Interception Points

#### `bind(sockfd, addr, addrlen)`

1. Checks if the address is `AF_INET` (IPv4 only)
2. Looks up `(ip, port)` in the forward map (exact match first, then wildcard `0.0.0.0` fallback)
3. If found: rewrites `sin_port` to `real_port`, calls real `bind()` with the modified address
4. If not found: passes through to real `bind()` unchanged

#### `getsockname(sockfd, addr, addrlen)`

1. Calls real `getsockname()` first
2. Looks up the returned `(ip, port)` in the reverse map
3. If found: rewrites `sin_port` back to `origin_port` (maintains the illusion that the server is on the original port)
4. If not found: returns unchanged

### Real Function Resolution

Uses `dlopen("libc.so.6")` + `dlsym()` to resolve real `bind` and `getsockname` — **not** `dlsym(RTLD_NEXT)`, which would return our own hooked function when we are the first library in the LD_PRELOAD chain.

### Thread Safety

The lookup HashMaps are built once at init time and never mutated. `HashMap` read access is thread-safe after construction — no `Mutex` needed.

### Fork Handling

After `fork()`, the child inherits the `.so` mapping table (copied via fork's memory semantics), environment variables, and existing file descriptors. No special handling needed.

## Project Structure

```
tng-hook/
├── types/              # tng-hook-types: shared struct definitions
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs      # HookMappingTable, HookMappingEntry, HookMappingLookup
└── cdylib/             # tng-hook-cdylib: the .so library
    ├── Cargo.toml
    └── src/
        └── lib.rs      # bind/getsockname interception, #[ctor] init
```

- **`tng-hook-types`** — Pure data types with serde serialization. No syscalls, no unsafe code. Used by both `tng` (for config) and the `.so`.
- **`tng-hook-cdylib`** — The actual LD_PRELOAD library (`libtng_hook.so`). Depends on `tng-hook-types` for shared types.

## Building

```bash
# Build the .so library
cargo build -p tng-hook-cdylib

# Build in release mode
cargo build --release -p tng-hook-cdylib

# Build and run type tests
cargo test -p tng-hook-types
```

The output is `target/debug/libtng_hook.so` (or `target/release/libtng_hook.so`).

## Usage

Run through `tng exec`:

```bash
tng exec --config-file=/etc/tng.json -- your-server --port 8080
```

`tng exec` handles everything:
1. Parses config, validates hook mode
2. Builds mapping table, auto-allocates real ports
3. Starts TNG tunnel listeners on origin ports
4. Spawns child with `LD_PRELOAD` and `TNG_HOOK_MAPPINGS` set

### Manual invocation (for debugging)

```bash
LD_PRELOAD=/path/to/libtng_hook.so \
TNG_HOOK_MAPPINGS='{"entries":[{"host":"0.0.0.0","origin_port":8080,"real_port":48080}]}' \
your-server --port 8080
```

## Logging

The `.so` initializes its own tracing subscriber writing to stderr at init time. Log level is controlled by `RUST_LOG`:

```bash
# Default: info level
RUST_LOG=info LD_PRELOAD=... your-server

# Debug: see all interception details
RUST_LOG=debug LD_PRELOAD=... your-server
```

**Bind interception log** (info level):
```
bind hijacked: 0.0.0.0:8080 → 0.0.0.0:48080
```

## Troubleshooting

### "libtng_hook.so not found"

TNG searches:
1. `$TNG_HOOK_LIB` — explicit override
2. Same directory as the `tng` binary
3. `/usr/lib/tng/libtng_hook.so` — system install

Set `TNG_HOOK_LIB=/path/to/libtng_hook.so` to specify a custom location.

### Port already in use

The real port (e.g., `48080`) is already occupied by another process. Check with `ss -tlnp | grep 48080`. Solutions:
- Use `redirect_to_port` in config to pick a different real port
- TNG auto-allocates ports via `portpicker` when `redirect_to_port` is not specified

### Connection refused on origin port

TNG tunnel listener failed to bind the origin port. Check if another process is already listening: `ss -tlnp | grep 8080`.

### getsockname returns wrong port

The reverse mapping may not cover the address returned by `getsockname()`. Check the `TNG_HOOK_MAPPINGS` env var:
```bash
echo $TNG_HOOK_MAPPINGS | python3 -m json.tool
```
Ensure `host` and `real_port` match what the application is actually binding to.

### Application crashes after bind intercept

Only `AF_INET` (IPv4) is supported. If the application uses IPv6 (`AF_INET6`), it passes through unchanged. Check the application logs for IPv6 binding attempts.

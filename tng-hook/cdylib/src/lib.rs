use std::io::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::os::raw::c_void;
use std::sync::{Arc, OnceLock};

use libc::{c_int, size_t, sockaddr, socklen_t, ssize_t};
use tng_hook_types::{
    EgressHookMappingLookup, EgressHookMappingTable, IngressHookLookup, IngressHookMappingTable,
    LevelRoutingWriter,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

/// Resolved real `bind` function pointer.
type BindFn = unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;

/// Resolved real `getsockname` function pointer.
type GetsocknameFn = unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t) -> c_int;

static REAL_BIND: OnceLock<BindFn> = OnceLock::new();
static REAL_GETSOCKNAME: OnceLock<GetsocknameFn> = OnceLock::new();

/// Resolved real `connect` function pointer.
type ConnectFn = unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;

static REAL_CONNECT: OnceLock<ConnectFn> = OnceLock::new();

/// Resolved real `sendto` function pointer.
type SendtoFn = unsafe extern "C" fn(
    c_int,
    *const c_void,
    size_t,
    c_int,
    *const sockaddr,
    socklen_t,
) -> ssize_t;

static REAL_SENDTO: OnceLock<SendtoFn> = OnceLock::new();

/// Holds the hook's rolling appender so the `#[ctor::dtor]` below can flush
/// its BufWriter on process exit. Rust statics (incl. the global subscriber
/// that owns the appender) are not dropped on exit, so without an explicit
/// flush the last buffered log lines would be lost. Only set when rolling is
/// enabled and a log file is configured.
static HOOK_ROLLING_APPENDER: OnceLock<
    Arc<std::sync::Mutex<tracing_rolling_file::RollingFileAppenderBase>>,
> = OnceLock::new();

/// Holds the hook's rolling ERROR appender (separate file for ERROR+ events
/// when `TNG_HOOK_LOG_ERROR_FILE` is injected by `tng exec`). Same flush-on-exit
/// rationale as `HOOK_ROLLING_APPENDER`. Only set when rolling is enabled AND
/// an error file path is configured.
static HOOK_ROLLING_ERROR_APPENDER: OnceLock<
    Arc<std::sync::Mutex<tracing_rolling_file::RollingFileAppenderBase>>,
> = OnceLock::new();

static INGRESS_LOOKUP: OnceLock<IngressHookLookup> = OnceLock::new();

/// Global mapping lookup table, initialized once from env var at library load.
static LOOKUP: OnceLock<EgressHookMappingLookup> = OnceLock::new();

/// Resolve a function pointer from libc via dlsym.
///
/// We explicitly `dlopen("libc.so.6")` to get the real libc functions,
/// because `dlsym(RTLD_NEXT, ...)` would return our own hooked function
/// when we are the first library in the LD_PRELOAD chain.
///
/// # Safety
/// Caller must ensure the function signature matches the actual symbol.
unsafe fn resolve_libc_symbol<T>(name: &str) -> Option<T> {
    let libc_path = c"libc.so.6";
    let handle = libc::dlopen(libc_path.as_ptr(), libc::RTLD_LAZY);
    if handle.is_null() {
        return None;
    }

    let name_cstr = std::ffi::CString::new(name).ok()?;
    let sym = libc::dlsym(handle, name_cstr.as_ptr());
    if sym.is_null() {
        None
    } else {
        Some(std::mem::transmute_copy(&sym))
    }
}

/// A `MakeWriter` over a shared `Arc<Mutex<RollingFileAppenderBase>>`.
///
/// The appender must be shared between the fmt layer (which writes) and the
/// `#[ctor::dtor]` (which flushes on exit). `Arc<Mutex<..>>` cannot be used
/// directly as a `MakeWriter`: tracing-subscriber's blanket `impl MakeWriter
/// for Arc<W>` does not satisfy the `for<'a> MakeWriter<'a>` HRTB. So we wrap
/// it and implement `MakeWriter` directly, delegating each write to the inner
/// `Mutex` (same `MutexGuardWriter`-equivalent path the plain `Mutex<W>` uses).
struct SharedRollingWriter(Arc<std::sync::Mutex<tracing_rolling_file::RollingFileAppenderBase>>);

/// A write handle that locks the shared appender for the duration of a write.
struct SharedRollingWriterGuard<'a>(
    std::sync::MutexGuard<'a, tracing_rolling_file::RollingFileAppenderBase>,
);

impl std::io::Write for SharedRollingWriterGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.0.write_all(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedRollingWriter {
    type Writer = SharedRollingWriterGuard<'a>;
    fn make_writer(&'a self) -> Self::Writer {
        SharedRollingWriterGuard(self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

/// Build the tracing fmt layer (json or text) as a boxed trait object.
///
/// Shared by the file and stderr branches so the json/text choice is not
/// duplicated. `with_writer` requires `W: for<'writer> MakeWriter<'writer> +
/// 'static`; `Send + Sync` is added so the resulting layer can be boxed to
/// `Box<dyn Layer<Registry> + Send + Sync>`.
fn build_log_layer<W>(
    format: tng_hook_types::LogFormat,
    writer: W,
    ansi: bool,
    filter: tracing_subscriber::EnvFilter,
) -> Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>
where
    W: for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> + Send + Sync + 'static,
{
    match format {
        tng_hook_types::LogFormat::Json => Box::new(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(writer)
                .with_ansi(false)
                .with_filter(filter),
        ),
        tng_hook_types::LogFormat::Text => Box::new(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_ansi(ansi)
                .with_filter(filter),
        ),
    }
}

/// Build a `SharedRollingWriter` for the given base log path, deriving the
/// PID-collision-free path via `hook_log_path`, constructing the rolling
/// appender, and stashing its `Arc<Mutex<..>>` clone in the provided global
/// `OnceLock` so the `#[ctor::dtor]` can flush the BufWriter on exit. Used for
/// both the info writer (`HOOK_ROLLING_APPENDER`) and the error writer
/// (`HOOK_ROLLING_ERROR_APPENDER`).
fn make_rolling_writer(
    base_path: &str,
    global: &'static OnceLock<Arc<std::sync::Mutex<tracing_rolling_file::RollingFileAppenderBase>>>,
    rolling: tng_hook_types::RollingConfig,
) -> SharedRollingWriter {
    let derived =
        tng_hook_types::hook_log_path(std::path::Path::new(base_path), std::process::id());
    let appender = tracing_rolling_file::RollingFileAppenderBase::new(
        derived,
        tracing_rolling_file::RollingConditionBase::new().max_size(rolling.max_size),
        rolling.max_backups,
    )
    .unwrap_or_else(|e| panic!("tng-hook: failed to open rolling log file {base_path:?}: {e}"));
    // One Arc clone goes to SharedRollingWriter (the fmt layer's MakeWriter),
    // one is stashed in the global so the dtor can flush on exit.
    let writer = Arc::new(std::sync::Mutex::new(appender));
    let _ = global.set(writer.clone());
    SharedRollingWriter(writer)
}

/// Destructor: flush the hook's rolling appender's BufWriter when the `.so`
/// is unloaded at process exit. Rust statics (incl. the global subscriber that
/// owns the appender) are not dropped on exit, so without this the last ~8 KiB
/// of buffered logs would never reach the file. Runs on normal exit / `exit()`;
/// not on SIGKILL. Poison is tolerated (a panicked holder still leaves the
/// appender flushable) via `into_inner`. Flushes BOTH the info appender and
/// the error appender (when `TNG_HOOK_LOG_ERROR_FILE` is configured).
#[ctor::dtor]
fn flush_rolling_appender_on_exit() {
    if let Some(appender) = HOOK_ROLLING_APPENDER.get() {
        let mut guard = appender.lock().unwrap_or_else(|e| e.into_inner());
        let _ = guard.flush();
    }
    if let Some(appender) = HOOK_ROLLING_ERROR_APPENDER.get() {
        let mut guard = appender.lock().unwrap_or_else(|e| e.into_inner());
        let _ = guard.flush();
    }
}

/// Initialize the library at load time.
///
/// This is called once when the `.so` is loaded (before main).
/// It resolves the real `bind`/`getsockname` via dlsym and builds
/// the mapping lookup table from the `TNG_HOOK_EGRESS_MAPPINGS` env var.
#[ctor::ctor]
fn init() {
    // Initialize tracing subscriber based on TNG_HOOK_LOG_FILE env var.
    // When set, write to the specified file; otherwise fall back to stderr.
    // Uses `set_default` so it won't panic if the host already has a subscriber.
    let log_file_path = std::env::var("TNG_HOOK_LOG_FILE").ok();

    let log_format: tng_hook_types::LogFormat = std::env::var("TNG_HOOK_LOG_FORMAT")
        .or_else(|_| std::env::var("TNG_LOG_FORMAT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(tng_hook_types::LogFormat::Text);
    let rolling = tng_hook_types::RollingConfig::from_hook_env();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    // Optional separate error log file (injected by `tng exec` when the user
    // passes --log-error-file). When set, ERROR+ events go to the error writer
    // and everything else to the info writer (disjoint — see LevelRoutingWriter).
    // Only meaningful when an info log file is also configured.
    let error_file_path = std::env::var("TNG_HOOK_LOG_ERROR_FILE").ok();
    let layer: Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync> =
        if let Some(ref path) = log_file_path {
            // When rolling is on, the hook writes its OWN file (pid-derived,
            // collision-free with the parent's base.N backups) and rolls it
            // independently — no shared file, no stale fd. When rolling is off,
            // share the parent's file (concurrent append, current behavior).
            if rolling.enabled {
                let info_writer = make_rolling_writer(path, &HOOK_ROLLING_APPENDER, rolling);
                let layer_writer = if let Some(ref epath) = error_file_path {
                    let error_writer =
                        make_rolling_writer(epath, &HOOK_ROLLING_ERROR_APPENDER, rolling);
                    LevelRoutingWriter::new(info_writer, Some(error_writer))
                } else {
                    LevelRoutingWriter::new(info_writer, None::<SharedRollingWriter>)
                };
                build_log_layer(log_format, layer_writer, false, filter)
            } else {
                let info_file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .unwrap_or_else(|e| panic!("tng-hook: failed to open log file {path:?}: {e}"));
                let info_writer = std::sync::Mutex::new(info_file);
                let layer_writer = if let Some(ref epath) = error_file_path {
                    let error_file = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(epath)
                        .unwrap_or_else(|e| {
                            panic!("tng-hook: failed to open error log file {epath:?}: {e}")
                        });
                    let error_writer = std::sync::Mutex::new(error_file);
                    LevelRoutingWriter::new(info_writer, Some(error_writer))
                } else {
                    LevelRoutingWriter::new(info_writer, None::<std::sync::Mutex<std::fs::File>>)
                };
                build_log_layer(log_format, layer_writer, false, filter)
            }
        } else {
            build_log_layer(
                log_format,
                std::sync::Mutex::new(std::io::stderr()),
                atty::is(atty::Stream::Stderr),
                filter,
            )
        };
    tracing_subscriber::registry().with(layer).init();

    // Resolve real functions directly from libc
    unsafe {
        let real_bind = resolve_libc_symbol::<BindFn>("bind").expect("Failed to resolve libc bind");
        tracing::debug!("init: resolved libc bind");
        let _ = REAL_BIND.set(real_bind);

        let real_getsockname = resolve_libc_symbol::<GetsocknameFn>("getsockname")
            .expect("Failed to resolve libc getsockname");
        tracing::debug!("init: resolved libc getsockname");
        let _ = REAL_GETSOCKNAME.set(real_getsockname);

        let real_connect =
            resolve_libc_symbol::<ConnectFn>("connect").expect("Failed to resolve libc connect");
        tracing::debug!("init: resolved libc connect");
        let _ = REAL_CONNECT.set(real_connect);

        let real_sendto =
            resolve_libc_symbol::<SendtoFn>("sendto").expect("Failed to resolve libc sendto");
        tracing::debug!("init: resolved libc sendto");
        let _ = REAL_SENDTO.set(real_sendto);
    }

    // Build egress lookup from env var
    match std::env::var("TNG_HOOK_EGRESS_MAPPINGS") {
        Ok(json) if !json.is_empty() => {
            let truncated = if json.len() > 512 {
                format!("{}...<{} bytes total>", &json[..512], json.len())
            } else {
                json.clone()
            };
            tracing::debug!("init: TNG_HOOK_EGRESS_MAPPINGS={}", truncated);
            match serde_json::from_str::<EgressHookMappingTable>(&json) {
                Ok(table) => {
                    let entries = table.entries.len();
                    let lookup = EgressHookMappingLookup::from_table(&table);
                    let _ = LOOKUP.set(lookup);
                    tracing::debug!("init: egress mapping loaded with {} entries", entries);
                    tracing::trace!("init: egress mapping table: {:#?}", table);
                }
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "init: failed to parse TNG_HOOK_EGRESS_MAPPINGS JSON"
                    );
                }
            }
        }
        Ok(_) => {
            tracing::warn!("init: TNG_HOOK_EGRESS_MAPPINGS is set but empty");
        }
        Err(_) => {
            tracing::debug!("init: TNG_HOOK_EGRESS_MAPPINGS not set (egress hook disabled)");
        }
    }

    // Build ingress lookup from env var
    match std::env::var("TNG_HOOK_INGRESS_MAPPINGS") {
        Ok(json) if !json.is_empty() => {
            let truncated = if json.len() > 512 {
                format!("{}...<{} bytes total>", &json[..512], json.len())
            } else {
                json.clone()
            };
            tracing::debug!("init: TNG_HOOK_INGRESS_MAPPINGS={}", truncated);
            match serde_json::from_str::<IngressHookMappingTable>(&json) {
                Ok(table) => {
                    let entries: usize =
                        table.ingresses.iter().map(|p| p.capture_rules.len()).sum();
                    let lookup = IngressHookLookup::from_table(&table);
                    let _ = INGRESS_LOOKUP.set(lookup);
                    tracing::debug!("init: ingress mapping loaded with {} entries", entries);
                    tracing::trace!("init: ingress mapping table: {:#?}", table);
                }
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "init: failed to parse TNG_HOOK_INGRESS_MAPPINGS JSON"
                    );
                }
            }
        }
        Ok(_) => {
            tracing::warn!("init: TNG_HOOK_INGRESS_MAPPINGS is set but empty");
        }
        Err(_) => {
            tracing::debug!("init: TNG_HOOK_INGRESS_MAPPINGS not set (ingress hook disabled)");
        }
    }

    tracing::info!("tng-hook: initialized");
}

/// Convert a sockaddr pointer to SocketAddrV4 if it's AF_INET.
///
/// # Safety
/// Caller must ensure `addr` points to a valid sockaddr of at least `addrlen` bytes.
unsafe fn sockaddr_to_v4(addr: *const sockaddr) -> Option<SocketAddrV4> {
    if addr.is_null() {
        tracing::trace!("sockaddr_to_v4: null address");
        return None;
    }
    let sa = &*addr;
    if sa.sa_family != libc::AF_INET as u16 {
        tracing::trace!(
            "sockaddr_to_v4: family={:#x} (not AF_INET={:#x})",
            sa.sa_family,
            libc::AF_INET
        );
        return None;
    }
    let sin = &*(addr as *const libc::sockaddr_in);
    let port = u16::from_be(sin.sin_port);
    let addr_bytes = sin.sin_addr.s_addr.to_ne_bytes();
    let ip = Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);
    tracing::trace!(
        "sockaddr_to_v4: parsed {}:{} (family={:#x})",
        ip,
        port,
        sa.sa_family
    );
    Some(SocketAddrV4::new(ip, port))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectAddressFamily {
    Ipv4,
    Ipv4MappedIpv6,
}

unsafe fn sockaddr_to_connect_v4(
    addr: *const sockaddr,
) -> Option<(SocketAddrV4, ConnectAddressFamily)> {
    if addr.is_null() {
        return None;
    }

    let sa = &*addr;
    if sa.sa_family == libc::AF_INET as u16 {
        return sockaddr_to_v4(addr).map(|addr| (addr, ConnectAddressFamily::Ipv4));
    }
    if sa.sa_family != libc::AF_INET6 as u16 {
        return None;
    }

    let sin6 = &*(addr as *const libc::sockaddr_in6);
    let octets = sin6.sin6_addr.s6_addr;
    let mapped_ip = Ipv6Addr::from(octets).to_ipv4_mapped()?;
    let port = u16::from_be(sin6.sin6_port);
    Some((
        SocketAddrV4::new(mapped_ip, port),
        ConnectAddressFamily::Ipv4MappedIpv6,
    ))
}

/// Intercepted `bind()` — rewrite origin port to real port if mapped.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn bind(sockfd: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int {
    let real_bind = REAL_BIND.get().expect("REAL_BIND not initialized");

    // Only intercept AF_INET (IPv4)
    if let Some(origin_addr) = unsafe { sockaddr_to_v4(addr) } {
        if let Some(lookup) = LOOKUP.get() {
            if let Some(real_port) = lookup.lookup_forward(origin_addr.port()) {
                // Rewrite the port in-place
                let mut new_addr = unsafe { std::ptr::read(addr as *const libc::sockaddr_in) };
                new_addr.sin_port = real_port.to_be();
                let new_addrlen = std::mem::size_of::<libc::sockaddr_in>() as socklen_t;

                let ip = origin_addr.ip();
                let origin_port = origin_addr.port();
                tracing::info!(
                    "bind hijacked: {}:{} → {}:{}",
                    ip,
                    origin_port,
                    ip,
                    real_port
                );

                return unsafe {
                    real_bind(
                        sockfd,
                        &new_addr as *const _ as *const sockaddr,
                        new_addrlen,
                    )
                };
            }
        }
    } else if !addr.is_null() {
        let sa = unsafe { &*addr };
        tracing::debug!(
            "bind: non-IPv4 socket, family={:#x}, fd={}, passthrough",
            sa.sa_family,
            sockfd
        );
    }

    // No match — pass through to real bind
    tracing::debug!("bind: passthrough fd={}", sockfd);
    unsafe { real_bind(sockfd, addr, addrlen) }
}

/// Intercepted `getsockname()` — rewrite real port back to origin port.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn getsockname(
    sockfd: c_int,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t,
) -> c_int {
    let real_getsockname = REAL_GETSOCKNAME
        .get()
        .expect("REAL_GETSOCKNAME not initialized");

    // Call the real getsockname first
    let result = unsafe { real_getsockname(sockfd, addr, addrlen) };
    if result != 0 {
        return result;
    }

    // Check if the returned address is one we remapped
    if let Some(real_addr) = unsafe { sockaddr_to_v4(addr) } {
        if let Some(lookup) = LOOKUP.get() {
            if let Some(origin_port) = lookup.lookup_reverse(real_addr.port()) {
                // Rewrite the port back to origin
                let mut new_addr = unsafe { std::ptr::read(addr as *const libc::sockaddr_in) };
                new_addr.sin_port = origin_port.to_be();
                unsafe {
                    std::ptr::write(addr as *mut libc::sockaddr_in, new_addr);
                }
                tracing::debug!(
                    "getsockname: rewrote port {} → {} on fd={}",
                    real_addr.port(),
                    origin_port,
                    sockfd
                );
                return result;
            }
        }
    }

    tracing::trace!("getsockname: no rewrite needed, fd={}", sockfd);
    result
}

/// Intercepted `connect()` — route matched destinations through HTTP CONNECT proxy.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn connect(sockfd: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int {
    let real_connect = REAL_CONNECT.get().expect("REAL_CONNECT not initialized");

    // Only hijack TCP sockets (SOCK_STREAM).  UDP, RAW, etc. must pass through
    // to the real connect() — they don't speak HTTP CONNECT.
    let mut sock_type: libc::c_int = 0;
    let mut sock_type_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            sockfd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut sock_type as *mut _ as *mut libc::c_void,
            &mut sock_type_len,
        );
    }
    if sock_type != libc::SOCK_STREAM {
        tracing::debug!(
            "connect: fd={} is not SOCK_STREAM (type={}), passthrough",
            sockfd,
            sock_type
        );
        return unsafe { real_connect(sockfd, addr, addrlen) };
    }

    let Some((dst_addr, address_family)) = (unsafe { sockaddr_to_connect_v4(addr) }) else {
        if !addr.is_null() {
            let sa = unsafe { &*addr };
            tracing::debug!(
                "connect: non-IPv4 destination, family={:#x}, fd={}, passthrough",
                sa.sa_family,
                sockfd
            );
        }
        return unsafe { real_connect(sockfd, addr, addrlen) };
    };

    tracing::debug!(
        "connect: fd={} dst={}:{}",
        sockfd,
        dst_addr.ip(),
        dst_addr.port()
    );

    // Reject connections to 0.0.0.0 (NULL IP) early. Connecting to the
    // unspecified address is often an application bug and should not be
    // routed through the proxy. Mirrors proxychains-ng's behavior
    // (src/libproxychains.c:702-705).
    if *dst_addr.ip() == Ipv4Addr::UNSPECIFIED {
        tracing::debug!("connect: rejecting 0.0.0.0 (null IP)");
        unsafe {
            *libc::__errno_location() = libc::ECONNREFUSED;
        }
        return -1;
    }

    // Check if this destination matches any ingress capture rule
    let Some(lookup) = INGRESS_LOOKUP.get() else {
        tracing::debug!(
            "connect: no ingress mapping, passthrough {}:{}",
            dst_addr.ip(),
            dst_addr.port()
        );
        return unsafe { real_connect(sockfd, addr, addrlen) };
    };

    let Some(proxy_port) = lookup.find_proxy_port(dst_addr) else {
        // No match — pass through to real connect()
        tracing::debug!(
            "connect: no capture rule for {}:{}, passthrough",
            dst_addr.ip(),
            dst_addr.port()
        );
        return unsafe { real_connect(sockfd, addr, addrlen) };
    };

    tracing::info!(
        "connect hijacked: {}:{} → proxy 127.0.0.1:{}",
        dst_addr.ip(),
        dst_addr.port(),
        proxy_port
    );

    // Save socket flags and force the socket to blocking mode so that
    // real_connect waits for the TCP handshake to complete.  This avoids
    // EINPROGRESS handling entirely — the same approach used by
    // proxychains-ng (src/libproxychains.c:752-763).
    let saved_flags = unsafe { libc::fcntl(sockfd, libc::F_GETFL, 0) };
    if saved_flags < 0 {
        tracing::error!(
            "connect hijacked: failed to get socket flags for proxy 127.0.0.1:{}: {}",
            proxy_port,
            std::io::Error::last_os_error()
        );
        // Cannot safely save/restore flags — fall back to the original
        // destination instead of hijacking.
        return unsafe { real_connect(sockfd, addr, addrlen) };
    }

    unsafe {
        libc::fcntl(sockfd, libc::F_SETFL, saved_flags & !libc::O_NONBLOCK);
    }

    // Restore O_NONBLOCK on every exit path so the caller's socket state
    // is preserved after the blocking handshake completes.
    scopeguard::defer! {
        unsafe {
            libc::fcntl(sockfd, libc::F_SETFL, saved_flags);
        }
    }

    let ret = unsafe {
        match address_family {
            ConnectAddressFamily::Ipv4 => {
                let proxy_sockaddr =
                    make_sockaddr_v4(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, proxy_port));
                real_connect(
                    sockfd,
                    &proxy_sockaddr as *const _ as *const sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as socklen_t,
                )
            }
            ConnectAddressFamily::Ipv4MappedIpv6 => {
                let proxy_sockaddr = make_sockaddr_v6(&SocketAddrV6::new(
                    Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
                    proxy_port,
                    0,
                    0,
                ));
                real_connect(
                    sockfd,
                    &proxy_sockaddr as *const _ as *const sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as socklen_t,
                )
            }
        }
    };
    if ret != 0 {
        let errno = unsafe { *libc::__errno_location() };
        tracing::error!(
            "connect hijacked: failed to connect to proxy 127.0.0.1:{}: {}",
            proxy_port,
            std::io::Error::from_raw_os_error(errno)
        );
        return ret;
    }

    tracing::debug!("connect: connected to proxy 127.0.0.1:{}", proxy_port);

    // Set a receive timeout for the HTTP CONNECT handshake so that
    // a proxy that accepts the TCP connection but never responds
    // cannot block this thread indefinitely.
    // Save the original timeout first so we can restore it afterward.
    let mut orig_timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut orig_len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            sockfd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &mut orig_timeout as *mut _ as *mut libc::c_void,
            &mut orig_len,
        );
    }

    // Restore the original SO_RCVTIMEO on every exit path from this point.
    // Using scopeguard::defer! ensures the restore happens regardless of
    // which branch returns, eliminating duplicate setsockopt calls.
    let restore_timeout = orig_timeout;
    scopeguard::defer! {
        unsafe {
            libc::setsockopt(
                sockfd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &restore_timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
    }

    let timeout = libc::timeval {
        tv_sec: 10,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            sockfd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Send HTTP CONNECT request
    let connect_req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost:{}:{}\r\n\r\n",
        dst_addr.ip(),
        dst_addr.port(),
        dst_addr.ip(),
        dst_addr.port()
    );

    tracing::debug!(
        "connect: sending CONNECT for {}:{}",
        dst_addr.ip(),
        dst_addr.port()
    );

    if let Err(e) = send_all(sockfd, connect_req.as_bytes()) {
        tracing::error!(
            "connect hijacked: failed to send CONNECT request for {}:{}: {}",
            dst_addr.ip(),
            dst_addr.port(),
            e
        );
        unsafe {
            *libc::__errno_location() = libc::ECONNREFUSED;
        }
        return -1;
    }

    // Read HTTP response
    match read_http_response_line(sockfd) {
        Ok(line) => {
            tracing::debug!("connect: received CONNECT response: {}", line.trim());
            if line.starts_with("HTTP/1.1 200") || line.starts_with("HTTP/1.0 200") {
                // Drain response headers until empty line
                loop {
                    match read_http_response_line(sockfd) {
                        Ok(h) if h.is_empty() => break,
                        Ok(h) => {
                            tracing::trace!("connect: response header: {}", h.trim());
                            continue;
                        }
                        Err(e) => {
                            tracing::error!(
                                "connect hijacked: failed to read response headers: {}",
                                e
                            );
                            unsafe {
                                *libc::__errno_location() = libc::ECONNREFUSED;
                            }
                            return -1;
                        }
                    }
                }

                tracing::info!(
                    "connect hijacked: {}:{} → proxy 127.0.0.1:{} (tunnel established)",
                    dst_addr.ip(),
                    dst_addr.port(),
                    proxy_port
                );
                return 0;
            } else {
                tracing::warn!(
                    "connect hijacked: {}:{} — proxy returned {}: {}",
                    dst_addr.ip(),
                    dst_addr.port(),
                    line.split_whitespace().nth(1).unwrap_or("?"),
                    line
                );
                unsafe {
                    *libc::__errno_location() = libc::ECONNREFUSED;
                }
                return -1;
            }
        }
        Err(e) => {
            tracing::error!(
                "connect hijacked: failed to read CONNECT response for {}:{}: {}",
                dst_addr.ip(),
                dst_addr.port(),
                e
            );
            unsafe {
                *libc::__errno_location() = libc::ECONNREFUSED;
            }
            return -1;
        }
    }
}

/// Intercepted `sendto()` — handle TCP Fast Open (MSG_FASTOPEN) by routing
/// through the `connect()` hook before delegating to the real `sendto`.
///
/// Applications using TCP Fast Open can call `sendto()` with `MSG_FASTOPEN`
/// without calling `connect()` first, which would bypass the proxy hijacking.
/// This hook ensures TFO connections go through the same proxy logic as
/// regular `connect()` calls.
///
/// Reference: proxychains-ng, src/libproxychains.c:894-901.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn sendto(
    sockfd: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    dest_addr: *const sockaddr,
    addrlen: socklen_t,
) -> ssize_t {
    let real_sendto = REAL_SENDTO.get().expect("REAL_SENDTO not initialized");

    // Only intercept when MSG_FASTOPEN is set — otherwise pass through.
    if (flags & libc::MSG_FASTOPEN) == 0 {
        return unsafe { real_sendto(sockfd, buf, len, flags, dest_addr, addrlen) };
    }

    // MSG_FASTOPEN is set: call our connect() hook first to trigger proxy
    // hijacking, then clear the flag and nullify the address for sendto.
    if !dest_addr.is_null() {
        let connect_ret = connect(sockfd, dest_addr, addrlen);
        if connect_ret == 0 {
            tracing::debug!(
                "sendto: TFO detected, connect hijacked fd={} dest_addr={:?}",
                sockfd,
                dest_addr
            );
        } else {
            // Connect failed — let the real sendto handle it with the
            // original parameters (TFO semantics).
            return unsafe { real_sendto(sockfd, buf, len, flags, dest_addr, addrlen) };
        }
    }

    // Clear MSG_FASTOPEN and nullify the address so the real sendto
    // behaves as a regular send on an already-connected socket.
    let cleared_flags = flags & !libc::MSG_FASTOPEN;
    unsafe { real_sendto(sockfd, buf, len, cleared_flags, std::ptr::null(), 0) }
}

/// Build a sockaddr_in for the given SocketAddrV4.
fn make_sockaddr_v4(addr: &SocketAddrV4) -> libc::sockaddr_in {
    let mut sin = unsafe { std::mem::zeroed::<libc::sockaddr_in>() };
    sin.sin_family = libc::AF_INET as u16;
    sin.sin_port = addr.port().to_be();
    let octets = addr.ip().octets();
    sin.sin_addr.s_addr = u32::from_ne_bytes(octets);
    sin
}

fn make_sockaddr_v6(addr: &SocketAddrV6) -> libc::sockaddr_in6 {
    let mut sin6 = unsafe { std::mem::zeroed::<libc::sockaddr_in6>() };
    sin6.sin6_family = libc::AF_INET6 as u16;
    sin6.sin6_port = addr.port().to_be();
    sin6.sin6_flowinfo = addr.flowinfo();
    sin6.sin6_addr.s6_addr = addr.ip().octets();
    sin6.sin6_scope_id = addr.scope_id();
    sin6
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn parse<T>(addr: &T) -> Option<(SocketAddrV4, ConnectAddressFamily)> {
        sockaddr_to_connect_v4(addr as *const _ as *const sockaddr)
    }

    #[test]
    fn parses_ipv4_connect_destinations() {
        let socket = SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 32000);
        let v4 = make_sockaddr_v4(&socket);
        let mapped = make_sockaddr_v6(&SocketAddrV6::new(
            socket.ip().to_ipv6_mapped(),
            socket.port(),
            0,
            0,
        ));
        assert_eq!(
            unsafe { parse(&v4) },
            Some((socket, ConnectAddressFamily::Ipv4))
        );
        assert_eq!(
            unsafe { parse(&mapped) },
            Some((socket, ConnectAddressFamily::Ipv4MappedIpv6))
        );
    }

    #[test]
    fn rejects_native_ipv6_connect_destination() {
        let addr = make_sockaddr_v6(&SocketAddrV6::new(Ipv6Addr::LOCALHOST, 32000, 0, 0));
        assert_eq!(unsafe { parse(&addr) }, None);
    }
}

/// Send all bytes on a socket, retrying on partial writes.
fn send_all(sockfd: c_int, data: &[u8]) -> std::io::Result<()> {
    let mut sent = 0;
    while sent < data.len() {
        let n = unsafe {
            libc::send(
                sockfd,
                data.as_ptr().add(sent) as *const c_void,
                data.len() - sent,
                0,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "socket closed during send",
            ));
        }
        sent += n as usize;
    }
    Ok(())
}

/// Read a single HTTP response line (up to \r\n) from a socket.
fn read_http_response_line(sockfd: c_int) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut prev_was_cr = false;
    loop {
        let mut byte = 0u8;
        let n = unsafe { libc::recv(sockfd, &mut byte as *mut u8 as *mut c_void, 1, 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "socket closed during response read",
            ));
        }
        if byte == b'\r' {
            prev_was_cr = true;
            continue;
        }
        if byte == b'\n' {
            if prev_was_cr {
                break;
            }
            // bare \n — treat as line end
            break;
        }
        prev_was_cr = false;
        buf.push(byte);
        // Guard against maliciously long lines
        if buf.len() > 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP response line too long",
            ));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

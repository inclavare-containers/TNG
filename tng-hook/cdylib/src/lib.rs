use std::io::{self, ErrorKind, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::os::raw::c_void;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, OnceLock};

use libc::{c_int, size_t, sockaddr, socklen_t, ssize_t};
use tng_hook_types::{
    encode_frame, EgressHookMappingLookup, EgressHookMappingTable, IngressHookLookup,
    IngressHookMappingTable, LevelRoutingWriter, Route,
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

/// Per-connection state for the centralized socket sink. `pending` holds the
/// unsent tail of at most one partially-written frame. Because framing is
/// length-prefixed with no resync marker, the writer must never leave a
/// half-frame on the wire: a partial is either completed on the next event or
/// dropped at cdylib exit (and the collector's `FrameDecoder::drain_partial`
/// handles a truncated final frame on EOF). One pending frame bounds memory.
struct ConnState {
    stream: UnixStream,
    pending: Option<Vec<u8>>,
}

/// A shared, mutex-guarded connection to the collector's abstract-namespace
/// socket. One `Conn` is reused across both the Info and Error sinks when
/// both streams carry the same socket name (route byte demuxes on the
/// collector).
type Conn = Arc<Mutex<ConnState>>;

/// Where a hook log line goes: an abstract-namespace UDS to the `tng exec`
/// collector (`Socket`), a directly-appended file (`File`), or stderr
/// (`Stderr`). `Socket` is the centralized path: the cdylib frames each
/// record and streams it to the collector, which owns rolling/file rotation.
/// `File`/`Stderr` are the non-centralized fallbacks.
#[derive(Clone)]
enum SinkKind {
    Socket(Arc<Mutex<ConnState>>),
    File(Arc<Mutex<std::fs::File>>),
    Stderr,
}

/// A `MakeWriter` producing one `HookSinkWriter` per log event, tagged with
/// the stream `route` (Info vs Error) so the collector can split them.
struct HookSink {
    kind: SinkKind,
    route: Route,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for HookSink {
    type Writer = HookSinkWriter;
    fn make_writer(&'a self) -> Self::Writer {
        HookSinkWriter {
            kind: self.kind.clone(),
            route: self.route,
            buf: Vec::new(),
        }
    }
}

/// Per-event write handle. `Socket` buffers writes in memory and emits one
/// framed record (`encode_frame`) on drop, so each tracing event becomes
/// exactly one wire frame. `File`/`Stderr` write straight through (no
/// framing), matching the old append/stderr behavior. The socket is
/// non-blocking (set at connect time), so a stalled collector can never block
/// the hooked host: `WouldBlock` and other I/O errors are swallowed.
struct HookSinkWriter {
    kind: SinkKind,
    route: Route,
    buf: Vec<u8>,
}

impl Write for HookSinkWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &self.kind {
            SinkKind::Socket(_) => {
                self.buf.extend_from_slice(buf);
                Ok(buf.len())
            }
            SinkKind::File(f) => f.lock().unwrap_or_else(|e| e.into_inner()).write(buf),
            SinkKind::Stderr => std::io::stderr().write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &self.kind {
            // The buffered payload is framed and sent on Drop, not here: a
            // mid-event `flush()` must not split one record into partial frames.
            SinkKind::Socket(_) => Ok(()),
            SinkKind::File(f) => f.lock().unwrap_or_else(|e| e.into_inner()).flush(),
            SinkKind::Stderr => std::io::stderr().flush(),
        }
    }
}

/// Try to flush a stuck partial tail (`pending`) non-blocking. Returns true
/// when there is no pending tail left (it drained fully, there was none, or a
/// dead stream made us drop it); false when `WouldBlock` left bytes still
/// unflushed, in which case the caller must not send a new frame this round
/// (the partial must complete first to keep the wire framed).
fn drain_pending<W: Write>(stream: &mut W, pending: &mut Option<Vec<u8>>) -> bool {
    let mut tail = match pending.take() {
        Some(t) => t,
        None => return true,
    };
    let mut written = 0;
    while written < tail.len() {
        match stream.write(&tail[written..]) {
            Ok(0) => return true,
            Ok(n) => written += n,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                tail.drain(..written);
                *pending = Some(tail);
                return false;
            }
            Err(_) => return true,
        }
    }
    true
}

/// Send a new `frame` non-blocking. Returns `Some(unsent_tail)` when a partial
/// write left bytes unflushed (to store as the sole pending frame); `None`
/// when the whole frame was sent or the stream is closed or errored (frame
/// dropped). Never blocks.
fn send_frame<W: Write>(stream: &mut W, frame: &[u8]) -> Option<Vec<u8>> {
    let mut written = 0;
    while written < frame.len() {
        match stream.write(&frame[written..]) {
            Ok(0) => return None,
            Ok(n) => written += n,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(_) => return None,
        }
    }
    if written < frame.len() {
        Some(frame[written..].to_vec())
    } else {
        None
    }
}

impl HookSinkWriter {
    /// Flush the in-memory buffer into one framed record on the socket. The
    /// socket is non-blocking, so a stalled collector can never block the host
    /// here. Drain ordering guarantees the wire only ever carries complete
    /// frames mid-stream: (1) finish any pending tail first, and if it is
    /// still stuck, drop this event's frame rather than queue behind it; (2)
    /// otherwise send this frame, and a partial leaves the unsent tail as the
    /// sole pending frame for the next round.
    fn flush_frame(&mut self) {
        let SinkKind::Socket(conn) = &self.kind else {
            return;
        };
        if self.buf.is_empty() {
            return;
        }
        let frame = encode_frame(self.route, &self.buf);
        self.buf.clear();
        // Bind a `&mut ConnState` so the disjoint `stream`/`pending` field
        // borrows below are accepted (disjoint borrows do not propagate
        // through `MutexGuard`'s `DerefMut`).
        let mut guard = conn.lock().unwrap_or_else(|e| e.into_inner());
        let state = &mut *guard;
        if !drain_pending(&mut state.stream, &mut state.pending) {
            return;
        }
        state.pending = send_frame(&mut state.stream, &frame);
    }
}

impl Drop for HookSinkWriter {
    fn drop(&mut self) {
        self.flush_frame();
    }
}

/// Open `path` for append, returning a `File` sink. On failure (e.g. the
/// directory does not exist) fall back to `Stderr` rather than aborting: a
/// cdylib ctor must never kill the host process it is injected into just
/// because a log file is unavailable.
fn open_log_sink(path: &str) -> SinkKind {
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(f) => SinkKind::File(Arc::new(Mutex::new(f))),
        Err(e) => {
            eprintln!("tng-hook: open log file {path} failed: {e}");
            SinkKind::Stderr
        }
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

/// Decide which socket(s) to connect from the per-stream socket-path env
/// values. When both paths are equal, shares ONE connection (shared-socket +
/// route byte: one fd, the collector demuxes by route byte). Pure modulo the
/// `connect` callback, so the dedup logic is unit-testable with a mock
/// connector instead of a real abstract-namespace socket.
fn resolve_connections<C: Fn(&str) -> io::Result<Conn>>(
    info_path: Option<&str>,
    error_path: Option<&str>,
    connect: &C,
) -> io::Result<(Option<Conn>, Option<Conn>)> {
    let info_conn = match info_path {
        Some(p) => Some(connect(p)?),
        None => None,
    };
    let error_conn = match error_path {
        // Different path than info -> open a second connection.
        Some(ep) if Some(ep) != info_path => Some(connect(ep)?),
        // Same path as info -> reuse the one connection (route byte demuxes).
        Some(_) => info_conn.clone(),
        None => None,
    };
    Ok((info_conn, error_conn))
}

/// Connect to the `tng exec` log collector over an abstract-namespace Unix
/// domain socket (`\0<name>`). Abstract namespaces avoid filesystem path
/// collisions and need no cleanup. The socket is set non-blocking before the
/// fd is handed to `UnixStream`, so a collector that stalls can never block the
/// hooked process's log path.
fn connect_hook_socket(name: &str) -> io::Result<Arc<Mutex<ConnState>>> {
    let sock = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    let addr = socket2::SockAddr::unix(std::path::Path::new(&format!("\0{}", name)))?;
    sock.connect(&addr)?;
    sock.set_nonblocking(true)?;
    // socket2 has no `From<Socket>` for `UnixStream`; convert via the raw fd.
    // The non-blocking flag set above persists on the fd.
    let fd = sock.into_raw_fd();
    // SAFETY: `fd` is a valid, connected, non-blocking UNIX socket we just
    // created; `into_raw_fd` transferred ownership to us.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    Ok(Arc::new(Mutex::new(ConnState {
        stream,
        pending: None,
    })))
}

/// Initialize the library at load time.
///
/// This is called once when the `.so` is loaded (before main).
/// It resolves the real `bind`/`getsockname` via dlsym and builds
/// the mapping lookup table from the `TNG_HOOK_EGRESS_MAPPINGS` env var.
#[ctor::ctor]
fn init() {
    // Resolve the real libc functions FIRST. The centralized log path below
    // opens an abstract-namespace UDS via `socket2::Socket::connect`, which
    // routes through this library's own intercepted `connect` (the PLT
    // resolves to our exported symbol); that passthrough needs `REAL_CONNECT`
    // already set, so dlsym must precede any socket creation here.
    unsafe {
        let real_bind = resolve_libc_symbol::<BindFn>("bind").expect("Failed to resolve libc bind");
        let _ = REAL_BIND.set(real_bind);

        let real_getsockname = resolve_libc_symbol::<GetsocknameFn>("getsockname")
            .expect("Failed to resolve libc getsockname");
        let _ = REAL_GETSOCKNAME.set(real_getsockname);

        let real_connect =
            resolve_libc_symbol::<ConnectFn>("connect").expect("Failed to resolve libc connect");
        let _ = REAL_CONNECT.set(real_connect);

        let real_sendto =
            resolve_libc_symbol::<SendtoFn>("sendto").expect("Failed to resolve libc sendto");
        let _ = REAL_SENDTO.set(real_sendto);
    }

    // Route hook logs to one of three sinks per stream (info vs error):
    //   * `TNG_HOOK_LOG_SOCKET` (info) / `TNG_HOOK_LOG_ERROR_SOCKET` (error)
    //     set -> stream framed records to the `tng exec` collector over an
    //     abstract-namespace UDS (the centralized path; the collector owns
    //     rolling/file rotation). Presence flags centralization, value is the
    //     socket name. When both vars carry the same name the cdylib connects
    //     once and demuxes by route byte.
    //   * `TNG_HOOK_LOG_FILE` / `TNG_HOOK_LOG_ERROR_FILE` set -> append directly
    //     to that file (non-centralized fallback, current behavior).
    //   * neither set (info only) -> stderr.
    // Uses `.init()` (not `set_default`), which panics if the host already set
    // a global subscriber. The LD_PRELOAD child is the only subscriber here, so
    // that is the intended behavior; a host that already has its own subscriber
    // will crash, which surfaces the conflict instead of silently dropping logs.
    let log_format: tng_hook_types::LogFormat = std::env::var("TNG_HOOK_LOG_FORMAT")
        .or_else(|_| std::env::var("TNG_LOG_FORMAT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(tng_hook_types::LogFormat::Text);

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // Per-stream socket paths: presence = "this stream is centralized",
    // value = the socket name. On connect failure the Options stay None and
    // the sinks below fall back to file/stderr (info) or file/None (error, in
    // which case the routing writer sends error events to the info sink).
    let info_sock_path = std::env::var("TNG_HOOK_LOG_SOCKET").ok();
    let error_sock_path = std::env::var("TNG_HOOK_LOG_ERROR_SOCKET").ok();
    let (info_conn, error_conn) = match resolve_connections(
        info_sock_path.as_deref(),
        error_sock_path.as_deref(),
        &connect_hook_socket,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("tng-hook: hook log socket connect failed: {e}");
            (None, None)
        }
    };

    let info_sink = if let Some(c) = info_conn {
        HookSink {
            kind: SinkKind::Socket(c),
            route: Route::Info,
        }
    } else if let Ok(p) = std::env::var("TNG_HOOK_LOG_FILE") {
        HookSink {
            kind: open_log_sink(&p),
            route: Route::Info,
        }
    } else {
        HookSink {
            kind: SinkKind::Stderr,
            route: Route::Info,
        }
    };

    let error_sink = if let Some(c) = error_conn {
        Some(HookSink {
            kind: SinkKind::Socket(c),
            route: Route::Error,
        })
    } else if let Ok(p) = std::env::var("TNG_HOOK_LOG_ERROR_FILE") {
        Some(HookSink {
            kind: open_log_sink(&p),
            route: Route::Error,
        })
    } else {
        None
    };

    // Only colorize the pure-stderr fallback (info to a tty, no separate error
    // stream): that path never reaches the collector, so ANSI escapes can't
    // corrupt machine-parsed frames. Centralized/file sinks are always plain.
    let ansi = matches!(info_sink.kind, SinkKind::Stderr)
        && error_sink.is_none()
        && atty::is(atty::Stream::Stderr);

    let layer_writer = LevelRoutingWriter::new(info_sink, error_sink);
    let layer: Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync> =
        build_log_layer(log_format, layer_writer, ansi, filter);
    tracing_subscriber::registry().with(layer).init();

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
                0
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
                -1
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
            -1
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

#[cfg(test)]
mod sink_tests {
    use super::*;
    use std::io::{Read, Write};
    use tng_hook_types::{encode_frame, FrameDecoder, Route};

    #[test]
    fn socket_kind_buffers_and_frames_one_frame_per_writer_drop() {
        // Socket kind with a real stream: use a socketpair to capture bytes.
        let (mut a, b) = UnixStream::pair().unwrap();
        b.set_nonblocking(true).unwrap();
        let conn = Arc::new(Mutex::new(ConnState {
            stream: b,
            pending: None,
        }));
        {
            let mut w = HookSinkWriter {
                kind: SinkKind::Socket(conn.clone()),
                route: Route::Info,
                buf: Vec::new(),
            };
            w.write_all(b"hello ").unwrap();
            w.write_all(b"world\n").unwrap();
            // drop -> one frame
        }
        // Close the write end so read_to_end sees EOF; the outer `conn` still
        // holds b, so without this drop the read would block forever.
        drop(conn);
        let mut bytes = Vec::new();
        a.read_to_end(&mut bytes).unwrap();
        let mut d = FrameDecoder::new();
        d.push(&bytes);
        let (route, payload) = d.next_frame().unwrap().unwrap();
        assert_eq!(route, Route::Info);
        assert_eq!(payload, b"hello world\n");
        assert!(d.next_frame().is_none());
    }

    /// A writer that accepts up to `budget` total bytes, then returns
    /// `WouldBlock` (models a full kernel send buffer). The test raises the
    /// budget to simulate the collector draining.
    struct BudgetWriter {
        out: Vec<u8>,
        budget: usize,
        written: usize,
    }

    impl Write for BudgetWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.written >= self.budget {
                return Err(io::Error::new(ErrorKind::WouldBlock, "send buffer full"));
            }
            let n = std::cmp::min(buf.len(), self.budget - self.written);
            self.out.extend_from_slice(&buf[..n]);
            self.written += n;
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A partial first send must leave the unsent tail as `pending` instead of
    /// writing a truncated length-prefixed frame that would desync the
    /// collector. The wire only carries the bytes that actually went out.
    #[test]
    fn send_frame_partial_leaves_unsent_tail_as_pending() {
        let frame = encode_frame(Route::Info, b"hello world\n"); // 17 bytes
        let mut w = BudgetWriter {
            out: Vec::new(),
            budget: 3,
            written: 0,
        };
        let pending = send_frame(&mut w, &frame);
        assert_eq!(pending.as_deref(), Some(&frame[3..]));
        // Only the first 3 bytes hit the wire; the rest is pending, so no
        // complete valid frame is decodable yet (no desync).
        assert_eq!(w.out, &frame[..3]);
        let mut d = FrameDecoder::new();
        d.push(&w.out);
        assert!(
            !matches!(d.next_frame(), Some(Ok(_))),
            "partial bytes must not decode to a valid frame (would desync)"
        );
    }

    /// When the collector drains (budget raised), the pending tail is flushed
    /// and the frame completes. The reassembled wire bytes decode to the
    /// original full frame.
    #[test]
    fn drain_pending_completes_truncated_frame_after_drain() {
        let frame = encode_frame(Route::Info, b"hello world\n");
        let mut w = BudgetWriter {
            out: Vec::new(),
            budget: 3,
            written: 0,
        };
        // First event: partial -> pending = frame[3..].
        let mut pending = send_frame(&mut w, &frame);
        assert_eq!(pending.as_deref(), Some(&frame[3..]));
        // Collector drained: raise the budget so the tail can flush fully.
        w.budget = frame.len() + 10;
        let fully_drained = drain_pending(&mut w, &mut pending);
        assert!(fully_drained);
        assert!(pending.is_none());
        // The wire now has the complete frame and decodes cleanly.
        assert_eq!(w.out, &frame[..]);
        let mut d = FrameDecoder::new();
        d.push(&w.out);
        let (route, payload) = d.next_frame().unwrap().unwrap();
        assert_eq!(route, Route::Info);
        assert_eq!(payload, b"hello world\n");
        assert!(d.next_frame().is_none());
    }

    /// If the pending tail still cannot fully drain (EAGAIN mid-tail), the
    /// remaining bytes stay pending and the partially-flushed bytes are on
    /// the wire (still no complete frame, still no desync).
    #[test]
    fn drain_pending_eagain_keeps_remaining_tail() {
        let frame = encode_frame(Route::Info, b"hello world\n"); // 17 bytes
                                                                 // 14-byte pending tail (frame[3..]) with a 5-byte budget.
        let mut pending = Some(frame[3..].to_vec());
        let mut w = BudgetWriter {
            out: Vec::new(),
            budget: 5,
            written: 0,
        };
        let fully_drained = drain_pending(&mut w, &mut pending);
        assert!(!fully_drained);
        // 5 of 14 bytes drained; the remaining 9 stay pending.
        assert_eq!(pending.as_deref(), Some(&frame[3 + 5..]));
        assert_eq!(w.out, &frame[3..3 + 5]);
        // Still no complete valid frame decodable from the partial bytes.
        let mut d = FrameDecoder::new();
        d.push(&w.out);
        assert!(
            !matches!(d.next_frame(), Some(Ok(_))),
            "partial bytes must not decode to a valid frame (would desync)"
        );
    }

    #[test]
    fn file_kind_writes_through_no_buffering() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let f = Arc::new(Mutex::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(tmp.path())
                .unwrap(),
        ));
        {
            let mut w = HookSinkWriter {
                kind: SinkKind::File(f.clone()),
                route: Route::Info,
                buf: Vec::new(),
            };
            w.write_all(b"direct\n").unwrap();
        }
        let contents = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(contents.contains("direct\n"));
    }

    /// Both an Info and an Error `HookSinkWriter` sharing one
    /// `Arc<Mutex<ConnState>>` (the single shared socket the cdylib opens when
    /// both streams are centralized) must frame each event independently with
    /// its own route tag. Interleaved drops produce a byte stream a real
    /// `FrameDecoder` reassembles into two correctly-tagged frames. Guards
    /// against a regression that reuses a single route for both streams.
    #[test]
    fn shared_socket_dual_route_frames_independently() {
        let (mut a, b) = UnixStream::pair().unwrap();
        b.set_nonblocking(true).unwrap();
        let conn = Arc::new(Mutex::new(ConnState {
            stream: b,
            pending: None,
        }));

        // Interleave drops: Info writer, then Error writer, then another Info,
        // all on the same shared connection.
        {
            let mut w = HookSinkWriter {
                kind: SinkKind::Socket(conn.clone()),
                route: Route::Info,
                buf: Vec::new(),
            };
            w.write_all(b"info-1\n").unwrap();
            // drop -> one Info frame
        }
        {
            let mut w = HookSinkWriter {
                kind: SinkKind::Socket(conn.clone()),
                route: Route::Error,
                buf: Vec::new(),
            };
            w.write_all(b"error-1\n").unwrap();
            // drop -> one Error frame
        }
        {
            let mut w = HookSinkWriter {
                kind: SinkKind::Socket(conn.clone()),
                route: Route::Info,
                buf: Vec::new(),
            };
            w.write_all(b"info-2\n").unwrap();
            // drop -> one Info frame
        }
        // Release the write end so read_to_end sees EOF.
        drop(conn);

        let mut bytes = Vec::new();
        a.read_to_end(&mut bytes).unwrap();

        let mut d = FrameDecoder::new();
        d.push(&bytes);
        let (r1, p1) = d.next_frame().unwrap().expect("frame 1 ok");
        let (r2, p2) = d.next_frame().unwrap().expect("frame 2 ok");
        let (r3, p3) = d.next_frame().unwrap().expect("frame 3 ok");
        assert!(d.next_frame().is_none());

        assert_eq!(r1, Route::Info);
        assert_eq!(p1, b"info-1\n");
        assert_eq!(r2, Route::Error);
        assert_eq!(p2, b"error-1\n");
        assert_eq!(r3, Route::Info);
        assert_eq!(p3, b"info-2\n");
    }

    /// Mock connector for `resolve_connections`: counts how many times it is
    /// called, records the paths it was asked to connect, and returns a fresh
    /// dummy `ConnState` (a real socketpair end, never read). The dedup logic
    /// is pure modulo this callback, so this exercises it without any real
    /// abstract-namespace socket.
    struct MockConnector {
        calls: usize,
        paths: Vec<String>,
    }

    impl MockConnector {
        fn new() -> Self {
            Self {
                calls: 0,
                paths: Vec::new(),
            }
        }
    }

    fn mock_connect(
        state: &Mutex<MockConnector>,
    ) -> impl Fn(&str) -> io::Result<Arc<Mutex<ConnState>>> + '_ {
        move |path: &str| {
            let mut g = state.lock().unwrap();
            g.calls += 1;
            g.paths.push(path.to_string());
            // A throwaway socketpair end satisfies `ConnState`'s `UnixStream`
            // field; the unit test never reads it.
            let (_a, b) = UnixStream::pair().unwrap();
            Ok(Arc::new(Mutex::new(ConnState {
                stream: b,
                pending: None,
            })))
        }
    }

    #[test]
    fn resolve_connections_both_paths_equal_shares_one_connection() {
        let state = Mutex::new(MockConnector::new());
        let connect = mock_connect(&state);
        let (info_conn, error_conn) =
            resolve_connections(Some("sock"), Some("sock"), &connect).unwrap();
        let g = state.lock().unwrap();
        assert_eq!(g.calls, 1, "same path -> connect once");
        assert_eq!(g.paths, vec!["sock".to_string()]);
        drop(g);
        let info = info_conn.expect("info_conn present");
        let error = error_conn.expect("error_conn present");
        assert!(
            Arc::ptr_eq(&info, &error),
            "same path -> error_conn is the same Arc as info_conn"
        );
    }

    #[test]
    fn resolve_connections_distinct_paths_open_two_connections() {
        let state = Mutex::new(MockConnector::new());
        let connect = mock_connect(&state);
        let (info_conn, error_conn) =
            resolve_connections(Some("info-sock"), Some("error-sock"), &connect).unwrap();
        let g = state.lock().unwrap();
        assert_eq!(g.calls, 2, "different paths -> connect twice");
        assert_eq!(
            g.paths,
            vec!["info-sock".to_string(), "error-sock".to_string()]
        );
        drop(g);
        let info = info_conn.expect("info_conn present");
        let error = error_conn.expect("error_conn present");
        assert!(
            !Arc::ptr_eq(&info, &error),
            "different paths -> distinct Arcs"
        );
    }

    #[test]
    fn resolve_connections_info_only_connects_once_error_none() {
        let state = Mutex::new(MockConnector::new());
        let connect = mock_connect(&state);
        let (info_conn, error_conn) =
            resolve_connections(Some("info-sock"), None, &connect).unwrap();
        let g = state.lock().unwrap();
        assert_eq!(g.calls, 1, "info-only -> connect once");
        assert_eq!(g.paths, vec!["info-sock".to_string()]);
        drop(g);
        assert!(info_conn.is_some(), "info_conn present");
        assert!(error_conn.is_none(), "error_conn absent for info-only");
    }

    #[test]
    fn resolve_connections_error_only_connects_once_info_none() {
        let state = Mutex::new(MockConnector::new());
        let connect = mock_connect(&state);
        let (info_conn, error_conn) =
            resolve_connections(None, Some("error-sock"), &connect).unwrap();
        let g = state.lock().unwrap();
        assert_eq!(g.calls, 1, "error-only -> connect once");
        assert_eq!(g.paths, vec!["error-sock".to_string()]);
        drop(g);
        assert!(info_conn.is_none(), "info_conn absent for error-only");
        assert!(error_conn.is_some(), "error_conn present");
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

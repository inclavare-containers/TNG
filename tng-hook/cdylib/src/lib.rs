use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::raw::c_void;
use std::sync::OnceLock;

use libc::{c_int, sockaddr, socklen_t};
use tng_hook_types::{
    EgressHookMappingLookup, EgressHookMappingTable, IngressHookLookup, IngressHookMappingTable,
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

/// Initialize the library at load time.
///
/// This is called once when the `.so` is loaded (before main).
/// It resolves the real `bind`/`getsockname` via dlsym and builds
/// the mapping lookup table from the `TNG_HOOK_EGRESS_MAPPINGS` env var.
#[ctor::ctor]
fn init() {
    // Initialize tracing subscriber writing to stderr.
    // This allows `tracing::info!` etc. to produce output even in a
    // preloaded library where the host process has no tracing configured.
    // The log level can be controlled via `RUST_LOG` env var (default: info).
    // Uses `set_default` so it won't panic if the host already has a subscriber.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(atty::is(atty::Stream::Stderr))
                .with_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                ),
        )
        .init();

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
                    let entries: usize = table.proxies.iter().map(|p| p.capture_rules.len()).sum();
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
        tracing::warn!(
            "bind: non-IPv4 socket, family={:#x}, fd={}",
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

    // Only handle AF_INET (IPv4)
    let Some(dst_addr) = (unsafe { sockaddr_to_v4(addr) }) else {
        if !addr.is_null() {
            let sa = unsafe { &*addr };
            tracing::warn!(
                "connect: non-IPv4 destination, family={:#x}, fd={}",
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

    // Connect to the internal HTTP proxy instead (now blocking)
    let proxy_sockaddr = make_sockaddr_v4(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, proxy_port));

    let ret = unsafe {
        real_connect(
            sockfd,
            &proxy_sockaddr as *const _ as *const sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as socklen_t,
        )
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

/// Build a sockaddr_in for the given SocketAddrV4.
fn make_sockaddr_v4(addr: &SocketAddrV4) -> libc::sockaddr_in {
    let mut sin = unsafe { std::mem::zeroed::<libc::sockaddr_in>() };
    sin.sin_family = libc::AF_INET as u16;
    sin.sin_port = addr.port().to_be();
    let octets = addr.ip().octets();
    sin.sin_addr.s_addr = u32::from_ne_bytes(octets);
    sin
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

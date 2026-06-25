use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::OnceLock;

use libc::{c_int, sockaddr, socklen_t};
use tng_hook_types::{HookMappingLookup, HookMappingTable};
use tracing_subscriber::util::SubscriberInitExt;

/// Resolved real `bind` function pointer.
type BindFn = unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;

/// Resolved real `getsockname` function pointer.
type GetsocknameFn = unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t) -> c_int;

static REAL_BIND: OnceLock<BindFn> = OnceLock::new();
static REAL_GETSOCKNAME: OnceLock<GetsocknameFn> = OnceLock::new();

/// Global mapping lookup table, initialized once from env var at library load.
static LOOKUP: OnceLock<HookMappingLookup> = OnceLock::new();

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
/// the mapping lookup table from the `TNG_HOOK_MAPPINGS` env var.
#[ctor::ctor]
fn init() {
    // Initialize tracing subscriber writing to stderr.
    // This allows `tracing::info!` etc. to produce output even in a
    // preloaded library where the host process has no tracing configured.
    // The log level can be controlled via `RUST_LOG` env var (default: info).
    // Uses `set_default` so it won't panic if the host already has a subscriber.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .without_time()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .set_default();

    // Resolve real functions directly from libc
    unsafe {
        if let Some(f) = resolve_libc_symbol::<BindFn>("bind") {
            let _ = REAL_BIND.set(f);
        }
        if let Some(f) = resolve_libc_symbol::<GetsocknameFn>("getsockname") {
            let _ = REAL_GETSOCKNAME.set(f);
        }
    }

    // Build lookup from env var
    if let Ok(json) = std::env::var("TNG_HOOK_MAPPINGS") {
        if !json.is_empty() {
            if let Ok(table) = serde_json::from_str::<HookMappingTable>(&json) {
                let lookup = HookMappingLookup::from_table(&table);
                let _ = LOOKUP.set(lookup);
            }
        }
    }
}

/// Convert a sockaddr pointer to SocketAddrV4 if it's AF_INET.
///
/// # Safety
/// Caller must ensure `addr` points to a valid sockaddr of at least `addrlen` bytes.
unsafe fn sockaddr_to_v4(addr: *const sockaddr) -> Option<SocketAddrV4> {
    if addr.is_null() {
        return None;
    }
    let sa = &*addr;
    if sa.sa_family != libc::AF_INET as u16 {
        return None;
    }
    let sin = &*(addr as *const libc::sockaddr_in);
    let port = u16::from_be(sin.sin_port);
    let addr_bytes = sin.sin_addr.s_addr.to_ne_bytes();
    let ip = Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);
    Some(SocketAddrV4::new(ip, port))
}

/// Intercepted `bind()` — rewrite origin port to real port if mapped.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn bind(sockfd: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int {
    let real_bind = match REAL_BIND.get() {
        Some(f) => f,
        None => {
            unsafe {
                *libc::__errno_location() = libc::EINVAL;
            }
            return -1;
        }
    };

    // Only intercept AF_INET (IPv4)
    if let Some(origin_addr) = unsafe { sockaddr_to_v4(addr) } {
        if let Some(lookup) = LOOKUP.get() {
            if let Some(real_port) = lookup.lookup_forward(origin_addr) {
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
    }

    // No match — pass through to real bind
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
    let real_getsockname = match REAL_GETSOCKNAME.get() {
        Some(f) => f,
        None => {
            unsafe {
                *libc::__errno_location() = libc::EINVAL;
            }
            return -1;
        }
    };

    // Call the real getsockname first
    let result = unsafe { real_getsockname(sockfd, addr, addrlen) };
    if result != 0 {
        return result;
    }

    // Check if the returned address is one we remapped
    if let Some(real_addr) = unsafe { sockaddr_to_v4(addr) } {
        if let Some(lookup) = LOOKUP.get() {
            if let Some(origin_port) = lookup.lookup_reverse(real_addr) {
                // Rewrite the port back to origin
                let mut new_addr = unsafe { std::ptr::read(addr as *const libc::sockaddr_in) };
                new_addr.sin_port = origin_port.to_be();
                unsafe {
                    std::ptr::write(addr as *mut libc::sockaddr_in, new_addr);
                }
            }
        }
    }

    result
}

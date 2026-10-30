// Fairness measurement server (std-only, dynamically linked so tng-hook can
// intercept `bind()`). Auto-built by the hook_connection_fairness test.
//
// Usage: fairness_server <base_port> <count> <size_bytes> [abrupt]
// Binds listeners on [base_port, base_port+count). For each listener, accepts
// exactly ONE connection: recv a 1-byte "go" signal, stream `size_bytes` of
// data, half-close the write side. The process exits once all `count`
// connections have been served (or after a 120s watchdog), so it never leaks
// as an orphan in the test's network namespace.
//
// With `abrupt`, each connection thread returns right after the write
// half-close instead of waiting for the client to close, so the process exits
// while tail data may still sit in the egress path. That reproduces a
// sender-side abrupt teardown, which the `tng exec` drain window must survive
// without losing the tail or hanging the receiver.
use std::env;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

const SEND_CHUNK: usize = 256 * 1024;
const WATCHDOG_SECS: u64 = 120;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 && args.len() != 5 {
        eprintln!("usage: {} <base_port> <count> <size_bytes> [abrupt]", args[0]);
        std::process::exit(2);
    }
    let abrupt = match args.get(4) {
        None => false,
        Some(mode) if mode == "abrupt" => true,
        Some(other) => {
            eprintln!(
                "usage: {} <base_port> <count> <size_bytes> [abrupt] (unknown mode {other:?})",
                args[0]
            );
            std::process::exit(2);
        }
    };
    let base_port: u16 = args[1].parse().expect("base_port");
    let count: u16 = args[2].parse().expect("count");
    let size: u64 = args[3].parse().expect("size_bytes");

    let mut listeners = Vec::new();
    for i in 0..count {
        let port = base_port + i;
        // The hook redirects this bind to an auto-allocated real port; tng
        // binds the origin port for tunnel traffic. SO_REUSEADDR for restarts.
        let l = match TcpListener::bind(("0.0.0.0", port)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("fairness_server: bind({port}) failed: {e}");
                std::process::exit(1);
            }
        };
        eprintln!("fairness_server: listening (disguised) port {port}");
        listeners.push((port, l));
    }

    let served = Arc::new(AtomicUsize::new(0));

    // Watchdog: ensure the process exits even if some accept() blocks forever
    // (e.g. a client that never connects). Bounded lifetime => no orphan leak.
    {
        let served = Arc::clone(&served);
        let count = count as usize;
        thread::spawn(move || {
            thread::sleep(std::time::Duration::from_secs(WATCHDOG_SECS));
            eprintln!(
                "fairness_server: watchdog fired after {WATCHDOG_SECS}s (served {}/{count})",
                served.load(Ordering::Relaxed)
            );
            std::process::exit(0);
        });
    }

    let mut handles = Vec::new();
    for (port, l) in listeners {
        let served = Arc::clone(&served);
        let total = count as usize;
        handles.push(thread::spawn(move || {
            // Accept exactly one connection on this port.
            if let Ok((mut stream, peer)) = l.accept() {
                eprintln!("fairness_server[{port}]: accepted from {peer}");
                let mut go = [0u8; 1];
                if stream.read_exact(&mut go).is_ok() {
                    let buf = vec![0u8; SEND_CHUNK];
                    let mut remaining = size;
                    while remaining > 0 {
                        let n = remaining.min(buf.len() as u64) as usize;
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        remaining -= n as u64;
                    }
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    if abrupt {
                        // Exit without waiting for the client: the process dies
                        // the moment its writes are handed to the socket, which
                        // is the abrupt-teardown scenario under test.
                        return;
                    }
                    // Wait for the client to close after it received everything.
                    // A long-running server (the real Prefill node) stays up, so
                    // the tunnel is torn down from the client (Decode) side in an
                    // orderly fashion instead of being abruptly killed by a
                    // server-process exit that could drop in-flight tail data.
                    let mut drain = [0u8; 1024];
                    while stream.read(&mut drain).unwrap_or(0) > 0 {}
                }
                let prev = served.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "fairness_server[{port}]: done (served {}/{total})",
                    prev + 1
                );
            } else {
                eprintln!("fairness_server[{port}]: accept failed");
            }
        }));
    }

    for h in handles {
        let _ = h.join();
    }
    eprintln!(
        "fairness_server: all connections served ({}), exiting",
        served.load(Ordering::Relaxed)
    );
}

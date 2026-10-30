// Fairness measurement client (std-only, dynamically linked so tng-hook can
// intercept `connect()`). Auto-built by the hook_connection_fairness test.
//
// Usage: fairness_client <server_ip> <base_port> <count> <size_bytes>
// Opens `count` concurrent connections to server_ip:{base_port+i}. After ALL
// are connected, each sends a 1-byte "go", starts its timer, recvs until
// `size_bytes` received, and records elapsed time. Prints a per-connection
// throughput table + summary (min/max/mean/median/stddev, max/min ratio, Jain's
// fairness index). Exits 0 only if all connections completed the full
// transfer: a recv that times out marks the connection STALLED, a clean EOF
// with fewer than `size_bytes` received marks it TRUNCATED (the tail was
// lost), and either fails the exit.
use std::env;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

const RECV_CHUNK: usize = 256 * 1024;
// A read that makes no progress for this long marks the connection stalled.
// Generous enough that a healthy flow never trips it (every active read resets
// the deadline), short enough to bound a hung run instead of waiting on TCP
// keepalives.
const READ_TIMEOUT_SEC: u64 = 20;

struct Result {
    port: u16,
    bytes: u64,
    elapsed_ms: f64,
    timed_out: bool,
    truncated: bool,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "usage: {} <server_ip> <base_port> <count> <size_bytes>",
            args[0]
        );
        std::process::exit(2);
    }
    let server_ip: String = args[1].clone();
    let base_port: u16 = args[2].parse().expect("base_port");
    let count: u16 = args[3].parse().expect("count");
    let size: u64 = args[4].parse().expect("size_bytes");

    let barrier = Arc::new(Barrier::new(count as usize));
    let mut handles = Vec::with_capacity(count as usize);

    let wall_start = Instant::now();
    for i in 0..count {
        let port = base_port + i;
        let addr = format!("{server_ip}:{port}");
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || -> std::io::Result<Result> {
            // Retry connect until the server/tng side is ready (bounded so a
            // misconfigured test fails fast instead of hanging the harness).
            let mut stream = {
                let mut attempts = 0;
                loop {
                    match TcpStream::connect(&addr) {
                        Ok(s) => break s,
                        Err(e) => {
                            attempts += 1;
                            if attempts > 150 {
                                eprintln!("fairness_client[{port}]: connect to {addr} gave up after retries: {e}");
                                return Err(e);
                            }
                            thread::sleep(std::time::Duration::from_millis(200));
                        }
                    }
                }
            };
            let _ = stream.set_nodelay(true);
            // Guard against a connection whose recv never returns (e.g. a tunnel
            // that tears down without delivering EOF/final data). A read that
            // stalls for READ_TIMEOUT_SEC with no progress is treated as
            // stalled: we record what we have, flag it timed_out, and move on
            // so the harness never hangs. An actively-transferring connection
            // resets the deadline on every successful read, so only truly stuck
            // flows surface here.
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(
                READ_TIMEOUT_SEC,
            )));

            // Wait until ALL connections are established before any transfer,
            // so all streams start their bulk transfer ~simultaneously.
            barrier.wait();

            // "go" signal — server begins streaming after receiving this.
            stream.write_all(&[b'G']).ok();
            let start = Instant::now();

            let mut total: u64 = 0;
            let mut timed_out = false;
            let mut buf = vec![0u8; RECV_CHUNK];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => total += n as u64,
                    Err(_) => {
                        // Read timeout (stalled) or error. Stop waiting so the
                        // report can be printed; mark partial transfers.
                        timed_out = true;
                        break;
                    }
                }
                if total >= size {
                    break;
                }
            }
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            // A clean EOF with less than the full payload means the flow was
            // cut short (e.g. an abrupt teardown that lost the tail). Separate
            // symptom from a stall: here the peer closed, there the read timed
            // out; conflating them hides truncation behind a false PASS.
            let truncated = total < size && !timed_out;
            let _ = stream.shutdown(Shutdown::Both);
            Ok(Result {
                port,
                bytes: total,
                elapsed_ms,
                timed_out,
                truncated,
            })
        }));
    }

    let mut results: Vec<Result> = Vec::new();
    let mut all_ok = true;
    for h in handles {
        match h.join() {
            Ok(Ok(r)) => results.push(r),
            Ok(Err(e)) => {
                eprintln!("fairness_client: conn failed: {e}");
                all_ok = false;
            }
            Err(_) => {
                eprintln!("fairness_client: thread panicked");
                all_ok = false;
            }
        }
    }
    // Count stalled (timed_out) and truncated connections AFTER results are
    // populated, so a stuck or short-closed flow both surfaces in the report
    // and fails the process exit code.
    let n_timed_out = results.iter().filter(|r| r.timed_out).count();
    let n_truncated = results.iter().filter(|r| r.truncated).count();
    if n_timed_out > 0 || n_truncated > 0 {
        all_ok = false;
    }
    let wall_ms = wall_start.elapsed().as_secs_f64() * 1000.0;

    // Throughput in MB/s (decimal). bytes / seconds / 1e6.
    let mut rows: Vec<(u16, u64, f64, f64, bool, bool)> = results
        .iter()
        .map(|r| {
            let secs = r.elapsed_ms / 1000.0;
            let mbps = if secs > 0.0 {
                r.bytes as f64 / secs / 1_000_000.0
            } else {
                0.0
            };
            (r.port, r.bytes, r.elapsed_ms, mbps, r.timed_out, r.truncated)
        })
        .collect();
    rows.sort_by(|a, b| a.3.partial_cmp(&b.3).unwrap());

    let n = rows.len();
    let mbps_vals: Vec<f64> = rows.iter().map(|r| r.3).collect();
    let min = mbps_vals.first().copied().unwrap_or(0.0);
    let max = mbps_vals.last().copied().unwrap_or(0.0);
    let mean = mbps_vals.iter().sum::<f64>() / n as f64;
    let median = {
        let mut v = mbps_vals.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        if n % 2 == 1 {
            v[n / 2]
        } else {
            (v[n / 2 - 1] + v[n / 2]) / 2.0
        }
    };
    let variance = mbps_vals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
    let stddev = variance.sqrt();
    let max_min_ratio = if min > 0.0 { max / min } else { f64::INFINITY };
    // Jain's fairness index: (Σxi)^2 / (n · Σxi^2). 1.0 = perfectly fair.
    let sum: f64 = mbps_vals.iter().sum();
    let sum_sq: f64 = mbps_vals.iter().map(|x| x * x).sum();
    let jain = if sum_sq > 0.0 {
        (sum * sum) / (n as f64 * sum_sq)
    } else {
        0.0
    };

    println!("FAIRNESS_REPORT_BEGIN");
    for (port, bytes, elapsed_ms, mbps, timed_out, truncated) in &rows {
        let flag = if *timed_out {
            " STALLED"
        } else if *truncated {
            " TRUNCATED"
        } else {
            ""
        };
        println!("conn port={port} bytes={bytes} elapsed_ms={elapsed_ms:.3} mbps={mbps:.3}{flag}");
    }
    let total_bytes: u64 = rows.iter().map(|r| r.1).sum();
    println!(
        "SUMMARY n={n} total_bytes={total_bytes} wall_ms={wall_ms:.3} min_mbps={min:.3} max_mbps={max:.3} mean_mbps={mean:.3} median_mbps={median:.3} stddev_mbps={stddev:.3} max_min_ratio={max_min_ratio:.3} jain={jain:.4} stalled={n_timed_out} truncated={n_truncated}"
    );
    println!("FAIRNESS_REPORT_END");

    if !all_ok {
        std::process::exit(1);
    }
}

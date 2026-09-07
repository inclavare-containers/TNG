//! Main-process collector for centralized hook logging.
//!
//! The `tng exec` process binds an abstract-namespace Unix-domain **datagram**
//! socket (`\0tng-hook-log-<pid>`). The `tng-hook` cdylib (LD_PRELOAD'd into
//! the hooked child) sends one route-tagged datagram per log record (see
//! `tng_hook_types::wire`). This module receives each datagram and fans the
//! payload into the main process's `info.log` / `error.log` via cloned
//! `NonBlocking` writers, so hook logs merge into the same rolling files the
//! main process owns.
//!
//! A datagram transport means the collector holds exactly **one** file
//! descriptor regardless of how many hook children are logging concurrently
//! (a stream transport needed one accept-loop fd per child), so the parent no
//! longer raises `RLIMIT_NOFILE`. Framing is also atomic: one `recv` yields
//! one complete frame, with no partial-frame reassembly and no stream-desync
//! recovery — a malformed datagram is dropped and the next one decodes
//! independently.
//!
//! Abstract-namespace sockets are Linux-only (no filesystem path, no cleanup),
//! and the cdylib is Linux-only too, so this whole module is
//! `#[cfg(target_os = "linux")]`-gated (the module-level gate lives in
//! `lib.rs`; this file is only compiled on Linux).

use std::io::{self, Write};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::path::Path;

use socket2::{Domain, SockAddr, Socket, Type};
use tokio::net::UnixDatagram;
use tokio::sync::oneshot;
use tracing_appender::non_blocking::NonBlocking;

use tng_hook_types::{decode_frame, Route};

/// Receive buffer for the datagram socket. 256 KiB covers any plausible
/// formatted log record (a single line is normally well under 8 KiB; even a
/// large `{:#?}` debug dump of a mapping table stays in the tens of KiB). The
/// kernel delivers datagrams up to roughly `wmem_max` (default ~212 KiB), so a
/// buffer below that would silently truncate a large record — see the
/// `large_datagram_is_delivered_whole_not_truncated` test. The buffer is
/// allocated once and reused, so its size is not a per-event cost.
const RECV_BUF_SIZE: usize = 256 * 1024;

/// Centralized hook log collector. Owns the bound datagram socket and the
/// cloned `NonBlocking` writers that hook payloads are merged into. `run`
/// reads datagrams in a single task — no per-connection state, no accept loop.
pub struct HookLogCollector {
    sock: UnixDatagram,
    info_nb: NonBlocking,
    error_nb: Option<NonBlocking>,
}

impl HookLogCollector {
    /// Bind the abstract-namespace datagram socket `\0tng-hook-log-<pid>` and
    /// return the BARE name `tng-hook-log-<pid>` (for `TNG_HOOK_LOG_SOCKET` env
    /// injection into hooked children) plus the collector, ready to `run`.
    ///
    /// The returned name carries no leading NUL: `setenv` uses NUL-terminated
    /// C strings, so a value starting with NUL would be truncated to empty,
    /// and the cdylib's `connect_hook_socket` prepends its own `\0` before
    /// connecting. The bind uses the `\0`-prefixed abstract name internally;
    /// callers inject the bare name into the child env verbatim.
    ///
    /// The socket is set non-blocking before being handed to tokio, so the
    /// recv loop never blocks the reactor on a stale fd. socket2 has no
    /// `From<Socket>` for `UnixDatagram`, so the conversion goes through the
    /// raw fd.
    pub async fn start(
        info_nb: NonBlocking,
        error_nb: Option<NonBlocking>,
    ) -> io::Result<(Self, String)> {
        let sock = Socket::new(Domain::UNIX, Type::DGRAM, None)?;
        // Bare name for env injection (no leading NUL): the cdylib prepends `\0`
        // itself when connecting, and setenv would truncate a NUL-bearing value.
        let name = format!("tng-hook-log-{}", std::process::id());
        // Bind with the `\0` prefix: leading NUL selects the abstract namespace
        // (no filesystem path, no unlink on exit, per-pid so names never collide).
        let addr = SockAddr::unix(Path::new(&format!("\0{}", name)))?;
        sock.bind(&addr)?;
        // Non-blocking must be set before the fd leaves socket2's ownership so
        // tokio's registration sees a non-blocking fd.
        sock.set_nonblocking(true)?;
        let fd = sock.into_raw_fd();
        // SAFETY: `fd` is a valid bound non-blocking UNIX datagram socket we
        // just created; `into_raw_fd` transferred ownership to us.
        let std_sock = unsafe { std::os::unix::net::UnixDatagram::from_raw_fd(fd) };
        let sock = UnixDatagram::from_std(std_sock)?;
        Ok((
            Self {
                sock,
                info_nb,
                error_nb,
            },
            name,
        ))
    }

    /// Receive loop. Each datagram is one complete frame, decoded and written
    /// to the matching `NonBlocking` writer. On cancel the loop breaks, then
    /// drains whatever children already queued in the kernel recv buffer
    /// (non-blocking `try_recv` until `WouldBlock`) so in-flight frames are not
    /// lost on shutdown.
    pub async fn run(self, cancel: oneshot::Receiver<()>) {
        let Self {
            sock,
            mut info_nb,
            mut error_nb,
        } = self;
        let mut buf = vec![0u8; RECV_BUF_SIZE];
        let mut cancel = cancel;
        loop {
            tokio::select! {
                // `&mut` so the same receiver can be polled across loop
                // iterations until it fires.
                _ = &mut cancel => break,
                res = sock.recv(&mut buf) => match res {
                    // Empty datagram: nothing to decode, keep receiving.
                    Ok(0) => continue,
                    Ok(n) => {
                        // A datagram at least as large as the recv buffer is
                        // truncated by the kernel to `buf.len()` and the excess
                        // is silently discarded (`recv` returns `min(msg_len,
                        // buf_len)` without `MSG_TRUNC`). A real log line never
                        // fills a 256 KiB buffer, so `n == buf.len()` means an
                        // oversized record — drop it with a warning rather than
                        // writing a truncated half-line to the log.
                        if n == buf.len() {
                            tracing::warn!(
                                size = n,
                                "hook log datagram truncated; oversized record dropped"
                            );
                            continue;
                        }
                        dispatch_frame(&buf[..n], &mut info_nb, &mut error_nb);
                    }
                    Err(error) => {
                        // A transient recv failure must not tear down
                        // collection for every other child. Log and keep
                        // receiving; the cancel branch still breaks on
                        // shutdown.
                        tracing::warn!(?error, "hook log recv failed");
                    }
                }
            }
        }

        // Drain datagrams the children already queued before the socket is
        // dropped. `try_recv` returns WouldBlock when the kernel buffer is
        // empty, so this is bounded and fast. By the time `run` is cancelled
        // (after `child.wait()` returned in `exec.rs`), no child is still
        // sending, so the buffered set is final. The same truncation guard
        // applies so a queued oversized record is dropped, not half-written.
        while let Ok(n) = sock.try_recv(&mut buf) {
            if n == 0 {
                continue;
            }
            if n == buf.len() {
                tracing::warn!(
                    size = n,
                    "hook log datagram truncated; oversized record dropped"
                );
                continue;
            }
            dispatch_frame(&buf[..n], &mut info_nb, &mut error_nb);
        }
    }
}

/// Decode one datagram's frame and write its payload to the matching
/// `NonBlocking` writer. `NonBlocking` is lossy by default (`write_all` never
/// blocks, never errors), so a slow rolling appender cannot stall the hook log
/// path.
///
/// Route dispatch: `Route::Error` goes to the error writer when one exists;
/// otherwise it falls back to the info writer (the "no separate error file"
/// case, mirroring `LevelRoutingWriter`'s behavior in the main subscriber).
/// `Route::Info` always goes to the info writer. A malformed datagram (empty,
/// or a bad route byte) is dropped — the next datagram decodes independently,
/// so one bad frame cannot desync the stream.
fn dispatch_frame(payload: &[u8], info_nb: &mut NonBlocking, error_nb: &mut Option<NonBlocking>) {
    match decode_frame(payload) {
        Ok((route, body)) => {
            // Disjoint mutable borrow: pick the writer for this route without
            // cloning.
            let target: &mut NonBlocking = match (route, error_nb) {
                (Route::Error, Some(e)) => e,
                _ => info_nb,
            };
            // Lossy + never blocks; a dropped line is preferable to stalling a
            // hooked host.
            let _ = target.write_all(body);
        }
        Err(error) => {
            tracing::warn!(?error, "hook log datagram decode error; dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serial_test::serial;
    use tng_hook_types::encode_frame;
    use web_time_compat::InstantExt;

    /// In-memory writer backed by a shared `Vec`, so the test can read what the
    /// `NonBlocking` worker thread eventually flushed. `tracing_appender`'s
    /// worker owns one of these and calls `write_all` from its own thread; the
    /// test holds a clone of the `Arc` to inspect the result after the guard is
    /// dropped (which joins the worker's drain).
    struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // A poisoned lock would mean a writer panicked mid-write; recover
            // the inner value rather than poisoning the whole test.
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Connect a socket2 datagram client to the abstract-namespace socket that
    /// `start` bound for the bare `name`. This mirrors the cdylib's
    /// `connect_hook_socket` exactly: it prepends `\0` to the bare name, then
    /// connects over the abstract namespace. std's
    /// `UnixDatagram::connect` cannot reach abstract namespaces, so socket2 is
    /// used for the client side too. Exercising the real prepend-`\0` contract
    /// (instead of relying on a NUL-bearing name) is what makes the tests cover
    /// the cdylib connect path.
    fn connect_abstract(name: &str) -> anyhow::Result<Socket> {
        let sock = Socket::new(Domain::UNIX, Type::DGRAM, None)?;
        let addr = SockAddr::unix(Path::new(&format!("\0{}", name)))?;
        sock.connect(&addr)?;
        Ok(sock)
    }

    /// Poll a captured buffer until it contains `needle`, up to `timeout`. The
    /// `NonBlocking` worker flushes asynchronously from its own thread, so the
    /// bytes land in `captured` some time after `dispatch_frame` writes them.
    /// Tests wait for the expected output BEFORE canceling the recv loop:
    /// canceling first is safe (the post-cancel `try_recv` drain catches any
    /// queued datagram), but waiting here keeps the success assertion off the
    /// cancel race and fails fast if a datagram never lands. Blocking the test
    /// thread is fine: these tests use the multi-thread runtime, so worker
    /// threads keep draining while this thread sleeps.
    fn wait_for_contains(captured: &Arc<Mutex<Vec<u8>>>, needle: &[u8], timeout: Duration) {
        let start = web_time_compat::Instant::get();
        loop {
            let buf = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if buf.windows(needle.len()).any(|w| w == needle) {
                return;
            }
            if start.elapsed() > timeout {
                panic!("timed out waiting for {needle:?} in captured bytes (got {buf:?})");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Two datagrams (Info + Error) are decoded in order and both payloads land
    /// in the merged info writer (no error writer set, so the Error route falls
    /// back to info, mirroring `LevelRoutingWriter`).
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn collects_and_routes_datagrams_into_merged_nonblocking() -> anyhow::Result<()> {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let (info_nb, guard) = tracing_appender::non_blocking(CapturedWriter(captured.clone()));

        let (collector, name) = HookLogCollector::start(info_nb, None).await?;
        let (cancel_tx, cancel_rx) = oneshot::channel();
        #[allow(clippy::disallowed_methods)]
        let run_task = tokio::spawn(async move { collector.run(cancel_rx).await });

        let client = connect_abstract(&name)?;
        // Send one Info datagram then one Error datagram. With no error writer,
        // both must route to the info writer, in order. Each datagram is one
        // complete atomic frame.
        client.send(&encode_frame(Route::Info, b"info-line\n"))?;
        client.send(&encode_frame(Route::Error, b"error-line\n"))?;

        // Wait for the recv loop to flush both payloads through the NonBlocking
        // worker before canceling.
        wait_for_contains(
            &captured,
            b"info-line\nerror-line\n",
            Duration::from_secs(2),
        );

        let _ = cancel_tx.send(());
        let _ = run_task.await;

        // Dropping the guard joins the NonBlocking worker's drain, so by the
        // time this returns every queued payload is in `captured`.
        drop(guard);

        let merged = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(merged, b"info-line\nerror-line\n");
        Ok(())
    }

    /// A datagram with a bad route byte must be dropped without panicking and
    /// must NOT desync the collector: the very next well-formed datagram still
    /// lands. This is the datagram-transport robustness property a byte stream
    /// cannot offer.
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn bad_route_datagram_is_dropped_then_next_lands() -> anyhow::Result<()> {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let (info_nb, guard) = tracing_appender::non_blocking(CapturedWriter(captured.clone()));

        let (collector, name) = HookLogCollector::start(info_nb, None).await?;
        let (cancel_tx, cancel_rx) = oneshot::channel();
        #[allow(clippy::disallowed_methods)]
        let run_task = tokio::spawn(async move { collector.run(cancel_rx).await });

        let client = connect_abstract(&name)?;
        // A datagram whose route byte is not a known Route. decode_frame
        // rejects it (BadRoute) and the datagram is dropped.
        let mut bad = encode_frame(Route::Info, b"garbage\n");
        bad[0] = 0;
        client.send(&bad)?;
        // Then a well-formed datagram. Under a byte stream, a bad byte mid-stream
        // would misalign the decoder and swallow this too; under datagrams it
        // lands cleanly.
        client.send(&encode_frame(Route::Info, b"good-line\n"))?;

        // Wait for the good datagram to land; the bad-route datagram must never
        // appear in the captured bytes.
        wait_for_contains(&captured, b"good-line\n", Duration::from_secs(2));

        let _ = cancel_tx.send(());
        let _ = run_task.await;

        drop(guard);
        let merged = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            merged, b"good-line\n",
            "expected only the good frame; bad-route frame desynced the collector: {merged:?}"
        );
        Ok(())
    }

    /// Datagrams already queued in the kernel recv buffer when shutdown is
    /// signaled must still be delivered — either serviced by the recv loop
    /// or caught by the post-cancel `try_recv` drain. Cancel is pre-fulfilled
    /// before `run` is spawned, so the recv loop may break on its very first
    /// iteration; whatever it does not service must be drained. This exercises
    /// the "in-flight frames are not lost on shutdown" claim. The outcome is
    /// deterministic on correct code: the loop + drain together always deliver
    /// every buffered datagram; a regression that removes the drain would
    /// (flakily) lose datagrams when cancel preempts the recv loop.
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn queued_datagrams_survive_cancellation() -> anyhow::Result<()> {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let (info_nb, guard) = tracing_appender::non_blocking(CapturedWriter(captured.clone()));

        let (collector, name) = HookLogCollector::start(info_nb, None).await?;
        let (cancel_tx, cancel_rx) = oneshot::channel();

        // Queue three datagrams before run starts, so they sit in the kernel
        // recv buffer when the recv loop first polls.
        let client = connect_abstract(&name)?;
        client.send(&encode_frame(Route::Info, b"first\n"))?;
        client.send(&encode_frame(Route::Info, b"second\n"))?;
        client.send(&encode_frame(Route::Info, b"third\n"))?;

        // Pre-fulfill cancel, then spawn run: the select may break on its
        // first iteration, forcing the try_recv drain to catch whatever the
        // loop did not service.
        let _ = cancel_tx.send(());
        #[allow(clippy::disallowed_methods)]
        let run_task = tokio::spawn(async move { collector.run(cancel_rx).await });
        let _ = run_task.await;

        drop(guard);
        let merged = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            merged, b"first\nsecond\nthird\n",
            "queued datagrams lost on shutdown: {merged:?}"
        );
        Ok(())
    }

    /// A datagram larger than the old 64 KiB recv buffer (but within the
    /// kernel's ~210 KiB deliverable ceiling — verified by probe) must land
    /// WHOLE, not silently truncated to the buffer size. With `RECV_BUF_SIZE`
    /// sized above the kernel ceiling, `recv` never truncates a legitimate
    /// record; this test would fail under the old 64 KiB buffer (a 100 KiB
    /// datagram truncated to 65535 payload bytes). The `n == buf.len()` guard
    /// in `run` is defense-in-depth for a misbehaving sender that raises
    /// `SO_SNDBUF` past the default ceiling; it cannot be triggered here
    /// because the kernel `EMSGSIZE`s any datagram at or above the buffer.
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn large_datagram_is_delivered_whole_not_truncated() -> anyhow::Result<()> {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let (info_nb, guard) = tracing_appender::non_blocking(CapturedWriter(captured.clone()));

        let (collector, name) = HookLogCollector::start(info_nb, None).await?;
        let (cancel_tx, cancel_rx) = oneshot::channel();
        #[allow(clippy::disallowed_methods)]
        let run_task = tokio::spawn(async move { collector.run(cancel_rx).await });

        // 100 KiB payload: above the old 64 KiB buffer, well below the 256 KiB
        // buffer and the ~210 KiB kernel ceiling.
        let payload = vec![b'x'; 100 * 1024];
        let client = connect_abstract(&name)?;
        client.send(&encode_frame(Route::Info, &payload))?;

        // Wait for the full payload to flush through the NonBlocking worker.
        wait_for_contains(&captured, &payload, Duration::from_secs(2));

        let _ = cancel_tx.send(());
        let _ = run_task.await;

        drop(guard);
        let merged = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            merged.len(),
            payload.len(),
            "datagram truncated: got {} bytes, expected {}",
            merged.len(),
            payload.len()
        );
        assert!(
            merged.iter().all(|&b| b == b'x'),
            "datagram payload corrupted: {merged:?}"
        );
        Ok(())
    }

    /// With a separate error writer set, `Route::Error` datagrams demux into the
    /// error writer and `Route::Info` datagrams into the info writer, with no
    /// cross-contamination. This is the spec's central promised behavior: the
    /// collector only demuxes. Exercises the `(Route::Error, Some(e))` arm of
    /// `dispatch_frame` over a real abstract-namespace round-trip.
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn error_route_demuxes_to_error_writer() -> anyhow::Result<()> {
        let info_captured = Arc::new(Mutex::new(Vec::new()));
        let error_captured = Arc::new(Mutex::new(Vec::new()));
        let (info_nb, info_guard) =
            tracing_appender::non_blocking(CapturedWriter(info_captured.clone()));
        let (error_nb, error_guard) =
            tracing_appender::non_blocking(CapturedWriter(error_captured.clone()));

        let (collector, name) = HookLogCollector::start(info_nb, Some(error_nb)).await?;
        let (cancel_tx, cancel_rx) = oneshot::channel();
        #[allow(clippy::disallowed_methods)]
        let run_task = tokio::spawn(async move { collector.run(cancel_rx).await });

        let client = connect_abstract(&name)?;
        // One Info datagram then one Error datagram on the SAME shared socket:
        // the route byte must demux them into the two writers.
        client.send(&encode_frame(Route::Info, b"info-line\n"))?;
        client.send(&encode_frame(Route::Error, b"error-line\n"))?;

        // Wait for BOTH payloads to flush through their respective NonBlocking
        // workers before canceling.
        wait_for_contains(&info_captured, b"info-line\n", Duration::from_secs(2));
        wait_for_contains(&error_captured, b"error-line\n", Duration::from_secs(2));

        let _ = cancel_tx.send(());
        let _ = run_task.await;

        // Drop both guards so the NonBlocking workers drain before we inspect.
        drop(info_guard);
        drop(error_guard);

        let info_merged = info_captured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let error_merged = error_captured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        // Info payload lands in the info writer ONLY.
        assert_eq!(info_merged, b"info-line\n");
        // Error payload lands in the error writer ONLY (no Info leak, no
        // fall-through to the info writer).
        assert_eq!(error_merged, b"error-line\n");
        assert!(
            !info_merged
                .windows(b"error-line\n".len())
                .any(|w| w == b"error-line\n"),
            "error payload leaked into info writer: {info_merged:?}"
        );
        assert!(
            !error_merged
                .windows(b"info-line\n".len())
                .any(|w| w == b"info-line\n"),
            "info payload leaked into error writer: {error_merged:?}"
        );
        Ok(())
    }
}

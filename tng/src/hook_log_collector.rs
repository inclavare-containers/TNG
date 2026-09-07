//! Main-process collector for centralized hook logging.
//!
//! The `tng exec` process listens on an abstract-namespace Unix domain socket
//! (`\0tng-hook-log-<pid>`). The `tng-hook` cdylib (LD_PRELOAD'd into the
//! hooked child) connects to this socket and streams length-prefixed,
//! route-tagged frames (see `tng_hook_types::wire`). This module decodes those
//! frames and fans each payload into the main process's `info.log` /
//! `error.log` via cloned `NonBlocking` writers, so hook logs merge into the
//! same rolling files the main process owns.
//!
//! Abstract-namespace sockets are Linux-only (no filesystem path, no cleanup),
//! and the cdylib is Linux-only too, so this whole module is
//! `#[cfg(target_os = "linux")]`-gated (the module-level gate lives in
//! `lib.rs`; this file is only compiled on Linux).

use std::future::Future;
use std::io::{self, Write};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use socket2::{Domain, SockAddr, Socket, Type};
use tokio::io::AsyncReadExt;
use tokio::net::unix::SocketAddr;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing_appender::non_blocking::NonBlocking;

use tng_hook_types::{FrameDecoder, Route};

/// The future returned by an [`AcceptSource`]. Boxed so the loop is polymorphic
/// over the accept source (real `UnixListener` in prod, an injected
/// perpetually-`Err` source in the backoff behavioral test) without naming the
/// concrete `accept` future type. `+ Send` so the loop can run on the
/// multi-thread runtime; the elided lifetime ties the borrow to `&self`.
type AcceptFut<'a> =
    Pin<Box<dyn Future<Output = io::Result<(UnixStream, SocketAddr)>> + Send + 'a>>;

/// Source of accepted hook connections. Prod impls this for `UnixListener`;
/// tests impl it for a perpetually-failing source so the backoff path can be
/// exercised deterministically (a real listener cannot be made to fail
/// synchronously and persistently without fd hacks).
trait AcceptSource {
    fn accept(&self) -> AcceptFut<'_>;
}

impl AcceptSource for UnixListener {
    fn accept(&self) -> AcceptFut<'_> {
        Box::pin(<UnixListener>::accept(self))
    }
}

/// Read buffer size for each connection. A single formatted log line is well
/// under 8 KiB; a larger chunk simply carries several frames at once, which the
/// `FrameDecoder` handles regardless of buffer size.
const READ_BUF_SIZE: usize = 8 * 1024;

/// Cap on how long `run` waits for in-flight connection readers to finish after
/// cancel before forcing them down. A hooked child that hangs mid-read should
/// not block main-process shutdown indefinitely.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Number of consecutive accept errors that retry immediately, with no sleep,
/// before any backoff kicks in. A handful of transient failures (the common
/// case, e.g. a brief EMFILE spike) stay zero-latency; only sustained failures
/// back off.
const ACCEPT_BACKOFF_IMMEDIATE: u32 = 3;

/// Floor and ceiling for the accept-error backoff sleep (see `accept_backoff`).
/// Starts at 1 ms once the immediate-retry threshold is exceeded and doubles
/// per consecutive error, capped at 100 ms: a persistently broken listener
/// never spins at full tilt, but the collector never goes quiet for long
/// either (it is a logging path, not a hot server).
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(1);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_millis(100);

/// Backoff applied before re-accepting after `consecutive_errors` consecutive
/// accept failures. The first `ACCEPT_BACKOFF_IMMEDIATE` failures return
/// `Duration::ZERO` so transient errors (the common case) add no latency;
/// beyond that the sleep doubles per consecutive error up to
/// `ACCEPT_BACKOFF_MAX`. Pure so the run loop can stay a thin cancel-aware
/// shell around it.
///
/// `consecutive_errors` counts failures so far including the most recent one,
/// so `0` means "last accept succeeded" and yields `Duration::ZERO`.
fn accept_backoff(consecutive_errors: u32) -> Duration {
    if consecutive_errors <= ACCEPT_BACKOFF_IMMEDIATE {
        return Duration::ZERO;
    }
    // Saturating shift count: the cap dominates well before this bound, and a
    // large shift would overflow the millis value on huge counts (e.g. a
    // listener fd that never recovers). 7 keeps the un-capped value <= 128 ms
    // before the final `.min` clamps it to 100 ms.
    let shifts = (consecutive_errors - ACCEPT_BACKOFF_IMMEDIATE - 1).min(7);
    let millis = (ACCEPT_BACKOFF_MIN.as_millis() as u64) << shifts;
    let cap_millis: u64 = ACCEPT_BACKOFF_MAX
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    Duration::from_millis(millis.min(cap_millis))
}

/// Centralized hook log collector. Owns the listening socket and the cloned
/// `NonBlocking` writers that hook payloads are merged into. `run` spawns one
/// reader task per accepted connection inside a `JoinSet`, so a misbehaving or
/// panicking child is isolated from the rest.
pub struct HookLogCollector {
    listener: UnixListener,
    info_nb: NonBlocking,
    error_nb: Option<NonBlocking>,
}

impl HookLogCollector {
    /// Bind the abstract-namespace listener `\0tng-hook-log-<pid>` and return
    /// the BARE name `tng-hook-log-<pid>` (for `TNG_HOOK_LOG_SOCKET` env
    /// injection into hooked children) plus the collector, ready to `run`.
    ///
    /// The returned name carries no leading NUL: `setenv` uses NUL-terminated
    /// C strings, so a value starting with NUL would be truncated to empty,
    /// and the cdylib's `connect_hook_socket` prepends its own `\0` before
    /// connecting. The bind uses the `\0`-prefixed abstract name internally;
    /// callers inject the bare name into the child env verbatim.
    ///
    /// The socket is set non-blocking before being handed to tokio, so the
    /// accept loop never blocks the reactor on a stale fd. socket2 has no
    /// `From<Socket>` for `UnixListener`, so the conversion goes through the
    /// raw fd.
    pub async fn start(
        info_nb: NonBlocking,
        error_nb: Option<NonBlocking>,
    ) -> io::Result<(Self, String)> {
        let sock = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        // Bare name for env injection (no leading NUL): the cdylib prepends `\0`
        // itself when connecting, and setenv would truncate a NUL-bearing value.
        let name = format!("tng-hook-log-{}", std::process::id());
        // Bind with the `\0` prefix: leading NUL selects the abstract namespace
        // (no filesystem path, no unlink on exit, per-pid so names never collide).
        let addr = SockAddr::unix(Path::new(&format!("\0{}", name)))?;
        sock.bind(&addr)?;
        sock.listen(1024)?;
        // Non-blocking must be set before the fd leaves socket2's ownership so
        // tokio's registration sees a non-blocking fd.
        sock.set_nonblocking(true)?;
        let fd = sock.into_raw_fd();
        // SAFETY: `fd` is a valid bound listening non-blocking UNIX socket we
        // just created; `into_raw_fd` transferred ownership to us.
        let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
        let listener = UnixListener::from_std(std_listener)?;
        Ok((
            Self {
                listener,
                info_nb,
                error_nb,
            },
            name,
        ))
    }

    /// Accept loop. Each accepted connection is read by a per-connection task
    /// owned by a `JoinSet`; on cancel, in-flight readers are drained (up to
    /// `DRAIN_TIMEOUT`) and then shut down so a stuck reader cannot block
    /// shutdown. Sustained accept errors back off (see `accept_backoff`) so a
    /// persistently failing listener cannot busy-spin.
    pub async fn run(self, cancel: oneshot::Receiver<()>) {
        let Self {
            listener,
            info_nb,
            error_nb,
        } = self;
        run_loop(&listener, info_nb, error_nb, cancel).await;
    }
}

/// The accept loop, parameterized over an [`AcceptSource`] so the backoff path
/// is testable with an injected failing source. The body is SEQUENTIAL, not
/// concurrent: the backoff sleep is completed (cancel-raced) BEFORE accept is
/// polled. A concurrent `select!` over sleep + accept would let a
/// synchronously failing accept (`Poll::Ready(Err)`, e.g. EMFILE or a broken
/// listener fd) win every iteration before the sleep elapses, defeating the
/// backoff entirely. Here the sleep is its own cancel-raced `select!`, and
/// only after it completes (or is skipped, for the first few errors) does a
/// second cancel-raced `select!` poll accept. Cancel breaks out of BOTH
/// `select!`s immediately, so shutdown is never delayed by backoff.
async fn run_loop<A: AcceptSource>(
    acceptor: &A,
    info_nb: NonBlocking,
    error_nb: Option<NonBlocking>,
    mut cancel: oneshot::Receiver<()>,
) {
    let mut conns: JoinSet<()> = JoinSet::new();
    // Consecutive accept failures. Reset on any successful accept. A
    // persistently failing listener (e.g. EMFILE that never clears, or a
    // broken listener fd) would otherwise busy-spin the accept loop until
    // cancel fires; `accept_backoff` throttles that without adding latency
    // to the common transient case.
    let mut consecutive_errors: u32 = 0;
    loop {
        let backoff = accept_backoff(consecutive_errors);
        // 1. Cancel-raced backoff sleep, completed BEFORE polling accept. The
        // first `ACCEPT_BACKOFF_IMMEDIATE` errors yield `Duration::ZERO`, so
        // this is skipped and accept is polled immediately (zero added latency
        // for the common transient case). Cancel wins immediately here.
        if !backoff.is_zero() {
            tokio::select! {
                _ = &mut cancel => break,
                _ = tokio::time::sleep(backoff) => {}
            }
        }
        // 2. Cancel-raced accept. Only polled once the backoff (if any) has
        // actually elapsed, so a synchronous `Ready(Err)` cannot race past the
        // sleep. Cancel wins immediately here too.
        let accept = tokio::select! {
            _ = &mut cancel => break,
            res = acceptor.accept() => res,
        };
        match accept {
            Ok((conn, _peer)) => {
                consecutive_errors = 0;
                let info_nb = info_nb.clone();
                let error_nb = error_nb.clone();
                conns.spawn(async move {
                    serve_conn(conn, info_nb, error_nb).await;
                });
            }
            Err(error) => {
                consecutive_errors = consecutive_errors.saturating_add(1);
                // A transient accept failure (e.g. EMFILE) must not tear down
                // collection for every other child. Log and keep accepting; the
                // cancel branches above still break the loop on shutdown, and
                // `accept_backoff` (sleep next iteration) keeps a sustained
                // failure from busy-spinning.
                tracing::warn!(consecutive_errors, ?error, "hook log accept failed");
            }
        }
    }

    // Give in-flight readers a bounded chance to finish their current
    // frame, then force the rest down so shutdown is not held hostage by a
    // stuck child.
    let drain = async { while conns.join_next().await.is_some() {} };
    if timeout(DRAIN_TIMEOUT, drain).await.is_err() {
        tracing::warn!(
            "hook log connection drain did not complete within {:?}, aborting remaining readers",
            DRAIN_TIMEOUT
        );
    }
    conns.shutdown().await;
}

/// Read loop for one hook connection. Decodes `[route][len][payload]` frames
/// and writes each payload to the matching `NonBlocking` writer. `NonBlocking`
/// is lossy by default (`write_all` never blocks, never errors), so a slow
/// rolling appender cannot stall the hook log path.
///
/// Route dispatch: `Route::Error` goes to the error writer when one exists;
/// otherwise it falls back to the info writer (the "no separate error file"
/// case, mirroring `LevelRoutingWriter`'s behavior in the main subscriber).
/// `Route::Info` always goes to the info writer.
///
/// On EOF mid-frame (`read` returns 0 with a partial frame buffered), the
/// partial is dropped via `drain_partial` so a crashed hook truncates only its
/// own last record instead of leaking into the next connection's decode state.
async fn serve_conn(
    mut conn: UnixStream,
    mut info_nb: NonBlocking,
    mut error_nb: Option<NonBlocking>,
) {
    let mut decoder = FrameDecoder::new();
    let mut buf = vec![0u8; READ_BUF_SIZE];
    loop {
        match conn.read(&mut buf).await {
            Ok(0) => {
                // EOF: drop any buffered partial frame so a truncated final
                // record does not leak into the next connection.
                decoder.drain_partial();
                return;
            }
            Ok(n) => {
                decoder.push(&buf[..n]);
                // Drain every complete frame in the buffer before reading more;
                // one `read` may carry several frames or a partial of the next.
                while let Some(frame) = decoder.next_frame() {
                    match frame {
                        Ok((route, payload)) => {
                            // Disjoint mutable borrow: pick the writer for this
                            // route without cloning.
                            let target: &mut NonBlocking = match (route, &mut error_nb) {
                                (Route::Error, Some(e)) => e,
                                _ => &mut info_nb,
                            };
                            // Lossy + never blocks; a dropped line is
                            // preferable to stalling a hooked host.
                            let _ = target.write_all(&payload);
                        }
                        Err(error) => {
                            // The stream is desynchronized (bad route byte or
                            // an absurd length). The decoder has already
                            // cleared its buffer; continuing to read would
                            // misalign on the next length field. Drop the
                            // connection.
                            tracing::warn!(
                                ?error,
                                "hook log frame decode error; closing connection"
                            );
                            return;
                        }
                    }
                }
            }
            Err(error) => {
                tracing::warn!(?error, "hook log connection read error");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use serial_test::serial;
    use tng_hook_types::encode_frame;
    use web_time_compat::InstantExt;

    /// Accept source whose `accept` always resolves to a synchronous `Err`,
    /// simulating a persistently broken listener (EMFILE that never clears, a
    /// bad listener fd). Each call increments `calls`, so the behavioral test
    /// can count accept attempts and prove the loop is throttled rather than
    /// busy-spinning. This is why `run` is parameterized over [`AcceptSource`]:
    /// a real `UnixListener` cannot be made to fail synchronously and
    /// persistently without unsound fd hacks.
    struct AlwaysErr {
        calls: Arc<AtomicU64>,
    }

    impl AcceptSource for AlwaysErr {
        fn accept(&self) -> AcceptFut<'_> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Err(io::Error::other("persistent accept failure")) })
        }
    }

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

    /// Connect a socket2 client to the abstract-namespace listener that `start`
    /// bound for the bare `name`. This mirrors the cdylib's `connect_hook_socket`
    /// exactly: it prepends `\0` to the bare name, then connects over the
    /// abstract namespace. std's `UnixStream::connect` cannot reach abstract
    /// namespaces, so socket2 is used for the client side too. Exercising the
    /// real prepend-`\0` contract (instead of relying on a NUL-bearing name)
    /// is what makes the tests cover the cdylib connect path.
    fn connect_abstract(name: &str) -> anyhow::Result<Socket> {
        let sock = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        let addr = SockAddr::unix(Path::new(&format!("\0{}", name)))?;
        sock.connect(&addr)?;
        Ok(sock)
    }

    /// Poll a captured buffer until it contains `needle`, up to `timeout`. The
    /// `NonBlocking` worker flushes asynchronously from its own thread, so the
    /// bytes land in `captured` some time after `serve_conn` writes them. Tests
    /// must wait for the expected output BEFORE canceling the accept loop: the
    /// run loop's `select!` must poll `listener.accept()` at least once to
    /// register interest with the reactor, and if `cancel` is already sent
    /// when `select!` is first polled, the cancel branch wins without ever
    /// polling accept, so the connection is never accepted and `serve_conn`
    /// never runs. Polling the captured bytes for the expected output proves
    /// `serve_conn` ran before teardown. Blocking the test thread is fine:
    /// these tests use the multi-thread runtime, so worker threads keep
    /// draining while this thread sleeps.
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

    /// Two frames (Info + Error) on one connection are decoded in order and
    /// both payloads land in the merged info writer (no error writer set, so
    /// the Error route falls back to info, mirroring `LevelRoutingWriter`).
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn collects_and_routes_frames_into_merged_nonblocking() -> anyhow::Result<()> {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let (info_nb, guard) = tracing_appender::non_blocking(CapturedWriter(captured.clone()));

        let (collector, name) = HookLogCollector::start(info_nb, None).await?;
        let (cancel_tx, cancel_rx) = oneshot::channel();
        #[allow(clippy::disallowed_methods)]
        let run_task = tokio::spawn(async move { collector.run(cancel_rx).await });

        let mut client = connect_abstract(&name)?;
        // Send one Info frame then one Error frame. With no error writer, both
        // must route to the info writer, in order.
        let mut bytes = encode_frame(Route::Info, b"info-line\n");
        bytes.extend_from_slice(&encode_frame(Route::Error, b"error-line\n"));
        client.write_all(&bytes)?;
        // Signal EOF so serve_conn drains, then returns.
        client.shutdown(std::net::Shutdown::Write)?;

        // Wait for serve_conn to accept the connection and flush both payloads
        // through the NonBlocking worker BEFORE canceling. See
        // `wait_for_contains`: canceling first would race the accept poll.
        wait_for_contains(
            &captured,
            b"info-line\nerror-line\n",
            Duration::from_secs(2),
        );

        // Cancel the accept loop; run drains the now-completed serve_conn task
        // within the drain timeout.
        let _ = cancel_tx.send(());
        let _ = run_task.await;

        // Dropping the guard joins the NonBlocking worker's drain, so by the
        // time this returns every queued payload is in `captured`.
        drop(guard);

        let merged = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(merged, b"info-line\nerror-line\n");
        Ok(())
    }

    /// A connection that closes mid-frame (header + partial payload sent, then
    /// EOF) must not panic and must not emit a truncated record: the partial is
    /// dropped and the merged writer stays empty.
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn eof_mid_frame_is_dropped_not_panicked() -> anyhow::Result<()> {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let (info_nb, guard) = tracing_appender::non_blocking(CapturedWriter(captured.clone()));

        let (collector, name) = HookLogCollector::start(info_nb, None).await?;
        let (cancel_tx, cancel_rx) = oneshot::channel();
        #[allow(clippy::disallowed_methods)]
        let run_task = tokio::spawn(async move { collector.run(cancel_rx).await });

        let mut client = connect_abstract(&name)?;
        // A full frame for a 16-byte payload, truncated to header + 3 payload
        // bytes: the length field promises 16 but only 3 arrive.
        let full = encode_frame(Route::Info, b"complete payload");
        let partial = &full[..5 + 3];
        client.write_all(partial)?;
        client.shutdown(std::net::Shutdown::Write)?;

        // Give serve_conn time to accept and read the partial + EOF before
        // canceling, so the empty assertion below is not vacuously true from
        // serve_conn never running (the accept-poll race noted above). A
        // partial frame must never emit a record, so the buffer stays empty.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let _ = cancel_tx.send(());
        // serve_conn must return cleanly (no panic) on EOF mid-frame.
        let _ = run_task.await;

        drop(guard);
        let merged = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            merged.is_empty(),
            "partial frame leaked into the writer: {merged:?}"
        );
        Ok(())
    }

    /// With a separate error writer set, `Route::Error` frames demux into the
    /// error writer and `Route::Info` frames into the info writer, with no
    /// cross-contamination. This is the spec's central promised behavior: the
    /// collector only demuxes. Exercises the `(Route::Error, Some(e))` arm of
    /// `serve_conn` over a real abstract-namespace round-trip.
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

        let mut client = connect_abstract(&name)?;
        // One Info frame then one Error frame on the SAME connection: the
        // single shared socket must demux them into the two writers.
        let mut bytes = encode_frame(Route::Info, b"info-line\n");
        bytes.extend_from_slice(&encode_frame(Route::Error, b"error-line\n"));
        client.write_all(&bytes)?;
        client.shutdown(std::net::Shutdown::Write)?;

        // Wait for BOTH payloads to flush through their respective NonBlocking
        // workers before canceling. See `wait_for_contains`: canceling first
        // would race the accept poll and skip serving the connection.
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

    /// The first `ACCEPT_BACKOFF_IMMEDIATE` consecutive failures retry
    /// immediately: zero added latency for the common transient case.
    #[test]
    fn accept_backoff_first_errors_are_zero() {
        assert_eq!(accept_backoff(0), Duration::ZERO);
        assert_eq!(accept_backoff(1), Duration::ZERO);
        assert_eq!(accept_backoff(2), Duration::ZERO);
        assert_eq!(accept_backoff(ACCEPT_BACKOFF_IMMEDIATE), Duration::ZERO);
    }

    /// Sustained failures yield a nonzero, bounded, monotonically non-decreasing
    /// backoff that saturates at the cap, even for absurd error counts (a
    /// listener fd that never recovers).
    #[test]
    fn accept_backoff_grows_and_caps() {
        let first_nonzero = accept_backoff(ACCEPT_BACKOFF_IMMEDIATE + 1);
        assert!(
            first_nonzero > Duration::ZERO,
            "first sustained backoff must be nonzero, got {first_nonzero:?}"
        );
        assert!(first_nonzero >= ACCEPT_BACKOFF_MIN);
        assert!(first_nonzero <= ACCEPT_BACKOFF_MAX);

        let mut prev = Duration::ZERO;
        for n in 0..10_000 {
            let d = accept_backoff(n);
            assert!(d <= ACCEPT_BACKOFF_MAX, "n={n} d={d:?} exceeds cap");
            assert!(
                d >= prev,
                "n={n} d={d:?} shrunk below prev {prev:?} (non-monotonic)"
            );
            prev = d;
        }
        assert_eq!(accept_backoff(u32::MAX), ACCEPT_BACKOFF_MAX);
    }

    /// The exponential growth is bounded between the floor and the ceiling once
    /// it kicks in, with explicit checkpoints so a regression in the shift math
    /// (e.g. off-by-one in the threshold subtraction) is caught.
    #[test]
    fn accept_backoff_checkpoints() {
        // First sustained step is the floor (1 ms), doubling each failure.
        assert_eq!(
            accept_backoff(ACCEPT_BACKOFF_IMMEDIATE + 1),
            ACCEPT_BACKOFF_MIN
        );
        assert_eq!(
            accept_backoff(ACCEPT_BACKOFF_IMMEDIATE + 2),
            ACCEPT_BACKOFF_MIN * 2
        );
        assert_eq!(
            accept_backoff(ACCEPT_BACKOFF_IMMEDIATE + 3),
            ACCEPT_BACKOFF_MIN * 4
        );
        // Eventually saturates at the cap and stays there.
        assert_eq!(
            accept_backoff(ACCEPT_BACKOFF_IMMEDIATE + 100),
            ACCEPT_BACKOFF_MAX
        );
    }

    /// A persistently failing accept (synchronous `Ready(Err)` every call) must
    /// NOT busy-spin: with the sequential backoff, accept is only re-polled
    /// after the backoff sleep elapses, so a bounded window yields only a
    /// bounded number of accept attempts. A concurrent sleep+accept `select!`
    /// (the bug this round fixes) would let the ready `Err` win every iteration
    /// and rack up tens of thousands of calls in the same window. Counts via
    /// the injected `AlwaysErr` source, so the assertion is deterministic and
    /// not wall-clock-fragile (generous margins).
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn persistent_accept_error_is_throttled_not_busy_spin() -> anyhow::Result<()> {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let (info_nb, guard) = tracing_appender::non_blocking(CapturedWriter(captured.clone()));

        let calls = Arc::new(AtomicU64::new(0));
        let acceptor = AlwaysErr {
            calls: calls.clone(),
        };
        let (cancel_tx, cancel_rx) = oneshot::channel();
        #[allow(clippy::disallowed_methods)]
        let run_task =
            tokio::spawn(async move { run_loop(&acceptor, info_nb, None, cancel_rx).await });

        // Window large enough for the backoff to saturate at the 100 ms cap:
        // errors 1..=3 are immediate, 4..=10 take 1+2+4+8+16+32+64 = 127 ms,
        // then each takes ~100 ms. So a throttled loop does well under 20
        // attempts in 400 ms; a busy-spin would do >100k. 500 is a generous
        // non-flaky ceiling that still fails loudly on the bug.
        tokio::time::sleep(Duration::from_millis(400)).await;

        let _ = cancel_tx.send(());
        let _ = run_task.await;
        drop(guard);

        let observed = calls.load(Ordering::Relaxed);
        assert!(
            observed <= 500,
            "expected a throttled loop (<=500 accept calls in 400ms), got {observed} (busy-spin?)"
        );
        // Ensure the loop actually ran past the immediate-retry band, so a
        // regression that drops the sleep cannot pass vacuously with zero
        // iterations (e.g. if cancel raced first).
        assert!(
            observed > ACCEPT_BACKOFF_IMMEDIATE as u64,
            "expected the loop to iterate past the immediate-retry band, got {observed}"
        );
        Ok(())
    }
}

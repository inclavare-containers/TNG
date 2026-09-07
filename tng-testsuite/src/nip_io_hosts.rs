//! Test-only `/etc/hosts` shim so `peer_shared` serf tests that use
//! `<ip>.nip.io` hostnames resolve without external DNS.
//!
//! glibc `getaddrinfo` consults `/etc/hosts` (nsswitch `files`) *before* DNS,
//! so writing `192.168.1.X  192.168.1.X.nip.io` makes the name resolve to the
//! same IP nip.io would — even with DNS entirely unavailable. The TNG
//! hostname-resolution code path (`Host::Domain` ->
//! `TokioHostAddrResolver` -> `to_socket_addrs`) is exercised identically;
//! only the DNS network hop is elided (that is glibc's job, not TNG's).
//!
//! ## Concurrency model
//!
//! The block is reference-counted by advisory file locks rather than a
//! counter file, so the OS tracks "how many processes still need it":
//!
//! - A live process holds a **shared** (`LOCK_SH`) flock on `holders.lock`
//!   for its whole lifetime ("I am a user of the block").
//! - At exit it releases its shared lock, then tries a **non-blocking
//!   exclusive** (`LOCK_EX | LOCK_NB`) lock; success means no other process
//!   holds a shared lock, i.e. it is the last user, so it removes the block.
//!   If the try fails (`EWOULDBLOCK`), other live processes still need it,
//!   so the block is left untouched.
//!
//! This is crash-safe: a process killed with `SIGKILL` has its file
//! descriptors closed by the kernel, releasing its shared lock — so a
//! crashed process never pins the block forever (unlike a counter file,
//! which would leak a count). Only the last *normally*-exiting process
//! cleans up; if even that one is killed, the block is left behind, which
//! is harmless (the mappings equal nip.io's real answers) and self-healing
//! (the next `ensure` reuses the existing marker block).
//!
//! Within a single process, parallel test tasks share the one shared lock
//! (installed once via `OnceLock`); cleanup runs only at process exit
//! (`#[dtor]` / `atexit`), never when an individual test task finishes, so
//! no task can remove the block from under another.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use ctor::dtor;

/// Markers delimiting our managed block in `/etc/hosts`, so the block can be
/// found and replaced idempotently without touching unrelated entries.
const MARKER_BEGIN: &str = "# BEGIN tng-test nip.io (auto-managed, do not edit)";
const MARKER_END: &str = "# END tng-test nip.io";

/// The test bridge network is `192.168.1.0/24` (bridge at `.254`,
/// attestation service at `192.168.1.254:8080`). Generate the whole usable
/// host range up-front so every node IP the tests might use is covered.
const SUBNET_HOST_RANGE: std::ops::RangeInclusive<u8> = 1..=253;

const HOSTS_PATH: &str = "/etc/hosts";
const HOLDERS_LOCK: &str = "/run/tng-test-nipio-holders.lock";
const INSTALL_LOCK: &str = "/run/tng-test-nipio-install.lock";

/// Long-lived shared lock on `holders.lock`, kept open for the whole process
/// lifetime so the dtor knows this process is a live user. Held in a mutex so
/// the dtor can take it out and close it.
static HOLDERS_FD: Mutex<Option<File>> = Mutex::new(None);

/// Whether this process actually registered as a holder. The `#[dtor]` runs
/// for *every* binary linking this crate (not only the ohttp one), so it must
/// no-op for binaries that never called `ensure`.
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Ensure the nip.io hosts block is present. Idempotent and thread-safe
/// (installs at most once per process via `OnceLock`). Best-effort: on
/// failure it only logs a warning — tests that need root/netns already
/// require root, and a non-root run won't get far regardless.
pub fn ensure_nip_io_hosts() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        if let Err(error) = install() {
            tracing::warn!(
                ?error,
                "failed to ensure nip.io hosts entries; tests using them may fail with DNS resolution errors"
            );
        }
    });
}

/// Install (if absent) and register this process as a live holder.
fn install() -> Result<()> {
    let holders = install_block_at(HOSTS_PATH, HOLDERS_LOCK, INSTALL_LOCK)?;
    {
        let mut slot = HOLDERS_FD.lock().expect("HOLDERS_FD mutex poisoned");
        *slot = Some(holders);
    }
    INSTALLED.store(true, Ordering::SeqCst);
    Ok(())
}

/// fs-level install against the given paths. Returns the holders file
/// descriptor, which the caller must keep open for the process lifetime to
/// remain a live holder (its shared lock blocks other processes' cleanup).
///
/// Split out so the fs/flock logic is unit-testable against temp files
/// without touching the real `/etc/hosts` or `/run`.
fn install_block_at(hosts_path: &str, holders_path: &str, install_path: &str) -> Result<File> {
    // 1. Become a live holder FIRST (shared lock on holders.lock, kept open
    //    for the process lifetime). This prevents any other process's dtor
    //    from removing the block while we still need it: its exclusive try
    //    will fail against our shared lock.
    let holders = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(holders_path)
        .with_context(|| format!("failed to open holders lock {holders_path}"))?;
    flock(&holders, libc::LOCK_SH)?;

    // 2. Serialize the check+append under the install lock so two processes
    //    don't both decide "block absent" and both append (TOCTOU).
    let install_lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(install_path)
        .with_context(|| format!("failed to open install lock {install_path}"))?;
    flock(&install_lock, libc::LOCK_EX)?;

    let result = (|| -> Result<()> {
        let mut hosts = OpenOptions::new()
            .read(true)
            .write(true)
            .open(hosts_path)
            .with_context(|| format!("failed to open {hosts_path}"))?;
        let mut content = String::new();
        hosts
            .read_to_string(&mut content)
            .with_context(|| format!("failed to read {hosts_path}"))?;

        if has_block(&content) {
            // Already present (e.g. leftover from a prior, or a concurrent
            // process that installed first) — nothing to do.
            return Ok(());
        }

        let mut new_content = content;
        if !new_content.is_empty() && !new_content.ends_with('\n') {
            new_content.push('\n');
        }
        new_content.push_str(&generate_block());
        new_content.push('\n');

        rewrite_hosts(&mut hosts, &new_content)?;
        Ok(())
    })();

    // Release the install lock by closing the fd (done on drop).
    drop(install_lock);

    result.map(|_| holders)
}

/// Remove the block iff this process is the last live user.
#[dtor]
fn cleanup() {
    if !INSTALLED.load(Ordering::SeqCst) {
        // This process never installed (e.g. a non-ohttp test binary) —
        // nothing to undo.
        return;
    }
    if let Err(error) = cleanup_impl() {
        // Best-effort: never panic at process exit.
        eprintln!("tng-test nip.io hosts cleanup failed: {error:?}");
    }
}

fn cleanup_impl() -> Result<()> {
    // 1. Release this process's shared holder lock by closing the fd.
    let holders = HOLDERS_FD.lock().expect("HOLDERS_FD mutex poisoned").take();
    drop(holders); // closing releases our shared lock

    // 2. Remove the block iff we are the last live user.
    remove_block_if_last(HOSTS_PATH, HOLDERS_LOCK, INSTALL_LOCK)
}

/// Remove the managed block iff this is the last live user, against the given
/// paths. "Last user" = no other process holds a shared lock on the holders
/// lockfile, detected by a non-blocking exclusive lock attempt succeeding.
///
/// Split out so the cleanup path is unit-testable against temp files.
fn remove_block_if_last(hosts_path: &str, holders_path: &str, install_path: &str) -> Result<()> {
    // Try exclusive (non-blocking). Success => no other process holds a
    // shared lock => we are the last user => remove the block.
    let probe = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(holders_path)
        .with_context(|| format!("failed to open holders lock {holders_path}"))?;

    match try_flock_ex(&probe) {
        Ok(true) => {
            // Last user. Remove the block under the install lock so we
            // don't race a concurrent installer.
            let install_lock = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(install_path)
                .with_context(|| format!("failed to open install lock {install_path}"))?;
            flock(&install_lock, libc::LOCK_EX)?;

            let res = (|| -> Result<()> {
                let mut hosts = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(hosts_path)
                    .with_context(|| format!("failed to open {hosts_path}"))?;
                let mut content = String::new();
                hosts
                    .read_to_string(&mut content)
                    .with_context(|| format!("failed to read {hosts_path}"))?;

                if !has_block(&content) {
                    return Ok(());
                }
                let new = remove_block(&content);
                rewrite_hosts(&mut hosts, &new)?;
                Ok(())
            })();

            drop(install_lock);
            drop(probe); // release the exclusive holders lock

            res?;

            // Lockfiles are harmless leftovers, but tidy up best-effort now
            // that no one is using them.
            let _ = std::fs::remove_file(holders_path);
            let _ = std::fs::remove_file(install_path);
            Ok(())
        }
        Ok(false) => {
            // Other live processes still hold a shared lock — leave the
            // block for them.
            drop(probe);
            Ok(())
        }
        Err(error) => {
            drop(probe);
            Err(error)
        }
    }
}

/// Does `content` already contain our managed block?
fn has_block(content: &str) -> bool {
    content.contains(MARKER_BEGIN)
}

/// Build the managed block (without a trailing newline; caller adds one).
fn generate_block() -> String {
    let mut s = String::new();
    s.push_str(MARKER_BEGIN);
    s.push('\n');
    for host in SUBNET_HOST_RANGE {
        let ip = format!("192.168.1.{host}");
        let name = format!("{ip}.nip.io");
        s.push_str(&format!("{ip} {name}\n"));
    }
    s.push_str(MARKER_END);
    s
}

/// Remove the managed block (markers inclusive) from `content`. Also drops
/// the single newline immediately following the block so we don't leave a
/// blank line. Content without the block is returned unchanged.
fn remove_block(content: &str) -> String {
    let Some(begin) = content.find(MARKER_BEGIN) else {
        return content.to_string();
    };
    let Some(end_rel) = content[begin..].find(MARKER_END) else {
        return content.to_string();
    };
    let end = begin + end_rel + MARKER_END.len();

    let mut new = String::with_capacity(content.len() - (end - begin));
    new.push_str(&content[..begin]);
    // Skip one trailing newline after the block to avoid a blank line.
    let rest = &content[end..];
    let rest = rest.strip_prefix('\n').unwrap_or(rest);
    new.push_str(rest);
    new
}

/// Seek to start, write `new_content`, then truncate to exactly its length
/// (the file shrinks when a block is removed) and sync.
fn rewrite_hosts(hosts: &mut File, new_content: &str) -> Result<()> {
    hosts
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("failed to seek {HOSTS_PATH}"))?;
    hosts
        .write_all(new_content.as_bytes())
        .with_context(|| format!("failed to write {HOSTS_PATH}"))?;
    let new_len: i64 = new_content
        .len()
        .try_into()
        .context("hosts content length overflows i64")?;
    // ftruncate to the new length so a shrunk file has no stale tail.
    // SAFETY: fd is a valid open file descriptor; ftruncate sets the file
    // size and is safe to call from any context.
    let r = unsafe { libc::ftruncate(hosts.as_raw_fd(), new_len) };
    if r != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to truncate {HOSTS_PATH}"));
    }
    // Best-effort fsync so other processes see the change promptly.
    let _ = hosts.sync_all();
    Ok(())
}

/// Acquire a blocking advisory flock. Linux `flock(2)`.
fn flock(file: &File, op: i32) -> Result<()> {
    // SAFETY: `file` holds a valid open file descriptor; flock only mutates
    // the lock state of that description, which is safe.
    let r = unsafe { libc::flock(file.as_raw_fd(), op) };
    if r != 0 {
        Err(std::io::Error::last_os_error()).context("flock failed")
    } else {
        Ok(())
    }
}

/// Try to acquire an exclusive, non-blocking flock. Returns `Ok(true)` if
/// acquired, `Ok(false)` if it would block (someone else holds a shared
/// lock), or `Err` on a real failure.
fn try_flock_ex(file: &File) -> Result<bool> {
    // SAFETY: see `flock`.
    let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if r == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        // EWOULDBLOCK and EAGAIN are the same value on Linux, so use a
        // guard to avoid an unreachable-pattern warning while staying
        // correct on platforms where they differ.
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => Ok(false),
        Some(code) => Err(anyhow::anyhow!(
            "flock(LOCK_EX|LOCK_NB) failed: errno {code}"
        )),
        None => Err(anyhow::anyhow!(
            "flock(LOCK_EX|LOCK_NB) failed: unknown error"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_block_has_all_hosts_and_markers() {
        let block = generate_block();
        assert!(block.starts_with(MARKER_BEGIN));
        assert!(block.ends_with(MARKER_END));
        for host in SUBNET_HOST_RANGE {
            let line = format!("192.168.1.{host} 192.168.1.{host}.nip.io\n");
            assert!(block.contains(&line), "missing entry for .{host}");
        }
    }

    #[test]
    fn has_block_detects_marker() {
        assert!(!has_block("127.0.0.1 localhost\n"));
        assert!(has_block(&format!("{MARKER_BEGIN}\n{MARKER_END}")));
    }

    #[test]
    fn remove_block_strips_managed_section() {
        let before = format!(
            "127.0.0.1 localhost\n{MARKER_BEGIN}\n192.168.1.1 192.168.1.1.nip.io\n{MARKER_END}\n8.8.8.8 dns\n"
        );
        let after = remove_block(&before);
        assert_eq!(after, "127.0.0.1 localhost\n8.8.8.8 dns\n");
    }

    #[test]
    fn remove_block_absent_is_noop() {
        let before = "127.0.0.1 localhost\n";
        assert_eq!(remove_block(before), before);
    }

    #[test]
    fn remove_block_without_end_marker_is_noop() {
        // Malformed (begin without end) — don't corrupt, leave as-is.
        let before = format!("127.0.0.1 localhost\n{MARKER_BEGIN}\n8.8.8.8 dns\n");
        assert_eq!(remove_block(&before), before);
    }

    // --- fs / flock tests (against temp files; never touch /etc/hosts or /run) ---

    use tempfile::NamedTempFile;

    /// Read a path back to a String.
    fn read_path(p: &std::path::Path) -> String {
        std::fs::read_to_string(p).expect("read path")
    }

    /// Call `remove_block_if_last` until the block is gone from `hosts_path` or
    /// `timeout` elapses.
    ///
    /// `remove_block_if_last` reports "not the last user" (and leaves the block
    /// in place) the instant any other open file description holds a shared
    /// flock on the holders lockfile. In this parallel unit-test binary that is
    /// usually a genuinely concurrent holder, but it can also be a *transient*
    /// one: a sibling test that spawns a child via `tokio::process::Command`
    /// makes std spawn with `vfork`+`execvp` here (its `posix_spawn` fast-path
    /// is not taken for this spawn, so it falls back to `vfork`+`execvp`).
    /// `vfork` copies the fd table, and `O_CLOEXEC` only closes the inherited
    /// holder fd on the first *successful* `execve`, so while `execvp` walks
    /// `PATH` (several failing `execve` attempts) the child transiently shares
    /// this holder's open file description and keeps the shared flock alive.
    /// The child releases it within microseconds once `execve` succeeds. Polling
    /// absorbs that transient false-negative.
    ///
    /// This does not mask a real "another live holder" condition: the callers
    /// below drop every holder before calling this, so the only possible
    /// `Ok(false)` here is the transient one above; a genuine leftover holder
    /// would make this exhaust its attempts and panic loudly.
    fn remove_block_until_gone(
        hosts_path: &str,
        holders_path: &str,
        install_path: &str,
        timeout: std::time::Duration,
    ) {
        // `std::time::Instant::now` is repo-disallowed (wasm-unsafe, see
        // clippy.toml); bound the loop by a retry count derived from `timeout`
        // instead of a wall-clock deadline.
        const INTERVAL: std::time::Duration = std::time::Duration::from_millis(2);
        let attempts = (timeout.as_millis() / INTERVAL.as_millis().max(1)).max(1) as usize;
        for attempt in 0..attempts {
            remove_block_if_last(hosts_path, holders_path, install_path).expect("cleanup");
            if !has_block(&read_path(std::path::Path::new(hosts_path))) {
                return;
            }
            if attempt + 1 == attempts {
                panic!(
                    "block still present {timeout:?} after cleanup; \
                     remove_block_if_last never won the holders flock"
                );
            }
            std::thread::sleep(INTERVAL);
        }
    }

    #[test]
    fn rewrite_hosts_writes_and_truncates() {
        let mut f = NamedTempFile::new().expect("tmp");
        write!(f, "AAAAAAAAAA").expect("write");
        // Rewrite with shorter content: stale tail must be truncated.
        rewrite_hosts(f.as_file_mut(), "BB").expect("rewrite");
        assert_eq!(read_path(f.path()), "BB");
    }

    #[test]
    fn install_then_cleanup_last_user_removes_block() {
        let hosts = NamedTempFile::new().expect("tmp hosts");
        std::fs::write(hosts.path(), "127.0.0.1 localhost\n").expect("write");
        let dir = tempfile::tempdir().expect("tmp dir");
        let holders = dir.path().join("h.lock");
        let install = dir.path().join("i.lock");
        let hp = hosts.path().to_str().unwrap();
        let hp2 = holders.to_str().unwrap();
        let ip2 = install.to_str().unwrap();

        // Install: block appears, original content preserved.
        let holder_fd = install_block_at(hp, hp2, ip2).expect("install");
        let after_install = read_path(hosts.path());
        assert!(
            has_block(&after_install),
            "block should be present after install"
        );
        assert!(
            after_install.starts_with("127.0.0.1 localhost\n"),
            "original hosts content must be preserved"
        );

        // Simulate process exit: drop the holder fd (releases our SH).
        drop(holder_fd);

        // Cleanup as the last (only) user: block removed, content restored.
        // Polled: see `remove_block_until_gone` — a sibling test's `vfork` spawn
        // can transiently hold our shared flock during its `execvp` PATH walk.
        remove_block_until_gone(hp, hp2, ip2, std::time::Duration::from_secs(2));
        let after_cleanup = read_path(hosts.path());
        assert!(
            !has_block(&after_cleanup),
            "block should be gone after cleanup"
        );
        assert_eq!(after_cleanup, "127.0.0.1 localhost\n");
    }

    #[test]
    fn cleanup_skips_when_another_holder_still_alive() {
        // The core guarantee: a process exiting while another is still live
        // must NOT remove the block from under it.
        let hosts = NamedTempFile::new().expect("tmp hosts");
        std::fs::write(hosts.path(), "127.0.0.1 localhost\n").expect("write");
        let dir = tempfile::tempdir().expect("tmp dir");
        let holders = dir.path().join("h.lock");
        let install = dir.path().join("i.lock");
        let hp = hosts.path().to_str().unwrap();
        let hp2 = holders.to_str().unwrap();
        let ip2 = install.to_str().unwrap();

        // First holder installs the block.
        let holder_fd = install_block_at(hp, hp2, ip2).expect("install");
        assert!(has_block(&read_path(hosts.path())));

        // A SECOND process is still alive: it holds its own shared lock.
        let other_holder = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&holders)
            .expect("open holders");
        flock(&other_holder, libc::LOCK_SH).expect("SH lock");

        // First process exits (drops its SH). Cleanup must detect `other` and
        // leave the block in place.
        drop(holder_fd);
        remove_block_if_last(hp, hp2, ip2).expect("cleanup");
        assert!(
            has_block(&read_path(hosts.path())),
            "block must remain while another holder is alive"
        );

        // Now the second holder leaves and cleanup as last user removes it.
        // Polled: see `remove_block_until_gone` for the transient-flock caveat.
        drop(other_holder);
        remove_block_until_gone(hp, hp2, ip2, std::time::Duration::from_secs(2));
        assert!(!has_block(&read_path(hosts.path())));
    }

    #[test]
    fn remove_block_until_gone_panics_when_cleanup_never_wins() {
        // The polling helper's contract: if a *genuine* holder keeps the shared
        // flock forever, give up loudly after the timeout rather than hang. This
        // is what makes the "expect removal" callers safe -- a real leftover
        // holder surfaces as a test failure, not a silent wrong-pass. It also
        // exercises the retry/timeout path (sleep + deadline) of the helper.
        let hosts = NamedTempFile::new().expect("tmp hosts");
        std::fs::write(hosts.path(), "127.0.0.1 localhost\n").expect("write");
        let dir = tempfile::tempdir().expect("tmp dir");
        let holders = dir.path().join("h.lock");
        let install = dir.path().join("i.lock");
        let hp = hosts.path().to_str().unwrap();
        let hp2 = holders.to_str().unwrap();
        let ip2 = install.to_str().unwrap();

        // Install, then leave a stuck shared holder that never releases.
        let holder_fd = install_block_at(hp, hp2, ip2).expect("install");
        let stuck = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&holders)
            .expect("open holders");
        flock(&stuck, libc::LOCK_SH).expect("SH lock");
        drop(holder_fd); // only the stuck holder remains

        // Tiny timeout: the helper retries (2 ms sleeps) a few times, then the
        // deadline trips and it panics. Catch the panic so the test stays green.
        let result = std::panic::catch_unwind(|| {
            remove_block_until_gone(hp, hp2, ip2, std::time::Duration::from_millis(30))
        });
        drop(stuck);
        assert!(
            result.is_err(),
            "must panic when cleanup never wins the holders flock"
        );
    }

    #[test]
    fn install_is_idempotent() {
        let hosts = NamedTempFile::new().expect("tmp hosts");
        std::fs::write(hosts.path(), "127.0.0.1 localhost\n").expect("write");
        let dir = tempfile::tempdir().expect("tmp dir");
        let hp = hosts.path().to_str().unwrap().to_string();
        let hp2 = dir.path().join("h.lock");
        let hp2s = hp2.to_str().unwrap().to_string();
        let ip2 = dir.path().join("i.lock");
        let ip2s = ip2.to_str().unwrap().to_string();

        let _a = install_block_at(&hp, &hp2s, &ip2s).expect("install 1");
        let _b = install_block_at(&hp, &hp2s, &ip2s).expect("install 2");
        let content = read_path(hosts.path());
        assert_eq!(
            content.matches(MARKER_BEGIN).count(),
            1,
            "block must appear exactly once after repeated installs"
        );
    }

    #[test]
    fn try_flock_ex_false_when_shared_held_then_true_when_released() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let p = dir.path().join("lock");
        let holder = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&p)
            .expect("open");
        flock(&holder, libc::LOCK_SH).expect("SH");

        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&p)
            .expect("open probe");
        match try_flock_ex(&probe) {
            Ok(false) => {}
            Ok(true) => panic!("expected Ok(false) while a shared lock is held"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }

        // Release the shared holder; an exclusive try must now succeed.
        drop(holder);
        match try_flock_ex(&probe) {
            Ok(true) => {}
            other => panic!("expected Ok(true) after releasing the shared lock, got {other:?}"),
        }
    }
}

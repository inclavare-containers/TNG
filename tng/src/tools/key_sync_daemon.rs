//! File-exporting daemon that wraps the existing serf-based
//! `PeerSharedKeyManager` and mirrors the live cluster key set to disk.
//!
//! The serf engine (see `serf.rs`) already handles serf setup, RA-TLS QUIC
//! transport, preboot sync, master election, rotation, broadcast/query and
//! graceful shutdown. This module does NOT touch any of that; it only reads
//! the shared `cluster_key_set` (and the serf member list for `cluster.json`)
//! and writes a partitioned snapshot to `out_dir`.
//!
//! == Step 1 verdict: private-key export format (spec 6.4) ==
//! `ohttp::KeyConfig::dangerous_sk() -> Option<&PrivateKey>` exposes the raw
//! X25519 private key, and `PrivateKey::serialize_to_pkcs8_pem()` returns a
//! PKCS#8 PEM string (the same path `serf_message.rs` uses to ship keys over
//! the wire, and the same format `KeyInfo::from_pkcs8_pem` loads back). So the
//! key material is written as PKCS#8 PEM, round-trippable by the file-based
//! key manager. No base64/proto fallback is needed.
//!
//! == File naming: public-key hex, not key_id ==
//! Every key the serf engine generates is constructed with `KeyInfo::generate`
//! which hard-codes `key_id = 0` (see `serf.rs` preboot and
//! `cluster_key_set::generate_pending_key_if_none`). The cluster key set is
//! therefore indexed by public key, not by key_id; several keys (active +
//! pending + multiple stale) can all carry key_id 0 at once. Using `<key_id>`
//! as the filename would clobber sibling keys in the same role directory, so
//! the stem is the public-key hex, which is the unique identifier the cluster
//! key set itself keys by.

use crate::config::egress::PeerSharedArgs;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::PeerSharedKeyManager;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::{KeyInfo, KeyStatus};
use crate::tunnel::ohttp::key_config::PublicKeyData;
use crate::tunnel::utils::runtime::TokioRuntime;

use anyhow::{Context as _, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::time::Duration;
use web_time_compat::SystemTime;

/// Wraps a [`PeerSharedKeyManager`] and exports its cluster key set to disk.
///
/// Owns the manager directly; dropping the daemon drops the manager, whose
/// `serf` `Arc<SerfGracefulShutdown>` then runs the graceful serf leave as its
/// last owner goes away. The daemon reads the key set and cluster topology
/// through the manager's `pub(crate)` read accessors rather than reaching into
/// its internal fields.
pub struct KeySyncDaemon {
    mgr: PeerSharedKeyManager,
    out_dir: PathBuf,
    ready_file: Option<PathBuf>,
    rotation_interval: u64,
}

impl KeySyncDaemon {
    /// Bring up the serf engine (preboot sync, watchers) and prepare `out_dir`.
    /// On success the cluster key set is bootstrapped and the `--ready-file`
    /// is written so callers know exports are imminent.
    pub async fn new(
        runtime: TokioRuntime,
        args: PeerSharedArgs,
        out_dir: PathBuf,
        ready_file: Option<PathBuf>,
    ) -> Result<Self> {
        tokio::fs::create_dir_all(&out_dir)
            .await
            .with_context(|| format!("create out_dir {}", out_dir.display()))?;
        // The exported `.key` files are X25519 PKCS#8 private keys; lock the
        // directory to owner-only so other accounts cannot list/enumerate them.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&out_dir, std::fs::Permissions::from_mode(0o700))
                .await
                .with_context(|| format!("chmod 0700 out_dir {}", out_dir.display()))?;
        }

        let rotation_interval = args.rotation_interval;
        let mgr = PeerSharedKeyManager::new(runtime, args).await?;
        let daemon = Self {
            mgr,
            out_dir,
            ready_file,
            rotation_interval,
        };
        if let Some(rf) = &daemon.ready_file {
            write_ready_file(rf).await?;
        }
        Ok(daemon)
    }

    /// Initial export, then re-export on every key-change notification, on a
    /// quarter-rotation poll fallback, and stop on Ctrl-C. Holding `self`
    /// keeps the serf engine alive; on return `KeySyncDaemon` drops and the
    /// `SerfGracefulShutdown` Drop runs the graceful leave.
    pub async fn serve(self) -> Result<()> {
        self.export_snapshot().await?;

        // Bind the change-notify handle once: it is shared with the key
        // watcher, and `.notified()` borrows it across loop iterations.
        let check_notify = self.mgr.check_notify();

        loop {
            // Poll at rotation_interval/4 so a missed check_notify (e.g. across
            // a process boundary) still refreshes exports well inside one
            // rotation window. max(1) avoids a zero-second busy-loop.
            let poll_secs = (self.rotation_interval.max(1)) / 4;
            let poll = tokio::time::sleep(Duration::from_secs(poll_secs.max(1)));
            tokio::pin!(poll);

            tokio::select! {
                _ = check_notify.notified() => {}
                _ = &mut poll => {}
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("key-sync received Ctrl-C, shutting down");
                    break;
                }
            }

            if let Err(error) = self.export_snapshot().await {
                tracing::error!(?error, "key-sync file export failed");
            }
        }

        Ok(())
    }

    /// Snapshot the cluster key set (cloned out under a short read guard),
    /// then write the role-partitioned files and `cluster.json` with the lock
    /// released. Releasing the read guard before the async disk/serf calls
    /// keeps the key watcher's writes from blocking on file IO.
    ///
    /// Eventually-consistent on-disk view: the lock is dropped before the
    /// per-role writes, so a reader sampling mid-export may see a transient
    /// cross-role mix (e.g. `current/` rewritten but `next/` not yet); it
    /// converges on the next export.
    async fn export_snapshot(&self) -> Result<()> {
        let keys = self.mgr.snapshot_keys().await;
        let (current, next, expired) = partition_by_status(&keys);
        rewrite_role(&self.out_dir.join("current"), &current).await?;
        rewrite_role(&self.out_dir.join("next"), &next).await?;
        rewrite_role(&self.out_dir.join("expired"), &expired).await?;
        self.export_cluster_json().await?;
        Ok(())
    }

    /// Write `<out_dir>/cluster.json` with the local node id and the live
    /// member list. Mirrors the `StatusProvider` impl in `key_manager.rs`.
    async fn export_cluster_json(&self) -> Result<()> {
        let serf = self.mgr.serf();
        let local_node_id = serf.memberlist().local_id().to_string();

        let members = serf.members().await;
        let members_json: Vec<serde_json::Value> = members
            .iter()
            .map(|m| {
                serde_json::json!({
                    "node_id": m.node().to_string(),
                    "status": format!("{:?}", m.status).to_lowercase(),
                })
            })
            .collect();

        let cluster = serde_json::json!({
            "local_node_id": local_node_id,
            "members": members_json,
        });
        let bytes = serde_json::to_vec_pretty(&cluster).context("serialize cluster.json")?;
        write_if_changed(&self.out_dir.join("cluster.json"), &bytes, false).await?;
        Ok(())
    }
}

/// One role's worth of (public key, key info) pairs, cloned out of the cluster
/// key set so they can be written after the read guard is released.
type RoleKeys = Vec<(PublicKeyData, KeyInfo)>;

/// Partition a snapshot of the cluster key set by status into `current`
/// (Active), `next` (Pending) and `expired` (Stale). The input is the cloned
/// snapshot produced under the `cluster_key_set` read lock, so the caller can
/// write the partitions after the lock is released.
fn partition_by_status(keys: &[(PublicKeyData, KeyInfo)]) -> (RoleKeys, RoleKeys, RoleKeys) {
    let mut current = Vec::new();
    let mut next = Vec::new();
    let mut expired = Vec::new();
    for (pk, info) in keys {
        match info.status {
            KeyStatus::Active => current.push((pk.clone(), info.clone())),
            KeyStatus::Pending => next.push((pk.clone(), info.clone())),
            KeyStatus::Stale => expired.push((pk.clone(), info.clone())),
        }
    }
    (current, next, expired)
}

/// Rewrite one role directory: drop it when empty, otherwise create it, remove
/// files whose key left this role (and any crash-leftover `.tmp`), then write
/// each key's `.key` (PKCS#8 PEM) and `.meta.json` atomically. Writes are
/// diffed first so unchanged keys are not needlessly rewritten.
async fn rewrite_role(role_dir: &Path, keys: &[(PublicKeyData, KeyInfo)]) -> Result<()> {
    if keys.is_empty() {
        // Empty role -> directory must not exist.
        if tokio::fs::metadata(role_dir).await.is_ok() {
            let _ = tokio::fs::remove_dir_all(role_dir).await;
        }
        return Ok(());
    }

    tokio::fs::create_dir_all(role_dir)
        .await
        .with_context(|| format!("mkdir {}", role_dir.display()))?;
    // Role dirs hold private-key files; keep them owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(role_dir, std::fs::Permissions::from_mode(0o700))
            .await
            .with_context(|| format!("chmod 0700 {}", role_dir.display()))?;
    }

    let new_ids: HashSet<String> = keys
        .iter()
        .map(|(pk, _)| hex::encode(pk.as_ref()))
        .collect();

    // Remove files belonging to keys that left this role, plus stale .tmp
    // files from a crashed previous write. Files for keys still present are
    // left in place and re-diffed below.
    let mut to_remove = Vec::new();
    let mut read_dir = tokio::fs::read_dir(role_dir)
        .await
        .with_context(|| format!("read dir {}", role_dir.display()))?;
    while let Some(ent) = read_dir
        .next_entry()
        .await
        .with_context(|| format!("readdir {}", role_dir.display()))?
    {
        let name = ent.file_name();
        let s = name.to_string_lossy();
        let stem = s.split('.').next().unwrap_or("");
        let is_tmp = s.ends_with(".tmp");
        if is_tmp || !new_ids.contains(stem) {
            to_remove.push(ent.path());
        }
    }
    for p in to_remove {
        let _ = tokio::fs::remove_file(p).await;
    }

    for (pk, info) in keys {
        let id = hex::encode(pk.as_ref());
        let material = material_bytes(info)?;
        // `.key` is a PKCS#8 private key; create the temp file 0600 before the
        // atomic rename so the private key is never world-readable on disk.
        write_if_changed(&role_dir.join(format!("{id}.key")), &material, true).await?;
        let meta = serde_json::to_vec_pretty(&meta_json(pk, info))
            .with_context(|| format!("serialize meta for {id}"))?;
        write_if_changed(&role_dir.join(format!("{id}.meta.json")), &meta, false).await?;
    }
    Ok(())
}

/// PKCS#8 PEM body for a `.key` file (see the top-of-file verdict).
fn material_bytes(info: &KeyInfo) -> Result<Vec<u8>> {
    let pem = info
        .key_config
        .dangerous_sk()
        .context("missing private key in key config")?
        .serialize_to_pkcs8_pem()
        .context("serialize private key to PKCS#8 PEM")?;
    Ok(pem.into_bytes())
}

/// Per-key metadata: key id, public key hex, KEM/suites, status, and the three
/// lifecycle timestamps as ISO 8601 (RFC 3339) strings.
fn meta_json(pk: &PublicKeyData, info: &KeyInfo) -> serde_json::Value {
    let suites: Vec<serde_json::Value> = info
        .key_config
        .symmetric()
        .iter()
        .map(|s| {
            serde_json::json!({
                "kdf": format!("{:?}", s.kdf()),
                "aead": format!("{:?}", s.aead()),
            })
        })
        .collect();

    serde_json::json!({
        "key_id": info.key_config.key_id(),
        "public_key": hex::encode(pk.as_ref()),
        "kem": format!("{:?}", info.key_config.kem()),
        "suites": suites,
        "status": serde_json::to_value(info.status).unwrap_or(serde_json::Value::Null),
        "actived_at": iso8601(info.actived_at),
        "stale_at": iso8601(info.stale_at),
        "expire_at": iso8601(info.expire_at),
    })
}

/// SystemTime -> RFC 3339 string (UTC), mirroring `format_system_time` in
/// `key_manager/mod.rs`.
fn iso8601(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339()
}

/// Write `bytes` to `path` via a sibling `.tmp` then rename, but only if the
/// current content differs (avoids redundant disk churn and keeps readers from
/// observing a half-written file). When `secret` is true the temp file is
/// created owner-only (0600 on unix) before the rename, for private-key files.
async fn write_if_changed(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    if let Ok(existing) = tokio::fs::read(path).await {
        if existing.as_slice() == bytes {
            return Ok(());
        }
    }
    let tmp = tmp_sibling(path);
    if secret {
        write_secret_file(&tmp, bytes).await?;
    } else {
        tokio::fs::write(&tmp, bytes)
            .await
            .with_context(|| format!("write tmp {}", tmp.display()))?;
    }
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Create a private-key temp file owner-only (0600) then write `bytes`, so the
/// key is never world-readable between create and the atomic rename.
#[cfg(unix)]
async fn write_secret_file(tmp: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(tmp)
        .with_context(|| format!("open secret tmp {}", tmp.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("write secret tmp {}", tmp.display()))?;
    Ok(())
}

/// Non-unix fallback: no file-mode concept, so a plain write (the temp sibling
/// + rename still keeps readers from seeing a half-written file).
#[cfg(not(unix))]
async fn write_secret_file(tmp: &Path, bytes: &[u8]) -> Result<()> {
    tokio::fs::write(tmp, bytes)
        .await
        .with_context(|| format!("write tmp {}", tmp.display()))
}

/// `<dir>/<name>` -> `<Dir>/<name>.tmp` (sibling, same filesystem -> rename is
/// atomic). Built from the file name so it works for both `<id>.key` and
/// `<id>.meta.json`.
fn tmp_sibling(path: &Path) -> PathBuf {
    let mut name = match path.file_name() {
        Some(n) => n.to_os_string(),
        None => PathBuf::from("keysync.tmp").into_os_string(),
    };
    name.push(".tmp");
    path.with_file_name(name)
}

/// Atomically write a ready marker so an external supervisor can poll for it.
async fn write_ready_file(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create ready_file parent {}", parent.display()))?;
    }
    write_if_changed(path, b"ready\n", false).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::egress::PeerSharedArgs;
    use crate::config::ra::RaArgsUnchecked;
    use crate::tests::run_test_with_tokio_runtime;
    use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::ClusterKeySet;
    use crate::tunnel::egress::protocol::ohttp::security::key_manager::KeyStatus;
    use crate::tunnel::ohttp::key_config::KeyConfigExtend;
    use web_time_compat::{Duration, Instant, InstantExt, SystemTime, SystemTimeExt as _};

    /// Test-only wrapper: partition then rewrite the three role dirs, the same
    /// sequence `KeySyncDaemon::export_snapshot` runs (minus `cluster.json`).
    async fn export_keyset(out_dir: &Path, cks: &ClusterKeySet) -> Result<()> {
        let keys: Vec<(PublicKeyData, KeyInfo)> = cks
            .iter_keys()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let (current, next, expired) = partition_by_status(&keys);
        rewrite_role(&out_dir.join("current"), &current).await?;
        rewrite_role(&out_dir.join("next"), &next).await?;
        rewrite_role(&out_dir.join("expired"), &expired).await?;
        Ok(())
    }

    /// Build a `ClusterKeySet` with one key per status, via the public
    /// `new`/`insert_key_from_peer` constructors (no serf needed).
    fn make_test_keyset() -> ClusterKeySet {
        let now = SystemTime::get();
        let active = KeyInfo::generate(1, KeyStatus::Active, now, 300).unwrap();
        let pending =
            KeyInfo::generate(2, KeyStatus::Pending, now + Duration::from_secs(100), 300).unwrap();
        let stale =
            KeyInfo::generate(3, KeyStatus::Stale, now - Duration::from_secs(1000), 300).unwrap();

        let pk_active = active.key_config.public_key().unwrap();
        let pk_pending = pending.key_config.public_key().unwrap();
        let pk_stale = stale.key_config.public_key().unwrap();

        let mut cks = ClusterKeySet::new(pk_active, active, 300);
        assert!(cks.insert_key_from_peer(pk_pending, pending));
        assert!(cks.insert_key_from_peer(pk_stale, stale));
        cks
    }

    fn list_key_stems(dir: &Path) -> Vec<String> {
        // Tolerate a not-yet-created role dir (callers that poll for a key to
        // appear race the first export); a missing dir simply means no keys.
        let mut v: Vec<String> = match std::fs::read_dir(dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().ends_with(".key"))
                .map(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .trim_end_matches(".key")
                        .to_string()
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        v.sort();
        v
    }

    /// Read and parse `<out_dir>/cluster.json` (must exist).
    fn read_cluster_json(out_dir: &Path) -> serde_json::Value {
        let p = out_dir.join("cluster.json");
        let bytes =
            std::fs::read(&p).unwrap_or_else(|_| panic!("read cluster.json at {}", p.display()));
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("parse cluster.json at {}", p.display()))
    }

    /// Wait until the node's serf memberlist reaches `n` members. Member
    /// discovery is eventually consistent across the gossip layer, so the caller
    /// must refresh exports (`export_snapshot`) before asserting `cluster.json`.
    async fn wait_for_member_count(
        mgr: &PeerSharedKeyManager,
        n: usize,
        timeout: Duration,
    ) -> Result<()> {
        let start = Instant::get();
        loop {
            if mgr.serf().members().await.len() >= n {
                return Ok(());
            }
            if start.elapsed() > timeout {
                let count = mgr.serf().members().await.len();
                anyhow::bail!("timeout waiting for {n} members, got {count}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Partitioning: Active->current, Pending->next, Stale->expired; each role
    /// has its key + meta; an absent role has no directory.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn export_partitions_by_status() {
        let dir = tempfile::tempdir().unwrap();
        let cks = make_test_keyset();
        export_keyset(dir.path(), &cks).await.unwrap();

        assert!(dir.path().join("current").exists());
        assert!(dir.path().join("next").exists());
        assert!(dir.path().join("expired").exists());

        // Exactly one .key per role, plus its .meta.json sibling.
        for role in ["current", "next", "expired"] {
            let role_dir = dir.path().join(role);
            let keys = list_key_stems(&role_dir);
            assert_eq!(keys.len(), 1, "{role} should have one key");
            let stem = &keys[0];
            assert!(
                role_dir.join(format!("{stem}.key")).exists(),
                "missing .key"
            );
            assert!(
                role_dir.join(format!("{stem}.meta.json")).exists(),
                "missing .meta.json"
            );
        }

        // cluster.json is written by the daemon, not export_keyset; not present here.
    }

    /// Re-export after a rotation must remove the old key from `current` and
    /// not leave stale files behind, while the new key appears.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn re_export_cleans_leftover_keys() {
        let dir = tempfile::tempdir().unwrap();

        // First snapshot: one active key in current.
        let cks_before = {
            let now = SystemTime::get();
            let k = KeyInfo::generate(1, KeyStatus::Active, now, 300).unwrap();
            ClusterKeySet::new(k.key_config.public_key().unwrap(), k, 300)
        };
        export_keyset(dir.path(), &cks_before).await.unwrap();
        let before = list_key_stems(&dir.path().join("current"));
        assert_eq!(before.len(), 1);

        // Second snapshot: a different active key (old one is gone).
        let cks_after = {
            let now = SystemTime::get();
            let k = KeyInfo::generate(2, KeyStatus::Active, now, 300).unwrap();
            ClusterKeySet::new(k.key_config.public_key().unwrap(), k, 300)
        };
        export_keyset(dir.path(), &cks_after).await.unwrap();
        let after = list_key_stems(&dir.path().join("current"));
        assert_eq!(after.len(), 1, "only the new active key should remain");
        assert_ne!(after[0], before[0], "the active key should have changed");
        assert!(
            !dir.path()
                .join("current")
                .join(format!("{}.key", before[0]))
                .exists(),
            "old key file must be removed from current"
        );
    }

    /// An empty role must have its directory removed; a role that becomes empty
    /// on re-export drops its directory.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn empty_role_dir_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let cks = make_test_keyset();
        export_keyset(dir.path(), &cks).await.unwrap();
        assert!(dir.path().join("expired").exists());

        // Re-export with no stale key -> expired/ must vanish.
        let now = SystemTime::get();
        let active = KeyInfo::generate(1, KeyStatus::Active, now, 300).unwrap();
        let pending =
            KeyInfo::generate(2, KeyStatus::Pending, now + Duration::from_secs(100), 300).unwrap();
        let mut cks2 = ClusterKeySet::new(active.key_config.public_key().unwrap(), active, 300);
        cks2.insert_key_from_peer(pending.key_config.public_key().unwrap(), pending);
        export_keyset(dir.path(), &cks2).await.unwrap();
        assert!(
            !dir.path().join("expired").exists(),
            "expired/ removed when empty"
        );
    }

    /// `write_if_changed` skips the write (and the rename) when content matches.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unchanged_file_not_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.key");
        write_if_changed(&path, b"hello", false).await.unwrap();
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();

        // Small sleep so a rewrite would move the mtime on this filesystem.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        write_if_changed(&path, b"hello", false).await.unwrap();
        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(
            mtime_before, mtime_after,
            "identical content must not be rewritten"
        );
    }

    /// `.meta.json` carries the expected fields and the public-key hex matches
    /// the file stem.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn meta_json_fields_and_stem() {
        let dir = tempfile::tempdir().unwrap();
        let cks = make_test_keyset();
        export_keyset(dir.path(), &cks).await.unwrap();

        let current = dir.path().join("current");
        let key_file = std::fs::read_dir(&current)
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().ends_with(".key"))
            .unwrap();
        let stem = key_file
            .file_name()
            .to_string_lossy()
            .trim_end_matches(".key")
            .to_string();

        let meta_path = current.join(format!("{stem}.meta.json"));
        let meta: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
        assert_eq!(
            meta["public_key"], stem,
            "public_key must equal the file stem"
        );
        assert_eq!(meta["status"], "Active");
        assert!(meta["kem"].is_string());
        assert!(meta["suites"].is_array() && !meta["suites"].as_array().unwrap().is_empty());
        assert!(meta["actived_at"].is_string());
        assert!(meta["stale_at"].is_string());
        assert!(meta["expire_at"].is_string());

        // The .key file is a PKCS#8 PEM block.
        let key_pem = std::fs::read_to_string(key_file.path()).unwrap();
        assert!(
            key_pem.contains("-----BEGIN PRIVATE KEY-----"),
            "expected PKCS#8 PEM"
        );
    }

    /// Private-key files (`.key`) are owner-only (0600) and the role dirs are
    /// 0700, so exported secrets are not world-readable on disk.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn secret_files_and_role_dirs_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cks = make_test_keyset();
        export_keyset(dir.path(), &cks).await.unwrap();

        for role in ["current", "next", "expired"] {
            let role_dir = dir.path().join(role);
            let mode = std::fs::metadata(&role_dir).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o700,
                "{role} dir must be 0700, got {:o}",
                mode & 0o777
            );
            for entry in std::fs::read_dir(&role_dir).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name();
                let s = name.to_string_lossy();
                let mode = std::fs::metadata(entry.path())
                    .unwrap()
                    .permissions()
                    .mode();
                if s.ends_with(".key") {
                    assert_eq!(
                        mode & 0o777,
                        0o600,
                        "{s} must be 0600, got {:o}",
                        mode & 0o777
                    );
                }
            }
        }
    }

    /// Two-node sync + rotation over no_ra serf (no AA/AS needed): both nodes
    /// export the same active key, and after a rotation cycle the active key
    /// changes on both. Mirrors the proven serf tests in `serf.rs`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn two_node_export_syncs_and_rotates() {
        run_test_with_tokio_runtime(async |runtime| {
            let port_a = portpicker::pick_unused_port().unwrap();
            let port_b = portpicker::pick_unused_port().unwrap();
            let dir_a = tempfile::tempdir().unwrap();
            let dir_b = tempfile::tempdir().unwrap();

            let make = |port: u16, peers: Vec<String>, rotation: u64| PeerSharedArgs {
                rotation_interval: rotation,
                host: "127.0.0.1".to_string(),
                port,
                peers,
                peers_file: None,
                ra_args: RaArgsUnchecked {
                    no_ra: true,
                    attest: None,
                    verify: None,
                },
            };

            let daemon_a = KeySyncDaemon::new(
                runtime.clone(),
                make(port_a, vec![], 2),
                dir_a.path().to_path_buf(),
                None,
            )
            .await?;
            daemon_a.export_snapshot().await?;
            let a_initial = list_key_stems(&dir_a.path().join("current"));
            assert_eq!(a_initial.len(), 1, "A should export one active key");

            tokio::time::sleep(Duration::from_secs(1)).await;
            let daemon_b = KeySyncDaemon::new(
                runtime.clone(),
                make(port_b, vec![format!("127.0.0.1:{}", port_a)], 2),
                dir_b.path().to_path_buf(),
                None,
            )
            .await?;
            daemon_b.export_snapshot().await?;

            // B must have synced A's active key (same file stem in current/).
            let deadline = Instant::get() + Duration::from_secs(15);
            loop {
                let b_current = list_key_stems(&dir_b.path().join("current"));
                if b_current == a_initial {
                    break;
                }
                if Instant::get() > deadline {
                    daemon_b.export_snapshot().await?;
                    let b_current = list_key_stems(&dir_b.path().join("current"));
                    anyhow::bail!("B did not sync A's active key: A={a_initial:?} B={b_current:?}");
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                daemon_b.export_snapshot().await?;
            }

            // Both nodes must export cluster.json carrying the local node id
            // and the two-member roster. Member discovery is eventually
            // consistent across the gossip layer, so wait for convergence then
            // refresh exports before asserting the on-disk json.
            wait_for_member_count(&daemon_a.mgr, 2, Duration::from_secs(15)).await?;
            wait_for_member_count(&daemon_b.mgr, 2, Duration::from_secs(15)).await?;
            let local_a = daemon_a.mgr.serf().memberlist().local_id().to_string();
            let local_b = daemon_b.mgr.serf().memberlist().local_id().to_string();
            daemon_a.export_snapshot().await?;
            daemon_b.export_snapshot().await?;
            for (dir, expected_local) in [(dir_a.path(), local_a), (dir_b.path(), local_b)] {
                let cluster = read_cluster_json(dir);
                let local = cluster["local_node_id"].as_str().with_context(|| {
                    format!(
                        "cluster.json local_node_id is a string at {}",
                        dir.display()
                    )
                })?;
                assert_eq!(
                    local, expected_local,
                    "local_node_id must match the serf local id"
                );
                let members = cluster["members"].as_array().with_context(|| {
                    format!("cluster.json members is an array at {}", dir.display())
                })?;
                assert_eq!(members.len(), 2, "cluster.json lists 2 members");
                for m in members {
                    assert!(
                        m["node_id"]
                            .as_str()
                            .map(|s| !s.is_empty())
                            .unwrap_or(false),
                        "member node_id must be a non-empty string"
                    );
                    assert!(
                        m["status"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
                        "member status must be a non-empty string"
                    );
                }
            }

            // Wait for a rotation cycle (2s interval -> stale@2s, expire@4s).
            tokio::time::sleep(Duration::from_secs(10)).await;
            daemon_a.export_snapshot().await?;
            daemon_b.export_snapshot().await?;
            let a_after = list_key_stems(&dir_a.path().join("current"));
            let b_after = list_key_stems(&dir_b.path().join("current"));
            assert_eq!(
                a_after.len(),
                1,
                "A current still has one key after rotation"
            );
            assert_ne!(a_after, a_initial, "A active key should have rotated");
            assert_eq!(
                a_after, b_after,
                "A and B should agree on the rotated active key"
            );

            Ok(())
        })
        .await
        .expect("two_node_export_syncs_and_rotates failed");
    }

    /// `serve()`'s event loop must re-export on the key-change notification
    /// (`check_notify`), not only on the `rotation_interval/4` poll fallback.
    /// With a long rotation interval the poll fallback is far away, so a
    /// re-export observed inside the test's bounded window can only come from
    /// the notify path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn serve_reexports_on_check_notify() {
        run_test_with_tokio_runtime(async |runtime| {
            let port = portpicker::pick_unused_port().unwrap();
            let dir = tempfile::tempdir().unwrap();

            // rotation_interval 600s -> poll fallback 150s; any re-export within
            // the test's 10s window must come from check_notify, not polling.
            let args = PeerSharedArgs {
                rotation_interval: 600,
                host: "127.0.0.1".to_string(),
                port,
                peers: vec![],
                peers_file: None,
                ra_args: RaArgsUnchecked {
                    no_ra: true,
                    attest: None,
                    verify: None,
                },
            };

            let daemon =
                KeySyncDaemon::new(runtime.clone(), args, dir.path().to_path_buf(), None)
                    .await?;

            // serve() consumes self; clone the manager so we can drive a
            // key-set mutation and the shared notify from outside the task.
            // The clone shares the inner Arc, so an injected key is visible to
            // serve()'s watcher exactly like a peer-sent key.
            let mgr = daemon.mgr.clone();
            let check_notify = mgr.check_notify();
            let serve_handle = runtime.spawn_unsupervised_task_current_span(async move {
                daemon.serve().await
            });

            // Run the probe in a block so serve_handle is always aborted, even
            // when the probe bails early; otherwise the serve() task would keep
            // the serf engine alive and stall the runtime's graceful shutdown.
            let probe: Result<()> = async {
                // Wait for the initial export: exactly one active key in current/.
                let initial = {
                    let deadline = Instant::get() + Duration::from_secs(10);
                    loop {
                        let stems = list_key_stems(&dir.path().join("current"));
                        if stems.len() == 1 {
                            break stems;
                        }
                        if Instant::get() > deadline {
                            anyhow::bail!("serve() initial export did not land within 10s");
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                };

                // Inject a pending key via the real peer-sent path
                // (insert_key_from_peer), which fires check_notify. The key
                // watcher won't rotate it (actived_at is 100s in the future) and
                // won't generate another pending one (one already exists), so
                // the only observable effect is serve() re-exporting into next/.
                let now = SystemTime::get();
                let pending = KeyInfo::generate(
                    2,
                    KeyStatus::Pending,
                    now + Duration::from_secs(100),
                    600,
                )
                .context("generate pending key")?;
                let pk = pending
                    .key_config
                    .public_key()
                    .context("pending key public key")?;
                assert!(
                    mgr.inject_peer_key(pk.clone(), pending).await,
                    "injected pending key must be new"
                );
                let injected_stem = hex::encode(pk.as_ref());

                // check_notify is shared with the key watcher, so a single
                // notify_one() permit may be consumed by the watcher instead of
                // serve(). notify_waiters() wakes every waiter currently parked
                // on the notify (serve() included), so rearming it in a loop
                // deterministically drives serve()'s re-export. The 150s poll
                // fallback cannot explain a re-export landing in this 10s window.
                let deadline = Instant::get() + Duration::from_secs(10);
                loop {
                    if list_key_stems(&dir.path().join("next"))
                        .iter()
                        .any(|s| s == &injected_stem)
                    {
                        break;
                    }
                    if Instant::get() > deadline {
                        anyhow::bail!(
                            "serve() did not re-export the injected pending key via check_notify within 10s; next/={:?}",
                            list_key_stems(&dir.path().join("next"))
                        );
                    }
                    check_notify.notify_waiters();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }

                // current/ is unchanged: the active key was not touched.
                let current_now = list_key_stems(&dir.path().join("current"));
                assert_eq!(current_now, initial, "active key must be unchanged");
                Ok(())
            }
            .await;

            serve_handle.abort();
            let _ = serve_handle.await;
            probe
        })
        .await
        .expect("serve_reexports_on_check_notify failed");
    }
}

//! Two-node `tng tools key-sync` daemon integration test.
//!
//! Spawns two `key-sync` daemons in-process (bootstrap A, then B joining A),
//! each with a short rotation interval, and asserts the file-export contract:
//! both nodes export the same active key, and after a rotation cycle the active
//! key changes on both. Mirrors the rats-tls testsuite tests: it drives the real
//! `tng::tools::key_sync::run` (the same code path as the `tng tools key-sync`
//! CLI), which builds a `PeerSharedArgs` from real `--attest`/`--verify` RA
//! configs, so the serf RA-TLS QUIC transport needs a live Attestation Agent
//! (`make test-dep-aa`) and Attestation Service (`restful-as` at 127.0.0.1:8080;
//! `make test-dep-as` is broken in this env, start it directly). Start both
//! before running this test.

use std::time::Duration;

use anyhow::{Context as _, Result};
use tng::tools::cli::KeySyncOptions;
use tng::tools::key_sync;

static INIT: std::sync::Once = std::sync::Once::new();

const ATTEST_AA_UDS: &str = r#"{"model":"background_check","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"}"#;
const VERIFY_AS_RESTFUL: &str = r#"{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}"#;

fn opts(
    port: u16,
    peers: Vec<String>,
    rotation_interval: u64,
    out_dir: std::path::PathBuf,
    ready_file: std::path::PathBuf,
) -> KeySyncOptions {
    KeySyncOptions {
        host: "127.0.0.1".to_string(),
        port,
        peers,
        peers_file: None,
        rotation_interval,
        attest: ATTEST_AA_UDS.to_string(),
        verify: VERIFY_AS_RESTFUL.to_string(),
        out_dir,
        ready_file: Some(ready_file),
    }
}

/// The single active-key stem (public-key hex) exported under `<out>/current`,
/// or None if `current/` has no `.key` yet.
fn current_key_stem(out_dir: &std::path::Path) -> Option<String> {
    let current = out_dir.join("current");
    let mut stems: Vec<String> = std::fs::read_dir(&current)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".key"))
        .map(|e| {
            e.file_name()
                .to_string_lossy()
                .trim_end_matches(".key")
                .to_string()
        })
        .collect();
    stems.sort();
    stems.pop()
}

async fn wait_for_ready(path: &std::path::Path, timeout: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    loop {
        if path.exists() {
            return Ok(());
        }
        if start.elapsed() > timeout {
            anyhow::bail!("timeout waiting for ready file {}", path.display());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_current_key(out_dir: &std::path::Path, timeout: Duration) -> Result<String> {
    let start = std::time::Instant::now();
    loop {
        if let Some(stem) = current_key_stem(out_dir) {
            return Ok(stem);
        }
        if start.elapsed() > timeout {
            anyhow::bail!(
                "timeout waiting for current/ key under {}",
                out_dir.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Two nodes form a cluster, sync the active key to disk, and rotate together.
/// Needs AA + AS (see module docs).
#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn two_node_key_sync_syncs_and_rotates() -> Result<()> {
    // key_sync::run builds the serf RA-TLS QUIC transport, which needs a rustls
    // process-default crypto provider. The tng binary installs one in main(),
    // but this test drives key_sync::run in-process and bypasses main(), so
    // install it here idempotently before bringing up the daemons. Matches the
    // aws_lc_rs provider the production CLI uses.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // install_default's Err variant is the already-installed provider, which
        // is the desired state, so it is not a real error to propagate.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    // Initialize tracing so the serf preboot/sync/rotation logs are visible
    // when debugging this test (the tng binary inits tracing in main(); this
    // in-process test bypasses main).
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    "info,tokio_graceful=off,rats_cert=debug,tng=debug,serf=debug".into()
                }),
            )
            .init();
    });

    let port_a = portpicker::pick_unused_port().context("pick port a")?;
    let port_b = portpicker::pick_unused_port().context("pick port b")?;
    let dir_a = tempfile::tempdir().context("tmpdir a")?;
    let dir_b = tempfile::tempdir().context("tmpdir b")?;
    let ready_a = dir_a.path().join("ready");
    let ready_b = dir_b.path().join("ready");

    // Bootstrap node A (no peers). rotation_interval 10s keeps A's initial key
    // active well past B's preboot latency (~3s for the serf query response
    // channel to close over RA-TLS QUIC), so B can sync a_initial before A
    // rotates. With 2s the preboot would finish after A had already rotated.
    let opts_a = opts(
        port_a,
        vec![],
        10,
        dir_a.path().to_path_buf(),
        ready_a.clone(),
    );
    let handle_a = tokio::spawn(async move { key_sync::run(opts_a).await });
    wait_for_ready(&ready_a, Duration::from_secs(30))
        .await
        .context("A ready")?;
    let a_initial = wait_for_current_key(dir_a.path(), Duration::from_secs(10))
        .await
        .context("A initial current key")?;

    // Node B joins A.
    let opts_b = opts(
        port_b,
        vec![format!("127.0.0.1:{port_a}")],
        10,
        dir_b.path().to_path_buf(),
        ready_b.clone(),
    );
    let handle_b = tokio::spawn(async move { key_sync::run(opts_b).await });
    wait_for_ready(&ready_b, Duration::from_secs(30))
        .await
        .context("B ready")?;

    // B must converge to A's active key in its exported current/.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(b_stem) = current_key_stem(dir_b.path()) {
            if b_stem == a_initial {
                break;
            }
        }
        if std::time::Instant::now() > deadline {
            anyhow::bail!(
                "B did not sync A's active key: A={a_initial} B={:?}",
                current_key_stem(dir_b.path())
            );
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // Wait for a rotation cycle (10s interval -> stale@10s, expire@20s).
    tokio::time::sleep(Duration::from_secs(12)).await;
    let a_after = wait_for_current_key(dir_a.path(), Duration::from_secs(10))
        .await
        .context("A after rotation")?;
    let b_after = wait_for_current_key(dir_b.path(), Duration::from_secs(10))
        .await
        .context("B after rotation")?;
    assert_ne!(a_after, a_initial, "A active key should have rotated");
    assert_eq!(a_after, b_after, "A and B should agree on rotated key");

    // Clean shutdown: abort the daemon tasks; KeySyncDaemon's Drop runs the
    // graceful serf leave.
    handle_a.abort();
    handle_b.abort();
    let _ = handle_a.await;
    let _ = handle_b.await;
    Ok(())
}

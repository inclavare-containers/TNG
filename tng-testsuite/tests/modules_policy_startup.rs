use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serial_test::serial;
use tng_testsuite::task::tng::binary_locator::resolve_tng_binary;

/// A valid 64-hex digest used only to make the modules entry parse; no traffic
/// reaches the image check in these tests.
const EXAMPLE_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn modules_verify_json() -> String {
    format!(
        r#"{{
            "model": "background_check",
            "as_type": "builtin",
            "attestation_policy": {{
                "type": "modules",
                "modules": [
                    {{ "type": "tdx", "value": {{}} }},
                    {{ "type": "com.alibabacloud.container.image.example", "value": "{EXAMPLE_DIGEST}" }}
                ]
            }}
        }}"#
    )
}

/// Egress-only config. `tng exec` supports hook egress only, so the capture
/// rule is a hook listen entry rather than a netfilter capture_dst.
fn startup_config(port: u16) -> String {
    format!(
        r#"{{
            "add_egress": [
                {{
                    "hook": {{ "capture_listen": [ {{ "port": {port} }} ] }},
                    "ohttp": {{}},
                    "verify": {}
                }}
            ]
        }}"#,
        modules_verify_json()
    )
}

/// The captured destination is also served by a hook egress in the same
/// process, so the wrapped curl's connect is intercepted by the ingress and
/// the request reaches the OHTTP handshake.
fn handshake_config(port: u16) -> String {
    format!(
        r#"{{
            "add_ingress": [
                {{
                    "hook": {{
                        "capture_dst": [ {{ "host": "127.0.0.1", "port": {port} }} ],
                        "capture_local_traffic": true
                    }},
                    "ohttp": {{}},
                    "verify": {}
                }}
            ],
            "add_egress": [
                {{
                    "hook": {{ "capture_listen": [ {{ "port": {port} }} ] }},
                    "ohttp": {{}},
                    "verify": {}
                }}
            ]
        }}"#,
        modules_verify_json(),
        modules_verify_json()
    )
}

/// Create (truncate) a deterministic per-test log file. Creation failing is an
/// error: assertions must never read a stale file.
fn fresh_log(name: &str) -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "tng-modules-policy-{name}-{}.log",
        std::process::id()
    ));
    std::fs::File::create(&path).with_context(|| format!("create log {}", path.display()))?;
    Ok(path)
}

fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn log_tail(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let lines: Vec<&str> = text.lines().collect();
            lines[lines.len().saturating_sub(80)..].join("\n")
        }
        Err(e) => format!("<cannot read {}: {e}>", path.display()),
    }
}

/// Whether this host can produce TDX evidence: a guest device plus a local
/// attestation agent. Both are needed for the handshake to succeed.
fn tdx_attestation_available() -> bool {
    Path::new("/dev/tdx_guest").exists()
        && Path::new("/run/confidential-containers/attestation-agent/attestation-agent.sock")
            .exists()
}

/// Run `tng exec` with a bounded wait and a guaranteed log level.
async fn run_exec(config: &str, log: &Path, command: &[&str]) -> Result<std::process::Output> {
    let mut cmd = tokio::process::Command::new(resolve_tng_binary()?);
    // A timed-out child must not outlive the test's runtime.
    cmd.kill_on_drop(true);
    cmd.arg("--log-file")
        .arg(log)
        .env("RUST_LOG", "info")
        .arg("exec")
        .arg("--config-content")
        .arg(config)
        .arg("--");
    for arg in command {
        cmd.arg(arg);
    }

    match tokio::time::timeout(Duration::from_secs(60), cmd.output()).await {
        Ok(result) => result.context("spawn tng exec"),
        Err(_) => anyhow::bail!(
            "tng exec timed out after 60 seconds; log tail:\n{}",
            log_tail(log)
        ),
    }
}

/// A modules policy must build at startup, so the wrapped command runs.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modules_policy_builds_and_runs_wrapped_command() -> Result<()> {
    let port = portpicker::pick_unused_port().expect("pick a free port");
    let config = startup_config(port);
    let log = fresh_log("startup")?;

    let output = run_exec(&config, &log, &["echo", "hi"]).await?;

    let log_text = read_log(&log);
    assert!(
        output.status.success(),
        "tng exec failed: status={:?} stderr={} log={log_text}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("hi"),
        "wrapped command did not run: {output:?}"
    );
    assert!(
        log_text.contains("All services are ready"),
        "startup did not complete: {log_text}"
    );
    assert!(
        !log_text.contains("Failed to build builtin policy template"),
        "modules policy failed to build: {log_text}"
    );
    assert!(
        !log_text.contains("unknown module type"),
        "modules policy rejected an entry type: {log_text}"
    );

    std::fs::remove_file(&log).context("remove temp log")?;
    Ok(())
}

/// Without a TEE the OHTTP/RA handshake cannot complete. The request must fail
/// at the attestation path, not because the modules policy could not be built
/// or parsed. On a host that can actually attest, the request may succeed, so
/// only the policy-build and handshake-attempt assertions are unconditional.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modules_policy_attestation_attempt_fails_without_tee() -> Result<()> {
    let port = portpicker::pick_unused_port().expect("pick a free port");
    let config = handshake_config(port);
    let log = fresh_log("attestation")?;
    let url = format!("http://127.0.0.1:{port}/");

    let output = run_exec(
        &config,
        &log,
        &["curl", "-f", "-sS", "-m", "10", "-o", "/dev/null", &url],
    )
    .await?;

    let log_text = read_log(&log);
    if !tdx_attestation_available() {
        assert!(
            !output.status.success(),
            "the request must fail without a TEE: status={:?} log={log_text}",
            output.status
        );
    }
    assert!(
        !log_text.contains("Failed to build builtin policy template"),
        "failure must not come from the modules policy build: {log_text}"
    );
    assert!(
        !log_text.contains("unknown module type"),
        "failure must not come from module type validation: {log_text}"
    );
    // Stable marker from the attestation handshake path: the ingress issues an
    // OHTTP key-config request carrying a background-check attestation request.
    // This assertion is coupled to the Debug rendering of `KeyConfigRequest`
    // (its `attestation_request: Some(BackgroundCheck { .. })` field); changing
    // that rendering requires updating this marker.
    assert!(
        log_text.contains("attestation_request: Some(BackgroundCheck"),
        "expected an attestation attempt in the log: {log_text}"
    );

    std::fs::remove_file(&log).context("remove temp log")?;
    Ok(())
}

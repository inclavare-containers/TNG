use anyhow::Result;
use tng_testsuite::task::tng::binary_locator::resolve_tng_binary;

/// Runs `tng exec --config-content <config> -- echo hi`. The config is
/// intentionally invalid past parsing, so the process stops at exec's
/// config validation without bringing up a tunnel. TNG logs to stdout.
async fn run_exec(config: &str) -> Result<String> {
    let tng_bin = resolve_tng_binary()?;
    let output = tokio::process::Command::new(tng_bin)
        .arg("exec")
        .arg("--config-content")
        .arg(config)
        .arg("--")
        .arg("echo")
        .arg("hi")
        .output()
        .await?;
    assert!(!output.status.success(), "tng exec should exit non-zero");
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn comments_reach_the_config_validator() -> Result<()> {
    let stdout = run_exec("// comment\n{}").await?;
    assert!(
        stdout.contains("requires at least one add_ingress or add_egress entry"),
        "config with a comment should parse and reach exec's validator, stdout: {stdout}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leading_bom_reaches_the_config_validator() -> Result<()> {
    let stdout = run_exec("\u{feff}{}").await?;
    assert!(
        stdout.contains("requires at least one add_ingress or add_egress entry"),
        "config with a leading BOM should parse and reach exec's validator, stdout: {stdout}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json5_extensions_are_still_rejected() -> Result<()> {
    let stdout = run_exec("{unquoted: 1}").await?;
    assert!(
        stdout.contains("line 1 column"),
        "unquoted property names must still be rejected, stdout: {stdout}"
    );
    assert!(
        !stdout.contains("requires at least one add_ingress or add_egress entry"),
        "unquoted property names must not reach exec's validator, stdout: {stdout}"
    );
    Ok(())
}

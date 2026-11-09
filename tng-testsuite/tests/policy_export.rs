use anyhow::Result;
use tng::tools::cli::PolicyCommand;
use tng::tools::policy;

const CONFIG: &str = r#"{
    // JSONC comments are accepted
    "add_ingress": [
        {
            "mapping": {"rules": [{"in": {"port": 10001}, "out": {"host": "127.0.0.1", "port": 20001}}]},
            "verify": {"model": "background_check", "as_type": "builtin",
                       "attestation_policy": {"type": "trust_all"}}
        }
    ],
    "add_egress": [
        {
            "mapping": {"rules": [{"in": {"port": 10003}, "out": {"host": "127.0.0.1", "port": 20003}}]},
            "verify": {"model": "background_check", "as_type": "builtin",
                       "attestation_policy": {"type": "modules",
                                              "modules": [{"type": "tdx", "value": {}}]}}
        },
        {
            "mapping": {"rules": [{"in": {"port": 10004}, "out": {"host": "127.0.0.1", "port": 20004}}]},
            "verify": {"model": "background_check", "as_type": "restful",
                       "as_addr": "http://127.0.0.1:8080", "policy_ids": []}
        }
    ]
}"#;

#[tokio::test]
async fn export_config_writes_one_file_per_builtin_policy() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("tng.json");
    std::fs::write(&config_path, CONFIG)?;
    let out = dir.path().join("policies");

    policy::run(PolicyCommand::Export {
        config: Some(config_path),
        attestation_policy: None,
        out_dir: Some(out.clone()),
    })
    .await?;

    let ingress =
        std::fs::read_to_string(out.join("add_ingress.0.verify.attestation_policy.rego"))?;
    let egress = std::fs::read_to_string(out.join("add_egress.0.verify.attestation_policy.rego"))?;
    assert!(ingress.contains("package policy"), "{ingress}");
    assert!(egress.contains("tdx_recognized"), "{egress}");
    assert!(!out
        .join("add_egress.1.verify.attestation_policy.rego")
        .exists());
    Ok(())
}

#[tokio::test]
async fn export_standalone_policy_names_the_file_attestation_policy() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("policies");

    policy::run(PolicyCommand::Export {
        config: None,
        attestation_policy: Some(
            r#"{"type":"modules","modules":[{"type":"tdx","value":{}}]}"#.to_string(),
        ),
        out_dir: Some(out.clone()),
    })
    .await?;

    let source = std::fs::read_to_string(out.join("attestation_policy.rego"))?;
    assert!(source.contains("package policy"), "{source}");
    Ok(())
}

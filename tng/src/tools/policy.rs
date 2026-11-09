//! `tng tools policy export`: render the Rego a builtin AS loads.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::config::ra::{
    CocoConverterArgs, ConverterArgs, PolicyConfig, RaArgsUnchecked, VerifyArgs,
};
use crate::config::TngConfig;

/// The two accepted input forms, after the CLI's optional flags collapse.
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyInput {
    /// A full TNG config file. `PathBuf::from("-")` means stdin.
    Config(PathBuf),
    /// A bare `attestation_policy` value.
    AttestationPolicy(String),
}

/// A builtin `attestation_policy` found in a config, with its JSON-path label.
#[derive(Debug)]
pub struct DiscoveredPolicy<'a> {
    pub label: String,
    pub policy: &'a PolicyConfig,
}

fn push_policy<'a>(
    found: &mut Vec<DiscoveredPolicy<'a>>,
    label: String,
    ra_args: &'a RaArgsUnchecked,
) {
    if ra_args.no_ra {
        return;
    }
    let Some(VerifyArgs::BackgroundCheck { converter, .. }) = ra_args.verify.as_ref() else {
        return;
    };
    let ConverterArgs::Coco(CocoConverterArgs::Builtin {
        attestation_policy, ..
    }) = converter
    else {
        return;
    };
    found.push(DiscoveredPolicy {
        label,
        policy: attestation_policy,
    });
}

/// Walk the config's ingress then egress entries in array order and return
/// every builtin `attestation_policy`. Non-builtin verifies are skipped.
pub fn collect_policies(config: &TngConfig) -> Vec<DiscoveredPolicy<'_>> {
    let mut found = Vec::new();
    for (i, entry) in config.add_ingress.iter().enumerate() {
        push_policy(
            &mut found,
            format!("add_ingress.{i}.verify.attestation_policy"),
            &entry.common.ra_args,
        );
    }
    for (i, entry) in config.add_egress.iter().enumerate() {
        push_policy(
            &mut found,
            format!("add_egress.{i}.verify.attestation_policy"),
            &entry.common.ra_args,
        );
    }
    found
}

/// The output file name for a JSON-path label.
pub fn file_name(label: &str) -> String {
    format!("{label}.rego")
}

/// Render stdout blocks: a `# <name>` header per block, a bare `---` between
/// blocks, and exactly one trailing newline per block.
pub fn render_stdout<'a>(blocks: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut out = String::new();
    for (i, (name, source)) in blocks.into_iter().enumerate() {
        if i > 0 {
            out.push_str("\n---\n\n");
        }
        out.push_str("# ");
        out.push_str(name);
        out.push('\n');
        out.push_str(source.trim_end_matches('\n'));
        out.push('\n');
    }
    out
}

fn resolve_input(
    config: Option<PathBuf>,
    attestation_policy: Option<String>,
) -> Result<PolicyInput> {
    match (config, attestation_policy) {
        (Some(config), None) => Ok(PolicyInput::Config(config)),
        (None, Some(policy)) => Ok(PolicyInput::AttestationPolicy(policy)),
        (None, None) => bail!("one of --config or --attestation-policy is required"),
        (Some(_), Some(_)) => bail!("--config and --attestation-policy are mutually exclusive"),
    }
}

async fn read_config_text(path: &Path) -> Result<String> {
    if path == Path::new("-") {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
            .context("read config from stdin")?;
        Ok(text)
    } else {
        tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("read config {}", path.display()))
    }
}

/// Render every builtin policy to `--out-dir`, or print them to stdout when no
/// output directory is given.
pub async fn run(cmd: super::cli::PolicyCommand) -> Result<()> {
    let super::cli::PolicyCommand::Export {
        config,
        attestation_policy,
        out_dir,
    } = cmd;
    let input = resolve_input(config, attestation_policy)?;

    let blocks = match input {
        PolicyInput::Config(path) => {
            let text = read_config_text(&path).await?;
            let config =
                crate::config::parse_config_str(&text).context("parse --config as a TNG config")?;
            let found = collect_policies(&config);
            if found.is_empty() {
                bail!(
                    "no builtin attestation_policy found in the config; set verify.as_type to \
                     \"builtin\" on an add_ingress or add_egress entry"
                );
            }
            let mut blocks = Vec::with_capacity(found.len());
            for discovered in found {
                let source = rats_cert::tee::coco::converter::builtin::render_policy_source(
                    discovered.policy,
                )
                .await
                .with_context(|| format!("render {}", discovered.label))?;
                blocks.push((file_name(&discovered.label), source));
            }
            blocks
        }
        PolicyInput::AttestationPolicy(json) => {
            let policy: PolicyConfig = serde_json::from_str(&json)
                .context("parse --attestation-policy as a PolicyConfig JSON value")?;
            let source = rats_cert::tee::coco::converter::builtin::render_policy_source(&policy)
                .await
                .context("render --attestation-policy")?;
            vec![(file_name("attestation_policy"), source)]
        }
    };

    match out_dir {
        Some(dir) => {
            tokio::fs::create_dir_all(&dir)
                .await
                .with_context(|| format!("create output directory {}", dir.display()))?;
            for (name, source) in &blocks {
                let path = dir.join(name);
                tokio::fs::write(&path, source)
                    .await
                    .with_context(|| format!("write {}", path.display()))?;
                eprintln!("wrote {}", path.display());
            }
        }
        None => print!(
            "{}",
            render_stdout(
                blocks
                    .iter()
                    .map(|(name, source)| (name.as_str(), source.as_str()))
            )
        ),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"{
        // JSONC comments are accepted
        "add_ingress": [
            {
                "mapping": {"rules": [{"in": {"port": 10001}, "out": {"host": "127.0.0.1", "port": 20001}}]},
                "verify": {"model": "background_check", "as_type": "builtin",
                           "attestation_policy": {"type": "trust_all"}}
            },
            {
                "mapping": {"rules": [{"in": {"port": 10002}, "out": {"host": "127.0.0.1", "port": 20002}}]},
                "verify": {"model": "background_check", "as_type": "builtin"}
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

    #[test]
    fn collect_policies_finds_builtin_verifies_in_order() {
        let config = crate::config::parse_config_str(CONFIG).expect("parse fixture");
        let found = collect_policies(&config);
        let labels: Vec<&str> = found.iter().map(|d| d.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "add_ingress.0.verify.attestation_policy",
                "add_ingress.1.verify.attestation_policy",
                "add_egress.0.verify.attestation_policy",
            ]
        );
        assert!(matches!(found[0].policy, PolicyConfig::TrustAll));
        assert!(matches!(found[1].policy, PolicyConfig::HardwareOnly));
        assert!(matches!(found[2].policy, PolicyConfig::Modules { .. }));
    }

    #[test]
    fn collect_policies_returns_empty_without_builtin() {
        let config = crate::config::parse_config_str(
            r#"{"add_ingress": [{"mapping": {"rules": [{"in": {"port": 10001},
                "out": {"host": "127.0.0.1", "port": 20001}}]},
                "no_ra": true}]}"#,
        )
        .expect("parse fixture");
        assert!(collect_policies(&config).is_empty());
    }

    #[test]
    fn file_name_appends_rego() {
        assert_eq!(
            file_name("add_ingress.0.verify.attestation_policy"),
            "add_ingress.0.verify.attestation_policy.rego"
        );
    }

    #[test]
    fn stdout_blocks_are_header_separator_header() {
        let out = render_stdout([
            (
                "add_ingress.0.verify.attestation_policy.rego",
                "package policy\n",
            ),
            (
                "add_egress.0.verify.attestation_policy.rego",
                "package policy\n",
            ),
        ]);
        assert_eq!(
            out,
            "# add_ingress.0.verify.attestation_policy.rego\npackage policy\n\n---\n\n\
             # add_egress.0.verify.attestation_policy.rego\npackage policy\n"
        );
    }

    #[test]
    fn resolve_input_requires_exactly_one_source() {
        assert!(matches!(
            resolve_input(Some(PathBuf::from("tng.json")), None),
            Ok(PolicyInput::Config(_))
        ));
        assert!(matches!(
            resolve_input(None, Some("{}".to_string())),
            Ok(PolicyInput::AttestationPolicy(_))
        ));
        assert!(resolve_input(None, None).is_err());
        assert!(resolve_input(Some(PathBuf::from("tng.json")), Some("{}".to_string())).is_err());
    }

    #[tokio::test]
    async fn export_writes_rendered_source_verbatim() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("tng.json");
        std::fs::write(&config_path, CONFIG).expect("write config");
        let out = dir.path().join("policies");

        run(crate::tools::cli::PolicyCommand::Export {
            config: Some(config_path),
            attestation_policy: None,
            out_dir: Some(out.clone()),
        })
        .await
        .expect("export");

        let written =
            std::fs::read_to_string(out.join("add_ingress.0.verify.attestation_policy.rego"))
                .expect("read exported file");

        let config = crate::config::parse_config_str(CONFIG).expect("parse config");
        let found = collect_policies(&config);
        let expected =
            rats_cert::tee::coco::converter::builtin::render_policy_source(found[0].policy)
                .await
                .expect("render expected");
        assert_eq!(written, expected);
    }

    #[tokio::test]
    async fn export_rejects_a_config_without_builtin_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("tng.json");
        std::fs::write(&config_path, r#"{"add_ingress": []}"#).expect("write config");
        let err = run(crate::tools::cli::PolicyCommand::Export {
            config: Some(config_path),
            attestation_policy: None,
            out_dir: None,
        })
        .await
        .expect_err("must reject");
        assert!(
            err.to_string().contains("no builtin attestation_policy"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn export_propagates_an_unknown_module_type() {
        let err = run(crate::tools::cli::PolicyCommand::Export {
            config: None,
            attestation_policy: Some(
                r#"{"type":"modules","modules":[{"type":"not.a.module","value":{}}]}"#.to_string(),
            ),
            out_dir: None,
        })
        .await
        .expect_err("must reject");
        assert!(
            format!("{err:#}").contains("unknown module type"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn export_reports_a_missing_policy_file() {
        let err = run(crate::tools::cli::PolicyCommand::Export {
            config: None,
            attestation_policy: Some(
                r#"{"type":"path","path":"/nonexistent/tng-policy.rego"}"#.to_string(),
            ),
            out_dir: None,
        })
        .await
        .expect_err("must reject");
        assert!(
            format!("{err:#}").contains("/nonexistent/tng-policy.rego"),
            "{err:#}"
        );
    }
}

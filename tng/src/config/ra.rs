use std::{collections::HashMap, path::Path};

use anyhow::{anyhow, bail, Context as _, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::{
    error::TngError,
    tunnel::{provider::ProviderType, utils::maybe_cached::RefreshStrategy},
};

/// Remote Attestation configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RaArgsUnchecked {
    /// Whether to disable Remote Attestation functionality
    #[serde(default = "bool::default")]
    pub no_ra: bool,

    /// Attestation parameters configuration (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attest: Option<AttestArgs>,

    /// Verification parameters configuration (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyArgs>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RaArgs {
    #[cfg(unix)]
    AttestOnly(AttestArgs),
    VerifyOnly(VerifyArgs),
    #[cfg(unix)]
    AttestAndVerify(AttestArgs, VerifyArgs),
    NoRa,
}

impl RaArgsUnchecked {
    pub fn into_checked(self) -> Result<RaArgs, TngError> {
        let ra_args = if self.no_ra {
            // Sanity check
            if self.verify.is_some() {
                return Err(TngError::InvalidParameter(anyhow!(
                    "The 'no_ra: true' flag should not be used with 'verify' field"
                )));
            }

            if self.attest.is_some() {
                return Err(TngError::InvalidParameter(anyhow!(
                    "The 'no_ra: true' flag should not be used with 'attest' field"
                )));
            }

            tracing::warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment");

            RaArgs::NoRa
        } else {
            match (self.attest, self.verify) {
                (None, None) => {
                    return Err(TngError::InvalidParameter(anyhow!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_egress'")));
                }
                (None, Some(verify)) => RaArgs::VerifyOnly(verify),
                #[cfg(unix)]
                (Some(attest), None) => RaArgs::AttestOnly(attest),
                #[cfg(unix)]
                (Some(attest), Some(verify)) => RaArgs::AttestAndVerify(attest, verify),
                #[cfg(wasm)]
                (Some(..), _) => {
                    return Err(TngError::InvalidParameter(anyhow!("`attest` option is not supported since attestation is not supported on this platform.")));
                }
            }
        };

        // Sanity check for the attest_args.
        #[cfg(unix)]
        if let RaArgs::AttestOnly(attest_args) | RaArgs::AttestAndVerify(attest_args, _) =
            &ra_args
        {
            let aa_addr = match attest_args.attester() {
                AttesterConfig::Coco { aa_addr } => aa_addr,
            };
            let aa_sock_file = aa_addr
                .strip_prefix("unix:///")
                .context("AA address must start with unix:///")
                .map_err(TngError::InvalidParameter)?;
            let aa_sock_file = Path::new("/").join(aa_sock_file);
            if !Path::new(&aa_sock_file).exists() {
                return Err(TngError::InvalidParameter(anyhow!(
                    "AA socket file {aa_sock_file:?} not found"
                )));
            }
        }

        // Sanity check for the verify_args.
        {
            let verify_args = match &ra_args {
                RaArgs::VerifyOnly(verify_args) => verify_args,
                #[cfg(unix)]
                RaArgs::AttestAndVerify(_, verify_args) => verify_args,
                _ => return Ok(ra_args),
            };

            let (trusted_certs_paths, has_as_addr) = match verify_args.verifier() {
                VerifierConfig::Coco {
                    trusted_certs_paths,
                    as_addr_config,
                    ..
                } => (trusted_certs_paths, as_addr_config.is_some()),
            };

            // Additional checks for Passport mode
            if let VerifyArgs::Passport { .. } = verify_args {
                if !has_as_addr && trusted_certs_paths.is_none() {
                    return Err(TngError::InvalidParameter(anyhow!("At least one of 'as_addr' or 'trusted_certs_paths' must be set to verify attestation token")));
                }
            }

            // Check if trusted certificate paths exist
            if let Some(paths) = &trusted_certs_paths {
                for path in paths {
                    if !Path::new(path).exists() {
                        return Err(TngError::InvalidParameter(anyhow!(
                            "Attestation service trusted certificate path does not exist: {}",
                            path
                        )));
                    }
                }
            }

            // Check if as_addr is a valid URL
            if let VerifyArgs::BackgroundCheck {
                converter: ConverterConfig::Coco { as_addr, .. },
                ..
            } = verify_args
            {
                Url::parse(as_addr)
                    .with_context(|| {
                        format!("Invalid attestation service address: {}", as_addr)
                    })
                    .map_err(TngError::InvalidParameter)?;
            }
        }

        Ok(ra_args)
    }
}

/// Attestation parameters configuration enum
#[derive(Debug, Clone, PartialEq)]
pub enum AttestArgs {
    /// Passport mode attestation parameters
    Passport {
        attester: AttesterConfig,
        converter: ConverterConfig,
        refresh_interval: Option<u64>,
    },

    /// Background check mode attestation parameters
    BackgroundCheck {
        attester: AttesterConfig,
        refresh_interval: Option<u64>,
    },
}

impl AttestArgs {
    pub fn attester(&self) -> &AttesterConfig {
        match self {
            Self::Passport { attester, .. } | Self::BackgroundCheck { attester, .. } => attester,
        }
    }

    pub fn converter(&self) -> Option<&ConverterConfig> {
        match self {
            Self::Passport { converter, .. } => Some(converter),
            Self::BackgroundCheck { .. } => None,
        }
    }

    pub fn refresh_strategy(&self) -> RefreshStrategy {
        let interval = match self {
            Self::Passport {
                refresh_interval, ..
            }
            | Self::BackgroundCheck {
                refresh_interval, ..
            } => refresh_interval.unwrap_or(EVIDENCE_REFRESH_INTERVAL_SECOND),
        };
        if interval == 0 {
            RefreshStrategy::Always
        } else {
            RefreshStrategy::Periodically { interval }
        }
    }

    pub fn attester_provider(&self) -> ProviderType {
        match self.attester() {
            AttesterConfig::Coco { .. } => ProviderType::Coco,
        }
    }

    pub fn converter_provider(&self) -> Option<ProviderType> {
        self.converter().map(|c| match c {
            ConverterConfig::Coco { .. } => ProviderType::Coco,
        })
    }
}

/// Verification parameters configuration enum
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyArgs {
    /// Passport mode verification parameters
    Passport {
        verifier: VerifierConfig,
    },

    /// Background check mode verification parameters
    BackgroundCheck {
        converter: ConverterConfig,
        verifier: VerifierConfig,
    },
}

impl VerifyArgs {
    pub fn verifier(&self) -> &VerifierConfig {
        match self {
            Self::Passport { verifier } | Self::BackgroundCheck { verifier, .. } => verifier,
        }
    }

    pub fn converter(&self) -> Option<&ConverterConfig> {
        match self {
            Self::BackgroundCheck { converter, .. } => Some(converter),
            Self::Passport { .. } => None,
        }
    }

    pub fn verifier_provider(&self) -> ProviderType {
        match self.verifier() {
            VerifierConfig::Coco { .. } => ProviderType::Coco,
        }
    }
}

const EVIDENCE_REFRESH_INTERVAL_SECOND: u64 = 10 * 60; // 10 minutes

/// Attestation service address configuration
#[derive(Debug, Clone, PartialEq)]
pub struct AsAddrConfig {
    pub as_addr: String,
    pub as_is_grpc: bool,
    pub as_headers: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AttesterConfig {
    Coco { aa_addr: String },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConverterConfig {
    Coco {
        as_addr: String,
        as_is_grpc: bool,
        as_headers: HashMap<String, String>,
        policy_ids: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum VerifierConfig {
    Coco {
        policy_ids: Vec<String>,
        trusted_certs_paths: Option<Vec<String>>,
        as_addr_config: Option<AsAddrConfig>,
    },
}

fn extract_required_string(
    fields: &mut HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<String> {
    match fields.remove(key) {
        Some(serde_json::Value::String(s)) => Ok(s),
        Some(v) => bail!("expected string for \"{key}\", got {v}"),
        None => bail!("missing required field \"{key}\""),
    }
}

fn extract_optional_string(
    fields: &mut HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<Option<String>> {
    match fields.remove(key) {
        Some(serde_json::Value::String(s)) => Ok(Some(s)),
        Some(serde_json::Value::Null) => Ok(None),
        Some(v) => bail!("expected string for \"{key}\", got {v}"),
        None => Ok(None),
    }
}

fn extract_optional_bool(
    fields: &mut HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<Option<bool>> {
    match fields.remove(key) {
        Some(serde_json::Value::Bool(b)) => Ok(Some(b)),
        Some(serde_json::Value::Null) => Ok(None),
        Some(v) => bail!("expected bool for \"{key}\", got {v}"),
        None => Ok(None),
    }
}

fn extract_optional_string_map(
    fields: &mut HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<Option<HashMap<String, String>>> {
    match fields.remove(key) {
        Some(serde_json::Value::Object(map)) => {
            let mut result = HashMap::new();
            for (k, v) in map {
                match v {
                    serde_json::Value::String(s) => {
                        result.insert(k, s);
                    }
                    _ => bail!("expected string values in \"{key}\" map"),
                }
            }
            Ok(Some(result))
        }
        Some(serde_json::Value::Null) => Ok(None),
        Some(v) => bail!("expected object for \"{key}\", got {v}"),
        None => Ok(None),
    }
}

fn extract_required_vec_string(
    fields: &mut HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<Vec<String>> {
    match fields.remove(key) {
        Some(serde_json::Value::Array(arr)) => arr
            .into_iter()
            .map(|v| match v {
                serde_json::Value::String(s) => Ok(s),
                _ => bail!("expected string elements in array \"{key}\""),
            })
            .collect(),
        Some(v) => bail!("expected array for \"{key}\", got {v}"),
        None => bail!("missing required field \"{key}\""),
    }
}

fn extract_optional_vec_string(
    fields: &mut HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<Option<Vec<String>>> {
    match fields.remove(key) {
        Some(serde_json::Value::Array(arr)) => {
            let v: Result<Vec<String>> = arr
                .into_iter()
                .map(|v| match v {
                    serde_json::Value::String(s) => Ok(s),
                    _ => bail!("expected string elements in array \"{key}\""),
                })
                .collect();
            Ok(Some(v?))
        }
        Some(serde_json::Value::Null) => Ok(None),
        Some(v) => bail!("expected array for \"{key}\", got {v}"),
        None => Ok(None),
    }
}

fn reject_unknown_fields(fields: &HashMap<String, serde_json::Value>) -> Result<()> {
    if !fields.is_empty() {
        bail!(
            "unknown fields: {:?}",
            fields.keys().collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[derive(Deserialize)]
struct AttestInput {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    aa_provider: Option<String>,
    #[serde(default)]
    as_provider: Option<String>,
    #[serde(default)]
    refresh_interval: Option<u64>,
    #[serde(flatten)]
    fields: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct VerifyInput {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    as_provider: Option<String>,
    #[serde(flatten)]
    fields: HashMap<String, serde_json::Value>,
}

impl TryFrom<AttestInput> for AttestArgs {
    type Error = anyhow::Error;

    fn try_from(input: AttestInput) -> Result<Self> {
        let aa_provider = input
            .aa_provider
            .as_deref()
            .unwrap_or("coco")
            .parse::<ProviderType>()?;
        let as_provider = input
            .as_provider
            .as_deref()
            .unwrap_or("coco")
            .parse::<ProviderType>()?;
        let model = input.model.as_deref().unwrap_or("background_check");
        let mut fields = input.fields;

        match model {
            "background_check" => {
                let attester = match aa_provider {
                    ProviderType::Coco => {
                        let aa_addr = extract_required_string(&mut fields, "aa_addr")?;
                        AttesterConfig::Coco { aa_addr }
                    }
                };
                reject_unknown_fields(&fields)?;
                Ok(AttestArgs::BackgroundCheck {
                    attester,
                    refresh_interval: input.refresh_interval,
                })
            }
            "passport" => {
                let attester = match aa_provider {
                    ProviderType::Coco => {
                        let aa_addr = extract_required_string(&mut fields, "aa_addr")?;
                        AttesterConfig::Coco { aa_addr }
                    }
                };
                let converter = match as_provider {
                    ProviderType::Coco => {
                        let as_addr = extract_required_string(&mut fields, "as_addr")?;
                        let as_is_grpc =
                            extract_optional_bool(&mut fields, "as_is_grpc")?.unwrap_or(false);
                        let as_headers =
                            extract_optional_string_map(&mut fields, "as_headers")?
                                .unwrap_or_default();
                        let policy_ids =
                            extract_required_vec_string(&mut fields, "policy_ids")?;
                        ConverterConfig::Coco {
                            as_addr,
                            as_is_grpc,
                            as_headers,
                            policy_ids,
                        }
                    }
                };
                reject_unknown_fields(&fields)?;
                Ok(AttestArgs::Passport {
                    attester,
                    converter,
                    refresh_interval: input.refresh_interval,
                })
            }
            other => bail!(
                r#"unsupported value for "model" field: "{other}", should be one of ["background_check", "passport"]"#
            ),
        }
    }
}

impl TryFrom<VerifyInput> for VerifyArgs {
    type Error = anyhow::Error;

    fn try_from(input: VerifyInput) -> Result<Self> {
        let as_provider = input
            .as_provider
            .as_deref()
            .unwrap_or("coco")
            .parse::<ProviderType>()?;
        let model = input.model.as_deref().unwrap_or("background_check");
        let mut fields = input.fields;

        match model {
            "background_check" => match as_provider {
                ProviderType::Coco => {
                    let as_addr = extract_required_string(&mut fields, "as_addr")?;
                    let as_is_grpc =
                        extract_optional_bool(&mut fields, "as_is_grpc")?.unwrap_or(false);
                    let as_headers =
                        extract_optional_string_map(&mut fields, "as_headers")?
                            .unwrap_or_default();
                    let policy_ids = extract_required_vec_string(&mut fields, "policy_ids")?;
                    let trusted_certs_paths =
                        extract_optional_vec_string(&mut fields, "trusted_certs_paths")?;
                    reject_unknown_fields(&fields)?;

                    let converter = ConverterConfig::Coco {
                        as_addr: as_addr.clone(),
                        as_is_grpc,
                        as_headers: as_headers.clone(),
                        policy_ids: policy_ids.clone(),
                    };
                    let verifier = VerifierConfig::Coco {
                        policy_ids,
                        trusted_certs_paths,
                        as_addr_config: Some(AsAddrConfig {
                            as_addr,
                            as_is_grpc,
                            as_headers,
                        }),
                    };
                    Ok(VerifyArgs::BackgroundCheck {
                        converter,
                        verifier,
                    })
                }
            },
            "passport" => match as_provider {
                ProviderType::Coco => {
                    let policy_ids = extract_required_vec_string(&mut fields, "policy_ids")?;
                    let trusted_certs_paths =
                        extract_optional_vec_string(&mut fields, "trusted_certs_paths")?;
                    let as_addr = extract_optional_string(&mut fields, "as_addr")?;
                    let as_is_grpc =
                        extract_optional_bool(&mut fields, "as_is_grpc")?.unwrap_or(false);
                    let as_headers =
                        extract_optional_string_map(&mut fields, "as_headers")?
                            .unwrap_or_default();
                    reject_unknown_fields(&fields)?;

                    let as_addr_config = as_addr.map(|addr| AsAddrConfig {
                        as_addr: addr,
                        as_is_grpc,
                        as_headers,
                    });
                    let verifier = VerifierConfig::Coco {
                        policy_ids,
                        trusted_certs_paths,
                        as_addr_config,
                    };
                    Ok(VerifyArgs::Passport { verifier })
                }
            },
            other => bail!(
                r#"unsupported value for "model" field: "{other}", should be one of ["background_check", "passport"]"#
            ),
        }
    }
}

impl<'de> Deserialize<'de> for AttestArgs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let input = AttestInput::deserialize(deserializer)?;
        AttestArgs::try_from(input).map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for VerifyArgs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let input = VerifyInput::deserialize(deserializer)?;
        VerifyArgs::try_from(input).map_err(serde::de::Error::custom)
    }
}

impl Serialize for AttestArgs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serde_json::Map::new();

        match self {
            AttestArgs::BackgroundCheck {
                attester,
                refresh_interval,
            } => {
                map.insert("model".into(), "background_check".into());
                serialize_attester_fields(&mut map, attester);
                if let Some(ri) = refresh_interval {
                    map.insert("refresh_interval".into(), (*ri).into());
                }
            }
            AttestArgs::Passport {
                attester,
                converter,
                refresh_interval,
            } => {
                map.insert("model".into(), "passport".into());
                serialize_attester_fields(&mut map, attester);
                serialize_converter_fields(&mut map, converter);
                if let Some(ri) = refresh_interval {
                    map.insert("refresh_interval".into(), (*ri).into());
                }
            }
        }

        serde_json::Value::Object(map).serialize(serializer)
    }
}

impl Serialize for VerifyArgs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serde_json::Map::new();

        match self {
            VerifyArgs::BackgroundCheck {
                converter,
                verifier,
            } => {
                map.insert("model".into(), "background_check".into());
                serialize_converter_fields(&mut map, converter);
                let VerifierConfig::Coco {
                    trusted_certs_paths,
                    ..
                } = verifier;
                if let Some(paths) = trusted_certs_paths {
                    map.insert("trusted_certs_paths".into(), serde_json::json!(paths));
                }
            }
            VerifyArgs::Passport { verifier } => {
                map.insert("model".into(), "passport".into());
                serialize_verifier_fields(&mut map, verifier);
            }
        }

        serde_json::Value::Object(map).serialize(serializer)
    }
}

fn serialize_attester_fields(
    map: &mut serde_json::Map<String, serde_json::Value>,
    attester: &AttesterConfig,
) {
    match attester {
        AttesterConfig::Coco { aa_addr } => {
            map.insert("aa_addr".into(), aa_addr.clone().into());
        }
    }
}

fn serialize_converter_fields(
    map: &mut serde_json::Map<String, serde_json::Value>,
    converter: &ConverterConfig,
) {
    match converter {
        ConverterConfig::Coco {
            as_addr,
            as_is_grpc,
            as_headers,
            policy_ids,
        } => {
            map.insert("as_addr".into(), as_addr.clone().into());
            map.insert("as_is_grpc".into(), (*as_is_grpc).into());
            map.insert("as_headers".into(), serde_json::json!(as_headers));
            map.insert("policy_ids".into(), serde_json::json!(policy_ids));
        }
    }
}

fn serialize_verifier_fields(
    map: &mut serde_json::Map<String, serde_json::Value>,
    verifier: &VerifierConfig,
) {
    match verifier {
        VerifierConfig::Coco {
            policy_ids,
            trusted_certs_paths,
            as_addr_config,
        } => {
            map.insert("policy_ids".into(), serde_json::json!(policy_ids));
            if let Some(paths) = trusted_certs_paths {
                map.insert("trusted_certs_paths".into(), serde_json::json!(paths));
            }
            if let Some(addr_config) = as_addr_config {
                map.insert("as_addr".into(), addr_config.as_addr.clone().into());
                map.insert("as_is_grpc".into(), addr_config.as_is_grpc.into());
                map.insert(
                    "as_headers".into(),
                    serde_json::json!(addr_config.as_headers),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_background_check_attest_without_model() {
        let json = json!(
            {
                "attest": {
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck {
                attester,
                refresh_interval,
            }) => {
                let AttesterConfig::Coco { aa_addr } = attester;
                assert_eq!(
                    aa_addr,
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                );
                assert_eq!(*refresh_interval, Some(3600));
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
        assert_eq!(
            ra_args.attest.as_ref().unwrap().attester_provider(),
            ProviderType::Coco
        );

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock""#));
        assert!(serialized.contains(r#""refresh_interval":3600"#));
        assert!(serialized.contains(r#""model":"background_check""#));
    }

    #[test]
    fn test_background_check_attest_with_model() {
        let json = json!(
            {
                "attest": {
                    "model": "background_check",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck {
                attester,
                refresh_interval,
            }) => {
                let AttesterConfig::Coco { aa_addr } = attester;
                assert_eq!(
                    aa_addr,
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                );
                assert_eq!(*refresh_interval, Some(3600));
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_passport_attest() {
        let json = json!(
            {
                "attest": {
                    "model": "passport",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600,
                    "as_addr": "localhost:8081",
                    "as_is_grpc": false,
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::Passport {
                attester,
                converter,
                refresh_interval,
            }) => {
                let AttesterConfig::Coco { aa_addr } = attester;
                assert_eq!(
                    aa_addr,
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                );
                assert_eq!(*refresh_interval, Some(3600));
                let ConverterConfig::Coco {
                    as_addr,
                    as_is_grpc,
                    policy_ids,
                    ..
                } = converter;
                assert_eq!(as_addr, "localhost:8081");
                assert!(!as_is_grpc);
                assert_eq!(policy_ids, &vec!["policy1", "policy2"]);
            }
            _ => panic!("Expected Passport variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""model":"passport""#));
        assert!(serialized.contains(r#""aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock""#));
        assert!(serialized.contains(r#""as_addr":"localhost:8081""#));
        assert!(serialized.contains(r#""policy_ids":["policy1","policy2"]"#));
    }

    #[test]
    #[should_panic]
    fn test_attest_bad_model() {
        let json = json!(
            {
                "attest": {
                    "model": "foobar",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        );

        serde_json::from_value::<RaArgsUnchecked>(json).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_passport_attest_missing_fields() {
        let json = json!(
            {
                "attest": {
                    "model": "passport",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        );

        serde_json::from_value::<RaArgsUnchecked>(json).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_verify_bad_model() {
        let json = json!(
            {
                "verify": {
                    "model": "foobar",
                    "as_addr": "localhost:8081",
                    "as_is_grpc": false,
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        serde_json::from_value::<RaArgsUnchecked>(json).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_passport_verify_missing_fields() {
        let json = json!(
            {
                "verify": {
                    "model": "passport",
                    "as_addr": "localhost:8081"
                }
            }
        );

        serde_json::from_value::<RaArgsUnchecked>(json).unwrap();
    }

    #[test]
    fn test_background_check_verify_without_model() {
        let json = json!(
            {
                "verify": {
                    "as_addr": "localhost:8081",
                    "as_is_grpc": false,
                    "policy_ids": ["policy1", "policy2"],
                    "trusted_certs_paths": null
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => {
                let ConverterConfig::Coco {
                    as_addr,
                    as_is_grpc,
                    policy_ids,
                    ..
                } = converter;
                assert_eq!(as_addr, "localhost:8081");
                assert!(!as_is_grpc);
                assert_eq!(policy_ids, &vec!["policy1", "policy2"]);
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_background_check_verify_with_model() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_addr": "localhost:8081",
                    "as_is_grpc": false,
                    "policy_ids": ["policy1", "policy2"],
                    "trusted_certs_paths": null
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => {
                let ConverterConfig::Coco {
                    as_addr,
                    as_is_grpc,
                    policy_ids,
                    ..
                } = converter;
                assert_eq!(as_addr, "localhost:8081");
                assert!(!as_is_grpc);
                assert_eq!(policy_ids, &vec!["policy1", "policy2"]);
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_passport_verify() {
        let json = json!(
            {
                "verify": {
                    "model": "passport",
                    "policy_ids": ["policy1", "policy2"],
                    "trusted_certs_paths": null
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::Passport { verifier }) => {
                let VerifierConfig::Coco { policy_ids, .. } = verifier;
                assert_eq!(policy_ids, &vec!["policy1", "policy2"]);
            }
            _ => panic!("Expected Passport variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""model":"passport""#));
        assert!(serialized.contains(r#""policy_ids":["policy1","policy2"]"#));
    }

    #[test]
    fn test_passport_verify_with_invalid_cert_path() {
        let json = json!(
            {
                "verify": {
                    "model": "passport",
                    "policy_ids": ["policy1"],
                    "trusted_certs_paths": ["/path/that/does/not/exist/cert.pem"]
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");
        let result = ra_args.into_checked();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("trusted certificate path does not exist"));
    }

    #[test]
    fn test_background_check_verify_with_invalid_cert_path() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_addr": "http://localhost:8080",
                    "policy_ids": ["policy1"],
                    "trusted_certs_paths": ["/path/that/does/not/exist/cert.pem"]
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");
        let result = ra_args.into_checked();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("trusted certificate path does not exist"));
    }

    #[test]
    fn test_background_check_verify_with_invalid_as_addr() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_addr": "not-a-valid-url",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");
        let result = ra_args.into_checked();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid attestation service address"));
    }

    #[test]
    fn test_background_check_verify_with_valid_as_addr() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_addr": "<should-be-a-url>:<should-be-a-port-number>",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value::<RaArgsUnchecked>(json).expect("Failed to deserialize");
        let result = ra_args.into_checked();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid attestation service address"));
    }

    #[test]
    fn test_background_check_attest_with_aa_provider() {
        let json = json!(
            {
                "attest": {
                    "aa_provider": "coco",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");
        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck { attester, .. }) => {
                assert_eq!(
                    ra_args.attest.as_ref().unwrap().attester_provider(),
                    ProviderType::Coco
                );
                let AttesterConfig::Coco { aa_addr } = attester;
                assert_eq!(
                    aa_addr,
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                );
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_passport_attest_with_providers() {
        let json = json!(
            {
                "attest": {
                    "aa_provider": "coco",
                    "as_provider": "coco",
                    "model": "passport",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600,
                    "as_addr": "localhost:8081",
                    "as_is_grpc": false,
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");
        match &ra_args.attest {
            Some(AttestArgs::Passport {
                attester,
                converter,
                ..
            }) => {
                assert_eq!(
                    ra_args.attest.as_ref().unwrap().attester_provider(),
                    ProviderType::Coco
                );
                let AttesterConfig::Coco { aa_addr } = attester;
                assert_eq!(
                    aa_addr,
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                );
                let ConverterConfig::Coco { as_addr, .. } = converter;
                assert_eq!(as_addr, "localhost:8081");
            }
            _ => panic!("Expected Passport variant"),
        }
    }

    #[test]
    fn test_background_check_verify_with_as_provider() {
        let json = json!(
            {
                "verify": {
                    "as_provider": "coco",
                    "model": "background_check",
                    "as_addr": "http://localhost:8081",
                    "as_is_grpc": false,
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");
        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => {
                assert_eq!(
                    ra_args.verify.as_ref().unwrap().verifier_provider(),
                    ProviderType::Coco
                );
                let ConverterConfig::Coco { as_addr, .. } = converter;
                assert_eq!(as_addr, "http://localhost:8081");
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_passport_verify_with_as_provider() {
        let json = json!(
            {
                "verify": {
                    "as_provider": "coco",
                    "model": "passport",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");
        match &ra_args.verify {
            Some(VerifyArgs::Passport { verifier }) => {
                assert_eq!(
                    ra_args.verify.as_ref().unwrap().verifier_provider(),
                    ProviderType::Coco
                );
                let VerifierConfig::Coco { policy_ids, .. } = verifier;
                assert_eq!(policy_ids, &vec!["policy1"]);
            }
            _ => panic!("Expected Passport variant"),
        }
    }

    #[test]
    fn test_attest_bad_aa_provider() {
        let json = json!(
            {
                "attest": {
                    "aa_provider": "unknown_provider",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        );

        let result = serde_json::from_value::<RaArgsUnchecked>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_bad_as_provider() {
        let json = json!(
            {
                "verify": {
                    "as_provider": "unknown_provider",
                    "model": "background_check",
                    "as_addr": "http://localhost:8081",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let result = serde_json::from_value::<RaArgsUnchecked>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_legacy_config_defaults_to_coco_provider() {
        let attest_json = json!(
            {
                "attest": {
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        );
        let ra_args: RaArgsUnchecked =
            serde_json::from_value(attest_json).expect("Failed to deserialize");
        assert_eq!(
            ra_args.attest.as_ref().unwrap().attester_provider(),
            ProviderType::Coco
        );

        let verify_json = json!(
            {
                "verify": {
                    "as_addr": "http://localhost:8081",
                    "policy_ids": ["policy1"]
                }
            }
        );
        let ra_args: RaArgsUnchecked =
            serde_json::from_value(verify_json).expect("Failed to deserialize");
        assert_eq!(
            ra_args.verify.as_ref().unwrap().verifier_provider(),
            ProviderType::Coco
        );
    }

    #[test]
    fn test_unknown_fields_rejected() {
        let json = json!(
            {
                "attest": {
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "some_unknown_field": "value"
                }
            }
        );
        let result = serde_json::from_value::<RaArgsUnchecked>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialization_roundtrip_background_check_attest() {
        let attest = AttestArgs::BackgroundCheck {
            attester: AttesterConfig::Coco {
                aa_addr: "unix:///test.sock".to_owned(),
            },
            refresh_interval: Some(600),
        };
        let ra = RaArgsUnchecked {
            no_ra: false,
            attest: Some(attest),
            verify: None,
        };
        let json_str = serde_json::to_string(&ra).unwrap();
        let ra2: RaArgsUnchecked = serde_json::from_str(&json_str).unwrap();
        assert_eq!(ra, ra2);
    }

    #[test]
    fn test_serialization_roundtrip_passport_attest() {
        let attest = AttestArgs::Passport {
            attester: AttesterConfig::Coco {
                aa_addr: "unix:///test.sock".to_owned(),
            },
            converter: ConverterConfig::Coco {
                as_addr: "http://localhost:8081".to_owned(),
                as_is_grpc: false,
                as_headers: HashMap::new(),
                policy_ids: vec!["p1".to_owned()],
            },
            refresh_interval: None,
        };
        let ra = RaArgsUnchecked {
            no_ra: false,
            attest: Some(attest),
            verify: None,
        };
        let json_str = serde_json::to_string(&ra).unwrap();
        let ra2: RaArgsUnchecked = serde_json::from_str(&json_str).unwrap();
        assert_eq!(ra, ra2);
    }

    #[test]
    fn test_serialization_roundtrip_background_check_verify() {
        let verify = VerifyArgs::BackgroundCheck {
            converter: ConverterConfig::Coco {
                as_addr: "http://localhost:8081".to_owned(),
                as_is_grpc: false,
                as_headers: HashMap::new(),
                policy_ids: vec!["p1".to_owned()],
            },
            verifier: VerifierConfig::Coco {
                policy_ids: vec!["p1".to_owned()],
                trusted_certs_paths: Some(vec!["/tmp/cert.pem".to_owned()]),
                as_addr_config: Some(AsAddrConfig {
                    as_addr: "http://localhost:8081".to_owned(),
                    as_is_grpc: false,
                    as_headers: HashMap::new(),
                }),
            },
        };
        let ra = RaArgsUnchecked {
            no_ra: false,
            attest: None,
            verify: Some(verify),
        };
        let json_str = serde_json::to_string(&ra).unwrap();
        let ra2: RaArgsUnchecked = serde_json::from_str(&json_str).unwrap();
        assert_eq!(ra, ra2);
    }

    #[test]
    fn test_serialization_roundtrip_passport_verify() {
        let verify = VerifyArgs::Passport {
            verifier: VerifierConfig::Coco {
                policy_ids: vec!["p1".to_owned()],
                trusted_certs_paths: None,
                as_addr_config: Some(AsAddrConfig {
                    as_addr: "http://localhost:8081".to_owned(),
                    as_is_grpc: true,
                    as_headers: HashMap::from([("key".to_owned(), "value".to_owned())]),
                }),
            },
        };
        let ra = RaArgsUnchecked {
            no_ra: false,
            attest: None,
            verify: Some(verify),
        };
        let json_str = serde_json::to_string(&ra).unwrap();
        let ra2: RaArgsUnchecked = serde_json::from_str(&json_str).unwrap();
        assert_eq!(ra, ra2);
    }
}

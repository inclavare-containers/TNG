pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/tng.ohttp.serf_message.rs"));
}

use anyhow::{anyhow, Context};
use prost_types::Timestamp;
use std::time::SystemTime;

use crate::tunnel::egress::protocol::ohttp::security::key_manager::KeyInfo;
use vec1::Vec1;

// ========== Rust to Protobuf ==========

impl TryFrom<super::cluster_key_set::ClusterKeySet> for pb::ClusterKeySet {
    type Error = anyhow::Error;

    fn try_from(value: super::cluster_key_set::ClusterKeySet) -> Result<Self, Self::Error> {
        Ok(Self {
            pending: value
                .pending
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .context("failed to convert pending keys")?,
            active: value
                .active
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .context("failed to convert active keys")?,
            stale: value
                .stale
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .context("failed to convert stale keys")?,
            rotation_interval: value.rotation_interval,
        })
    }
}

impl TryFrom<KeyInfo> for pb::KeyInfo {
    type Error = anyhow::Error;

    fn try_from(value: KeyInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            key_config: Some(value.key_config.try_into()?),
            status: value.status as i32,
            actived_at: Some(system_time_to_timestamp(value.actived_at)),
            stale_at: Some(system_time_to_timestamp(value.stale_at)),
            expire_at: Some(system_time_to_timestamp(value.expire_at)),
        })
    }
}

impl TryFrom<ohttp::KeyConfig> for pb::KeyConfig {
    type Error = anyhow::Error;

    fn try_from(value: ohttp::KeyConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            key_id: value.key_id() as u32,
            kem: value.kem() as i32,
            symmetric: value.symmetric().iter().map(Into::into).collect(),
            sk: value
                .dangerous_sk()
                .context("missing private key in the key config")?
                .serialize_to_pkcs8_pem()
                .context("failed to serialize private key to pkcs8 pem")?,
        })
    }
}

impl From<&ohttp::SymmetricSuite> for pb::SymmetricSuite {
    fn from(value: &ohttp::SymmetricSuite) -> Self {
        Self {
            kdf: value.kdf() as i32,
            aead: value.aead() as i32,
        }
    }
}

// ========== Protobuf to Rust ==========

impl TryFrom<pb::ClusterKeySet> for super::cluster_key_set::ClusterKeySet {
    type Error = anyhow::Error;

    fn try_from(value: pb::ClusterKeySet) -> Result<Self, Self::Error> {
        let pending: Vec<KeyInfo> = value
            .pending
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .context("failed to convert pending keys")?;

        let active_keys: Vec<KeyInfo> = value
            .active
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .context("failed to convert active keys")?;

        // ClusterKeySet requires at least one active key
        let active = Vec1::try_from(active_keys)
            .map_err(|_| anyhow::anyhow!("ClusterKeySet must have at least one active key"))?;

        let stale: Vec<KeyInfo> = value
            .stale
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .context("failed to convert stale keys")?;

        Ok(Self {
            pending,
            active,
            stale,
            rotation_interval: value.rotation_interval,
        })
    }
}

impl TryFrom<pb::KeyInfo> for KeyInfo {
    type Error = anyhow::Error;

    fn try_from(value: pb::KeyInfo) -> Result<Self, Self::Error> {
        let key_config = value
            .key_config
            .ok_or_else(|| anyhow!("missing key_config field"))?
            .try_into()
            .context("failed to convert KeyConfig")?;

        let status = value.status.try_into().context("invalid KeyStatus")?;

        let actived_at =
            timestamp_to_system_time(value.actived_at).context("invalid actived_at timestamp")?;
        let stale_at =
            timestamp_to_system_time(value.stale_at).context("invalid stale_at timestamp")?;
        let expire_at =
            timestamp_to_system_time(value.expire_at).context("invalid expire_at timestamp")?;

        Ok(Self {
            key_config,
            status,
            actived_at,
            stale_at,
            expire_at,
        })
    }
}

impl TryFrom<pb::KeyConfig> for ohttp::KeyConfig {
    type Error = anyhow::Error;

    fn try_from(value: pb::KeyConfig) -> Result<Self, Self::Error> {
        let key_id = u8::try_from(value.key_id)
            .with_context(|| format!("key_id {} out of range for u8", value.key_id))?;

        let kem_value = u16::try_from(value.kem)
            .with_context(|| format!("kem value {} out of range for u16", value.kem))?;
        let kem = ohttp::hpke::Kem::try_from(kem_value)
            .with_context(|| anyhow!("unsupported KEM algorithm ID: {}", kem_value))?;

        let symmetric = value
            .symmetric
            .into_iter()
            .map(|s| s.try_into())
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse symmetric suites")?;

        let key_config = ohttp::KeyConfig::new_from_pkcs8_pem(key_id, kem, symmetric, &value.sk)
            .context("failed to construct KeyConfig from PKCS#8")?;

        Ok(key_config)
    }
}

impl TryFrom<pb::SymmetricSuite> for ohttp::SymmetricSuite {
    type Error = anyhow::Error;

    fn try_from(value: pb::SymmetricSuite) -> Result<Self, Self::Error> {
        let kdf_value = u16::try_from(value.kdf)
            .with_context(|| format!("KDF value {} out of range for u16", value.kdf))?;
        let aead_value = u16::try_from(value.aead)
            .with_context(|| format!("AEAD value {} out of range for u16", value.aead))?;

        let kdf = ohttp::hpke::Kdf::try_from(kdf_value)
            .with_context(|| anyhow!("unsupported KDF algorithm ID: {}", kdf_value))?;
        let aead = ohttp::hpke::Aead::try_from(aead_value)
            .with_context(|| anyhow!("unsupported AEAD algorithm ID: {}", aead_value))?;

        Ok(Self::new(kdf, aead))
    }
}

// ========== Helper Functions ==========

fn system_time_to_timestamp(t: SystemTime) -> Timestamp {
    t.into()
}

fn timestamp_to_system_time(ts: Option<Timestamp>) -> Result<SystemTime, anyhow::Error> {
    let ts = ts.ok_or_else(|| anyhow!("missing timestamp"))?;

    if ts.nanos < 0 || ts.nanos >= 1_000_000_000 {
        return Err(anyhow!("timestamp has invalid nanos: {}", ts.nanos));
    }

    let secs = u64::try_from(ts.seconds)
        .with_context(|| anyhow!("timestamp seconds out of range: {}", ts.seconds))?;

    std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::new(secs, ts.nanos as u32))
        .ok_or_else(|| anyhow!("invalid duration derived from timestamp"))
}

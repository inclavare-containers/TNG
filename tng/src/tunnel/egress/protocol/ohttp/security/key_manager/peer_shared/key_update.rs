pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/tng.ohttp.key_update.rs"));
}

use anyhow::{anyhow, Context};
use prost_types::Timestamp;
use std::{borrow::Cow, time::SystemTime};

use crate::tunnel::egress::protocol::ohttp::security::key_manager::{self, callback_manager};

// === rust type to protobuf type ===

impl<'a> TryFrom<super::serf::KeyUpdateMessage<'a>> for pb::KeyUpdateMessage {
    type Error = anyhow::Error;

    fn try_from(value: super::serf::KeyUpdateMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            node_id: value.node_id.to_string(),
            event: Some(value.event.try_into()?),
        })
    }
}

impl TryFrom<key_manager::KeyInfo> for pb::KeyInfo {
    type Error = anyhow::Error;

    fn try_from(value: key_manager::KeyInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            key_config: Some(value.key_config.try_into()?),
            status: value.status as i32,
            created_at: Some(Self::system_time_to_timestamp(value.created_at)),
            stale_at: Some(Self::system_time_to_timestamp(value.stale_at)),
            expire_at: Some(Self::system_time_to_timestamp(value.expire_at)),
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

impl<'a> TryFrom<callback_manager::KeyChangeEvent<'a>> for pb::key_update_message::Event {
    type Error = anyhow::Error;

    fn try_from(event: callback_manager::KeyChangeEvent<'a>) -> Result<Self, Self::Error> {
        use pb::key_update_message::Event;
        match event {
            callback_manager::KeyChangeEvent::Created { key_info } => {
                let key_info = pb::KeyInfo::try_from(key_info.into_owned())
                    .context("failed to convert KeyInfo for Created event")?;
                Ok(Event::Created(pb::KeyEventCreated {
                    key_info: Some(key_info),
                }))
            }
            callback_manager::KeyChangeEvent::Removed { key_info } => {
                let key_info = pb::KeyInfo::try_from(key_info.into_owned())
                    .context("failed to convert KeyInfo for Removed event")?;
                Ok(Event::Removed(pb::KeyEventRemoved {
                    key_info: Some(key_info),
                }))
            }
            callback_manager::KeyChangeEvent::StatusChanged {
                key_info,
                old_status,
                new_status,
            } => {
                let key_info = pb::KeyInfo::try_from(key_info.into_owned())
                    .context("failed to convert KeyInfo for StatusChanged event")?;
                Ok(Event::StatusChanged(pb::KeyEventStatusChanged {
                    key_info: Some(key_info),
                    old_status: old_status as i32,
                    new_status: new_status as i32,
                }))
            }
        }
    }
}

// === protobuf type to rust type ===

impl pb::KeyInfo {
    fn system_time_to_timestamp(t: SystemTime) -> Timestamp {
        t.into()
    }
}

impl TryFrom<pb::KeyUpdateMessage> for super::serf::KeyUpdateMessage<'static> {
    type Error = anyhow::Error;

    fn try_from(value: pb::KeyUpdateMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            node_id: value.node_id,
            event: value
                .event
                .ok_or_else(|| anyhow::anyhow!("missing event"))?
                .try_into()
                .context("failed to convert key event")?,
        })
    }
}

impl TryFrom<pb::KeyInfo> for key_manager::KeyInfo {
    type Error = anyhow::Error;

    fn try_from(value: pb::KeyInfo) -> Result<Self, Self::Error> {
        let key_config = value
            .key_config
            .ok_or_else(|| anyhow!("missing key_config field"))?
            .try_into()
            .context("failed to convert KeyConfig")?;

        let status = value.status.try_into().context("invalid KeyStatus")?;

        let created_at =
            timestamp_to_system_time(value.created_at).context("invalid created_at timestamp")?;
        let stale_at =
            timestamp_to_system_time(value.stale_at).context("invalid stale_at timestamp")?;
        let expire_at =
            timestamp_to_system_time(value.expire_at).context("invalid expire_at timestamp")?;

        Ok(Self {
            key_config,
            status,
            created_at,
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
impl TryFrom<i32> for key_manager::KeyStatus {
    type Error = anyhow::Error;

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(key_manager::KeyStatus::Active),
            1 => Ok(key_manager::KeyStatus::Stale),
            _ => Err(anyhow!("unknown KeyStatus value: {}", v)),
        }
    }
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

impl TryFrom<pb::key_update_message::Event> for callback_manager::KeyChangeEvent<'static> {
    type Error = anyhow::Error;

    fn try_from(event: pb::key_update_message::Event) -> Result<Self, Self::Error> {
        use pb::key_update_message::Event;
        match event {
            Event::Created(pb::KeyEventCreated { key_info }) => {
                let key_info = key_info
                    .ok_or_else(|| anyhow!("missing key_info in KeyEventCreated"))?
                    .try_into()
                    .context("failed to convert KeyInfo in Created event")?;
                Ok(callback_manager::KeyChangeEvent::Created {
                    key_info: Cow::Owned(key_info),
                })
            }
            Event::Removed(pb::KeyEventRemoved { key_info }) => {
                let key_info = key_info
                    .ok_or_else(|| anyhow!("missing key_info in KeyEventRemoved"))?
                    .try_into()
                    .context("failed to convert KeyInfo in Removed event")?;
                Ok(callback_manager::KeyChangeEvent::Removed {
                    key_info: Cow::Owned(key_info),
                })
            }
            Event::StatusChanged(pb::KeyEventStatusChanged {
                key_info,
                old_status,
                new_status,
            }) => {
                let key_info = key_info
                    .ok_or_else(|| anyhow!("missing key_info in KeyEventStatusChanged"))?
                    .try_into()
                    .context("failed to convert KeyInfo in StatusChanged event")?;
                let old_status = old_status
                    .try_into()
                    .context("invalid old_status in StatusChanged")?;
                let new_status = new_status
                    .try_into()
                    .context("invalid new_status in StatusChanged")?;

                Ok(callback_manager::KeyChangeEvent::StatusChanged {
                    key_info: Cow::Owned(key_info),
                    old_status,
                    new_status,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::egress::protocol::ohttp::security::key_manager::{KeyInfo, KeyStatus};
    use crate::tunnel::ohttp::key_config::KeyConfigExtend;
    use bytes::BytesMut;
    use ohttp::hpke::{Aead, Kdf, Kem};
    use prost::Message;
    use std::time::Duration;

    fn make_test_key_config() -> ohttp::KeyConfig {
        ohttp::KeyConfig::new(
            1,
            Kem::X25519Sha256,
            vec![ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm)],
        )
        .expect("failed to create test key config")
    }

    fn make_test_key_info() -> KeyInfo {
        let now = SystemTime::now();
        KeyInfo {
            key_config: make_test_key_config(),
            status: KeyStatus::Active,
            created_at: now,
            stale_at: now + Duration::from_secs(3600),
            expire_at: now + Duration::from_secs(7200),
        }
    }

    // === Roundtrip tests ===

    #[test]
    fn test_key_config_roundtrip() {
        let original = make_test_key_config();
        let pb: pb::KeyConfig = original.clone().try_into().unwrap();
        let restored: ohttp::KeyConfig = pb.try_into().unwrap();
        assert_eq!(original.key_id(), restored.key_id());
        assert_eq!(original.kem(), restored.kem());
    }

    #[test]
    fn test_key_info_roundtrip() {
        let original = make_test_key_info();
        let pb: pb::KeyInfo = original.clone().try_into().unwrap();
        let restored: KeyInfo = pb.try_into().unwrap();
        assert_eq!(original.status as i32, restored.status as i32);
        assert_eq!(
            original.key_config.public_key_data().unwrap(),
            restored.key_config.public_key_data().unwrap()
        );
    }

    #[test]
    fn test_key_event_created_roundtrip() {
        let key_info = make_test_key_info();
        let event = callback_manager::KeyChangeEvent::Created {
            key_info: Cow::Owned(key_info),
        };
        let pb_event: pb::key_update_message::Event = event.try_into().unwrap();
        let restored: callback_manager::KeyChangeEvent<'static> = pb_event.try_into().unwrap();
        assert!(matches!(
            restored,
            callback_manager::KeyChangeEvent::Created { .. }
        ));
    }

    #[test]
    fn test_key_event_removed_roundtrip() {
        let key_info = make_test_key_info();
        let event = callback_manager::KeyChangeEvent::Removed {
            key_info: Cow::Owned(key_info),
        };
        let pb_event: pb::key_update_message::Event = event.try_into().unwrap();
        let restored: callback_manager::KeyChangeEvent<'static> = pb_event.try_into().unwrap();
        assert!(matches!(
            restored,
            callback_manager::KeyChangeEvent::Removed { .. }
        ));
    }

    #[test]
    fn test_key_event_status_changed_roundtrip() {
        let key_info = make_test_key_info();
        let event = callback_manager::KeyChangeEvent::StatusChanged {
            key_info: Cow::Owned(key_info.clone()),
            old_status: KeyStatus::Active,
            new_status: KeyStatus::Stale,
        };
        let pb_event: pb::key_update_message::Event = event.try_into().unwrap();
        let restored: callback_manager::KeyChangeEvent<'static> = pb_event.try_into().unwrap();
        if let callback_manager::KeyChangeEvent::StatusChanged {
            old_status,
            new_status,
            ..
        } = restored
        {
            assert_eq!(old_status as i32, KeyStatus::Active as i32);
            assert_eq!(new_status as i32, KeyStatus::Stale as i32);
        } else {
            panic!("expected StatusChanged event");
        }
    }

    #[test]
    fn test_key_update_message_encode_decode_roundtrip() {
        let key_info = make_test_key_info();
        let rust_msg = super::super::serf::KeyUpdateMessage {
            node_id: "test-node-uuid".to_string(),
            event: callback_manager::KeyChangeEvent::Created {
                key_info: Cow::Owned(key_info),
            },
        };
        let pb_msg: pb::KeyUpdateMessage = rust_msg.try_into().unwrap();

        let mut buf = BytesMut::new();
        pb_msg.encode(&mut buf).unwrap();

        let decoded = pb::KeyUpdateMessage::decode(buf.as_ref()).unwrap();
        assert_eq!(decoded.node_id, "test-node-uuid");
        assert!(decoded.event.is_some());
    }

    // === Error case tests ===

    #[test]
    fn test_decode_missing_event() {
        let pb_msg = pb::KeyUpdateMessage {
            node_id: "node".to_string(),
            event: None,
        };
        let mut buf = BytesMut::new();
        pb_msg.encode(&mut buf).unwrap();
        let decoded = pb::KeyUpdateMessage::decode(buf.as_ref()).unwrap();
        let result: Result<super::super::serf::KeyUpdateMessage<'static>, _> = decoded.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_key_info_missing_key_config() {
        let pb_info = pb::KeyInfo {
            key_config: None,
            status: 0,
            created_at: Some(Timestamp::default()),
            stale_at: Some(Timestamp::default()),
            expire_at: Some(Timestamp::default()),
        };
        let result: Result<KeyInfo, _> = pb_info.try_into();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key_config"));
    }

    #[test]
    fn test_key_info_missing_timestamps() {
        let original_config = make_test_key_config();
        let pb_config: pb::KeyConfig = original_config.clone().try_into().unwrap();
        let pb_info = pb::KeyInfo {
            key_config: Some(pb_config),
            status: 0,
            created_at: None,
            stale_at: Some(Timestamp::default()),
            expire_at: Some(Timestamp::default()),
        };
        let result: Result<KeyInfo, _> = pb_info.try_into();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("created_at"));
    }

    #[test]
    fn test_invalid_key_status_value() {
        let result: Result<key_manager::KeyStatus, _> = 99.try_into();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("99"));
    }

    #[test]
    fn test_negative_timestamp_seconds() {
        let ts = Timestamp {
            seconds: -1,
            nanos: 0,
        };
        let result = timestamp_to_system_time(Some(ts));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_nanos() {
        let ts = Timestamp {
            seconds: 1_000_000,
            nanos: 2_000_000_000,
        };
        let result = timestamp_to_system_time(Some(ts));
        assert!(result.is_err());
    }

    #[test]
    fn test_key_id_out_of_range() {
        let pb_config = pb::KeyConfig {
            key_id: 300,
            kem: pb::Kem::X25519Sha256 as i32,
            symmetric: vec![pb::SymmetricSuite {
                kdf: pb::Kdf::HkdfSha256 as i32,
                aead: pb::Aead::Aes128Gcm as i32,
            }],
            sk: String::new(),
        };
        let result: Result<ohttp::KeyConfig, _> = pb_config.try_into();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key_id"));
    }

    #[test]
    fn test_reserved_enum_values_rejected() {
        let pb_config = pb::KeyConfig {
            key_id: 1,
            kem: pb::Kem::Reserved as i32,
            symmetric: vec![pb::SymmetricSuite {
                kdf: pb::Kdf::HkdfSha256 as i32,
                aead: pb::Aead::Aes128Gcm as i32,
            }],
            sk: String::new(),
        };
        let result: Result<ohttp::KeyConfig, _> = pb_config.try_into();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported"));
    }
}

use hpke::generic_array::GenericArray;
use sha2::Digest;

use crate::error::TngError;

pub type KeyConfigHash =
    GenericArray<u8, <sha2::Sha256 as sha2::digest::OutputSizeUser>::OutputSize>;

pub(crate) trait KeyConfigExtend {
    fn key_config_hash(&self) -> Result<KeyConfigHash, TngError>;
}

impl KeyConfigExtend for ohttp::KeyConfig {
    fn key_config_hash(&self) -> Result<KeyConfigHash, TngError> {
        Ok(sha2::Sha256::digest(self.encode()?))
    }
}

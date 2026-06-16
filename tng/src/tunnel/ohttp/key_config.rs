use crate::error::TngError;
use serde::ser::Serializer;

#[derive(Eq, Hash, PartialEq, Clone, Ord, PartialOrd)]
pub struct PublicKeyData(Vec<u8>);

impl serde::Serialize for PublicKeyData {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl PublicKeyData {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Debug for PublicKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for PublicKeyData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) trait KeyConfigExtend {
    fn public_key(&self) -> Result<PublicKeyData, TngError>;
}

impl KeyConfigExtend for ohttp::KeyConfig {
    fn public_key(&self) -> Result<PublicKeyData, TngError> {
        Ok(PublicKeyData::new(self.pk_data()?))
    }
}

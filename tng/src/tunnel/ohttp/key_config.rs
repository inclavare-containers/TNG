use crate::error::TngError;

#[derive(Eq, Hash, PartialEq, Clone)]
pub struct PublicKeyData(Vec<u8>);

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

pub(crate) trait KeyConfigExtend {
    fn public_key_data(&self) -> Result<PublicKeyData, TngError>;
}

impl KeyConfigExtend for ohttp::KeyConfig {
    fn public_key_data(&self) -> Result<PublicKeyData, TngError> {
        Ok(PublicKeyData::new(self.pk_data()?))
    }
}

use crate::errors::*;

use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use sha2::Digest as _;
use zeroize::Zeroizing;

#[derive(PartialEq, Debug, Clone, Copy)]
#[repr(C)]
pub enum HashAlgo {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(PartialEq, Debug, Clone, Copy)]
#[repr(C)]
pub enum AsymmetricAlgo {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    P256,
}

// TODO: try refactor AsymmetricPrivateKey to AsymmetricAlgo + trait object
#[derive(Debug, Clone)]
pub enum AsymmetricPrivateKey {
    Rsa2048(rsa::RsaPrivateKey),
    Rsa3072(rsa::RsaPrivateKey),
    Rsa4096(rsa::RsaPrivateKey),
    P256(p256::SecretKey),
}

impl AsymmetricPrivateKey {
    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>> {
        Ok(match self {
            AsymmetricPrivateKey::Rsa2048(key)
            | AsymmetricPrivateKey::Rsa3072(key)
            | AsymmetricPrivateKey::Rsa4096(key) => key.to_pkcs8_pem(LineEnding::LF)?,
            AsymmetricPrivateKey::P256(key) => key.to_pkcs8_pem(LineEnding::LF)?,
        })
    }

    pub fn from_pkcs8_pem(private_key_pkcs8: &str) -> Result<Self> {
        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_pem(private_key_pkcs8) {
            let bit_len = key.n().bits();
            match bit_len {
                2048 => Ok(AsymmetricPrivateKey::Rsa2048(key)),
                3072 => Ok(AsymmetricPrivateKey::Rsa3072(key)),
                4096 => Ok(AsymmetricPrivateKey::Rsa4096(key)),
                _ => Err(Error::kind_with_msg(
                    ErrorKind::ParsePrivateKey,
                    format!("unsupported rsa modulus bit length: {}", bit_len),
                )),
            }
        } else {
            match p256::SecretKey::from_pkcs8_pem(private_key_pkcs8) {
                Ok(key) => Ok(AsymmetricPrivateKey::P256(key)),
                Err(e) => Err(e).kind(ErrorKind::ParsePrivateKey).context(format!(
                    "failed to parse private key from pkcs8 pem format. content: '{}'",
                    private_key_pkcs8,
                )),
            }
        }
    }
}

pub struct DefaultCrypto {}

impl DefaultCrypto {
    pub fn gen_private_key(algo: AsymmetricAlgo) -> Result<AsymmetricPrivateKey> {
        let mut rng = rand::thread_rng();
        match algo {
            AsymmetricAlgo::Rsa2048 => Ok(AsymmetricPrivateKey::Rsa2048(rsa::RsaPrivateKey::new(
                &mut rng, 2048,
            )?)),
            AsymmetricAlgo::Rsa3072 => Ok(AsymmetricPrivateKey::Rsa3072(rsa::RsaPrivateKey::new(
                &mut rng, 3072,
            )?)),
            AsymmetricAlgo::Rsa4096 => Ok(AsymmetricPrivateKey::Rsa4096(rsa::RsaPrivateKey::new(
                &mut rng, 4096,
            )?)),
            AsymmetricAlgo::P256 => Ok(AsymmetricPrivateKey::P256(p256::SecretKey::random(
                &mut rng,
            ))),
        }
    }

    /// Calculate hash of SubjectPublicKeyInfo(SPKI) object
    pub fn hash_of_private_key(
        hash_algo: HashAlgo,
        private_key: &AsymmetricPrivateKey,
    ) -> Result<Vec<u8>> {
        let spki_doc = match private_key {
            AsymmetricPrivateKey::Rsa2048(key)
            | AsymmetricPrivateKey::Rsa3072(key)
            | AsymmetricPrivateKey::Rsa4096(key) => key.to_public_key().to_public_key_der(),
            AsymmetricPrivateKey::P256(key) => key.public_key().to_public_key_der(),
        }?;
        let bytes = spki_doc.as_bytes();

        Ok(Self::hash(hash_algo, bytes))
    }

    pub fn hash(hash_algo: HashAlgo, bytes: &[u8]) -> Vec<u8> {
        match hash_algo {
            HashAlgo::Sha256 => sha2::Sha256::new().chain_update(bytes).finalize().to_vec(),
            HashAlgo::Sha384 => sha2::Sha384::new().chain_update(bytes).finalize().to_vec(),
            HashAlgo::Sha512 => sha2::Sha512::new().chain_update(bytes).finalize().to_vec(),
        }
    }
}

#[cfg(test)]
pub mod tests {

    use rayon::iter::{IntoParallelIterator as _, ParallelIterator};

    use super::*;

    #[test]
    fn test_gen_private_key() -> Result<()> {
        [
            AsymmetricAlgo::Rsa2048,
            AsymmetricAlgo::Rsa3072,
            AsymmetricAlgo::Rsa4096,
            AsymmetricAlgo::P256,
        ]
        .into_par_iter()
        .map(|algo| {
            let key = DefaultCrypto::gen_private_key(algo)?.to_pkcs8_pem()?;
            println!("generated {:?} key:\n{}", algo, key.as_str());
            Ok(())
        })
        .collect()
    }
}

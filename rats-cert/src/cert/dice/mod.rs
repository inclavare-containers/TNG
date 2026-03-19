pub mod cbor;
pub mod extensions;

use self::extensions::{DiceEndorsementExtension, DiceEvidenceExtension};
use crate::crypto::{AsymmetricPrivateKey, HashAlgo};
use crate::errors::*;

use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::Builder;
use x509_cert::builder::{CertificateBuilder, Profile};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

pub(crate) fn generate_and_sign_dice_cert(
    subject: &str,
    hash_algo: HashAlgo,
    private_key: &AsymmetricPrivateKey,
    evidence_buffer: &[u8],
    endorsements_buffer: Option<&[u8]>,
) -> Result<Certificate> {
    let serial_number = SerialNumber::from(42u32);
    // TODO: use per-connection freshness instead of longer duration, currently is 6 hours
    let validity = Validity::from_now(Duration::new(6 * 60 * 60, 0))
        .kind(ErrorKind::GenCertError)
        .context("bad validity value")?;
    let subject = Name::from_str(subject)
        .kind(ErrorKind::GenCertError)
        .with_context(|| format!("bad subject value `{}`", subject))?;
    let profile = Profile::Leaf {
        issuer: subject.clone(),
        enable_key_agreement: true,
        enable_key_encipherment: true,
    };

    let pub_key_info = match private_key {
        AsymmetricPrivateKey::Rsa2048(key)
        | AsymmetricPrivateKey::Rsa3072(key)
        | AsymmetricPrivateKey::Rsa4096(key) => {
            SubjectPublicKeyInfoOwned::from_key(key.to_public_key())
        }
        AsymmetricPrivateKey::P256(key) => SubjectPublicKeyInfoOwned::from_key(key.public_key()),
    }
    .kind(ErrorKind::GenCertError)
    .context("failed to create SubjectPublicKeyInfo")?;

    macro_rules! build_with_signer {
        ($signer:expr) => {
            build_with_signer!($signer, _)
        };
        ($signer:expr, $signature_type:ty) => {{
            let signer = $signer;

            let mut builder = CertificateBuilder::new(
                profile,
                serial_number,
                validity,
                subject,
                pub_key_info,
                &signer,
            )
            .kind(ErrorKind::GenCertError)
            .context("failed to create certificate builder")?;

            builder
                .add_extension(&DiceEvidenceExtension(evidence_buffer))
                .kind(ErrorKind::GenCertError)
                .context("failed to add evidence extension")?;

            if let Some(endorsements_buffer) = endorsements_buffer {
                builder
                    .add_extension(&DiceEndorsementExtension(endorsements_buffer))
                    .kind(ErrorKind::GenCertError)
                    .context("failed to add endorsement extension")?;
            }

            let certificate: x509_cert::Certificate = builder
                .build::<$signature_type>()
                .kind(ErrorKind::GenCertError)
                .context("failed to create certificate")?;

            certificate
        }};
    }

    let certificate = match private_key {
        AsymmetricPrivateKey::Rsa2048(key)
        | AsymmetricPrivateKey::Rsa3072(key)
        | AsymmetricPrivateKey::Rsa4096(key) => match hash_algo {
            HashAlgo::Sha256 => {
                build_with_signer!(rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone()))
            }
            HashAlgo::Sha384 => {
                build_with_signer!(rsa::pkcs1v15::SigningKey::<sha2::Sha384>::new(key.clone()))
            }
            HashAlgo::Sha512 => {
                build_with_signer!(rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(key.clone()))
            }
        },
        AsymmetricPrivateKey::P256(key) => {
            /* for p256(prime256v1), the hash algorithm implicitly is sha256 */
            build_with_signer!(
                p256::ecdsa::SigningKey::from(key),
                p256::ecdsa::DerSignature
            )
        }
    };

    Ok(certificate)
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::crypto::{AsymmetricAlgo, DefaultCrypto};
    use pkcs8::{der::EncodePem, LineEnding};

    #[test]
    fn test_gen_cert() -> Result<()> {
        let key = DefaultCrypto::gen_private_key(AsymmetricAlgo::P256)?;
        let pem = generate_and_sign_dice_cert(
            "CN=rats-rs,O=Inclavare Containers",
            HashAlgo::Sha256,
            &key,
            b"\x01\x02\x03\x04",
            Some(b"\x05\x06\x07\x08"),
        )?
        .to_pem(LineEnding::LF)
        .kind(ErrorKind::GenCertError)
        .context("failed to encode certificate as pem")?;

        println!("generated pem:\n{}", pem);
        // you can also view the cert manually with https://certificatedecoder.dev/

        Ok(())
    }
}

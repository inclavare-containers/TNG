use pkcs8::{AssociatedOid, ObjectIdentifier};
use x509_cert::ext::AsExtension;

pub const OID_TCG_DICE_TAGGED_EVIDENCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.5.4.9");

pub struct DiceEvidenceExtension<T: AsRef<[u8]>>(pub T);

impl<T: AsRef<[u8]>> AssociatedOid for DiceEvidenceExtension<T> {
    const OID: ObjectIdentifier = OID_TCG_DICE_TAGGED_EVIDENCE;
}

impl<T: AsRef<[u8]>> x509_cert::der::Encode for DiceEvidenceExtension<T> {
    fn encoded_len(&self) -> x509_cert::der::Result<x509_cert::der::Length> {
        Ok(x509_cert::der::Length::new(self.0.as_ref().len() as u16))
    }

    fn encode(&self, encoder: &mut impl x509_cert::der::Writer) -> x509_cert::der::Result<()> {
        encoder.write(self.0.as_ref())
    }
}

impl<T: AsRef<[u8]>> AsExtension for DiceEvidenceExtension<T> {
    fn critical(
        &self,
        _subject: &x509_cert::name::Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> bool {
        false
    }

    fn to_extension(
        &self,
        subject: &x509_cert::name::Name,
        extensions: &[x509_cert::ext::Extension],
    ) -> std::prelude::v1::Result<x509_cert::ext::Extension, x509_cert::der::Error> {
        let content = x509_cert::der::asn1::OctetString::new(self.0.as_ref())?;

        Ok(x509_cert::ext::Extension {
            extn_id: <Self as AssociatedOid>::OID,
            critical: self.critical(subject, extensions),
            extn_value: content,
        })
    }
}

pub const OID_TCG_DICE_ENDORSEMENT_MANIFEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.5.4.2");

pub struct DiceEndorsementExtension<T: AsRef<[u8]>>(pub T);

impl<T: AsRef<[u8]>> AssociatedOid for DiceEndorsementExtension<T> {
    const OID: ObjectIdentifier = OID_TCG_DICE_ENDORSEMENT_MANIFEST;
}

impl<T: AsRef<[u8]>> x509_cert::der::Encode for DiceEndorsementExtension<T> {
    fn encoded_len(&self) -> x509_cert::der::Result<x509_cert::der::Length> {
        Ok(x509_cert::der::Length::new(self.0.as_ref().len() as u16))
    }

    fn encode(&self, encoder: &mut impl x509_cert::der::Writer) -> x509_cert::der::Result<()> {
        encoder.write(self.0.as_ref())
    }
}

impl<T: AsRef<[u8]>> AsExtension for DiceEndorsementExtension<T> {
    fn critical(
        &self,
        _subject: &x509_cert::name::Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> bool {
        false
    }

    fn to_extension(
        &self,
        subject: &x509_cert::name::Name,
        extensions: &[x509_cert::ext::Extension],
    ) -> std::prelude::v1::Result<x509_cert::ext::Extension, x509_cert::der::Error> {
        let content = x509_cert::der::asn1::OctetString::new(self.0.as_ref())?;

        Ok(x509_cert::ext::Extension {
            extn_id: <Self as AssociatedOid>::OID,
            critical: self.critical(subject, extensions),
            extn_value: content,
        })
    }
}

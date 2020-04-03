use yasna::models::ObjectIdentifier;
use crate::certificate::extensions::Extension;

#[derive(Clone)]
pub struct SubjectKeyIdentifier(pub Vec<u8>);

impl From<SubjectKeyIdentifier> for Extension {
    fn from(ski:SubjectKeyIdentifier) -> Self {
        // OID: 2.5.29.14
        // {
        //      joint-iso-itu-t(2)
        //      ds(5)
        //      certificateExtension(29)
        //      subjectKeyIdentifier(14)
        //  }
        let extension_oid = ObjectIdentifier::from_slice(&[2,5,29,14]);
        let extension_value = yasna::construct_der(|writer| {
            writer.write_bytes(&ski.0);
        });
        Extension{
            oid: extension_oid,
            critical: false,
            value: extension_value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subject_key_identifier_should_encode_correctly () {

        let expected = vec!(0x30,0x2c, // SEQUENCE, 44 bytes
            0x06,0x03, // OID, 3 bytes
                0x55,0x1d,0x0e, // encoding of OID(2.5.29.14)
            0x01,0x01, // BOOL, 1 byte
                 0x00, // FALSE (is critical)
            0x04,0x22, // OCTET STRING 34 bytes
                 0x04,0x20, // OCTET STRING 32 bytes
                     0x3a,0x61,0xe7,0xe8,0x3f,0x1f,0x2e,0x55, // subject key identifier (sha 256)
                     0x10,0x4d,0x2f,0xf2,0x14,0xd3,0x65,0x4e,
                     0xf0,0xfd,0x66,0x5d,0x20,0x58,0x63,0x6d,
                     0x0e,0x28,0xd0,0xd1,0xcc,0xe5,0xb5,0x7a);

        let sha256:Vec<u8> = vec!(
            0x3a,0x61,0xe7,0xe8,0x3f,0x1f,0x2e,0x55,
            0x10,0x4d,0x2f,0xf2,0x14,0xd3,0x65,0x4e,
            0xf0,0xfd,0x66,0x5d,0x20,0x58,0x63,0x6d,
            0x0e,0x28,0xd0,0xd1,0xcc,0xe5,0xb5,0x7a
        );

        let ski = SubjectKeyIdentifier(sha256);
        let der = yasna::encode_der(&Extension::from(ski));

        assert_eq!(der, expected);
    }
}

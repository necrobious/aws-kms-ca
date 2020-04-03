use yasna::models::ObjectIdentifier;
use crate::certificate::extensions::Extension;

// OID: 2.5.29.15
// {
//      joint-iso-itu-t(2)
//      ds(5)
//      certificateExtension(29)
//      keyUsage(15)
//  }
const OID_CE_KEY_USAGE : &'static [u64] = &[2,5,29,15];

#[derive(Clone,Ord,PartialOrd,Eq,PartialEq)]
pub enum KeyUsage {
    DigitalSignature,
    ContentCommitment,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}
#[derive(Clone)]
pub struct KeyUsages(pub Vec<KeyUsage>);

impl From<KeyUsages> for Extension {
    fn from(ku:KeyUsages) -> Self {
        use KeyUsage::*;
        let extension_oid = ObjectIdentifier::from_slice(OID_CE_KEY_USAGE);
        let extension_value = yasna::construct_der(|writer| {
            let bits = [
                ku.0.contains(&DigitalSignature),
                ku.0.contains(&ContentCommitment),
                ku.0.contains(&KeyEncipherment),
                ku.0.contains(&DataEncipherment),
                ku.0.contains(&KeyAgreement),
                ku.0.contains(&KeyCertSign),
                ku.0.contains(&CrlSign),
                ku.0.contains(&EncipherOnly),
                ku.0.contains(&DecipherOnly),
            ];
            writer.write_bitvec(&bits.iter().map(|&i| i ).collect());
        });
        Extension{
            oid: extension_oid,
            critical: true,
            value: extension_value,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_usage_with_digital_signature_and_content_commitment_should_encode_correctly () {
        let expected = vec!(0x30,0x0f, // SEQUENCE, 15 bytes
            0x06,0x03, // OID, 3 bytes
                0x55,0x1d,0x0f, // encoding of OID(2.5.29.15)
            0x01,0x01, // BOOL, 1 byte
                 0xff, // TRUE (is critical)
            0x04,0x05, // OCTET STRING 5 bytes
                 0x03,0x03, // BIT STRING, 3 bytes length
                    0x07,   // 7 pad/unused bits SEE NOTE below
                    0xc0,   // b11000000
                            //  1   digitalSignature        (0),
                            //  1   nonRepudiation          (1),
                            //  0   keyEncipherment         (2),
                            //  0   dataEncipherment        (3),
                            //  0   keyAgreement            (4),
                            //  0   keyCertSign             (5),
                            //  0   cRLSign                 (6),
                            //  0   encipherOnly            (7),
                    0x00);  //  0   decipherOnly            (8)
                            //  0   pad, 7 bits
        let ku = KeyUsages(vec!(KeyUsage::DigitalSignature, KeyUsage::ContentCommitment));
        let der = yasna::encode_der(&Extension::from(ku));

        assert_eq!(der, expected);
    }

    #[test]
    fn key_usage_with_key_cert_sign_and_crl_sign_should_encode_correctly () {
        let expected = vec!(0x30,0x0f, // SEQUENCE, 15 bytes length
            0x06,0x03, // OID, 3 bytes length
                0x55,0x1d,0x0f, // encoding of OID(2.5.29.15)
            0x01,0x01, // BOOL, 1 byte length
                 0xff, // TRUE (is critical)
            0x04,0x05, // OCTET STRING 5 bytes length
                 0x03,0x03, // BIT STRING, 3 bytes length
                    0x07,   // 7 pad/unused bits SEE NOTE below
                    0x06,   // b00000110
                            //  0   digitalSignature        (0),
                            //  0   nonRepudiation          (1),
                            //  0   keyEncipherment         (2),
                            //  0   dataEncipherment        (3),
                            //  0   keyAgreement            (4),
                            //  1   keyCertSign             (5),
                            //  1   cRLSign                 (6),
                            //  0   encipherOnly            (7),
                    0x00);  //  0   decipherOnly            (8)
                            //  0   pad, 7 bits
        let ku = KeyUsages(vec!(KeyUsage::KeyCertSign, KeyUsage::CrlSign));
        let der = yasna::encode_der(&Extension::from(ku));

        assert_eq!(der, expected);
    }

    #[test]
    fn key_usage_with_digital_signature_content_commitment_key_cert_sign_crl_sign_should_encode_correctly () {
        let expected = vec!(0x30,0x0f, // SEQUENCE, 15 bytes length
            0x06,0x03, // OID, 3 bytes length
                0x55,0x1d,0x0f, // encoding of OID(2.5.29.15)
            0x01,0x01, // BOOL, 1 byte length
                 0xff, // TRUE (is critical)
            0x04,0x05, // OCTET STRING 5 bytes length
                 0x03,0x03, // BIT STRING, 3 bytes length
                    0x07,   // 7 pad/unused bits SEE NOTE below
                    0xc6,   // b11000110
                            //  1   digitalSignature        (0),
                            //  1   nonRepudiation          (1),
                            //  0   keyEncipherment         (2),
                            //  0   dataEncipherment        (3),
                            //  0   keyAgreement            (4),
                            //  1   keyCertSign             (5),
                            //  1   cRLSign                 (6),
                            //  0   encipherOnly            (7),
                    0x00);  //  0   decipherOnly            (8)
                            //  0   pad, 7 bits
        let ku = KeyUsages(vec!(
            KeyUsage::KeyCertSign,
            KeyUsage::CrlSign,
            KeyUsage::DigitalSignature,
            KeyUsage::ContentCommitment
        ));
        let der = yasna::encode_der(&Extension::from(ku));

        assert_eq!(der, expected);
    }

    #[test]
    fn key_usage_with_decipher_only_should_encode_correctly () {
        let expected = vec!(0x30,0x0f, // SEQUENCE, 15 bytes length
            0x06,0x03, // OID, 3 bytes length
                0x55,0x1d,0x0f, // encoding of OID(2.5.29.15)
            0x01,0x01, // BOOL, 1 byte length
                 0xff, // TRUE (is critical)
            0x04,0x05, // OCTET STRING 5 bytes length
                 0x03,0x03, // BIT STRING, 3 bytes length
                    0x07,   // 7 pad/unused bits SEE NOTE below
                    0x00,   //  0   digitalSignature        (0),
                            //  0   nonRepudiation          (1),
                            //  0   keyEncipherment         (2),
                            //  0   dataEncipherment        (3),
                            //  0   keyAgreement            (4),
                            //  0   keyCertSign             (5),
                            //  0   cRLSign                 (6),
                            //  0   encipherOnly            (7),
                    0x80);  //  1   decipherOnly            (8)
                            //  0   pad, 7 bits
        let ku = KeyUsages(vec!(
            KeyUsage::DecipherOnly,
        ));
        let der = yasna::encode_der(&Extension::from(ku));

        assert_eq!(der, expected);
    }
}
// NOTE: Key useage BIT STRING DER envoding appears to have two ways of encoding a BIT STRING with
// with no 1 bits in the trailing, padded byte, and the `yasna` crate's choice appears to be the
// 'explicit' way of encoding, where the number of unused bits is explictly defined, and a 0x00
// byte added. OpenSSL appears to use the more compact encodding mentioned in the thread in the
// following link:  https://mailarchive.ietf.org/arch/msg/pkix/AuzwGS2imBAUIXmc7QWUkfFSAw4/



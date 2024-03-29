use crate::certificate::key_algorithm_identifier::KeyAlgorithmIdentifier;
use yasna::{
    ASN1Error,
    ASN1ErrorKind,
    ASN1Result,
    DERWriter,
    DEREncodable,
    BERReader,
    BERDecodable,
};

#[cfg(feature = "tracing")]
use tracing::{debug};

#[derive(Clone, Debug, PartialEq,)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: KeyAlgorithmIdentifier,
    pub public_key: Vec<u8>,
}

impl From<&SubjectPublicKeyInfo> for SubjectPublicKeyInfo {
    fn from(spki: &SubjectPublicKeyInfo) -> SubjectPublicKeyInfo {
        spki.clone()
    }
}

impl BERDecodable for SubjectPublicKeyInfo {
    #[cfg_attr(feature = "tracing", tracing::instrument(name = "SubjectPublicKeyInfo::decode_ber"))]
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        #[cfg(feature = "tracing")]
        debug!("parsing subject public key info");
        reader.read_sequence(|reader| {
            let algorithm = KeyAlgorithmIdentifier::decode_ber(reader.next())?;
            if algorithm == KeyAlgorithmIdentifier::P256 ||
                algorithm == KeyAlgorithmIdentifier::P384 {

                let (public_key, bits_count) = reader.next().read_bitvec_bytes()?;

                if algorithm == KeyAlgorithmIdentifier::P256 && bits_count != 65 * 8 {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                } 

                if algorithm == KeyAlgorithmIdentifier::P384 && bits_count != 97 * 8 {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                } 

                return Ok(SubjectPublicKeyInfo {
                    algorithm: algorithm,
                    public_key: public_key,
                })
            }
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid)); 
        })
    }
}

impl DEREncodable for SubjectPublicKeyInfo {
    fn encode_der(&self, writer: DERWriter) {
        let len   = self.public_key.len();
        let bytes = self.public_key.as_slice();
        writer.write_sequence(|writer| {
            self.algorithm.encode_der(writer.next());
            writer.next().write_bitvec_bytes(bytes,len * 8);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subject_public_key_info_should_encode_correctly () {
        let expected = vec!(0x30,0x76, // SEQUENCE, 118 bytes
            // -- P-384 public key algorithm encoding
            0x30,0x10, // SEQUENCE, 16 bytes
                0x06,0x07, // OID, 7 bytes
                    0x2a,0x86,0x48,0xce,0x3d,0x02,0x01, // encoding of OID(1.2.840.10045.2.1)
                0x06,0x05, // OID, 5 bytes
                    0x2b,0x81,0x04,0x00,0x22, // encoding of OID(1.3.132.0.34)
            // -- P-384 Public Key encoding
            0x03,0x62,// BIT STRING, 98 bytes
                0x00, // unused bit count, 1 byte
                0x04,0x74,0xf4,0x86,0x1a,0x09,0xe2,0x5a, // P-384 Public Key, 97 bytes
                0xff,0x27,0xd3,0x02,0x71,0x72,0x56,0x33,
                0x7a,0xce,0x0b,0x92,0x00,0xb7,0xb0,0x7a,
                0x91,0x07,0x91,0xf3,0x1e,0xd8,0xc9,0xe1,
                0x32,0x4e,0x0e,0x0f,0x3b,0x84,0x00,0x33,
                0xb0,0x9d,0x1a,0x92,0xf0,0x20,0xa1,0x05,
                0xe8,0xdf,0xe1,0x2d,0xb5,0x08,0xdb,0x10,
                0xe1,0x17,0x1b,0xdc,0x35,0xbf,0x55,0xe6,
                0x98,0xb5,0x93,0xe2,0x5d,0xd7,0x05,0x8c,
                0x04,0x1a,0xfb,0x3f,0x2b,0x24,0xac,0x31,
                0x33,0xc6,0x7f,0xab,0xab,0x05,0x4c,0xda,
                0xed,0xbd,0x40,0x85,0x4a,0x90,0xc8,0x4f,
                0x9c
        );

        let spki = SubjectPublicKeyInfo {
            algorithm: KeyAlgorithmIdentifier::P384,
            public_key: vec!(
                0x04,0x74,0xf4,0x86,0x1a,0x09,0xe2,0x5a, // P-384 Public Key, 97 bytes
                0xff,0x27,0xd3,0x02,0x71,0x72,0x56,0x33,
                0x7a,0xce,0x0b,0x92,0x00,0xb7,0xb0,0x7a,
                0x91,0x07,0x91,0xf3,0x1e,0xd8,0xc9,0xe1,
                0x32,0x4e,0x0e,0x0f,0x3b,0x84,0x00,0x33,
                0xb0,0x9d,0x1a,0x92,0xf0,0x20,0xa1,0x05,
                0xe8,0xdf,0xe1,0x2d,0xb5,0x08,0xdb,0x10,
                0xe1,0x17,0x1b,0xdc,0x35,0xbf,0x55,0xe6,
                0x98,0xb5,0x93,0xe2,0x5d,0xd7,0x05,0x8c,
                0x04,0x1a,0xfb,0x3f,0x2b,0x24,0xac,0x31,
                0x33,0xc6,0x7f,0xab,0xab,0x05,0x4c,0xda,
                0xed,0xbd,0x40,0x85,0x4a,0x90,0xc8,0x4f,
                0x9c
            ),
        };

        let der = yasna::encode_der(&spki);

        assert_eq!(der, expected);
    }

    #[test]
    fn subject_public_key_info_should_decode_correctly () {
        let asserted = vec!(0x30,0x76, // SEQUENCE, 118 bytes
            // -- P-384 public key algorithm encoding
            0x30,0x10, // SEQUENCE, 16 bytes
                0x06,0x07, // OID, 7 bytes
                    0x2a,0x86,0x48,0xce,0x3d,0x02,0x01, // encoding of OID(1.2.840.10045.2.1)
                0x06,0x05, // OID, 5 bytes
                    0x2b,0x81,0x04,0x00,0x22, // encoding of OID(1.3.132.0.34)
            // -- P-384 Public Key encoding
            0x03,0x62,// BIT STRING, 98 bytes
                0x00, // unused bit count, 1 byte
                0x04,0x74,0xf4,0x86,0x1a,0x09,0xe2,0x5a, // P-384 Public Key, 97 bytes
                0xff,0x27,0xd3,0x02,0x71,0x72,0x56,0x33,
                0x7a,0xce,0x0b,0x92,0x00,0xb7,0xb0,0x7a,
                0x91,0x07,0x91,0xf3,0x1e,0xd8,0xc9,0xe1,
                0x32,0x4e,0x0e,0x0f,0x3b,0x84,0x00,0x33,
                0xb0,0x9d,0x1a,0x92,0xf0,0x20,0xa1,0x05,
                0xe8,0xdf,0xe1,0x2d,0xb5,0x08,0xdb,0x10,
                0xe1,0x17,0x1b,0xdc,0x35,0xbf,0x55,0xe6,
                0x98,0xb5,0x93,0xe2,0x5d,0xd7,0x05,0x8c,
                0x04,0x1a,0xfb,0x3f,0x2b,0x24,0xac,0x31,
                0x33,0xc6,0x7f,0xab,0xab,0x05,0x4c,0xda,
                0xed,0xbd,0x40,0x85,0x4a,0x90,0xc8,0x4f,
                0x9c
        );

        let spki = SubjectPublicKeyInfo {
            algorithm: KeyAlgorithmIdentifier::P384,
            public_key: vec!(
                0x04,0x74,0xf4,0x86,0x1a,0x09,0xe2,0x5a, // P-384 Public Key, 97 bytes
                0xff,0x27,0xd3,0x02,0x71,0x72,0x56,0x33,
                0x7a,0xce,0x0b,0x92,0x00,0xb7,0xb0,0x7a,
                0x91,0x07,0x91,0xf3,0x1e,0xd8,0xc9,0xe1,
                0x32,0x4e,0x0e,0x0f,0x3b,0x84,0x00,0x33,
                0xb0,0x9d,0x1a,0x92,0xf0,0x20,0xa1,0x05,
                0xe8,0xdf,0xe1,0x2d,0xb5,0x08,0xdb,0x10,
                0xe1,0x17,0x1b,0xdc,0x35,0xbf,0x55,0xe6,
                0x98,0xb5,0x93,0xe2,0x5d,0xd7,0x05,0x8c,
                0x04,0x1a,0xfb,0x3f,0x2b,0x24,0xac,0x31,
                0x33,0xc6,0x7f,0xab,0xab,0x05,0x4c,0xda,
                0xed,0xbd,0x40,0x85,0x4a,0x90,0xc8,0x4f,
                0x9c
            ),
        };

        let expected = Ok(spki);
        let actual = yasna::parse_der(&asserted, SubjectPublicKeyInfo::decode_ber);
        assert_eq!(actual, expected);
    }
}

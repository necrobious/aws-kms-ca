use yasna::models::ObjectIdentifier;

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
pub enum SignatureAlgorithmIdentifier {
    EcdsaWithSha256,
    EcdsaWithSha384,
//    EcdsaWithSha512,
}

impl BERDecodable for SignatureAlgorithmIdentifier {
    #[cfg_attr(feature = "tracing", tracing::instrument(name = "SignatureAlgorithmIdentifier::decode_ber"))]
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        #[cfg(feature = "tracing")]
        debug!("parsing signature algorithm identifier");
        reader.read_sequence(|reader| {
            let e256 = ObjectIdentifier::from_slice(&[1,2,840,10045,4,3,2]);
            let e384 = ObjectIdentifier::from_slice(&[1,2,840,10045,4,3,3]);
            let oid = reader.next().read_oid()?;
            if oid == e256 {
                return Ok(SignatureAlgorithmIdentifier::EcdsaWithSha256)
            } else if oid == e384 {
                return Ok(SignatureAlgorithmIdentifier::EcdsaWithSha384)
            } else {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid))
            }
        })
    }
}

impl DEREncodable for SignatureAlgorithmIdentifier {
    fn encode_der(&self, writer: DERWriter) {
        use SignatureAlgorithmIdentifier::*;
        writer.write_sequence( |writer| {
            let oid = match self {
                // OID: 1.2.840.10045.4.3.2
                // {
                //      iso(1)
                //      member-body(2)
                //      us(840)
                //      ansi-x962(10045)
                //      signatures(4)
                //      ecdsa-with-SHA2(3)
                //      ecdsa-with-SHA256(2)
                // }
                EcdsaWithSha256 => ObjectIdentifier::from_slice(&[1,2,840,10045,4,3,2]),
                // OID: 1.2.840.10045.4.3.3
                // {
                //      iso(1)
                //      member-body(2)
                //      us(840)
                //      ansi-x962(10045)
                //      signatures(4)
                //      ecdsa-with-SHA2(3)
                //      ecdsa-with-SHA384(3)
                // }
                EcdsaWithSha384 => ObjectIdentifier::from_slice(&[1,2,840,10045,4,3,3]),
/*
                // OID: 1.2.840.10045.4.3.2
                // {
                //      iso(1)
                //      member-body(2)
                //      us(840)
                //      ansi-x962(10045)
                //      signatures(4)
                //      ecdsa-with-SHA2(3)
                //      ecdsa-with-SHA512(4)
                // }
                EcdsaWithSha512 => ObjectIdentifier::from_slice(&[1,2,840,10045,4,3,4]),
*/

            };
            writer.next().write_oid(&oid);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
/*
    #[test]
    fn ecdsa_with_sha512_should_encode_correctly () {
        let expected = vec!(0x30,0x0a, // SEQUENCE, 10 bytes
            0x06,0x08, // OID, 8 bytes
                0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x04);// encoding of OID(1.2.840.10045.4.3.4)

        let der = yasna::encode_der(&SignatureAlgorithmIdentifier::EcdsaWithSha512);

        assert_eq!(der, expected);
    }
*/

    #[test]
    fn ecdsa_with_sha384_should_encode_correctly () {
        let expected = vec!(0x30,0x0a, // SEQUENCE, 10 bytes
            0x06,0x08, // OID, 8 bytes
                0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x03);// encoding of OID(1.2.840.10045.4.3.3)

        let der = yasna::encode_der(&SignatureAlgorithmIdentifier::EcdsaWithSha384);

        assert_eq!(der, expected);
    }

    #[test]
    fn ecdsa_with_sha256_should_encode_correctly () {
        let expected = vec!(0x30,0x0a, // SEQUENCE, 10 bytes
            0x06,0x08, // OID, 8 bytes
                0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02);// encoding of OID(1.2.840.10045.4.3.2)

        let der = yasna::encode_der(&SignatureAlgorithmIdentifier::EcdsaWithSha256);

        assert_eq!(der, expected);
    }

    #[test]
    fn ecdsa_with_sha384_should_decode_correctly () {
        // DER encoding of the OID(1.2.840.10045.4.3.3)
        let asserted = vec!(0x30,0x0a, // SEQUENCE, 10 bytes
            0x06,0x08, // OID, 8 bytes
                0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x03);// encoding of OID(1.2.840.10045.4.3.3)

        let expected = Ok(SignatureAlgorithmIdentifier::EcdsaWithSha384); 

        let actual = yasna::parse_der(&asserted, SignatureAlgorithmIdentifier::decode_ber);
        assert_eq!(actual, expected);
    }

    #[test]
    fn ecdsa_with_sha256_should_decode_correctly () {
        // DER encoding of the OID(1.2.840.10045.4.3.2)
        let asserted = vec!(0x30,0x0a, // SEQUENCE, 10 bytes
            0x06,0x08, // OID, 8 bytes
                0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02);// encoding of OID(1.2.840.10045.4.3.2)

        let expected = Ok(SignatureAlgorithmIdentifier::EcdsaWithSha256); 

        let actual = yasna::parse_der(&asserted, SignatureAlgorithmIdentifier::decode_ber);
        assert_eq!(actual, expected);
    }

    #[test]
    fn a_valid_oid_of_an_unsupported_identifier_should_fail() {
        // DER encoding of the OID(1.2.840.10045.4.3.4)
        let asserted = vec!(0x30,0x0a, // SEQUENCE, 10 bytes
            0x06,0x08, // OID, 8 bytes
                0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x04);// encoding of OID(1.2.840.10045.4.3.4)

        let expected = Err(ASN1Error::new(ASN1ErrorKind::Invalid)); 

        let actual = yasna::parse_der(&asserted, SignatureAlgorithmIdentifier::decode_ber);
        assert_eq!(actual, expected);
    }

}

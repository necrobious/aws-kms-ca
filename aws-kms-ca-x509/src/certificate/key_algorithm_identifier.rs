use yasna::{
    ASN1Error,
    ASN1ErrorKind,
    ASN1Result,
    DERWriter,
    DEREncodable,
    BERReader,
    BERDecodable,
    models::ObjectIdentifier,
};


#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyAlgorithmIdentifier {
    P256,
    P384,
}

impl DEREncodable for KeyAlgorithmIdentifier {
    fn encode_der(&self, writer: DERWriter) {
        use KeyAlgorithmIdentifier::*;

        // RFC 5480 2.1.1
        // OID: 1.2.840.10045.2.1
        // {
        //      iso(1)
        //      member-body(2)
        //      us(840)
        //      ansi-x962(10045)
        //      keyType(2)
        //      ecPublicKey(1)
        // }
        let ec_public_key = ObjectIdentifier::from_slice(&[1,2,840,10045,2,1]);

        // RFC 5480 2.1.1.1 - secp256r1 
        // OID: 1.2.840.10045.3.1.7
        // {
        //      iso(1)
        //      member-body(2)
        //      us(840)
        //      ansi-x962(10045)
        //      curves(3)
        //      prime(1)
        //      prime256v1(7)
        // }
        let p_256 = ObjectIdentifier::from_slice(&[1,2,840,10045,3,1,7]);

        // RFC 5480 2.1.1.1 - secp384r1
        // OID: 1.3.132.0.34
        // {
        //      iso(1)
        //      identified-organization(3)
        //      certicom(132)
        //      curve(0)
        //      ansip384r1(34)
        // }
        let p_384 = ObjectIdentifier::from_slice(&[1,3,132,0,34]);

        writer.write_sequence(|writer| {
            writer.next().write_oid(&ec_public_key);
            match self {
                P256 => writer.next().write_oid(&p_256),
                P384 => writer.next().write_oid(&p_384),
            }
        });
    }
}

impl BERDecodable for KeyAlgorithmIdentifier {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let ec_public_key = ObjectIdentifier::from_slice(&[1,2,840,10045,2,1]);
            let p_256 = ObjectIdentifier::from_slice(&[1,2,840,10045,3,1,7]);
            let p_384 = ObjectIdentifier::from_slice(&[1,3,132,0,34]);
            let algo_oid = reader.next().read_oid()?;
            if algo_oid != ec_public_key {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid))
            }

            let curve_oid = reader.next().read_oid()?;
            if curve_oid == p_256 {
                return Ok(KeyAlgorithmIdentifier::P256)
            }
            if curve_oid == p_384 {
                return Ok(KeyAlgorithmIdentifier::P384)
            }
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_key_identifier_decode_correctly () {
        let asserted= vec!(0x30,0x13, // SEQUENCE, 10 bytes
            0x06,0x07, // OID, 7 bytes
                0x2a,0x86,0x48,0xce,0x3d,0x02,0x01, // encoding of OID(1.2.840.10045.2.1)
            0x06,0x08, // OID, 8 bytes
                0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07);// encoding of OID(1.2.840.10045.3.1.7)

        let expected = Ok(KeyAlgorithmIdentifier::P256);
        let actual = yasna::parse_der(&asserted, KeyAlgorithmIdentifier::decode_ber);
        assert_eq!(actual, expected);
    }

    #[test]
    fn p384_key_identifier_decode_correctly () {
        let asserted = vec!(0x30,0x10, // SEQUENCE, 16 bytes
            0x06,0x07, // OID, 7 bytes
                0x2a,0x86,0x48,0xce,0x3d,0x02,0x01, // encoding of OID(1.2.840.10045.2.1)
            0x06,0x05, // OID, 5 bytes
                0x2b,0x81,0x04,0x00,0x22);// encoding of OID(1.3.132.0.34)

        let expected = Ok(KeyAlgorithmIdentifier::P384);
        let actual = yasna::parse_der(&asserted, KeyAlgorithmIdentifier::decode_ber);
        assert_eq!(actual, expected);
    }

    #[test]
    fn p256_key_identifier_encode_correctly () {
        let expected = vec!(0x30,0x13, // SEQUENCE, 10 bytes
            0x06,0x07, // OID, 7 bytes
                0x2a,0x86,0x48,0xce,0x3d,0x02,0x01, // encoding of OID(1.2.840.10045.2.1)
            0x06,0x08, // OID, 8 bytes
                0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07);// encoding of OID(1.2.840.10045.3.1.7)

        let der = yasna::encode_der(&KeyAlgorithmIdentifier::P256);

        assert_eq!(der, expected);
    }

    #[test]
    fn p384_key_identifier_encode_correctly () {
        let expected = vec!(0x30,0x10, // SEQUENCE, 16 bytes
            0x06,0x07, // OID, 7 bytes
                0x2a,0x86,0x48,0xce,0x3d,0x02,0x01, // encoding of OID(1.2.840.10045.2.1)
            0x06,0x05, // OID, 5 bytes
                0x2b,0x81,0x04,0x00,0x22);// encoding of OID(1.3.132.0.34)

        let der = yasna::encode_der(&KeyAlgorithmIdentifier::P384);

        assert_eq!(der, expected);
    }
}
